use crate::common::{MemoryStorage, Storage, TestSubject};
use axum::async_trait;
use did_key::{generate, Ed25519KeyPair};
use jsonwebtoken::Algorithm;
use lazy_static::lazy_static;
use oid4vc_core::{
    authentication::sign::ExternalSign,
    authorization_request::{AuthorizationRequest, ByReference, Object},
    authorization_response::AuthorizationResponse,
    client_metadata::ClientMetadataResource,
    scope::{Scope, ScopeValue},
    DidMethod, Sign, Subject, SubjectSyntaxType, Verify,
};
use oid4vc_manager::{methods::key_method::KeySubject, ProviderManager, RelyingPartyManager};
use siopv2::{
    authorization_request::ClientMetadataParameters,
    claims::{Address, IndividualClaimRequest},
    siopv2::SIOPv2,
    StandardClaimsRequests, StandardClaimsValues,
};
use std::{str::FromStr, sync::Arc};
use wiremock::{
    http::Method,
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

/// A Subject that can sign and verify messages with multiple different DID Methods.
#[derive(Debug)]
pub struct MultiDidMethodSubject {
    pub test_subject: TestSubject,
    pub key_subject: KeySubject,
}

#[async_trait]
impl Sign for MultiDidMethodSubject {
    async fn key_id(&self, subject_syntax_type: &str, algorithm: Algorithm) -> Option<String> {
        match subject_syntax_type {
            "did:test" => self.test_subject.key_id(subject_syntax_type, algorithm).await,
            "did:key" => self.key_subject.key_id(subject_syntax_type, algorithm).await,
            _ => None,
        }
    }

    async fn sign(&self, message: &str, subject_syntax_type: &str, algorithm: Algorithm) -> anyhow::Result<Vec<u8>> {
        match subject_syntax_type {
            "did:test" => self.test_subject.sign(message, subject_syntax_type, algorithm).await,
            "did:key" => self.key_subject.sign(message, subject_syntax_type, algorithm).await,
            _ => Err(anyhow::anyhow!("Unsupported DID method.")),
        }
    }

    fn external_signer(&self) -> Option<Arc<dyn ExternalSign>> {
        None
    }
}

#[async_trait]
impl Verify for MultiDidMethodSubject {
    async fn public_key(&self, kid: &str) -> anyhow::Result<Vec<u8>> {
        match kid {
            _ if kid.contains("did:test") => self.test_subject.public_key(kid).await,
            _ if kid.contains("did:key") => self.key_subject.public_key(kid).await,
            _ => Err(anyhow::anyhow!("Unsupported DID method.")),
        }
    }
}

#[async_trait]
impl Subject for MultiDidMethodSubject {
    async fn identifier(&self, subject_syntax_type: &str, algorithm: Algorithm) -> anyhow::Result<String> {
        match subject_syntax_type {
            "did:test" => self.test_subject.identifier(subject_syntax_type, algorithm).await,
            "did:key" => self.key_subject.identifier(subject_syntax_type, algorithm).await,
            _ => Err(anyhow::anyhow!("Unsupported DID method.")),
        }
    }
}

lazy_static! {
    pub static ref USER_CLAIMS: serde_json::Value = serde_json::json!(
        {
            "name": "Jane Doe",
            "given_name": "Jane",
            "family_name": "Doe",
            "middle_name": "Middle",
            "nickname": "JD",
            "preferred_username": "j.doe",
            "profile": "https://example.com/janedoe",
            "picture": "https://example.com/janedoe/me.jpg",
            "website": "https://example.com",
            "email": "jane.doe@example.com",
            "updated_at": 1311280970,
            "phone_number": "+1 555 555 5555",
            "address": {
                "formatted": "100 Universal City Plaza\nHollywood, CA 91608",
                "street_address": "100 Universal City Plaza",
                "locality": "Hollywood",
                "region": "CA",
                "postal_code": "91608",
                "country": "US"
            }
        }
    );
}

#[rstest::rstest]
#[case("did:key")]
#[case("did:test")]
#[tokio::test]
async fn test_implicit_flow(#[case] did_method: &str) {
    // Create a new mock server and retreive it's url.
    let mock_server = MockServer::start().await;
    let server_url = mock_server.uri();

    // Create a new subject.
    let subject = MultiDidMethodSubject {
        test_subject: TestSubject::new(
            "did:test:relying_party".to_string(),
            "did:test:relying_party#key_id".to_string(),
        )
        .unwrap(),
        key_subject: KeySubject::from_keypair(generate::<Ed25519KeyPair>(None), None),
    };

    let client_id = subject.identifier(did_method, Algorithm::EdDSA).await.unwrap();

    // Create a new relying party manager.
    let relying_party_manager =
        RelyingPartyManager::new(Arc::new(subject), did_method, vec![Algorithm::EdDSA]).unwrap();

    // Create a new RequestUrl with response mode `direct_post` for cross-device communication.
    let authorization_request: AuthorizationRequest<Object<SIOPv2>> = AuthorizationRequest::<Object<SIOPv2>>::builder()
        .client_id(&client_id)
        .scope(Scope::from(vec![ScopeValue::OpenId, ScopeValue::Phone]))
        .redirect_uri(format!("{server_url}/redirect_uri").parse::<url::Url>().unwrap())
        .response_mode("direct_post".to_string())
        .client_metadata(ClientMetadataResource::ClientMetadata { // TODO: removed <ClientMetadataParameters>::, not sure of the consequences
            client_name: None,
            logo_uri: None,
            extension: ClientMetadataParameters {
                subject_syntax_types_supported: vec![SubjectSyntaxType::Did(DidMethod::from_str(did_method).unwrap())],
                id_token_signed_response_alg: Some(Algorithm::EdDSA),
            },
            other: Default::default(),
        })
        .claims(
            r#"{
                "id_token": {
                    "name": null,
                    "email": {
                        "essential": true
                    },
                    "address": null,
                    "updated_at": null
                }
            }"#,
        )
        .nonce("n-0S6_WzA2Mj".to_string())
        .build()
        .unwrap();

    // Create a new `request_uri` endpoint on the mock server and load it with the JWT encoded `AuthorizationRequest`.
    Mock::given(method("GET"))
        .and(path("/request_uri"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(relying_party_manager.encode(&authorization_request).await.unwrap()),
        )
        .mount(&mock_server)
        .await;

    // Create a new `redirect_uri` endpoint on the mock server where the `Provider` will send the `AuthorizationResponse`.
    Mock::given(method("POST"))
        .and(path("/redirect_uri"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    // Create a new storage for the user's claims.
    let storage = MemoryStorage::new(serde_json::from_value(USER_CLAIMS.clone()).unwrap());

    // Create a new subject.
    let subject = MultiDidMethodSubject {
        test_subject: TestSubject::new("did:test:subject".to_string(), "did:test:subject#key_id".to_string()).unwrap(),
        key_subject: KeySubject::from_keypair(generate::<Ed25519KeyPair>(None), None),
    };

    // Create a new provider manager.
    let provider_manager = ProviderManager::new(Arc::new(subject), vec![did_method], vec![Algorithm::EdDSA]).unwrap();

    // Create a new RequestUrl which includes a `request_uri` pointing to the mock server's `request_uri` endpoint.
    let authorization_request = AuthorizationRequest::<ByReference> {
        custom_url_scheme: "openid".to_string(),
        body: ByReference {
            client_id,
            request_uri: format!("{server_url}/request_uri").parse::<url::Url>().unwrap(),
        },
    };

    // The Provider obtains the request url either by a deeplink or by scanning a QR code. It then validates the
    // authorization_request. Since in this case the authorization_request is a JWT, the provider will fetch the authorization_request by sending a GET
    // authorization_request to mock server's `request_uri` endpoint.
    let generic_authorization_request = provider_manager
        .validate_request(authorization_request.to_string())
        .await
        .unwrap();

    let authorization_request =
        AuthorizationRequest::<Object<SIOPv2>>::from_generic(&generic_authorization_request).unwrap();

    // The provider can now access the claims requested by the relying party.
    let request_claims = authorization_request.body.extension.id_token_request_claims().unwrap();
    assert_eq!(
        request_claims,
        StandardClaimsRequests {
            name: Some(IndividualClaimRequest::Null),
            email: Some(IndividualClaimRequest::object().essential(true)),
            address: Some(IndividualClaimRequest::Null),
            updated_at: Some(IndividualClaimRequest::Null),
            phone_number: Some(IndividualClaimRequest::Null),
            phone_number_verified: Some(IndividualClaimRequest::Null),
            ..Default::default()
        }
    );

    // Assert that the authorization_request was successfully received by the mock server at the `request_uri` endpoint.
    let get_request = mock_server.received_requests().await.unwrap()[0].clone();
    assert_eq!(get_request.method, Method::Get);
    assert_eq!(get_request.url.path(), "/request_uri");

    // The user can now provide the claims requested by the relying party.
    let response_claims: StandardClaimsValues = storage.fetch_claims(&request_claims);

    // Let the provider generate a authorization_response based on the validated authorization_request. The response is an `IdToken` which is
    // encoded as a JWT.
    let authorization_response: AuthorizationResponse<SIOPv2> = provider_manager
        .generate_response(&authorization_request, response_claims)
        .await
        .unwrap();

    // The provider manager sends it's authorization_response to the mock server's `redirect_uri` endpoint.
    provider_manager.send_response(&authorization_response).await.unwrap();

    // Assert that the AuthorizationResponse was successfully received by the mock server at the expected endpoint.
    let post_request = mock_server.received_requests().await.unwrap()[1].clone();
    assert_eq!(post_request.method, Method::Post);
    assert_eq!(post_request.url.path(), "/redirect_uri");
    let authorization_response: AuthorizationResponse<SIOPv2> =
        serde_urlencoded::from_bytes(post_request.body.as_slice()).unwrap();

    // The `RelyingParty` then validates the authorization_response by decoding the header of the id_token, by fetching the public
    // key corresponding to the key identifier and finally decoding the id_token using the public key and by
    // validating the signature.
    let id_token = relying_party_manager
        .validate_response(&authorization_response)
        .await
        .unwrap();
    assert_eq!(
        id_token.standard_claims,
        StandardClaimsValues {
            name: Some("Jane Doe".to_string()),
            email: Some("jane.doe@example.com".to_string()),
            updated_at: Some(1311280970),
            phone_number: Some("+1 555 555 5555".to_string()),
            address: Some(Address {
                formatted: Some("100 Universal City Plaza\nHollywood, CA 91608".to_string()),
                street_address: Some("100 Universal City Plaza".to_string()),
                locality: Some("Hollywood".to_string()),
                region: Some("CA".to_string()),
                postal_code: Some("91608".to_string()),
                country: Some("US".to_string()),
            }),
            ..Default::default()
        }
    );
}
