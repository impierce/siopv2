use did_key::{generate, Ed25519KeyPair};
use identity_credential::{credential::Jwt, presentation::Presentation};
use jsonwebtoken::{Algorithm, Header};
use lazy_static::lazy_static;
use oid4vc_core::{
    authorization_request::{AuthorizationRequest, Object},
    authorization_response::AuthorizationResponse,
    client_metadata::ClientMetadataResource,
    jwt, Subject,
};
use oid4vc_manager::{
    managers::presentation::create_presentation_submission, methods::key_method::KeySubject, ProviderManager,
    RelyingPartyManager,
};
use oid4vci::VerifiableCredentialJwt;
use oid4vp::{
    authorization_request::ClientMetadataParameters,
    oid4vp::{AuthorizationResponseInput, PresentationInputType, OID4VP},
    ClaimFormatDesignation, ClaimFormatProperty, PresentationDefinition,
};
use serde_json::json;
use std::{collections::HashMap, sync::Arc};

lazy_static! {
    pub static ref PRESENTATION_DEFINITION: PresentationDefinition = serde_json::from_value(json!(
        {
            "id":"Verifiable Presentation request for sign-on",
                "input_descriptors":[
                {
                    "id":"Request for Ferris's Verifiable Credential",
                    "constraints":{
                        "fields":[
                            {
                                "path":[
                                    "$.vc.type"
                                ],
                                "filter":{
                                    "type":"array",
                                    "contains":{
                                        "const":"PersonalInformation"
                                    }
                                }
                            },
                            {
                                "path":[
                                    "$.vc.credentialSubject.givenName"
                                ]
                            },
                            {
                                "path":[
                                    "$.vc.credentialSubject.familyName"
                                ]
                            },
                            {
                                "path":[
                                    "$.vc.credentialSubject.email"
                                ]
                            },
                            {
                                "path":[
                                    "$.vc.credentialSubject.birthdate"
                                ]
                            }
                        ]
                    }
                }
            ]
        }
    ))
    .unwrap();
}

#[tokio::test]
async fn test_implicit_flow() {
    // Create a new issuer.
    let issuer = KeySubject::from_keypair(
        generate::<Ed25519KeyPair>(Some(
            "this-is-a-very-UNSAFE-issuer-secret-key".as_bytes().try_into().unwrap(),
        )),
        None,
    );
    let issuer_did = issuer.identifier("did:key", Algorithm::EdDSA).await.unwrap();

    // Create a new subject.
    let subject = Arc::new(KeySubject::from_keypair(
        generate::<Ed25519KeyPair>(Some("this-is-a-very-UNSAFE-secret-key".as_bytes().try_into().unwrap())),
        None,
    ));
    let subject_did = subject.identifier("did:key", Algorithm::EdDSA).await.unwrap();

    // Create a new relying party.
    let relying_party = Arc::new(KeySubject::new());
    let relying_party_did = relying_party.identifier("did:key", Algorithm::EdDSA).await.unwrap();
    let relying_party_manager = RelyingPartyManager::new(relying_party, "did:key", vec![Algorithm::EdDSA]).unwrap();

    // Create authorization request with response_type `id_token vp_token`
    let authorization_request = AuthorizationRequest::<Object<OID4VP>>::builder()
        .client_id(relying_party_did)
        .redirect_uri("https://example.com".parse::<url::Url>().unwrap())
        .presentation_definition(PRESENTATION_DEFINITION.clone())
        .client_metadata(ClientMetadataResource::ClientMetadata {
            client_name: None,
            logo_uri: None,
            extension: ClientMetadataParameters {
                vp_formats: vec![(
                    ClaimFormatDesignation::JwtVcJson,
                    ClaimFormatProperty::Alg(vec![Algorithm::EdDSA]),
                )]
                .into_iter()
                .collect(),
            },
            other: HashMap::from_iter(vec![(
                "subject_syntax_types_supported".to_string(),
                json!(vec!["did:key".to_string(),]),
            )]),
        })
        .nonce("nonce".to_string())
        .build()
        .unwrap();

    // Create a provider manager and validate the authorization request.
    let provider_manager = ProviderManager::new(subject, vec!["did:key"], vec![Algorithm::EdDSA]).unwrap();

    // Create a new verifiable credential.
    let verifiable_credential = VerifiableCredentialJwt::builder()
        .sub(&subject_did)
        .iss(&issuer_did)
        .iat(0)
        .exp(9999999999i64)
        .verifiable_credential(serde_json::json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "type": [
                "VerifiableCredential",
                "PersonalInformation"
            ],
            "issuanceDate": "2022-01-01T00:00:00Z",
            "issuer": issuer_did,
            "credentialSubject": {
            "id": subject_did,
            "givenName": "Ferris",
            "familyName": "Crabman",
            "email": "ferris.crabman@crabmail.com",
            "birthdate": "1985-05-21"
            }
        }))
        .build()
        .unwrap();

    // Create presentation submission using the presentation definition and the verifiable credential.
    let presentation_submission = create_presentation_submission(
        &PRESENTATION_DEFINITION,
        &vec![serde_json::to_value(&verifiable_credential).unwrap()],
    )
    .unwrap();

    // Encode the verifiable credential as a JWT.
    let jwt = jwt::encode(
        Arc::new(issuer),
        Header {
            alg: Algorithm::EdDSA,
            ..Default::default()
        },
        &verifiable_credential,
        "did:key",
    )
    .await
    .unwrap();

    // Create a verifiable presentation using the JWT.
    let verifiable_presentation =
        Presentation::builder(subject_did.parse().unwrap(), identity_core::common::Object::new())
            .credential(Jwt::from(jwt))
            .build()
            .unwrap();

    let verifiable_presentation_input = PresentationInputType::Unsigned(verifiable_presentation);

    // Generate the authorization_response. It will include both an IdToken and a VpToken.
    let authorization_response: AuthorizationResponse<OID4VP> = provider_manager
        .generate_response(
            &authorization_request,
            AuthorizationResponseInput {
                verifiable_presentation_input,
                presentation_submission,
            },
        )
        .await
        .unwrap();

    // Validate the authorization_response.
    assert!(relying_party_manager
        .validate_response(&authorization_response)
        .await
        .is_ok());
}
