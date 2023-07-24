use crate::common::{get_jwt_claims, memory_storage::MemoryStorage};
use did_key::{generate, Ed25519KeyPair};
use oid4vc_core::Subject;
use oid4vc_manager::{
    managers::credential_issuer::CredentialIssuerManager, methods::key_method::KeySubject,
    servers::credential_issuer::Server,
};
use oid4vci::{
    credential_format::CredentialFormat,
    credential_format_profiles::w3c_verifiable_credentials::jwt_vc_json::JwtVcJson,
    credential_offer::{CredentialOfferQuery, Grants},
    token_request::{PreAuthorizedCode, TokenRequest},
    Wallet,
};
use std::sync::Arc;

#[tokio::test]
async fn test_pre_authorized_code_flow() {
    // Setup the credential issuer.
    let mut credential_issuer = Server::setup(
        CredentialIssuerManager::new(
            None,
            MemoryStorage,
            [Arc::new(KeySubject::from_keypair(generate::<Ed25519KeyPair>(Some(
                "this-is-a-very-UNSAFE-issuer-secret-key".as_bytes().try_into().unwrap(),
            ))))],
        )
        .unwrap(),
    )
    .unwrap();
    credential_issuer.start_server().unwrap();

    // Get the credential offer url.
    let credential_offer_url = credential_issuer
        .credential_issuer_manager
        .credential_offer_uri()
        .unwrap();

    // Parse the credential offer url.
    let credential_offer = match credential_offer_url.parse().unwrap() {
        CredentialOfferQuery::CredentialOffer(credential_offer) => credential_offer,
        _ => unreachable!(),
    };

    // The credential offer contains a credential format for a university degree.
    let university_degree_credential_format: CredentialFormat<JwtVcJson> =
        serde_json::from_value(credential_offer.credentials.get(0).unwrap().clone()).unwrap();

    // The credential offer contains a credential issuer url.
    let credential_issuer_url = credential_offer.credential_issuer;

    // Create a new subject.
    let subject = KeySubject::new();
    let subject_did = subject.identifier().unwrap();

    // Create a new wallet.
    let wallet = Wallet::new(Arc::new(subject));

    // Get the authorization server metadata.
    let authorization_server_metadata = wallet
        .get_authorization_server_metadata(credential_issuer_url.clone())
        .await
        .unwrap();

    // Get the credential issuer metadata.
    let credential_issuer_metadata = wallet
        .get_credential_issuer_metadata(credential_issuer_url.clone())
        .await
        .unwrap();

    // Create a token request with grant_type `pre_authorized_code`.
    let token_request = match credential_offer.grants {
        Some(Grants {
            pre_authorized_code, ..
        }) => TokenRequest::PreAuthorizedCode {
            grant_type: PreAuthorizedCode,
            pre_authorized_code: pre_authorized_code.unwrap().pre_authorized_code,
            user_pin: Some("493536".to_string()),
        },
        None => unreachable!(),
    };

    // Get an access token.
    let token_response = wallet
        .get_access_token(authorization_server_metadata.token_endpoint, token_request)
        .await
        .unwrap();

    // Get the credential.
    let credential_response = wallet
        .get_credential(
            credential_issuer_metadata,
            &token_response,
            university_degree_credential_format,
        )
        .await
        .unwrap();

    // Decode the JWT without performing validation
    let claims = get_jwt_claims(credential_response.credential.unwrap().clone());

    // Check the credential.
    assert_eq!(
        claims["vc"],
        serde_json::json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "type": [
                "VerifiableCredential",
                "PersonalInformation"
            ],
            "issuanceDate": "2022-01-01T00:00:00Z",
            "issuer": credential_issuer_url,
            "credentialSubject": {
                "id": subject_did,
                "givenName": "Ferris",
                "familyName": "Crabman",
                "email": "ferris.crabman@crabmail.com",
                "birthdate": "1985-05-21"
            }
        })
    )
}
