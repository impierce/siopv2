use crate::authorization_details::AuthorizationDetailsObject;
use crate::authorization_request::AuthorizationRequest;
use crate::authorization_response::AuthorizationResponse;
use crate::credential_format_profiles::{CredentialFormatCollection, CredentialFormats, WithParameters};
use crate::credential_issuer::credential_configurations_supported::CredentialConfigurationsSupportedObject;
use crate::credential_issuer::{
    authorization_server_metadata::AuthorizationServerMetadata, credential_issuer_metadata::CredentialIssuerMetadata,
};
use crate::credential_offer::CredentialOfferParameters;
use crate::credential_request::{BatchCredentialRequest, CredentialRequest};
use crate::credential_response::BatchCredentialResponse;
use crate::proof::{KeyProofType, ProofType};
use crate::{credential_response::CredentialResponse, token_request::TokenRequest, token_response::TokenResponse};
use anyhow::{anyhow, Result};
use jsonwebtoken::Algorithm;
use oid4vc_core::authentication::subject::SigningSubject;
use oid4vc_core::SubjectSyntaxType;
use reqwest::Url;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::policies::ExponentialBackoff;
use reqwest_retry::RetryTransientMiddleware;
use serde::de::DeserializeOwned;
use std::str::FromStr;

pub struct Wallet<CFC = CredentialFormats<WithParameters>>
where
    CFC: CredentialFormatCollection,
{
    pub subject: SigningSubject,
    pub supported_subject_syntax_types: Vec<SubjectSyntaxType>,
    pub client: ClientWithMiddleware,
    pub proof_signing_alg_values_supported: Vec<Algorithm>,
    phantom: std::marker::PhantomData<CFC>,
}

impl<CFC: CredentialFormatCollection + DeserializeOwned> Wallet<CFC> {
    pub fn new(
        subject: SigningSubject,
        supported_subject_syntax_types: Vec<impl TryInto<SubjectSyntaxType>>,
        proof_signing_alg_values_supported: Vec<Algorithm>,
    ) -> anyhow::Result<Self> {
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(5);
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();
        Ok(Self {
            subject,
            supported_subject_syntax_types: supported_subject_syntax_types
                .into_iter()
                .map(|subject_syntax_type| {
                    subject_syntax_type
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Invalid did method."))
                })
                .collect::<Result<_>>()?,
            client,
            proof_signing_alg_values_supported,
            phantom: std::marker::PhantomData,
        })
    }

    pub async fn get_credential_offer(&self, credential_offer_uri: Url) -> Result<CredentialOfferParameters> {
        self.client
            .get(credential_offer_uri)
            .send()
            .await?
            .json::<CredentialOfferParameters>()
            .await
            .map_err(|_| anyhow::anyhow!("Failed to get credential offer"))
    }

    pub async fn get_authorization_server_metadata(
        &self,
        credential_issuer_url: Url,
    ) -> Result<AuthorizationServerMetadata> {
        let mut oauth_authorization_server_endpoint = credential_issuer_url.clone();

        // TODO(NGDIL): remove this NGDIL specific code. This is a temporary fix to get the authorization server metadata.
        oauth_authorization_server_endpoint
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("unable to parse credential issuer url"))
            .unwrap()
            .push(".well-known")
            .push("oauth-authorization-server");

        self.client
            .get(oauth_authorization_server_endpoint)
            .send()
            .await?
            .json::<AuthorizationServerMetadata>()
            .await
            .map_err(|_| anyhow::anyhow!("Failed to get authorization server metadata"))
    }

    pub async fn get_credential_issuer_metadata(
        &self,
        credential_issuer_url: Url,
    ) -> Result<CredentialIssuerMetadata<CFC>> {
        let mut openid_credential_issuer_endpoint = credential_issuer_url.clone();

        // TODO(NGDIL): remove this NGDIL specific code. This is a temporary fix to get the credential issuer metadata.
        openid_credential_issuer_endpoint
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("unable to parse credential issuer url"))?
            .push(".well-known")
            .push("openid-credential-issuer");

        self.client
            .get(openid_credential_issuer_endpoint)
            .send()
            .await?
            .json::<CredentialIssuerMetadata<CFC>>()
            .await
            .map_err(|_| anyhow::anyhow!("Failed to get credential issuer metadata"))
    }

    pub async fn get_authorization_code(
        &self,
        authorization_endpoint: Url,
        authorization_details: Vec<AuthorizationDetailsObject<CFC>>,
    ) -> Result<AuthorizationResponse> {
        self.client
            .get(authorization_endpoint)
            // TODO: must be `form`, but `AuthorizationRequest needs to be able to serilalize properly.
            .json(&AuthorizationRequest {
                response_type: "code".to_string(),
                client_id: self
                    .subject
                    .identifier(
                        &self
                            .supported_subject_syntax_types
                            .first()
                            .map(ToString::to_string)
                            .ok_or(anyhow!("No supported subject syntax types found."))?,
                        self.proof_signing_alg_values_supported[0],
                    )
                    .await?,
                redirect_uri: None,
                scope: None,
                state: None,
                authorization_details,
            })
            .send()
            .await?
            .json::<AuthorizationResponse>()
            .await
            .map_err(|_| anyhow::anyhow!("Failed to get authorization code"))
    }

    pub async fn get_access_token(&self, token_endpoint: Url, token_request: TokenRequest) -> Result<TokenResponse> {
        self.client
            .post(token_endpoint)
            .form(&token_request)
            .send()
            .await?
            .json()
            .await
            .map_err(|e| e.into())
    }

    // Select supported signing algorithm that matches the Credential Issuer's supported Proof Types.
    // Supplying the `proof` parameter to the Credential Request is only required when the `proof_types_supported`
    // parameter is present in the Credential Configuration in the Credential Issuer's metadata. However, if the
    // `proof_types_supported` is not present, the Wallet will still provide the `proof` signed with its own preferred
    // signing algorithm. For more information see: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#section-7.2-2.2.1
    fn select_signing_algorithm(
        &self,
        credential_configuration: &CredentialConfigurationsSupportedObject,
    ) -> Result<Algorithm> {
        let proof_types_supported = &credential_configuration.proof_types_supported;

        // If the Credential Issuer does not define any supported Proof Types, then the Wallet wil uses its own default signing algorithm.
        if proof_types_supported.is_empty() {
            return self
                .proof_signing_alg_values_supported
                .first()
                .ok_or(anyhow::anyhow!("Wallet does not support any signing algorithms"))
                .cloned();
        }

        // Extract the actual signing algorithms if the Credential Issuer supports JWT proof types.
        // TODO: support Proof types other than Jwt.
        let credential_issuer_proof_signing_alg_values_supported = proof_types_supported
            .get(&ProofType::Jwt)
            .map(|proof_type| proof_type.proof_signing_alg_values_supported.clone())
            .ok_or(anyhow::anyhow!(
                "The Credential Issuer does not support JWT proof types"
            ))?;

        // Return the first signing algorithm that matches any of the Credential Issuer's supported signing algorithms.
        self.proof_signing_alg_values_supported
            .iter()
            .find(|supported_algorithm| {
                credential_issuer_proof_signing_alg_values_supported.contains(supported_algorithm)
            })
            .cloned()
            .ok_or(anyhow::anyhow!("No matching supported signing algorithms found."))
    }

    fn select_subject_syntax_type(
        &self,
        credential_configuration: &CredentialConfigurationsSupportedObject,
    ) -> Result<SubjectSyntaxType> {
        let credential_issuer_cryptographic_binding_methods_supported: Vec<SubjectSyntaxType> =
            credential_configuration
                .cryptographic_binding_methods_supported
                .iter()
                .filter_map(|binding_method| SubjectSyntaxType::from_str(binding_method).ok())
                .collect();

        self.supported_subject_syntax_types
            .iter()
            .find(|supported_syntax_type| {
                credential_issuer_cryptographic_binding_methods_supported.contains(supported_syntax_type)
            })
            .cloned()
            .ok_or(anyhow::anyhow!("No supported subject syntax types found."))
    }

    pub async fn get_credential(
        &self,
        credential_issuer_metadata: CredentialIssuerMetadata<CFC>,
        token_response: &TokenResponse,
        credential_configuration: &CredentialConfigurationsSupportedObject,
    ) -> Result<CredentialResponse> {
        let credential_format = credential_configuration.credential_format.to_owned();

        let signing_algorithm = self.select_signing_algorithm(credential_configuration)?;
        let subject_syntax_type = self.select_subject_syntax_type(credential_configuration)?;

        let credential_request = CredentialRequest {
            credential_format,
            proof: Some(
                KeyProofType::builder()
                    .proof_type(ProofType::Jwt)
                    .algorithm(signing_algorithm)
                    .signer(self.subject.clone())
                    .iss(
                        self.subject
                            .identifier(&subject_syntax_type.to_string(), signing_algorithm)
                            .await?,
                    )
                    .aud(credential_issuer_metadata.credential_issuer)
                    // TODO: Use current time.
                    .iat(1571324800)
                    // TODO: so is this REQUIRED or OPTIONAL?
                    .nonce(
                        token_response
                            .c_nonce
                            .as_ref()
                            .ok_or(anyhow::anyhow!("No c_nonce found."))?
                            .clone(),
                    )
                    .subject_syntax_type(subject_syntax_type.to_string())
                    .build()
                    .await?,
            ),
        };

        self.client
            .post(credential_issuer_metadata.credential_endpoint)
            .bearer_auth(token_response.access_token.clone())
            .json(&credential_request)
            .send()
            .await?
            .json()
            .await
            .map_err(|e| e.into())
    }

    pub async fn get_batch_credential(
        &self,
        credential_issuer_metadata: CredentialIssuerMetadata<CFC>,
        token_response: &TokenResponse,
        credential_configurations: &[CredentialConfigurationsSupportedObject],
    ) -> Result<BatchCredentialResponse> {
        // TODO: This needs to be fixed since this current implementation assumes that for all credentials the same Proof Type is supported.
        let credential_configuration = credential_configurations
            .first()
            .ok_or(anyhow::anyhow!("No credential configurations found."))?;

        let signing_algorithm = self.select_signing_algorithm(credential_configuration)?;
        let subject_syntax_type = self.select_subject_syntax_type(credential_configuration)?;

        let proof = Some(
            KeyProofType::builder()
                .proof_type(ProofType::Jwt)
                .algorithm(signing_algorithm)
                .signer(self.subject.clone())
                .iss(
                    self.subject
                        .identifier(&subject_syntax_type.to_string(), signing_algorithm)
                        .await?,
                )
                .aud(credential_issuer_metadata.credential_issuer)
                // TODO: Use current time.
                .iat(1571324800)
                // TODO: so is this REQUIRED or OPTIONAL?
                .nonce(
                    token_response
                        .c_nonce
                        .as_ref()
                        .ok_or(anyhow::anyhow!("No c_nonce found."))?
                        .clone(),
                )
                .subject_syntax_type(subject_syntax_type.to_string())
                .build()
                .await?,
        );

        let batch_credential_request = BatchCredentialRequest {
            credential_requests: credential_configurations
                .iter()
                .map(|credential_configuration| CredentialRequest {
                    credential_format: credential_configuration.credential_format.to_owned(),
                    proof: proof.clone(),
                })
                .collect(),
        };

        self.client
            .post(credential_issuer_metadata.batch_credential_endpoint.unwrap())
            .bearer_auth(token_response.access_token.clone())
            .json(&batch_credential_request)
            .send()
            .await?
            .json()
            .await
            .map_err(|e| e.into())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::proof::KeyProofMetadata;
    use oid4vc_core::test_utils::TestSubject;
    use std::{collections::HashMap, sync::Arc};

    #[test]
    fn select_signing_algorithm_returns_first_supported_signing_algorithm_when_no_proof_types_supported() {
        // Create a new Wallet.
        let wallet: Wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test"],
            vec![Algorithm::EdDSA],
        )
        .unwrap();

        let signing_algorithm = wallet
            // The Credential Issuer does not supply the `proof_types_supported` parameter, so the Wallet will use its own
            // preferred signing algorithm
            .select_signing_algorithm(&CredentialConfigurationsSupportedObject::default())
            .unwrap();

        assert_eq!(signing_algorithm, Algorithm::EdDSA);
    }

    #[test]
    fn select_signing_algorithm_returns_error_when_issuers_supported_proof_type_is_not_supported() {
        // Create a new Wallet.
        let wallet: Wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test"],
            vec![Algorithm::EdDSA],
        )
        .unwrap();

        let error = wallet
            .select_signing_algorithm(&CredentialConfigurationsSupportedObject {
                proof_types_supported: HashMap::from_iter(vec![(
                    // This Proof Type is not supported in the Wallet (as of now) so the Wallet will return an error.
                    ProofType::Cwt,
                    KeyProofMetadata {
                        proof_signing_alg_values_supported: vec![Algorithm::EdDSA],
                    },
                )]),
                ..Default::default()
            })
            .unwrap_err()
            .to_string();

        assert_eq!(error, "The Credential Issuer does not support JWT proof types");
    }

    #[test]
    fn select_signing_algorithm_returns_error_when_it_cannot_find_matching_signing_algorithm() {
        // Create a new Wallet.
        let wallet: Wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test"],
            vec![Algorithm::EdDSA],
        )
        .unwrap();

        let error = wallet
            .select_signing_algorithm(&CredentialConfigurationsSupportedObject {
                proof_types_supported: HashMap::from_iter(vec![(
                    ProofType::Jwt,
                    KeyProofMetadata {
                        // This proof signing algorithm will not match any of the Wallet's supported signing algorithms.
                        proof_signing_alg_values_supported: vec![Algorithm::RS256],
                    },
                )]),
                ..Default::default()
            })
            .unwrap_err()
            .to_string();

        assert_eq!(error, "No matching supported signing algorithms found.");
    }

    #[test]
    fn select_signing_algorithm_returns_matching_signing_algorithm() {
        // Create a new Wallet.
        let wallet: Wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test"],
            vec![Algorithm::EdDSA],
        )
        .unwrap();

        let signing_algorithm = wallet
            .select_signing_algorithm(&CredentialConfigurationsSupportedObject {
                proof_types_supported: HashMap::from_iter(vec![(
                    // This Proof Type is supported by the Wallet
                    ProofType::Jwt,
                    KeyProofMetadata {
                        // This proof signing algorithm will match the Wallet's supported signing algorithms.
                        proof_signing_alg_values_supported: vec![Algorithm::EdDSA],
                    },
                )]),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(signing_algorithm, Algorithm::EdDSA);
    }
}
