use crate::authorization_request::{
    AuthorizationRequestBuilder, AuthorizationRequestParameters, ClientMetadataParameters,
};
use crate::oid4vp_params::{serde_oid4vp_response, Oid4vpParams};
use crate::token::vp_token::VpToken;
use chrono::{Duration, Utc};
use dif_presentation_exchange::presentation_definition::ClaimFormatProperty;
pub use dif_presentation_exchange::{
    evaluate_input, ClaimFormatDesignation, InputDescriptor, InputDescriptorMappingObject, PathNested,
    PresentationDefinition, PresentationSubmission,
};
use futures::future::join_all;
use identity_credential::{credential::Jwt, presentation::Presentation};
use jsonwebtoken::{Algorithm, Header};
use oid4vc_core::client_metadata::ClientMetadataResource;
use oid4vc_core::openid4vc_extension::{OpenID4VC, RequestHandle, ResponseHandle};
use oid4vc_core::{authorization_response::AuthorizationResponse, jwt, openid4vc_extension::Extension, Subject};
use oid4vc_core::{SubjectSyntaxType, Validator};
use oid4vci::VerifiableCredentialJwt;
use reqwest_middleware::ClientBuilder;
use reqwest_retry::policies::ExponentialBackoff;
use reqwest_retry::RetryTransientMiddleware;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;

/// This is the [`RequestHandle`] for the [`OID4VP`] extension.
#[derive(Debug, PartialEq, Clone)]
pub struct RequestHandler {}
impl RequestHandle for RequestHandler {
    type Parameters = AuthorizationRequestParameters;
    type Builder = AuthorizationRequestBuilder;
}

/// This is the [`ResponseHandle`] for the [`OID4VP`] extension.
#[derive(Debug, PartialEq, Clone)]
pub struct ResponseHandler {}
impl ResponseHandle for ResponseHandler {
    type Input = AuthorizationResponseInput;
    type Parameters = AuthorizationResponseParameters;
    type ResponseItem = Vec<VerifiableCredentialJwt>;
}

/// This is the [`Extension`] implementation for the [`OID4VP`] extension.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct OID4VP;
impl OpenID4VC for OID4VP {}
impl Extension for OID4VP {
    type RequestHandle = RequestHandler;
    type ResponseHandle = ResponseHandler;

    async fn generate_token(
        subject: Arc<dyn Subject>,
        client_id: &str,
        extension_parameters: &<Self::RequestHandle as RequestHandle>::Parameters,
        user_input: &<Self::ResponseHandle as ResponseHandle>::Input,
        subject_syntax_type: impl TryInto<SubjectSyntaxType>,
        signing_algorithm: impl TryInto<Algorithm>,
    ) -> anyhow::Result<Vec<String>> {
        let signing_algorithm = signing_algorithm
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert the signing algorithm"))?;

        let subject_syntax_type_string = subject_syntax_type
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert the subject syntax type"))?
            .to_string();
        let subject_identifier = subject
            .identifier(&subject_syntax_type_string, signing_algorithm)
            .await?;

        let mut jwts = vec![];
        match &user_input.verifiable_presentation_input {
            PresentationInputType::Unsigned(verifiable_presentation) => {
                let vp_token = VpToken::builder()
                    .iss(subject_identifier.clone())
                    .sub(subject_identifier.clone())
                    .aud(client_id)
                    .nonce(extension_parameters.nonce.to_owned())
                    // TODO: make this configurable.
                    .exp((Utc::now() + Duration::minutes(10)).timestamp())
                    .iat((Utc::now()).timestamp())
                    .verifiable_presentation(verifiable_presentation.clone())
                    .build()?;

                let jwt = jwt::encode(
                    subject.clone(),
                    Header::new(signing_algorithm),
                    vp_token,
                    &subject_syntax_type_string,
                )
                .await?;

                jwts.push(jwt);
            }
            PresentationInputType::Signed(jwt) => {
                jwts.push(jwt.to_owned());
            }
        }

        Ok(jwts)
    }

    // TODO: combine this function with `get_relying_party_supported_syntax_types`.
    async fn get_relying_party_supported_algorithms(
        authorization_request: &<Self::RequestHandle as RequestHandle>::Parameters,
    ) -> anyhow::Result<Vec<Algorithm>> {
        let client_metadata = match &authorization_request.client_metadata {
            // Fetch the client metadata from the given URI.
            ClientMetadataResource::ClientMetadataUri(client_metadata_uri) => {
                let retry_policy = ExponentialBackoff::builder().build_with_max_retries(5);
                let client = ClientBuilder::new(reqwest::Client::new())
                    .with(RetryTransientMiddleware::new_with_policy(retry_policy))
                    .build();
                let client_metadata: ClientMetadataResource<ClientMetadataParameters> =
                    client.get(client_metadata_uri).send().await?.json().await?;
                client_metadata
            }
            client_metadata => client_metadata.clone(),
        };

        // TODO: in this current solution we assume that if there is a`ClaimFormatDesignation::JwtVcJson` `alg` present
        // in the client_metadata that this same `alg` will apply for the signing of all the credentials and the VP as
        // well as the Proof of Possession.
        match client_metadata {
            // Fetch the client metadata from the given URI.
            ClientMetadataResource::ClientMetadataUri(_) => unreachable!(),
            ClientMetadataResource::ClientMetadata { extension, .. } => extension
                .vp_formats
                .get(&ClaimFormatDesignation::JwtVcJson)
                .or_else(|| extension.vp_formats.get(&ClaimFormatDesignation::VcSdJwt))
                .and_then(|claim_format_property| match claim_format_property {
                    ClaimFormatProperty::Alg(algs) => Some(algs.clone()),
                    // TODO: implement `ProofType`.
                    ClaimFormatProperty::ProofType(_) => None,
                    ClaimFormatProperty::SdJwt {
                        sd_jwt_alg_values,
                        // TODO: implement Key Binding
                        kb_jwt_alg_values: _kb_jwt_alg_values,
                    } => Some(sd_jwt_alg_values.clone()),
                })
                .ok_or(anyhow::anyhow!("No supported algorithms found.")),
        }
    }

    async fn get_relying_party_supported_syntax_types(
        authorization_request: &<Self::RequestHandle as RequestHandle>::Parameters,
    ) -> anyhow::Result<Vec<SubjectSyntaxType>> {
        let client_metadata = match &authorization_request.client_metadata {
            ClientMetadataResource::ClientMetadataUri(client_metadata_uri) => {
                let retry_policy = ExponentialBackoff::builder().build_with_max_retries(5);
                let client = ClientBuilder::new(reqwest::Client::new())
                    .with(RetryTransientMiddleware::new_with_policy(retry_policy))
                    .build();
                let client_metadata: ClientMetadataResource<ClientMetadataParameters> =
                    client.get(client_metadata_uri).send().await?.json().await?;
                client_metadata
            }
            client_metadata => client_metadata.clone(),
        };

        match client_metadata {
            ClientMetadataResource::ClientMetadataUri(_) => unreachable!(),
            ClientMetadataResource::ClientMetadata { other, .. } => {
                let subject_syntax_types_supported: Vec<SubjectSyntaxType> = other
                    // TODO(ngdil): this is a custom implementation at the moment as `subject_syntax_types_supported` is
                    // strictly a `SIOPv2` Client Metadata parameter and is not mentioned in the `OID4VP` documentation. It
                    // is expected that that a similar parameter will be added to the `OID4VP` Client Metadata.
                    .get("subject_syntax_types_supported")
                    .and_then(|subject_syntax_types_supported| {
                        subject_syntax_types_supported
                            .as_array()
                            .and_then(|subject_syntax_types_supported| {
                                subject_syntax_types_supported
                                    .iter()
                                    .map(|subject_syntax_type| {
                                        subject_syntax_type.as_str().map(|subject_syntax_type| {
                                            SubjectSyntaxType::from_str(subject_syntax_type).unwrap()
                                        })
                                    })
                                    .collect()
                            })
                    })
                    .unwrap_or_default();

                Ok(subject_syntax_types_supported)
            }
        }
    }

    fn build_authorization_response(
        jwts: Vec<String>,
        user_input: <Self::ResponseHandle as ResponseHandle>::Input,
        redirect_uri: String,
        state: Option<String>,
    ) -> anyhow::Result<AuthorizationResponse<Self>> {
        Ok(AuthorizationResponse {
            redirect_uri,
            state,
            extension: AuthorizationResponseParameters {
                oid4vp_parameters: Oid4vpParams::Params {
                    vp_token: jwts.first().unwrap().to_owned(),
                    presentation_submission: user_input.presentation_submission,
                },
            },
        })
    }

    async fn decode_authorization_response(
        validator: Validator,
        response: &AuthorizationResponse<Self>,
    ) -> anyhow::Result<<Self::ResponseHandle as ResponseHandle>::ResponseItem> {
        let vp_token: VpToken = match &response.extension.oid4vp_parameters {
            Oid4vpParams::Jwt { .. } => todo!(),
            Oid4vpParams::Params { vp_token, .. } => validator.decode(vp_token.to_owned()).await?,
        };

        join_all(
            vp_token
                .verifiable_presentation()
                .verifiable_credential
                .iter()
                .map(|vc| validator.decode(vc.as_str().to_owned()))
                .collect::<Vec<_>>(),
        )
        .await
        .into_iter()
        .collect()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct AuthorizationResponseParameters {
    #[serde(flatten, with = "serde_oid4vp_response")]
    pub oid4vp_parameters: Oid4vpParams,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct AuthorizationResponseInput {
    pub verifiable_presentation_input: PresentationInputType,
    pub presentation_submission: PresentationSubmission,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum PresentationInputType {
    Unsigned(Presentation<Jwt>),
    Signed(String),
}
