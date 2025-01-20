use anyhow::Result;
use jsonwebtoken::Algorithm;
use oid4vc_core::{
    authorization_request::{AuthorizationRequest, Object},
    authorization_response::AuthorizationResponse,
    openid4vc_extension::{Extension, OpenID4VC, ResponseHandle},
    Subject, SubjectSyntaxType,
};
use reqwest::StatusCode;
use siopv2::Provider;
use std::sync::Arc;

/// Manager struct for [`siopv2::Provider`].
#[derive(Debug)]
pub struct ProviderManager {
    pub provider: Provider,
}

impl ProviderManager {
    pub fn new(
        subject: Arc<dyn Subject>,
        supported_subject_syntax_types: Vec<impl TryInto<SubjectSyntaxType>>,
        supported_signing_algorithms: Vec<Algorithm>,
    ) -> Result<Self> {
        Ok(Self {
            provider: Provider::new(subject, supported_subject_syntax_types, supported_signing_algorithms)?,
        })
    }

    pub async fn validate_request(&self, authorization_request: String) -> Result<AuthorizationRequest<Object>> {
        self.provider.validate_request(authorization_request).await
    }

    pub async fn get_matching_signing_algorithm<E: Extension>(
        &self,
        authorization_request: &AuthorizationRequest<Object<E>>,
    ) -> Result<Algorithm> {
        self.provider
            .get_matching_signing_algorithm(authorization_request)
            .await
    }

    pub async fn get_matching_subject_syntax_type<E: Extension>(
        &self,
        authorization_request: &AuthorizationRequest<Object<E>>,
    ) -> Result<SubjectSyntaxType> {
        self.provider
            .get_matching_subject_syntax_type(authorization_request)
            .await
    }

    pub async fn generate_response<E: Extension + OpenID4VC>(
        &self,
        authorization_request: &AuthorizationRequest<Object<E>>,
        input: <E::ResponseHandle as ResponseHandle>::Input,
    ) -> Result<AuthorizationResponse<E>> {
        self.provider.generate_response(authorization_request, input).await
    }

    pub async fn send_response<E: Extension>(
        &self,
        authorization_response: &AuthorizationResponse<E>,
    ) -> Result<StatusCode> {
        self.provider.send_response(authorization_response).await
    }

    pub fn default_subject_syntax_types(&self) -> &Vec<SubjectSyntaxType> {
        &self.provider.supported_subject_syntax_types
    }
}
