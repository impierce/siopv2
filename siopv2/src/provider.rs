use anyhow::Result;
use oid4vc_core::{
    authentication::subject::SigningSubject,
    authorization_request::{AuthorizationRequest, AuthorizationRequestObject},
    authorization_response::AuthorizationResponse,
    openid4vc_extension::Extension,
    Decoder,
};
use reqwest::StatusCode;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};

/// A Self-Issued OpenID Provider (SIOP), which is responsible for generating and signing [`IdToken`]'s in response to
/// [`AuthorizationRequest`]'s from [crate::relying_party::RelyingParty]'s (RPs). The [`Provider`] acts as a trusted intermediary between the RPs and
/// the user who is trying to authenticate.
pub struct Provider {
    pub subject: SigningSubject,
    client: ClientWithMiddleware,
}

impl Provider {
    // TODO: Use ProviderBuilder instead.
    pub fn new(subject: SigningSubject) -> Result<Self> {
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(5);
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();
        Ok(Provider { subject, client })
    }

    /// TODO: Add more validation rules.
    /// Takes a [`RequestUrl`] and returns a [`AuthorizationRequest`]. The [`RequestUrl`] can either be a [`AuthorizationRequest`] or a
    /// request by value. If the [`RequestUrl`] is a request by value, the request is decoded by the [`Subject`] of the [`Provider`].
    /// If the request is valid, the request is returned.
    pub async fn validate_request<E: Extension>(
        &self,
        authorization_request: AuthorizationRequest,
        decoder: Decoder,
    ) -> Result<AuthorizationRequestObject<E>> {
        if let AuthorizationRequest::Object(authorization_request) = authorization_request {
            E::from_generic(*authorization_request)
        } else {
            let (request_object, client_id) = match authorization_request {
                AuthorizationRequest::ByReference { request_uri, client_id } => {
                    let builder = self.client.get(request_uri);
                    let request_value = builder.send().await?.text().await?;
                    (request_value, client_id)
                }
                AuthorizationRequest::ByValue { request, client_id } => (request, client_id),
                _ => unreachable!(),
            };
            let authorization_request: AuthorizationRequestObject<E> = decoder.decode(request_object).await?;
            anyhow::ensure!(authorization_request.client_id == client_id, "Client id mismatch.");
            Ok(authorization_request)
        }
    }

    /// Generates an [`AuthorizationResponse`] in response to an [`AuthorizationRequest`] and the user's claims. The [`AuthorizationResponse`]
    /// contains an [`IdToken`], which is signed by the [`Subject`] of the [`Provider`].
    pub fn generate_response<E: Extension>(
        &self,
        authorization_request: &AuthorizationRequestObject<E>,
        user_claims: E::AuthorizationResponseInput,
    ) -> Result<AuthorizationResponse<E>> {
        let redirect_uri = authorization_request.redirect_uri.to_string();
        let state = authorization_request.state.clone();

        let jwts = E::generate_token(
            self.subject.clone(),
            &authorization_request.client_id,
            &authorization_request.extension,
            &user_claims,
        )?;

        E::build_authorization_response(jwts, user_claims, redirect_uri, state)
    }

    pub async fn send_response<E: Extension>(
        &self,
        authorization_response: &AuthorizationResponse<E>,
    ) -> Result<StatusCode> {
        Ok(self
            .client
            .post(authorization_response.redirect_uri.clone())
            .form(&authorization_response)
            .send()
            .await?
            .status())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{siopv2::SIOPv2, test_utils::TestSubject};
    use oid4vc_core::{Subject, SubjectSyntaxType, Validator, Validators};
    use std::{str::FromStr, sync::Arc};

    #[tokio::test]
    async fn test_provider() {
        // Create a new subject and validator.
        let subject = TestSubject::new("did:test:123".to_string(), "key_id".to_string()).unwrap();

        // Create a new provider.
        let provider = Provider::new(Arc::new(subject)).unwrap();

        // Get a new SIOP authorization_request with response mode `direct_post` for cross-device communication.
        let request_url = "\
            siopv2://idtoken?\
                scope=openid\
                &response_type=id_token\
                &client_id=did%3Aexample%3AEiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA\
                &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
                &response_mode=direct_post\
                &client_metadata=%7B%22subject_syntax_types_supported%22%3A\
                %5B%22did%3Atest%22%5D%2C%0A%20%20%20%20\
                %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
                &nonce=n-0S6_WzA2Mj\
            ";

        // Let the provider validate the authorization_request.
        let authorization_request: AuthorizationRequestObject<SIOPv2> = provider
            .validate_request(
                request_url.parse().unwrap(),
                Decoder {
                    validators: Validators::from([(
                        SubjectSyntaxType::from_str("did:test").unwrap(),
                        Arc::new(Validator::Subject(Arc::new(TestSubject::default()) as Arc<dyn Subject>)),
                    )]),
                },
            )
            .await
            .unwrap();

        // Test whether the provider can generate a authorization_response for the authorization_request succesfully.
        assert!(provider
            .generate_response(&authorization_request, Default::default())
            .is_ok());
    }
}
