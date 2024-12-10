use crate::siopv2::SIOPv2;
use anyhow::Result;
use jsonwebtoken::{Algorithm, Header};
use oid4vc_core::{
    authentication::subject::SigningSubject,
    authorization_request::{AuthorizationRequest, Object},
    authorization_response::AuthorizationResponse,
    jwt,
    openid4vc_extension::{Extension, ResponseHandle},
    SubjectSyntaxType, Validator,
};
use std::collections::HashMap;

pub struct RelyingParty {
    // TODO: Strictly speaking a relying party doesn't need to have a [`Subject`]. It just needs methods to
    // sign and verify tokens. For simplicity we use a [`Subject`] here for now but we should consider a cleaner solution.
    pub subject: SigningSubject,
    pub default_subject_syntax_type: SubjectSyntaxType,
    pub sessions: HashMap<(String, String), AuthorizationRequest<Object<SIOPv2>>>,
}

impl RelyingParty {
    // TODO: Use RelyingPartyBuilder instead.
    pub fn new(subject: SigningSubject, default_subject_syntax_type: impl TryInto<SubjectSyntaxType>) -> Result<Self> {
        Ok(RelyingParty {
            subject,
            default_subject_syntax_type: default_subject_syntax_type
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid did method."))?,
            sessions: HashMap::new(),
        })
    }

    pub async fn encode<E: Extension>(
        &self,
        authorization_request: &AuthorizationRequest<Object<E>>,
        signing_algorithm: impl TryInto<Algorithm>,
    ) -> Result<String> {
        let mut header = Header::new(
            signing_algorithm
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid signing algorithm."))?,
        );
        header.typ = Some("oauth-authz-req+jwt".to_string());
        jwt::encode(
            self.subject.clone(),
            header,
            authorization_request,
            &self.default_subject_syntax_type.to_string(),
        )
        .await
    }

    /// Validates a [`AuthorizationResponse`] by decoding the header of the id_token, fetching the public key corresponding to
    /// the key identifier and finally decoding the id_token using the public key and by validating the signature.
    pub async fn validate_response<E: Extension>(
        &self,
        authorization_response: &AuthorizationResponse<E>,
    ) -> Result<<E::ResponseHandle as ResponseHandle>::ResponseItem> {
        E::decode_authorization_response(Validator::Subject(self.subject.clone()), authorization_response).await
    }
}
