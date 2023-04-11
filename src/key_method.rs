use anyhow::{anyhow, Result};
use async_trait::async_trait;
use did_key::{generate, resolve, Config, CoreSign, DIDCore, Document, Ed25519KeyPair, KeyMaterial, PatchedKeyPair};

use crate::{Subject, Validator};

/// This [`KeySubject`] implements the [`Subject`] trait and can be used as a subject for a [`Provider`]. It uses the
/// 'key' DID method.
pub struct KeySubject {
    keypair: PatchedKeyPair,
    document: Document,
}

impl KeySubject {
    /// Creates a new [`KeySubject`].
    pub fn new() -> Self {
        let keypair = generate::<Ed25519KeyPair>(None);
        let document = keypair.get_did_document(Config::default());
        KeySubject { keypair, document }
    }

    /// Creates a new [`KeySubject`] from a [`PatchedKeyPair`].
    pub fn from_keypair(keypair: PatchedKeyPair) -> Self {
        let document = keypair.get_did_document(Config::default());
        KeySubject { keypair, document }
    }
}

impl Default for KeySubject {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Subject for KeySubject {
    fn did(&self) -> Result<did_url::DID> {
        Ok(did_url::DID::parse(self.document.id.clone())?)
    }

    fn key_identifier(&self) -> Option<String> {
        self.document
            .authentication
            .as_ref()
            .and_then(|authentication_methods| authentication_methods.get(0).cloned())
    }

    async fn sign<'a>(&self, message: &'a str) -> Result<Vec<u8>> {
        Ok(self.keypair.sign(message.as_bytes()).to_vec())
    }
}

/// This [`KeyValidator`] implements the [`Validator`] trait and can be used as a validator for a [`RelyingParty`]. It uses
/// the 'key' DID method.
#[derive(Default)]
pub struct KeyValidator;

impl KeyValidator {
    pub fn new() -> Self {
        KeyValidator {}
    }
}

#[async_trait]
impl Validator for KeyValidator {
    async fn public_key<'a>(&self, kid: &'a str) -> Result<Vec<u8>> {
        let keypair = resolve(kid).map_err(|_| anyhow!("Failed to resolve the key identifier"))?;
        let authentication_method = keypair
            .get_did_document(Config::default())
            .authentication
            .and_then(|authentication_methods| authentication_methods.get(0).cloned())
            .ok_or(anyhow!("No public key found"))?;
        PatchedKeyPair::try_from(authentication_method.as_str())
            .map(|keypair| keypair.public_key_bytes())
            .map_err(|_| anyhow!("Failed to construct keypair from the default authentication method"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IdToken, Provider, RelyingParty, SiopRequest};
    use chrono::{Duration, Utc};

    #[tokio::test]
    async fn test_key_subject() {
        // Create a new subject.
        let subject = KeySubject::new();

        // Create a new provider.
        let provider = Provider::new(subject).await.unwrap();

        // Get a new SIOP request with response mode `post` for cross-device communication.
        let request: SiopRequest = serde_qs::from_str(
            "\
                response_type=id_token\
                &response_mode=post\
                &client_id=did:key:z6MkiTcXZ1JxooACo99YcfkugH6Kifzj7ZupSDCmLEABpjpF\
                &redirect_uri=http://127.0.0.1:4200/redirect_uri\
                &scope=openid\
                &nonce=n-0S6_WzA2Mj\
                &subject_syntax_types_supported[0]=did%3Akey\
            ",
        )
        .unwrap();

        // The provider generates a signed SIOP response from the new SIOP request.
        let response = provider.generate_response(request).await.unwrap();

        // Let the relying party validate the response.
        let relying_party = RelyingParty::new(KeyValidator::new());
        let id_token = relying_party.validate_response(&response).await.unwrap();

        let IdToken { aud, nonce, .. } = IdToken::new(
            "".to_string(),
            "".to_string(),
            "did:key:z6MkiTcXZ1JxooACo99YcfkugH6Kifzj7ZupSDCmLEABpjpF".to_string(),
            "n-0S6_WzA2Mj".to_string(),
            (Utc::now() + Duration::minutes(10)).timestamp(),
        );
        assert_eq!(id_token.iss, id_token.sub);
        assert_eq!(id_token.aud, aud);
        assert_eq!(id_token.nonce, nonce);
    }
}