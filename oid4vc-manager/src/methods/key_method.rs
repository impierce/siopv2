use anyhow::{anyhow, Result};
use async_trait::async_trait;
use derivative::Derivative;
use did_key::{generate, resolve, Config, CoreSign, DIDCore, Document, Ed25519KeyPair, KeyMaterial, PatchedKeyPair};
use jsonwebtoken::Algorithm;
use oid4vc_core::{authentication::sign::ExternalSign, Sign, Subject, Verify};
use std::sync::Arc;

/// This [`KeySubject`] implements the [`Subject`] trait and can be used as a subject for a [`Provider`]. It uses the
/// 'key' DID method.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct KeySubject {
    #[derivative(Debug = "ignore")]
    keypair: PatchedKeyPair,
    document: Document,
    external_signer: Option<Arc<dyn ExternalSign>>,
}

impl KeySubject {
    /// Creates a new [`KeySubject`].
    pub fn new() -> Self {
        let keypair = generate::<Ed25519KeyPair>(None);
        let document = keypair.get_did_document(Config::default());
        KeySubject {
            keypair,
            document,
            external_signer: None,
        }
    }

    /// Creates a new [`KeySubject`] from a [`PatchedKeyPair`].
    pub fn from_keypair(keypair: PatchedKeyPair, external_signer: Option<Arc<dyn ExternalSign>>) -> Self {
        let document = keypair.get_did_document(Config::default());
        KeySubject {
            keypair,
            document,
            external_signer,
        }
    }
}

impl Default for KeySubject {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Sign for KeySubject {
    async fn key_id(&self, _subject_syntax_type: &str, _algorithm: Algorithm) -> Option<String> {
        self.document
            .authentication
            .as_ref()
            .and_then(|authentication_methods| authentication_methods.first().cloned())
    }

    async fn sign(&self, message: &str, _subject_syntax_type: &str, _algorithm: Algorithm) -> Result<Vec<u8>> {
        match self.external_signer() {
            Some(external_signer) => external_signer.sign(message),
            None => Ok(self.keypair.sign(message.as_bytes())),
        }
    }

    fn external_signer(&self) -> Option<Arc<dyn ExternalSign>> {
        self.external_signer.clone()
    }
}

#[async_trait]
impl Verify for KeySubject {
    async fn public_key(&self, kid: &str) -> Result<Vec<u8>> {
        Ok(resolve_public_key(kid).await?)
    }
}

#[async_trait]
impl Subject for KeySubject {
    async fn identifier(&self, _subject_syntax_type: &str, _algorithm: Algorithm) -> Result<String> {
        Ok(self.document.id.clone())
    }
}

/// This [`KeyValidator`] implements the [`Verify`] trait and can be used as a validator for a [`RelyingParty`]. It uses
/// the 'key' DID method.
#[derive(Default)]
pub struct KeyValidator;

impl KeyValidator {
    pub fn new() -> Self {
        KeyValidator {}
    }
}

#[async_trait]
impl Verify for KeyValidator {
    async fn public_key(&self, kid: &str) -> Result<Vec<u8>> {
        Ok(resolve_public_key(kid).await?)
    }
}

/// Resolves the public key from the given key identifier.
async fn resolve_public_key(kid: &str) -> Result<Vec<u8>> {
    let keypair = resolve(kid).map_err(|_| anyhow!("Failed to resolve the key identifier"))?;
    let authentication_method = keypair
        .get_did_document(Config::default())
        .authentication
        .and_then(|authentication_methods| authentication_methods.first().cloned())
        .ok_or(anyhow!("No public key found"))?;
    PatchedKeyPair::try_from(authentication_method.as_str())
        .map(|keypair| keypair.public_key_bytes())
        .map_err(|_| anyhow!("Failed to construct keypair from the default authentication method"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProviderManager, RelyingPartyManager};
    use jsonwebtoken::Algorithm;
    use oid4vc_core::authorization_request::{AuthorizationRequest, Object};
    use siopv2::siopv2::SIOPv2;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_key_subject() {
        // Create a new subject.
        let subject = KeySubject::new();

        // Create a new provider manager.
        let provider_manager =
            ProviderManager::new(Arc::new(subject), vec!["did:key"], vec![Algorithm::EdDSA]).unwrap();

        // Get a new SIOP authorization_request with response mode `direct_post` for cross-device communication.
        let request_url = "\
            siopv2://idtoken?\
                scope=openid\
                &response_type=id_token\
                &client_id=did:key:z6MkiTcXZ1JxooACo99YcfkugH6Kifzj7ZupSDCmLEABpjpF\
                &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
                &response_mode=direct_post\
                &client_metadata=%7B%22subject_syntax_types_supported%22%3A\
                %5B%22did%3Akey%22%5D%2C%0A%20%20%20%20\
                %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
                &nonce=n-0S6_WzA2Mj\
            ";

        // Let the provider manager validate the authorization_request.
        let authorization_request = provider_manager
            .validate_request(request_url.to_string())
            .await
            .unwrap();

        let authorization_request =
            AuthorizationRequest::<Object<SIOPv2>>::from_generic(&authorization_request).unwrap();

        // Test whether the provider manager can generate a authorization_response for the authorization_request succesfully.
        let authorization_response = provider_manager
            .generate_response(&authorization_request, Default::default())
            .await
            .unwrap();

        // Let the relying party validate the authorization_response.
        let relying_party_manager =
            RelyingPartyManager::new(Arc::new(KeySubject::new()), "did:key", vec![Algorithm::EdDSA]).unwrap();
        assert!(relying_party_manager
            .validate_response(&authorization_response)
            .await
            .is_ok());
    }
}
