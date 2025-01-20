use crate::{StandardClaimsRequests, StandardClaimsValues};
use anyhow::Result;
use async_trait::async_trait;
use derivative::{self, Derivative};
use ed25519_dalek::{Signature, Signer, SigningKey};
use jsonwebtoken::Algorithm;
use lazy_static::lazy_static;
use oid4vc_core::{authentication::sign::ExternalSign, Sign, Subject, Verify};
use rand::rngs::OsRng;
use std::sync::Arc;

// SigningKey for mocking purposes.
lazy_static! {
    pub static ref TEST_KEYPAIR: SigningKey = SigningKey::generate(&mut OsRng);
}

#[derive(Derivative, Debug)]
#[derivative(Default)]
pub struct TestSubject {
    #[derivative(Default(value = "did_url::DID::parse(\"did:test:123\").unwrap()"))]
    pub did: did_url::DID,
    pub key_id: String,
}

impl TestSubject {
    pub fn new(did: String, key_id: String) -> Result<Self> {
        Ok(TestSubject {
            did: did_url::DID::parse(did)?,
            key_id,
        })
    }
}

#[async_trait]
impl Sign for TestSubject {
    async fn key_id(&self, _subject_syntax_type: &str, _algorithm: Algorithm) -> Option<String> {
        Some(self.key_id.clone())
    }

    async fn sign(&self, message: &str, _subject_syntax_type: &str, _algorithm: Algorithm) -> Result<Vec<u8>> {
        let signature: Signature = TEST_KEYPAIR.sign(message.as_bytes());
        Ok(signature.to_bytes().to_vec())
    }

    fn external_signer(&self) -> Option<Arc<dyn ExternalSign>> {
        None
    }
}

#[async_trait]
impl Verify for TestSubject {
    async fn public_key(&self, _kid: &str) -> Result<Vec<u8>> {
        Ok(TEST_KEYPAIR.verifying_key().to_bytes().to_vec())
    }
}

#[async_trait]
impl Subject for TestSubject {
    async fn identifier(&self, _subject_syntax_type: &str, _algorithm: Algorithm) -> Result<String> {
        Ok(self.did.to_string())
    }
}

pub struct MockVerifier;

impl MockVerifier {
    pub fn new() -> Self {
        MockVerifier {}
    }
}

#[async_trait]
impl Verify for MockVerifier {
    async fn public_key(&self, _kid: &str) -> Result<Vec<u8>> {
        Ok(TEST_KEYPAIR.verifying_key().to_bytes().to_vec())
    }
}

pub trait Storage {
    fn fetch_claims(&self, request_claims: &StandardClaimsRequests) -> StandardClaimsValues;
}

#[derive(Default, Debug)]
pub struct MemoryStorage {
    data: StandardClaimsValues,
}

impl MemoryStorage {
    pub fn new(data: StandardClaimsValues) -> Self {
        MemoryStorage { data }
    }
}

impl Storage for MemoryStorage {
    fn fetch_claims(&self, request_claims: &StandardClaimsRequests) -> StandardClaimsValues {
        let mut present = StandardClaimsValues::default();

        macro_rules! present_if {
            ($claim:ident) => {
                if request_claims.$claim.is_some() {
                    present.$claim = self.data.$claim.clone();
                }
            };
        }

        present_if!(name);
        present_if!(family_name);
        present_if!(given_name);
        present_if!(middle_name);
        present_if!(nickname);
        present_if!(preferred_username);
        present_if!(profile);
        present_if!(picture);
        present_if!(website);
        present_if!(gender);
        present_if!(birthdate);
        present_if!(zoneinfo);
        present_if!(locale);
        present_if!(updated_at);
        present_if!(email);
        present_if!(email_verified);
        present_if!(address);
        present_if!(phone_number);
        present_if!(phone_number_verified);

        present
    }
}
