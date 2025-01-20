use anyhow::Result;
use async_trait::async_trait;
use jsonwebtoken::Algorithm;
use std::{fmt::Debug, sync::Arc};

#[async_trait]
pub trait Sign: Send + Sync {
    // TODO: add this?
    // fn jwt_alg_name() -> &'static str;
    async fn key_id(&self, subject_syntax_type: &str, algorithm: Algorithm) -> Option<String>;
    async fn sign(&self, message: &str, subject_syntax_type: &str, algorithm: Algorithm) -> Result<Vec<u8>>;
    fn external_signer(&self) -> Option<Arc<dyn ExternalSign>>;
}

pub trait ExternalSign: Send + Sync + Debug{
    fn sign(&self, message: &str) -> Result<Vec<u8>>;
}
