use crate::credentials_supported::CredentialsSupportedJson;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CredentialIssuerMetadata {
    pub credential_issuer: Url,
    pub authorization_server: Option<Url>,
    pub credential_endpoint: Url,
    pub batch_credential_endpoint: Option<Url>,
    pub deferred_credential_endpoint: Option<Url>,
    pub credentials_supported: Vec<CredentialsSupportedJson>,
    pub display: Option<Vec<serde_json::Value>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CredentialsSupportedDisplay {
    name: String,
    locale: Option<String>,
    logo: Option<Logo>,
    description: Option<String>,
    background_color: Option<String>,
    text_color: Option<String>,
    #[serde(flatten)]
    other: Option<Map<String, Value>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Logo {
    url: Option<Url>,
    alt_text: Option<String>,
    #[serde(flatten)]
    other: Option<Map<String, Value>>,
}