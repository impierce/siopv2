use crate::credential_format;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::CredentialSubject;

credential_format!("jwt_vc_json-ld", JwtVcJsonLd, {
    credential_definition: CredentialDefinition,
    order: Option<Vec<String>>
});

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct CredentialDefinition {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub type_: Vec<String>,
    #[serde(flatten)]
    pub credential_subject: CredentialSubject,
}
