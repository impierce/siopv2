use crate::credential_format;

credential_format!("vc+sd-jwt", VcSdJwt, {
    vct: String,
    claims: Option<serde_json::Value>,
    order: Option<Vec<String>>
});
