use crate::claims::ClaimRequests;
use crate::{Registration, RequestUrlBuilder, Scope, StandardClaims};
use anyhow::{anyhow, Result};
use derive_more::Display;
use getset::Getters;
use merge::Merge;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::convert::TryInto;
use std::str::FromStr;

/// As specified in the
/// [SIOPv2 specification](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#name-self-issued-openid-provider-a)
/// [`RelyingParty`]'s can either send a request as a query parameter or as a request URI.
/// # Examples
///
/// ```
/// # use siopv2::RequestUrl;
/// # use std::str::FromStr;
///
/// // An example of a form-urlencoded request with only the `request_uri` parameter will be parsed as a
/// // `RequestUrl::RequestUri` variant.
/// let request_url = RequestUrl::from_str("siopv2://idtoken?request_uri=https://example.com/request_uri").unwrap();
/// assert_eq!(
///     request_url,
///     RequestUrl::RequestUri {
///         request_uri: "https://example.com/request_uri".to_owned()
///     }
/// );
///
/// // An example of a form-urlencoded request that is parsed as a `RequestUrl::Request` variant.
/// let request_url = RequestUrl::from_str(
///     "\
///         siopv2://idtoken?\
///             scope=openid\
///             &response_type=id_token\
///             &client_id=did%3Aexample%3AEiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA\
///             &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
///             &response_mode=post\
///             &registration=%7B%22subject_syntax_types_supported%22%3A\
///             %5B%22did%3Amock%22%5D%2C%0A%20%20%20%20\
///             %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
///             &nonce=n-0S6_WzA2Mj\
///     ",
/// )
/// .unwrap();
/// assert!(match request_url {
///    RequestUrl::Request(_) => Ok(()),
///   RequestUrl::RequestUri { .. } => Err(()),
/// }.is_ok());
/// ```
#[derive(Deserialize, Debug, PartialEq, Clone, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum RequestUrl {
    Request(Box<SiopRequest>),
    // TODO: Add client_id parameter.
    RequestUri { request_uri: String },
}

impl RequestUrl {
    pub fn builder() -> RequestUrlBuilder {
        RequestUrlBuilder::new()
    }
}

impl TryInto<SiopRequest> for RequestUrl {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<SiopRequest, Self::Error> {
        match self {
            RequestUrl::Request(request) => Ok(*request),
            RequestUrl::RequestUri { .. } => Err(anyhow!("Request is a request URI.")),
        }
    }
}

impl FromStr for RequestUrl {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = url::Url::parse(s)?;
        let query = url.query().ok_or_else(|| anyhow!("No query found."))?;
        let map = serde_urlencoded::from_str::<Map<String, Value>>(query)?
            .into_iter()
            .filter_map(|(k, v)| match v {
                Value::String(s) => Some(Ok((k, serde_json::from_str(&s).unwrap_or(Value::String(s))))),
                _ => None,
            })
            .collect::<Result<_, anyhow::Error>>()?;
        let request: RequestUrl = serde_json::from_value(Value::Object(map))?;
        Ok(request)
    }
}

/// In order to convert a [`RequestUrl`] to a string, we need to convert all the values to strings. This is because
/// `serde_urlencoded` does not support serializing non-primitive types.
// TODO: Find a way to dynamically generate the `siopv2://idtoken?` part of the URL. This will require some refactoring
// for the `RequestUrl` enum.
impl std::fmt::Display for RequestUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let map: Map<String, Value> = serde_json::to_value(self)
            .map_err(|_| std::fmt::Error)?
            .as_object()
            .ok_or(std::fmt::Error)?
            .iter()
            .filter_map(|(k, v)| match v {
                Value::Object(_) | Value::Array(_) => Some((k.clone(), Value::String(serde_json::to_string(v).ok()?))),
                Value::String(_) => Some((k.clone(), v.clone())),
                _ => None,
            })
            .collect();

        let encoded = serde_urlencoded::to_string(map).map_err(|_| std::fmt::Error)?;
        write!(f, "siopv2://idtoken?{}", encoded)
    }
}

#[derive(Deserialize, Debug, PartialEq, Clone, Serialize, Default, Display)]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    #[default]
    #[display(fmt = "id_token")]
    IdToken,
}

/// [`SiopRequest`] is a request from a [crate::relying_party::RelyingParty] (RP) to a [crate::provider::Provider] (SIOP).
#[allow(dead_code)]
#[derive(Debug, Getters, PartialEq, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiopRequest {
    pub(crate) response_type: ResponseType,
    pub(crate) response_mode: Option<String>,
    #[getset(get = "pub")]
    pub(crate) client_id: String,
    #[getset(get = "pub")]
    pub(crate) scope: Scope,
    #[getset(get = "pub")]
    pub(crate) claims: Option<ClaimRequests>,
    #[getset(get = "pub")]
    pub(crate) redirect_uri: String,
    #[getset(get = "pub")]
    pub(crate) nonce: String,
    #[getset(get = "pub")]
    pub(crate) registration: Option<Registration>,
    pub(crate) iss: Option<String>,
    pub(crate) iat: Option<i64>,
    pub(crate) exp: Option<i64>,
    pub(crate) nbf: Option<i64>,
    pub(crate) jti: Option<String>,
    #[getset(get = "pub")]
    pub(crate) state: Option<String>,
}

impl SiopRequest {
    pub fn is_cross_device_request(&self) -> bool {
        self.response_mode == Some("post".to_owned())
    }

    pub fn subject_syntax_types_supported(&self) -> Option<&Vec<String>> {
        self.registration
            .as_ref()
            .and_then(|r| r.subject_syntax_types_supported().as_ref())
    }

    /// Returns the `id_token` claims from the `claims` parameter including those from the request's scope values.
    pub fn id_token_request_claims(&self) -> Option<StandardClaims> {
        self.claims()
            .as_ref()
            .and_then(|claims| claims.id_token.clone())
            .map(|mut id_token_claims| {
                id_token_claims.merge(self.scope().into());
                id_token_claims
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_request_uri() {
        // A form urlencoded string with a `request_uri` parameter should deserialize into the `RequestUrl::RequestUri` variant.
        let request_url = RequestUrl::from_str("siopv2://idtoken?request_uri=https://example.com/request_uri").unwrap();
        assert_eq!(
            request_url,
            RequestUrl::RequestUri {
                request_uri: "https://example.com/request_uri".to_owned()
            }
        );
    }

    #[test]
    fn test_valid_request() {
        // A form urlencoded string without a `request_uri` parameter should deserialize into the `RequestUrl::Request` variant.
        let request_url = RequestUrl::from_str(
            "\
            siopv2://idtoken?\
                scope=openid\
                &response_type=id_token\
                &client_id=did%3Aexample%3AEiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA\
                &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
                &response_mode=post\
                &registration=%7B%22subject_syntax_types_supported%22%3A\
                %5B%22did%3Amock%22%5D%2C%0A%20%20%20%20\
                %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
                &nonce=n-0S6_WzA2Mj\
            ",
        )
        .unwrap();
        assert_eq!(
            request_url.clone(),
            RequestUrl::Request(Box::new(SiopRequest {
                response_type: ResponseType::IdToken,
                response_mode: Some("post".to_owned()),
                client_id: "did:example:\
                            EiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA"
                    .to_owned(),
                scope: Scope::openid(),
                claims: None,
                redirect_uri: "https://client.example.org/cb".to_owned(),
                nonce: "n-0S6_WzA2Mj".to_owned(),
                registration: Some(
                    Registration::default()
                        .with_subject_syntax_types_supported(vec!["did:mock".to_owned()])
                        .with_id_token_signing_alg_values_supported(vec!["EdDSA".to_owned()]),
                ),
                iss: None,
                iat: None,
                exp: None,
                nbf: None,
                jti: None,
                state: None,
            }))
        );

        assert_eq!(
            request_url,
            RequestUrl::from_str(&RequestUrl::to_string(&request_url)).unwrap()
        );
    }

    #[test]
    fn test_invalid_request() {
        // A form urlencoded string with an otherwise valid request is invalid when the `request_uri` parameter is also
        // present.
        let request_url = RequestUrl::from_str(
            "\
            siopv2://idtoken?\
                scope=openid\
                &response_type=id_token\
                &client_id=did%3Aexample%3AEiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA\
                &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
                &response_mode=post\
                &registration=%7B%22subject_syntax_types_supported%22%3A\
                %5B%22did%3Amock%22%5D%2C%0A%20%20%20%20\
                %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
                &nonce=n-0S6_WzA2Mj\
                &request_uri=https://example.com/request_uri\
            ",
        );
        assert!(request_url.is_err())
    }

    #[test]
    fn test_invalid_request_uri() {
        // A form urlencoded string with a `request_uri` should not have any other parameters.
        let request_url =
            RequestUrl::from_str("siopv2://idtoken?request_uri=https://example.com/request_uri&scope=openid");
        assert!(request_url.is_err(),);
    }
}

#[derive(Deserialize, Getters, Debug)]
pub struct Registration {
    #[getset(get = "pub")]
    subject_syntax_types_supported: Option<Vec<String>>,
    id_token_signing_alg_values_supported: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration() {
        let request_url = RequestUrl::from_str(
            "\
            siopv2://idtoken?\
                scope=openid\
                &response_type=id_token\
                &client_id=did%3Aexample%3AEiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA\
                &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
                &response_mode=post\
                &registration=%7B%22subject_syntax_types_supported%22%3A\
                %5B%22did%3Amock%22%5D%2C%0A%20%20%20%20\
                %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
                &nonce=n-0S6_WzA2Mj\
            ",
        )
        .unwrap();

        assert_eq!(
            RequestUrl::from_str(&RequestUrl::to_string(&request_url)).unwrap(),
            request_url
        );
    }

    #[test]
    fn test_valid_request_uri() {
        // A form urlencoded string with a `request_uri` parameter should deserialize into the `RequestUrl::RequestUri` variant.
        let request_url = RequestUrl::from_str("siopv2://idtoken?request_uri=https://example.com/request_uri").unwrap();
        assert_eq!(
            request_url,
            RequestUrl::RequestUri {
                request_uri: "https://example.com/request_uri".to_owned()
            }
        );
    }

    #[test]
    fn test_valid_request() {
        // A form urlencoded string without a `request_uri` parameter should deserialize into the `RequestUrl::Request` variant.
        let request_url = RequestUrl::from_str(
            "\
            siopv2://idtoken?\
                scope=openid\
                &response_type=id_token\
                &client_id=did%3Aexample%3AEiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA\
                &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
                &response_mode=post\
                &registration=%7B%22subject_syntax_types_supported%22%3A\
                %5B%22did%3Amock%22%5D%2C%0A%20%20%20%20\
                %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
                &nonce=n-0S6_WzA2Mj\
            ",
        )
        .unwrap();
        assert_eq!(
            request_url.clone(),
            RequestUrl::Request(Box::new(SiopRequest {
                response_type: ResponseType::IdToken,
                response_mode: Some("post".to_owned()),
                client_id: "did:example:\
                            EiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA"
                    .to_owned(),
                scope: "openid".to_owned(),
                claims: None,
                redirect_uri: "https://client.example.org/cb".to_owned(),
                nonce: "n-0S6_WzA2Mj".to_owned(),
                registration: Some(Registration {
                    subject_syntax_types_supported: Some(vec!["did:mock".to_owned()]),
                    id_token_signing_alg_values_supported: Some(vec!["EdDSA".to_owned()]),
                }),
                iss: None,
                iat: None,
                exp: None,
                nbf: None,
                jti: None,
                state: None,
            }))
        );

        assert_eq!(
            request_url,
            RequestUrl::from_str(&RequestUrl::to_string(&request_url)).unwrap()
        );
    }

    #[test]
    fn test_invalid_request() {
        // A form urlencoded string with an otherwise valid request is invalid when the `request_uri` parameter is also
        // present.
        let request_url = RequestUrl::from_str(
            "\
            siopv2://idtoken?\
                scope=openid\
                &response_type=id_token\
                &client_id=did%3Aexample%3AEiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA\
                &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
                &response_mode=post\
                &registration=%7B%22subject_syntax_types_supported%22%3A\
                %5B%22did%3Amock%22%5D%2C%0A%20%20%20%20\
                %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
                &nonce=n-0S6_WzA2Mj\
                &request_uri=https://example.com/request_uri\
            ",
        );
        assert!(request_url.is_err())
    }

    #[test]
    fn test_invalid_request_uri() {
        // A form urlencoded string with a `request_uri` should not have any other parameters.
        let request_url =
            RequestUrl::from_str("siopv2://idtoken?request_uri=https://example.com/request_uri&scope=openid");
        assert!(request_url.is_err(),);
    }
}
