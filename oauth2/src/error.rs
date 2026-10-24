use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use std::error::Error;
use std::fmt::{Debug, Display, Formatter};

/// Server Error Response
///
/// See [Section 5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2) of RFC 6749.
/// This trait exists separately from the `StandardErrorResponse` struct
/// to support customization by clients, such as supporting interoperability with
/// non-standards-complaint OAuth2 providers.
///
/// The [`Display`] trait implementation for types implementing [`ErrorResponse`] should be a
/// human-readable string suitable for printing (e.g., within a [`RequestTokenError`]).
pub trait ErrorResponse: Debug + Display + DeserializeOwned + Serialize {}

/// Error types enum.
///
/// NOTE: The serialization must return the `snake_case` representation of
/// this error type. This value must match the error type from the relevant OAuth 2.0 standards
/// (RFC 6749 or an extension).
pub trait ErrorResponseType: Debug + DeserializeOwned + Serialize {}

/// Error response returned by server after requesting an access token.
///
/// The fields in this structure are defined in
/// [Section 5.2 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-5.2). This
/// trait is parameterized by a `ErrorResponseType` to support error types specific to future OAuth2
/// authentication schemes and extensions.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct StandardErrorResponse<T: ErrorResponseType> {
    #[serde(bound = "T: ErrorResponseType")]
    pub(crate) error: T,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error_description: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error_uri: Option<String>,
}

impl<T: ErrorResponseType> StandardErrorResponse<T> {
    /// Instantiate a new `ErrorResponse`.
    ///
    /// # Arguments
    ///
    /// * `error` - REQUIRED. A single ASCII error code deserialized to the generic parameter.
    ///   `ErrorResponseType`.
    /// * `error_description` - OPTIONAL. Human-readable ASCII text providing additional
    ///   information, used to assist the client developer in understanding the error that
    ///   occurred. Values for this parameter MUST NOT include characters outside the set
    ///   `%x20-21 / %x23-5B / %x5D-7E`.
    /// * `error_uri` - OPTIONAL. A URI identifying a human-readable web page with information
    ///   about the error used to provide the client developer with additional information about
    ///   the error. Values for the "error_uri" parameter MUST conform to the URI-reference
    ///   syntax and thus MUST NOT include characters outside the set `%x21 / %x23-5B / %x5D-7E`.
    pub fn new(error: T, error_description: Option<String>, error_uri: Option<String>) -> Self {
        Self {
            error,
            error_description,
            error_uri,
        }
    }

    /// REQUIRED. A single ASCII error code deserialized to the generic parameter
    /// `ErrorResponseType`.
    pub fn error(&self) -> &T {
        &self.error
    }
    /// OPTIONAL. Human-readable ASCII text providing additional information, used to assist
    /// the client developer in understanding the error that occurred. Values for this
    /// parameter MUST NOT include characters outside the set `%x20-21 / %x23-5B / %x5D-7E`.
    pub fn error_description(&self) -> Option<&String> {
        self.error_description.as_ref()
    }
    /// OPTIONAL. URI identifying a human-readable web page with information about the error,
    /// used to provide the client developer with additional information about the error.
    /// Values for the "error_uri" parameter MUST conform to the URI-reference syntax and
    /// thus MUST NOT include characters outside the set `%x21 / %x23-5B / %x5D-7E`.
    pub fn error_uri(&self) -> Option<&String> {
        self.error_uri.as_ref()
    }
}

impl<T> ErrorResponse for StandardErrorResponse<T> where T: ErrorResponseType + Display + 'static {}

impl<TE> Display for StandardErrorResponse<TE>
where
    TE: ErrorResponseType + Display,
{
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        let mut formatted = self.error().to_string();

        if let Some(error_description) = self.error_description() {
            formatted.push_str(": ");
            formatted.push_str(error_description);
        }

        if let Some(error_uri) = self.error_uri() {
            formatted.push_str(" (see ");
            formatted.push_str(error_uri);
            formatted.push(')');
        }

        write!(f, "{formatted}")
    }
}

/// Error encountered while requesting access token.
#[derive(thiserror::Error)]
pub enum RequestTokenError<RE, T>
where
    RE: Error + 'static,
    T: ErrorResponse + 'static,
{
    /// Error response returned by authorization server. Contains the parsed `ErrorResponse`
    /// returned by the server.
    #[error("Server returned error response: {0}")]
    ServerResponse(T),
    /// An error occurred while sending the request or receiving the response (e.g., network
    /// connectivity failed).
    #[error("Request failed")]
    Request(#[from] RE),
    /// Failed to parse server response. Parse errors may occur while parsing either successful
    /// or error responses.
    #[error("Failed to parse server response")]
    Parse(
        #[source] serde_path_to_error::Error<serde_json::error::Error>,
        Vec<u8>,
    ),
    /// Some other type of error occurred (e.g., an unexpected server response).
    #[error("Other error: {}", _0)]
    Other(String),
}

impl<RE, T> Debug for RequestTokenError<RE, T>
where
    RE: Error + 'static,
    T: ErrorResponse + 'static,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServerResponse(error) => f.debug_tuple("ServerResponse").field(error).finish(),
            Self::Request(error) => f.debug_tuple("Request").field(error).finish(),
            Self::Parse(error, _) => {
                // Parser messages and paths can contain response values, including secrets.
                // Keep only value-independent diagnostics; the original error and body remain
                // available by matching the Parse variant.
                f.debug_struct("Parse")
                    .field("category", &error.inner().classify())
                    .field("line", &error.inner().line())
                    .field("column", &error.inner().column())
                    .field("error", &"[REDACTED]")
                    .field("body", &"[REDACTED]")
                    .finish()
            }
            Self::Other(error) => f.debug_tuple("Other").field(error).finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RequestTokenError;
    use crate::basic::{BasicErrorResponse, BasicErrorResponseType};
    use crate::{EmptyExtraTokenFields, StandardTokenResponse, TokenType};
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    #[serde(rename_all = "lowercase")]
    enum TestTokenType {
        Bearer,
    }

    impl TokenType for TestTokenType {}

    fn assert_parse_debug_redacts(body: &[u8], secret: &str, path: &str) {
        let parse_error = serde_path_to_error::deserialize::<
            _,
            StandardTokenResponse<EmptyExtraTokenFields, TestTokenType>,
        >(&mut serde_json::Deserializer::from_slice(body))
        .unwrap_err();
        assert_eq!(parse_error.path().to_string(), path);
        assert!(parse_error.inner().to_string().contains(secret));
        let error: RequestTokenError<std::io::Error, BasicErrorResponse> =
            RequestTokenError::Parse(parse_error, body.to_vec());

        let ordinary = format!("{error:?}");
        let pretty = format!("{error:#?}");
        for debug in [ordinary, pretty] {
            assert!(debug.contains("Parse"));
            assert!(debug.contains("[REDACTED]"));
            let compact_debug: String = debug.chars().filter(|c| !c.is_whitespace()).collect();
            for sensitive in [
                secret,
                "access-token-debug-secret",
                "refresh-token-debug-secret",
            ] {
                assert!(!debug.contains(sensitive));
                let numeric_bytes = sensitive
                    .as_bytes()
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                assert!(!compact_debug.contains(&numeric_bytes));
            }
        }
        assert!(std::error::Error::source(&error)
            .unwrap()
            .to_string()
            .contains(secret));
        match error {
            RequestTokenError::Parse(parse_error, raw_body) => {
                assert_eq!(raw_body, body);
                assert_eq!(parse_error.path().to_string(), path);
                assert!(parse_error.inner().to_string().contains(secret));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_parse_debug_redacts_invalid_expires_in() {
        assert_parse_debug_redacts(
            br#"{"access_token":"access-token-debug-secret","refresh_token":"refresh-token-debug-secret","token_type":"bearer","expires_in":"expires-debug-secret"}"#,
            "expires-debug-secret",
            "expires_in",
        );
        assert_parse_debug_redacts(
            br#"{"access_token":"access-token-debug-secret","refresh_token":"refresh-token-debug-secret","token_type":"bearer","expires_in":-93847561029}"#,
            "-93847561029",
            "expires_in",
        );
    }

    #[test]
    fn test_parse_debug_redacts_secret_enum_value() {
        assert_parse_debug_redacts(
            br#"{"access_token":"access-token-debug-secret","refresh_token":"refresh-token-debug-secret","token_type":"token-type-debug-secret"}"#,
            "token-type-debug-secret",
            "token_type",
        );
    }

    #[test]
    fn test_error_response_serializer() {
        assert_eq!(
            "{\"error\":\"unauthorized_client\"}",
            serde_json::to_string(&BasicErrorResponse::new(
                BasicErrorResponseType::UnauthorizedClient,
                None,
                None,
            ))
            .unwrap(),
        );

        assert_eq!(
            "{\
         \"error\":\"invalid_client\",\
         \"error_description\":\"Invalid client_id\",\
         \"error_uri\":\"https://example.com/errors/invalid_client\"\
         }",
            serde_json::to_string(&BasicErrorResponse::new(
                BasicErrorResponseType::InvalidClient,
                Some("Invalid client_id".to_string()),
                Some("https://example.com/errors/invalid_client".to_string()),
            ))
            .unwrap(),
        );
    }
}
