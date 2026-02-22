//! Control socket protocol types.
//!
//! Line-delimited JSON protocol for the Unix domain socket.
//! Each request is one JSON line, each response is one JSON line.

use serde::{Deserialize, Serialize};

/// A control request from a client.
#[derive(Debug, Deserialize)]
pub struct Request {
    /// The command to execute (e.g., "show_status", "show_peers").
    pub command: String,
}

/// A control response to a client.
#[derive(Debug, Serialize)]
pub struct Response {
    /// "ok" or "error".
    pub status: String,
    /// Response data (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Error message (present on failure).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Response {
    /// Create a success response with data.
    pub fn ok(data: serde_json::Value) -> Self {
        Self {
            status: "ok".to_string(),
            data: Some(data),
            message: None,
        }
    }

    /// Create an error response with a message.
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: "error".to_string(),
            data: None,
            message: Some(message.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_request() {
        let json = r#"{"command": "show_status"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.command, "show_status");
    }

    #[test]
    fn test_serialize_ok_response() {
        let resp = Response::ok(serde_json::json!({"state": "running"}));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"state\":\"running\""));
        assert!(!json.contains("\"message\""));
    }

    #[test]
    fn test_serialize_error_response() {
        let resp = Response::error("unknown command: foo");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"status\":\"error\""));
        assert!(json.contains("unknown command: foo"));
        assert!(!json.contains("\"data\""));
    }

    #[test]
    fn test_deserialize_unknown_fields_ignored() {
        let json = r#"{"command": "show_peers", "extra": true}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.command, "show_peers");
    }

    #[test]
    fn test_deserialize_malformed_request() {
        let json = r#"{"not_command": "foo"}"#;
        let result: Result<Request, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }
}
