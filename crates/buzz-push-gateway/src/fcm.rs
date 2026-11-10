//! FCM HTTP v1 envelope construction and response classification.
//!
//! The application data object is always [`FCM_RECONNECT_DATA`]. Token, TTL,
//! and priority are routing controls and MUST NOT enter that object.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::{header::CONTENT_TYPE, StatusCode};
use serde::Deserialize;
use thiserror::Error;

use crate::apns::{DeliveryAttempt, DeliveryOutcome, PushTransport};
use crate::model::FCM_RECONNECT_DATA;

/// Classify an FCM HTTP v1 status/reason without conflating provider faults
/// with endpoints.
pub fn classify(code: u16, status: Option<&str>, error_code: Option<&str>) -> DeliveryOutcome {
    match (code, status, error_code) {
        (200, _, _) => DeliveryOutcome::Accepted,
        (_, Some("NOT_FOUND"), _) | (_, _, Some("UNREGISTERED")) => {
            DeliveryOutcome::InvalidEndpoint {
                unregistered_at: None,
            }
        }
        (
            _,
            Some("UNAUTHENTICATED" | "PERMISSION_DENIED"),
            _,
        )
        | (_, _, Some("SENDER_ID_MISMATCH" | "THIRD_PARTY_AUTH_ERROR" | "API_DISABLED")) => {
            DeliveryOutcome::ConfigurationFault
        }
        (401 | 403, _, _) => DeliveryOutcome::ConfigurationFault,
        (429 | 500 | 502 | 503 | 504, _, _)
        | (_, Some("UNAVAILABLE" | "INTERNAL" | "RESOURCE_EXHAUSTED" | "DEADLINE_EXCEEDED"), _) => {
            DeliveryOutcome::Retry {
                retry_after_seconds: None,
            }
        }
        _ => DeliveryOutcome::PermanentRequestFault,
    }
}

/// Build the HTTP v1 JSON body. `data` is the compiled-in byte constant.
pub fn encode_send_body(token: &str, ttl_seconds: i64) -> Result<Vec<u8>, FcmError> {
    if token.is_empty() || token.len() > crate::model::MAX_ENDPOINT_HEX_BYTES {
        return Err(FcmError::Token);
    }
    let ttl = ttl_seconds.clamp(1, 2_419_200);
    let escaped_token = serde_json::to_string(token).map_err(|_| FcmError::Token)?;
    let mut body = Vec::from(br#"{"message":{"token":"#);
    body.extend_from_slice(escaped_token.as_bytes());
    body.extend_from_slice(br#","android":{"priority":"HIGH","ttl":""#);
    body.extend_from_slice(ttl.to_string().as_bytes());
    body.extend_from_slice(br#"s"},"data":"#);
    body.extend_from_slice(FCM_RECONNECT_DATA);
    body.extend_from_slice(br#"}}"#);
    Ok(body)
}

/// Supplies a short-lived OAuth access token for FCM HTTP v1.
#[async_trait]
pub trait FcmTokenSource: Send + Sync {
    async fn access_token(&self) -> Result<String, FcmError>;
}

/// Fixed bearer used by mock-wire tests. Never a Google credential.
pub struct StaticAccessToken(pub String);

#[async_trait]
impl FcmTokenSource for StaticAccessToken {
    async fn access_token(&self) -> Result<String, FcmError> {
        Ok(self.0.clone())
    }
}

/// Google service-account JWT bearer for FCM HTTP v1.
pub struct ServiceAccountToken {
    client_email: String,
    encoding_key: jsonwebtoken::EncodingKey,
    client: reqwest::Client,
    token_url: String,
}

impl ServiceAccountToken {
    pub fn from_pem(client_email: String, private_key_pem: &str) -> Result<Self, FcmError> {
        if client_email.is_empty() || !client_email.contains('@') {
            return Err(FcmError::Credential);
        }
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .map_err(|_| FcmError::Credential)?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| FcmError::Credential)?;
        Ok(Self {
            client_email,
            encoding_key,
            client,
            token_url: "https://oauth2.googleapis.com/token".to_owned(),
        })
    }
}

#[derive(serde::Serialize)]
struct GoogleJwtClaims {
    iss: String,
    scope: &'static str,
    aud: String,
    iat: i64,
    exp: i64,
}

#[derive(Deserialize)]
struct GoogleTokenResponse {
    access_token: Option<String>,
}

#[async_trait]
impl FcmTokenSource for ServiceAccountToken {
    async fn access_token(&self) -> Result<String, FcmError> {
        let now = chrono::Utc::now().timestamp();
        let claims = GoogleJwtClaims {
            iss: self.client_email.clone(),
            scope: "https://www.googleapis.com/auth/firebase.messaging",
            aud: self.token_url.clone(),
            iat: now,
            exp: now + 3600,
        };
        let assertion = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
            &claims,
            &self.encoding_key,
        )
        .map_err(|_| FcmError::Credential)?;
        let response = self
            .client
            .post(&self.token_url)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!(
                "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={assertion}"
            ))
            .send()
            .await
            .map_err(|_| FcmError::Transport)?;
        let body = response
            .json::<GoogleTokenResponse>()
            .await
            .map_err(|_| FcmError::Transport)?;
        body.access_token.filter(|t| !t.is_empty()).ok_or(FcmError::Credential)
    }
}

/// Direct HTTP/2 FCM transport.
pub struct FcmTransport {
    client: reqwest::Client,
    project_id: String,
    base_url: String,
    tokens: Arc<dyn FcmTokenSource>,
}

impl FcmTransport {
    /// Production constructor. `base_url` is `https://fcm.googleapis.com`.
    pub fn http_v1(
        project_id: String,
        tokens: Arc<dyn FcmTokenSource>,
    ) -> Result<Self, FcmError> {
        Self::with_base_url(
            project_id,
            "https://fcm.googleapis.com".to_owned(),
            tokens,
        )
    }

    pub fn with_base_url(
        project_id: String,
        base_url: String,
        tokens: Arc<dyn FcmTokenSource>,
    ) -> Result<Self, FcmError> {
        if project_id.is_empty()
            || !project_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(FcmError::Credential);
        }
        let client = reqwest::Client::builder()
            .http2_keep_alive_while_idle(false)
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| FcmError::Credential)?;
        Ok(Self {
            client,
            project_id,
            base_url,
            tokens,
        })
    }

    fn send_url(&self) -> String {
        format!(
            "{}/v1/projects/{}/messages:send",
            self.base_url, self.project_id
        )
    }

    async fn send_response(
        &self,
        attempt: DeliveryAttempt,
        endpoint: &str,
    ) -> Result<reqwest::Response, FcmError> {
        let now = chrono::Utc::now().timestamp();
        let ttl = attempt.expires_at.saturating_sub(now);
        let body = encode_send_body(endpoint, ttl)?;
        debug_assert!(
            body.windows(FCM_RECONNECT_DATA.len())
                .any(|w| w == FCM_RECONNECT_DATA)
        );
        let access = self.tokens.access_token().await?;
        self.client
            .post(self.send_url())
            .header(CONTENT_TYPE, "application/json")
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {access}"))
            .body(body)
            .send()
            .await
            .map_err(|_| FcmError::Transport)
    }
}

/// FCM transport setup or send failure. It carries no credential or token.
#[derive(Debug, Error)]
pub enum FcmError {
    #[error("invalid FCM credential")]
    Credential,
    #[error("invalid FCM token")]
    Token,
    #[error("FCM transport failure")]
    Transport,
}

#[derive(Deserialize)]
struct FcmErrorBody {
    error: Option<FcmRpcError>,
}

#[derive(Deserialize)]
struct FcmRpcError {
    status: Option<String>,
    details: Option<Vec<FcmErrorDetail>>,
}

#[derive(Deserialize)]
struct FcmErrorDetail {
    #[serde(rename = "errorCode")]
    error_code: Option<String>,
}

#[async_trait]
impl PushTransport for FcmTransport {
    async fn send(&self, attempt: DeliveryAttempt, endpoint: &str) -> DeliveryOutcome {
        crate::metrics::record_fcm_send_attempt();
        let response = match self.send_response(attempt, endpoint).await {
            Ok(response) => response,
            Err(_) => {
                return DeliveryOutcome::Retry {
                    retry_after_seconds: None,
                }
            }
        };
        if response.status() == StatusCode::OK {
            return DeliveryOutcome::Accepted;
        }
        let code = response.status().as_u16();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<i64>().ok())
            .map(|seconds| seconds.clamp(1, 3600));
        let detail = response.json::<FcmErrorBody>().await.ok();
        let status = detail
            .as_ref()
            .and_then(|d| d.error.as_ref())
            .and_then(|e| e.status.as_deref());
        let error_code = detail
            .as_ref()
            .and_then(|d| d.error.as_ref())
            .and_then(|e| e.details.as_ref())
            .and_then(|details| {
                details
                    .iter()
                    .find_map(|item| item.error_code.as_deref())
            });
        match classify(code, status, error_code) {
            DeliveryOutcome::Retry { .. } => DeliveryOutcome::Retry {
                retry_after_seconds: retry_after,
            },
            outcome => outcome,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Bytes,
        extract::State,
        http::HeaderMap,
        routing::post,
        Router,
    };
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct CapturedRequest {
        headers: HeaderMap,
        body: Vec<u8>,
    }

    async fn capture_request(
        State(requests): State<Arc<Mutex<Vec<CapturedRequest>>>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> StatusCode {
        requests.lock().unwrap().push(CapturedRequest {
            headers,
            body: body.to_vec(),
        });
        StatusCode::OK
    }

    #[test]
    fn encode_send_body_embeds_the_constant_and_escapes_the_token() {
        let body = encode_send_body("abc:APA91b-token", 60).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            parsed["message"]["data"],
            serde_json::from_slice::<serde_json::Value>(FCM_RECONNECT_DATA).unwrap()
        );
        assert_eq!(parsed["message"]["token"], "abc:APA91b-token");
        assert_eq!(parsed["message"]["android"]["priority"], "HIGH");
        assert_eq!(parsed["message"]["android"]["ttl"], "60s");
        assert!(parsed["message"].get("notification").is_none());
        assert!(std::str::from_utf8(&body)
            .unwrap()
            .contains(std::str::from_utf8(FCM_RECONNECT_DATA).unwrap()));
    }

    #[test]
    fn encode_send_body_does_not_copy_event_unread_or_relay_bytes() {
        let body = encode_send_body("tok", 1).unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        for forbidden in [
            "event",
            "unread",
            "relay",
            "channel",
            "title",
            "body",
            "notification",
        ] {
            assert!(
                !text.contains(forbidden),
                "application envelope leaked {forbidden}"
            );
        }
    }

    #[tokio::test]
    async fn http_v1_transport_sends_exact_data_for_every_attempt() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route(
                "/v1/projects/{project}/messages:send",
                post(capture_request),
            )
            .with_state(requests.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let transport = FcmTransport::with_base_url(
            "nest-project".to_owned(),
            base_url,
            Arc::new(StaticAccessToken("test-bearer".to_owned())),
        )
        .unwrap();
        for (request_id, expires_at, endpoint) in [
            (uuid::Uuid::nil(), chrono::Utc::now().timestamp() + 30, "aaa:APA91b"),
            (
                uuid::Uuid::max(),
                chrono::Utc::now().timestamp() + 90,
                "zzz:APA91b-other",
            ),
        ] {
            assert_eq!(
                transport
                    .send(
                        DeliveryAttempt {
                            request_id,
                            expires_at,
                        },
                        endpoint,
                    )
                    .await,
                DeliveryOutcome::Accepted
            );
        }
        let captured = requests.lock().unwrap();
        assert_eq!(captured.len(), 2);
        for request in captured.iter() {
            assert!(request
                .body
                .windows(FCM_RECONNECT_DATA.len())
                .any(|window| window == FCM_RECONNECT_DATA));
            let parsed: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(
                parsed["message"]["data"],
                serde_json::from_slice::<serde_json::Value>(FCM_RECONNECT_DATA).unwrap()
            );
            assert!(parsed["message"].get("notification").is_none());
            let auth = request
                .headers
                .get(reqwest::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .unwrap();
            assert_eq!(auth, "Bearer test-bearer");
            let text = std::str::from_utf8(&request.body).unwrap();
            assert!(!text.contains(&uuid::Uuid::nil().to_string()));
            assert!(!text.contains("unread"));
            assert!(!text.contains("relay"));
        }
        let first: serde_json::Value = serde_json::from_slice(&captured[0].body).unwrap();
        let second: serde_json::Value = serde_json::from_slice(&captured[1].body).unwrap();
        assert_eq!(first["message"]["data"], second["message"]["data"]);
        assert_ne!(first["message"]["token"], second["message"]["token"]);
    }

    #[test]
    fn response_classes_do_not_massacre_endpoints_on_provider_faults() {
        assert_eq!(
            classify(404, Some("NOT_FOUND"), Some("UNREGISTERED")),
            DeliveryOutcome::InvalidEndpoint {
                unregistered_at: None
            }
        );
        assert_eq!(
            classify(401, Some("UNAUTHENTICATED"), None),
            DeliveryOutcome::ConfigurationFault
        );
        assert_eq!(
            classify(403, Some("PERMISSION_DENIED"), Some("SENDER_ID_MISMATCH")),
            DeliveryOutcome::ConfigurationFault
        );
        assert_eq!(
            classify(429, Some("RESOURCE_EXHAUSTED"), None),
            DeliveryOutcome::Retry {
                retry_after_seconds: None
            }
        );
        assert_eq!(
            classify(500, Some("INTERNAL"), None),
            DeliveryOutcome::Retry {
                retry_after_seconds: None
            }
        );
        assert_eq!(
            classify(400, Some("INVALID_ARGUMENT"), Some("INVALID_ARGUMENT")),
            DeliveryOutcome::PermanentRequestFault
        );
    }

    #[test]
    fn empty_project_id_fails_as_a_credential_error() {
        assert!(matches!(
            FcmTransport::http_v1(
                String::new(),
                Arc::new(StaticAccessToken("x".to_owned()))
            ),
            Err(FcmError::Credential)
        ));
    }
}
