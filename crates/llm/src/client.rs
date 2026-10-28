use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

/// Who authored an [`LlmMessage`] — mapped to GigaChat's `"user"`/`"assistant"`/
/// `"function"` role strings by [`GigaChatProvider`].
///
/// `System` (2026-09-22, SEC-21) carries the assistant's own operating instructions —
/// notably that tool-call results (device/alert data pulled from the monitored network,
/// which an attacker can influence: a syslog message, a trap payload, an alert comment)
/// are untrusted *data*, never instructions to follow. `crate::assistant::run_assistant_turn`
/// sends exactly one `System` message, first, on every turn — not stored as a `Message` in
/// the conversation's own history, since its content is static and re-derived each call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmRole {
    System,
    User,
    Assistant,
    Tool,
}

/// One turn of chat history, provider-agnostic. A `Tool`-role message carries the result
/// of a previously requested [`ToolCall`] — `tool_name` names which tool it's the result
/// of (GigaChat's `"function"`-role wire message needs this), `content` carries the
/// (usually JSON-stringified) result body. An `Assistant`-role message with `tool_call`
/// set is the model's own prior request to call a tool, replayed back as history on the
/// next turn. `tool_call_id` (2026-09-18, added for `OpenRouterProvider`) is the
/// OpenAI-style `tool_call_id` an OpenAI-compatible provider's `"tool"`-role wire message
/// must carry to correlate a result back to the specific call it answers — `None` for
/// GigaChat, which correlates by `tool_name` alone and has no id concept at all. Set via
/// [`Self::with_tool_call_id`], not a `tool_result` parameter, so the one existing call
/// site that doesn't need it (GigaChat) is untouched.
#[derive(Debug, Clone)]
pub struct LlmMessage {
    pub role: LlmRole,
    pub content: Option<String>,
    pub tool_call: Option<ToolCall>,
    pub tool_name: Option<String>,
    pub tool_call_id: Option<String>,
}

impl LlmMessage {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: LlmRole::System,
            content: Some(content.into()),
            tool_call: None,
            tool_name: None,
            tool_call_id: None,
        }
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: LlmRole::User,
            content: Some(content.into()),
            tool_call: None,
            tool_name: None,
            tool_call_id: None,
        }
    }

    pub fn assistant_text(content: impl Into<String>) -> Self {
        Self {
            role: LlmRole::Assistant,
            content: Some(content.into()),
            tool_call: None,
            tool_name: None,
            tool_call_id: None,
        }
    }

    pub fn assistant_tool_call(tool_call: ToolCall) -> Self {
        Self {
            role: LlmRole::Assistant,
            content: None,
            tool_call: Some(tool_call),
            tool_name: None,
            tool_call_id: None,
        }
    }

    pub fn tool_result(tool_name: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: LlmRole::Tool,
            content: Some(content.into()),
            tool_call: None,
            tool_name: Some(tool_name.into()),
            tool_call_id: None,
        }
    }

    /// Attaches the `tool_call_id` an OpenAI-compatible provider needs on a `"tool"`-role
    /// message — see this struct's docs. A no-op for providers (GigaChat) that never read
    /// this field back.
    pub fn with_tool_call_id(mut self, id: impl Into<String>) -> Self {
        self.tool_call_id = Some(id.into());
        self
    }
}

/// A tool the model wants to invoke (or, on the way back into the next turn's history,
/// already invoked) — `arguments` is a JSON object of named parameters. `id` (2026-09-18)
/// is the OpenAI-style call id an OpenAI-compatible provider assigns to each tool call and
/// expects back on the correlating `tool_call_id` — `None` for GigaChat, which has no id
/// concept and correlates by name alone.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    pub name: String,
    pub arguments: serde_json::Value,
    pub id: Option<String>,
}

/// One tool's advertised schema, handed to [`LlmProvider::chat`] so the model knows what
/// it can call. `parameters` is a JSON-schema object (`{"type":"object","properties":{...}}`).
#[derive(Debug, Clone)]
pub struct ToolSchema {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

/// The model's response to one `chat()` call — either a final text reply, or a request
/// to call a tool (never expected to carry both at once in this codebase's usage, but
/// not asserted here since a provider *could* legitimately send reasoning text alongside
/// a function call).
#[derive(Debug, Clone, Default)]
pub struct LlmTurn {
    pub text: Option<String>,
    pub tool_call: Option<ToolCall>,
}

/// Provider-agnostic chat client — see this crate's module docs for why this is a trait
/// (self-hosted backend planned as a second implementation later, not yet built).
#[async_trait]
pub trait LlmProvider: Send + Sync {
    async fn chat(&self, history: &[LlmMessage], tools: &[ToolSchema]) -> anyhow::Result<LlmTurn>;
}

// ---------------------------------------------------------------- GigaChat wire format

#[derive(Debug, Serialize)]
struct GigaChatMessage {
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    function_call: Option<GigaChatFunctionCallOut>,
}

#[derive(Debug, Serialize)]
struct GigaChatFunctionCallOut {
    name: String,
    /// A nested JSON object, **not** a pre-serialized string — confirmed against a real
    /// live call (2026-09-18): sending this as a JSON-encoded string (the OpenAI-old-format
    /// guess this module originally shipped with) gets a hard `400 "Your request contains
    /// invalid JSON syntax"` from the real GigaChat API. Unlike OpenAI's pre-`tools`
    /// function-calling format, GigaChat's `arguments` is a real nested object on **both**
    /// the incoming (see [`GigaChatFunctionCallIn`]) and outgoing side — symmetric, no
    /// string encoding anywhere in this exchange.
    arguments: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct GigaChatFunction {
    name: String,
    description: String,
    parameters: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<GigaChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    functions: Option<Vec<GigaChatFunction>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    function_call: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Debug, Deserialize)]
struct ChatChoice {
    message: GigaChatResponseMessage,
}

#[derive(Debug, Deserialize)]
struct GigaChatResponseMessage {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    function_call: Option<GigaChatFunctionCallIn>,
}

#[derive(Debug, Deserialize)]
struct GigaChatFunctionCallIn {
    name: String,
    /// Accepted either as a JSON object or as a JSON-encoded string — see
    /// [`parse_tool_call`]'s docs for why this can't just be `serde_json::Value` handled
    /// uniformly.
    #[serde(default)]
    arguments: serde_json::Value,
}

fn parse_tool_call(fc: GigaChatFunctionCallIn) -> ToolCall {
    // Defensive: some providers (and possibly GigaChat, unverified — see this module's
    // docs) send `arguments` as a JSON-encoded *string* rather than a nested object.
    // Falls back to the raw value unchanged if it's already an object/array, or if the
    // string doesn't parse as JSON (kept as a string value rather than dropped).
    let arguments = match fc.arguments {
        serde_json::Value::String(s) => {
            serde_json::from_str(&s).unwrap_or(serde_json::Value::String(s))
        }
        other => other,
    };
    ToolCall {
        name: fc.name,
        arguments,
        id: None,
    }
}

fn to_wire_messages(history: &[LlmMessage]) -> Vec<GigaChatMessage> {
    history
        .iter()
        .map(|m| {
            let role = match m.role {
                LlmRole::System => "system",
                LlmRole::User => "user",
                LlmRole::Assistant => "assistant",
                LlmRole::Tool => "function",
            }
            .to_string();
            let function_call = m.tool_call.as_ref().map(|tc| GigaChatFunctionCallOut {
                name: tc.name.clone(),
                arguments: tc.arguments.clone(),
            });
            GigaChatMessage {
                role,
                content: m.content.clone(),
                name: m.tool_name.clone(),
                function_call,
            }
        })
        .collect()
}

#[derive(Debug, Deserialize)]
struct OAuthResponse {
    access_token: String,
    /// Unix timestamp in **milliseconds** — confirmed against a real OAuth response
    /// (2026-09-18, live verification with real GigaChat Studio credentials): a fresh
    /// token came back with `expires_at` on the order of 1.79e12, consistent with
    /// millis-since-epoch for that date, not seconds. `ensure_token` still applies the
    /// magnitude-based defensive check below rather than hardcoding "always millis" — cheap
    /// insurance against a future API revision changing units without a version bump.
    expires_at: i64,
}

/// GigaChat (Sber) — the real, network-calling [`LlmProvider`] implementation. Holds one
/// shared `reqwest::Client` (built once, reused for every OAuth/chat call), same "own the
/// connection machinery once" reasoning `discovery_notify::RealNotifier` gives for its own
/// shared client. The OAuth/chat-completions wire format below (URLs, field names,
/// `expires_at` units, `arguments` as a nested object on both request and response) is
/// confirmed against a real live call with real GigaChat Studio credentials (2026-09-18) —
/// see `crates/llm`'s live-verification notes in the feature's Changelog entry for the
/// exact request/response pairs this was checked against.
pub struct GigaChatProvider {
    http: reqwest::Client,
    client_id: String,
    client_secret: String,
    scope: String,
    token: RwLock<Option<(String, DateTime<Utc>)>>,
    oauth_base: String,
    chat_base: String,
}

impl GigaChatProvider {
    const OAUTH_URL: &'static str = "https://ngw.devices.sberbank.ru:9443/api/v2/oauth";
    const CHAT_URL: &'static str = "https://gigachat.devices.sberbank.ru/api/v1/chat/completions";

    /// The public Russian Trusted Root CA + Sub CA bundle (combined PEM, two certificates)
    /// that issues `gigachat.devices.sberbank.ru`'s TLS certificate — **confirmed by live
    /// verification (2026-09-18)**, not a guess: without it, TLS verification against the
    /// real GigaChat API fails (`SSL certificate problem: self signed certificate in
    /// certificate chain`), with it, it succeeds. Public government root certificates, not
    /// secrets — safe to embed in source control, same category as a `webpki-roots`
    /// dependency would be. Sourced from the official distribution point
    /// (gosuslugi.ru/crt, mirrored at gu-st.ru) and verified against the real leaf
    /// certificate's issuer chain before being checked in. Applied unconditionally in
    /// [`Self::new`] so this works out of the box for every deployment of this product —
    /// no customer should have to know to install a Russian government CA into their own
    /// system trust store just to use the default provider.
    const RUSSIAN_TRUSTED_CA_PEM: &'static [u8] = include_bytes!("../certs/russian_trusted_ca.pem");

    pub fn new(client_id: String, client_secret: String, scope: String) -> anyhow::Result<Self> {
        let cert = reqwest::Certificate::from_pem(Self::RUSSIAN_TRUSTED_CA_PEM)?;
        Ok(Self {
            http: reqwest::Client::builder()
                .add_root_certificate(cert)
                .build()?,
            client_id,
            client_secret,
            scope,
            token: RwLock::new(None),
            oauth_base: Self::OAUTH_URL.to_string(),
            chat_base: Self::CHAT_URL.to_string(),
        })
    }

    /// Seam for a *replacement* trusted root CA, on top of the bundled
    /// [`Self::RUSSIAN_TRUSTED_CA_PEM`] already applied by [`Self::new`] — for a future
    /// self-hosted/alternate provider behind a different internal CA, not something a
    /// GigaChat deployment should normally need. Never fall back to disabling TLS
    /// verification instead of this.
    pub fn with_root_cert(mut self, pem: &[u8]) -> anyhow::Result<Self> {
        let cert = reqwest::Certificate::from_pem(pem)?;
        self.http = reqwest::Client::builder()
            .add_root_certificate(cert)
            .build()?;
        Ok(self)
    }

    #[cfg(test)]
    fn with_oauth_base(mut self, base: impl Into<String>) -> Self {
        self.oauth_base = base.into();
        self
    }

    #[cfg(test)]
    fn with_chat_base(mut self, base: impl Into<String>) -> Self {
        self.chat_base = base.into();
        self
    }

    /// Returns a cached access token if it's not within 60s of expiring, otherwise
    /// performs the OAuth client-credentials exchange and caches the result. Re-checks
    /// the cache after acquiring the write lock — two concurrent callers racing past the
    /// initial read-lock check must not both pay for a fresh token fetch.
    async fn ensure_token(&self) -> anyhow::Result<String> {
        let fresh_enough =
            |expires_at: &DateTime<Utc>| *expires_at - chrono::Duration::seconds(60) > Utc::now();
        {
            let guard = self.token.read().await;
            if let Some((token, expires_at)) = guard.as_ref() {
                if fresh_enough(expires_at) {
                    return Ok(token.clone());
                }
            }
        }
        let mut guard = self.token.write().await;
        if let Some((token, expires_at)) = guard.as_ref() {
            if fresh_enough(expires_at) {
                return Ok(token.clone());
            }
        }

        let auth_header = format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", self.client_id, self.client_secret))
        );
        let rquid = Uuid::new_v4().to_string();
        let response = self
            .http
            .post(&self.oauth_base)
            .header(reqwest::header::AUTHORIZATION, auth_header)
            .header("RqUID", rquid)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(reqwest::header::ACCEPT, "application/json")
            .body(format!("scope={}", self.scope))
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        anyhow::ensure!(
            status.is_success(),
            "GigaChat OAuth token request returned HTTP {status}: {body}"
        );
        let parsed: OAuthResponse = serde_json::from_str(&body).map_err(|e| anyhow::anyhow!("GigaChat OAuth response (HTTP {status}) was not the expected shape: {e}; body: {body}"))?;

        // `expires_at` unit is unconfirmed (see this struct's docs) — a value too large to
        // be a plausible Unix-seconds timestamp is treated as milliseconds instead.
        let expires_at = if parsed.expires_at > 100_000_000_000 {
            DateTime::from_timestamp_millis(parsed.expires_at)
        } else {
            DateTime::from_timestamp(parsed.expires_at, 0)
        }
        .ok_or_else(|| {
            anyhow::anyhow!(
                "GigaChat OAuth response had an invalid expires_at: {}",
                parsed.expires_at
            )
        })?;

        *guard = Some((parsed.access_token.clone(), expires_at));
        Ok(parsed.access_token)
    }
}

#[async_trait]
impl LlmProvider for GigaChatProvider {
    async fn chat(&self, history: &[LlmMessage], tools: &[ToolSchema]) -> anyhow::Result<LlmTurn> {
        let token = self.ensure_token().await?;
        let messages = to_wire_messages(history);
        let functions = if tools.is_empty() {
            None
        } else {
            Some(
                tools
                    .iter()
                    .map(|t| GigaChatFunction {
                        name: t.name.clone(),
                        description: t.description.clone(),
                        parameters: t.parameters.clone(),
                    })
                    .collect(),
            )
        };
        let function_call = functions.is_some().then(|| "auto".to_string());
        let request = ChatRequest {
            model: "GigaChat".to_string(),
            messages,
            functions,
            function_call,
        };

        let response = self
            .http
            .post(&self.chat_base)
            .bearer_auth(&token)
            .json(&request)
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        anyhow::ensure!(
            status.is_success(),
            "GigaChat chat completions returned HTTP {status}: {body}"
        );
        let parsed: ChatCompletionResponse = serde_json::from_str(&body).map_err(|e| {
            anyhow::anyhow!(
                "GigaChat response (HTTP {status}) was not the expected shape: {e}; body: {body}"
            )
        })?;
        let choice = parsed
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("GigaChat response had no choices"))?;
        let tool_call = choice.message.function_call.map(parse_tool_call);
        Ok(LlmTurn {
            text: choice.message.content,
            tool_call,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Same "real protocol, fake backend" approach `discovery_notify::real`'s own tests
    /// use — a real local TCP socket capturing the raw request bytes, rather than mocking
    /// at the `reqwest` layer.
    async fn capture_one_request(
        reply_body: &'static str,
    ) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 64 * 1024];
            let n = stream.read(&mut buf).await.unwrap();
            buf.truncate(n);
            let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", reply_body.len(), reply_body);
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.ok();
            buf
        });
        (format!("http://{addr}"), handle)
    }

    fn provider(oauth_url: &str, chat_url: &str) -> GigaChatProvider {
        GigaChatProvider::new(
            "test-client".to_string(),
            "test-secret".to_string(),
            "GIGACHAT_API_PERS".to_string(),
        )
        .unwrap()
        .with_oauth_base(oauth_url)
        .with_chat_base(chat_url)
    }

    #[tokio::test]
    async fn ensure_token_fetches_and_caches() {
        let (oauth_url, handle) =
            capture_one_request(r#"{"access_token":"tok-1","expires_at":9999999999}"#).await;
        let p = provider(&oauth_url, "unused");
        let token = p.ensure_token().await.unwrap();
        assert_eq!(token, "tok-1");

        let raw = handle.await.unwrap();
        let request = String::from_utf8_lossy(&raw);
        assert!(
            request.starts_with("POST "),
            "unexpected request line: {request}"
        );
        assert!(
            request.to_lowercase().contains("authorization: basic"),
            "missing Basic auth header: {request}"
        );
        assert!(
            request.to_lowercase().contains("rquid:"),
            "missing RqUID header: {request}"
        );
        assert!(
            request.contains("scope=GIGACHAT_API_PERS"),
            "missing scope in body: {request}"
        );

        // Second call must not hit the network again — no listener is bound anymore, so a
        // second real request would fail outright.
        let token2 = p.ensure_token().await.unwrap();
        assert_eq!(token2, "tok-1");
    }

    #[tokio::test]
    async fn ensure_token_refreshes_once_expired() {
        let (oauth_url, handle1) =
            capture_one_request(r#"{"access_token":"tok-old","expires_at":1}"#).await;
        let p = provider(&oauth_url, "unused");
        assert_eq!(p.ensure_token().await.unwrap(), "tok-old");
        handle1.await.unwrap();

        let (oauth_url2, handle2) =
            capture_one_request(r#"{"access_token":"tok-new","expires_at":9999999999}"#).await;
        let p = p.with_oauth_base(oauth_url2);
        assert_eq!(
            p.ensure_token().await.unwrap(),
            "tok-new",
            "an expired cached token must trigger a fresh fetch"
        );
        handle2.await.unwrap();
    }

    #[tokio::test]
    async fn chat_sends_history_and_tools_and_parses_text_reply() {
        let (oauth_url, oauth_handle) =
            capture_one_request(r#"{"access_token":"tok","expires_at":9999999999}"#).await;
        let (chat_url, chat_handle) =
            capture_one_request(r#"{"choices":[{"message":{"content":"привет"}}]}"#).await;
        let p = provider(&oauth_url, &chat_url);

        let history = vec![LlmMessage::user("покажи тревоги")];
        let tools = vec![ToolSchema {
            name: "list_alerts".to_string(),
            description: "список тревог".to_string(),
            parameters: serde_json::json!({"type": "object", "properties": {}}),
        }];
        let turn = p.chat(&history, &tools).await.unwrap();
        assert_eq!(turn.text.as_deref(), Some("привет"));
        assert!(turn.tool_call.is_none());

        oauth_handle.await.unwrap();
        let raw = chat_handle.await.unwrap();
        let request = String::from_utf8_lossy(&raw);
        assert!(
            request.to_lowercase().contains("authorization: bearer tok"),
            "missing bearer token: {request}"
        );
        assert!(
            request.contains("\"list_alerts\""),
            "tool schema missing from request: {request}"
        );
        assert!(
            request.contains("покажи тревоги"),
            "user message missing from request: {request}"
        );
    }

    #[tokio::test]
    async fn chat_sends_a_replayed_tool_call_arguments_as_a_nested_object_not_a_string() {
        // Regression test for a real bug caught during live verification (2026-09-18):
        // this module originally serialized outgoing `function_call.arguments` as a
        // JSON-encoded *string* (an unverified guess at plan-writing time, modeled on
        // OpenAI's old functions format) — the real GigaChat API rejects that with a hard
        // `400 "Your request contains invalid JSON syntax"`. `arguments` must be a nested
        // object on the wire, same as it is when GigaChat sends one to us.
        let (oauth_url, oauth_handle) =
            capture_one_request(r#"{"access_token":"tok","expires_at":9999999999}"#).await;
        let (chat_url, chat_handle) =
            capture_one_request(r#"{"choices":[{"message":{"content":"готово"}}]}"#).await;
        let p = provider(&oauth_url, &chat_url);

        let history = vec![
            LlmMessage::user("покажи тревоги"),
            LlmMessage::assistant_tool_call(ToolCall {
                name: "list_alerts".to_string(),
                arguments: serde_json::json!({"level": "critical"}),
                id: None,
            }),
            LlmMessage::tool_result("list_alerts", r#"{"total":0}"#),
        ];
        p.chat(&history, &[]).await.unwrap();

        oauth_handle.await.unwrap();
        let raw = chat_handle.await.unwrap();
        let request = String::from_utf8_lossy(&raw);
        assert!(
            request.contains(r#""arguments":{"level":"critical"}"#),
            "arguments must be a nested JSON object, not a string: {request}"
        );
        assert!(
            !request.contains(r#""arguments":"{"#),
            "arguments must not be JSON-encoded as a string: {request}"
        );
    }

    #[tokio::test]
    async fn chat_parses_a_function_call_with_string_encoded_arguments() {
        let (oauth_url, oauth_handle) =
            capture_one_request(r#"{"access_token":"tok","expires_at":9999999999}"#).await;
        let reply = r#"{"choices":[{"message":{"function_call":{"name":"list_alerts","arguments":"{\"level\":\"critical\"}"}}}]}"#;
        let (chat_url, chat_handle) = capture_one_request(reply).await;
        let p = provider(&oauth_url, &chat_url);

        let turn = p
            .chat(&[LlmMessage::user("критичные тревоги")], &[])
            .await
            .unwrap();
        assert!(turn.text.is_none());
        let tool_call = turn.tool_call.expect("expected a tool call");
        assert_eq!(tool_call.name, "list_alerts");
        assert_eq!(
            tool_call.arguments,
            serde_json::json!({"level": "critical"})
        );

        oauth_handle.await.unwrap();
        chat_handle.await.unwrap();
    }

    #[tokio::test]
    async fn chat_parses_a_function_call_with_object_arguments() {
        let (oauth_url, oauth_handle) =
            capture_one_request(r#"{"access_token":"tok","expires_at":9999999999}"#).await;
        let reply = r#"{"choices":[{"message":{"function_call":{"name":"list_alerts","arguments":{"level":"critical"}}}}]}"#;
        let (chat_url, chat_handle) = capture_one_request(reply).await;
        let p = provider(&oauth_url, &chat_url);

        let turn = p
            .chat(&[LlmMessage::user("критичные тревоги")], &[])
            .await
            .unwrap();
        let tool_call = turn.tool_call.expect("expected a tool call");
        assert_eq!(
            tool_call.arguments,
            serde_json::json!({"level": "critical"})
        );

        oauth_handle.await.unwrap();
        chat_handle.await.unwrap();
    }

    #[tokio::test]
    async fn chat_fails_clearly_on_a_non_success_status() {
        let (oauth_url, oauth_handle) =
            capture_one_request(r#"{"access_token":"tok","expires_at":9999999999}"#).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 64 * 1024];
            let _ = stream.read(&mut buf).await.unwrap();
            let body = r#"{"message":"unauthorized"}"#;
            let response = format!("HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.ok();
        });
        let p = provider(&oauth_url, &format!("http://{addr}"));
        let err = p.chat(&[LlmMessage::user("hi")], &[]).await.unwrap_err();
        assert!(err.to_string().contains("401"), "unexpected error: {err}");

        oauth_handle.await.unwrap();
        handle.await.unwrap();
    }
}
