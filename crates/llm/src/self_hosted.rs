//! Self-hosted OpenAI-compatible inference — the third [`LlmProvider`] implementation
//! (2026-09-18, follow-up to [`crate::OpenRouterProvider`] the same day — closes
//! `docs/Roadmap.md`'s self-hosted-model backlog item at the protocol level in this
//! pass). Targets any server that exposes the OpenAI Chat Completions wire format over
//! `/v1/chat/completions` — vLLM, Ollama, LM Studio, text-generation-webui all commonly
//! do. Wire format is byte-for-byte the same as [`crate::OpenRouterProvider`]'s (this
//! module deliberately mirrors that one's request/response shapes almost verbatim, kept
//! as its own independent set of structs rather than shared types — same "every provider
//! module is fully self-contained" posture [`crate::GigaChatProvider`]/
//! [`crate::OpenRouterProvider`] already have relative to each other) — see that module's
//! docs for the `tools`/`tool_calls`, id-correlated tool results, and
//! `function.arguments`-as-a-JSON-string details, all identical here.
//!
//! Two differences from [`crate::OpenRouterProvider`], both driven directly by what
//! "self-hosted" means for this product's customers (regional ISPs unwilling to send
//! alert/device data to an external cloud API — see `docs/Roadmap.md`'s self-hosted
//! item):
//!
//! - **`base_url` has no fixed default.** Unlike OpenRouter's single well-known
//!   endpoint, a self-hosted server's address is entirely the customer's own
//!   (`http://localhost:11434/v1/chat/completions` for a local Ollama,
//!   `http://vllm-host:8000/v1/chat/completions` for a vLLM deployment, etc.) — always a
//!   required, user-configured field
//!   (`discovery_core::AiAssistantProviderConfig::self_hosted_base_url`), never a
//!   compiled-in constant the way [`crate::OpenRouterProvider::BASE_URL`] is.
//! - **`api_key` is optional.** Self-hosted servers commonly run with no auth at all (a
//!   vLLM/Ollama instance reachable only inside the customer's own network), or accept
//!   any non-empty dummy bearer value. [`Self::new`] takes `Option<String>`; the
//!   `Authorization` header is only sent when a key is actually configured — no
//!   `Authorization` header at all otherwise, not an empty/placeholder one (some
//!   OpenAI-compatible servers are stricter about a malformed-but-present header than a
//!   missing one).
//!
//! Protocol-level tested only, same disclaimer [`crate::OpenRouterProvider`] shipped
//! with — no real vLLM/Ollama/LM Studio/text-generation-webui server was available to
//! live-verify against in this pass (see this feature's Changelog entry).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::client::{LlmMessage, LlmProvider, LlmRole, LlmTurn, ToolCall, ToolSchema};

#[derive(Debug, Serialize)]
struct SelfHostedFunctionCallOut {
    name: String,
    /// JSON-encoded string, **not** a nested object — same OpenAI-compatible wire shape
    /// as `OpenRouterFunctionCallOut`, see this module's docs.
    arguments: String,
}

#[derive(Debug, Serialize)]
struct SelfHostedToolCallOut {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    function: SelfHostedFunctionCallOut,
}

#[derive(Debug, Serialize)]
struct SelfHostedMessage {
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<SelfHostedToolCallOut>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct SelfHostedFunctionSchema {
    name: String,
    description: String,
    parameters: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct SelfHostedToolSchemaOut {
    #[serde(rename = "type")]
    kind: String,
    function: SelfHostedFunctionSchema,
}

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<SelfHostedMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<SelfHostedToolSchemaOut>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Debug, Deserialize)]
struct ChatChoice {
    message: SelfHostedResponseMessage,
}

#[derive(Debug, Deserialize)]
struct SelfHostedResponseMessage {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<SelfHostedToolCallIn>>,
}

#[derive(Debug, Deserialize)]
struct SelfHostedToolCallIn {
    id: String,
    function: SelfHostedFunctionCallIn,
}

#[derive(Debug, Deserialize)]
struct SelfHostedFunctionCallIn {
    name: String,
    /// Defensive — see [`parse_tool_call`]'s docs: accepted as either the spec's JSON
    /// string or (should some backend behind this provider deviate) a nested object.
    #[serde(default)]
    arguments: serde_json::Value,
}

fn parse_tool_call(tc: SelfHostedToolCallIn) -> ToolCall {
    let arguments = match tc.function.arguments {
        serde_json::Value::String(s) => {
            serde_json::from_str(&s).unwrap_or(serde_json::Value::String(s))
        }
        other => other,
    };
    ToolCall {
        name: tc.function.name,
        arguments,
        id: Some(tc.id),
    }
}

fn to_wire_messages(history: &[LlmMessage]) -> Vec<SelfHostedMessage> {
    history
        .iter()
        .map(|m| {
            let role = match m.role {
                LlmRole::System => "system",
                LlmRole::User => "user",
                LlmRole::Assistant => "assistant",
                LlmRole::Tool => "tool",
            }
            .to_string();
            let tool_calls = m.tool_call.as_ref().map(|tc| {
                vec![SelfHostedToolCallOut {
                    id: tc.id.clone().unwrap_or_default(),
                    kind: "function".to_string(),
                    function: SelfHostedFunctionCallOut {
                        name: tc.name.clone(),
                        arguments: tc.arguments.to_string(),
                    },
                }]
            });
            SelfHostedMessage {
                role,
                content: m.content.clone(),
                tool_calls,
                tool_call_id: m.tool_call_id.clone(),
            }
        })
        .collect()
}

/// Self-hosted OpenAI-compatible inference (vLLM/Ollama/LM Studio/text-generation-webui/
/// etc.) — real, network-calling [`LlmProvider`]. See this module's docs for the two
/// differences from [`crate::OpenRouterProvider`]: no fixed `base_url` default, optional
/// `api_key`.
pub struct SelfHostedProvider {
    http: reqwest::Client,
    api_key: Option<String>,
    model: String,
    base_url: String,
}

impl SelfHostedProvider {
    /// `base_url` is the full chat-completions endpoint (e.g.
    /// `http://localhost:11434/v1/chat/completions` for Ollama,
    /// `http://vllm-host:8000/v1/chat/completions` for vLLM) — the customer's own server,
    /// never defaulted. `api_key` is `None` when the server needs no auth at all (common
    /// for a self-hosted deployment reachable only inside the customer's network) — see
    /// this module's docs for why that's a real, expected configuration, not a degraded
    /// one; an empty string is treated the same as `None` (defensive — callers should
    /// already be filtering this the way `crate::assistant::build_provider` does for
    /// `OpenRouterProvider`, but nothing here depends on that). `model` is whatever name
    /// the server itself knows the loaded model by — not validated here, a bad name
    /// simply fails at the first real `chat()` call with the server's own error message,
    /// same posture as `OpenRouterProvider::new`.
    pub fn new(base_url: String, api_key: Option<String>, model: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            api_key: api_key.filter(|k| !k.is_empty()),
            model,
            base_url,
        }
    }
}

#[async_trait]
impl LlmProvider for SelfHostedProvider {
    async fn chat(&self, history: &[LlmMessage], tools: &[ToolSchema]) -> anyhow::Result<LlmTurn> {
        let messages = to_wire_messages(history);
        let tools_wire = if tools.is_empty() {
            None
        } else {
            Some(
                tools
                    .iter()
                    .map(|t| SelfHostedToolSchemaOut {
                        kind: "function".to_string(),
                        function: SelfHostedFunctionSchema {
                            name: t.name.clone(),
                            description: t.description.clone(),
                            parameters: t.parameters.clone(),
                        },
                    })
                    .collect(),
            )
        };
        let tool_choice = tools_wire.is_some().then(|| "auto".to_string());
        let request = ChatRequest {
            model: self.model.clone(),
            messages,
            tools: tools_wire,
            tool_choice,
        };

        // `Authorization` sent only when a key is actually configured — see this
        // module's docs: a missing key is an expected, common self-hosted setup, not a
        // fallback/error state, so there's no empty/placeholder header sent in its place.
        let mut request_builder = self.http.post(&self.base_url).json(&request);
        if let Some(key) = self.api_key.as_deref() {
            request_builder = request_builder.bearer_auth(key);
        }
        let response = request_builder.send().await?;
        let status = response.status();
        let body = response.text().await?;
        anyhow::ensure!(
            status.is_success(),
            "self-hosted chat completions returned HTTP {status}: {body}"
        );
        let parsed: ChatCompletionResponse = serde_json::from_str(&body).map_err(|e| anyhow::anyhow!("self-hosted response (HTTP {status}) was not the expected shape: {e}; body: {body}"))?;
        let choice = parsed
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("self-hosted response had no choices"))?;
        // Only the first tool call, if the model returned several — see
        // `crate::openrouter`'s module docs for the shared rationale.
        let tool_call = choice
            .message
            .tool_calls
            .and_then(|calls| calls.into_iter().next())
            .map(parse_tool_call);
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

    /// Same "real protocol, fake backend" approach `OpenRouterProvider`'s/
    /// `GigaChatProvider`'s own tests use — a real local TCP socket capturing the raw
    /// request bytes, rather than mocking at the `reqwest` layer.
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

    fn provider(base_url: &str) -> SelfHostedProvider {
        SelfHostedProvider::new(
            base_url.to_string(),
            Some("test-key".to_string()),
            "llama3".to_string(),
        )
    }

    #[tokio::test]
    async fn chat_sends_bearer_auth_history_and_tools_and_parses_text_reply() {
        let (url, handle) =
            capture_one_request(r#"{"choices":[{"message":{"content":"привет"}}]}"#).await;
        let p = provider(&url);

        let history = vec![LlmMessage::user("покажи тревоги")];
        let tools = vec![ToolSchema {
            name: "list_alerts".to_string(),
            description: "список тревог".to_string(),
            parameters: serde_json::json!({"type": "object", "properties": {}}),
        }];
        let turn = p.chat(&history, &tools).await.unwrap();
        assert_eq!(turn.text.as_deref(), Some("привет"));
        assert!(turn.tool_call.is_none());

        let raw = handle.await.unwrap();
        let request = String::from_utf8_lossy(&raw);
        assert!(
            request
                .to_lowercase()
                .contains("authorization: bearer test-key"),
            "missing bearer auth: {request}"
        );
        assert!(
            request.contains(r#""type":"function""#),
            "tool schema missing 'type':'function' wrapper: {request}"
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
    async fn chat_works_with_no_api_key_configured_at_all() {
        // The differentiator from OpenRouter/GigaChat — a self-hosted server commonly
        // needs no auth, so `None` must not add an `Authorization` header at all (not an
        // empty/placeholder one) and must not error out.
        let (url, handle) =
            capture_one_request(r#"{"choices":[{"message":{"content":"готово"}}]}"#).await;
        let p = SelfHostedProvider::new(url, None, "llama3".to_string());

        let turn = p.chat(&[LlmMessage::user("hi")], &[]).await.unwrap();
        assert_eq!(turn.text.as_deref(), Some("готово"));

        let raw = handle.await.unwrap();
        let request = String::from_utf8_lossy(&raw);
        assert!(
            !request.to_lowercase().contains("authorization"),
            "no api_key configured must mean no Authorization header at all: {request}"
        );
    }

    #[tokio::test]
    async fn chat_parses_a_tool_call_and_keeps_its_id() {
        let reply = r#"{"choices":[{"message":{"content":null,"tool_calls":[{"id":"call_abc123","type":"function","function":{"name":"list_alerts","arguments":"{\"level\":\"critical\"}"}}]}}]}"#;
        let (url, handle) = capture_one_request(reply).await;
        let p = provider(&url);

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
        assert_eq!(
            tool_call.id.as_deref(),
            Some("call_abc123"),
            "the wire id must survive parsing — it's what correlates the tool result back"
        );

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn chat_honors_only_the_first_tool_call_when_the_model_requests_several() {
        // Regression test for the documented "parallel tool calling" simplification —
        // see `crate::openrouter`'s module docs (shared rationale, same orchestration
        // loop consumes this provider's output too).
        let reply = r#"{"choices":[{"message":{"tool_calls":[
            {"id":"call_1","type":"function","function":{"name":"list_alerts","arguments":"{}"}},
            {"id":"call_2","type":"function","function":{"name":"list_devices","arguments":"{}"}}
        ]}}]}"#;
        let (url, handle) = capture_one_request(reply).await;
        let p = provider(&url);

        let turn = p.chat(&[LlmMessage::user("hi")], &[]).await.unwrap();
        let tool_call = turn.tool_call.expect("expected a tool call");
        assert_eq!(
            tool_call.name, "list_alerts",
            "must take only the first tool_calls entry"
        );
        assert_eq!(tool_call.id.as_deref(), Some("call_1"));

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn chat_sends_a_replayed_tool_call_arguments_as_a_json_string_not_an_object() {
        let (url, handle) =
            capture_one_request(r#"{"choices":[{"message":{"content":"готово"}}]}"#).await;
        let p = provider(&url);

        let history = vec![
            LlmMessage::user("покажи тревоги"),
            LlmMessage::assistant_tool_call(ToolCall {
                name: "list_alerts".to_string(),
                arguments: serde_json::json!({"level": "critical"}),
                id: Some("call_abc123".to_string()),
            }),
            LlmMessage::tool_result("list_alerts", r#"{"total":0}"#)
                .with_tool_call_id("call_abc123"),
        ];
        p.chat(&history, &[]).await.unwrap();

        let raw = handle.await.unwrap();
        let request = String::from_utf8_lossy(&raw);
        assert!(
            request.contains(r#""arguments":"{\"level\":\"critical\"}""#),
            "arguments must be a JSON-encoded string, not a nested object: {request}"
        );
        assert!(
            request.contains(r#""tool_call_id":"call_abc123""#),
            "the tool result message must carry the matching tool_call_id: {request}"
        );
    }

    #[tokio::test]
    async fn chat_fails_clearly_on_a_non_success_status() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 64 * 1024];
            let _ = stream.read(&mut buf).await.unwrap();
            let body = r#"{"error":{"message":"model not loaded"}}"#;
            let response = format!("HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.ok();
        });
        let p = provider(&format!("http://{addr}"));
        let err = p.chat(&[LlmMessage::user("hi")], &[]).await.unwrap_err();
        assert!(err.to_string().contains("503"), "unexpected error: {err}");

        handle.await.unwrap();
    }
}
