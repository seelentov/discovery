//! OpenRouter — the second [`LlmProvider`] implementation (2026-09-18, direct user
//! request: "внешние LLM кроме GigaChat", started with OpenRouter specifically because it
//! offers `:free`-suffixed models, making a genuine live-verification pass possible
//! without a paid key). Simpler than [`crate::GigaChatProvider`] in two ways: a single
//! static Bearer API key (no OAuth client-credentials exchange, no token cache) and no
//! custom TLS root CA (OpenRouter's certificate chains to an ordinary public CA, unlike
//! GigaChat's Russian Trusted Sub CA).
//!
//! **Wire format is the modern `tools`/`tool_calls` shape, not GigaChat's old
//! `functions`/`function_call`** — this is the reason `discovery_llm::ToolCall` grew an
//! `id` field and `LlmMessage` grew `tool_call_id`/`with_tool_call_id` (2026-09-18, added
//! alongside this provider): a `"tool"`-role message must carry the `tool_call_id` of the
//! specific call it answers, not just the tool's name — `GigaChatProvider` has no
//! equivalent concept and always leaves both `None`. **`function.arguments` is a
//! JSON-encoded string on both directions of this wire format** — the opposite of
//! GigaChat, where it's a nested object both ways (confirmed live for GigaChat
//! 2026-09-18, see that provider's docs for the bug that shipped from guessing wrong).
//! Taken here from the OpenAI Chat Completions API's own widely-documented, extremely
//! widely-implemented spec, not guessed — but still unconfirmed against a real network
//! call until this provider's own live verification happens (see this feature's
//! Changelog entry).
//!
//! **Only the first `tool_calls` entry is honored if the model requests several in one
//! turn ("parallel tool calling").** `crate::assistant::run_assistant_turn`'s
//! orchestration (in `discovery-web`) is built around exactly one tool call per turn
//! (`LlmTurn.tool_call: Option<ToolCall>`, not a list) — same "documented, deliberately
//! narrow simplification, not encountered live yet" posture as that loop's own
//! `MAX_TURN_ITERATIONS` cap. A model that truly needs parallel calling to make progress
//! will simply see one result per turn instead of several at once; it still converges,
//! just in more turns.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::client::{LlmMessage, LlmProvider, LlmRole, LlmTurn, ToolCall, ToolSchema};

#[derive(Debug, Serialize)]
struct OpenRouterFunctionCallOut {
    name: String,
    /// JSON-encoded string, **not** a nested object — see this module's docs for why
    /// that's the opposite of `GigaChatProvider`'s wire format.
    arguments: String,
}

#[derive(Debug, Serialize)]
struct OpenRouterToolCallOut {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    function: OpenRouterFunctionCallOut,
}

#[derive(Debug, Serialize)]
struct OpenRouterMessage {
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<OpenRouterToolCallOut>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct OpenRouterFunctionSchema {
    name: String,
    description: String,
    parameters: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct OpenRouterToolSchemaOut {
    #[serde(rename = "type")]
    kind: String,
    function: OpenRouterFunctionSchema,
}

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<OpenRouterMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<OpenRouterToolSchemaOut>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Debug, Deserialize)]
struct ChatChoice {
    message: OpenRouterResponseMessage,
}

#[derive(Debug, Deserialize)]
struct OpenRouterResponseMessage {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<OpenRouterToolCallIn>>,
}

#[derive(Debug, Deserialize)]
struct OpenRouterToolCallIn {
    id: String,
    function: OpenRouterFunctionCallIn,
}

#[derive(Debug, Deserialize)]
struct OpenRouterFunctionCallIn {
    name: String,
    /// Defensive — see [`parse_tool_call`]'s docs: accepted as either the spec's JSON
    /// string or (should some model behind OpenRouter deviate) a nested object.
    #[serde(default)]
    arguments: serde_json::Value,
}

fn parse_tool_call(tc: OpenRouterToolCallIn) -> ToolCall {
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

fn to_wire_messages(history: &[LlmMessage]) -> Vec<OpenRouterMessage> {
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
                vec![OpenRouterToolCallOut {
                    id: tc.id.clone().unwrap_or_default(),
                    kind: "function".to_string(),
                    function: OpenRouterFunctionCallOut {
                        name: tc.name.clone(),
                        arguments: tc.arguments.to_string(),
                    },
                }]
            });
            OpenRouterMessage {
                role,
                content: m.content.clone(),
                tool_calls,
                tool_call_id: m.tool_call_id.clone(),
            }
        })
        .collect()
}

/// OpenRouter — real, network-calling [`LlmProvider`]. See this module's docs for the
/// wire-format differences from [`crate::GigaChatProvider`].
pub struct OpenRouterProvider {
    http: reqwest::Client,
    api_key: String,
    model: String,
    base_url: String,
}

impl OpenRouterProvider {
    const BASE_URL: &'static str = "https://openrouter.ai/api/v1/chat/completions";

    /// `model` is an OpenRouter model id (e.g. `"openai/gpt-4o-mini"`, or any `:free`-
    /// suffixed id — see openrouter.ai/models) — not validated here, a bad id simply
    /// fails at the first real `chat()` call with OpenRouter's own error message.
    pub fn new(api_key: String, model: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            api_key,
            model,
            base_url: Self::BASE_URL.to_string(),
        }
    }

    #[cfg(test)]
    fn with_base_url(mut self, base: impl Into<String>) -> Self {
        self.base_url = base.into();
        self
    }
}

#[async_trait]
impl LlmProvider for OpenRouterProvider {
    async fn chat(&self, history: &[LlmMessage], tools: &[ToolSchema]) -> anyhow::Result<LlmTurn> {
        let messages = to_wire_messages(history);
        let tools_wire = if tools.is_empty() {
            None
        } else {
            Some(
                tools
                    .iter()
                    .map(|t| OpenRouterToolSchemaOut {
                        kind: "function".to_string(),
                        function: OpenRouterFunctionSchema {
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

        // "X-Title" is OpenRouter's optional attribution header (shown on their own
        // dashboard) — a plain identifying string, not a claimed URL, so there's nothing
        // here to get wrong the way a fabricated `HTTP-Referer` would be. Omitted
        // entirely would also be fine; this costs nothing to include.
        let response = self
            .http
            .post(&self.base_url)
            .bearer_auth(&self.api_key)
            .header("X-Title", "discovery")
            .json(&request)
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        anyhow::ensure!(
            status.is_success(),
            "OpenRouter chat completions returned HTTP {status}: {body}"
        );
        let parsed: ChatCompletionResponse = serde_json::from_str(&body).map_err(|e| {
            anyhow::anyhow!(
                "OpenRouter response (HTTP {status}) was not the expected shape: {e}; body: {body}"
            )
        })?;
        let choice = parsed
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("OpenRouter response had no choices"))?;
        // Only the first tool call, if the model returned several — see this module's docs.
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

    /// Same "real protocol, fake backend" approach `GigaChatProvider`'s own tests use — a
    /// real local TCP socket capturing the raw request bytes, rather than mocking at the
    /// `reqwest` layer.
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

    fn provider(base_url: &str) -> OpenRouterProvider {
        OpenRouterProvider::new("test-key".to_string(), "openai/gpt-4o-mini".to_string())
            .with_base_url(base_url)
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
        // see this module's docs.
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
        // Mirror image of the real bug found live on GigaChat (2026-09-18) — there,
        // `arguments` had to be a nested object on both sides; here, the OpenAI-compatible
        // spec requires the opposite (a JSON-encoded string) — getting this backwards
        // would be the same class of bug in the other direction.
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
            let body = r#"{"error":{"message":"invalid api key"}}"#;
            let response = format!("HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.ok();
        });
        let p = provider(&format!("http://{addr}"));
        let err = p.chat(&[LlmMessage::user("hi")], &[]).await.unwrap_err();
        assert!(err.to_string().contains("401"), "unexpected error: {err}");

        handle.await.unwrap();
    }
}
