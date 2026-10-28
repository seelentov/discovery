use async_trait::async_trait;
use std::collections::VecDeque;
use tokio::sync::Mutex;

use crate::{LlmMessage, LlmProvider, LlmTurn, ToolSchema};

/// Scripted [`LlmProvider`] for tests/e2e — same "in-memory recorded calls" shape as
/// `discovery_notify::FakeNotifier`. Real GigaChat never participates in automated tests
/// (network calls to a paid, rate-limited external API would make them slow, costly, and
/// non-deterministic); every unit/integration/e2e test that needs a chat orchestration
/// loop scripts one of these instead. Popping past the end of the scripted queue panics —
/// a test bug (a turn calling `chat()` more times than the test scripted for), not a
/// production scenario to paper over.
pub struct FakeLlmProvider {
    responses: Mutex<VecDeque<LlmTurn>>,
    /// Every call this provider received, in order — `(history, tools)` — so a test can
    /// assert what the orchestration loop actually sent (e.g. that a tool result got
    /// appended to history before the next call).
    pub calls: Mutex<Vec<(Vec<LlmMessage>, Vec<ToolSchema>)>>,
}

impl FakeLlmProvider {
    pub fn with_responses(responses: Vec<LlmTurn>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub async fn call_count(&self) -> usize {
        self.calls.lock().await.len()
    }
}

#[async_trait]
impl LlmProvider for FakeLlmProvider {
    async fn chat(&self, history: &[LlmMessage], tools: &[ToolSchema]) -> anyhow::Result<LlmTurn> {
        self.calls
            .lock()
            .await
            .push((history.to_vec(), tools.to_vec()));
        self.responses.lock().await.pop_front().ok_or_else(|| anyhow::anyhow!("FakeLlmProvider ran out of scripted responses — the test scripted fewer turns than the orchestration loop actually needed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_scripted_responses_in_order_and_records_calls() {
        let fake = FakeLlmProvider::with_responses(vec![
            LlmTurn {
                text: Some("first".to_string()),
                tool_call: None,
            },
            LlmTurn {
                text: Some("second".to_string()),
                tool_call: None,
            },
        ]);

        let turn1 = fake.chat(&[LlmMessage::user("a")], &[]).await.unwrap();
        assert_eq!(turn1.text.as_deref(), Some("first"));
        let turn2 = fake.chat(&[LlmMessage::user("b")], &[]).await.unwrap();
        assert_eq!(turn2.text.as_deref(), Some("second"));

        assert_eq!(fake.call_count().await, 2);
        let calls = fake.calls.lock().await;
        assert_eq!(calls[0].0[0].content.as_deref(), Some("a"));
        assert_eq!(calls[1].0[0].content.as_deref(), Some("b"));
    }

    #[tokio::test]
    #[should_panic(expected = "ran out of scripted responses")]
    async fn panics_clearly_when_the_script_runs_out() {
        let fake = FakeLlmProvider::with_responses(vec![]);
        fake.chat(&[LlmMessage::user("a")], &[]).await.unwrap();
    }
}
