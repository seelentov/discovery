//! `discovery-llm` — provider-agnostic LLM chat client for the AI assistant feature.
//! [`LlmProvider`] is the trait every backend implements; [`GigaChatProvider`] is the
//! real GigaChat (Sber) implementation (2026-09-18, first backend — see
//! `docs/Roadmap.md`'s self-hosted-model follow-up item for why this is a trait and not
//! a concrete struct baked into the caller), [`OpenRouterProvider`] the second (same day,
//! separate follow-up request — see that module's docs for the wire-format differences
//! this one exposed: OpenAI-style `tools`/`tool_calls`, id-correlated tool results,
//! `arguments` as a JSON string rather than GigaChat's nested object), [`FakeLlmProvider`]
//! is the scripted test/e2e double. Mirrors `discovery-notify`'s
//! `Notifier`/`RealNotifier`/`FakeNotifier` split.

mod client;
mod fake;
mod openrouter;
mod self_hosted;

pub use client::*;
pub use fake::*;
pub use openrouter::*;
pub use self_hosted::*;
