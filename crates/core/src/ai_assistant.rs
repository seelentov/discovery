use serde::{Deserialize, Serialize};

/// System-wide AI provider credentials — one backend at a time
/// (`discovery_llm::LlmProvider`, selected by `provider`), configured once by an admin and
/// used by every user's assistant chat, not per-user. Stored as a
/// `discovery_core::SettingsStore` category, added 2026-09-18 alongside the AI assistant
/// feature — see that trait's docs for why a new category is a new typed method over the
/// existing generic `settings` table, not a new migration/table. Configuring this is
/// deliberately admin-only (`admin_guard!`, like `/api/users`/`/api/roles`), not gated by a
/// `discovery_core::Domain` — unlike `NotificationProviderConfig`, using the assistant chat
/// itself has no domain gate at all (any authenticated user may open it; what the assistant
/// can *do* is bounded entirely by that user's own domain permissions at tool-execution
/// time), so there is no natural domain to hang this settings category off of either.
///
/// **Flat struct with one field group per provider** (`client_*` for GigaChat,
/// `openrouter_*` for OpenRouter, `self_hosted_*` for self-hosted OpenAI-compatible
/// servers (vLLM/Ollama/etc., 2026-09-18 — third provider, direct user request "внешние
/// LLM кроме GigaChat" plus the self-hosted follow-up), same shape
/// `NotificationProviderConfig` already uses for `smtp_*`/`telegram_*` — not a nested
/// enum keyed by `provider`. Only the group named by `provider` is ever read by
/// `crate::assistant::build_provider` in `discovery-web`; the other groups' fields simply
/// sit unused (and still redacted-on-read like any other secret here) until `provider`
/// switches to them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AiAssistantProviderConfig {
    #[serde(default)]
    pub enabled: bool,
    /// `"gigachat"` | `"openrouter"` | `"self_hosted"` — which field group below is
    /// actually used.
    #[serde(default = "default_provider")]
    pub provider: String,
    // ---- GigaChat ----
    #[serde(default)]
    pub client_id: String,
    /// Encrypted at rest by `discovery-config-store`'s `SettingsStore` implementation via
    /// `crate::secret::encrypt_secret`/`decrypt_secret`, same as
    /// [`crate::NotificationProviderConfig::smtp_password`] — plaintext here in memory
    /// only.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// OAuth scope — `"GIGACHAT_API_PERS"` (personal), `"GIGACHAT_API_B2B"` (pay-as-you-go
    /// business) or `"GIGACHAT_API_CORP"` (contract-based corporate). Found live during the
    /// 2026-09-20 pre-release audit: `crate::assistant::build_provider` hardcoded the
    /// personal-tariff scope even though `GigaChatProvider::new` already took it as a
    /// parameter — a customer on a B2B/CORP tariff could never actually connect. Not an
    /// `Option` — always some scope is required for OAuth to succeed, so the default just
    /// preserves the previous (personal-tariff) behavior for anyone who never touches this
    /// field.
    #[serde(default = "default_gigachat_scope")]
    pub client_scope: String,
    // ---- OpenRouter ----
    /// Encrypted at rest — same treatment as `client_secret` above.
    #[serde(default)]
    pub openrouter_api_key: Option<String>,
    /// An OpenRouter model id (e.g. `"openai/gpt-4o-mini"`, or a `:free`-suffixed one —
    /// see openrouter.ai/models). Not a secret — plain text, unlike `openrouter_api_key`.
    #[serde(default)]
    pub openrouter_model: String,
    // ---- Self-hosted (vLLM/Ollama/LM Studio/text-generation-webui/...) ----
    /// The customer's own server — e.g. `"http://localhost:11434/v1/chat/completions"`
    /// for a local Ollama. No compiled-in default the way `OpenRouterProvider::BASE_URL`
    /// is; required when `provider == "self_hosted"`.
    #[serde(default)]
    pub self_hosted_base_url: String,
    /// Encrypted at rest — same treatment as `client_secret`/`openrouter_api_key` above.
    /// Genuinely optional (not just "empty means unset the way the others are read") —
    /// many self-hosted deployments run with no auth at all; see
    /// `discovery_llm::SelfHostedProvider`'s docs for why a missing key sends no
    /// `Authorization` header at all rather than an empty/placeholder one.
    #[serde(default)]
    pub self_hosted_api_key: Option<String>,
    /// Whatever name the self-hosted server itself knows the loaded model by. Not a
    /// secret — plain text, required when `provider == "self_hosted"`.
    #[serde(default)]
    pub self_hosted_model: String,
}

fn default_provider() -> String {
    "gigachat".to_string()
}

fn default_gigachat_scope() -> String {
    "GIGACHAT_API_PERS".to_string()
}

/// `#[derive(Default)]` would give `provider: String::new()` (per-field
/// `Default::default()`, blind to the `#[serde(default = "...")]` attribute above) —
/// implemented by hand instead so `AiAssistantProviderConfig::default()` (the
/// `SettingsStore::ai_assistant_provider()` convenience fallback for "nothing configured
/// yet") lands on the same `"gigachat"` a freshly-deserialized empty JSON object would,
/// same reasoning as [`crate::NotificationProviderConfig`]'s hand-written `Default` for
/// `smtp_port`.
impl Default for AiAssistantProviderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: default_provider(),
            client_id: String::new(),
            client_secret: None,
            client_scope: default_gigachat_scope(),
            openrouter_api_key: None,
            openrouter_model: String::new(),
            self_hosted_base_url: String::new(),
            self_hosted_api_key: None,
            self_hosted_model: String::new(),
        }
    }
}
