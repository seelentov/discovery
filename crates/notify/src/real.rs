use async_trait::async_trait;
use discovery_core::{
    Alert, NotificationChannel, NotificationChannelKind, NotificationProviderConfig,
    NotificationTrigger,
};
use hmac::{Hmac, Mac};
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde::Serialize;
use sha2::Sha256;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tracing::warn;

use crate::format_alert_notification;
use crate::Notifier;

const TELEGRAM_API_BASE: &str = "https://api.telegram.org";
const NOTIFICATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Real sender — dispatches by [`NotificationChannel::kind`] inside one method, same
/// "protocol dispatched inside the implementation" shape
/// `discovery_servicecheck::RealServiceChecker::check` already uses for TCP/HTTP(S)/SSH.
/// Holds one shared `reqwest::Client` (built once, reused for every webhook/Telegram call)
/// — same "own the connection machinery once" reasoning `RealServiceChecker`/
/// `discovery_ping::IcmpPinger` give for their own shared clients. Email doesn't share a
/// long-lived connection the same way: a fresh SMTP session per send, mirroring
/// `discovery_ssh::RealCliClient`'s "reconnect every call, no session pool" choice (see that
/// type's docs for the equivalent reasoning — a low-volume, correctness-over-throughput
/// operation, not a hot path).
pub struct RealNotifier {
    http: reqwest::Client,
    request_timeout: Duration,
    /// `https://api.telegram.org` in production — overridable only via
    /// [`Self::with_telegram_api_base`], a test-only seam (not exposed through
    /// `NotificationProviderConfig`, which real operators configure: the Bot API's own
    /// hostname isn't something a deployment should ever need to change, only tests
    /// pointing at a local fake need to redirect it).
    telegram_api_base: String,
    #[cfg(test)]
    allow_local_webhook_targets: bool,
}

impl RealNotifier {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(NOTIFICATION_TIMEOUT)
                .build()?,
            request_timeout: NOTIFICATION_TIMEOUT,
            telegram_api_base: TELEGRAM_API_BASE.to_string(),
            #[cfg(test)]
            allow_local_webhook_targets: true,
        })
    }

    /// Test-only seam — see [`Self::telegram_api_base`]'s docs.
    #[cfg(test)]
    fn with_telegram_api_base(mut self, base: impl Into<String>) -> Self {
        self.telegram_api_base = base.into();
        self
    }

    #[cfg(test)]
    fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self.http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .expect("test HTTP client timeout is valid");
        self
    }

    async fn webhook_client(&self, target: &str) -> anyhow::Result<reqwest::Client> {
        let url = reqwest::Url::parse(target)
            .map_err(|_| anyhow::anyhow!("webhook target is not a valid URL"))?;
        anyhow::ensure!(
            matches!(url.scheme(), "http" | "https"),
            "webhook target must use http or https"
        );
        anyhow::ensure!(
            url.username().is_empty() && url.password().is_none(),
            "webhook target must not contain URL credentials"
        );
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("webhook target must contain a host"))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| anyhow::anyhow!("webhook target must specify a known port"))?;
        let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
        anyhow::ensure!(!addresses.is_empty(), "webhook target did not resolve");
        let selected = addresses
            .iter()
            .find(|address| {
                #[cfg(test)]
                if self.allow_local_webhook_targets {
                    return true;
                }
                !is_forbidden_webhook_ip(address.ip())
            })
            .copied()
            .ok_or_else(|| anyhow::anyhow!("webhook target resolves only to internal, loopback, link-local, or metadata addresses"))?;
        #[cfg(not(test))]
        anyhow::ensure!(
            !is_forbidden_webhook_ip(selected.ip()),
            "webhook target resolves to a forbidden address"
        );
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(self.request_timeout)
            .resolve(host, selected)
            .build()
            .map_err(Into::into)
    }

    async fn send_webhook(
        &self,
        channel: &NotificationChannel,
        alert: &Alert,
        trigger: NotificationTrigger,
    ) -> anyhow::Result<()> {
        #[derive(Serialize)]
        struct WebhookPayload<'a> {
            trigger: NotificationTrigger,
            alert: &'a Alert,
        }
        // The whole `Alert` is reused as-is (it already derives `Serialize`) rather than a
        // hand-duplicated field list — simpler, and it can never drift out of sync with
        // what `Alert` actually carries.
        let body = serde_json::to_vec(&WebhookPayload { trigger, alert })?;

        let client = self.webhook_client(&channel.target).await?;
        let mut request = client
            .post(&channel.target)
            .header("Content-Type", "application/json")
            .body(body.clone());
        if let Some(secret) = &channel.secret {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
                .expect("HMAC accepts a key of any length");
            mac.update(&body);
            let signature = hex::encode(mac.finalize().into_bytes());
            request = request.header("X-Discovery-Signature", signature);
        }

        let response = request.send().await?;
        let status = response.status();
        anyhow::ensure!(
            status.is_success(),
            "webhook {} returned HTTP {}",
            channel.target,
            status.as_u16()
        );
        Ok(())
    }

    async fn send_telegram(
        &self,
        channel: &NotificationChannel,
        provider: &NotificationProviderConfig,
        alert: &Alert,
        trigger: NotificationTrigger,
    ) -> anyhow::Result<()> {
        let token = provider.telegram_bot_token.as_deref().ok_or_else(|| anyhow::anyhow!("Telegram channel configured but no bot token is set in notification provider settings"))?;
        let (_, body) = format_alert_notification(alert, trigger);
        let url = format!("{}/bot{token}/sendMessage", self.telegram_api_base);

        #[derive(Serialize)]
        struct SendMessage<'a> {
            chat_id: &'a str,
            text: &'a str,
        }
        #[derive(serde::Deserialize)]
        struct TelegramResponse {
            ok: bool,
            description: Option<String>,
        }

        let response = self
            .http
            .post(&url)
            .json(&SendMessage {
                chat_id: &channel.target,
                text: &body,
            })
            .send()
            .await?;
        let status = response.status();
        let parsed: TelegramResponse = response.json().await.map_err(|e| {
            anyhow::anyhow!("Telegram API response (HTTP {status}) was not the expected shape: {e}")
        })?;
        anyhow::ensure!(
            parsed.ok,
            "Telegram API rejected the message: {}",
            parsed
                .description
                .unwrap_or_else(|| "no description".to_string())
        );
        Ok(())
    }

    async fn send_email(
        &self,
        channel: &NotificationChannel,
        provider: &NotificationProviderConfig,
        alert: &Alert,
        trigger: NotificationTrigger,
    ) -> anyhow::Result<()> {
        let host = provider.smtp_host.as_deref().ok_or_else(|| anyhow::anyhow!("Email channel configured but no SMTP host is set in notification provider settings"))?;
        let from = provider.smtp_from_address.as_deref().ok_or_else(|| anyhow::anyhow!("Email channel configured but no SMTP from-address is set in notification provider settings"))?;
        let (subject, body) = format_alert_notification(alert, trigger);

        let from: Mailbox = from
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid smtp_from_address '{from}': {e}"))?;
        let to: Mailbox = channel.target.parse().map_err(|e| {
            anyhow::anyhow!("invalid email channel target '{}': {e}", channel.target)
        })?;
        let email = Message::builder()
            .from(from)
            .to(to)
            .subject(subject)
            .body(body)?;

        // `starttls_relay` — mandatory STARTTLS upgrade before authenticating, the correct
        // default for a real SMTP relay on the standard submission port (587). Unlike
        // `SnmpAuth::Community`'s "not really a secret" passthrough, there's no legitimate
        // "send credentials in the clear" mode worth supporting here.
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)?
            .port(provider.smtp_port)
            .timeout(Some(NOTIFICATION_TIMEOUT));
        if let (Some(username), Some(password)) = (&provider.smtp_username, &provider.smtp_password)
        {
            builder = builder.credentials(Credentials::new(username.clone(), password.clone()));
        }
        let mailer = builder.build();
        mailer.send(email).await?;
        Ok(())
    }
}

fn is_forbidden_webhook_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.octets()[0] == 0
                || ip.octets()[0] == 100 && (ip.octets()[1] & 0b1100_0000) == 0b0100_0000
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.segments()[0] & 0xffc0 == 0xfe80
        }
    }
}

#[async_trait]
impl Notifier for RealNotifier {
    async fn send(
        &self,
        channel: &NotificationChannel,
        provider: &NotificationProviderConfig,
        alert: &Alert,
        trigger: NotificationTrigger,
    ) -> anyhow::Result<()> {
        if !channel.enabled {
            // Defensive — `AlertEvalHandler::dispatch_notifications` already filters to
            // `enabled` channels before enqueuing a job at all, so reaching here with a
            // disabled channel would mean a stale job outlived a channel being turned off
            // after it was already queued. Treated as a silent no-op success (not a retry-
            // worthy error): the operator's intent ("stop notifying this channel") should
            // win, not get overridden by a job that predates it.
            warn!(channel_id = %channel.id, "skipping delivery to a channel that was disabled after its dispatch job was enqueued");
            return Ok(());
        }
        match channel.kind {
            NotificationChannelKind::Webhook => self.send_webhook(channel, alert, trigger).await,
            NotificationChannelKind::Telegram => {
                self.send_telegram(channel, provider, alert, trigger).await
            }
            NotificationChannelKind::Email => {
                self.send_email(channel, provider, alert, trigger).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use discovery_core::{AlertLevel, AlertState};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use uuid::Uuid;

    fn channel(
        kind: NotificationChannelKind,
        target: &str,
        secret: Option<&str>,
    ) -> NotificationChannel {
        NotificationChannel {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            kind,
            target: target.to_string(),
            secret: secret.map(|s| s.to_string()),
            enabled: true,
            created_at: chrono::Utc::now(),
        }
    }

    fn alert() -> Alert {
        Alert {
            details: Default::default(),
            id: Uuid::new_v4(),
            device_id: Uuid::new_v4(),
            device_ip: "10.0.0.5".to_string(),
            name: "high_cpu".to_string(),
            row_key: None,
            level: AlertLevel::Critical,
            message: "CPU 97%".to_string(),
            state: AlertState::Active,
            facts: None,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            cleared_at: None,
            closed_by: None,
            acknowledged_by: None,
            acknowledged_at: None,
            snoozed_until: None,
            snoozed_by: None,
            auto_clear_reason: None,
            repeat_count: 0,
            escalation_level: 0,
            repeated_at: None,
            escalation_reason: None,
            flapping: false,
            suppression_reason: None,
            comment_count: 0,
            suppressed_by_alert_id: None,
            reopened_from_alert_id: None,
        }
    }

    #[test]
    fn webhook_forbidden_ip_ranges_include_metadata_and_private_space() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "192.168.1.1",
            "::1",
            "fc00::1",
            "fe80::1",
        ] {
            assert!(
                is_forbidden_webhook_ip(ip.parse().unwrap()),
                "{ip} must be blocked"
            );
        }
        assert!(!is_forbidden_webhook_ip("8.8.8.8".parse().unwrap()));
    }

    /// Minimal HTTP/1.1 request-capturing listener — same "real protocol, fake backend"
    /// approach `discovery-servicecheck`/`discovery-ssh`'s own tests already use against a
    /// real TCP socket rather than mocking at the `reqwest`/HTTP-client level. Reads exactly
    /// one request, replies `200 OK` with `reply_body`, and hands the raw request bytes back
    /// to the caller for inspection.
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

    #[tokio::test]
    async fn webhook_posts_json_body_with_trigger_and_alert() {
        let (url, handle) = capture_one_request("").await;
        let notifier = RealNotifier::new().unwrap();
        let c = channel(NotificationChannelKind::Webhook, &url, None);
        notifier
            .send(
                &c,
                &NotificationProviderConfig::default(),
                &alert(),
                NotificationTrigger::Activated,
            )
            .await
            .unwrap();

        let raw = handle.await.unwrap();
        let request = String::from_utf8_lossy(&raw);
        assert!(
            request.starts_with("POST "),
            "unexpected request line: {request}"
        );
        assert!(
            request.contains("\"trigger\":\"activated\""),
            "request body missing trigger: {request}"
        );
        assert!(
            request.contains("\"name\":\"high_cpu\""),
            "request body missing alert name: {request}"
        );
        assert!(
            !request.to_lowercase().contains("x-discovery-signature"),
            "no secret configured — must not sign"
        );
    }

    #[tokio::test]
    async fn webhook_with_a_secret_adds_a_verifiable_hmac_signature() {
        let (url, handle) = capture_one_request("").await;
        let notifier = RealNotifier::new().unwrap();
        let c = channel(NotificationChannelKind::Webhook, &url, Some("sekrit"));
        notifier
            .send(
                &c,
                &NotificationProviderConfig::default(),
                &alert(),
                NotificationTrigger::Cleared,
            )
            .await
            .unwrap();

        let raw = handle.await.unwrap();
        let request = String::from_utf8_lossy(&raw);
        let sig_header = request
            .lines()
            .find(|l| l.to_lowercase().starts_with("x-discovery-signature:"))
            .expect("signature header missing");
        let signature = sig_header.split(':').nth(1).unwrap().trim();

        // The body is whatever follows the blank line separating headers from body.
        let body = request.split("\r\n\r\n").nth(1).unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(b"sekrit").unwrap();
        mac.update(body.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!(
            signature, expected,
            "signature must verify against the exact body bytes sent"
        );
    }

    #[tokio::test]
    async fn webhook_timeout_releases_delivery_instead_of_hanging_forever() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let notifier = RealNotifier::new()
            .unwrap()
            .with_request_timeout(Duration::from_millis(20));
        let c = channel(
            NotificationChannelKind::Webhook,
            &format!("http://{addr}"),
            None,
        );
        let started = std::time::Instant::now();
        let err = notifier
            .send(
                &c,
                &NotificationProviderConfig::default(),
                &alert(),
                NotificationTrigger::Activated,
            )
            .await
            .unwrap_err();

        assert!(!err.to_string().is_empty());
        assert!(
            started.elapsed() < Duration::from_millis(80),
            "hung webhook was not bounded: {:?}",
            started.elapsed()
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn telegram_posts_chat_id_and_text_to_the_bot_token_path() {
        let (url, handle) = capture_one_request(r#"{"ok":true}"#).await;
        let notifier = RealNotifier::new().unwrap().with_telegram_api_base(url);
        let c = channel(NotificationChannelKind::Telegram, "123456", None);
        let provider = NotificationProviderConfig {
            telegram_bot_token: Some("test-token".to_string()),
            ..Default::default()
        };

        notifier
            .send(&c, &provider, &alert(), NotificationTrigger::Activated)
            .await
            .unwrap();

        let raw = handle.await.unwrap();
        let request = String::from_utf8_lossy(&raw);
        assert!(
            request.starts_with("POST /bottest-token/sendMessage"),
            "unexpected request line: {request}"
        );
        assert!(request.contains("\"chat_id\":\"123456\""));
        assert!(
            request.contains("high_cpu") || request.contains("CPU 97%"),
            "text must carry the alert content: {request}"
        );
    }

    #[tokio::test]
    async fn telegram_rejects_when_the_api_reports_ok_false() {
        let (url, _handle) =
            capture_one_request(r#"{"ok":false,"description":"chat not found"}"#).await;
        let notifier = RealNotifier::new().unwrap().with_telegram_api_base(url);
        let c = channel(NotificationChannelKind::Telegram, "bogus-chat", None);
        let provider = NotificationProviderConfig {
            telegram_bot_token: Some("test-token".to_string()),
            ..Default::default()
        };

        let err = notifier
            .send(&c, &provider, &alert(), NotificationTrigger::Activated)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("chat not found"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn telegram_without_bot_token_fails_fast_without_a_network_call() {
        let notifier = RealNotifier::new().unwrap();
        let c = channel(NotificationChannelKind::Telegram, "123456", None);
        let err = notifier
            .send(
                &c,
                &NotificationProviderConfig::default(),
                &alert(),
                NotificationTrigger::Activated,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("bot token"));
    }

    #[tokio::test]
    async fn email_without_smtp_host_configured_fails_fast_without_a_network_call() {
        let notifier = RealNotifier::new().unwrap();
        let c = channel(NotificationChannelKind::Email, "user@example.com", None);
        let err = notifier
            .send(
                &c,
                &NotificationProviderConfig::default(),
                &alert(),
                NotificationTrigger::Activated,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("SMTP host"));
    }

    #[tokio::test]
    async fn disabled_channel_is_a_silent_no_op() {
        let notifier = RealNotifier::new().unwrap();
        let mut c = channel(NotificationChannelKind::Webhook, "http://127.0.0.1:1", None); // nothing listening
        c.enabled = false;
        notifier
            .send(
                &c,
                &NotificationProviderConfig::default(),
                &alert(),
                NotificationTrigger::Activated,
            )
            .await
            .unwrap();
    }
}
