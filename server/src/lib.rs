//! Hypercast public rendezvous and opaque relay service.
//!
//! This process deliberately knows nothing about video, input, clipboard, or audio. It issues
//! short-lived, single-use endpoint tickets and forwards only `HCE1` encrypted envelopes. The
//! business ingress is disabled by default so a server can be deployed and health-checked before
//! Host/Android pairing and authenticated key establishment are available.

use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use axum::middleware::{self, Next};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use futures::{SinkExt, StreamExt};
use p256::{
    ecdsa::{signature::Verifier, Signature as P256Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
};
use ring::{
    digest, hmac,
    rand::{SecureRandom, SystemRandom},
    signature::{UnparsedPublicKey, ED25519},
};
pub mod telemetry;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
// 跨端纯函数协议实现唯一来源(conformance 由 protocol-kit fixtures 锁定)
use hypercast_protocol_kit::{
    client_handshake_offer_transcript, host_registration_transcript, mailbox_id_for_token,
    p2p_answer_transcript, p2p_offer_transcript, session_handshake_transcript,
    ticket_request_transcript,
};
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc, Mutex},
};

const HCE1_MAGIC: &[u8; 4] = b"HCE1";

/// 观测计数器(Prometheus /metrics)。无锁原子, 对热路径零影响。
struct ObservabilityCounters {
    registrations: std::sync::atomic::AtomicU64,
    session_requests: std::sync::atomic::AtomicU64,
    session_completions: std::sync::atomic::AtomicU64,
    tickets_issued: std::sync::atomic::AtomicU64,
    requests_total: std::sync::atomic::AtomicU64,
}
static COUNTERS: ObservabilityCounters = ObservabilityCounters {
    registrations: std::sync::atomic::AtomicU64::new(0),
    session_requests: std::sync::atomic::AtomicU64::new(0),
    session_completions: std::sync::atomic::AtomicU64::new(0),
    tickets_issued: std::sync::atomic::AtomicU64::new(0),
    requests_total: std::sync::atomic::AtomicU64::new(0),
};

async fn metrics_endpoint() -> Response {
    use std::sync::atomic::Ordering;
    let body = format!(
        "# HELP hypercast_rendezvous_registrations_total Host mailbox registrations.\n# TYPE hypercast_rendezvous_registrations_total counter\nhypercast_rendezvous_registrations_total {{}} {}\n# HELP hypercast_rendezvous_session_requests_total Client session requests accepted.\n# TYPE hypercast_rendezvous_session_requests_total counter\nhypercast_rendezvous_session_requests_total {{}} {}\n# HELP hypercast_rendezvous_session_completions_total Host completions accepted.\n# TYPE hypercast_rendezvous_session_completions_total counter\nhypercast_rendezvous_session_completions_total {{}} {}\n# HELP hypercast_rendezvous_tickets_issued_total Tickets issued.\n# TYPE hypercast_rendezvous_tickets_issued_total counter\nhypercast_rendezvous_tickets_issued_total {{}} {}\n# HELP hypercast_rendezvous_http_requests_total HTTP requests served.\n# TYPE hypercast_rendezvous_http_requests_total counter\nhypercast_rendezvous_http_requests_total {{}} {}\n",
        COUNTERS.registrations.load(Ordering::Relaxed),
        COUNTERS.session_requests.load(Ordering::Relaxed),
        COUNTERS.session_completions.load(Ordering::Relaxed),
        COUNTERS.tickets_issued.load(Ordering::Relaxed),
        COUNTERS.requests_total.load(Ordering::Relaxed),
    );
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
}
const MAX_SEALED_ENVELOPE_BYTES: usize = 8 * 1024 * 1024 + 128;
const DEFAULT_TICKET_TTL: Duration = Duration::from_secs(60);
const MAX_TICKET_TTL: Duration = Duration::from_secs(5 * 60);
const TICKET_REQUEST_PROTOCOL: &str = "hypercast-ticket-request/1";
const ENDPOINT_CLAIM_MAGIC: &[u8; 4] = b"HCR1";
const HOST_REGISTRATION_PROTOCOL: &str = "hypercast-host-registration/1";
const SESSION_REQUEST_PROTOCOL: &str = "hypercast-session-request/1";
const SESSION_COMPLETION_PROTOCOL: &str = "hypercast-session-completion/1";
const MAX_HOST_LEASE: Duration = Duration::from_secs(10 * 60);
const MAX_PENDING_SESSIONS_PER_HOST: usize = 8;
const MAX_P2P_SDP_BYTES: usize = 64 * 1024;
// 2026-09-03：600s 默认是中继视频每 10 分钟整点必死的最终根源（凭证 expiry 嵌在
// username 里，coturn use-auth-secret 按 expiry 拒绝过期凭证的一切续期事务——
// Refresh/Permission 全灭，实测三轮分秒吻合）。会话常跑远超 10 分钟，默认拉到
// 1 小时（MAX 同值）；客户端续签机制后续另做。
const DEFAULT_TURN_CREDENTIAL_TTL: Duration = Duration::from_secs(60 * 60);
const MAX_TURN_CREDENTIAL_TTL: Duration = Duration::from_secs(60 * 60);
const MAX_ICE_URLS: usize = 8;
const PERSISTED_STATE_VERSION: u8 = 1;
const MAX_PERSISTED_STATE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PERSISTED_MAILBOXES: usize = 4_096;
const MAX_PERSISTED_TICKETS: usize = 4_096;
const MAX_PERSISTED_NONCES: usize = 16_384;
const SLOW_RELAY_FORWARD: Duration = Duration::from_millis(25);

#[derive(Clone, Debug)]
pub struct TurnCredentialConfig {
    pub urls: Vec<String>,
    pub shared_secret: Vec<u8>,
    pub credential_ttl: Duration,
}

impl TurnCredentialConfig {
    fn issue(&self, mailbox_id: &str, now_unix_seconds: u64) -> Result<IssuedTurnCredential> {
        let expires_at_unix_seconds = now_unix_seconds
            .checked_add(self.credential_ttl.as_secs())
            .context("TURN credential expiry overflow")?;
        let mailbox_suffix = mailbox_id.get(..16).context("invalid TURN mailbox ID")?;
        let session_suffix = random_hex(8)
            .map_err(|_| anyhow::anyhow!("TURN credential nonce generation failed"))?;
        let username = format!("{expires_at_unix_seconds}:{mailbox_suffix}:{session_suffix}");
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &self.shared_secret);
        let credential = BASE64_STANDARD.encode(hmac::sign(&key, username.as_bytes()).as_ref());
        Ok(IssuedTurnCredential {
            urls: self.urls.clone(),
            username,
            credential,
            expires_at_unix_ms: expires_at_unix_seconds.saturating_mul(1_000),
        })
    }
}

struct IssuedTurnCredential {
    urls: Vec<String>,
    username: String,
    credential: String,
    expires_at_unix_ms: u64,
}

#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub bind: SocketAddr,
    pub enabled: bool,
    pub public_relay_url: String,
    pub admin_token: Option<String>,
    pub ticket_ttl: Duration,
    pub stun_urls: Vec<String>,
    pub turn: Option<TurnCredentialConfig>,
    pub state_file: Option<PathBuf>,
}

impl RelayConfig {
    pub fn from_env() -> Result<Self> {
        let bind = env::var("HYPERCAST_RELAY_BIND")
            .unwrap_or_else(|_| "127.0.0.1:5443".to_owned())
            .parse()
            .context("parse HYPERCAST_RELAY_BIND")?;
        let enabled = env_flag("HYPERCAST_RELAY_ENABLED")?;
        let public_relay_url = env::var("HYPERCAST_RELAY_PUBLIC_URL")
            .unwrap_or_else(|_| "wss://relay.invalid/v1/relay".to_owned());
        let admin_token = env::var("HYPERCAST_RELAY_ADMIN_TOKEN").ok();
        let ticket_ttl = env::var("HYPERCAST_RELAY_TICKET_TTL_SECS")
            .ok()
            .map(|value| {
                value
                    .parse::<u64>()
                    .context("parse HYPERCAST_RELAY_TICKET_TTL_SECS")
            })
            .transpose()?
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_TICKET_TTL);
        let stun_urls = parse_ice_urls(
            "HYPERCAST_STUN_URLS",
            env::var("HYPERCAST_STUN_URLS")
                // 默认用自建 STUN(与本服务 TURN 同机);Google STUN 国内不可达,
                // 会导致客户端 srflx 恒为 0、跨网会话无法打洞(2026-08-29 实测)。
                .unwrap_or_else(|_| "stun:relay.example.com:3478".into()),
            &["stun:", "stuns:"],
        )?;
        let turn_urls = env::var("HYPERCAST_TURN_URLS").ok();
        let turn_secret = env::var("HYPERCAST_TURN_SHARED_SECRET").ok();
        let state_file = env::var_os("HYPERCAST_RELAY_STATE_FILE").map(PathBuf::from);
        let turn = match (turn_urls, turn_secret) {
            (None, None) => None,
            (Some(urls), Some(secret)) => {
                if secret.len() < 32 {
                    anyhow::bail!("TURN shared secret must contain at least 32 characters");
                }
                let credential_ttl = env::var("HYPERCAST_TURN_CREDENTIAL_TTL_SECS")
                    .ok()
                    .map(|value| {
                        value
                            .parse::<u64>()
                            .context("parse HYPERCAST_TURN_CREDENTIAL_TTL_SECS")
                    })
                    .transpose()?
                    .map(Duration::from_secs)
                    .unwrap_or(DEFAULT_TURN_CREDENTIAL_TTL);
                if credential_ttl.is_zero() || credential_ttl > MAX_TURN_CREDENTIAL_TTL {
                    anyhow::bail!("TURN credential TTL must be between 1 and 3600 seconds");
                }
                Some(TurnCredentialConfig {
                    urls: parse_ice_urls("HYPERCAST_TURN_URLS", urls, &["turn:", "turns:"])?,
                    shared_secret: secret.into_bytes(),
                    credential_ttl,
                })
            }
            _ => anyhow::bail!(
                "HYPERCAST_TURN_URLS and HYPERCAST_TURN_SHARED_SECRET must be configured together"
            ),
        };

        if ticket_ttl.is_zero() || ticket_ttl > MAX_TICKET_TTL {
            anyhow::bail!(
                "ticket TTL must be between 1 and {} seconds",
                MAX_TICKET_TTL.as_secs()
            );
        }
        if enabled {
            let token = admin_token.as_deref().unwrap_or_default();
            if token.len() < 32 {
                anyhow::bail!("enabled relay requires a 32+ character HYPERCAST_RELAY_ADMIN_TOKEN");
            }
            if !public_relay_url.starts_with("wss://") {
                anyhow::bail!(
                    "enabled relay requires an HTTPS WebSocket HYPERCAST_RELAY_PUBLIC_URL"
                );
            }
            if state_file.as_ref().is_some_and(|path| !path.is_absolute()) {
                anyhow::bail!("HYPERCAST_RELAY_STATE_FILE must be an absolute path");
            }
        }
        Ok(Self {
            bind,
            enabled,
            public_relay_url,
            admin_token,
            ticket_ttl,
            stun_urls,
            turn,
            state_file,
        })
    }
}

fn parse_ice_urls(name: &str, value: String, allowed_schemes: &[&str]) -> Result<Vec<String>> {
    let urls = value
        .split(',')
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if urls.is_empty() || urls.len() > MAX_ICE_URLS {
        anyhow::bail!("{name} must contain between 1 and {MAX_ICE_URLS} URLs");
    }
    for url in &urls {
        if url.len() > 512 || !allowed_schemes.iter().any(|scheme| url.starts_with(scheme)) {
            anyhow::bail!("{name} contains an invalid ICE URL");
        }
    }
    Ok(urls)
}

pub async fn serve_from_env() -> Result<()> {
    let config = RelayConfig::from_env()?;
    if let Ok(directory_url) = std::env::var("HYPERCAST_DIRECTORY_URL") {
        let node_id =
            std::env::var("HYPERCAST_NODE_ID").unwrap_or_else(|_| "unnamed-node".to_owned());
        telemetry::spawn(directory_url, node_id.clone());
        tracing::info!(
            node_id,
            "telemetry reporting enabled (opt-in, aggregates only)"
        );
    }
    let bind = config.bind;
    let state = AppState::load(config).await?;
    let app = app_with_state(state);
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .context("bind rendezvous relay")?;
    tracing::info!(%bind, "Hypercast rendezvous relay listening");
    axum::serve(listener, app)
        .await
        .context("serve rendezvous relay")
}

pub fn app(config: RelayConfig) -> Router {
    app_with_state(AppState::new(config))
}

fn app_with_state(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/metrics", get(metrics_endpoint))
        .route("/v1/hosts/:mailbox_id/register", post(register_host))
        .route(
            "/v1/hosts/:mailbox_id/requests",
            post(submit_session_request),
        )
        .route(
            "/v1/hosts/:mailbox_id/requests/next",
            get(next_session_request),
        )
        .route(
            "/v1/hosts/:mailbox_id/requests/:request_id/complete",
            post(complete_session_request),
        )
        .route(
            "/v1/hosts/:mailbox_id/requests/:request_id",
            get(session_status),
        )
        .route("/v1/hosts/:mailbox_id/ice-config", get(ice_configuration))
        .route("/v1/accounts/:account/hosts", get(account_hosts))
        .route("/v1/tickets", post(create_ticket))
        .route("/v1/relay/:ticket_id", get(upgrade_relay))
        .layer(middleware::from_fn(cors_middleware))
        .with_state(state)
}

/// Permissive CORS. Every endpoint carries explicit bearer/signed credentials
/// (no ambient cookies), so CSRF does not apply; the web client must reach the
/// rendezvous directly from its (arbitrary-origin) host-served page.
/// docs/plans/2026-08-16-browser-rendezvous-signaling-design.md.
async fn cors_middleware(request: axum::extract::Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let has_auth = request.headers().contains_key(header::AUTHORIZATION);
    if request.method() == axum::http::Method::OPTIONS {
        tracing::debug!(%method, %path, has_auth, "preflight");
        return cors_headers(StatusCode::NO_CONTENT.into_response());
    }
    let response = next.run(request).await;
    COUNTERS
        .requests_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    tracing::debug!(%method, %path, has_auth, status = %response.status(), "request");
    cors_headers(response)
}

fn cors_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        header::HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        header::HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        header::HeaderValue::from_static("Authorization, Content-Type"),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        header::HeaderValue::from_static("600"),
    );
    response
}

#[derive(Clone)]
struct AppState {
    config: Arc<RelayConfig>,
    memory: Arc<Mutex<RelayMemoryState>>,
    state_file: Option<Arc<PathBuf>>,
}

#[derive(Default)]
struct RelayMemoryState {
    tickets: HashMap<String, Ticket>,
    used_request_nonces: HashMap<[u8; 32], u64>,
    host_mailboxes: HashMap<String, HostMailbox>,
    /// 账号 → (mailbox_id → 登记项)。纯内存: Host 60s 续约会自动重建。
    account_hosts: HashMap<String, HashMap<String, AccountHostEntry>>,
}

/// 账号名规范: 1-64 字符, [A-Za-z0-9_-]。测试阶段默认公共账号 "default"。
/// 账号只做设备发现映射, 不承载任何连接凭据(端到端信任仍由配对 secret
/// + Host Ed25519 签名承担, 服务端无法冒充 Host)。
fn normalize_account(raw: Option<&str>) -> Result<String, RelayError> {
    let name = raw.unwrap_or("default");
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if valid {
        Ok(name.to_owned())
    } else {
        Err(RelayError::InvalidAccount)
    }
}

#[derive(Clone)]
struct AccountHostEntry {
    host_fingerprint: String,
    registered_at_unix: u64,
    last_seen_unix: u64,
}

impl AppState {
    fn new(config: RelayConfig) -> Self {
        let state_file = config.state_file.clone().map(Arc::new);
        Self {
            config: Arc::new(config),
            memory: Arc::new(Mutex::new(RelayMemoryState::default())),
            state_file,
        }
    }

    async fn load(config: RelayConfig) -> Result<Self> {
        let state = Self::new(config);
        let Some(path) = state.state_file.as_deref() else {
            return Ok(state);
        };
        let bytes = match tokio::fs::read(path).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(state),
            Err(error) => return Err(error).context("read persisted Relay state"),
        };
        if bytes.len() as u64 > MAX_PERSISTED_STATE_BYTES {
            anyhow::bail!("persisted Relay state exceeds size limit");
        }
        let persisted: PersistedRelayState =
            serde_json::from_slice(&bytes).context("decode persisted Relay state")?;
        if persisted.version != PERSISTED_STATE_VERSION {
            anyhow::bail!("unsupported persisted Relay state version");
        }
        if persisted.host_mailboxes.len() > MAX_PERSISTED_MAILBOXES
            || persisted.tickets.len() > MAX_PERSISTED_TICKETS
            || persisted.used_request_nonces.len() > MAX_PERSISTED_NONCES
        {
            anyhow::bail!("persisted Relay state exceeds entry limits");
        }
        let now = unix_ms_now();
        let mut used_request_nonces = HashMap::new();
        for entry in persisted.used_request_nonces {
            let nonce = decode_hex::<32>(&entry.nonce)
                .context("persisted Relay state contains an invalid nonce")?;
            if entry.expires_at_unix_ms > now {
                used_request_nonces.insert(nonce, entry.expires_at_unix_ms);
            }
        }
        let mut host_mailboxes = HashMap::new();
        for (mailbox_id, mut mailbox) in persisted.host_mailboxes {
            if decode_hex::<32>(&mailbox_id).is_none()
                || mailbox.host_public_key.len() != 32
                || !is_fingerprint(&mailbox.host_fingerprint)
                || mailbox.sessions.len() > MAX_PENDING_SESSIONS_PER_HOST
            {
                anyhow::bail!("persisted Relay state contains an invalid mailbox");
            }
            mailbox.sessions.retain(|_, session| {
                session.request.expires_at_unix_ms > now
                    && session
                        .ready
                        .as_ref()
                        .is_none_or(|ready| ready.ticket.expires_at_unix_ms > now)
            });
            if mailbox.expires_at_unix_ms > now {
                host_mailboxes.insert(mailbox_id, mailbox);
            }
        }
        let mut memory = RelayMemoryState {
            used_request_nonces,
            host_mailboxes,
            ..RelayMemoryState::default()
        };
        for (ticket_id, ticket) in persisted.tickets {
            if ticket.expires_at_unix_ms <= now {
                continue;
            }
            if decode_hex::<16>(&ticket_id).is_none()
                || ticket.host_public_key.len() != 32
                || ticket.client_public_key.len() < 64
                || ticket.client_public_key.len() > 256
            {
                anyhow::bail!("persisted Relay state contains an invalid ticket");
            }
            let (arrival_tx, arrival_rx) = mpsc::channel(2);
            let ttl = Duration::from_millis(ticket.expires_at_unix_ms - now);
            memory.tickets.insert(
                ticket_id.clone(),
                Ticket {
                    host_public_key: ticket.host_public_key,
                    client_public_key: ticket.client_public_key,
                    expires_at_unix_ms: ticket.expires_at_unix_ms,
                    host_claimed: false,
                    client_claimed: false,
                    arrival_tx,
                },
            );
            tokio::spawn(run_ticket_broker(ticket_id, arrival_rx, ttl));
        }
        tracing::info!(
            mailboxes = memory.host_mailboxes.len(),
            tickets = memory.tickets.len(),
            nonces = memory.used_request_nonces.len(),
            "restored pending Relay state"
        );
        *state.memory.lock().await = memory;
        Ok(state)
    }

    async fn persist_locked(&self, memory: &RelayMemoryState) -> Result<(), RelayError> {
        let Some(path) = self.state_file.as_deref() else {
            return Ok(());
        };
        let now = unix_ms_now();
        let persisted = PersistedRelayState {
            version: PERSISTED_STATE_VERSION,
            tickets: memory
                .tickets
                .iter()
                .filter(|(_, ticket)| {
                    ticket.expires_at_unix_ms > now
                        && !(ticket.host_claimed && ticket.client_claimed)
                })
                .map(|(ticket_id, ticket)| {
                    (
                        ticket_id.clone(),
                        PersistedTicket {
                            host_public_key: ticket.host_public_key.clone(),
                            client_public_key: ticket.client_public_key.clone(),
                            expires_at_unix_ms: ticket.expires_at_unix_ms,
                        },
                    )
                })
                .collect(),
            used_request_nonces: memory
                .used_request_nonces
                .iter()
                .filter(|(_, expires_at)| **expires_at > now)
                .map(|(nonce, expires_at)| PersistedNonce {
                    nonce: hex(nonce),
                    expires_at_unix_ms: *expires_at,
                })
                .collect(),
            host_mailboxes: memory
                .host_mailboxes
                .iter()
                .filter(|(_, mailbox)| mailbox.expires_at_unix_ms > now)
                .map(|(mailbox_id, mailbox)| (mailbox_id.clone(), mailbox.clone()))
                .collect(),
        };
        let bytes = serde_json::to_vec(&persisted).map_err(|_| RelayError::Internal)?;
        if bytes.len() as u64 > MAX_PERSISTED_STATE_BYTES {
            return Err(RelayError::CapacityExceeded);
        }
        let parent = path.parent().ok_or(RelayError::Internal)?;
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|_| RelayError::Internal)?;
        let suffix = random_hex(8).map_err(|_| RelayError::Internal)?;
        let temporary = path.with_extension(format!("tmp-{suffix}"));
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let result = async {
            let mut file = options.open(&temporary).await?;
            file.write_all(&bytes).await?;
            file.sync_all().await?;
            drop(file);
            tokio::fs::rename(&temporary, path).await
        }
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(RelayError::Internal);
        }
        Ok(())
    }

    async fn claim(
        &self,
        ticket_id: &str,
        role: EndpointRole,
        proof: &str,
    ) -> Result<mpsc::Sender<PeerArrival>, RelayError> {
        let now = unix_ms_now();
        let mut memory = self.memory.lock().await;
        memory
            .tickets
            .retain(|_, ticket| ticket.expires_at_unix_ms > now);
        let (sender, both_claimed) = {
            let ticket = memory
                .tickets
                .get_mut(ticket_id)
                .ok_or(RelayError::NotFound)?;
            let public_key = match role {
                EndpointRole::Host => &ticket.host_public_key,
                EndpointRole::Client => &ticket.client_public_key,
            };
            let signature = decode_hex_vec(proof, 64, 80).ok_or(RelayError::Unauthorized)?;
            if !verify_endpoint_signature(
                role,
                public_key,
                &endpoint_claim_message(ticket_id, role),
                &signature,
            ) {
                return Err(RelayError::Unauthorized);
            }
            let claimed = match role {
                EndpointRole::Host => &mut ticket.host_claimed,
                EndpointRole::Client => &mut ticket.client_claimed,
            };
            if *claimed {
                return Err(RelayError::AlreadyClaimed);
            }
            *claimed = true;
            (
                ticket.arrival_tx.clone(),
                ticket.host_claimed && ticket.client_claimed,
            )
        };
        if let Err(error) = self.persist_locked(&memory).await {
            if let Some(ticket) = memory.tickets.get_mut(ticket_id) {
                match role {
                    EndpointRole::Host => ticket.host_claimed = false,
                    EndpointRole::Client => ticket.client_claimed = false,
                }
            }
            return Err(error);
        }
        if both_claimed {
            memory.tickets.remove(ticket_id);
        }
        Ok(sender)
    }

    #[cfg(test)]
    async fn use_request_nonce(
        &self,
        nonce: [u8; 32],
        valid_for: Duration,
    ) -> Result<(), RelayError> {
        let mut memory = self.memory.lock().await;
        Self::use_request_nonce_locked(&mut memory, nonce, valid_for)?;
        if let Err(error) = self.persist_locked(&memory).await {
            memory.used_request_nonces.remove(&nonce);
            return Err(error);
        }
        Ok(())
    }

    fn use_request_nonce_locked(
        memory: &mut RelayMemoryState,
        nonce: [u8; 32],
        valid_for: Duration,
    ) -> Result<(), RelayError> {
        let now = unix_ms_now();
        memory
            .used_request_nonces
            .retain(|_, expires_at| *expires_at > now);
        if memory.used_request_nonces.contains_key(&nonce) {
            return Err(RelayError::AlreadyClaimed);
        }
        memory
            .used_request_nonces
            .insert(nonce, unix_ms_after(valid_for));
        Ok(())
    }

    async fn register_host(
        &self,
        mailbox_id: &str,
        token: &str,
        request: HostRegistrationRequest,
    ) -> Result<(), RelayError> {
        if !self.config.enabled {
            return Err(RelayError::Disabled);
        }
        authorize_mailbox(mailbox_id, token)?;
        let validated = validate_host_registration(mailbox_id, &request)?;
        let account = normalize_account(request.account.as_deref())?;
        let account_fingerprint = request.host_fingerprint.clone();
        let now = unix_ms_now();
        let mut memory = self.memory.lock().await;
        memory
            .host_mailboxes
            .retain(|_, mailbox| mailbox.expires_at_unix_ms > now);
        let previous = memory.host_mailboxes.get(mailbox_id).cloned();
        if let Some(existing) = memory.host_mailboxes.get_mut(mailbox_id) {
            if !constant_time_eq(&existing.token_digest, &token_digest(token))
                || existing.host_public_key != validated.host_public_key
            {
                return Err(RelayError::Unauthorized);
            }
            existing.expires_at_unix_ms = unix_ms_after(validated.valid_for);
        } else {
            memory.host_mailboxes.insert(
                mailbox_id.to_owned(),
                HostMailbox {
                    token_digest: token_digest(token),
                    host_public_key: validated.host_public_key,
                    host_fingerprint: request.host_fingerprint,
                    expires_at_unix_ms: unix_ms_after(validated.valid_for),
                    sessions: HashMap::new(),
                },
            );
        }
        // 账号登记簿 upsert(注册/续约都会走到这里 → 服务端重启后 ≤60s 自愈)
        let entry = memory
            .account_hosts
            .entry(account)
            .or_default()
            .entry(mailbox_id.to_owned())
            .or_insert_with(|| AccountHostEntry {
                host_fingerprint: account_fingerprint.clone(),
                registered_at_unix: now / 1000,
                last_seen_unix: now / 1000,
            });
        entry.last_seen_unix = now / 1000;
        if let Err(error) = self.persist_locked(&memory).await {
            match previous {
                Some(mailbox) => {
                    memory.host_mailboxes.insert(mailbox_id.to_owned(), mailbox);
                }
                None => {
                    memory.host_mailboxes.remove(mailbox_id);
                }
            }
            return Err(error);
        }
        Ok(())
    }

    /// 账号设备发现: 返回该账号下所有在线租约内的 Host。
    /// 惰性清理: 滤掉 mailbox 租约已过期的登记项。
    async fn list_account_hosts(&self, account: &str) -> Result<Vec<AccountHost>, RelayError> {
        let account = normalize_account(Some(account))?;
        let now = unix_ms_now();
        let mut memory = self.memory.lock().await;
        memory
            .host_mailboxes
            .retain(|_, mailbox| mailbox.expires_at_unix_ms > now);
        let mut expired: Vec<String> = Vec::new();
        if let Some(registry) = memory.account_hosts.get(&account) {
            for mailbox_id in registry.keys() {
                if !memory.host_mailboxes.contains_key(mailbox_id) {
                    expired.push(mailbox_id.clone());
                }
            }
        }
        let mut hosts = Vec::new();
        if let Some(registry) = memory.account_hosts.get_mut(&account) {
            for mailbox_id in &expired {
                registry.remove(mailbox_id);
            }
            for (mailbox_id, entry) in registry.iter() {
                hosts.push(AccountHost {
                    mailbox_id: mailbox_id.clone(),
                    host_fingerprint: entry.host_fingerprint.clone(),
                    registered_at_unix: entry.registered_at_unix,
                    last_seen_unix: entry.last_seen_unix,
                });
            }
        }
        hosts.sort_by(|a, b| a.mailbox_id.cmp(&b.mailbox_id));
        Ok(hosts)
    }

    async fn submit_session_request(
        &self,
        mailbox_id: &str,
        token: &str,
        request: ClientSessionRequest,
    ) -> Result<String, RelayError> {
        if !self.config.enabled {
            return Err(RelayError::Disabled);
        }
        if let Err(e) = authorize_mailbox(mailbox_id, token) {
            tracing::debug!(%mailbox_id, "submit: authorize_mailbox failed");
            return Err(e);
        }
        let now = unix_ms_now();
        let mut memory = self.memory.lock().await;
        memory
            .host_mailboxes
            .retain(|_, mailbox| mailbox.expires_at_unix_ms > now);
        let previous_mailbox = memory
            .host_mailboxes
            .get(mailbox_id)
            .cloned()
            .ok_or(RelayError::NotFound)?;
        let mailbox = memory
            .host_mailboxes
            .get_mut(mailbox_id)
            .expect("mailbox was present when its rollback snapshot was captured");
        if let Err(e) = authorize_mailbox_token(mailbox, token) {
            tracing::debug!(%mailbox_id, "submit: authorize_mailbox_token failed");
            return Err(e);
        }
        validate_client_session_request(
            &request,
            &mailbox.host_public_key,
            &mailbox.host_fingerprint,
        )?;
        mailbox
            .sessions
            .retain(|_, session| session.request.expires_at_unix_ms > unix_ms_now());
        if mailbox
            .sessions
            .values()
            .any(|session| session.request.request_nonce == request.request_nonce)
        {
            return Err(RelayError::AlreadyClaimed);
        }
        // The Android client retries a rendezvous request when a Relay restart
        // interrupts its wait. Keep only the newest request for one paired
        // client so the Host cannot issue several stale tickets after recovery.
        mailbox
            .sessions
            .retain(|_, session| session.request.client_fingerprint != request.client_fingerprint);
        if mailbox.sessions.len() >= MAX_PENDING_SESSIONS_PER_HOST {
            return Err(RelayError::CapacityExceeded);
        }
        let request_id = random_hex(16).map_err(|_| RelayError::Internal)?;
        mailbox.sessions.insert(
            request_id.clone(),
            StoredSessionRequest {
                request,
                ready: None,
            },
        );
        if let Err(error) = self.persist_locked(&memory).await {
            memory
                .host_mailboxes
                .insert(mailbox_id.to_owned(), previous_mailbox);
            return Err(error);
        }
        COUNTERS
            .session_requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(request_id)
    }

    async fn next_session_request(
        &self,
        mailbox_id: &str,
        token: &str,
    ) -> Result<Option<PendingSessionResponse>, RelayError> {
        if !self.config.enabled {
            return Err(RelayError::Disabled);
        }
        authorize_mailbox(mailbox_id, token)?;
        let now = unix_ms_now();
        let mut memory = self.memory.lock().await;
        memory
            .host_mailboxes
            .retain(|_, mailbox| mailbox.expires_at_unix_ms > now);
        let mailbox = memory
            .host_mailboxes
            .get_mut(mailbox_id)
            .ok_or(RelayError::NotFound)?;
        authorize_mailbox_token(mailbox, token)?;
        mailbox
            .sessions
            .retain(|_, session| session.request.expires_at_unix_ms > unix_ms_now());
        let response = mailbox
            .sessions
            .iter()
            .find(|(_, session)| session.ready.is_none())
            .map(|(request_id, session)| PendingSessionResponse {
                request_id: request_id.clone(),
                protocol: session.request.protocol.clone(),
                logical_session_id: session.request.logical_session_id.clone(),
                host_public_key: hex(&mailbox.host_public_key),
                host_fingerprint: mailbox.host_fingerprint.clone(),
                client_public_key: session.request.client_public_key.clone(),
                client_fingerprint: session.request.client_fingerprint.clone(),
                request_nonce: session.request.request_nonce.clone(),
                expires_at_unix_ms: session.request.expires_at_unix_ms,
                client_signature: session.request.client_signature.clone(),
                client_ephemeral_public_key: session.request.client_ephemeral_public_key.clone(),
                client_challenge: session.request.client_challenge.clone(),
                client_handshake_signature: session.request.client_handshake_signature.clone(),
                p2p_offer_sdp: session.request.p2p_offer_sdp.clone(),
                p2p_offer_signature: session.request.p2p_offer_signature.clone(),
            });
        Ok(response)
    }

    async fn complete_session_request(
        &self,
        mailbox_id: &str,
        token: &str,
        request_id: &str,
        completion: HostSessionCompletion,
    ) -> Result<SessionReadyResponse, RelayError> {
        if !self.config.enabled {
            return Err(RelayError::Disabled);
        }
        authorize_mailbox(mailbox_id, token)?;
        if completion.protocol != SESSION_COMPLETION_PROTOCOL {
            return Err(RelayError::InvalidTicketRequest);
        }
        let now = unix_ms_now();
        let mut memory = self.memory.lock().await;
        memory
            .host_mailboxes
            .retain(|_, mailbox| mailbox.expires_at_unix_ms > now);
        let (host_public_key, host_fingerprint, request) = {
            let mailbox = memory
                .host_mailboxes
                .get(mailbox_id)
                .ok_or(RelayError::NotFound)?;
            authorize_mailbox_token(mailbox, token)?;
            let stored = mailbox
                .sessions
                .get(request_id)
                .ok_or(RelayError::NotFound)?;
            if let Some(ready) = &stored.ready {
                return Ok(ready.clone());
            }
            (
                mailbox.host_public_key.clone(),
                mailbox.host_fingerprint.clone(),
                stored.request.clone(),
            )
        };
        let handshake = validate_host_session_completion(&completion, &request, &host_public_key)?;
        let ticket_request = CreateTicketRequest {
            protocol: TICKET_REQUEST_PROTOCOL.into(),
            logical_session_id: request.logical_session_id,
            host_public_key: hex(&host_public_key),
            client_public_key: request.client_public_key,
            host_fingerprint,
            client_fingerprint: request.client_fingerprint,
            request_nonce: request.request_nonce,
            expires_at_unix_ms: request.expires_at_unix_ms,
            host_signature: completion.host_signature,
            client_signature: request.client_signature,
        };
        let validated = validate_ticket_request(&ticket_request)?;
        let (ticket, broker) = self.issue_ticket_locked(&mut memory, validated)?;
        let ready = SessionReadyResponse { ticket, handshake };
        let mailbox = memory
            .host_mailboxes
            .get_mut(mailbox_id)
            .ok_or(RelayError::NotFound)?;
        let stored = mailbox
            .sessions
            .get_mut(request_id)
            .ok_or(RelayError::NotFound)?;
        stored.ready = Some(ready.clone());
        if let Err(error) = self.persist_locked(&memory).await {
            if let Some(mailbox) = memory.host_mailboxes.get_mut(mailbox_id) {
                if let Some(stored) = mailbox.sessions.get_mut(request_id) {
                    stored.ready = None;
                }
            }
            memory.tickets.remove(&broker.ticket_id);
            memory.used_request_nonces.remove(&broker.request_nonce);
            return Err(error);
        }
        drop(memory);
        tokio::spawn(run_ticket_broker(
            broker.ticket_id,
            broker.arrival_rx,
            broker.ttl,
        ));
        Ok(ready)
    }

    async fn session_status(
        &self,
        mailbox_id: &str,
        token: &str,
        request_id: &str,
    ) -> Result<SessionStatusResponse, RelayError> {
        if !self.config.enabled {
            return Err(RelayError::Disabled);
        }
        authorize_mailbox(mailbox_id, token)?;
        let now = unix_ms_now();
        let mut memory = self.memory.lock().await;
        memory
            .host_mailboxes
            .retain(|_, mailbox| mailbox.expires_at_unix_ms > now);
        let mailbox = memory
            .host_mailboxes
            .get(mailbox_id)
            .ok_or(RelayError::NotFound)?;
        authorize_mailbox_token(mailbox, token)?;
        let stored = mailbox
            .sessions
            .get(request_id)
            .ok_or(RelayError::NotFound)?;
        if stored.request.expires_at_unix_ms <= unix_ms_now() {
            return Err(RelayError::Expired);
        }
        let response = SessionStatusResponse {
            status: if stored.ready.is_some() {
                SessionRequestStatus::Ready
            } else {
                SessionRequestStatus::Pending
            },
            ticket: stored.ready.as_ref().map(|ready| ready.ticket.clone()),
            handshake: stored.ready.as_ref().map(|ready| ready.handshake.clone()),
        };
        Ok(response)
    }

    async fn ice_configuration(
        &self,
        mailbox_id: &str,
        token: &str,
    ) -> Result<IceConfigurationResponse, RelayError> {
        if !self.config.enabled {
            return Err(RelayError::Disabled);
        }
        authorize_mailbox(mailbox_id, token)?;
        let now = unix_ms_now();
        let mut memory = self.memory.lock().await;
        memory
            .host_mailboxes
            .retain(|_, mailbox| mailbox.expires_at_unix_ms > now);
        let mailbox = memory
            .host_mailboxes
            .get(mailbox_id)
            .ok_or(RelayError::NotFound)?;
        authorize_mailbox_token(mailbox, token)?;
        drop(memory);

        let mut ice_servers = Vec::with_capacity(2);
        if !self.config.stun_urls.is_empty() {
            ice_servers.push(IceServerResponse {
                urls: self.config.stun_urls.clone(),
                username: String::new(),
                credential: String::new(),
            });
        }
        let expires_at_unix_ms = if let Some(turn) = &self.config.turn {
            let issued = turn
                .issue(mailbox_id, unix_seconds_now())
                .map_err(|_| RelayError::Internal)?;
            let expires_at_unix_ms = issued.expires_at_unix_ms;
            ice_servers.push(IceServerResponse {
                urls: issued.urls,
                username: issued.username,
                credential: issued.credential,
            });
            expires_at_unix_ms
        } else {
            unix_ms_after(DEFAULT_TURN_CREDENTIAL_TTL)
        };
        Ok(IceConfigurationResponse {
            ice_servers,
            expires_at_unix_ms,
        })
    }

    async fn issue_ticket(
        &self,
        validated: ValidatedTicketRequest,
    ) -> Result<CreateTicketResponse, RelayError> {
        let mut memory = self.memory.lock().await;
        let (ticket, broker) = self.issue_ticket_locked(&mut memory, validated)?;
        if let Err(error) = self.persist_locked(&memory).await {
            memory.tickets.remove(&broker.ticket_id);
            memory.used_request_nonces.remove(&broker.request_nonce);
            return Err(error);
        }
        drop(memory);
        tokio::spawn(run_ticket_broker(
            broker.ticket_id,
            broker.arrival_rx,
            broker.ttl,
        ));
        COUNTERS
            .session_completions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        COUNTERS
            .tickets_issued
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(ticket)
    }

    fn issue_ticket_locked(
        &self,
        memory: &mut RelayMemoryState,
        validated: ValidatedTicketRequest,
    ) -> Result<(CreateTicketResponse, PendingTicketBroker), RelayError> {
        let request_nonce = validated.request_nonce;
        Self::use_request_nonce_locked(memory, request_nonce, validated.valid_for)?;
        let ticket_id = random_hex(16).map_err(|_| RelayError::Internal)?;
        let (arrival_tx, arrival_rx) = mpsc::channel(2);
        let ttl = self.config.ticket_ttl.min(validated.valid_for);
        let expires_at_unix_ms = unix_ms_after(ttl);
        memory.tickets.insert(
            ticket_id.clone(),
            Ticket {
                host_public_key: validated.host_public_key,
                client_public_key: validated.client_public_key,
                expires_at_unix_ms,
                host_claimed: false,
                client_claimed: false,
                arrival_tx,
            },
        );
        Ok((
            CreateTicketResponse {
                ticket_id: ticket_id.clone(),
                relay_url: self.config.public_relay_url.clone(),
                expires_at_unix_ms,
            },
            PendingTicketBroker {
                ticket_id,
                arrival_rx,
                ttl,
                request_nonce,
            },
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HostMailbox {
    token_digest: [u8; 32],
    host_public_key: Vec<u8>,
    host_fingerprint: String,
    expires_at_unix_ms: u64,
    sessions: HashMap<String, StoredSessionRequest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredSessionRequest {
    request: ClientSessionRequest,
    ready: Option<SessionReadyResponse>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedRelayState {
    version: u8,
    tickets: HashMap<String, PersistedTicket>,
    used_request_nonces: Vec<PersistedNonce>,
    host_mailboxes: HashMap<String, HostMailbox>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedTicket {
    host_public_key: Vec<u8>,
    client_public_key: Vec<u8>,
    expires_at_unix_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedNonce {
    nonce: String,
    expires_at_unix_ms: u64,
}

#[derive(Serialize)]
struct HealthResponse {
    service: &'static str,
    protocol: &'static str,
    relay_enabled: bool,
    turn_enabled: bool,
    state_persistence_enabled: bool,
    ticket_ttl_seconds: u64,
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        service: "hypercast-rendezvous-relay",
        protocol: "1",
        relay_enabled: state.config.enabled,
        turn_enabled: state.config.turn.is_some(),
        state_persistence_enabled: state.state_file.is_some(),
        ticket_ttl_seconds: state.config.ticket_ttl.as_secs(),
    })
}

#[derive(Clone, Debug, Serialize)]
struct IceServerResponse {
    urls: Vec<String>,
    username: String,
    credential: String,
}

#[derive(Clone, Debug, Serialize)]
struct IceConfigurationResponse {
    ice_servers: Vec<IceServerResponse>,
    expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct HostRegistrationRequest {
    protocol: String,
    host_public_key: String,
    host_fingerprint: String,
    registration_nonce: String,
    expires_at_unix_ms: u64,
    signature: String,
    /// 账号命名空间(设备发现)。缺省 "default": 旧版 Host 不发该字段,
    /// 自动落入公共测试账号 —— 完全向后兼容。
    #[serde(default)]
    account: Option<String>,
}

/// GET /v1/accounts/:account/hosts 响应。只含公开信息(指纹),
/// 不含任何连接凭据。
#[derive(Clone, Debug, Serialize)]
struct AccountHost {
    mailbox_id: String,
    host_fingerprint: String,
    registered_at_unix: u64,
    last_seen_unix: u64,
}

#[derive(Clone, Debug, Serialize)]
struct AccountHostsResponse {
    account: String,
    hosts: Vec<AccountHost>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ClientSessionRequest {
    protocol: String,
    logical_session_id: String,
    host_fingerprint: String,
    client_public_key: String,
    client_fingerprint: String,
    request_nonce: String,
    expires_at_unix_ms: u64,
    client_signature: String,
    client_ephemeral_public_key: String,
    client_challenge: String,
    client_handshake_signature: String,
    p2p_offer_sdp: Option<String>,
    p2p_offer_signature: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct PendingSessionResponse {
    request_id: String,
    protocol: String,
    logical_session_id: String,
    host_public_key: String,
    host_fingerprint: String,
    client_public_key: String,
    client_fingerprint: String,
    request_nonce: String,
    expires_at_unix_ms: u64,
    client_signature: String,
    client_ephemeral_public_key: String,
    client_challenge: String,
    client_handshake_signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    p2p_offer_sdp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p2p_offer_signature: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct HostSessionCompletion {
    protocol: String,
    host_signature: String,
    host_ephemeral_public_key: String,
    host_challenge: String,
    host_handshake_signature: String,
    p2p_answer_sdp: Option<String>,
    p2p_answer_signature: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HostHandshakeResponse {
    host_ephemeral_public_key: String,
    host_challenge: String,
    host_handshake_signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    p2p_answer_sdp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p2p_answer_signature: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SessionReadyResponse {
    ticket: CreateTicketResponse,
    handshake: HostHandshakeResponse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SessionRequestStatus {
    Pending,
    Ready,
}

#[derive(Clone, Debug, Serialize)]
struct SessionStatusResponse {
    status: SessionRequestStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    ticket: Option<CreateTicketResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    handshake: Option<HostHandshakeResponse>,
}

#[derive(Serialize)]
struct SessionRequestCreated {
    request_id: String,
}

async fn register_host(
    State(state): State<AppState>,
    Path(mailbox_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<HostRegistrationRequest>,
) -> Result<StatusCode, RelayError> {
    let token = bearer_token(&headers)
        .ok_or(RelayError::Unauthorized)?
        .to_owned();
    state.register_host(&mailbox_id, &token, request).await?;
    telemetry::MAILBOX_REGISTRATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(StatusCode::NO_CONTENT)
}

/// 账号设备发现(测试阶段无鉴权, 正式版应加账号 token):
/// 只暴露公开指纹, 连接凭据仍需经配对(扫码)获得。
async fn account_hosts(
    State(state): State<AppState>,
    Path(account): Path<String>,
) -> Result<Json<AccountHostsResponse>, RelayError> {
    let hosts = state.list_account_hosts(&account).await?;
    Ok(Json(AccountHostsResponse { account, hosts }))
}

async fn submit_session_request(
    State(state): State<AppState>,
    Path(mailbox_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ClientSessionRequest>,
) -> Result<Json<SessionRequestCreated>, RelayError> {
    let token = match bearer_token(&headers) {
        Some(token) => token.to_owned(),
        None => {
            tracing::debug!(
                has_auth_header = headers.contains_key(header::AUTHORIZATION),
                origin = ?headers.get(header::ORIGIN),
                "submit route: bearer_token parse failed"
            );
            return Err(RelayError::Unauthorized);
        }
    };
    let request_id = state
        .submit_session_request(&mailbox_id, &token, request)
        .await?;
    telemetry::SESSION_REQUESTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(Json(SessionRequestCreated { request_id }))
}

async fn next_session_request(
    State(state): State<AppState>,
    Path(mailbox_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, RelayError> {
    let token = bearer_token(&headers)
        .ok_or(RelayError::Unauthorized)?
        .to_owned();
    Ok(
        match state.next_session_request(&mailbox_id, &token).await? {
            Some(request) => Json(request).into_response(),
            None => StatusCode::NO_CONTENT.into_response(),
        },
    )
}

async fn complete_session_request(
    State(state): State<AppState>,
    Path((mailbox_id, request_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(completion): Json<HostSessionCompletion>,
) -> Result<Json<SessionReadyResponse>, RelayError> {
    let token = bearer_token(&headers)
        .ok_or(RelayError::Unauthorized)?
        .to_owned();
    state
        .complete_session_request(&mailbox_id, &token, &request_id, completion)
        .await
        .map(Json)
}

async fn session_status(
    State(state): State<AppState>,
    Path((mailbox_id, request_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<SessionStatusResponse>, RelayError> {
    let token = bearer_token(&headers)
        .ok_or(RelayError::Unauthorized)?
        .to_owned();
    state
        .session_status(&mailbox_id, &token, &request_id)
        .await
        .map(Json)
}

async fn ice_configuration(
    State(state): State<AppState>,
    Path(mailbox_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<IceConfigurationResponse>, RelayError> {
    let token = bearer_token(&headers)
        .ok_or(RelayError::Unauthorized)?
        .to_owned();
    state.ice_configuration(&mailbox_id, &token).await.map(Json)
}

#[derive(Deserialize)]
struct CreateTicketRequest {
    protocol: String,
    logical_session_id: String,
    host_public_key: String,
    client_public_key: String,
    host_fingerprint: String,
    client_fingerprint: String,
    request_nonce: String,
    expires_at_unix_ms: u64,
    host_signature: String,
    client_signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CreateTicketResponse {
    ticket_id: String,
    relay_url: String,
    expires_at_unix_ms: u64,
}

async fn create_ticket(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateTicketRequest>,
) -> Result<Json<CreateTicketResponse>, RelayError> {
    if !state.config.enabled {
        return Err(RelayError::Disabled);
    }
    authorize_admin(&headers, state.config.admin_token.as_deref())
        .map_err(|_| RelayError::Unauthorized)?;
    let validated = validate_ticket_request(&request)?;
    state.issue_ticket(validated).await.map(Json)
}

async fn upgrade_relay(
    State(state): State<AppState>,
    Path(ticket_id): Path<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, RelayError> {
    if !state.config.enabled {
        return Err(RelayError::Disabled);
    }
    let role = endpoint_role(&headers)?;
    let proof = bearer_token(&headers).ok_or(RelayError::Unauthorized)?;
    let sender = state.claim(&ticket_id, role, proof).await?;
    let trace_id = relay_trace_id(&ticket_id);
    Ok(ws.on_upgrade(move |socket| async move {
        if sender.send(PeerArrival { role, socket }).await.is_err() {
            tracing::warn!(relay_trace_id = %trace_id, "relay peer arrived after ticket expired");
        }
    }))
}

struct Ticket {
    host_public_key: Vec<u8>,
    client_public_key: Vec<u8>,
    expires_at_unix_ms: u64,
    host_claimed: bool,
    client_claimed: bool,
    arrival_tx: mpsc::Sender<PeerArrival>,
}

struct PendingTicketBroker {
    ticket_id: String,
    arrival_rx: mpsc::Receiver<PeerArrival>,
    ttl: Duration,
    request_nonce: [u8; 32],
}

struct PeerArrival {
    role: EndpointRole,
    socket: WebSocket,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EndpointRole {
    Host,
    Client,
}

async fn run_ticket_broker(
    ticket_id: String,
    mut arrivals: mpsc::Receiver<PeerArrival>,
    ttl: Duration,
) {
    let trace_id = relay_trace_id(&ticket_id);
    // The ticket TTL is an admission deadline, not a session duration. Once both signed
    // endpoints have claimed the ticket, keep forwarding until either peer disconnects.
    let arrivals = tokio::time::timeout(ttl, async {
        let first = arrivals.recv().await.ok_or(RelayError::PeerClosed)?;
        let second = arrivals.recv().await.ok_or(RelayError::PeerClosed)?;
        if first.role == second.role {
            return Err(RelayError::AlreadyClaimed);
        }
        let (host, client) = if first.role == EndpointRole::Host {
            (first.socket, second.socket)
        } else {
            (second.socket, first.socket)
        };
        Ok::<_, RelayError>((host, client))
    })
    .await;

    let (host, client) = match arrivals {
        Ok(Ok(peers)) => peers,
        Ok(Err(error)) => {
            tracing::warn!(relay_trace_id = %trace_id, error = %error, "relay ticket closed");
            return;
        }
        Err(_) => {
            tracing::debug!(relay_trace_id = %trace_id, "relay ticket expired before both peers joined");
            return;
        }
    };
    match relay_pair(host, client, &trace_id).await {
        Ok(()) => tracing::info!(relay_trace_id = %trace_id, "opaque relay session closed"),
        Err(error) => {
            tracing::warn!(relay_trace_id = %trace_id, error = %error, "relay session closed")
        }
    }
}

async fn relay_pair(host: WebSocket, client: WebSocket, trace_id: &str) -> Result<(), RelayError> {
    let (host_sink, host_stream) = host.split();
    let (client_sink, client_stream) = client.split();
    tokio::try_join!(
        forward_opaque(host_stream, client_sink, trace_id, "host_to_client"),
        forward_opaque(client_stream, host_sink, trace_id, "client_to_host")
    )?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RelayForwardStats {
    frames: u64,
    bytes: u64,
    max_forward_us: u64,
}

impl RelayForwardStats {
    fn record(&mut self, bytes: usize, elapsed: Duration) {
        self.frames = self.frames.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes as u64);
        self.max_forward_us = self
            .max_forward_us
            .max(elapsed.as_micros().try_into().unwrap_or(u64::MAX));
    }
}

struct RelayForwardTelemetry {
    trace_id: String,
    direction: &'static str,
    started: Instant,
    stats: RelayForwardStats,
}

impl RelayForwardTelemetry {
    fn new(trace_id: &str, direction: &'static str) -> Self {
        Self {
            trace_id: trace_id.to_owned(),
            direction,
            started: Instant::now(),
            stats: RelayForwardStats::default(),
        }
    }

    fn record(&mut self, bytes: usize, elapsed: Duration) {
        self.stats.record(bytes, elapsed);
    }
}

impl Drop for RelayForwardTelemetry {
    fn drop(&mut self) {
        tracing::info!(
            relay_trace_id = self.trace_id,
            direction = self.direction,
            duration_ms = self.started.elapsed().as_millis() as u64,
            frames = self.stats.frames,
            bytes = self.stats.bytes,
            max_forward_us = self.stats.max_forward_us,
            "opaque relay forwarding summary"
        );
    }
}

async fn forward_opaque<S, R>(
    mut source: R,
    mut sink: S,
    trace_id: &str,
    direction: &'static str,
) -> Result<(), RelayError>
where
    S: futures::Sink<Message, Error = axum::Error> + Unpin,
    R: futures::Stream<Item = Result<Message, axum::Error>> + Unpin,
{
    // Drop-based emission guarantees a bounded summary even when try_join! cancels this direction
    // after the peer-facing half closes first.
    let mut telemetry = RelayForwardTelemetry::new(trace_id, direction);
    while let Some(message) = source.next().await {
        match message.map_err(|_| RelayError::PeerClosed)? {
            Message::Binary(bytes) => {
                if !is_opaque_envelope(&bytes) {
                    return Err(RelayError::InvalidOpaqueEnvelope);
                }
                let frame_bytes = bytes.len();
                let started = Instant::now();
                sink.send(Message::Binary(bytes))
                    .await
                    .map_err(|_| RelayError::PeerClosed)?;
                let elapsed = started.elapsed();
                telemetry.record(frame_bytes, elapsed);
                if elapsed >= SLOW_RELAY_FORWARD {
                    tracing::warn!(
                        relay_trace_id = trace_id,
                        direction,
                        frame_bytes,
                        forward_ms = elapsed.as_millis() as u64,
                        "slow opaque relay forward"
                    );
                }
            }
            Message::Close(_) => return Ok(()),
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Text(_) => return Err(RelayError::InvalidOpaqueEnvelope),
        }
    }
    Ok(())
}

fn relay_trace_id(ticket_id: &str) -> String {
    let hash = digest::digest(&digest::SHA256, ticket_id.as_bytes());
    hex(&hash.as_ref()[..6])
}

fn is_opaque_envelope(bytes: &[u8]) -> bool {
    bytes.len() >= 17 + 16 + 44
        && bytes.len() <= MAX_SEALED_ENVELOPE_BYTES
        && bytes.starts_with(HCE1_MAGIC)
        && bytes[4] == 1
}

struct ValidatedTicketRequest {
    host_public_key: Vec<u8>,
    client_public_key: Vec<u8>,
    request_nonce: [u8; 32],
    valid_for: Duration,
}

struct ValidatedHostRegistration {
    host_public_key: Vec<u8>,
    valid_for: Duration,
}

fn validate_host_registration(
    mailbox_id: &str,
    request: &HostRegistrationRequest,
) -> Result<ValidatedHostRegistration, RelayError> {
    if request.protocol != HOST_REGISTRATION_PROTOCOL || !is_fingerprint(&request.host_fingerprint)
    {
        return Err(RelayError::InvalidRegistration);
    }
    decode_hex::<32>(mailbox_id).ok_or(RelayError::InvalidRegistration)?;
    let host_public_key =
        decode_hex_vec(&request.host_public_key, 32, 32).ok_or(RelayError::InvalidRegistration)?;
    if fingerprint(&host_public_key) != request.host_fingerprint {
        return Err(RelayError::InvalidRegistration);
    }
    let registration_nonce =
        decode_hex::<32>(&request.registration_nonce).ok_or(RelayError::InvalidRegistration)?;
    let signature =
        decode_hex_vec(&request.signature, 64, 64).ok_or(RelayError::InvalidRegistration)?;
    let now = unix_ms_now();
    let latest = now.saturating_add(MAX_HOST_LEASE.as_millis() as u64);
    if request.expires_at_unix_ms <= now || request.expires_at_unix_ms > latest {
        return Err(RelayError::InvalidRegistration);
    }
    let transcript = host_registration_transcript(
        mailbox_id,
        request.expires_at_unix_ms,
        &registration_nonce,
        &host_public_key,
    );
    if UnparsedPublicKey::new(&ED25519, &host_public_key)
        .verify(&transcript, &signature)
        .is_err()
    {
        return Err(RelayError::Unauthorized);
    }
    COUNTERS
        .registrations
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(ValidatedHostRegistration {
        host_public_key,
        valid_for: Duration::from_millis(request.expires_at_unix_ms - now),
    })
}

fn validate_client_session_request(
    request: &ClientSessionRequest,
    host_public_key: &[u8],
    host_fingerprint: &str,
) -> Result<(), RelayError> {
    if request.protocol != SESSION_REQUEST_PROTOCOL {
        tracing::debug!("session request rejected: protocol");
        return Err(RelayError::InvalidTicketRequest);
    }
    if request.host_fingerprint != host_fingerprint {
        tracing::debug!(
            got = %request.host_fingerprint,
            expected = %host_fingerprint,
            "session request rejected: host fingerprint"
        );
        return Err(RelayError::InvalidTicketRequest);
    }
    if !is_fingerprint(&request.client_fingerprint) {
        tracing::debug!("session request rejected: client fingerprint format");
        return Err(RelayError::InvalidTicketRequest);
    }
    if request.client_fingerprint == host_fingerprint {
        tracing::debug!("session request rejected: fingerprints equal");
        return Err(RelayError::InvalidTicketRequest);
    }
    let logical_session_id = match decode_hex::<16>(&request.logical_session_id) {
        Some(v) => v,
        None => {
            tracing::debug!("session request rejected: logical session id");
            return Err(RelayError::InvalidTicketRequest);
        }
    };
    let client_public_key = match decode_hex_vec(&request.client_public_key, 64, 256) {
        Some(v) => v,
        None => {
            tracing::debug!("session request rejected: client public key size");
            return Err(RelayError::InvalidTicketRequest);
        }
    };
    if fingerprint(&client_public_key) != request.client_fingerprint {
        tracing::debug!("session request rejected: client fingerprint mismatch");
        return Err(RelayError::InvalidTicketRequest);
    }
    let request_nonce = match decode_hex::<32>(&request.request_nonce) {
        Some(v) => v,
        None => {
            tracing::debug!("session request rejected: nonce");
            return Err(RelayError::InvalidTicketRequest);
        }
    };
    let client_signature = match decode_hex_vec(&request.client_signature, 64, 80) {
        Some(v) => v,
        None => {
            tracing::debug!("session request rejected: client signature size");
            return Err(RelayError::InvalidTicketRequest);
        }
    };
    let client_ephemeral_public_key =
        match decode_hex_vec(&request.client_ephemeral_public_key, 64, 256) {
            Some(v) => v,
            None => {
                tracing::debug!("session request rejected: ephemeral key size");
                return Err(RelayError::InvalidTicketRequest);
            }
        };
    let client_challenge = match decode_hex::<32>(&request.client_challenge) {
        Some(v) => v,
        None => {
            tracing::debug!("session request rejected: challenge");
            return Err(RelayError::InvalidTicketRequest);
        }
    };
    let client_handshake_signature =
        match decode_hex_vec(&request.client_handshake_signature, 64, 80) {
            Some(v) => v,
            None => {
                tracing::debug!("session request rejected: handshake signature size");
                return Err(RelayError::InvalidTicketRequest);
            }
        };
    let now = unix_ms_now();
    let latest = now.saturating_add(MAX_TICKET_TTL.as_millis() as u64);
    if request.expires_at_unix_ms <= now || request.expires_at_unix_ms > latest {
        tracing::debug!(
            expires = request.expires_at_unix_ms,
            now,
            "session request rejected: expiry window"
        );
        return Err(RelayError::InvalidTicketRequest);
    }
    let transcript = ticket_request_transcript(
        &logical_session_id,
        request.expires_at_unix_ms,
        &request_nonce,
        host_public_key,
        &client_public_key,
    );
    if !verify_client_signature(&client_public_key, &transcript, &client_signature) {
        return Err(RelayError::Unauthorized);
    }
    let handshake_offer = client_handshake_offer_transcript(
        &logical_session_id,
        host_public_key,
        &client_public_key,
        &client_ephemeral_public_key,
        &client_challenge,
        &request_nonce,
    );
    if !verify_client_signature(
        &client_public_key,
        &handshake_offer,
        &client_handshake_signature,
    ) {
        return Err(RelayError::Unauthorized);
    }
    validate_client_p2p_offer(
        request,
        &logical_session_id,
        host_public_key,
        &client_public_key,
        &request_nonce,
    )?;
    Ok(())
}

fn validate_client_p2p_offer(
    request: &ClientSessionRequest,
    logical_session_id: &[u8; 16],
    host_public_key: &[u8],
    client_public_key: &[u8],
    request_nonce: &[u8; 32],
) -> Result<(), RelayError> {
    let (offer_sdp, signature) = match (
        request.p2p_offer_sdp.as_deref(),
        request.p2p_offer_signature.as_deref(),
    ) {
        (None, None) => return Ok(()),
        (Some(offer_sdp), Some(signature)) => (offer_sdp, signature),
        _ => return Err(RelayError::InvalidTicketRequest),
    };
    validate_p2p_sdp(offer_sdp)?;
    let signature = decode_hex_vec(signature, 64, 80).ok_or(RelayError::InvalidTicketRequest)?;
    let transcript = p2p_offer_transcript(
        logical_session_id,
        offer_sdp.as_bytes(),
        host_public_key,
        client_public_key,
        request_nonce,
    );
    if !verify_client_signature(client_public_key, &transcript, &signature) {
        return Err(RelayError::Unauthorized);
    }
    Ok(())
}

fn validate_host_session_completion(
    completion: &HostSessionCompletion,
    request: &ClientSessionRequest,
    host_public_key: &[u8],
) -> Result<HostHandshakeResponse, RelayError> {
    let logical_session_id =
        decode_hex::<16>(&request.logical_session_id).ok_or(RelayError::InvalidTicketRequest)?;
    let client_public_key = decode_hex_vec(&request.client_public_key, 64, 256)
        .ok_or(RelayError::InvalidTicketRequest)?;
    let client_ephemeral_public_key = decode_hex_vec(&request.client_ephemeral_public_key, 64, 256)
        .ok_or(RelayError::InvalidTicketRequest)?;
    let client_challenge =
        decode_hex::<32>(&request.client_challenge).ok_or(RelayError::InvalidTicketRequest)?;
    let host_ephemeral_public_key = decode_hex_vec(&completion.host_ephemeral_public_key, 64, 256)
        .ok_or(RelayError::InvalidTicketRequest)?;
    let host_challenge =
        decode_hex::<32>(&completion.host_challenge).ok_or(RelayError::InvalidTicketRequest)?;
    let signature = decode_hex_vec(&completion.host_handshake_signature, 64, 64)
        .ok_or(RelayError::InvalidTicketRequest)?;
    let transcript = session_handshake_transcript(
        &logical_session_id,
        host_public_key,
        &client_public_key,
        &host_ephemeral_public_key,
        &client_ephemeral_public_key,
        &host_challenge,
        &client_challenge,
    );
    if UnparsedPublicKey::new(&ED25519, host_public_key)
        .verify(&transcript, &signature)
        .is_err()
    {
        return Err(RelayError::Unauthorized);
    }
    let (p2p_answer_sdp, p2p_answer_signature) = validate_host_p2p_answer(
        completion,
        request,
        &logical_session_id,
        host_public_key,
        &client_public_key,
    )?;
    Ok(HostHandshakeResponse {
        host_ephemeral_public_key: completion.host_ephemeral_public_key.clone(),
        host_challenge: completion.host_challenge.clone(),
        host_handshake_signature: completion.host_handshake_signature.clone(),
        p2p_answer_sdp,
        p2p_answer_signature,
    })
}

fn validate_host_p2p_answer(
    completion: &HostSessionCompletion,
    request: &ClientSessionRequest,
    logical_session_id: &[u8; 16],
    host_public_key: &[u8],
    client_public_key: &[u8],
) -> Result<(Option<String>, Option<String>), RelayError> {
    let Some(offer_sdp) = request.p2p_offer_sdp.as_deref() else {
        if completion.p2p_answer_sdp.is_some() || completion.p2p_answer_signature.is_some() {
            return Err(RelayError::InvalidTicketRequest);
        }
        return Ok((None, None));
    };
    let answer_sdp = completion
        .p2p_answer_sdp
        .as_deref()
        .ok_or(RelayError::InvalidTicketRequest)?;
    let signature_hex = completion
        .p2p_answer_signature
        .as_deref()
        .ok_or(RelayError::InvalidTicketRequest)?;
    validate_p2p_sdp(answer_sdp)?;
    let signature =
        decode_hex_vec(signature_hex, 64, 64).ok_or(RelayError::InvalidTicketRequest)?;
    let transcript = p2p_answer_transcript(
        logical_session_id,
        offer_sdp.as_bytes(),
        answer_sdp.as_bytes(),
        host_public_key,
        client_public_key,
    );
    if UnparsedPublicKey::new(&ED25519, host_public_key)
        .verify(&transcript, &signature)
        .is_err()
    {
        return Err(RelayError::Unauthorized);
    }
    Ok((Some(answer_sdp.to_owned()), Some(signature_hex.to_owned())))
}

fn validate_p2p_sdp(sdp: &str) -> Result<(), RelayError> {
    if sdp.is_empty()
        || sdp.len() > MAX_P2P_SDP_BYTES
        || !(sdp.starts_with("v=0\r\n") || sdp.starts_with("v=0\n"))
        || sdp.as_bytes().contains(&0)
    {
        return Err(RelayError::InvalidTicketRequest);
    }
    Ok(())
}

fn validate_ticket_request(
    request: &CreateTicketRequest,
) -> Result<ValidatedTicketRequest, RelayError> {
    if request.protocol != TICKET_REQUEST_PROTOCOL
        || !is_fingerprint(&request.host_fingerprint)
        || !is_fingerprint(&request.client_fingerprint)
        || request.host_fingerprint == request.client_fingerprint
    {
        return Err(RelayError::InvalidTicketRequest);
    }
    let host_public_key =
        decode_hex_vec(&request.host_public_key, 32, 32).ok_or(RelayError::InvalidTicketRequest)?;
    let client_public_key = decode_hex_vec(&request.client_public_key, 64, 256)
        .ok_or(RelayError::InvalidTicketRequest)?;
    let logical_session_id =
        decode_hex::<16>(&request.logical_session_id).ok_or(RelayError::InvalidTicketRequest)?;
    if fingerprint(&host_public_key) != request.host_fingerprint
        || fingerprint(&client_public_key) != request.client_fingerprint
    {
        return Err(RelayError::InvalidTicketRequest);
    }
    let request_nonce =
        decode_hex::<32>(&request.request_nonce).ok_or(RelayError::InvalidTicketRequest)?;
    let host_signature =
        decode_hex_vec(&request.host_signature, 64, 64).ok_or(RelayError::InvalidTicketRequest)?;
    let client_signature = decode_hex_vec(&request.client_signature, 64, 80)
        .ok_or(RelayError::InvalidTicketRequest)?;
    let now = unix_ms_now();
    let latest = now.saturating_add(MAX_TICKET_TTL.as_millis() as u64);
    if request.expires_at_unix_ms <= now || request.expires_at_unix_ms > latest {
        return Err(RelayError::InvalidTicketRequest);
    }
    let transcript = ticket_request_transcript(
        &logical_session_id,
        request.expires_at_unix_ms,
        &request_nonce,
        &host_public_key,
        &client_public_key,
    );
    if UnparsedPublicKey::new(&ED25519, &host_public_key)
        .verify(&transcript, &host_signature)
        .is_err()
        || !verify_client_signature(&client_public_key, &transcript, &client_signature)
    {
        return Err(RelayError::Unauthorized);
    }
    Ok(ValidatedTicketRequest {
        host_public_key,
        client_public_key,
        request_nonce,
        valid_for: Duration::from_millis(request.expires_at_unix_ms - now),
    })
}

fn endpoint_claim_message(ticket_id: &str, role: EndpointRole) -> Vec<u8> {
    let mut message = Vec::with_capacity(ENDPOINT_CLAIM_MAGIC.len() + 1 + ticket_id.len());
    message.extend_from_slice(ENDPOINT_CLAIM_MAGIC);
    message.push(match role {
        EndpointRole::Host => 0,
        EndpointRole::Client => 1,
    });
    message.extend_from_slice(ticket_id.as_bytes());
    message
}

fn verify_endpoint_signature(
    role: EndpointRole,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    match role {
        EndpointRole::Host => UnparsedPublicKey::new(&ED25519, public_key)
            .verify(message, signature)
            .is_ok(),
        EndpointRole::Client => verify_client_signature(public_key, message, signature),
    }
}

fn verify_client_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_public_key_der(public_key) else {
        return false;
    };
    let Ok(signature) = P256Signature::from_der(signature) else {
        return false;
    };
    verifying_key.verify(message, &signature).is_ok()
}

fn endpoint_role(headers: &HeaderMap) -> Result<EndpointRole, RelayError> {
    match headers
        .get("x-hypercast-role")
        .and_then(|value| value.to_str().ok())
    {
        Some("host") => Ok(EndpointRole::Host),
        Some("client") => Ok(EndpointRole::Client),
        _ => Err(RelayError::InvalidRole),
    }
}

fn authorize_mailbox(mailbox_id: &str, token: &str) -> Result<[u8; 32], RelayError> {
    let token = decode_hex::<32>(token).ok_or(RelayError::Unauthorized)?;
    let expected = mailbox_id_for_token(&token);
    if !constant_time_eq(mailbox_id.as_bytes(), expected.as_bytes()) {
        return Err(RelayError::Unauthorized);
    }
    Ok(token)
}

fn authorize_mailbox_token(mailbox: &HostMailbox, token: &str) -> Result<(), RelayError> {
    constant_time_eq(&mailbox.token_digest, &token_digest(token))
        .then_some(())
        .ok_or(RelayError::Unauthorized)
}

fn authorize_admin(headers: &HeaderMap, expected: Option<&str>) -> Result<(), ()> {
    let token = bearer_token(headers).ok_or(())?;
    let expected = expected.ok_or(())?;
    constant_time_eq(&token_digest(token), &token_digest(expected))
        .then_some(())
        .ok_or(())
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn env_flag(key: &str) -> Result<bool> {
    match env::var(key)
        .unwrap_or_else(|_| "false".to_owned())
        .as_str()
    {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => anyhow::bail!("{key} must be true or false"),
    }
}

fn is_fingerprint(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn fingerprint(public_key: &[u8]) -> String {
    format!(
        "sha256:{}",
        hex(digest::digest(&digest::SHA256, public_key).as_ref())
    )
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    let decoded = decode_hex_vec(value, N, N)?;
    decoded.try_into().ok()
}

fn decode_hex_vec(value: &str, minimum_bytes: usize, maximum_bytes: usize) -> Option<Vec<u8>> {
    if value.len() % 2 != 0
        || value.len() < minimum_bytes * 2
        || value.len() > maximum_bytes * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn random_hex(bytes: usize) -> Result<String, ring::error::Unspecified> {
    let mut value = vec![0; bytes];
    SystemRandom::new().fill(&mut value)?;
    Ok(value.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn token_digest(value: &str) -> [u8; 32] {
    digest::digest(&digest::SHA256, value.as_bytes())
        .as_ref()
        .try_into()
        .expect("SHA-256 length")
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_ms_after(duration: Duration) -> u64 {
    SystemTime::now()
        .checked_add(duration)
        .unwrap_or(SystemTime::now())
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug)]
enum RelayError {
    Disabled,
    Unauthorized,
    InvalidRegistration,
    InvalidAccount,
    InvalidTicketRequest,
    InvalidRole,
    NotFound,
    Expired,
    AlreadyClaimed,
    CapacityExceeded,
    InvalidOpaqueEnvelope,
    PeerClosed,
    Internal,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::Disabled => "relay ingress is disabled",
            Self::Unauthorized => "unauthorized",
            Self::InvalidRegistration => "invalid Host registration",
            Self::InvalidAccount => "invalid account name",
            Self::InvalidTicketRequest => "invalid ticket request",
            Self::InvalidRole => "invalid endpoint role",
            Self::NotFound => "ticket not found",
            Self::Expired => "ticket expired",
            Self::AlreadyClaimed => "ticket endpoint already claimed",
            Self::CapacityExceeded => "rendezvous mailbox capacity exceeded",
            Self::InvalidOpaqueEnvelope => "relay accepts only HCE1 encrypted envelopes",
            Self::PeerClosed => "peer closed",
            Self::Internal => "internal relay error",
        };
        formatter.write_str(message)
    }
}

impl IntoResponse for RelayError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Disabled => StatusCode::SERVICE_UNAVAILABLE,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::InvalidRegistration
            | Self::InvalidAccount
            | Self::InvalidTicketRequest
            | Self::InvalidRole
            | Self::InvalidOpaqueEnvelope => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Expired | Self::AlreadyClaimed => StatusCode::GONE,
            Self::CapacityExceeded => StatusCode::TOO_MANY_REQUESTS,
            Self::PeerClosed | Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, self.to_string()).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{
        ecdsa::{signature::Signer, SigningKey},
        pkcs8::EncodePublicKey,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use tokio_tungstenite::{
        connect_async,
        tungstenite::{client::IntoClientRequest, Message},
    };

    #[tokio::test]
    async fn cors_preflight_and_headers_present() {
        use axum::body::Body;
        use tower::util::ServiceExt;
        let router = app(config(true));
        let preflight = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("OPTIONS")
                    .uri("/v1/hosts/abc/requests")
                    .header("origin", "http://localhost:8123")
                    .header("access-control-request-method", "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(preflight.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            preflight
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "*"
        );
        let health = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            health
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "*"
        );
    }

    fn config(enabled: bool) -> RelayConfig {
        RelayConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            enabled,
            public_relay_url: "wss://relay.example.test/v1/relay".into(),
            admin_token: Some("x".repeat(32)),
            ticket_ttl: Duration::from_secs(60),
            stun_urls: vec!["stun:relay.example.com:3478".into()],
            turn: None,
            state_file: None,
        }
    }

    struct TestIdentities {
        host: Ed25519KeyPair,
        client: SigningKey,
        host_public_key: Vec<u8>,
        client_public_key: Vec<u8>,
    }

    impl TestIdentities {
        fn new() -> Self {
            let host_pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            let host = Ed25519KeyPair::from_pkcs8(host_pkcs8.as_ref()).unwrap();
            let client = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
            let host_public_key = host.public_key().as_ref().to_vec();
            let client_public_key = client
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes()
                .to_vec();
            Self {
                host,
                client,
                host_public_key,
                client_public_key,
            }
        }

        fn endpoint_proof(&self, ticket_id: &str, role: EndpointRole) -> String {
            let message = endpoint_claim_message(ticket_id, role);
            match role {
                EndpointRole::Host => hex(self.host.sign(&message).as_ref()),
                EndpointRole::Client => {
                    let signature: P256Signature = self.client.sign(&message);
                    hex(signature.to_der().as_bytes())
                }
            }
        }

        fn signed_ticket_request(&self) -> CreateTicketRequest {
            self.signed_ticket_request_with_nonce([9u8; 32])
        }

        fn signed_ticket_request_with_nonce(&self, request_nonce: [u8; 32]) -> CreateTicketRequest {
            let expires_at_unix_ms = unix_ms_after(Duration::from_secs(60));
            let logical_session_id = [4u8; 16];
            let transcript = ticket_request_transcript(
                &logical_session_id,
                expires_at_unix_ms,
                &request_nonce,
                &self.host_public_key,
                &self.client_public_key,
            );
            let client_signature: P256Signature = self.client.sign(&transcript);
            CreateTicketRequest {
                protocol: TICKET_REQUEST_PROTOCOL.into(),
                logical_session_id: hex(&logical_session_id),
                host_public_key: hex(&self.host_public_key),
                client_public_key: hex(&self.client_public_key),
                host_fingerprint: fingerprint(&self.host_public_key),
                client_fingerprint: fingerprint(&self.client_public_key),
                request_nonce: hex(&request_nonce),
                expires_at_unix_ms,
                host_signature: hex(self.host.sign(&transcript).as_ref()),
                client_signature: hex(client_signature.to_der().as_bytes()),
            }
        }

        fn host_registration(
            &self,
            mailbox_id: &str,
            expires_at_unix_ms: u64,
        ) -> HostRegistrationRequest {
            self.host_registration_with_account(mailbox_id, expires_at_unix_ms, None)
        }

        fn host_registration_with_account(
            &self,
            mailbox_id: &str,
            expires_at_unix_ms: u64,
            account: Option<&str>,
        ) -> HostRegistrationRequest {
            let registration_nonce = [5u8; 32];
            let transcript = host_registration_transcript(
                mailbox_id,
                expires_at_unix_ms,
                &registration_nonce,
                &self.host_public_key,
            );
            HostRegistrationRequest {
                protocol: HOST_REGISTRATION_PROTOCOL.into(),
                host_public_key: hex(&self.host_public_key),
                host_fingerprint: fingerprint(&self.host_public_key),
                registration_nonce: hex(&registration_nonce),
                expires_at_unix_ms,
                signature: hex(self.host.sign(&transcript).as_ref()),
                account: account.map(str::to_owned),
            }
        }

        fn client_session_request(&self) -> ClientSessionRequest {
            self.client_session_request_with_nonce([9u8; 32])
        }

        fn client_session_request_with_nonce(
            &self,
            request_nonce: [u8; 32],
        ) -> ClientSessionRequest {
            let ticket = self.signed_ticket_request_with_nonce(request_nonce);
            let client_ephemeral = SigningKey::from_bytes((&[8u8; 32]).into()).unwrap();
            let client_ephemeral_public_key = client_ephemeral
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes()
                .to_vec();
            let client_challenge = [6u8; 32];
            let handshake_offer = client_handshake_offer_transcript(
                &decode_hex::<16>(&ticket.logical_session_id).unwrap(),
                &self.host_public_key,
                &self.client_public_key,
                &client_ephemeral_public_key,
                &client_challenge,
                &decode_hex::<32>(&ticket.request_nonce).unwrap(),
            );
            let client_handshake_signature: P256Signature = self.client.sign(&handshake_offer);
            ClientSessionRequest {
                protocol: SESSION_REQUEST_PROTOCOL.into(),
                logical_session_id: ticket.logical_session_id,
                host_fingerprint: ticket.host_fingerprint,
                client_public_key: ticket.client_public_key,
                client_fingerprint: ticket.client_fingerprint,
                request_nonce: ticket.request_nonce,
                expires_at_unix_ms: ticket.expires_at_unix_ms,
                client_signature: ticket.client_signature,
                client_ephemeral_public_key: hex(&client_ephemeral_public_key),
                client_challenge: hex(&client_challenge),
                client_handshake_signature: hex(client_handshake_signature.to_der().as_bytes()),
                p2p_offer_sdp: None,
                p2p_offer_signature: None,
            }
        }

        fn p2p_session_request(&self) -> ClientSessionRequest {
            let mut request = self.client_session_request();
            let offer = "v=0\r\na=ice-ufrag:client\r\na=fingerprint:sha-256 00\r\n";
            let transcript = p2p_offer_transcript(
                &decode_hex::<16>(&request.logical_session_id).unwrap(),
                offer.as_bytes(),
                &self.host_public_key,
                &self.client_public_key,
                &decode_hex::<32>(&request.request_nonce).unwrap(),
            );
            let signature: P256Signature = self.client.sign(&transcript);
            request.p2p_offer_sdp = Some(offer.into());
            request.p2p_offer_signature = Some(hex(signature.to_der().as_bytes()));
            request
        }

        fn host_session_signature(&self, request: &ClientSessionRequest) -> String {
            let transcript = ticket_request_transcript(
                &decode_hex::<16>(&request.logical_session_id).unwrap(),
                request.expires_at_unix_ms,
                &decode_hex::<32>(&request.request_nonce).unwrap(),
                &self.host_public_key,
                &decode_hex_vec(&request.client_public_key, 64, 256).unwrap(),
            );
            hex(self.host.sign(&transcript).as_ref())
        }

        fn host_completion(
            &self,
            request: &ClientSessionRequest,
            host_signature: String,
        ) -> HostSessionCompletion {
            let host_ephemeral = SigningKey::from_bytes((&[10u8; 32]).into()).unwrap();
            let host_ephemeral_public_key = host_ephemeral
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes()
                .to_vec();
            let host_challenge = [11u8; 32];
            let transcript = session_handshake_transcript(
                &decode_hex::<16>(&request.logical_session_id).unwrap(),
                &self.host_public_key,
                &self.client_public_key,
                &host_ephemeral_public_key,
                &decode_hex_vec(&request.client_ephemeral_public_key, 64, 256).unwrap(),
                &host_challenge,
                &decode_hex::<32>(&request.client_challenge).unwrap(),
            );
            HostSessionCompletion {
                protocol: SESSION_COMPLETION_PROTOCOL.into(),
                host_signature,
                host_ephemeral_public_key: hex(&host_ephemeral_public_key),
                host_challenge: hex(&host_challenge),
                host_handshake_signature: hex(self.host.sign(&transcript).as_ref()),
                p2p_answer_sdp: None,
                p2p_answer_signature: None,
            }
        }

        fn p2p_host_completion(
            &self,
            request: &ClientSessionRequest,
            host_signature: String,
        ) -> HostSessionCompletion {
            let mut completion = self.host_completion(request, host_signature);
            let offer = request.p2p_offer_sdp.as_deref().unwrap();
            let answer = "v=0\r\na=ice-ufrag:host\r\na=fingerprint:sha-256 11\r\n";
            let transcript = p2p_answer_transcript(
                &decode_hex::<16>(&request.logical_session_id).unwrap(),
                offer.as_bytes(),
                answer.as_bytes(),
                &self.host_public_key,
                &self.client_public_key,
            );
            completion.p2p_answer_sdp = Some(answer.into());
            completion.p2p_answer_signature = Some(hex(self.host.sign(&transcript).as_ref()));
            completion
        }

        fn ticket(&self, arrival_tx: mpsc::Sender<PeerArrival>, ttl: Duration) -> Ticket {
            Ticket {
                host_public_key: self.host_public_key.clone(),
                client_public_key: self.client_public_key.clone(),
                expires_at_unix_ms: unix_ms_after(ttl),
                host_claimed: false,
                client_claimed: false,
                arrival_tx,
            }
        }
    }

    #[test]
    fn opaque_relay_accepts_only_sized_hce1_v1_bytes() {
        let mut valid = vec![0; 17 + 16 + 44];
        valid[..4].copy_from_slice(b"HCE1");
        valid[4] = 1;
        assert!(is_opaque_envelope(&valid));
        valid[4] = 2;
        assert!(!is_opaque_envelope(&valid));
        assert!(!is_opaque_envelope(b"HCS1 plaintext is forbidden"));
    }

    #[tokio::test]
    async fn endpoint_identity_proofs_are_bound_to_role_and_single_use() {
        let identities = TestIdentities::new();
        let state = AppState::new(config(true));
        let (arrival_tx, _arrival_rx) = mpsc::channel(2);
        state.memory.lock().await.tickets.insert(
            "ticket".into(),
            identities.ticket(arrival_tx, Duration::from_secs(30)),
        );
        let host_proof = identities.endpoint_proof("ticket", EndpointRole::Host);
        let client_proof = identities.endpoint_proof("ticket", EndpointRole::Client);
        assert!(state
            .claim("ticket", EndpointRole::Host, &host_proof)
            .await
            .is_ok());
        assert!(matches!(
            state.claim("ticket", EndpointRole::Host, &host_proof).await,
            Err(RelayError::AlreadyClaimed)
        ));
        assert!(matches!(
            state
                .claim("ticket", EndpointRole::Client, &host_proof)
                .await,
            Err(RelayError::Unauthorized)
        ));
        assert!(state
            .claim("ticket", EndpointRole::Client, &client_proof)
            .await
            .is_ok());
    }

    #[test]
    fn ticket_request_requires_both_identity_signatures_and_fresh_expiry() {
        let identities = TestIdentities::new();
        let request = identities.signed_ticket_request();
        let validated = validate_ticket_request(&request).unwrap();
        assert_eq!(validated.host_public_key, identities.host_public_key);
        assert_eq!(validated.client_public_key, identities.client_public_key);

        let mut forged = identities.signed_ticket_request();
        forged.client_signature = forged.host_signature.clone();
        assert!(matches!(
            validate_ticket_request(&forged),
            Err(RelayError::Unauthorized)
        ));

        let mut expired = identities.signed_ticket_request();
        expired.expires_at_unix_ms = unix_ms_now().saturating_sub(1);
        assert!(matches!(
            validate_ticket_request(&expired),
            Err(RelayError::InvalidTicketRequest)
        ));
    }

    #[test]
    fn p2p_transcripts_bind_exact_offer_answer_and_both_identities() {
        let logical_session_id = [1u8; 16];
        let request_nonce = [2u8; 32];
        let host_public_key = [3u8; 32];
        let client_public_key = [4u8; 91];
        let offer = b"v=0\r\na=ice-ufrag:client\r\n";
        let answer = b"v=0\r\na=ice-ufrag:host\r\n";

        let offer_transcript = p2p_offer_transcript(
            &logical_session_id,
            offer,
            &host_public_key,
            &client_public_key,
            &request_nonce,
        );
        let answer_transcript = p2p_answer_transcript(
            &logical_session_id,
            offer,
            answer,
            &host_public_key,
            &client_public_key,
        );

        assert_eq!(offer_transcript.len(), 148);
        assert_eq!(&offer_transcript[..4], b"HPO1");
        assert_eq!(
            &offer_transcript[20..52],
            digest::digest(&digest::SHA256, offer).as_ref(),
        );
        assert_eq!(answer_transcript.len(), 148);
        assert_eq!(&answer_transcript[..4], b"HPA1");
        assert_eq!(
            &answer_transcript[52..84],
            digest::digest(&digest::SHA256, answer).as_ref(),
        );
    }

    #[test]
    fn signed_p2p_offer_is_optional_identity_bound_and_bounded() {
        let identities = TestIdentities::new();
        let legacy = identities.client_session_request();
        assert!(validate_client_session_request(
            &legacy,
            &identities.host_public_key,
            &fingerprint(&identities.host_public_key),
        )
        .is_ok());

        let request = identities.p2p_session_request();
        assert!(validate_client_session_request(
            &request,
            &identities.host_public_key,
            &fingerprint(&identities.host_public_key),
        )
        .is_ok());

        let mut forged = request.clone();
        forged.p2p_offer_sdp = Some("v=0\r\na=ice-ufrag:attacker\r\n".into());
        assert!(matches!(
            validate_client_session_request(
                &forged,
                &identities.host_public_key,
                &fingerprint(&identities.host_public_key),
            ),
            Err(RelayError::Unauthorized),
        ));

        let mut oversized = request;
        oversized.p2p_offer_sdp = Some("x".repeat(MAX_P2P_SDP_BYTES + 1));
        assert!(matches!(
            validate_client_session_request(
                &oversized,
                &identities.host_public_key,
                &fingerprint(&identities.host_public_key),
            ),
            Err(RelayError::InvalidTicketRequest),
        ));
    }

    #[test]
    fn signed_p2p_answer_is_required_and_bound_to_the_exact_offer() {
        let identities = TestIdentities::new();
        let request = identities.p2p_session_request();
        let host_signature = identities.host_session_signature(&request);

        assert!(matches!(
            validate_host_session_completion(
                &identities.host_completion(&request, host_signature.clone()),
                &request,
                &identities.host_public_key,
            ),
            Err(RelayError::InvalidTicketRequest),
        ));

        let completion = identities.p2p_host_completion(&request, host_signature);
        let response =
            validate_host_session_completion(&completion, &request, &identities.host_public_key)
                .unwrap();
        assert_eq!(response.p2p_answer_sdp, completion.p2p_answer_sdp);

        let mut forged = completion;
        forged.p2p_answer_sdp = Some("v=0\r\na=ice-ufrag:attacker\r\n".into());
        assert!(matches!(
            validate_host_session_completion(&forged, &request, &identities.host_public_key),
            Err(RelayError::Unauthorized),
        ));
    }

    #[tokio::test]
    async fn ticket_request_nonce_is_single_use() {
        let state = AppState::new(config(true));
        let nonce = [3u8; 32];
        assert!(state
            .use_request_nonce(nonce, Duration::from_secs(30))
            .await
            .is_ok());
        assert!(matches!(
            state
                .use_request_nonce(nonce, Duration::from_secs(30))
                .await,
            Err(RelayError::AlreadyClaimed)
        ));
    }

    /// 四端一致性(共享 fixture): crates/protocol-kit/fixtures/ 是唯一权威,
    /// Rust/Swift/Kotlin/TS 的 conformance 测试断言同一份文件。
    /// 任一端改了 transcript 布局而没同步其余端, 这里会先红。
    #[test]
    fn conformance_transcripts_match_shared_fixtures() {
        fn unhex(value: &serde_json::Value) -> Vec<u8> {
            let s = value.as_str().expect("hex string in fixture");
            (0..s.len() / 2)
                .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex byte"))
                .collect()
        }
        fn hex_str(value: &serde_json::Value) -> &str {
            value.as_str().expect("hex string in fixture")
        }

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../protocol-kit/fixtures/protocol_fixtures.json"
        );
        let root: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).expect("shared fixtures present"))
                .expect("fixtures JSON");
        let inputs = &root["inputs"];
        let transcripts = &root["transcripts"];

        let session_id = decode_hex::<16>(hex_str(&inputs["session_id"])).unwrap();
        let nonce = decode_hex::<32>(hex_str(&inputs["nonce"])).unwrap();
        let host_key = unhex(&inputs["host_key"]);
        let client_key = unhex(&inputs["client_spki"]);
        let client_eph = unhex(&inputs["client_eph_spki"]);
        let host_eph = unhex(&inputs["host_eph_spki"]);
        let host_challenge = decode_hex::<32>(hex_str(&inputs["host_challenge"])).unwrap();
        let client_challenge = decode_hex::<32>(hex_str(&inputs["client_challenge"])).unwrap();
        let offer_sdp = hex_str(&inputs["offer_sdp"]).as_bytes().to_vec();
        let answer_sdp = hex_str(&inputs["answer_sdp"]).as_bytes().to_vec();
        let expires = inputs["expires_at_ms"].as_u64().unwrap();

        assert_eq!(
            hex(&ticket_request_transcript(
                &session_id,
                expires,
                &nonce,
                &host_key,
                &client_key
            )),
            hex_str(&transcripts["hct1"]),
            "HCT1 与共享 fixture 漂移"
        );
        assert_eq!(
            hex(&client_handshake_offer_transcript(
                &session_id,
                &host_key,
                &client_key,
                &client_eph,
                &client_challenge,
                &nonce
            )),
            hex_str(&transcripts["hco1"]),
            "HCO1 与共享 fixture 漂移"
        );
        assert_eq!(
            hex(&p2p_offer_transcript(
                &session_id,
                &offer_sdp,
                &host_key,
                &client_key,
                &nonce
            )),
            hex_str(&transcripts["hpo1"]),
            "HPO1 与共享 fixture 漂移"
        );
        assert_eq!(
            hex(&p2p_answer_transcript(
                &session_id,
                &offer_sdp,
                &answer_sdp,
                &host_key,
                &client_key
            )),
            hex_str(&transcripts["hpa1"]),
            "HPA1 与共享 fixture 漂移"
        );
        assert_eq!(
            hex(&session_handshake_transcript(
                &session_id,
                &host_key,
                &client_key,
                &host_eph,
                &client_eph,
                &host_challenge,
                &client_challenge
            )),
            hex_str(&transcripts["hck1"]),
            "HCK1 与共享 fixture 漂移"
        );

        // 邮箱派生: token → mailbox_id(与四端 mailbox 公式对拍)
        let token = decode_hex::<32>(hex_str(&root["mailbox"]["bearer_token_hex"])).unwrap();
        assert_eq!(
            mailbox_id_for_token(&token),
            hex_str(&root["mailbox"]["mailbox_id"]),
            "mailbox 派生与共享 fixture 漂移"
        );
    }

    #[tokio::test]
    async fn account_host_discovery_defaults_and_namespacing() {
        let identities = TestIdentities::new();
        let state = AppState::new(config(true));

        // 旧版 Host(不带 account 字段)→ 落入公共默认账号
        let token_a = hex(&[0x42u8; 32]);
        let mailbox_a = mailbox_id_for_token(&[0x42u8; 32]);
        state
            .register_host(
                &mailbox_a,
                &token_a,
                identities.host_registration(&mailbox_a, unix_ms_after(Duration::from_secs(120))),
            )
            .await
            .unwrap();

        // 新 Host 指定自定义账号
        let token_b = hex(&[0x43u8; 32]);
        let mailbox_b = mailbox_id_for_token(&[0x43u8; 32]);
        state
            .register_host(
                &mailbox_b,
                &token_b,
                identities.host_registration_with_account(
                    &mailbox_b,
                    unix_ms_after(Duration::from_secs(120)),
                    Some("team-x"),
                ),
            )
            .await
            .unwrap();

        let default_hosts = state.list_account_hosts("default").await.unwrap();
        assert_eq!(default_hosts.len(), 1);
        assert_eq!(default_hosts[0].mailbox_id, mailbox_a);
        assert_eq!(
            default_hosts[0].host_fingerprint,
            fingerprint(&identities.host_public_key)
        );

        let team_hosts = state.list_account_hosts("team-x").await.unwrap();
        assert_eq!(team_hosts.len(), 1);
        assert_eq!(team_hosts[0].mailbox_id, mailbox_b);

        // 租约过期后登记项惰性清退
        // (不实际等待 —— 直接把 mailbox 过期掉再查询)
        {
            let mut memory = state.memory.lock().await;
            if let Some(mailbox) = memory.host_mailboxes.get_mut(&mailbox_a) {
                mailbox.expires_at_unix_ms = 0;
            }
        }
        let after_expiry = state.list_account_hosts("default").await.unwrap();
        assert!(after_expiry.is_empty(), "过期 mailbox 应从账号列表消失");

        // 非法账号名被拒
        assert!(matches!(
            state.list_account_hosts("bad account!").await,
            Err(RelayError::InvalidAccount)
        ));
        assert!(matches!(
            state.list_account_hosts(&"x".repeat(65)).await,
            Err(RelayError::InvalidAccount)
        ));
    }

    #[tokio::test]
    async fn newest_client_retry_supersedes_older_pending_request() {
        let identities = TestIdentities::new();
        let state = AppState::new(config(true));
        let token = hex(&[0x42u8; 32]);
        let mailbox_id = mailbox_id_for_token(&[0x42u8; 32]);
        state
            .register_host(
                &mailbox_id,
                &token,
                identities.host_registration(&mailbox_id, unix_ms_after(Duration::from_secs(120))),
            )
            .await
            .unwrap();

        let first_request = identities.client_session_request_with_nonce([9u8; 32]);
        let first_request_id = state
            .submit_session_request(&mailbox_id, &token, first_request)
            .await
            .unwrap();
        let second_request = identities.client_session_request_with_nonce([10u8; 32]);
        let second_request_id = state
            .submit_session_request(&mailbox_id, &token, second_request.clone())
            .await
            .unwrap();

        assert_ne!(first_request_id, second_request_id);
        let pending = state
            .next_session_request(&mailbox_id, &token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pending.request_id, second_request_id);
        assert_eq!(pending.request_nonce, second_request.request_nonce);
        assert!(matches!(
            state
                .session_status(&mailbox_id, &token, &first_request_id)
                .await,
            Err(RelayError::NotFound)
        ));
        assert!(matches!(
            state
                .submit_session_request(&mailbox_id, &token, second_request)
                .await,
            Err(RelayError::AlreadyClaimed)
        ));

        let memory = state.memory.lock().await;
        assert_eq!(memory.host_mailboxes[&mailbox_id].sessions.len(), 1);
    }

    #[tokio::test]
    async fn pending_and_ready_sessions_survive_state_reload() {
        let identities = TestIdentities::new();
        let state_directory =
            std::env::temp_dir().join(format!("hypercast-relay-state-{}", random_hex(8).unwrap()));
        let state_file = state_directory.join("state.json");
        let mut relay_config = config(true);
        relay_config.state_file = Some(state_file.clone());
        let token = hex(&[0x42u8; 32]);
        let mailbox_id = mailbox_id_for_token(&[0x42u8; 32]);
        let request = identities.client_session_request();

        let state = AppState::new(relay_config.clone());
        state
            .register_host(
                &mailbox_id,
                &token,
                identities.host_registration(&mailbox_id, unix_ms_after(Duration::from_secs(120))),
            )
            .await
            .unwrap();
        let request_id = state
            .submit_session_request(&mailbox_id, &token, request.clone())
            .await
            .unwrap();
        drop(state);

        let restarted = AppState::load(relay_config.clone()).await.unwrap();
        let pending = restarted
            .next_session_request(&mailbox_id, &token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pending.request_id, request_id);
        let ready = restarted
            .complete_session_request(
                &mailbox_id,
                &token,
                &request_id,
                identities.host_completion(&request, identities.host_session_signature(&request)),
            )
            .await
            .unwrap();
        drop(restarted);

        let restarted_again = AppState::load(relay_config).await.unwrap();
        let status = restarted_again
            .session_status(&mailbox_id, &token, &request_id)
            .await
            .unwrap();
        assert_eq!(status.status, SessionRequestStatus::Ready);
        assert_eq!(status.ticket.unwrap().ticket_id, ready.ticket.ticket_id);
        let memory = restarted_again.memory.lock().await;
        assert!(memory
            .used_request_nonces
            .contains_key(&decode_hex::<32>(&request.request_nonce).unwrap()));
        assert!(memory.tickets.contains_key(&ready.ticket.ticket_id));
        drop(memory);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&state_file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        tokio::fs::remove_dir_all(state_directory).await.unwrap();
    }

    #[tokio::test]
    async fn failed_state_write_does_not_publish_a_mailbox() {
        let identities = TestIdentities::new();
        let state_directory = std::env::temp_dir().join(format!(
            "hypercast-relay-blocked-state-{}",
            random_hex(8).unwrap()
        ));
        tokio::fs::create_dir_all(&state_directory).await.unwrap();
        let blocked_parent = state_directory.join("not-a-directory");
        tokio::fs::write(&blocked_parent, b"blocked").await.unwrap();
        let mut relay_config = config(true);
        relay_config.state_file = Some(blocked_parent.join("state.json"));
        let state = AppState::new(relay_config);
        let token = hex(&[0x42u8; 32]);
        let mailbox_id = mailbox_id_for_token(&[0x42u8; 32]);

        assert!(matches!(
            state
                .register_host(
                    &mailbox_id,
                    &token,
                    identities
                        .host_registration(&mailbox_id, unix_ms_after(Duration::from_secs(120)),),
                )
                .await,
            Err(RelayError::Internal),
        ));
        assert!(!state
            .memory
            .lock()
            .await
            .host_mailboxes
            .contains_key(&mailbox_id));
        tokio::fs::remove_dir_all(state_directory).await.unwrap();
    }

    #[test]
    fn fingerprints_are_strict_and_do_not_accept_hostnames() {
        let fingerprint = format!("sha256:{}", "a".repeat(64));
        assert!(is_fingerprint(&fingerprint));
        assert!(!is_fingerprint("sha256:not-a-fingerprint"));
        assert!(!is_fingerprint("relay.example.test"));
    }

    #[test]
    fn admin_authentication_does_not_accept_a_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".parse().unwrap(),
        );
        assert!(authorize_admin(&headers, Some(&"x".repeat(32))).is_ok());
        headers.insert(
            header::AUTHORIZATION,
            "Bearer xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".parse().unwrap(),
        );
        assert!(authorize_admin(&headers, Some(&"x".repeat(32))).is_err());
    }

    #[test]
    fn mailbox_id_is_cryptographically_bound_to_a_strict_token() {
        let token = [0x42u8; 32];
        let token_hex = hex(&token);
        let mailbox_id = mailbox_id_for_token(&token);
        assert!(authorize_mailbox(&mailbox_id, &token_hex).is_ok());
        assert!(authorize_mailbox(&mailbox_id, &hex(&[0x43u8; 32])).is_err());
        assert!(authorize_mailbox("relay.example.test", &token_hex).is_err());
        assert!(authorize_mailbox(&mailbox_id, "too-short").is_err());
    }

    #[test]
    fn turn_rest_credentials_are_bounded_and_coturn_compatible() {
        let turn = TurnCredentialConfig {
            urls: vec![
                "turn:43.163.194.230:5444?transport=udp".into(),
                "turn:43.163.194.230:5444?transport=tcp".into(),
            ],
            shared_secret: b"0123456789abcdef0123456789abcdef".to_vec(),
            credential_ttl: Duration::from_secs(600),
        };

        let issued = turn.issue(&"a".repeat(64), 1_700_000_000).unwrap();

        assert_eq!(issued.urls, turn.urls);
        assert!(issued.username.starts_with("1700000600:aaaaaaaaaaaaaaaa:"));
        assert_eq!(issued.username.len(), 44);
        assert!(issued.username[28..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()));
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &turn.shared_secret);
        assert_eq!(
            issued.credential,
            BASE64_STANDARD.encode(hmac::sign(&key, issued.username.as_bytes()).as_ref())
        );
        assert_eq!(issued.expires_at_unix_ms, 1_700_000_600_000);
    }

    #[test]
    fn turn_rest_credentials_are_unique_for_consecutive_sessions() {
        let turn = TurnCredentialConfig {
            urls: vec!["turn:43.163.194.230:5444?transport=udp".into()],
            shared_secret: b"0123456789abcdef0123456789abcdef".to_vec(),
            credential_ttl: Duration::from_secs(600),
        };

        let first = turn.issue(&"a".repeat(64), 1_700_000_000).unwrap();
        let second = turn.issue(&"a".repeat(64), 1_700_000_000).unwrap();

        assert_ne!(first.username, second.username);
        assert!(first.username.starts_with("1700000600:aaaaaaaaaaaaaaaa:"));
        assert!(second.username.starts_with("1700000600:aaaaaaaaaaaaaaaa:"));
    }

    #[tokio::test]
    async fn ice_configuration_requires_a_live_authenticated_mailbox() {
        let identities = TestIdentities::new();
        let mut relay_config = config(true);
        relay_config.turn = Some(TurnCredentialConfig {
            urls: vec!["turn:43.163.194.230:5444?transport=udp".into()],
            shared_secret: b"0123456789abcdef0123456789abcdef".to_vec(),
            credential_ttl: Duration::from_secs(600),
        });
        let state = AppState::new(relay_config);
        let token = hex(&[0x42u8; 32]);
        let mailbox_id = mailbox_id_for_token(&[0x42u8; 32]);

        assert!(matches!(
            state.ice_configuration(&mailbox_id, &token).await,
            Err(RelayError::NotFound)
        ));

        state
            .register_host(
                &mailbox_id,
                &token,
                identities.host_registration(&mailbox_id, unix_ms_after(Duration::from_secs(120))),
            )
            .await
            .unwrap();
        let response = state.ice_configuration(&mailbox_id, &token).await.unwrap();
        assert_eq!(response.ice_servers.len(), 2);
        assert_eq!(response.ice_servers[0].urls, state.config.stun_urls);
        assert!(response.ice_servers[0].username.is_empty());
        assert_eq!(response.ice_servers[1].username.len(), 44);
        assert!(!response.ice_servers[1].credential.is_empty());

        assert!(matches!(
            state
                .ice_configuration(&mailbox_id, &hex(&[0x43u8; 32]))
                .await,
            Err(RelayError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn paired_mailbox_requires_both_identity_signatures_before_issuing_a_ticket() {
        let identities = TestIdentities::new();
        let state = AppState::new(config(true));
        let token = hex(&[0x42u8; 32]);
        let mailbox_id = mailbox_id_for_token(&[0x42u8; 32]);
        let registration =
            identities.host_registration(&mailbox_id, unix_ms_after(Duration::from_secs(120)));
        state
            .register_host(&mailbox_id, &token, registration)
            .await
            .unwrap();

        let request = identities.client_session_request();
        let request_id = state
            .submit_session_request(&mailbox_id, &token, request.clone())
            .await
            .unwrap();
        let pending = state
            .next_session_request(&mailbox_id, &token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pending.request_id, request_id);
        assert_eq!(pending.host_public_key, hex(&identities.host_public_key));

        assert!(matches!(
            state
                .complete_session_request(
                    &mailbox_id,
                    &token,
                    &request_id,
                    identities.host_completion(&request, "00".repeat(64)),
                )
                .await,
            Err(RelayError::Unauthorized)
        ));

        let ticket = state
            .complete_session_request(
                &mailbox_id,
                &token,
                &request_id,
                identities.host_completion(&request, identities.host_session_signature(&request)),
            )
            .await
            .unwrap();
        assert!(ticket.ticket.relay_url.starts_with("wss://"));
        assert_eq!(
            state
                .session_status(&mailbox_id, &token, &request_id)
                .await
                .unwrap()
                .status,
            SessionRequestStatus::Ready,
        );
    }

    #[tokio::test]
    async fn websocket_relay_outlives_its_admission_ticket_and_forwards_hce1() {
        let identities = TestIdentities::new();
        let state = AppState::new(config(true));
        let (arrival_tx, arrival_rx) = mpsc::channel(2);
        state.memory.lock().await.tickets.insert(
            "ticket".into(),
            identities.ticket(arrival_tx, Duration::from_secs(10)),
        );
        let broker = tokio::spawn(run_ticket_broker(
            "ticket".into(),
            arrival_rx,
            Duration::from_secs(1),
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app_with_state(state)).await.unwrap();
        });

        let connect = |role: &str, proof: &str| {
            let mut request = format!("ws://{address}/v1/relay/ticket")
                .into_client_request()
                .unwrap();
            request
                .headers_mut()
                .insert("x-hypercast-role", role.parse().unwrap());
            request.headers_mut().insert(
                header::AUTHORIZATION,
                format!("Bearer {proof}").parse().unwrap(),
            );
            request
        };
        let host_proof = identities.endpoint_proof("ticket", EndpointRole::Host);
        let client_proof = identities.endpoint_proof("ticket", EndpointRole::Client);
        let (mut host, _) = connect_async(connect("host", &host_proof)).await.unwrap();
        let (mut client, _) = connect_async(connect("client", &client_proof))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        let mut envelope = vec![0; 17 + 16 + 44];
        envelope[..4].copy_from_slice(HCE1_MAGIC);
        envelope[4] = 1;
        host.send(Message::Binary(envelope.clone())).await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(2), client.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(received, Message::Binary(envelope));
        host.close(None).await.unwrap();
        client.close(None).await.unwrap();
        server.abort();
        broker.abort();
    }

    #[test]
    fn relay_forward_stats_are_bounded_and_track_the_slowest_frame() {
        let mut stats = RelayForwardStats::default();
        stats.record(1_024, Duration::from_micros(350));
        stats.record(2_048, Duration::from_millis(3));

        assert_eq!(stats.frames, 2);
        assert_eq!(stats.bytes, 3_072);
        assert_eq!(stats.max_forward_us, 3_000);

        stats.frames = u64::MAX;
        stats.bytes = u64::MAX;
        stats.record(1, Duration::from_secs(u64::MAX));
        assert_eq!(stats.frames, u64::MAX);
        assert_eq!(stats.bytes, u64::MAX);
        assert_eq!(stats.max_forward_us, u64::MAX);
    }

    #[test]
    fn relay_trace_id_is_stable_short_and_does_not_expose_the_ticket() {
        let ticket = "ticket-secret-that-must-not-appear-in-logs";
        let first = relay_trace_id(ticket);
        let second = relay_trace_id(ticket);

        assert_eq!(first, second);
        assert_eq!(first.len(), 12);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(!first.contains(ticket));
    }
}
