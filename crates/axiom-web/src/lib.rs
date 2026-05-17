use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use axiom_config::{AdminCredentials, AxiomConfig, PolicyConfig, ProxyListenerConfig};
use axiom_core::{
    InspectionContext, InspectionResult, PolicyRuntimeSnapshot, RuntimeState, StatusSnapshot,
    TrafficDirection,
};
use axiom_net::bind_tcp_listener_to_interface;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

const SESSION_COOKIE_NAME: &str = "axiom_session";
const SESSION_MAX_AGE_SECONDS: u64 = 8 * 60 * 60;

struct WebState {
    runtime: Arc<RuntimeState>,
    config_path: PathBuf,
    config: Mutex<AxiomConfig>,
}

pub async fn run_management_server(
    config_path: PathBuf,
    config: AxiomConfig,
    runtime: Arc<RuntimeState>,
) -> anyhow::Result<()> {
    let management = config.management.clone();
    let listener =
        bind_tcp_listener_to_interface(&management.interface, management.listen_addr(), 1024)
            .await
            .with_context(|| {
                format!(
                    "failed binding management server to interface '{}' at {}",
                    management.interface,
                    management.listen_addr()
                )
            })?;

    let state = Arc::new(WebState {
        runtime,
        config_path,
        config: Mutex::new(config),
    });

    let app = Router::new()
        .route("/", get(dashboard_page))
        .route("/dashboard", get(dashboard_page))
        .route("/login", get(login_page))
        .route("/api/status", get(api_status))
        .route("/api/diagnostics", get(api_diagnostics))
        .route("/api/policies", get(api_policies).put(api_update_policies))
        .route("/api/policies/self-test", post(api_policy_self_test))
        .route("/api/login", post(api_login))
        .route("/api/logout", post(api_logout))
        .with_state(state);

    info!(
        interface = management.interface,
        listen_addr = %management.listen_addr(),
        "management GUI server started"
    );

    axum::serve(listener, app).await?;
    Ok(())
}

async fn login_page(headers: HeaderMap, State(state): State<Arc<WebState>>) -> Response {
    if is_authorized(&headers, &state) {
        return Redirect::temporary("/dashboard").into_response();
    }

    Html(LOGIN_HTML).into_response()
}

async fn dashboard_page(headers: HeaderMap, State(state): State<Arc<WebState>>) -> Response {
    if !is_authorized(&headers, &state) {
        return Redirect::temporary("/login").into_response();
    }

    Html(DASHBOARD_HTML).into_response()
}

async fn api_status(headers: HeaderMap, State(state): State<Arc<WebState>>) -> Response {
    if !is_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                message: "authentication required",
            }),
        )
            .into_response();
    }

    Json(build_status_response(&state)).into_response()
}

async fn api_diagnostics(headers: HeaderMap, State(state): State<Arc<WebState>>) -> Response {
    if !is_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                message: "authentication required",
            }),
        )
            .into_response();
    }

    Json(build_diagnostics_response(&state)).into_response()
}

async fn api_policies(headers: HeaderMap, State(state): State<Arc<WebState>>) -> Response {
    if !is_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                message: "authentication required",
            }),
        )
            .into_response();
    }

    Json(state.runtime.policy_config()).into_response()
}

async fn api_update_policies(
    headers: HeaderMap,
    State(state): State<Arc<WebState>>,
    Json(policy): Json<PolicyConfig>,
) -> Response {
    if !is_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                message: "authentication required",
            }),
        )
            .into_response();
    }

    if let Err(error) = policy.validate() {
        warn!(?error, "invalid policy update rejected");
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                message: "invalid policy configuration",
            }),
        )
            .into_response();
    }

    let persisted = {
        let mut config = state.config.lock().expect("web config mutex poisoned");
        config.policy = policy.clone();
        persist_config(&state.config_path, &config)
    };

    if let Err(error) = persisted {
        warn!(?error, "failed persisting policy update");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                message: "failed saving policy configuration",
            }),
        )
            .into_response();
    }

    let runtime_policy = state.runtime.update_policy(policy);

    Json(PolicyUpdateResponse {
        message: "policy updated and applied to the running engine",
        process_id: std::process::id(),
        config_path: state.config_path.display().to_string(),
        policy_runtime: runtime_policy,
    })
    .into_response()
}

async fn api_policy_self_test(headers: HeaderMap, State(state): State<Arc<WebState>>) -> Response {
    if !is_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                message: "authentication required",
            }),
        )
            .into_response();
    }

    let context = InspectionContext {
        route_name: "policy-self-test",
        interface: "local",
        direction: TrafficDirection::ClientToServer,
        peer_addr: "127.0.0.1:44500".parse().expect("static address is valid"),
        target_addr: "127.0.0.1:445".parse().expect("static address is valid"),
    };

    let tests = [
        (
            "Synthetic signature",
            b"SMB write body AXIOM_TEST_THREAT payload".to_vec(),
        ),
        (
            "UTF-16LE synthetic signature",
            utf16le_test_payload("AXIOM_TEST_THREAT"),
        ),
        (
            "EICAR signature",
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".to_vec(),
        ),
        (
            "RAR filename extension",
            utf16le_test_payload("FinanceBackup.rar"),
        ),
        (
            "ZIP content header",
            b"\x00\x00\x00\x40\xfeSMBpaddingPK\x03\x04\x14\x00\x00\x00payload".to_vec(),
        ),
    ];

    let results = tests
        .into_iter()
        .map(|(name, payload)| {
            let outcome = state.runtime.inspect_chunk(&context, &payload);
            PolicySelfTestResult::from_outcome(name, outcome)
        })
        .collect();

    Json(PolicySelfTestResponse {
        message: "policy self-test completed",
        process_id: std::process::id(),
        policy_runtime: state.runtime.policy_runtime_snapshot(),
        results,
    })
    .into_response()
}

async fn api_login(
    State(state): State<Arc<WebState>>,
    Json(request): Json<LoginRequest>,
) -> Response {
    let provider = request.provider.unwrap_or(AuthProvider::Local);

    if provider == AuthProvider::Ldap {
        return (
            StatusCode::UNAUTHORIZED,
            Json(LoginResponse {
                authenticated: false,
                token: None,
                message: "ldap authentication is disabled in this deployment",
            }),
        )
            .into_response();
    }

    let admin = {
        let config = state.config.lock().expect("web config mutex poisoned");
        config.management.admin.clone()
    };
    let admin = &admin;
    if request.username == admin.username && verify_admin_password(admin, &request.password) {
        let token = session_token(admin);
        let cookie = format!(
            "{SESSION_COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_MAX_AGE_SECONDS}"
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::SET_COOKIE,
            HeaderValue::from_str(&cookie).unwrap_or_else(|_| {
                HeaderValue::from_static(
                    "axiom_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
                )
            }),
        );

        return (
            StatusCode::OK,
            headers,
            Json(LoginResponse {
                authenticated: true,
                token: Some(token),
                message: "authenticated",
            }),
        )
            .into_response();
    }

    warn!(username = request.username, "management login failed");

    (
        StatusCode::UNAUTHORIZED,
        Json(LoginResponse {
            authenticated: false,
            token: None,
            message: "invalid credentials",
        }),
    )
        .into_response()
}

async fn api_logout() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_static("axiom_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),
    );

    (
        StatusCode::OK,
        headers,
        Json(ErrorResponse {
            message: "logged out",
        }),
    )
        .into_response()
}

fn build_status_response(state: &WebState) -> StatusResponse {
    let config = state.config.lock().expect("web config mutex poisoned");
    StatusResponse {
        process_id: std::process::id(),
        config_path: state.config_path.display().to_string(),
        management_interface: config.management.interface.clone(),
        management_bind_addr: config.management.listen_addr().to_string(),
        configured_proxy_listeners: config.proxy_listeners.len(),
        proxy_listeners: config
            .proxy_listeners
            .iter()
            .map(ProxyListenerStatus::from)
            .collect(),
        stats: state.runtime.snapshot(),
    }
}

fn build_diagnostics_response(state: &WebState) -> DiagnosticsResponse {
    let config = state.config.lock().expect("web config mutex poisoned");
    DiagnosticsResponse {
        process_id: std::process::id(),
        executable_path: std::env::current_exe()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|error| format!("unavailable: {error}")),
        config_path: state.config_path.display().to_string(),
        management_bind_addr: config.management.listen_addr().to_string(),
        proxy_listeners: config
            .proxy_listeners
            .iter()
            .map(ProxyListenerStatus::from)
            .collect(),
        status: state.runtime.snapshot(),
        command_outputs: vec![
            run_diagnostic_command("ss", &["-ltnp"]),
            run_diagnostic_command("ss", &["-tnp"]),
            run_diagnostic_command("ip", &["-br", "addr"]),
            run_diagnostic_command("ip", &["route"]),
            run_diagnostic_command("ip", &["rule"]),
            run_diagnostic_command("nft", &["list", "ruleset"]),
            run_diagnostic_command("iptables-save", &[]),
            run_diagnostic_command("sysctl", &["net.ipv4.ip_forward"]),
            run_diagnostic_command("sysctl", &["net.ipv4.conf.all.forwarding"]),
            run_diagnostic_command("sysctl", &["net.ipv4.conf.all.route_localnet"]),
            run_diagnostic_command("ls", &["-l", "/var/log/axiom"]),
            run_diagnostic_command("tail", &["-n", "80", "/var/log/axiom/audit.jsonl"]),
        ],
        proc_self_status: fs::read_to_string("/proc/self/status").ok(),
    }
}

fn is_authorized(headers: &HeaderMap, state: &WebState) -> bool {
    let expected_token = {
        let config = state.config.lock().expect("web config mutex poisoned");
        session_token(&config.management.admin)
    };

    if let Some(header_value) = headers.get(header::AUTHORIZATION)
        && let Ok(value) = header_value.to_str()
        && let Some(token) = value.strip_prefix("Bearer ")
        && constant_time_eq(token.as_bytes(), expected_token.as_bytes())
    {
        return true;
    }

    if let Some(header_value) = headers.get(header::COOKIE)
        && let Ok(value) = header_value.to_str()
        && let Some(token) = cookie_value(value, SESSION_COOKIE_NAME)
        && constant_time_eq(token.as_bytes(), expected_token.as_bytes())
    {
        return true;
    }

    false
}

fn cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    cookie_header.split(';').find_map(|part| {
        let trimmed = part.trim();
        let (key, value) = trimmed.split_once('=')?;
        (key == name).then_some(value)
    })
}

fn verify_admin_password(admin: &AdminCredentials, password: &str) -> bool {
    let Some((scheme, remainder)) = admin.password_hash.split_once('$') else {
        return false;
    };
    let Some((salt, expected_hash)) = remainder.split_once('$') else {
        return false;
    };

    if scheme != "sha256" || salt.is_empty() || expected_hash.len() != 64 {
        return false;
    }

    let candidate = sha256_hex(format!("{salt}:{password}").as_bytes());
    constant_time_eq(candidate.as_bytes(), expected_hash.as_bytes())
}

fn session_token(admin: &AdminCredentials) -> String {
    sha256_hex(format!("axiom-session:{}:{}", admin.username, admin.password_hash).as_bytes())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);

    for byte in digest {
        output.push(hex_char(byte >> 4));
        output.push(hex_char(byte & 0x0f));
    }

    output
}

fn hex_char(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => '0',
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        diff |= left ^ right;
    }

    diff == 0
}

fn persist_config(path: &Path, config: &AxiomConfig) -> anyhow::Result<()> {
    let serialized = toml::to_string_pretty(config).context("failed serializing Axiom config")?;

    if path.exists() {
        let backup_path = path.with_extension(format!("toml.bak-{}", unix_timestamp_seconds()));
        fs::copy(path, &backup_path).with_context(|| {
            format!(
                "failed backing up config from {} to {}",
                path.display(),
                backup_path.display()
            )
        })?;
    }

    fs::write(path, serialized)
        .with_context(|| format!("failed writing config to {}", path.display()))?;

    Ok(())
}

fn unix_timestamp_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn run_diagnostic_command(command: &str, args: &[&str]) -> CommandOutput {
    match Command::new(command).args(args).output() {
        Ok(output) => CommandOutput {
            command: format!("{} {}", command, args.join(" ")),
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        },
        Err(error) => CommandOutput {
            command: format!("{} {}", command, args.join(" ")),
            exit_code: None,
            stdout: String::new(),
            stderr: error.to_string(),
        },
    }
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    process_id: u32,
    config_path: String,
    management_interface: String,
    management_bind_addr: String,
    configured_proxy_listeners: usize,
    proxy_listeners: Vec<ProxyListenerStatus>,
    stats: StatusSnapshot,
}

#[derive(Debug, Serialize)]
struct DiagnosticsResponse {
    process_id: u32,
    executable_path: String,
    config_path: String,
    management_bind_addr: String,
    proxy_listeners: Vec<ProxyListenerStatus>,
    status: StatusSnapshot,
    command_outputs: Vec<CommandOutput>,
    proc_self_status: Option<String>,
}

#[derive(Debug, Serialize)]
struct CommandOutput {
    command: String,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Serialize)]
struct ProxyListenerStatus {
    name: String,
    source_interface: String,
    client_vlan: Option<u16>,
    listen_addr: String,
    target_file_server_addr: String,
}

impl From<&ProxyListenerConfig> for ProxyListenerStatus {
    fn from(config: &ProxyListenerConfig) -> Self {
        Self {
            name: config.name.clone(),
            source_interface: config.source_interface.clone(),
            client_vlan: config.client_vlan,
            listen_addr: config.listen_addr().to_string(),
            target_file_server_addr: config.target_addr().to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    provider: Option<AuthProvider>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AuthProvider {
    Local,
    Ldap,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    authenticated: bool,
    token: Option<String>,
    message: &'static str,
}

#[derive(Debug, Serialize)]
struct PolicyUpdateResponse {
    message: &'static str,
    process_id: u32,
    config_path: String,
    policy_runtime: PolicyRuntimeSnapshot,
}

#[derive(Debug, Serialize)]
struct PolicySelfTestResponse {
    message: &'static str,
    process_id: u32,
    policy_runtime: PolicyRuntimeSnapshot,
    results: Vec<PolicySelfTestResult>,
}

#[derive(Debug, Serialize)]
struct PolicySelfTestResult {
    name: &'static str,
    outcome: &'static str,
    rule_name: Option<String>,
    reason: Option<String>,
}

impl PolicySelfTestResult {
    fn from_outcome(name: &'static str, outcome: InspectionResult) -> Self {
        match outcome {
            InspectionResult::Allow { .. } => Self {
                name,
                outcome: "allow",
                rule_name: None,
                reason: None,
            },
            InspectionResult::Monitor { event } => Self {
                name,
                outcome: "monitor",
                rule_name: Some(event.rule_name),
                reason: Some(event.reason),
            },
            InspectionResult::Block { event } => Self {
                name,
                outcome: "block",
                rule_name: Some(event.rule_name),
                reason: Some(event.reason),
            },
        }
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    message: &'static str,
}

fn utf16le_test_payload(value: &str) -> Vec<u8> {
    let mut payload = b"\x00\x00\x00\x90\xfeSMBself-test-padding".to_vec();
    payload.extend(value.encode_utf16().flat_map(|unit| unit.to_le_bytes()));
    payload
}

const LOGIN_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Axiom Management Login</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-zinc-950 text-zinc-100">
  <main class="grid min-h-screen grid-cols-1 lg:grid-cols-[1.1fr_0.9fr]">
    <section class="relative flex items-center overflow-hidden bg-[radial-gradient(circle_at_20%_20%,rgba(16,185,129,0.28),transparent_30%),radial-gradient(circle_at_80%_10%,rgba(14,165,233,0.18),transparent_28%),linear-gradient(135deg,#09090b,#18181b_58%,#052e2b)] px-8 py-12">
      <div class="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-emerald-400/60 to-transparent"></div>
      <div class="max-w-3xl">
        <div class="mb-8 inline-flex items-center gap-3 rounded-full border border-emerald-400/25 bg-emerald-400/10 px-4 py-2 text-sm text-emerald-100">
          <span class="h-2 w-2 rounded-full bg-emerald-300"></span>
          Inline SMB protection
        </div>
        <h1 class="text-5xl font-semibold tracking-normal text-white md:text-7xl">Axiom</h1>
        <p class="mt-6 max-w-2xl text-lg leading-8 text-zinc-300">Real-time SMB reverse proxy visibility for segmented enterprise file-server networks.</p>
      </div>
    </section>

    <section class="flex items-center justify-center px-6 py-12">
      <div class="w-full max-w-md rounded-lg border border-zinc-800 bg-zinc-900/80 p-8 shadow-2xl shadow-black/30">
        <div class="mb-8">
          <p class="text-sm font-medium uppercase tracking-[0.28em] text-emerald-300">Management</p>
          <h2 class="mt-3 text-3xl font-semibold text-white">Sign in</h2>
        </div>

        <form id="login-form" class="space-y-5">
          <label class="block">
            <span class="text-sm text-zinc-300">Username</span>
            <input id="username" name="username" autocomplete="username" required class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-4 py-3 text-white outline-none transition focus:border-emerald-400 focus:ring-2 focus:ring-emerald-400/20">
          </label>

          <label class="block">
            <span class="text-sm text-zinc-300">Password</span>
            <input id="password" name="password" type="password" autocomplete="current-password" required class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-4 py-3 text-white outline-none transition focus:border-emerald-400 focus:ring-2 focus:ring-emerald-400/20">
          </label>

          <button class="w-full rounded-md bg-emerald-400 px-4 py-3 font-semibold text-zinc-950 transition hover:bg-emerald-300 focus:outline-none focus:ring-2 focus:ring-emerald-300 focus:ring-offset-2 focus:ring-offset-zinc-950" type="submit">Log in</button>
          <p id="error" class="hidden rounded-md border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200"></p>
        </form>
      </div>
    </section>
  </main>

  <script>
    const form = document.getElementById("login-form");
    const errorBox = document.getElementById("error");

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      errorBox.classList.add("hidden");

      const response = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: document.getElementById("username").value,
          password: document.getElementById("password").value,
          provider: "local"
        })
      });

      const payload = await response.json().catch(() => ({ message: "login failed" }));
      if (!response.ok || !payload.authenticated) {
        errorBox.textContent = payload.message || "Invalid credentials";
        errorBox.classList.remove("hidden");
        return;
      }

      localStorage.setItem("axiomToken", payload.token);
      window.location.href = "/dashboard";
    });
  </script>
</body>
</html>
"##;

const DASHBOARD_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Axiom Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-zinc-950 text-zinc-100">
  <header class="border-b border-zinc-800 bg-zinc-950/95">
    <div class="mx-auto flex max-w-7xl items-center justify-between px-6 py-5">
      <div>
        <p class="text-sm font-medium uppercase tracking-[0.28em] text-emerald-300">Axiom</p>
        <h1 class="mt-1 text-2xl font-semibold text-white">SMB Protection Dashboard</h1>
      </div>
      <button id="logout" class="rounded-md border border-zinc-700 px-4 py-2 text-sm text-zinc-200 transition hover:border-red-400 hover:text-red-200">Log out</button>
    </div>
  </header>

  <main class="mx-auto max-w-7xl px-6 py-8">
    <section class="grid gap-5 md:grid-cols-4 xl:grid-cols-8">
      <article class="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
        <p class="text-sm text-zinc-400">Forwarded Bytes</p>
        <p id="forwarded-bytes" class="mt-4 text-4xl font-semibold text-white">0 B</p>
      </article>
      <article class="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
        <p class="text-sm text-zinc-400">Socket Bytes Read</p>
        <p id="stream-bytes" class="mt-4 text-4xl font-semibold text-sky-200">0 B</p>
      </article>
      <article class="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
        <p class="text-sm text-zinc-400">SMB Write Bytes</p>
        <p id="smb-write-bytes" class="mt-4 text-4xl font-semibold text-lime-200">0 B</p>
      </article>
      <article class="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
        <p class="text-sm text-zinc-400">Active Connections</p>
        <p id="active-connections" class="mt-4 text-4xl font-semibold text-cyan-200">0</p>
      </article>
      <article class="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
        <p class="text-sm text-zinc-400">Blocked Threats</p>
        <p id="blocked-threats" class="mt-4 text-4xl font-semibold text-red-300">0</p>
      </article>
      <article class="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
        <p class="text-sm text-zinc-400">Monitored Detections</p>
        <p id="monitored-threats" class="mt-4 text-4xl font-semibold text-amber-200">0</p>
      </article>
      <article class="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
        <p class="text-sm text-zinc-400">Inspected Chunks</p>
        <p id="inspected-chunks" class="mt-4 text-4xl font-semibold text-emerald-200">0</p>
      </article>
      <article class="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
        <p class="text-sm text-zinc-400">Observed Files</p>
        <p id="observed-files" class="mt-4 text-4xl font-semibold text-violet-200">0</p>
      </article>
      <article class="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
        <p class="text-sm text-zinc-400">Server-side Copies</p>
        <p id="server-side-copies" class="mt-4 text-4xl font-semibold text-orange-200">0</p>
      </article>
    </section>

    <section class="mt-6 rounded-lg border border-emerald-500/20 bg-emerald-500/5 px-6 py-5">
      <div class="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <p class="text-sm font-semibold uppercase tracking-wider text-emerald-300">Runtime Enforcement</p>
          <h2 id="runtime-policy-state" class="mt-2 text-xl font-semibold text-white">Loading active policy</h2>
          <p id="runtime-policy-detail" class="mt-1 text-sm text-zinc-300"></p>
        </div>
        <div class="flex flex-col gap-3 sm:flex-row sm:items-center">
          <button id="run-policy-self-test" class="rounded-md border border-emerald-400/40 px-4 py-2 text-sm font-semibold text-emerald-100 transition hover:border-emerald-300 hover:bg-emerald-400/10">Run policy self-test</button>
          <p id="self-test-state" class="text-sm text-zinc-400">Self-test not run</p>
        </div>
      </div>
      <div id="self-test-results" class="mt-4 grid gap-3 md:grid-cols-4"></div>
    </section>

    <section class="mt-8 rounded-lg border border-zinc-800 bg-zinc-900">
      <div class="flex flex-col gap-4 border-b border-zinc-800 px-6 py-5 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 class="text-xl font-semibold text-white">Policy Controls</h2>
          <p id="policy-state" class="mt-1 text-sm text-zinc-400">Loading policies</p>
        </div>
        <div class="flex flex-wrap gap-2">
          <button data-preset="monitor" class="policy-preset rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-200 transition hover:border-cyan-300 hover:text-cyan-100">Monitor only</button>
          <button data-preset="balanced" class="policy-preset rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-200 transition hover:border-emerald-300 hover:text-emerald-100">Balanced</button>
          <button data-preset="strict" class="policy-preset rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-200 transition hover:border-red-300 hover:text-red-100">Strict</button>
          <button id="save-policies" class="rounded-md bg-emerald-400 px-4 py-2 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-300">Save and apply</button>
        </div>
      </div>

      <div class="grid gap-6 p-6 lg:grid-cols-[1fr_1fr]">
        <div>
          <h3 class="text-sm font-semibold uppercase tracking-wider text-zinc-400">SMB Transport Rules</h3>
          <div class="mt-4">
            <label class="block">
              <span class="text-sm text-zinc-300">SMB Encrypted Payload</span>
              <select id="policy-smb-encrypted-payload" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-white"></select>
            </label>
            <p class="mt-2 text-xs leading-5 text-zinc-500">When SMB encryption is active, file bytes are not visible to archive or signature rules.</p>
          </div>
        </div>

        <div>
          <h3 class="text-sm font-semibold uppercase tracking-wider text-zinc-400">Archive Rules</h3>
          <div class="mt-4 grid gap-4 sm:grid-cols-2">
            <label class="block">
              <span class="text-sm text-zinc-300">RAR</span>
              <select id="policy-rar" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-white"></select>
            </label>
            <label class="block">
              <span class="text-sm text-zinc-300">7z</span>
              <select id="policy-seven-zip" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-white"></select>
            </label>
            <label class="block">
              <span class="text-sm text-zinc-300">ZIP</span>
              <select id="policy-zip" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-white"></select>
            </label>
            <label class="block">
              <span class="text-sm text-zinc-300">Encrypted ZIP</span>
              <select id="policy-encrypted-zip" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-white"></select>
            </label>
          </div>
        </div>

        <div>
          <h3 class="text-sm font-semibold uppercase tracking-wider text-zinc-400">Entropy Rule</h3>
          <div class="mt-4 grid gap-4 sm:grid-cols-3">
            <label class="block">
              <span class="text-sm text-zinc-300">Mode</span>
              <select id="policy-entropy-mode" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-white"></select>
            </label>
            <label class="block">
              <span class="text-sm text-zinc-300">Threshold</span>
              <input id="policy-entropy-threshold" type="number" step="0.01" min="0" max="8" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-white">
            </label>
            <label class="block">
              <span class="text-sm text-zinc-300">Min Chunk</span>
              <input id="policy-entropy-minimum" type="number" min="1" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-white">
            </label>
          </div>
        </div>

        <div class="lg:col-span-2">
          <h3 class="text-sm font-semibold uppercase tracking-wider text-zinc-400">Signatures</h3>
          <textarea id="policy-signatures" rows="5" spellcheck="false" class="mt-4 w-full rounded-md border border-zinc-700 bg-zinc-950 px-4 py-3 font-mono text-sm text-white outline-none focus:border-emerald-400"></textarea>
        </div>
      </div>
    </section>

    <section class="mt-8 rounded-lg border border-zinc-800 bg-zinc-900">
      <div class="flex flex-col gap-2 border-b border-zinc-800 px-6 py-5 md:flex-row md:items-end md:justify-between">
        <div>
          <h2 class="text-xl font-semibold text-white">NIC Mappings</h2>
          <p id="management-info" class="mt-1 text-sm text-zinc-400"></p>
        </div>
        <p id="refresh-state" class="text-sm text-zinc-500">Waiting for telemetry</p>
      </div>

      <div class="overflow-x-auto">
        <table class="min-w-full divide-y divide-zinc-800">
          <thead class="bg-zinc-950/60">
            <tr>
              <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Route</th>
              <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Interface</th>
              <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">VLAN</th>
              <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Listen</th>
              <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Target File Server</th>
              <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Connections</th>
              <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Inspected</th>
              <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Route Bytes</th>
            </tr>
          </thead>
          <tbody id="mapping-body" class="divide-y divide-zinc-800"></tbody>
        </table>
      </div>
    </section>

    <section class="mt-8 rounded-lg border border-zinc-800 bg-zinc-900">
      <div class="flex flex-col gap-2 border-b border-zinc-800 px-6 py-5 md:flex-row md:items-end md:justify-between">
        <div>
          <h2 class="text-xl font-semibold text-white">Global Activity Log</h2>
          <p id="audit-state" class="mt-1 text-sm text-zinc-400">Waiting for SMB activity</p>
        </div>
        <p id="audit-count" class="text-sm text-zinc-500">0 audit events</p>
      </div>
      <div id="audit-log" class="divide-y divide-zinc-800"></div>
    </section>

    <section class="mt-8 rounded-lg border border-zinc-800 bg-zinc-900">
      <div class="border-b border-zinc-800 px-6 py-5">
        <h2 class="text-xl font-semibold text-white">Recent Policy Events</h2>
      </div>
      <div id="threats" class="divide-y divide-zinc-800"></div>
    </section>

    <section class="mt-8 rounded-lg border border-zinc-800 bg-zinc-900">
      <div class="flex flex-col gap-4 border-b border-zinc-800 px-6 py-5 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 class="text-xl font-semibold text-white">Runtime Diagnostics</h2>
          <p id="diagnostics-state" class="mt-1 text-sm text-zinc-400">Diagnostics not loaded</p>
        </div>
        <button id="load-diagnostics" class="rounded-md border border-zinc-700 px-4 py-2 text-sm text-zinc-200 transition hover:border-emerald-300 hover:text-emerald-200">Load diagnostics</button>
      </div>
      <pre id="diagnostics-output" class="max-h-96 overflow-auto whitespace-pre-wrap px-6 py-5 text-xs leading-5 text-zinc-300"></pre>
    </section>
  </main>

  <script>
    const token = localStorage.getItem("axiomToken") || "";
    const modes = ["disabled", "monitor", "block"];

    function authHeaders(extra = {}) {
      return token ? { ...extra, Authorization: `Bearer ${token}` } : extra;
    }

    function formatBytes(value) {
      const units = ["B", "KB", "MB", "GB", "TB"];
      let size = Number(value || 0);
      let unit = 0;
      while (size >= 1024 && unit < units.length - 1) {
        size /= 1024;
        unit += 1;
      }
      return `${size.toFixed(unit === 0 ? 0 : 2)} ${units[unit]}`;
    }

    function text(value) {
      return value === null || value === undefined || value === "" ? "—" : String(value);
    }

    function formatTime(seconds) {
      if (!seconds) return "not available";
      return new Date(Number(seconds) * 1000).toLocaleString();
    }

    function renderPolicyRuntime(runtime) {
      if (!runtime) return;
      const blocking = runtime.blocking_rules || [];
      const monitoring = runtime.monitoring_rules || [];
      document.getElementById("runtime-policy-state").textContent = `Policy generation ${runtime.generation} is active`;
      document.getElementById("runtime-policy-detail").textContent =
        `${blocking.length} blocking rules · ${monitoring.length} monitor rules · applied ${formatTime(runtime.last_updated_unix_timestamp_seconds)}`;
    }

    async function refresh() {
      const response = await fetch("/api/status", {
        headers: authHeaders()
      });

      if (response.status === 401) {
        localStorage.removeItem("axiomToken");
        window.location.href = "/login";
        return;
      }

      const data = await response.json();
      const stats = data.stats;
      const forwardedBytes = Number(stats.bytes_client_to_server || 0) + Number(stats.bytes_server_to_client || 0);
      const streamBytes = Number(stats.stream_bytes_client_to_server || 0) + Number(stats.stream_bytes_server_to_client || 0);

      document.getElementById("forwarded-bytes").textContent = formatBytes(forwardedBytes);
      document.getElementById("stream-bytes").textContent = formatBytes(streamBytes);
      document.getElementById("smb-write-bytes").textContent = formatBytes(stats.smb_write_bytes || 0);
      document.getElementById("active-connections").textContent = stats.active_connections;
      document.getElementById("blocked-threats").textContent = stats.blocked_threats;
      document.getElementById("monitored-threats").textContent = stats.monitored_threats;
      document.getElementById("inspected-chunks").textContent = stats.inspected_chunks;
      document.getElementById("observed-files").textContent = stats.observed_file_events || 0;
      document.getElementById("server-side-copies").textContent = stats.server_side_copy_requests || 0;
      document.getElementById("management-info").textContent = `${data.management_interface} at ${data.management_bind_addr}`;
      document.getElementById("refresh-state").textContent = `PID ${data.process_id} · ${data.config_path} · updated ${new Date().toLocaleTimeString()}`;
      renderPolicyRuntime(stats.policy_runtime);

      const mappingBody = document.getElementById("mapping-body");
      const routeStats = new Map((stats.route_stats || []).map((route) => [route.route_name, route]));
      mappingBody.innerHTML = data.proxy_listeners.map((route) => `
        ${(() => {
          const runtime = routeStats.get(route.name) || {};
          const routeBytes = Number(runtime.bytes_client_to_server || 0) + Number(runtime.bytes_server_to_client || 0);
          const routeStreamBytes = Number(runtime.stream_bytes_client_to_server || 0) + Number(runtime.stream_bytes_server_to_client || 0);
          return `
        <tr class="hover:bg-zinc-800/40">
          <td class="whitespace-nowrap px-6 py-4 text-sm font-medium text-white">${text(route.name)}</td>
          <td class="whitespace-nowrap px-6 py-4 text-sm text-emerald-200">${text(route.source_interface)}</td>
          <td class="whitespace-nowrap px-6 py-4 text-sm text-zinc-300">${text(route.client_vlan)}</td>
          <td class="whitespace-nowrap px-6 py-4 text-sm text-zinc-300">${text(route.listen_addr)}</td>
          <td class="whitespace-nowrap px-6 py-4 text-sm text-cyan-200">${text(route.target_file_server_addr)}</td>
          <td class="whitespace-nowrap px-6 py-4 text-sm text-zinc-300">${text(runtime.active_connections || 0)} active / ${text(runtime.total_connections || 0)} total</td>
          <td class="whitespace-nowrap px-6 py-4 text-sm text-zinc-300">${text(runtime.inspected_chunks || 0)} chunks</td>
          <td class="whitespace-nowrap px-6 py-4 text-sm text-zinc-300">${formatBytes(routeBytes)} fwd / ${formatBytes(routeStreamBytes)} read</td>
        </tr>
          `;
        })()}
      `).join("");

      const auditLog = document.getElementById("audit-log");
      const auditEvents = stats.recent_audit_events || [];
      document.getElementById("audit-count").textContent = `${stats.audit_events || 0} audit events`;
      document.getElementById("audit-state").textContent = auditEvents.length
        ? `Latest event ${new Date(auditEvents[auditEvents.length - 1].unix_timestamp_seconds * 1000).toLocaleTimeString()}`
        : "Waiting for SMB activity";

      if (!auditEvents.length) {
        auditLog.innerHTML = `<div class="px-6 py-6 text-sm text-zinc-400">No SMB activity recorded.</div>`;
      } else {
        auditLog.innerHTML = auditEvents.slice().reverse().slice(0, 80).map((event) => {
          const severityClass = event.severity === "critical" ? "text-red-200" : event.severity === "warning" ? "text-amber-200" : "text-zinc-200";
          const badgeClass = event.kind === "policy_blocked" ? "border-red-400/40 bg-red-500/10 text-red-100" : event.kind === "policy_detection" ? "border-amber-400/40 bg-amber-500/10 text-amber-100" : "border-zinc-700 bg-zinc-950 text-zinc-300";
          return `
            <div class="px-6 py-4">
              <div class="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
                <div class="min-w-0">
                  <div class="flex flex-wrap items-center gap-2">
                    <span class="rounded-full border px-2.5 py-1 text-xs font-semibold uppercase ${badgeClass}">${text(event.kind).replaceAll("_", " ")}</span>
                    <span class="text-sm font-semibold ${severityClass}">${text(event.action).toUpperCase()}</span>
                    <span class="text-sm text-zinc-400">${text(event.peer_addr)} → ${text(event.target_addr)}</span>
                  </div>
                  <p class="mt-2 truncate text-sm text-white">${text(event.file_path)}</p>
                  <p class="mt-1 text-sm text-zinc-400">${text(event.reason)}${event.rule_name ? ` · ${text(event.rule_name)}` : ""}</p>
                </div>
                <p class="text-xs text-zinc-500">${new Date(event.unix_timestamp_seconds * 1000).toLocaleString()}</p>
              </div>
            </div>
          `;
        }).join("");
      }

      const threats = document.getElementById("threats");
      if (!stats.recent_threats.length) {
        threats.innerHTML = `<div class="px-6 py-6 text-sm text-zinc-400">No policy detections recorded.</div>`;
      } else {
        threats.innerHTML = stats.recent_threats.slice().reverse().map((event) => `
          <div class="px-6 py-4">
            <div class="flex flex-col gap-1 md:flex-row md:items-center md:justify-between">
              <p class="font-medium ${event.action === "block" ? "text-red-200" : "text-amber-200"}">${text(event.action).toUpperCase()} · ${text(event.reason)}</p>
              <p class="text-xs text-zinc-500">${new Date(event.unix_timestamp_seconds * 1000).toLocaleString()}</p>
            </div>
            <p class="mt-2 text-sm text-zinc-400">${text(event.rule_name)} · ${text(event.route_name)} · ${text(event.interface)} · ${text(event.direction)} · ${text(event.peer_addr)} · entropy ${Number(event.entropy || 0).toFixed(3)}</p>
          </div>
        `).join("");
      }
    }

    function fillModeSelect(id, value) {
      const element = document.getElementById(id);
      element.innerHTML = modes.map((mode) => `<option value="${mode}">${mode}</option>`).join("");
      element.value = value || "disabled";
    }

    async function loadPolicies() {
      const response = await fetch("/api/policies", { headers: authHeaders() });
      if (response.status === 401) {
        localStorage.removeItem("axiomToken");
        window.location.href = "/login";
        return;
      }

      const policy = await response.json();
      fillModeSelect("policy-smb-encrypted-payload", policy.smb.encrypted_payload);
      fillModeSelect("policy-rar", policy.archive.rar);
      fillModeSelect("policy-seven-zip", policy.archive.seven_zip);
      fillModeSelect("policy-zip", policy.archive.zip);
      fillModeSelect("policy-encrypted-zip", policy.archive.encrypted_zip);
      fillModeSelect("policy-entropy-mode", policy.entropy.mode);
      document.getElementById("policy-entropy-threshold").value = policy.entropy.threshold;
      document.getElementById("policy-entropy-minimum").value = policy.entropy.minimum_chunk_size;
      document.getElementById("policy-signatures").value = (policy.signatures || [])
        .map((signature) => `${signature.name}|${signature.mode}|${signature.pattern}`)
        .join("\n");
      document.getElementById("policy-state").textContent = "Policies loaded";
    }

    function readPolicyPayload() {
      const signatures = document.getElementById("policy-signatures").value
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => {
          const [name, mode, ...patternParts] = line.split("|");
          return {
            name: (name || "").trim(),
            mode: modes.includes((mode || "").trim()) ? mode.trim() : "monitor",
            pattern: patternParts.join("|")
          };
        })
        .filter((signature) => signature.name && signature.pattern);

      return {
        smb: {
          encrypted_payload: document.getElementById("policy-smb-encrypted-payload").value
        },
        archive: {
          rar: document.getElementById("policy-rar").value,
          seven_zip: document.getElementById("policy-seven-zip").value,
          zip: document.getElementById("policy-zip").value,
          encrypted_zip: document.getElementById("policy-encrypted-zip").value
        },
        entropy: {
          mode: document.getElementById("policy-entropy-mode").value,
          threshold: Number(document.getElementById("policy-entropy-threshold").value),
          minimum_chunk_size: Number(document.getElementById("policy-entropy-minimum").value)
        },
        signatures
      };
    }

    function setMode(id, mode) {
      document.getElementById(id).value = mode;
    }

    function applyPreset(name) {
      if (name === "monitor") {
        setMode("policy-smb-encrypted-payload", "monitor");
        setMode("policy-rar", "monitor");
        setMode("policy-seven-zip", "monitor");
        setMode("policy-zip", "monitor");
        setMode("policy-encrypted-zip", "monitor");
        setMode("policy-entropy-mode", "monitor");
        document.getElementById("policy-entropy-threshold").value = "7.9";
        document.getElementById("policy-entropy-minimum").value = "8192";
      }

      if (name === "balanced") {
        setMode("policy-smb-encrypted-payload", "monitor");
        setMode("policy-rar", "block");
        setMode("policy-seven-zip", "block");
        setMode("policy-zip", "block");
        setMode("policy-encrypted-zip", "block");
        setMode("policy-entropy-mode", "monitor");
        document.getElementById("policy-entropy-threshold").value = "7.9";
        document.getElementById("policy-entropy-minimum").value = "8192";
      }

      if (name === "strict") {
        setMode("policy-smb-encrypted-payload", "block");
        setMode("policy-rar", "block");
        setMode("policy-seven-zip", "block");
        setMode("policy-zip", "block");
        setMode("policy-encrypted-zip", "block");
        setMode("policy-entropy-mode", "block");
        document.getElementById("policy-entropy-threshold").value = "7.5";
        document.getElementById("policy-entropy-minimum").value = "2048";
      }

      document.getElementById("policy-state").textContent = `${name} preset selected; save to apply`;
    }

    async function savePolicies() {
      document.getElementById("policy-state").textContent = "Saving policies";
      const response = await fetch("/api/policies", {
        method: "PUT",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(readPolicyPayload())
      });

      const payload = await response.json().catch(() => ({ message: "save failed" }));
      if (!response.ok) {
        document.getElementById("policy-state").textContent = payload.message || "Policy save failed";
        return;
      }

      await loadPolicies();
      renderPolicyRuntime(payload.policy_runtime);
      document.getElementById("policy-state").textContent =
        `Saved and active on PID ${payload.process_id} · generation ${payload.policy_runtime.generation}`;
      await refresh();
    }

    async function runPolicySelfTest() {
      document.getElementById("self-test-state").textContent = "Running self-test";
      const response = await fetch("/api/policies/self-test", {
        method: "POST",
        headers: authHeaders()
      });
      const payload = await response.json().catch(() => ({ message: "self-test failed" }));

      if (!response.ok) {
        document.getElementById("self-test-state").textContent = payload.message || "Self-test failed";
        return;
      }

      renderPolicyRuntime(payload.policy_runtime);
      document.getElementById("self-test-results").innerHTML = (payload.results || []).map((result) => {
        const color = result.outcome === "block" ? "border-red-400/40 text-red-100" : result.outcome === "monitor" ? "border-amber-400/40 text-amber-100" : "border-zinc-700 text-zinc-200";
        return `
          <div class="rounded-md border ${color} bg-zinc-950/50 px-4 py-3">
            <p class="text-sm font-semibold">${text(result.name)}</p>
            <p class="mt-2 text-lg font-semibold uppercase">${text(result.outcome)}</p>
            <p class="mt-1 text-xs text-zinc-400">${text(result.rule_name)}</p>
          </div>
        `;
      }).join("");
      document.getElementById("self-test-state").textContent =
        `Self-test completed on PID ${payload.process_id}`;
    }

    async function loadDiagnostics() {
      document.getElementById("diagnostics-state").textContent = "Loading diagnostics";
      const response = await fetch("/api/diagnostics", { headers: authHeaders() });
      const payload = await response.json().catch(() => ({ message: "diagnostics failed" }));

      if (!response.ok) {
        document.getElementById("diagnostics-state").textContent = payload.message || "Diagnostics failed";
        return;
      }

      const important = {
        process_id: payload.process_id,
        executable_path: payload.executable_path,
        config_path: payload.config_path,
        proxy_listeners: payload.proxy_listeners,
        route_stats: payload.status.route_stats,
        commands: payload.command_outputs
      };

      document.getElementById("diagnostics-output").textContent = JSON.stringify(important, null, 2);
      document.getElementById("diagnostics-state").textContent = "Diagnostics loaded";
    }

    document.getElementById("logout").addEventListener("click", async () => {
      await fetch("/api/logout", { method: "POST" });
      localStorage.removeItem("axiomToken");
      window.location.href = "/login";
    });
    document.getElementById("save-policies").addEventListener("click", savePolicies);
    document.getElementById("run-policy-self-test").addEventListener("click", runPolicySelfTest);
    document.getElementById("load-diagnostics").addEventListener("click", loadDiagnostics);
    document.querySelectorAll(".policy-preset").forEach((button) => {
      button.addEventListener("click", () => applyPreset(button.dataset.preset));
    });

    refresh();
    loadPolicies();
    setInterval(refresh, 2000);
  </script>
</body>
</html>
"##;
