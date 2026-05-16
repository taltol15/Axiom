use std::sync::Arc;

use anyhow::Context;
use axiom_config::{AdminCredentials, ManagementConfig, ProxyListenerConfig};
use axiom_core::{RuntimeState, StatusSnapshot};
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

#[derive(Clone)]
struct WebState {
    runtime: Arc<RuntimeState>,
    management: ManagementConfig,
    proxy_listeners: Vec<ProxyListenerConfig>,
}

pub async fn run_management_server(
    management: ManagementConfig,
    proxy_listeners: Vec<ProxyListenerConfig>,
    runtime: Arc<RuntimeState>,
) -> anyhow::Result<()> {
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
        management: management.clone(),
        proxy_listeners,
    });

    let app = Router::new()
        .route("/", get(dashboard_page))
        .route("/dashboard", get(dashboard_page))
        .route("/login", get(login_page))
        .route("/api/status", get(api_status))
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

    let admin = &state.management.admin;
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
    StatusResponse {
        management_interface: state.management.interface.clone(),
        management_bind_addr: state.management.listen_addr().to_string(),
        configured_proxy_listeners: state.proxy_listeners.len(),
        proxy_listeners: state
            .proxy_listeners
            .iter()
            .map(ProxyListenerStatus::from)
            .collect(),
        stats: state.runtime.snapshot(),
    }
}

fn is_authorized(headers: &HeaderMap, state: &WebState) -> bool {
    let expected_token = session_token(&state.management.admin);

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

#[derive(Debug, Serialize)]
struct StatusResponse {
    management_interface: String,
    management_bind_addr: String,
    configured_proxy_listeners: usize,
    proxy_listeners: Vec<ProxyListenerStatus>,
    stats: StatusSnapshot,
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
struct ErrorResponse {
    message: &'static str,
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
    <section class="grid gap-5 md:grid-cols-4">
      <article class="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
        <p class="text-sm text-zinc-400">Total Bytes Transferred</p>
        <p id="total-bytes" class="mt-4 text-4xl font-semibold text-white">0 B</p>
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
        <p class="text-sm text-zinc-400">Inspected Chunks</p>
        <p id="inspected-chunks" class="mt-4 text-4xl font-semibold text-emerald-200">0</p>
      </article>
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
            </tr>
          </thead>
          <tbody id="mapping-body" class="divide-y divide-zinc-800"></tbody>
        </table>
      </div>
    </section>

    <section class="mt-8 rounded-lg border border-zinc-800 bg-zinc-900">
      <div class="border-b border-zinc-800 px-6 py-5">
        <h2 class="text-xl font-semibold text-white">Recent Threat Events</h2>
      </div>
      <div id="threats" class="divide-y divide-zinc-800"></div>
    </section>
  </main>

  <script>
    const token = localStorage.getItem("axiomToken") || "";

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

    async function refresh() {
      const response = await fetch("/api/status", {
        headers: token ? { Authorization: `Bearer ${token}` } : {}
      });

      if (response.status === 401) {
        localStorage.removeItem("axiomToken");
        window.location.href = "/login";
        return;
      }

      const data = await response.json();
      const stats = data.stats;
      const totalBytes = Number(stats.bytes_client_to_server || 0) + Number(stats.bytes_server_to_client || 0);

      document.getElementById("total-bytes").textContent = formatBytes(totalBytes);
      document.getElementById("active-connections").textContent = stats.active_connections;
      document.getElementById("blocked-threats").textContent = stats.blocked_threats;
      document.getElementById("inspected-chunks").textContent = stats.inspected_chunks;
      document.getElementById("management-info").textContent = `${data.management_interface} at ${data.management_bind_addr}`;
      document.getElementById("refresh-state").textContent = `Updated ${new Date().toLocaleTimeString()}`;

      const mappingBody = document.getElementById("mapping-body");
      mappingBody.innerHTML = data.proxy_listeners.map((route) => `
        <tr class="hover:bg-zinc-800/40">
          <td class="whitespace-nowrap px-6 py-4 text-sm font-medium text-white">${text(route.name)}</td>
          <td class="whitespace-nowrap px-6 py-4 text-sm text-emerald-200">${text(route.source_interface)}</td>
          <td class="whitespace-nowrap px-6 py-4 text-sm text-zinc-300">${text(route.client_vlan)}</td>
          <td class="whitespace-nowrap px-6 py-4 text-sm text-zinc-300">${text(route.listen_addr)}</td>
          <td class="whitespace-nowrap px-6 py-4 text-sm text-cyan-200">${text(route.target_file_server_addr)}</td>
        </tr>
      `).join("");

      const threats = document.getElementById("threats");
      if (!stats.recent_threats.length) {
        threats.innerHTML = `<div class="px-6 py-6 text-sm text-zinc-400">No blocked threats recorded.</div>`;
        return;
      }

      threats.innerHTML = stats.recent_threats.slice().reverse().map((event) => `
        <div class="px-6 py-4">
          <div class="flex flex-col gap-1 md:flex-row md:items-center md:justify-between">
            <p class="font-medium text-red-200">${text(event.reason)}</p>
            <p class="text-xs text-zinc-500">${new Date(event.unix_timestamp_seconds * 1000).toLocaleString()}</p>
          </div>
          <p class="mt-2 text-sm text-zinc-400">${text(event.route_name)} · ${text(event.interface)} · ${text(event.direction)} · entropy ${Number(event.entropy || 0).toFixed(3)}</p>
        </div>
      `).join("");
    }

    document.getElementById("logout").addEventListener("click", async () => {
      await fetch("/api/logout", { method: "POST" });
      localStorage.removeItem("axiomToken");
      window.location.href = "/login";
    });

    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>
"##;
