use std::{
    collections::{HashMap, HashSet},
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use axiom_config::{
    AdminCredentials, AxiomConfig, DirectoryConfig, DnsPolicyConfig, NodeRole, PolicyConfig,
    ProxyListenerConfig,
};
use axiom_control::{
    ControlApplyResponse, ControlPolicyBundle, EncryptedEnvelope, decrypt_payload, encrypt_payload,
};
use axiom_core::{
    DnsPolicyRuntimeSnapshot, InspectionContext, InspectionResult, PolicyRuntimeSnapshot,
    RuntimeState, StatusSnapshot, TrafficDirection,
};
use axiom_license::{LicenseStatus, LicenseUsage, evaluate_license, install_license_text};
use axiom_net::bind_tcp_listener_to_interface;
use axiom_reputation::{
    FileReputationReport, ReputationBulkImportRequest, ReputationBulkImportResponse,
    ReputationCreateRequest, ReputationEntry, ReputationError, ReputationLookupResponse,
    ReputationStore, ReputationUpdateRequest, ReputationVerdict,
};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path as AxumPath, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post, put},
};
use axum_server::tls_rustls::RustlsConfig;
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

const SESSION_COOKIE_NAME: &str = "axiom_session";
const SESSION_MAX_AGE_SECONDS: u64 = 8 * 60 * 60;
const DEFAULT_MANAGEMENT_TLS_CERT_PATH: &str = "/etc/axiom/tls/axiom.crt";
const DEFAULT_MANAGEMENT_TLS_KEY_PATH: &str = "/etc/axiom/tls/axiom.key";
const AXIOM_RESTART_HELPER_PATH: &str = "/usr/local/sbin/axiom-restart-service";

struct WebState {
    runtime: Arc<RuntimeState>,
    config_path: PathBuf,
    config: Mutex<AxiomConfig>,
    reputation: Arc<ReputationStore>,
    fleet_nodes: Mutex<HashMap<String, FleetNodeStatus>>,
    client_identities: Mutex<HashMap<String, ClientIdentityCacheEntry>>,
}

#[derive(Debug, Clone)]
struct ClientIdentityCacheEntry {
    hostname: String,
    expires_unix_timestamp_seconds: u64,
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

    let reputation = Arc::new(
        ReputationStore::open_default()
            .context("failed opening management reputation store under /var/lib/axiom")?,
    );
    let state = Arc::new(WebState {
        runtime,
        config_path,
        config: Mutex::new(config),
        reputation,
        fleet_nodes: Mutex::new(HashMap::new()),
        client_identities: Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/", get(dashboard_page))
        .route("/dashboard", get(dashboard_page))
        .route("/login", get(login_page))
        .route("/api/status", get(api_status))
        .route("/api/diagnostics", get(api_diagnostics))
        .route("/api/nodes/report", post(api_node_report))
        .route("/api/nodes/runtime-config", get(api_node_runtime_config))
        .route(
            "/api/management/tls",
            get(api_management_tls).put(api_update_management_tls),
        )
        .route("/api/license", get(api_license).put(api_install_license))
        .route(
            "/api/reputation",
            get(api_reputation).post(api_create_reputation),
        )
        .route("/api/reputation/import", post(api_import_reputation))
        .route("/api/reputation/files", post(api_report_file_reputation))
        .route(
            "/api/reputation/lookup/{sha256}",
            get(api_lookup_reputation),
        )
        .route(
            "/api/reputation/{id}",
            put(api_update_reputation).delete(api_delete_reputation),
        )
        .route("/api/enrollment-token", get(api_enrollment_token))
        .route(
            "/api/enrollment-token/rotate",
            post(api_rotate_enrollment_token),
        )
        .route("/api/policies", get(api_policies).put(api_update_policies))
        .route(
            "/api/dns-policy",
            get(api_dns_policy).put(api_update_dns_policy),
        )
        .route("/api/policies/self-test", post(api_policy_self_test))
        .route("/api/login", post(api_login))
        .route("/api/logout", post(api_logout))
        .layer(middleware::from_fn(add_security_headers))
        .with_state(state);

    if management.tls.enabled {
        match load_management_tls_config(&management.tls.cert_path, &management.tls.key_path).await
        {
            Ok(tls_config) => {
                info!(
                    interface = management.interface,
                    listen_addr = %management.listen_addr(),
                    tls_enabled = true,
                    cert_path = management.tls.cert_path,
                    key_path = management.tls.key_path,
                    "management GUI server started"
                );
                axum_server::from_tcp_rustls(listener.into_std()?, tls_config)
                    .serve(app.into_make_service())
                    .await?;
            }
            Err(error) => {
                warn!(
                    ?error,
                    cert_path = management.tls.cert_path,
                    key_path = management.tls.key_path,
                    "management TLS could not be loaded; falling back to HTTP"
                );
                info!(
                    interface = management.interface,
                    listen_addr = %management.listen_addr(),
                    tls_enabled = false,
                    tls_fallback = true,
                    "management GUI server started"
                );
                axum::serve(listener, app).await?;
            }
        }
    } else {
        info!(
            interface = management.interface,
            listen_addr = %management.listen_addr(),
            tls_enabled = false,
            "management GUI server started"
        );
        axum::serve(listener, app).await?;
    }
    Ok(())
}

async fn add_security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' https://cdn.tailwindcss.com 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'",
        ),
    );
    response
}

async fn login_page(headers: HeaderMap, State(state): State<Arc<WebState>>) -> Response {
    if is_authorized(&headers, &state) {
        return Redirect::temporary("/dashboard").into_response();
    }

    html_no_cache(LOGIN_HTML)
}

async fn dashboard_page(headers: HeaderMap, State(state): State<Arc<WebState>>) -> Response {
    if !is_authorized(&headers, &state) {
        return Redirect::temporary("/login").into_response();
    }

    html_no_cache(DASHBOARD_HTML)
}

fn html_no_cache(html: &'static str) -> Response {
    let mut response = Html(html).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::EXPIRES, HeaderValue::from_static("0"));
    response
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

async fn api_node_report(
    headers: HeaderMap,
    State(state): State<Arc<WebState>>,
    Json(report): Json<NodeReport>,
) -> Response {
    if !is_node_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                message: "node enrollment token required",
            }),
        )
            .into_response();
    }

    let node_id = report.node_id.trim().to_string();
    if node_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                message: "node_id is required",
            }),
        )
            .into_response();
    }

    let last_control_push = state
        .fleet_nodes
        .lock()
        .expect("fleet nodes mutex poisoned")
        .get(&node_id)
        .and_then(|node| node.last_control_push.clone());

    let status = FleetNodeStatus {
        node_id: node_id.clone(),
        display_name: report.display_name,
        role: report.role,
        hostname: report.hostname,
        version: report.version,
        last_seen_unix_timestamp_seconds: unix_timestamp_seconds(),
        management_url: report.management_url,
        control_url: report.control_url,
        proxy_listeners: report.proxy_listeners,
        dns: report.dns,
        stats: report.stats,
        last_control_push,
    };

    state
        .fleet_nodes
        .lock()
        .expect("fleet nodes mutex poisoned")
        .insert(node_id, status);

    Json(NodeAckResponse {
        accepted: true,
        message: "node report accepted",
    })
    .into_response()
}

async fn api_node_runtime_config(
    headers: HeaderMap,
    State(state): State<Arc<WebState>>,
) -> Response {
    if !is_node_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                message: "node enrollment token required",
            }),
        )
            .into_response();
    }

    Json(NodeRuntimeConfigResponse {
        policy_runtime: state.runtime.policy_runtime_snapshot(),
        dns_policy_runtime: state.runtime.dns_policy_runtime_snapshot(),
        known_bad_reputation_hashes: state.reputation.known_bad_sha256s(),
    })
    .into_response()
}

async fn api_reputation(headers: HeaderMap, State(state): State<Arc<WebState>>) -> Response {
    if !is_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiErrorResponse::new("authentication required")),
        )
            .into_response();
    }

    Json(state.reputation.list()).into_response()
}

async fn api_lookup_reputation(
    headers: HeaderMap,
    State(state): State<Arc<WebState>>,
    AxumPath(sha256): AxumPath<String>,
) -> Response {
    if !is_authorized(&headers, &state) && !is_node_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiErrorResponse::new("authentication required")),
        )
            .into_response();
    }

    match state.reputation.lookup(&sha256) {
        Ok(response) => Json(response).into_response(),
        Err(error) => reputation_error_response(error),
    }
}

async fn api_create_reputation(
    headers: HeaderMap,
    State(state): State<Arc<WebState>>,
    Json(request): Json<ReputationCreateRequest>,
) -> Response {
    if !is_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiErrorResponse::new("authentication required")),
        )
            .into_response();
    }

    let actor = admin_actor(&state);
    match state.reputation.create(request, &actor) {
        Ok(entry) => {
            let push_results = push_reputation_hashes_to_smb_nodes(state.as_ref()).await;
            warn_failed_node_pushes("reputation create", &push_results);
            Json(ReputationEntryMutationResponse {
                entry,
                node_push_results: push_results,
            })
            .into_response()
        }
        Err(error) => reputation_error_response(error),
    }
}

async fn api_update_reputation(
    headers: HeaderMap,
    State(state): State<Arc<WebState>>,
    AxumPath(id): AxumPath<u64>,
    Json(request): Json<ReputationUpdateRequest>,
) -> Response {
    if !is_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiErrorResponse::new("authentication required")),
        )
            .into_response();
    }

    let actor = admin_actor(&state);
    match state.reputation.update(id, request, &actor) {
        Ok(entry) => {
            let push_results = push_reputation_hashes_to_smb_nodes(state.as_ref()).await;
            warn_failed_node_pushes("reputation update", &push_results);
            Json(ReputationEntryMutationResponse {
                entry,
                node_push_results: push_results,
            })
            .into_response()
        }
        Err(error) => reputation_error_response(error),
    }
}

async fn api_delete_reputation(
    headers: HeaderMap,
    State(state): State<Arc<WebState>>,
    AxumPath(id): AxumPath<u64>,
) -> Response {
    if !is_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiErrorResponse::new("authentication required")),
        )
            .into_response();
    }

    let actor = admin_actor(&state);
    match state.reputation.delete(id, &actor) {
        Ok(entry) => {
            let push_results = push_reputation_hashes_to_smb_nodes(state.as_ref()).await;
            warn_failed_node_pushes("reputation delete", &push_results);
            Json(ReputationEntryMutationResponse {
                entry,
                node_push_results: push_results,
            })
            .into_response()
        }
        Err(error) => reputation_error_response(error),
    }
}

async fn api_import_reputation(
    headers: HeaderMap,
    State(state): State<Arc<WebState>>,
    Json(request): Json<ReputationBulkImportRequest>,
) -> Response {
    if !is_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiErrorResponse::new("authentication required")),
        )
            .into_response();
    }

    let actor = admin_actor(&state);
    let response = state.reputation.bulk_import(request, &actor);
    let push_results = push_reputation_hashes_to_smb_nodes(state.as_ref()).await;
    warn_failed_node_pushes("reputation import", &push_results);
    Json(ReputationImportWithPushResponse {
        response,
        node_push_results: push_results,
    })
    .into_response()
}

async fn api_report_file_reputation(
    headers: HeaderMap,
    State(state): State<Arc<WebState>>,
    Json(report): Json<FileReputationReport>,
) -> Response {
    if !is_node_authorized(&headers, &state) && !is_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiErrorResponse::new("node enrollment token required")),
        )
            .into_response();
    }

    let verdict = state.reputation.record_file_report(report);
    if verdict == ReputationVerdict::KnownBad {
        let push_results = push_reputation_hashes_to_smb_nodes(state.as_ref()).await;
        warn_failed_node_pushes("known bad file report", &push_results);
    }

    Json(ReputationLookupResponse {
        verdict,
        entry: None,
    })
    .into_response()
}

async fn api_management_tls(headers: HeaderMap, State(state): State<Arc<WebState>>) -> Response {
    if !is_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                message: "authentication required",
            }),
        )
            .into_response();
    }

    let config = state.config.lock().expect("web config mutex poisoned");
    Json(ManagementTlsResponse::from_config(
        &config,
        false,
        "TLS settings loaded".to_string(),
    ))
    .into_response()
}

async fn api_update_management_tls(
    headers: HeaderMap,
    State(state): State<Arc<WebState>>,
    Json(request): Json<ManagementTlsUpdateRequest>,
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

    let restart_requested = request.restart_service.unwrap_or(true);
    let current_config = {
        state
            .config
            .lock()
            .expect("web config mutex poisoned")
            .clone()
    };
    let cert_path = normalized_tls_path(
        request.cert_path,
        &current_config.management.tls.cert_path,
        DEFAULT_MANAGEMENT_TLS_CERT_PATH,
    );
    let key_path = normalized_tls_path(
        request.key_path,
        &current_config.management.tls.key_path,
        DEFAULT_MANAGEMENT_TLS_KEY_PATH,
    );

    if request.enabled {
        if !Path::new(&cert_path).is_file() {
            return (
                StatusCode::BAD_REQUEST,
                Json(ManagementTlsResponse::from_config(
                    &current_config,
                    false,
                    format!("certificate file was not found: {cert_path}"),
                )),
            )
                .into_response();
        }

        if !Path::new(&key_path).is_file() {
            return (
                StatusCode::BAD_REQUEST,
                Json(ManagementTlsResponse::from_config(
                    &current_config,
                    false,
                    format!("private key file was not found: {key_path}"),
                )),
            )
                .into_response();
        }

        if let Err(error) = load_management_tls_config(&cert_path, &key_path).await {
            warn!(
                ?error,
                cert_path,
                key_path,
                "management TLS update rejected because certificate or key could not be loaded"
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(ManagementTlsResponse::from_config(
                    &current_config,
                    false,
                    "TLS certificate/private key could not be loaded; check file format and permissions for the axiom service user".to_string(),
                )),
            )
                .into_response();
        }
    }

    let response = {
        let mut config = state.config.lock().expect("web config mutex poisoned");
        let mut candidate = config.clone();
        candidate.management.tls.enabled = request.enabled;
        candidate.management.tls.cert_path = cert_path;
        candidate.management.tls.key_path = key_path;

        if let Err(error) = candidate.validate() {
            warn!(?error, "invalid management TLS update rejected");
            return (
                StatusCode::BAD_REQUEST,
                Json(ManagementTlsResponse::from_config(
                    &candidate,
                    false,
                    "invalid TLS configuration".to_string(),
                )),
            )
                .into_response();
        }

        if let Err(error) = persist_config(&state.config_path, &candidate) {
            warn!(?error, "failed persisting management TLS update");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ManagementTlsResponse::from_config(
                    &config,
                    false,
                    "failed saving TLS configuration".to_string(),
                )),
            )
                .into_response();
        }

        let message = if restart_requested {
            "TLS settings saved; Axiom service restart was scheduled".to_string()
        } else {
            "TLS settings saved; restart Axiom to apply the listener change".to_string()
        };
        *config = candidate;
        ManagementTlsResponse::from_config(&config, false, message)
    };

    let mut response = response;
    if restart_requested {
        response.restart_scheduled = schedule_service_restart();
        if !response.restart_scheduled {
            response.message =
                "TLS settings saved, but the restart helper could not be started".to_string();
        }
    }

    Json(response).into_response()
}

async fn api_license(headers: HeaderMap, State(state): State<Arc<WebState>>) -> Response {
    if !is_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                message: "authentication required",
            }),
        )
            .into_response();
    }

    Json(build_license_status(&state)).into_response()
}

async fn api_install_license(
    headers: HeaderMap,
    State(state): State<Arc<WebState>>,
    Json(request): Json<LicenseInstallRequest>,
) -> Response {
    if !is_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiErrorResponse::new("authentication required")),
        )
            .into_response();
    }

    let config = state
        .config
        .lock()
        .expect("web config mutex poisoned")
        .clone();
    let client_identities = state
        .client_identities
        .lock()
        .expect("client identity mutex poisoned")
        .iter()
        .map(|(address, entry)| (address.clone(), entry.hostname.clone()))
        .collect();
    let usage = build_license_usage(
        &config,
        &fleet_node_snapshots(&state),
        &state.reputation,
        &client_identities,
    );

    match install_license_text(&config.license, &request.license_text, usage) {
        Ok(status) => Json(status).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorResponse::new(format!("license rejected: {error}"))),
        )
            .into_response(),
    }
}

async fn api_enrollment_token(headers: HeaderMap, State(state): State<Arc<WebState>>) -> Response {
    if !is_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                message: "authentication required",
            }),
        )
            .into_response();
    }

    let config = state.config.lock().expect("web config mutex poisoned");
    Json(EnrollmentTokenResponse {
        token: config.node.enrollment_token.clone(),
        token_preview: token_preview(config.node.enrollment_token.as_deref()),
        management_url: current_management_url(&config),
        reporting_nodes: state
            .fleet_nodes
            .lock()
            .expect("fleet nodes mutex poisoned")
            .len(),
    })
    .into_response()
}

async fn api_rotate_enrollment_token(
    headers: HeaderMap,
    State(state): State<Arc<WebState>>,
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

    let token = generate_enrollment_token();
    let persisted = {
        let mut config = state.config.lock().expect("web config mutex poisoned");
        config.node.enrollment_token = Some(token.clone());
        persist_config(&state.config_path, &config)
    };

    if let Err(error) = persisted {
        warn!(?error, "failed rotating enrollment token");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                message: "failed rotating enrollment token",
            }),
        )
            .into_response();
    }

    state
        .fleet_nodes
        .lock()
        .expect("fleet nodes mutex poisoned")
        .clear();

    Json(EnrollmentTokenResponse {
        token: Some(token.clone()),
        token_preview: token_preview(Some(&token)),
        management_url: {
            let config = state.config.lock().expect("web config mutex poisoned");
            current_management_url(&config)
        },
        reporting_nodes: 0,
    })
    .into_response()
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

    let runtime_policy = state.runtime.update_policy(policy.clone());
    let node_push_results = push_policy_bundle_to_nodes(
        state.as_ref(),
        Some(policy),
        None,
        Some(state.reputation.known_bad_sha256s()),
    )
    .await;

    Json(PolicyUpdateResponse {
        message: "policy updated and applied to the running engine",
        process_id: std::process::id(),
        config_path: state.config_path.display().to_string(),
        policy_runtime: runtime_policy,
        node_push_results,
    })
    .into_response()
}

async fn api_dns_policy(headers: HeaderMap, State(state): State<Arc<WebState>>) -> Response {
    if !is_authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                message: "authentication required",
            }),
        )
            .into_response();
    }

    Json(state.runtime.dns_policy_config()).into_response()
}

async fn api_update_dns_policy(
    headers: HeaderMap,
    State(state): State<Arc<WebState>>,
    Json(policy): Json<DnsPolicyConfig>,
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
        warn!(?error, "invalid DNS policy update rejected");
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                message: "invalid DNS policy configuration",
            }),
        )
            .into_response();
    }

    let persisted = {
        let mut config = state.config.lock().expect("web config mutex poisoned");
        config.dns.policy = policy.clone();
        persist_config(&state.config_path, &config)
    };

    if let Err(error) = persisted {
        warn!(?error, "failed persisting DNS policy update");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                message: "failed saving DNS policy configuration",
            }),
        )
            .into_response();
    }

    let dns_policy_runtime = state.runtime.update_dns_policy(policy.clone());
    let node_push_results =
        push_policy_bundle_to_nodes(state.as_ref(), None, Some(policy), None).await;

    Json(DnsPolicyUpdateResponse {
        message: "DNS policy updated and applied to the running resolver",
        process_id: std::process::id(),
        config_path: state.config_path.display().to_string(),
        dns_policy_runtime,
        node_push_results,
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
        file_path_hint: Some("policy-self-test.bin"),
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

    let admin = {
        let config = state.config.lock().expect("web config mutex poisoned");
        config.management.admin.clone()
    };
    let tls_enabled = {
        let config = state.config.lock().expect("web config mutex poisoned");
        config.management.tls.enabled
    };

    if provider == AuthProvider::Ldap {
        let directory = {
            let config = state.config.lock().expect("web config mutex poisoned");
            config.management.directory.clone()
        };

        if !directory.enabled {
            return (
                StatusCode::UNAUTHORIZED,
                Json(LoginResponse {
                    authenticated: false,
                    token: None,
                    message: "directory authentication is disabled",
                }),
            )
                .into_response();
        }

        match authenticate_directory_user(&directory, &request.username, &request.password).await {
            Ok(()) => {
                return authenticated_response(&admin, tls_enabled);
            }
            Err(error) => {
                warn!(
                    username = request.username,
                    ?error,
                    "directory login failed"
                );
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(LoginResponse {
                        authenticated: false,
                        token: None,
                        message: "invalid directory credentials",
                    }),
                )
                    .into_response();
            }
        }
    }

    let admin = &admin;
    if request.username == admin.username && verify_admin_password(admin, &request.password) {
        return authenticated_response(admin, tls_enabled);
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

fn authenticated_response(admin: &AdminCredentials, tls_enabled: bool) -> Response {
    let token = session_token(admin);
    let secure_flag = if tls_enabled { "; Secure" } else { "" };
    let cookie = format!(
        "{SESSION_COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_MAX_AGE_SECONDS}{secure_flag}"
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).unwrap_or_else(|_| {
            HeaderValue::from_static("axiom_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
        }),
    );

    (
        StatusCode::OK,
        headers,
        Json(LoginResponse {
            authenticated: true,
            token: Some(token),
            message: "authenticated",
        }),
    )
        .into_response()
}

async fn api_logout(State(state): State<Arc<WebState>>) -> Response {
    let tls_enabled = {
        let config = state.config.lock().expect("web config mutex poisoned");
        config.management.tls.enabled
    };
    let secure_flag = if tls_enabled { "; Secure" } else { "" };
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "axiom_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{secure_flag}"
        ))
        .unwrap_or_else(|_| {
            HeaderValue::from_static("axiom_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
        }),
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
    let stats = state.runtime.snapshot();
    let deployment_warnings = build_deployment_warnings(&config, &stats);
    let fleet_nodes = fleet_node_snapshots(state);
    let client_identities =
        resolve_client_identities(state, &config.management.directory, &stats, &fleet_nodes);
    let license =
        build_license_status_for(&config, &fleet_nodes, &state.reputation, &client_identities);
    StatusResponse {
        process_id: std::process::id(),
        config_path: state.config_path.display().to_string(),
        node: NodeInfo::from_config(&config),
        license,
        security: ManagementSecurityStatus::from_config(&config),
        management_interface: config.management.interface.clone(),
        management_bind_addr: config.management.listen_addr().to_string(),
        configured_proxy_listeners: config.proxy_listeners.len(),
        proxy_listeners: config
            .proxy_listeners
            .iter()
            .map(ProxyListenerStatus::from)
            .collect(),
        dns: DnsStatus::from(&config.dns),
        deployment_warnings,
        fleet_nodes,
        client_identities,
        stats,
    }
}

fn build_license_status(state: &WebState) -> LicenseStatus {
    let config = state.config.lock().expect("web config mutex poisoned");
    let fleet_nodes = fleet_node_snapshots(state);
    let client_identities = state
        .client_identities
        .lock()
        .expect("client identity mutex poisoned")
        .iter()
        .map(|(address, entry)| (address.clone(), entry.hostname.clone()))
        .collect();
    build_license_status_for(&config, &fleet_nodes, &state.reputation, &client_identities)
}

fn build_license_status_for(
    config: &AxiomConfig,
    fleet_nodes: &[FleetNodeStatus],
    reputation: &ReputationStore,
    client_identities: &HashMap<String, String>,
) -> LicenseStatus {
    evaluate_license(
        &config.license,
        build_license_usage(config, fleet_nodes, reputation, client_identities),
    )
}

fn build_license_usage(
    config: &AxiomConfig,
    fleet_nodes: &[FleetNodeStatus],
    reputation: &ReputationStore,
    client_identities: &HashMap<String, String>,
) -> LicenseUsage {
    let mut smb_nodes = u32::from(config.node.role.runs_smb_proxy());
    let mut dns_nodes = u32::from(config.node.role.runs_dns() && config.dns.enabled);

    for node in fleet_nodes {
        match node.role {
            NodeRole::SmbProxy => smb_nodes = smb_nodes.saturating_add(1),
            NodeRole::Dns => dns_nodes = dns_nodes.saturating_add(1),
            NodeRole::StandaloneLab => {
                smb_nodes = smb_nodes.saturating_add(1);
                dns_nodes = dns_nodes.saturating_add(1);
            }
            NodeRole::Management => {}
        }
    }

    LicenseUsage {
        management_nodes: u32::from(config.node.role.runs_management()),
        smb_nodes,
        dns_nodes,
        protected_clients: client_identities.len() as u32,
        reputation_entries: reputation.list().summary.total_entries as u32,
    }
}

fn build_diagnostics_response(state: &WebState) -> DiagnosticsResponse {
    let config = state.config.lock().expect("web config mutex poisoned");
    let status = state.runtime.snapshot();
    let deployment_warnings = build_deployment_warnings(&config, &status);
    let fleet_nodes = fleet_node_snapshots(state);
    let client_identities =
        resolve_client_identities(state, &config.management.directory, &status, &fleet_nodes);
    let license =
        build_license_status_for(&config, &fleet_nodes, &state.reputation, &client_identities);
    let mut command_outputs = vec![
        run_diagnostic_command("ss", &["-ltnp"]),
        run_diagnostic_command("ss", &["-lunp"]),
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
    ];

    for upstream in &config.dns.upstreams {
        let upstream_ip = upstream.ip().to_string();
        command_outputs.push(run_diagnostic_command(
            "ip",
            &["route", "get", upstream_ip.as_str()],
        ));
    }

    for listener in &config.proxy_listeners {
        let target_ip = listener.target_addr().ip().to_string();
        command_outputs.push(run_diagnostic_command(
            "ip",
            &["route", "get", target_ip.as_str()],
        ));
    }

    DiagnosticsResponse {
        process_id: std::process::id(),
        executable_path: std::env::current_exe()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|error| format!("unavailable: {error}")),
        config_path: state.config_path.display().to_string(),
        node: NodeInfo::from_config(&config),
        license,
        management_bind_addr: config.management.listen_addr().to_string(),
        proxy_listeners: config
            .proxy_listeners
            .iter()
            .map(ProxyListenerStatus::from)
            .collect(),
        dns: DnsStatus::from(&config.dns),
        deployment_warnings,
        fleet_nodes,
        status,
        command_outputs,
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

fn is_node_authorized(headers: &HeaderMap, state: &WebState) -> bool {
    let expected_token = {
        let config = state.config.lock().expect("web config mutex poisoned");
        config.node.enrollment_token.clone()
    };
    let Some(expected_token) = expected_token else {
        return false;
    };

    if expected_token.is_empty() {
        return false;
    }

    if let Some(header_value) = headers.get(header::AUTHORIZATION)
        && let Ok(value) = header_value.to_str()
        && let Some(token) = value.strip_prefix("Bearer ")
    {
        return constant_time_eq(token.as_bytes(), expected_token.as_bytes());
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

async fn authenticate_directory_user(
    directory: &DirectoryConfig,
    username: &str,
    password: &str,
) -> anyhow::Result<()> {
    if username.trim().is_empty() || password.is_empty() {
        return Err(anyhow::anyhow!("empty directory credentials"));
    }

    let (conn, mut ldap) = LdapConnAsync::new(&directory.url)
        .await
        .with_context(|| format!("failed connecting to directory {}", directory.url))?;
    ldap3::drive!(conn);

    let user_bind = directory
        .user_bind_format
        .replace("{username}", username.trim());
    ldap.simple_bind(&user_bind, password)
        .await
        .context("directory user bind failed")?
        .success()
        .context("directory rejected user bind")?;

    if let Some(required_group_dn) = directory
        .required_group_dn
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if let (Some(bind_dn), Some(bind_password)) = (
            directory
                .bind_dn
                .as_deref()
                .filter(|value| !value.is_empty()),
            directory
                .bind_password
                .as_deref()
                .filter(|value| !value.is_empty()),
        ) {
            ldap.simple_bind(bind_dn, bind_password)
                .await
                .context("directory service bind failed")?
                .success()
                .context("directory rejected service bind")?;
        }

        let filter = directory
            .user_filter
            .replace("{username}", &ldap_escape_filter_value(username.trim()));
        let (entries, _) = ldap
            .search(
                &directory.base_dn,
                Scope::Subtree,
                &filter,
                vec!["memberOf"],
            )
            .await
            .context("directory group search failed")?
            .success()
            .context("directory group search returned an error")?;

        let required_group = required_group_dn.to_ascii_lowercase();
        let is_member = entries.into_iter().any(|entry| {
            SearchEntry::construct(entry)
                .attrs
                .get("memberOf")
                .map(|groups| {
                    groups
                        .iter()
                        .any(|group| group.to_ascii_lowercase() == required_group)
                })
                .unwrap_or(false)
        });

        if !is_member {
            let _ = ldap.unbind().await;
            return Err(anyhow::anyhow!(
                "directory user is not in the required group"
            ));
        }
    }

    let _ = ldap.unbind().await;
    Ok(())
}

fn ldap_escape_filter_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'*' => escaped.push_str("\\2a"),
            b'(' => escaped.push_str("\\28"),
            b')' => escaped.push_str("\\29"),
            b'\\' => escaped.push_str("\\5c"),
            0 => escaped.push_str("\\00"),
            _ => escaped.push(byte as char),
        }
    }
    escaped
}

fn session_token(admin: &AdminCredentials) -> String {
    sha256_hex(format!("axiom-session:{}:{}", admin.username, admin.password_hash).as_bytes())
}

fn generate_enrollment_token() -> String {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).expect("operating system random source is unavailable");
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        token.push(hex_char(byte >> 4));
        token.push(hex_char(byte & 0x0f));
    }
    token
}

fn token_preview(token: Option<&str>) -> String {
    let Some(token) = token else {
        return "not configured".to_string();
    };
    if token.len() <= 12 {
        return token.to_string();
    }
    format!("{}...{}", &token[..6], &token[token.len() - 6..])
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

fn normalized_tls_path(requested: Option<String>, current: &str, fallback: &str) -> String {
    requested
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            let current = current.trim();
            (!current.is_empty()).then(|| current.to_string())
        })
        .unwrap_or_else(|| fallback.to_string())
}

async fn load_management_tls_config(
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<RustlsConfig> {
    RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .with_context(|| {
            format!("failed loading management TLS cert '{cert_path}' and key '{key_path}'")
        })
}

fn management_url(config: &AxiomConfig, https: bool) -> String {
    format!(
        "{}://{}",
        if https { "https" } else { "http" },
        config.management.listen_addr()
    )
}

fn current_management_url(config: &AxiomConfig) -> String {
    management_url(config, config.management.tls.enabled)
}

fn schedule_service_restart() -> bool {
    match thread::Builder::new()
        .name("axiom-service-restart".to_string())
        .spawn(|| {
            thread::sleep(Duration::from_millis(900));
            let sudo_path = if Path::new("/usr/bin/sudo").is_file() {
                "/usr/bin/sudo"
            } else {
                "sudo"
            };

            match Command::new(sudo_path)
                .arg("-n")
                .arg(AXIOM_RESTART_HELPER_PATH)
                .status()
            {
                Ok(status) if status.success() => {
                    info!("scheduled Axiom service restart through local helper");
                }
                Ok(status) => {
                    warn!(
                        ?status,
                        "Axiom service restart helper returned non-zero status"
                    );
                }
                Err(error) => {
                    warn!(?error, "failed launching Axiom service restart helper");
                }
            }
        }) {
        Ok(_) => true,
        Err(error) => {
            warn!(?error, "failed spawning Axiom service restart task");
            false
        }
    }
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

fn unix_timestamp_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos()
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

fn resolve_client_identities(
    state: &WebState,
    directory: &DirectoryConfig,
    stats: &StatusSnapshot,
    fleet_nodes: &[FleetNodeStatus],
) -> HashMap<String, String> {
    if !directory.client_reverse_dns {
        return HashMap::new();
    }

    let mut ips = HashSet::new();
    if let Ok(value) = serde_json::to_value(stats) {
        collect_client_ips_from_json(&value, &mut ips);
    }
    for node in fleet_nodes {
        collect_client_ips_from_json(&node.stats, &mut ips);
    }

    let now = unix_timestamp_seconds();
    let mut cache = state
        .client_identities
        .lock()
        .expect("client identity cache mutex poisoned");
    cache.retain(|_, entry| entry.expires_unix_timestamp_seconds > now);

    for ip in ips.iter().take(96) {
        if cache.contains_key(ip) {
            continue;
        }

        if let Some(hostname) = reverse_lookup_hostname(ip) {
            cache.insert(
                ip.clone(),
                ClientIdentityCacheEntry {
                    hostname,
                    expires_unix_timestamp_seconds: now + 3600,
                },
            );
        }
    }

    cache
        .iter()
        .map(|(ip, entry)| (ip.clone(), entry.hostname.clone()))
        .collect()
}

fn collect_client_ips_from_json(value: &serde_json::Value, ips: &mut HashSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for key in ["peer_addr", "client_addr"] {
                if let Some(raw) = map.get(key).and_then(serde_json::Value::as_str)
                    && let Some(ip) = ip_from_endpoint(raw)
                {
                    ips.insert(ip);
                }
            }
            for nested in map.values() {
                collect_client_ips_from_json(nested, ips);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_client_ips_from_json(item, ips);
            }
        }
        _ => {}
    }
}

fn ip_from_endpoint(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(ip.to_string());
    }

    let without_port = trimmed.rsplit_once(':').map_or(trimmed, |(ip, _)| ip);
    without_port.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

fn reverse_lookup_hostname(ip: &str) -> Option<String> {
    let output = Command::new("getent").args(["hosts", ip]).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .split_whitespace()
        .nth(1)
        .map(|value| value.trim_end_matches('.').to_string())
        .filter(|value| !value.is_empty())
}

fn build_deployment_warnings(config: &AxiomConfig, stats: &StatusSnapshot) -> DeploymentWarnings {
    DeploymentWarnings {
        smb: smb_deployment_warnings(config, stats),
        dns: dns_deployment_warnings(&config.dns),
    }
}

fn fleet_node_snapshots(state: &WebState) -> Vec<FleetNodeStatus> {
    let mut nodes: Vec<_> = state
        .fleet_nodes
        .lock()
        .expect("fleet nodes mutex poisoned")
        .values()
        .cloned()
        .collect();

    nodes.sort_by(|left, right| {
        right
            .last_seen_unix_timestamp_seconds
            .cmp(&left.last_seen_unix_timestamp_seconds)
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    nodes
}

async fn push_reputation_hashes_to_smb_nodes(state: &WebState) -> Vec<NodePushResult> {
    push_policy_bundle_to_nodes(
        state,
        None,
        None,
        Some(state.reputation.known_bad_sha256s()),
    )
    .await
}

fn warn_failed_node_pushes(context: &str, results: &[NodePushResult]) {
    for result in results.iter().filter(|result| !result.accepted) {
        warn!(
            context,
            node_id = result.node_id,
            role = result.role.as_str(),
            control_url = result.control_url,
            message = result.message,
            "failed pushing update to node"
        );
    }
}

async fn push_policy_bundle_to_nodes(
    state: &WebState,
    policy: Option<PolicyConfig>,
    dns_policy: Option<DnsPolicyConfig>,
    known_bad_reputation_hashes: Option<Vec<String>>,
) -> Vec<NodePushResult> {
    let target_nodes: Vec<_> = fleet_node_snapshots(state)
        .into_iter()
        .filter(|node| {
            (policy.is_some() && node.role == NodeRole::SmbProxy)
                || (dns_policy.is_some() && node.role == NodeRole::Dns)
                || (known_bad_reputation_hashes.is_some() && node.role == NodeRole::SmbProxy)
        })
        .collect();

    if target_nodes.is_empty() {
        return Vec::new();
    }

    let shared_secret = {
        let config = state.config.lock().expect("web config mutex poisoned");
        config.node.enrollment_token.clone()
    };
    let Some(shared_secret) = shared_secret.filter(|token| !token.trim().is_empty()) else {
        let results: Vec<_> = target_nodes
            .into_iter()
            .map(|node| {
                node_push_failure(
                    node.node_id,
                    node.role,
                    node.control_url,
                    None,
                    "management enrollment token is not configured",
                )
            })
            .collect();
        for result in &results {
            record_node_push_result(state, result);
        }
        return results;
    };

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(6))
        .user_agent("AxiomManagementControl/0.1")
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            let results: Vec<_> = target_nodes
                .into_iter()
                .map(|node| {
                    node_push_failure(
                        node.node_id,
                        node.role,
                        node.control_url,
                        None,
                        format!("failed building control client: {error}"),
                    )
                })
                .collect();
            for result in &results {
                record_node_push_result(state, result);
            }
            return results;
        }
    };

    let mut results = Vec::with_capacity(target_nodes.len());
    for node in target_nodes {
        let result = push_policy_bundle_to_node(
            &client,
            &shared_secret,
            node,
            policy.clone(),
            dns_policy.clone(),
            known_bad_reputation_hashes.clone(),
        )
        .await;
        record_node_push_result(state, &result);
        results.push(result);
    }

    results
}

fn node_push_failure(
    node_id: String,
    role: NodeRole,
    control_url: Option<String>,
    command_id: Option<String>,
    message: impl Into<String>,
) -> NodePushResult {
    NodePushResult {
        node_id,
        role,
        control_url,
        accepted: false,
        message: message.into(),
        command_id,
        pushed_unix_timestamp_seconds: unix_timestamp_seconds(),
        applied_unix_timestamp_seconds: None,
        policy_generation: None,
        dns_policy_generation: None,
        known_bad_reputation_hash_count: None,
    }
}

fn node_push_success(
    node_id: String,
    role: NodeRole,
    control_url: Option<String>,
    command_id: String,
    pushed_unix_timestamp_seconds: u64,
    response: ControlApplyResponse,
) -> NodePushResult {
    NodePushResult {
        node_id,
        role,
        control_url,
        accepted: response.accepted,
        message: response.message,
        command_id: Some(command_id),
        pushed_unix_timestamp_seconds,
        applied_unix_timestamp_seconds: Some(response.applied_unix_timestamp_seconds),
        policy_generation: Some(response.policy_generation),
        dns_policy_generation: Some(response.dns_policy_generation),
        known_bad_reputation_hash_count: Some(response.known_bad_reputation_hash_count),
    }
}

fn record_node_push_result(state: &WebState, result: &NodePushResult) {
    let mut fleet_nodes = state
        .fleet_nodes
        .lock()
        .expect("fleet nodes mutex poisoned");
    if let Some(node) = fleet_nodes.get_mut(&result.node_id) {
        node.last_control_push = Some(NodeControlPushStatus {
            command_id: result.command_id.clone(),
            accepted: result.accepted,
            message: result.message.clone(),
            pushed_unix_timestamp_seconds: result.pushed_unix_timestamp_seconds,
            applied_unix_timestamp_seconds: result.applied_unix_timestamp_seconds,
            policy_generation: result.policy_generation,
            dns_policy_generation: result.dns_policy_generation,
            known_bad_reputation_hash_count: result.known_bad_reputation_hash_count,
        });
    }
}

async fn push_policy_bundle_to_node(
    client: &reqwest::Client,
    shared_secret: &str,
    node: FleetNodeStatus,
    policy: Option<PolicyConfig>,
    dns_policy: Option<DnsPolicyConfig>,
    known_bad_reputation_hashes: Option<Vec<String>>,
) -> NodePushResult {
    let node_id = node.node_id.clone();
    let role = node.role;
    let control_url = node.control_url.clone();
    let Some(control_url_value) = control_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return node_push_failure(
            node_id,
            role,
            control_url,
            None,
            "node did not publish a control URL yet",
        );
    };

    let command_id = format!(
        "{}-{}-{}",
        unix_timestamp_nanos(),
        std::process::id(),
        node_id
    );
    let pushed_unix_timestamp_seconds = unix_timestamp_seconds();
    let command = ControlPolicyBundle {
        command_id: command_id.clone(),
        issued_unix_timestamp_seconds: pushed_unix_timestamp_seconds,
        policy,
        dns_policy,
        known_bad_reputation_hashes,
    };

    let envelope = match encrypt_payload(&node_id, shared_secret, &command) {
        Ok(envelope) => envelope,
        Err(error) => {
            return node_push_failure(
                node_id,
                role,
                control_url,
                Some(command_id),
                format!("failed encrypting policy bundle: {error}"),
            );
        }
    };

    let url = format!(
        "{}/api/control/policies",
        control_url_value.trim_end_matches('/')
    );
    let response = match client
        .post(url)
        .bearer_auth(shared_secret)
        .json(&envelope)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return node_push_failure(
                node_id,
                role,
                control_url,
                Some(command_id),
                format!("control push request failed: {error}"),
            );
        }
    };

    if !response.status().is_success() {
        return node_push_failure(
            node_id,
            role,
            control_url,
            Some(command_id),
            format!("node returned HTTP {}", response.status()),
        );
    }

    let response_envelope: EncryptedEnvelope = match response.json().await {
        Ok(envelope) => envelope,
        Err(error) => {
            return node_push_failure(
                node_id,
                role,
                control_url,
                Some(command_id),
                format!("failed decoding encrypted node response: {error}"),
            );
        }
    };

    if response_envelope.node_id != node_id {
        return node_push_failure(
            node_id,
            role,
            control_url,
            Some(command_id),
            "node response identity mismatch",
        );
    }

    match decrypt_payload::<ControlApplyResponse>(shared_secret, &response_envelope) {
        Ok(response) => node_push_success(
            node_id,
            role,
            control_url,
            command_id,
            pushed_unix_timestamp_seconds,
            response,
        ),
        Err(error) => node_push_failure(
            node_id,
            role,
            control_url,
            Some(command_id),
            format!("failed decrypting node response: {error}"),
        ),
    }
}

fn smb_deployment_warnings(config: &AxiomConfig, stats: &StatusSnapshot) -> Vec<String> {
    if config.proxy_listeners.is_empty() {
        return Vec::new();
    }

    let mut warnings = Vec::new();
    for listener in &config.proxy_listeners {
        let route_stats = stats
            .route_stats
            .iter()
            .find(|route| route.route_name == listener.name);

        match route_stats {
            Some(route) if !route.listener_ready => warnings.push(format!(
                "SMB route '{}' is configured but the listener is not ready.",
                listener.name
            )),
            Some(route) if route.total_connections == 0 => warnings.push(format!(
                "SMB route '{}' is listening on {}, but no client has reached the Axiom proxy yet.",
                listener.name,
                listener.listen_addr()
            )),
            Some(route)
                if route.stream_bytes_client_to_server + route.stream_bytes_server_to_client
                    < route.smb_write_bytes =>
            {
                warnings.push(format!(
                    "SMB route '{}' has inconsistent counters; reload diagnostics and verify the proxy path.",
                    listener.name
                ));
            }
            None => warnings.push(format!(
                "SMB route '{}' is configured but no runtime route telemetry exists yet.",
                listener.name
            )),
            _ => {}
        }
    }

    warnings.push(
        "For SMB enforcement, endpoints must not have direct TCP/445 access to the target file server; only Axiom should reach the backend SMB server."
            .to_string(),
    );
    warnings
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    process_id: u32,
    config_path: String,
    node: NodeInfo,
    license: LicenseStatus,
    security: ManagementSecurityStatus,
    management_interface: String,
    management_bind_addr: String,
    configured_proxy_listeners: usize,
    proxy_listeners: Vec<ProxyListenerStatus>,
    dns: DnsStatus,
    deployment_warnings: DeploymentWarnings,
    fleet_nodes: Vec<FleetNodeStatus>,
    client_identities: HashMap<String, String>,
    stats: StatusSnapshot,
}

#[derive(Debug, Serialize)]
struct DiagnosticsResponse {
    process_id: u32,
    executable_path: String,
    config_path: String,
    node: NodeInfo,
    license: LicenseStatus,
    management_bind_addr: String,
    proxy_listeners: Vec<ProxyListenerStatus>,
    dns: DnsStatus,
    deployment_warnings: DeploymentWarnings,
    fleet_nodes: Vec<FleetNodeStatus>,
    status: StatusSnapshot,
    command_outputs: Vec<CommandOutput>,
    proc_self_status: Option<String>,
}

#[derive(Debug, Serialize)]
struct NodeInfo {
    node_id: String,
    display_name: String,
    role: NodeRole,
    management_url: Option<String>,
    heartbeat_interval_seconds: u64,
}

#[derive(Debug, Serialize)]
struct ManagementSecurityStatus {
    https_enabled: bool,
    cert_path: String,
    key_path: String,
    http_url: String,
    https_url: String,
    restart_command: String,
    directory_enabled: bool,
    directory_url: Option<String>,
    client_reverse_dns: bool,
}

impl ManagementSecurityStatus {
    fn from_config(config: &AxiomConfig) -> Self {
        Self {
            https_enabled: config.management.tls.enabled,
            cert_path: tls_cert_path(config),
            key_path: tls_key_path(config),
            http_url: management_url(config, false),
            https_url: management_url(config, true),
            restart_command: "sudo systemctl restart axiom.service".to_string(),
            directory_enabled: config.management.directory.enabled,
            directory_url: config
                .management
                .directory
                .enabled
                .then(|| config.management.directory.url.clone()),
            client_reverse_dns: config.management.directory.client_reverse_dns,
        }
    }
}

fn tls_cert_path(config: &AxiomConfig) -> String {
    normalized_tls_path(
        None,
        &config.management.tls.cert_path,
        DEFAULT_MANAGEMENT_TLS_CERT_PATH,
    )
}

fn tls_key_path(config: &AxiomConfig) -> String {
    normalized_tls_path(
        None,
        &config.management.tls.key_path,
        DEFAULT_MANAGEMENT_TLS_KEY_PATH,
    )
}

impl NodeInfo {
    fn from_config(config: &AxiomConfig) -> Self {
        Self {
            node_id: config.node.node_id.clone(),
            display_name: config.node.display_name.clone(),
            role: config.node.role,
            management_url: config.node.management_url.clone(),
            heartbeat_interval_seconds: config.node.heartbeat_interval_seconds,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FleetNodeStatus {
    node_id: String,
    display_name: String,
    role: NodeRole,
    hostname: String,
    version: String,
    last_seen_unix_timestamp_seconds: u64,
    management_url: Option<String>,
    control_url: Option<String>,
    proxy_listeners: Vec<ProxyListenerStatus>,
    dns: DnsStatus,
    stats: serde_json::Value,
    last_control_push: Option<NodeControlPushStatus>,
}

#[derive(Debug, Deserialize)]
struct NodeReport {
    node_id: String,
    display_name: String,
    role: NodeRole,
    hostname: String,
    version: String,
    management_url: Option<String>,
    control_url: Option<String>,
    proxy_listeners: Vec<ProxyListenerStatus>,
    dns: DnsStatus,
    stats: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct NodeAckResponse {
    accepted: bool,
    message: &'static str,
}

#[derive(Debug, Serialize)]
struct NodeRuntimeConfigResponse {
    policy_runtime: PolicyRuntimeSnapshot,
    dns_policy_runtime: DnsPolicyRuntimeSnapshot,
    known_bad_reputation_hashes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ManagementTlsUpdateRequest {
    enabled: bool,
    cert_path: Option<String>,
    key_path: Option<String>,
    restart_service: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct LicenseInstallRequest {
    license_text: String,
}

#[derive(Debug, Serialize)]
struct ManagementTlsResponse {
    enabled: bool,
    cert_path: String,
    key_path: String,
    current_url: String,
    next_url: String,
    restart_scheduled: bool,
    restart_command: String,
    message: String,
}

impl ManagementTlsResponse {
    fn from_config(config: &AxiomConfig, restart_scheduled: bool, message: String) -> Self {
        Self {
            enabled: config.management.tls.enabled,
            cert_path: tls_cert_path(config),
            key_path: tls_key_path(config),
            current_url: current_management_url(config),
            next_url: current_management_url(config),
            restart_scheduled,
            restart_command: "sudo systemctl restart axiom.service".to_string(),
            message,
        }
    }
}

#[derive(Debug, Serialize)]
struct EnrollmentTokenResponse {
    token: Option<String>,
    token_preview: String,
    management_url: String,
    reporting_nodes: usize,
}

#[derive(Debug, Serialize)]
struct DeploymentWarnings {
    smb: Vec<String>,
    dns: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CommandOutput {
    command: String,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProxyListenerStatus {
    name: String,
    source_interface: String,
    client_vlan: Option<u16>,
    listen_addr: String,
    target_file_server_addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DnsStatus {
    enabled: bool,
    interface: String,
    listen_udp_addr: String,
    listen_tcp_addr: String,
    upstream_interface: String,
    upstreams: Vec<String>,
    threat_feed_urls: Vec<String>,
    blocked_domains: usize,
    monitored_domains: usize,
    local_records: usize,
    block_response: String,
    deployment_warnings: Vec<String>,
}

impl From<&axiom_config::DnsConfig> for DnsStatus {
    fn from(config: &axiom_config::DnsConfig) -> Self {
        Self {
            enabled: config.enabled,
            interface: config.interface.clone(),
            listen_udp_addr: config.udp_listen_addr().to_string(),
            listen_tcp_addr: config.tcp_listen_addr().to_string(),
            upstream_interface: config.upstream_interface().to_string(),
            upstreams: config.upstreams.iter().map(ToString::to_string).collect(),
            threat_feed_urls: config.policy.threat_feed_urls.clone(),
            blocked_domains: config.policy.blocked_domains.len(),
            monitored_domains: config.policy.monitored_domains.len(),
            local_records: config.policy.local_records.len(),
            block_response: format!("{:?}", config.policy.block_response).to_ascii_lowercase(),
            deployment_warnings: dns_deployment_warnings(config),
        }
    }
}

fn dns_deployment_warnings(config: &axiom_config::DnsConfig) -> Vec<String> {
    if !config.enabled {
        return Vec::new();
    }

    let mut warnings = Vec::new();
    if config
        .upstreams
        .iter()
        .any(|upstream| Some(upstream.ip()) == config.listen_ip)
    {
        warnings.push(
            "A DNS upstream is equal to the Axiom DNS listen IP; this creates a self-loop."
                .to_string(),
        );
    }

    if config.upstream_interface() == config.interface {
        warnings.push("DNS upstream egress uses the same NIC as the listener; verify that this NIC can route to the upstream resolvers.".to_string());
    }

    if !config.policy.threat_feed_urls.is_empty() {
        warnings.push(
            "DNS threat feeds are enabled and may block domains before local allowlisting exists."
                .to_string(),
        );
    }

    warnings.push("If the DC forwards DNS to Axiom, do not configure that same DC as an Axiom upstream resolver.".to_string());
    warnings
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
    node_push_results: Vec<NodePushResult>,
}

#[derive(Debug, Serialize)]
struct DnsPolicyUpdateResponse {
    message: &'static str,
    process_id: u32,
    config_path: String,
    dns_policy_runtime: DnsPolicyRuntimeSnapshot,
    node_push_results: Vec<NodePushResult>,
}

#[derive(Debug, Serialize)]
struct ReputationEntryMutationResponse {
    #[serde(flatten)]
    entry: ReputationEntry,
    node_push_results: Vec<NodePushResult>,
}

#[derive(Debug, Serialize)]
struct ReputationImportWithPushResponse {
    #[serde(flatten)]
    response: ReputationBulkImportResponse,
    node_push_results: Vec<NodePushResult>,
}

#[derive(Debug, Serialize)]
struct NodePushResult {
    node_id: String,
    role: NodeRole,
    control_url: Option<String>,
    accepted: bool,
    message: String,
    command_id: Option<String>,
    pushed_unix_timestamp_seconds: u64,
    applied_unix_timestamp_seconds: Option<u64>,
    policy_generation: Option<u64>,
    dns_policy_generation: Option<u64>,
    known_bad_reputation_hash_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodeControlPushStatus {
    command_id: Option<String>,
    accepted: bool,
    message: String,
    pushed_unix_timestamp_seconds: u64,
    applied_unix_timestamp_seconds: Option<u64>,
    policy_generation: Option<u64>,
    dns_policy_generation: Option<u64>,
    known_bad_reputation_hash_count: Option<usize>,
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

#[derive(Debug, Serialize)]
struct ApiErrorResponse {
    message: String,
}

impl ApiErrorResponse {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

fn admin_actor(state: &WebState) -> String {
    state
        .config
        .lock()
        .expect("web config mutex poisoned")
        .management
        .admin
        .username
        .clone()
}

fn reputation_error_response(error: ReputationError) -> Response {
    let status = match error {
        ReputationError::InvalidSha256 | ReputationError::InvalidMd5 => StatusCode::BAD_REQUEST,
        ReputationError::NotFound => StatusCode::NOT_FOUND,
        ReputationError::DuplicateSha256 => StatusCode::CONFLICT,
    };

    (status, Json(ApiErrorResponse::new(error.to_string()))).into_response()
}

fn utf16le_test_payload(value: &str) -> Vec<u8> {
    let mut payload = b"\x00\x00\x00\x90\xfeSMBself-test-padding".to_vec();
    payload.extend(value.encode_utf16().flat_map(|unit| unit.to_le_bytes()));
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_ldap_filter_values() {
        assert_eq!(
            ldap_escape_filter_value(r"tal*(ops)\admin"),
            r"tal\2a\28ops\29\5cadmin"
        );
    }

    #[test]
    fn extracts_ip_from_socket_endpoint() {
        assert_eq!(
            ip_from_endpoint("10.0.0.22:50444"),
            Some("10.0.0.22".to_string())
        );
    }

    #[test]
    fn token_preview_masks_long_tokens() {
        assert_eq!(
            token_preview(Some("abcdef1234567890")),
            "abcdef...567890".to_string()
        );
    }
}

const LOGIN_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Axiom Management Login</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: #09090b;
      color: #f8fafc;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: 0;
    }
    main { display: grid; min-height: 100vh; grid-template-columns: 1fr; }
    section { padding: 3rem 2rem; }
    section:first-child {
      align-items: center;
      background:
        radial-gradient(circle at 20% 20%, rgba(16, 185, 129, 0.28), transparent 30%),
        radial-gradient(circle at 80% 10%, rgba(14, 165, 233, 0.18), transparent 28%),
        linear-gradient(135deg, #09090b, #18181b 58%, #052e2b);
      display: flex;
      overflow: hidden;
      position: relative;
    }
    section:last-child { align-items: center; display: flex; justify-content: center; }
    h1 { color: #fff; font-size: clamp(3rem, 8vw, 5.5rem); line-height: 1; margin: 0; }
    h2 { color: #fff; font-size: 1.875rem; line-height: 2.25rem; margin: 0.75rem 0 0; }
    p { margin: 0; }
    form { display: grid; gap: 1.25rem; }
    label, span { display: block; }
    input, select {
      background: #09090b;
      border: 1px solid #3f3f46;
      border-radius: 6px;
      color: #fff;
      margin-top: 0.5rem;
      outline: none;
      padding: 0.75rem 1rem;
      width: 100%;
    }
    input:focus, select:focus {
      border-color: #34d399;
      box-shadow: 0 0 0 3px rgba(52, 211, 153, 0.18);
    }
    button {
      background: #34d399;
      border: 0;
      border-radius: 6px;
      color: #09090b;
      cursor: pointer;
      font-weight: 700;
      padding: 0.75rem 1rem;
      width: 100%;
    }
    button:hover { background: #6ee7b7; }
    .axiom-brand {
      align-items: center;
      display: inline-flex;
      gap: 0.75rem;
    }
    .axiom-brand svg {
      flex: 0 0 auto;
      height: 3rem;
      width: 3rem;
    }
    .axiom-wordmark {
      color: #fff;
      font-size: clamp(2.6rem, 7vw, 4.75rem);
      font-weight: 800;
      line-height: 1;
    }
    .axiom-wordmark span { color: #34f5c5; display: inline; }
    .max-w-3xl { max-width: 48rem; }
    .max-w-md { max-width: 28rem; }
    .w-full { width: 100%; }
    .rounded-lg { border-radius: 8px; }
    .border { border: 1px solid #27272a; }
    .bg-zinc-900\/80 { background: rgba(24, 24, 27, 0.82); }
    .p-8 { padding: 2rem; }
    .shadow-2xl { box-shadow: 0 24px 70px rgba(0, 0, 0, 0.34); }
    .mb-8 { margin-bottom: 2rem; }
    .mt-2 { margin-top: 0.5rem; }
    .mt-3 { margin-top: 0.75rem; }
    .mt-6 { margin-top: 1.5rem; }
    .mb-8 { margin-bottom: 2rem; }
    .text-sm { font-size: 0.875rem; line-height: 1.25rem; }
    .text-lg { font-size: 1.125rem; line-height: 1.75rem; }
    .text-zinc-300 { color: #d4d4d8; }
    .text-emerald-300 { color: #6ee7b7; }
    .hidden { display: none; }
    .uppercase { text-transform: uppercase; }
    [class*="tracking-"] { letter-spacing: 0 !important; }
    @media (min-width: 1024px) {
      main { grid-template-columns: 1.1fr 0.9fr; }
    }
  </style>
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
        <h1 class="axiom-brand" aria-label="Axiom">
          <svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Axiom logomark">
            <defs>
              <linearGradient id="axiom-login-grad" x1="6" y1="4" x2="42" y2="44" gradientUnits="userSpaceOnUse">
                <stop stop-color="#34F5C5" />
                <stop offset="0.5" stop-color="#2FE3FF" />
                <stop offset="1" stop-color="#5B8CFF" />
              </linearGradient>
              <linearGradient id="axiom-login-grad-soft" x1="6" y1="4" x2="42" y2="44" gradientUnits="userSpaceOnUse">
                <stop stop-color="#2FE3FF" stop-opacity="0.25" />
                <stop offset="1" stop-color="#5B8CFF" stop-opacity="0.05" />
              </linearGradient>
            </defs>
            <path d="M24 2.5 41.6 12.75v20.5L24 43.5 6.4 33.25v-20.5z" fill="url(#axiom-login-grad-soft)" stroke="url(#axiom-login-grad)" stroke-width="2" stroke-linejoin="round" />
            <path d="M16 33 24 14l8 19" stroke="url(#axiom-login-grad)" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" />
            <path d="M19.2 26.5h9.6" stroke="url(#axiom-login-grad)" stroke-width="2.6" stroke-linecap="round" />
            <circle cx="24" cy="13.4" r="2.5" fill="#05070d" stroke="url(#axiom-login-grad)" stroke-width="2" />
            <circle cx="15.6" cy="33.4" r="2.2" fill="#05070d" stroke="url(#axiom-login-grad)" stroke-width="2" />
            <circle cx="32.4" cy="33.4" r="2.2" fill="#05070d" stroke="url(#axiom-login-grad)" stroke-width="2" />
          </svg>
          <span class="axiom-wordmark">AXIOM<span>.</span></span>
        </h1>
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

          <label class="block">
            <span class="text-sm text-zinc-300">Provider</span>
            <select id="provider" name="provider" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-4 py-3 text-white outline-none transition focus:border-emerald-400 focus:ring-2 focus:ring-emerald-400/20">
              <option value="local">Local Admin</option>
              <option value="ldap">Active Directory</option>
            </select>
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
          provider: document.getElementById("provider").value
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
  <style>
    :root {
      --page: #eef5f8;
      --page-soft: #f8fafc;
      --surface: rgba(255, 255, 255, 0.94);
      --surface-strong: #ffffff;
      --surface-subtle: #f1f5f9;
      --border: #d7e1ea;
      --border-strong: #b8c7d5;
      --text: #0f172a;
      --muted: #64748b;
      --faint: #94a3b8;
      --nav: #0f172a;
      --nav-soft: #111827;
      --accent: #34d399;
      --accent-strong: #10b981;
      --danger: #ef4444;
      --warning: #d97706;
      --info: #0284c7;
      --shadow: 0 14px 36px rgba(15, 23, 42, 0.08);
      --shadow-soft: 0 8px 22px rgba(15, 23, 42, 0.06);
    }

    html[data-theme="dark"] {
      --page: #07111f;
      --page-soft: #0b1220;
      --surface: rgba(15, 23, 42, 0.94);
      --surface-strong: #111827;
      --surface-subtle: #0b1220;
      --border: #263244;
      --border-strong: #334155;
      --text: #f8fafc;
      --muted: #a8b3c5;
      --faint: #7b8798;
      --nav: #050b16;
      --nav-soft: #0b1220;
      --shadow: 0 18px 42px rgba(0, 0, 0, 0.22);
      --shadow-soft: 0 10px 28px rgba(0, 0, 0, 0.18);
    }

    * { box-sizing: border-box; }

    .min-h-screen { min-height: 100vh; }
    .mx-auto { margin-left: auto; margin-right: auto; }
    .max-w-7xl { max-width: 80rem; }
    .max-w-full { max-width: 100%; }
    .w-full { width: 100%; }
    .w-80 { width: 20rem; }
    .w-fit { width: fit-content; }
    .min-w-full { min-width: 100%; }
    .min-w-0 { min-width: 0; }
    .max-h-96 { max-height: 24rem; }
    .flex { display: flex; }
    .grid { display: grid; }
    .block { display: block; }
    .hidden { display: none; }
    .inline-flex { display: inline-flex; }
    .flex-col { flex-direction: column; }
    .flex-wrap { flex-wrap: wrap; }
    .items-center { align-items: center; }
    .items-start { align-items: flex-start; }
    .items-end { align-items: flex-end; }
    .justify-between { justify-content: space-between; }
    .gap-1 { gap: 0.25rem; }
    .gap-2 { gap: 0.5rem; }
    .gap-3 { gap: 0.75rem; }
    .gap-4 { gap: 1rem; }
    .gap-5 { gap: 1.25rem; }
    .gap-6 { gap: 1.5rem; }
    .shrink-0 { flex-shrink: 0; }
    .grid-cols-1 { grid-template-columns: repeat(1, minmax(0, 1fr)); }
    .overflow-x-auto { overflow-x: auto; }
    .overflow-auto { overflow: auto; }
    .overflow-hidden { overflow: hidden; }
    .truncate { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .whitespace-nowrap { white-space: nowrap; }
    .whitespace-pre-wrap { white-space: pre-wrap; }
    .rounded-full { border-radius: 9999px; }
    .border { border-width: 1px; border-style: solid; }
    .border-b { border-bottom-width: 1px; border-bottom-style: solid; }
    .border-t { border-top-width: 1px; border-top-style: solid; }
    .divide-y > :not([hidden]) ~ :not([hidden]) { border-top-width: 1px; border-top-style: solid; }
    .p-4 { padding: 1rem; }
    .p-6 { padding: 1.5rem; }
    .px-2\.5 { padding-left: 0.625rem; padding-right: 0.625rem; }
    .px-3 { padding-left: 0.75rem; padding-right: 0.75rem; }
    .px-4 { padding-left: 1rem; padding-right: 1rem; }
    .px-6 { padding-left: 1.5rem; padding-right: 1.5rem; }
    .py-1 { padding-top: 0.25rem; padding-bottom: 0.25rem; }
    .py-2 { padding-top: 0.5rem; padding-bottom: 0.5rem; }
    .py-3 { padding-top: 0.75rem; padding-bottom: 0.75rem; }
    .py-4 { padding-top: 1rem; padding-bottom: 1rem; }
    .py-5 { padding-top: 1.25rem; padding-bottom: 1.25rem; }
    .py-6 { padding-top: 1.5rem; padding-bottom: 1.5rem; }
    .py-8 { padding-top: 2rem; padding-bottom: 2rem; }
    .mt-1 { margin-top: 0.25rem; }
    .mt-2 { margin-top: 0.5rem; }
    .mt-3 { margin-top: 0.75rem; }
    .mt-4 { margin-top: 1rem; }
    .mt-8 { margin-top: 2rem; }
    .uppercase { text-transform: uppercase; }
    .font-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    .font-medium { font-weight: 500; }
    .font-semibold { font-weight: 650; }
    .cursor-pointer { cursor: pointer; }
    .text-left { text-align: left; }
    .text-right { text-align: right; }
    .text-xs { font-size: 0.75rem; line-height: 1rem; }
    .text-sm { font-size: 0.875rem; line-height: 1.25rem; }
    .text-lg { font-size: 1.125rem; line-height: 1.75rem; }
    .text-xl { font-size: 1.25rem; line-height: 1.75rem; }
    [class*="tracking-"] { letter-spacing: 0 !important; }

    @media (min-width: 640px) {
      .sm\:grid-cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .sm\:grid-cols-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    }

    @media (min-width: 768px) {
      .md\:grid-cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .md\:grid-cols-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      .md\:grid-cols-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }
      .md\:flex-row { flex-direction: row; }
      .md\:items-center { align-items: center; }
      .md\:items-end { align-items: flex-end; }
      .md\:justify-between { justify-content: space-between; }
    }

    @media (min-width: 1024px) {
      .lg\:grid-cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .lg\:grid-cols-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      .lg\:grid-cols-\[1fr_1fr\] { grid-template-columns: 1fr 1fr; }
      .lg\:col-span-2 { grid-column: span 2 / span 2; }
      .lg\:col-span-3 { grid-column: span 3 / span 3; }
      .lg\:flex-row { flex-direction: row; }
      .lg\:items-center { align-items: center; }
      .lg\:justify-between { justify-content: space-between; }
      .lg\:text-right { text-align: right; }
    }

    @media (min-width: 1280px) {
      .xl\:grid-cols-5 { grid-template-columns: repeat(5, minmax(0, 1fr)); }
    }

    body {
      background:
        linear-gradient(180deg, var(--page) 0%, var(--page-soft) 46%, var(--page) 100%);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: 0;
      margin: 0;
    }

    header {
      background: linear-gradient(90deg, var(--nav) 0%, var(--nav-soft) 100%) !important;
      border-color: rgba(148, 163, 184, 0.18) !important;
      box-shadow: 0 18px 46px rgba(15, 23, 42, 0.18);
      position: sticky;
      top: 0;
      z-index: 30;
    }

    header h1,
    header button,
    header .text-zinc-200 {
      color: #f8fafc !important;
    }

    main > .dashboard-view > section,
    main article {
      background: var(--surface) !important;
      border-color: var(--border) !important;
      box-shadow: var(--shadow);
    }

    main article {
      min-height: 142px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      overflow: hidden;
      position: relative;
    }

    main article::before {
      background: linear-gradient(90deg, var(--accent), transparent);
      content: "";
      height: 3px;
      inset: 0 0 auto 0;
      opacity: 0.75;
      position: absolute;
    }

    main .text-white,
    main .text-zinc-100,
    main .text-zinc-200,
    main .text-zinc-300 {
      color: var(--text) !important;
    }

    main .text-zinc-400,
    main .text-zinc-500 {
      color: var(--muted) !important;
    }

    html:not([data-theme="dark"]) main .text-emerald-100,
    html:not([data-theme="dark"]) main .text-emerald-200,
    html:not([data-theme="dark"]) main .text-emerald-300,
    html:not([data-theme="dark"]) main .text-emerald-700 {
      color: #047857 !important;
    }

    html:not([data-theme="dark"]) main .text-red-100,
    html:not([data-theme="dark"]) main .text-red-200,
    html:not([data-theme="dark"]) main .text-red-300,
    html:not([data-theme="dark"]) main .text-red-700 {
      color: #b91c1c !important;
    }

    html:not([data-theme="dark"]) main .text-amber-100,
    html:not([data-theme="dark"]) main .text-amber-200,
    html:not([data-theme="dark"]) main .text-amber-500,
    html:not([data-theme="dark"]) main .text-amber-700 {
      color: #b45309 !important;
    }

    html:not([data-theme="dark"]) main .text-sky-200,
    html:not([data-theme="dark"]) main .text-cyan-200,
    html:not([data-theme="dark"]) main .text-cyan-300 {
      color: #0369a1 !important;
    }

    main .bg-zinc-950,
    main .bg-zinc-950\/50,
    main .bg-zinc-950\/60,
    main .bg-zinc-900,
    main .hover\:bg-zinc-800\/40:hover {
      background-color: var(--surface-strong) !important;
    }

    main .border-zinc-700,
    main .border-zinc-800,
    main .divide-zinc-800 > :not([hidden]) ~ :not([hidden]) {
      border-color: var(--border) !important;
    }

    select,
    input {
      background: var(--surface-strong) !important;
      color: var(--text) !important;
      border-color: var(--border-strong) !important;
    }

    textarea,
    pre {
      background: #0b1220 !important;
      color: #dbeafe !important;
      border-color: #263247 !important;
    }

    table {
      border-collapse: separate;
      border-spacing: 0;
      font-size: 0.9rem;
    }

    table thead {
      background: var(--surface-subtle) !important;
    }

    table th {
      color: var(--muted) !important;
      white-space: nowrap;
    }

    table td {
      color: var(--text);
      vertical-align: top;
    }

    tbody tr {
      transition: background-color 140ms ease;
    }

    tbody tr:hover {
      background: rgba(52, 211, 153, 0.08) !important;
    }

    .policy-preset {
      background: var(--surface-strong) !important;
    }

    .dashboard-view {
      display: none;
    }

    .dashboard-view.active {
      display: block;
      animation: axiom-fade 160ms ease-out;
    }

    @keyframes axiom-fade {
      from { opacity: 0; transform: translateY(4px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .top-nav-button {
      background: rgba(15, 23, 42, 0.32);
      border-color: rgba(148, 163, 184, 0.28) !important;
      color: #e2e8f0 !important;
      min-height: 42px;
    }

    .top-nav-button.active {
      background: var(--accent);
      border-color: var(--accent);
      color: #0f172a !important;
      box-shadow: 0 10px 24px rgba(52, 211, 153, 0.22);
    }

    .top-nav-button:hover {
      background: rgba(52, 211, 153, 0.12);
      border-color: rgba(52, 211, 153, 0.65) !important;
      color: #ecfdf5 !important;
    }

    .axiom-brand {
      align-items: center;
      color: #fff;
      display: inline-flex;
      gap: 0.75rem;
      min-width: 0;
    }

    .axiom-brand svg {
      flex: 0 0 auto;
      height: 2.4rem;
      width: 2.4rem;
    }

    .axiom-wordmark {
      color: #fff;
      font-size: 1.55rem;
      font-weight: 800;
      line-height: 1;
    }

    .axiom-wordmark span {
      color: var(--accent);
      display: inline;
    }

    .axiom-console-label {
      color: #94a3b8;
      font-size: 0.875rem;
      margin-top: 0.35rem;
    }

    .toast-stack {
      bottom: 1.25rem;
      display: grid;
      gap: 0.75rem;
      max-width: min(28rem, calc(100vw - 2rem));
      position: fixed;
      right: 1.25rem;
      z-index: 80;
    }

    .toast {
      background: rgba(15, 23, 42, 0.96);
      border: 1px solid rgba(148, 163, 184, 0.24);
      border-radius: 8px;
      box-shadow: 0 22px 56px rgba(2, 6, 23, 0.34);
      color: #e2e8f0;
      opacity: 0;
      padding: 0.9rem 1rem;
      transform: translateY(0.65rem);
      transition: opacity 160ms ease, transform 160ms ease;
    }

    .toast.show {
      opacity: 1;
      transform: translateY(0);
    }

    .toast.success { border-color: rgba(52, 211, 153, 0.5); }
    .toast.warning { border-color: rgba(251, 191, 36, 0.55); }
    .toast.error { border-color: rgba(248, 113, 113, 0.58); }

    .push-progress {
      background: rgba(15, 23, 42, 0.97);
      border: 1px solid rgba(52, 211, 153, 0.34);
      border-radius: 8px;
      box-shadow: 0 24px 70px rgba(2, 6, 23, 0.42);
      color: #e2e8f0;
      left: 50%;
      max-width: min(40rem, calc(100vw - 2rem));
      padding: 1rem;
      position: fixed;
      top: 1rem;
      transform: translateX(-50%);
      width: 40rem;
      z-index: 70;
    }

    .push-progress-bar {
      background: rgba(51, 65, 85, 0.8);
      border-radius: 999px;
      height: 0.45rem;
      margin-top: 0.85rem;
      overflow: hidden;
    }

    .push-progress-fill {
      background: linear-gradient(90deg, #34f5c5, #2fe3ff);
      height: 100%;
      transition: width 220ms ease;
      width: 8%;
    }

    .button-busy {
      cursor: wait !important;
      opacity: 0.75;
      pointer-events: none;
    }

    .button-busy::after {
      animation: axiom-spin 700ms linear infinite;
      border: 2px solid rgba(15, 23, 42, 0.25);
      border-top-color: rgba(15, 23, 42, 0.9);
      border-radius: 999px;
      content: "";
      display: inline-block;
      height: 0.85rem;
      margin-left: 0.55rem;
      vertical-align: -0.12rem;
      width: 0.85rem;
    }

    @keyframes axiom-spin {
      to { transform: rotate(360deg); }
    }

    .rounded-lg {
      border-radius: 8px !important;
    }

    .rounded-md {
      border-radius: 6px !important;
    }

    .text-4xl {
      font-size: clamp(2rem, 3vw, 2.6rem) !important;
      line-height: 1.08 !important;
    }

    .text-3xl {
      font-size: clamp(1.65rem, 2.5vw, 2.1rem) !important;
      line-height: 1.12 !important;
    }

    footer {
      background: var(--nav) !important;
      border-color: rgba(148, 163, 184, 0.18) !important;
    }

    @media (max-width: 768px) {
      header {
        position: static;
      }

      nav[aria-label="Dashboard sections"] {
        overflow-x: auto;
        flex-wrap: nowrap;
        padding-bottom: 1rem;
      }

      .top-nav-button {
        flex: 0 0 auto;
      }
    }
  </style>
</head>
<body class="min-h-screen bg-zinc-950 text-zinc-100">
  <header class="border-b border-zinc-800 bg-zinc-950/95">
    <div class="mx-auto flex max-w-7xl items-center justify-between gap-6 px-6 py-5">
      <div>
        <div class="axiom-brand" aria-label="Axiom">
          <svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Axiom logomark">
            <defs>
              <linearGradient id="axiom-dashboard-grad" x1="6" y1="4" x2="42" y2="44" gradientUnits="userSpaceOnUse">
                <stop stop-color="#34F5C5" />
                <stop offset="0.5" stop-color="#2FE3FF" />
                <stop offset="1" stop-color="#5B8CFF" />
              </linearGradient>
              <linearGradient id="axiom-dashboard-grad-soft" x1="6" y1="4" x2="42" y2="44" gradientUnits="userSpaceOnUse">
                <stop stop-color="#2FE3FF" stop-opacity="0.25" />
                <stop offset="1" stop-color="#5B8CFF" stop-opacity="0.05" />
              </linearGradient>
            </defs>
            <path d="M24 2.5 41.6 12.75v20.5L24 43.5 6.4 33.25v-20.5z" fill="url(#axiom-dashboard-grad-soft)" stroke="url(#axiom-dashboard-grad)" stroke-width="2" stroke-linejoin="round" />
            <path d="M16 33 24 14l8 19" stroke="url(#axiom-dashboard-grad)" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" />
            <path d="M19.2 26.5h9.6" stroke="url(#axiom-dashboard-grad)" stroke-width="2.6" stroke-linecap="round" />
            <circle cx="24" cy="13.4" r="2.5" fill="#05070d" stroke="url(#axiom-dashboard-grad)" stroke-width="2" />
            <circle cx="15.6" cy="33.4" r="2.2" fill="#05070d" stroke="url(#axiom-dashboard-grad)" stroke-width="2" />
            <circle cx="32.4" cy="33.4" r="2.2" fill="#05070d" stroke="url(#axiom-dashboard-grad)" stroke-width="2" />
          </svg>
          <span class="axiom-wordmark">AXIOM<span>.</span></span>
        </div>
        <p class="axiom-console-label">Management Console</p>
      </div>
      <button id="logout" class="rounded-md border border-zinc-700 px-4 py-2 text-sm text-zinc-200 transition hover:border-red-400 hover:text-red-200">Log out</button>
    </div>
    <div class="border-t border-zinc-800 bg-zinc-900/70">
      <nav class="mx-auto flex max-w-7xl flex-wrap gap-2 px-6 py-3" aria-label="Dashboard sections">
        <button data-view="overview" class="top-nav-button active rounded-md border border-zinc-700 px-4 py-2 text-sm font-medium text-zinc-200 transition hover:border-emerald-300 hover:text-emerald-100">Overview</button>
        <button data-view="nodes" class="top-nav-button rounded-md border border-zinc-700 px-4 py-2 text-sm font-medium text-zinc-200 transition hover:border-emerald-300 hover:text-emerald-100">Nodes</button>
        <button data-view="smb" class="top-nav-button rounded-md border border-zinc-700 px-4 py-2 text-sm font-medium text-zinc-200 transition hover:border-emerald-300 hover:text-emerald-100">SMB Protection</button>
        <button data-view="dns" class="top-nav-button rounded-md border border-zinc-700 px-4 py-2 text-sm font-medium text-zinc-200 transition hover:border-emerald-300 hover:text-emerald-100">DNS Security</button>
        <button data-view="security" class="top-nav-button rounded-md border border-zinc-700 px-4 py-2 text-sm font-medium text-zinc-200 transition hover:border-emerald-300 hover:text-emerald-100">Security</button>
        <button data-view="audit" class="top-nav-button rounded-md border border-zinc-700 px-4 py-2 text-sm font-medium text-zinc-200 transition hover:border-emerald-300 hover:text-emerald-100">Global Audit Log</button>
        <button data-view="support" class="top-nav-button rounded-md border border-zinc-700 px-4 py-2 text-sm font-medium text-zinc-200 transition hover:border-emerald-300 hover:text-emerald-100">Support</button>
        <button data-view="settings" class="top-nav-button rounded-md border border-zinc-700 px-4 py-2 text-sm font-medium text-zinc-200 transition hover:border-emerald-300 hover:text-emerald-100">Settings</button>
      </nav>
    </div>
  </header>

  <main class="mx-auto max-w-7xl px-6 py-8">
    <section id="view-overview" class="dashboard-view active">
      <div class="grid gap-5 md:grid-cols-2 xl:grid-cols-5">
        <article class="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
          <p class="text-sm text-zinc-400">SMB Protected Traffic</p>
          <p id="overview-smb-traffic" class="mt-4 text-4xl font-semibold text-white">0 B</p>
          <p id="overview-smb-detail" class="mt-2 text-xs text-zinc-500">Waiting for SMB telemetry</p>
        </article>
        <article class="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
          <p class="text-sm text-zinc-400">DNS Queries</p>
          <p id="overview-dns-queries" class="mt-4 text-4xl font-semibold text-sky-200">0</p>
          <p id="overview-dns-detail" class="mt-2 text-xs text-zinc-500">Waiting for DNS telemetry</p>
        </article>
        <article class="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
          <p class="text-sm text-zinc-400">Blocked SMB Threats</p>
          <p id="overview-blocked-smb" class="mt-4 text-4xl font-semibold text-red-300">0</p>
          <p id="overview-smb-policy-detail" class="mt-2 text-xs text-zinc-500">No SMB blocks recorded</p>
        </article>
        <article class="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
          <p class="text-sm text-zinc-400">Blocked DNS Domains</p>
          <p id="overview-blocked-dns" class="mt-4 text-4xl font-semibold text-red-300">0</p>
          <p id="overview-dns-policy-detail" class="mt-2 text-xs text-zinc-500">No DNS blocks recorded</p>
        </article>
        <article class="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
          <p class="text-sm text-zinc-400">License</p>
          <p id="overview-license-state" class="mt-4 text-3xl font-semibold text-emerald-200">Loading</p>
          <p id="overview-license-detail" class="mt-2 text-xs text-zinc-500">Checking entitlement</p>
        </article>
      </div>

      <section class="mt-8 rounded-lg border border-emerald-500/20 bg-emerald-500/5 px-6 py-5">
        <div class="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p class="text-sm font-semibold uppercase tracking-wider text-emerald-300">Runtime Enforcement</p>
            <h2 id="runtime-policy-state" class="mt-2 text-xl font-semibold text-white">Loading active policy</h2>
            <p id="runtime-policy-detail" class="mt-1 text-sm text-zinc-300"></p>
          </div>
          <div class="flex flex-col gap-1 text-sm text-zinc-500 lg:text-right">
            <p id="management-info"></p>
            <p id="refresh-state">Waiting for telemetry</p>
          </div>
        </div>
      </section>

      <section id="deployment-warnings-section" class="mt-8 hidden rounded-lg border border-amber-400/30 bg-amber-400/10">
        <div class="border-b border-amber-400/20 px-6 py-5">
          <p class="text-sm font-semibold uppercase tracking-wider text-amber-500">Deployment Checks</p>
          <h2 class="mt-2 text-xl font-semibold text-white">Network path warnings</h2>
          <p class="mt-1 text-sm text-zinc-400">Axiom can enforce only traffic that actually reaches its DNS and SMB listeners.</p>
        </div>
        <div id="deployment-warnings" class="divide-y divide-amber-400/20"></div>
      </section>

      <section class="mt-8 rounded-lg border border-zinc-800 bg-zinc-900">
        <div class="flex flex-col gap-2 border-b border-zinc-800 px-6 py-5 md:flex-row md:items-end md:justify-between">
          <div>
            <h2 class="text-xl font-semibold text-white">Service Map</h2>
            <p class="mt-1 text-sm text-zinc-400">Management, SMB proxy routes, and DNS listener status.</p>
          </div>
        </div>
        <div class="grid gap-4 p-6 lg:grid-cols-2">
          <div>
            <h3 class="text-sm font-semibold uppercase tracking-wider text-zinc-400">SMB Proxy Routes</h3>
            <div class="mt-4 overflow-x-auto">
              <table class="min-w-full divide-y divide-zinc-800">
                <thead class="bg-zinc-950/60">
                  <tr>
                    <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Route</th>
                    <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Interface</th>
                    <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Target</th>
                    <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Bytes</th>
                  </tr>
                </thead>
                <tbody id="mapping-body" class="divide-y divide-zinc-800"></tbody>
              </table>
            </div>
          </div>
          <div>
            <h3 class="text-sm font-semibold uppercase tracking-wider text-zinc-400">DNS Gateway</h3>
            <div class="mt-4 grid gap-4">
              <div class="rounded-md border border-zinc-800 bg-zinc-950/50 p-4">
                <p class="text-xs font-semibold uppercase tracking-wider text-zinc-500">Listener</p>
                <p id="dns-listener" class="mt-2 text-sm font-medium text-white">—</p>
              </div>
              <div class="rounded-md border border-zinc-800 bg-zinc-950/50 p-4">
                <p class="text-xs font-semibold uppercase tracking-wider text-zinc-500">Upstreams</p>
                <p id="dns-upstreams" class="mt-2 text-sm font-medium text-cyan-200">—</p>
              </div>
              <div class="rounded-md border border-zinc-800 bg-zinc-950/50 p-4">
                <p class="text-xs font-semibold uppercase tracking-wider text-zinc-500">Policy</p>
                <p id="dns-policy" class="mt-2 text-sm font-medium text-white">—</p>
              </div>
            </div>
          </div>
        </div>
      </section>
    </section>

    <section id="view-support" class="dashboard-view">
      <section class="rounded-lg border border-emerald-500/20 bg-emerald-500/5 px-6 py-5">
        <div class="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p class="text-sm font-semibold uppercase tracking-wider text-emerald-300">Support</p>
            <h2 class="mt-2 text-2xl font-semibold text-white">Support Center</h2>
            <p class="mt-1 text-sm text-zinc-400">Release readiness, diagnostics export, and support bundle tools for production operations.</p>
          </div>
          <div class="rounded-lg border border-emerald-400/25 bg-zinc-950/70 px-4 py-3 text-sm text-zinc-300">
            <p class="font-semibold text-emerald-100">Operator workflow</p>
            <p class="mt-1 text-xs text-zinc-500">Check readiness, export diagnostics, then attach the bundle to a support case.</p>
          </div>
        </div>
      </section>

      <section class="mt-8 rounded-lg border border-zinc-800 bg-zinc-900">
        <div class="flex flex-col gap-4 border-b border-zinc-800 px-6 py-5 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p class="text-sm font-semibold uppercase tracking-wider text-emerald-300">Production Gate</p>
            <h2 class="mt-2 text-2xl font-semibold text-white">Release Readiness</h2>
            <p id="readiness-summary" class="mt-1 text-sm text-zinc-400">Waiting for deployment telemetry</p>
          </div>
          <div class="rounded-lg border border-zinc-700 bg-zinc-950 px-5 py-4 text-right">
            <p class="text-xs font-semibold uppercase tracking-wider text-zinc-500">Readiness score</p>
            <p id="readiness-score" class="mt-2 text-4xl font-semibold text-white">—</p>
            <p id="readiness-score-detail" class="mt-1 text-xs text-zinc-500">Calculating</p>
          </div>
        </div>

        <div class="grid gap-4 border-b border-zinc-800 p-6 md:grid-cols-3">
          <article class="rounded-lg border border-zinc-800 bg-zinc-950/60 p-5">
            <p class="text-xs font-semibold uppercase tracking-wider text-zinc-500">Blocking Issues</p>
            <p id="readiness-fail-count" class="mt-3 text-3xl font-semibold text-red-300">0</p>
          </article>
          <article class="rounded-lg border border-zinc-800 bg-zinc-950/60 p-5">
            <p class="text-xs font-semibold uppercase tracking-wider text-zinc-500">Warnings</p>
            <p id="readiness-warn-count" class="mt-3 text-3xl font-semibold text-amber-300">0</p>
          </article>
          <article class="rounded-lg border border-zinc-800 bg-zinc-950/60 p-5">
            <p class="text-xs font-semibold uppercase tracking-wider text-zinc-500">Passed Checks</p>
            <p id="readiness-pass-count" class="mt-3 text-3xl font-semibold text-emerald-300">0</p>
          </article>
        </div>

        <div class="grid gap-6 p-6 lg:grid-cols-[1.25fr_0.75fr]">
          <div>
            <h3 class="text-sm font-semibold uppercase tracking-wider text-zinc-400">Checks</h3>
            <div id="readiness-checks" class="mt-4 grid gap-3"></div>
          </div>
          <div>
            <h3 class="text-sm font-semibold uppercase tracking-wider text-zinc-400">Next Actions</h3>
            <div id="readiness-actions" class="mt-4 grid gap-3"></div>
          </div>
        </div>
      </section>

      <section class="mt-8 rounded-lg border border-zinc-800 bg-zinc-900">
        <div class="flex flex-col gap-4 border-b border-zinc-800 px-6 py-5 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p class="text-sm font-semibold uppercase tracking-wider text-sky-300">Support Bundle</p>
            <h2 class="mt-2 text-xl font-semibold text-white">Export Diagnostics</h2>
            <p id="diagnostics-state" class="mt-1 text-sm text-zinc-400">Diagnostics not loaded</p>
          </div>
          <div class="flex flex-wrap gap-3">
            <button id="load-diagnostics" class="rounded-md border border-zinc-700 px-4 py-2 text-sm text-zinc-200 transition hover:border-emerald-300 hover:text-emerald-200">Load diagnostics</button>
            <button id="export-support-bundle" class="rounded-md bg-emerald-400 px-4 py-2 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-300">Export support bundle</button>
          </div>
        </div>
        <div class="grid gap-6 p-6 lg:grid-cols-[0.75fr_1.25fr]">
          <div class="rounded-lg border border-zinc-800 bg-zinc-950/50 p-5">
            <h3 class="text-sm font-semibold uppercase tracking-wider text-zinc-400">Bundle contents</h3>
            <ul class="mt-4 grid gap-2 text-sm text-zinc-300">
              <li>Management process, role, and node identity</li>
              <li>Fleet nodes, listener state, and policy warnings</li>
              <li>SMB route stats, active connections, and file activity</li>
              <li>DNS listener, upstream health, and recent DNS events</li>
              <li>Selected command outputs for troubleshooting</li>
            </ul>
            <p class="mt-4 text-xs text-zinc-500">Secrets and license private keys are not exposed by this diagnostics endpoint.</p>
          </div>
          <pre id="diagnostics-output" class="max-h-96 overflow-auto whitespace-pre-wrap rounded-lg border border-zinc-800 bg-zinc-950 px-5 py-4 text-xs leading-5 text-zinc-300"></pre>
        </div>
      </section>
    </section>

    <section id="view-nodes" class="dashboard-view">
      <section class="rounded-lg border border-zinc-800 bg-zinc-900">
        <div class="flex flex-col gap-2 border-b border-zinc-800 px-6 py-5 md:flex-row md:items-end md:justify-between">
          <div>
            <h2 class="text-xl font-semibold text-white">Axiom Nodes</h2>
            <p id="fleet-state" class="mt-1 text-sm text-zinc-400">Waiting for remote nodes</p>
          </div>
          <p id="fleet-count" class="text-sm text-zinc-500">0 registered nodes</p>
        </div>
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-zinc-800">
            <thead class="bg-zinc-950/60">
              <tr>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Node</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Role</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Health</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Traffic</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Security</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Services</th>
              </tr>
            </thead>
            <tbody id="fleet-nodes-body" class="divide-y divide-zinc-800"></tbody>
          </table>
        </div>
      </section>
    </section>

    <section id="view-smb" class="dashboard-view">
      <section class="rounded-lg border border-zinc-800 bg-zinc-900">
        <div class="flex flex-col gap-2 border-b border-zinc-800 px-6 py-5 md:flex-row md:items-end md:justify-between">
          <div>
            <h2 class="text-xl font-semibold text-white">Live SMB Connections</h2>
            <p id="live-connection-state" class="mt-1 text-sm text-zinc-400">Waiting for active SMB sessions</p>
          </div>
          <p id="live-connection-count" class="text-sm text-zinc-500">0 live connections</p>
        </div>

        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-zinc-800">
            <thead class="bg-zinc-950/60">
              <tr>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Client</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Target</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Route</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Current File</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Wire Traffic</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Forwarded</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">SMB Writes</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Last Activity</th>
              </tr>
            </thead>
            <tbody id="live-connections-body" class="divide-y divide-zinc-800"></tbody>
          </table>
        </div>
      </section>

      <section class="mt-8 rounded-lg border border-zinc-800 bg-zinc-900">
        <div class="flex flex-col gap-2 border-b border-zinc-800 px-6 py-5 md:flex-row md:items-end md:justify-between">
          <div>
            <h2 class="text-xl font-semibold text-white">File Transfer Ledger</h2>
            <p id="file-activity-state" class="mt-1 text-sm text-zinc-400">Waiting for per-file SMB activity</p>
          </div>
          <p id="file-activity-count" class="text-sm text-zinc-500">0 tracked files</p>
        </div>

        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-zinc-800">
            <thead class="bg-zinc-950/60">
              <tr>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">File</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Client</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Target</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">SMB Writes</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Events</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Last Result</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Updated</th>
              </tr>
            </thead>
            <tbody id="file-activity-body" class="divide-y divide-zinc-800"></tbody>
          </table>
        </div>
      </section>

      <section class="mt-8 rounded-lg border border-zinc-800 bg-zinc-900">
      <div class="flex flex-col gap-4 border-b border-zinc-800 px-6 py-5 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 class="text-xl font-semibold text-white">SMB Policies</h2>
          <p id="policy-state" class="mt-1 text-sm text-zinc-400">Loading policies</p>
        </div>
        <div class="flex flex-wrap gap-2">
          <button id="run-policy-self-test" class="rounded-md border border-emerald-400/40 px-3 py-2 text-sm font-semibold text-emerald-100 transition hover:border-emerald-300 hover:bg-emerald-400/10">Run self-test</button>
          <button data-preset="monitor" class="policy-preset rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-200 transition hover:border-cyan-300 hover:text-cyan-100">Monitor only</button>
          <button data-preset="balanced" class="policy-preset rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-200 transition hover:border-emerald-300 hover:text-emerald-100">Balanced</button>
          <button data-preset="strict" class="policy-preset rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-200 transition hover:border-red-300 hover:text-red-100">Strict</button>
          <button id="save-policies" class="rounded-md bg-emerald-400 px-4 py-2 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-300">Save and apply</button>
        </div>
      </div>
      <div class="border-b border-zinc-800 px-6 py-4">
        <p id="self-test-state" class="text-sm text-zinc-400">Self-test not run</p>
        <div id="self-test-results" class="mt-4 grid gap-3 md:grid-cols-4"></div>
      </div>

      <div class="grid gap-4 border-b border-zinc-800 px-6 py-5 md:grid-cols-3">
        <div class="rounded-md border border-zinc-800 bg-zinc-950/50 p-4">
          <p class="text-xs font-semibold uppercase tracking-wider text-zinc-500">Archive Handling</p>
          <p id="policy-summary-archives" class="mt-2 text-lg font-semibold text-white">Loading</p>
        </div>
        <div class="rounded-md border border-zinc-800 bg-zinc-950/50 p-4">
          <p class="text-xs font-semibold uppercase tracking-wider text-zinc-500">Signature Rules</p>
          <p id="policy-summary-signatures" class="mt-2 text-lg font-semibold text-white">Loading</p>
        </div>
        <div class="rounded-md border border-zinc-800 bg-zinc-950/50 p-4">
          <p class="text-xs font-semibold uppercase tracking-wider text-zinc-500">Entropy Detection</p>
          <p id="policy-summary-entropy" class="mt-2 text-lg font-semibold text-white">Loading</p>
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

        <div>
          <h3 class="text-sm font-semibold uppercase tracking-wider text-zinc-400">Reputation Rule</h3>
          <div class="mt-4 grid gap-4 sm:grid-cols-2">
            <label class="block">
              <span class="text-sm text-zinc-300">Known Bad Action</span>
              <select id="policy-reputation-known-bad-action" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-white">
                <option value="alert">alert</option>
                <option value="allow">allow</option>
                <option value="block">block</option>
                <option value="quarantine">quarantine</option>
              </select>
            </label>
            <label class="block">
              <span class="text-sm text-zinc-300">Cache TTL Seconds</span>
              <input id="policy-reputation-cache-ttl" type="number" min="1" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-white">
            </label>
          </div>
          <p class="mt-2 text-xs leading-5 text-zinc-500">V1 default is alert. Block/quarantine deny SMB writes when a streamed SHA256 matches a local known_bad reputation hash.</p>
        </div>

        <div class="lg:col-span-2">
          <h3 class="text-sm font-semibold uppercase tracking-wider text-zinc-400">Signatures</h3>
          <textarea id="policy-signatures" rows="5" spellcheck="false" class="mt-4 w-full rounded-md border border-zinc-700 bg-zinc-950 px-4 py-3 font-mono text-sm text-white outline-none focus:border-emerald-400"></textarea>
        </div>
      </div>
    </section>
    </section>

    <section id="view-dns" class="dashboard-view">
      <section class="rounded-lg border border-zinc-800 bg-zinc-900">
      <div class="flex flex-col gap-2 border-b border-zinc-800 px-6 py-5 md:flex-row md:items-end md:justify-between">
        <div>
          <h2 class="text-xl font-semibold text-white">Live DNS Queries</h2>
          <p id="dns-state" class="mt-1 text-sm text-zinc-400">Waiting for DNS telemetry</p>
        </div>
        <p id="dns-config" class="text-sm text-zinc-500"></p>
      </div>

      <div class="overflow-x-auto">
        <table class="min-w-full divide-y divide-zinc-800">
          <thead class="bg-zinc-950/60">
            <tr>
              <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Client</th>
              <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Domain</th>
              <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Type</th>
              <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Action</th>
              <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Upstream</th>
              <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Latency</th>
              <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Time</th>
            </tr>
          </thead>
          <tbody id="dns-events-body" class="divide-y divide-zinc-800"></tbody>
        </table>
      </div>
    </section>

    <section class="mt-8 grid gap-6 lg:grid-cols-2">
      <section class="rounded-lg border border-zinc-800 bg-zinc-900">
        <div class="border-b border-zinc-800 px-6 py-5">
          <h2 class="text-xl font-semibold text-white">Top Queried Domains</h2>
        </div>
        <div id="top-domains" class="divide-y divide-zinc-800"></div>
      </section>
      <section class="rounded-lg border border-zinc-800 bg-zinc-900">
        <div class="border-b border-zinc-800 px-6 py-5">
          <h2 class="text-xl font-semibold text-white">Top Clients</h2>
        </div>
        <div id="top-clients" class="divide-y divide-zinc-800"></div>
      </section>
    </section>

    <section class="mt-8 grid gap-6 lg:grid-cols-3">
      <section class="rounded-lg border border-zinc-800 bg-zinc-900">
        <div class="border-b border-zinc-800 px-6 py-5">
          <h2 class="text-xl font-semibold text-white">Blocked Domains</h2>
        </div>
        <div id="blocked-domains" class="divide-y divide-zinc-800"></div>
      </section>
      <section class="rounded-lg border border-zinc-800 bg-zinc-900">
        <div class="border-b border-zinc-800 px-6 py-5">
          <h2 class="text-xl font-semibold text-white">Upstream Resolver Health</h2>
        </div>
        <div id="upstream-health" class="divide-y divide-zinc-800"></div>
      </section>
      <section class="rounded-lg border border-zinc-800 bg-zinc-900">
        <div class="border-b border-zinc-800 px-6 py-5">
          <h2 class="text-xl font-semibold text-white">DNS Policies</h2>
        </div>
        <div id="dns-policy-summary" class="divide-y divide-zinc-800"></div>
      </section>
    </section>

    <section class="mt-8 rounded-lg border border-zinc-800 bg-zinc-900">
      <div class="flex flex-col gap-4 border-b border-zinc-800 px-6 py-5 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 class="text-xl font-semibold text-white">DNS Policies and Local Records</h2>
          <p id="dns-policy-state" class="mt-1 text-sm text-zinc-400">Loading DNS policy</p>
        </div>
        <button id="save-dns-policy" class="rounded-md bg-emerald-400 px-4 py-2 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-300">Save and apply</button>
      </div>
      <div class="grid gap-6 p-6 lg:grid-cols-3">
        <label class="block">
          <span class="text-sm text-zinc-300">Blocked Domain Action</span>
          <select id="dns-blocked-action" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-white"></select>
        </label>
        <label class="block">
          <span class="text-sm text-zinc-300">Monitored Domain Action</span>
          <select id="dns-monitored-action" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-white"></select>
        </label>
        <label class="block">
          <span class="text-sm text-zinc-300">Block Response</span>
          <select id="dns-block-response" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-white">
            <option value="nxdomain">nxdomain</option>
            <option value="refused">refused</option>
            <option value="sinkhole">sinkhole</option>
          </select>
        </label>
        <label class="block">
          <span class="text-sm text-zinc-300">Blocked Domains</span>
          <textarea id="dns-blocked-domains" rows="6" spellcheck="false" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-4 py-3 font-mono text-sm text-white"></textarea>
        </label>
        <label class="block">
          <span class="text-sm text-zinc-300">Monitored Domains</span>
          <textarea id="dns-monitored-domains" rows="6" spellcheck="false" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-4 py-3 font-mono text-sm text-white"></textarea>
        </label>
        <label class="block">
          <span class="text-sm text-zinc-300">Threat Feed URLs</span>
          <textarea id="dns-threat-feeds" rows="6" spellcheck="false" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-4 py-3 font-mono text-sm text-white"></textarea>
        </label>
        <label class="block lg:col-span-3">
          <span class="text-sm text-zinc-300">Local DNS Records</span>
          <textarea id="dns-local-records" rows="5" spellcheck="false" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-4 py-3 font-mono text-sm text-white"></textarea>
          <span class="mt-2 block text-xs text-zinc-500">Format: name|type|value|ttl. Example: intranet.local|a|10.0.0.5|300</span>
        </label>
      </div>
    </section>
    </section>

    <section id="view-security" class="dashboard-view">
      <section class="rounded-lg border border-zinc-800 bg-zinc-900">
        <div class="flex flex-col gap-4 border-b border-zinc-800 px-6 py-5 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <h2 class="text-xl font-semibold text-white">Reputation Center</h2>
            <p id="reputation-state" class="mt-1 text-sm text-zinc-400">Loading reputation database</p>
          </div>
          <div class="flex flex-wrap gap-2">
            <input id="reputation-search" type="search" placeholder="Search hash, verdict, source or notes" class="w-80 max-w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-white">
            <select id="reputation-filter" class="rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-white">
              <option value="all">all verdicts</option>
              <option value="known_good">known_good</option>
              <option value="known_bad">known_bad</option>
              <option value="unknown">unknown</option>
            </select>
          </div>
        </div>

        <div class="grid gap-4 border-b border-zinc-800 p-6 md:grid-cols-4">
          <div class="rounded-md border border-zinc-800 bg-zinc-950/50 p-4">
            <p class="text-xs font-semibold uppercase tracking-wider text-zinc-500">Known Good</p>
            <p id="rep-known-good" class="mt-3 text-3xl font-semibold text-emerald-200">0</p>
          </div>
          <div class="rounded-md border border-zinc-800 bg-zinc-950/50 p-4">
            <p class="text-xs font-semibold uppercase tracking-wider text-zinc-500">Known Bad</p>
            <p id="rep-known-bad" class="mt-3 text-3xl font-semibold text-red-200">0</p>
          </div>
          <div class="rounded-md border border-zinc-800 bg-zinc-950/50 p-4">
            <p class="text-xs font-semibold uppercase tracking-wider text-zinc-500">Unknown</p>
            <p id="rep-unknown" class="mt-3 text-3xl font-semibold text-amber-200">0</p>
          </div>
          <div class="rounded-md border border-zinc-800 bg-zinc-950/50 p-4">
            <p class="text-xs font-semibold uppercase tracking-wider text-zinc-500">Pending Scans</p>
            <p id="rep-pending-scans" class="mt-3 text-3xl font-semibold text-sky-200">0</p>
          </div>
        </div>

        <div class="grid gap-6 border-b border-zinc-800 p-6 lg:grid-cols-[1fr_1fr]">
          <section class="rounded-md border border-zinc-800 bg-zinc-950/40 p-4">
            <h3 class="text-sm font-semibold uppercase tracking-wider text-zinc-400">Add Hash</h3>
            <div class="mt-4 grid gap-3">
              <input id="rep-add-sha256" placeholder="SHA256" class="rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs text-white">
              <input id="rep-add-md5" placeholder="MD5 optional" class="rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs text-white">
              <select id="rep-add-verdict" class="rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-white">
                <option value="known_good">known_good</option>
                <option value="known_bad">known_bad</option>
                <option value="unknown">unknown</option>
              </select>
              <textarea id="rep-add-notes" rows="3" placeholder="Notes" class="rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-white"></textarea>
              <button id="rep-add-button" class="rounded-md bg-emerald-400 px-4 py-2 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-300">Add reputation entry</button>
            </div>
          </section>

          <section class="rounded-md border border-zinc-800 bg-zinc-950/40 p-4">
            <h3 class="text-sm font-semibold uppercase tracking-wider text-zinc-400">Bulk Import</h3>
            <textarea id="rep-import-contents" rows="8" spellcheck="false" placeholder="sha256,verdict,notes" class="mt-4 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs text-white"></textarea>
            <button id="rep-import-button" class="mt-3 rounded-md border border-emerald-400/40 px-4 py-2 text-sm font-semibold text-emerald-100 transition hover:border-emerald-300 hover:bg-emerald-400/10">Import hashes</button>
            <p class="mt-2 text-xs text-zinc-500">CSV/TXT format: sha256,verdict,notes</p>
          </section>
        </div>

        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-zinc-800">
            <thead class="bg-zinc-950/60">
              <tr>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">SHA256</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">MD5</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Verdict</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Source</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Hit Count</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Last Seen</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Notes</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-400">Action</th>
              </tr>
            </thead>
            <tbody id="reputation-table-body" class="divide-y divide-zinc-800"></tbody>
          </table>
        </div>
      </section>

      <section class="mt-8 grid gap-6 lg:grid-cols-2">
        <section class="rounded-lg border border-zinc-800 bg-zinc-900">
          <div class="border-b border-zinc-800 px-6 py-5">
            <h2 class="text-xl font-semibold text-white">Top Seen Files</h2>
          </div>
          <div id="rep-top-seen" class="divide-y divide-zinc-800"></div>
        </section>
        <section class="rounded-lg border border-zinc-800 bg-zinc-900">
          <div class="border-b border-zinc-800 px-6 py-5">
            <h2 class="text-xl font-semibold text-white">Recent File Observations</h2>
          </div>
          <div id="rep-recent-observations" class="divide-y divide-zinc-800"></div>
        </section>
      </section>
    </section>

    <section id="view-audit" class="dashboard-view">
      <section class="rounded-lg border border-zinc-800 bg-zinc-900">
        <div class="flex flex-col gap-2 border-b border-zinc-800 px-6 py-5 md:flex-row md:items-end md:justify-between">
          <div>
            <h2 class="text-xl font-semibold text-white">Global Audit Log</h2>
            <p id="audit-state" class="mt-1 text-sm text-zinc-400">Waiting for SMB and DNS activity</p>
            <p class="mt-1 text-xs text-zinc-500">SMB + DNS events in one timeline</p>
          </div>
          <p id="audit-count" class="text-sm text-zinc-500">0 events</p>
        </div>
        <div id="audit-log" class="divide-y divide-zinc-800"></div>
      </section>

    </section>

    <section id="view-settings" class="dashboard-view">
      <section class="rounded-lg border border-zinc-800 bg-zinc-900">
        <div class="border-b border-zinc-800 px-6 py-5">
          <h2 class="text-xl font-semibold text-white">Management Settings</h2>
          <p id="settings-state" class="mt-1 text-sm text-zinc-400">Local console preferences and identity settings</p>
        </div>
        <div class="grid gap-6 p-6 lg:grid-cols-2">
          <label class="block">
            <span class="text-sm text-zinc-300">Display Name</span>
            <input id="settings-display-name" type="text" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-white">
          </label>
          <label class="block">
            <span class="text-sm text-zinc-300">Theme</span>
            <select id="settings-theme" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-white">
              <option value="system">system</option>
              <option value="light">light</option>
              <option value="dark">dark</option>
            </select>
          </label>
          <div class="rounded-md border border-zinc-800 bg-zinc-950/50 p-4">
            <div class="flex items-center justify-between gap-3">
              <p class="text-sm font-semibold text-white">Node Enrollment Token</p>
              <span id="enrollment-token-preview" class="rounded-full border border-emerald-400/40 px-2.5 py-1 text-xs font-semibold text-emerald-700">loading</span>
            </div>
            <input id="enrollment-token-value" readonly class="mt-3 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs text-white">
            <div class="mt-3 flex flex-wrap gap-2">
              <button id="copy-enrollment-token" class="rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-200 transition hover:border-emerald-300 hover:text-emerald-200">Copy token</button>
              <button id="rotate-enrollment-token" class="rounded-md border border-red-300 px-3 py-2 text-sm font-semibold text-red-700 transition hover:bg-red-50">Rotate token</button>
            </div>
            <p id="enrollment-token-state" class="mt-3 text-xs text-zinc-500">Token not loaded</p>
          </div>
          <div class="rounded-md border border-zinc-800 bg-zinc-950/50 p-4 lg:col-span-2">
            <div class="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
              <div>
                <p class="text-sm font-semibold text-white">License Activation</p>
                <p id="license-status" class="mt-2 text-sm text-zinc-500">Loading license state</p>
                <p id="license-customer" class="mt-1 text-xs text-zinc-500">—</p>
              </div>
              <span id="license-state-badge" class="w-fit rounded-full border border-zinc-700 px-2.5 py-1 text-xs font-semibold uppercase text-zinc-300">loading</span>
            </div>

            <div class="mt-4 grid gap-4 lg:grid-cols-2">
              <div class="rounded-md border border-zinc-800 bg-zinc-950/50 p-4">
                <p class="text-xs font-semibold uppercase tracking-wide text-zinc-500">Step 1</p>
                <h3 class="mt-2 text-lg font-semibold text-white">Download activation file</h3>
                <p class="mt-2 text-sm text-zinc-500">Send this file to Axiom support or upload it to the customer portal. No internet access is required on this server.</p>
                <button id="download-activation-file" class="mt-4 rounded-md bg-emerald-400 px-3 py-2 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-300">Download activation file</button>
              </div>
              <div class="rounded-md border border-zinc-800 bg-zinc-950/50 p-4">
                <p class="text-xs font-semibold uppercase tracking-wide text-zinc-500">Step 2</p>
                <h3 class="mt-2 text-lg font-semibold text-white">Upload license file</h3>
                <p class="mt-2 text-sm text-zinc-500">Upload the signed <span class="font-mono">.axlic</span> file returned by Axiom. The license is verified locally before it is installed.</p>
                <input id="license-file-input" type="file" accept=".axlic,.json,.b64,text/plain,application/json" class="mt-4 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-white">
                <button id="install-license-file" class="mt-3 rounded-md bg-emerald-400 px-3 py-2 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-300">Upload license file</button>
              </div>
            </div>

            <p id="license-usage" class="mt-3 text-xs text-zinc-500">Usage not loaded</p>
            <p id="license-install-state" class="mt-1 text-xs text-zinc-500">No license operation running</p>

            <details class="mt-4 rounded-md border border-zinc-800 bg-zinc-950/50 p-4">
              <summary class="cursor-pointer text-sm font-semibold text-zinc-300">Advanced support data</summary>
              <div class="mt-4 grid gap-4 lg:grid-cols-2">
                <label class="block">
                  <span class="text-xs font-semibold uppercase tracking-wide text-zinc-500">Activation request</span>
                  <textarea id="license-activation-request" readonly rows="7" spellcheck="false" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs text-white"></textarea>
                </label>
                <label class="block">
                  <span class="text-xs font-semibold uppercase tracking-wide text-zinc-500">Paste signed license</span>
                  <textarea id="license-install-text" rows="7" spellcheck="false" placeholder="Paste signed Axiom license JSON or base64 package" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs text-white"></textarea>
                </label>
              </div>
              <div class="mt-4 flex flex-wrap gap-2">
                <button id="copy-license-request" class="rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-200 transition hover:border-emerald-300 hover:text-emerald-200">Copy activation request</button>
                <button id="install-license" class="rounded-md border border-emerald-400/40 px-3 py-2 text-sm font-semibold text-emerald-100 transition hover:border-emerald-300 hover:bg-emerald-400/10">Install pasted license</button>
              </div>
            </details>
          </div>
          <div class="rounded-md border border-zinc-800 bg-zinc-950/50 p-4">
            <p class="text-sm font-semibold text-white">Directory Integration</p>
            <p id="directory-status" class="mt-2 text-sm text-zinc-500">Loading directory status</p>
            <p id="client-identity-status" class="mt-1 text-xs text-zinc-500">Loading client identity status</p>
          </div>
          <div class="rounded-md border border-zinc-800 bg-zinc-950/50 p-4">
            <p class="text-sm font-semibold text-white">Management Security</p>
            <p id="https-status" class="mt-2 text-sm text-zinc-500">Loading HTTPS status</p>
            <div class="mt-4 grid gap-3">
              <label class="block">
                <span class="text-xs font-semibold uppercase tracking-wide text-zinc-500">Certificate path</span>
                <input id="tls-cert-path" type="text" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs text-white">
              </label>
              <label class="block">
                <span class="text-xs font-semibold uppercase tracking-wide text-zinc-500">Private key path</span>
                <input id="tls-key-path" type="text" class="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs text-white">
              </label>
              <div class="flex flex-wrap gap-2">
                <button id="enable-https" class="rounded-md bg-emerald-400 px-3 py-2 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-300">Enable HTTPS</button>
                <button id="disable-https" class="rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-200 transition hover:border-amber-300 hover:text-amber-200">Disable HTTPS</button>
              </div>
              <a id="tls-next-url" href="#" class="hidden text-sm font-semibold text-emerald-300 hover:text-emerald-200">Open updated management URL</a>
              <p class="text-xs text-zinc-500">Installer creates a lab self-signed certificate here by default. Browser trust warnings are expected until a trusted enterprise certificate is installed.</p>
              <code id="tls-restart-command" class="block rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-400">sudo systemctl restart axiom.service</code>
            </div>
          </div>
          <div class="rounded-md border border-zinc-800 bg-zinc-950/50 p-4">
            <p class="text-sm font-semibold text-white">Two-factor Authentication</p>
            <p class="mt-2 text-sm text-zinc-500">TOTP enrollment will be enforced in the next authentication hardening pass.</p>
            <button disabled class="mt-4 rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-500">2FA queued</button>
          </div>
        </div>
        <div class="border-t border-zinc-800 px-6 py-5">
          <button id="save-settings" class="rounded-md bg-emerald-400 px-4 py-2 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-300">Save settings</button>
        </div>
      </section>
    </section>
  </main>

  <footer class="border-t border-zinc-800 bg-zinc-950 px-6 py-6 text-sm text-zinc-500">
    <div class="mx-auto flex max-w-7xl flex-col gap-2 md:flex-row md:items-center md:justify-between">
      <p>© 2026 Axiom Security. Lab build for authorized defensive testing only.</p>
      <div class="flex flex-wrap gap-4">
        <a class="hover:text-emerald-300" href="#">Documentation</a>
        <a class="hover:text-emerald-300" href="#">Support</a>
        <a class="hover:text-emerald-300" href="#">Privacy</a>
      </div>
    </div>
  </footer>

  <div id="toast-stack" class="toast-stack" aria-live="polite" aria-atomic="true"></div>

  <section id="push-progress" class="push-progress hidden" aria-live="polite" aria-atomic="true">
    <div class="flex items-start justify-between gap-4">
      <div>
        <p id="push-progress-title" class="text-sm font-semibold text-white">Applying update</p>
        <p id="push-progress-detail" class="mt-1 text-xs text-zinc-400">Preparing node push</p>
      </div>
      <span id="push-progress-percent" class="rounded-full border border-emerald-400/35 bg-emerald-500/10 px-2.5 py-1 text-xs font-semibold text-emerald-100">0%</span>
    </div>
    <div class="push-progress-bar">
      <div id="push-progress-fill" class="push-progress-fill"></div>
    </div>
    <div id="push-progress-results" class="mt-3 grid gap-2 text-xs text-zinc-300"></div>
  </section>

  <script>
    const token = localStorage.getItem("axiomToken") || "";
    const modes = ["disabled", "monitor", "block"];
    let clientIdentities = {};
    let lastFleetNodes = [];
    let reputationEntries = [];
    let latestLicenseStatus = null;
    let latestDiagnosticsBundle = null;

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

    function html(value) {
      return text(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
    }

    function licenseBadgeClass(state) {
      if (state === "licensed" || state === "trial") return "border-emerald-400/40 bg-emerald-500/10 text-emerald-100";
      if (state === "expiring_soon") return "border-amber-400/40 bg-amber-500/10 text-amber-100";
      if (state === "limit_exceeded" || state === "expired" || state === "invalid") return "border-red-400/40 bg-red-500/10 text-red-100";
      return "border-zinc-700 bg-zinc-950 text-zinc-300";
    }

    function activationFilePayload(license) {
      if (!license?.activation_request) return null;
      return {
        format: "axiom_activation_request_v1",
        product: "Axiom",
        generated_by: "Axiom Management Server",
        activation_request: license.activation_request
      };
    }

    function updateLicenseUi(license) {
      if (!license) return;
      latestLicenseStatus = license;
      const state = license.state || "missing";
      const badgeClass = licenseBadgeClass(state);
      const title = state.replaceAll("_", " ");
      const usage = license.usage || {};
      const limits = license.limits || {};
      const days = license.days_remaining === null || license.days_remaining === undefined
        ? "offline request ready"
        : `${license.days_remaining} days remaining`;
      const customer = license.customer_name
        ? `${license.customer_name} · ${text(license.edition)} · ${text(license.license_id)}`
        : `${text(license.edition)} · ${days}`;
      const usageText =
        `${usage.smb_nodes || 0}/${text(limits.max_smb_nodes)} SMB nodes · ` +
        `${usage.dns_nodes || 0}/${text(limits.max_dns_nodes)} DNS nodes · ` +
        `${usage.protected_clients || 0}/${text(limits.max_protected_clients)} clients · ` +
        `${usage.reputation_entries || 0}/${text(limits.max_reputation_entries)} reputation entries`;

      document.getElementById("overview-license-state").textContent = title;
      document.getElementById("overview-license-state").className =
        `mt-4 text-3xl font-semibold ${license.valid ? "text-emerald-700" : state === "expiring_soon" ? "text-amber-700" : "text-red-700"}`;
      document.getElementById("overview-license-detail").textContent = license.message || customer;
      document.getElementById("license-status").textContent = license.message || "License status unavailable";
      document.getElementById("license-customer").textContent = customer;
      document.getElementById("license-usage").textContent = usageText;

      const badge = document.getElementById("license-state-badge");
      badge.className = `w-fit rounded-full border px-2.5 py-1 text-xs font-semibold uppercase ${badgeClass}`;
      badge.textContent = title;

      const activation = document.getElementById("license-activation-request");
      if (activation && document.activeElement !== activation) {
        const activationFile = activationFilePayload(license);
        activation.value = activationFile
          ? JSON.stringify(activationFile, null, 2)
          : (license.activation_request_b64 || "");
      }
    }

    function endpointIp(value) {
      const raw = text(value);
      if (raw === "—") return "";
      const parts = raw.split(":");
      return parts.length > 1 ? parts.slice(0, -1).join(":") : raw;
    }

    function clientLabel(value) {
      const ip = endpointIp(value);
      const hostname = clientIdentities[ip];
      return hostname ? `${hostname} (${text(value)})` : text(value);
    }

    function formatTime(seconds) {
      if (!seconds) return "not available";
      return new Date(Number(seconds) * 1000).toLocaleString();
    }

    function showToast(title, message, tone = "success") {
      const stack = document.getElementById("toast-stack");
      const toast = document.createElement("div");
      toast.className = `toast ${tone}`;
      toast.innerHTML = `
        <p class="text-sm font-semibold text-white">${html(title)}</p>
        <p class="mt-1 text-xs text-zinc-400">${html(message)}</p>
      `;
      stack.appendChild(toast);
      requestAnimationFrame(() => toast.classList.add("show"));
      window.setTimeout(() => {
        toast.classList.remove("show");
        window.setTimeout(() => toast.remove(), 220);
      }, tone === "error" ? 7600 : 4600);
    }

    function setButtonBusy(buttonOrId, busy, busyLabel) {
      const button = typeof buttonOrId === "string" ? document.getElementById(buttonOrId) : buttonOrId;
      if (!button) return;
      if (!button.dataset.originalLabel) {
        button.dataset.originalLabel = button.textContent.trim();
      }
      button.classList.toggle("button-busy", Boolean(busy));
      button.disabled = Boolean(busy);
      button.textContent = busy ? (busyLabel || "Working") : button.dataset.originalLabel;
    }

    function nodeTargetsFor(kind) {
      const role = kind === "dns" ? "dns" : "smb_proxy";
      return lastFleetNodes.filter((node) => node.role === role);
    }

    function setPushProgress(percent, detail) {
      const safePercent = Math.max(0, Math.min(100, Number(percent || 0)));
      document.getElementById("push-progress-fill").style.width = `${safePercent}%`;
      document.getElementById("push-progress-percent").textContent = `${Math.round(safePercent)}%`;
      if (detail) document.getElementById("push-progress-detail").textContent = detail;
    }

    function beginPushProgress(title, targets) {
      const panel = document.getElementById("push-progress");
      const targetCount = Array.isArray(targets) ? targets.length : 0;
      document.getElementById("push-progress-title").textContent = title;
      document.getElementById("push-progress-detail").textContent =
        targetCount ? `Sending encrypted update to ${targetCount} node${targetCount === 1 ? "" : "s"}` : "Saving locally; no remote nodes targeted";
      document.getElementById("push-progress-results").innerHTML = targetCount
        ? targets.map((node) => `
            <div class="flex items-center justify-between rounded-md border border-zinc-700 bg-zinc-950/50 px-3 py-2">
              <span>${html(node.display_name || node.node_id)}</span>
              <span class="text-sky-200">pending</span>
            </div>
          `).join("")
        : `<div class="rounded-md border border-zinc-700 bg-zinc-950/50 px-3 py-2 text-zinc-400">No remote node target for this action.</div>`;
      panel.classList.remove("hidden");
      setPushProgress(targetCount ? 18 : 100);
    }

    function completePushProgress(results, localMessage) {
      const items = Array.isArray(results) ? results : [];
      const accepted = items.filter((item) => item.accepted).length;
      const failed = items.length - accepted;
      const tone = failed ? "warning" : "success";
      const summary = items.length
        ? `${accepted}/${items.length} nodes acknowledged the update`
        : (localMessage || "Saved locally");
      document.getElementById("push-progress-detail").textContent = summary;
      document.getElementById("push-progress-results").innerHTML = items.length
        ? items.map((item) => `
            <div class="flex items-start justify-between gap-3 rounded-md border ${item.accepted ? "border-emerald-400/30 bg-emerald-500/10" : "border-red-400/35 bg-red-500/10"} px-3 py-2">
              <div class="min-w-0">
                <p class="truncate text-zinc-100">${html(item.node_id)}</p>
                <p class="mt-1 text-[0.7rem] text-zinc-400">${html(item.message)}</p>
              </div>
              <span class="${item.accepted ? "text-emerald-200" : "text-red-200"}">${item.accepted ? "ack" : "failed"}</span>
            </div>
          `).join("")
        : `<div class="rounded-md border border-zinc-700 bg-zinc-950/50 px-3 py-2 text-zinc-400">${html(localMessage || "No remote nodes were targeted.")}</div>`;
      setPushProgress(100);
      showToast(
        failed ? "Update saved with node warnings" : "Update applied",
        summary,
        tone
      );
      if (!failed) {
        window.setTimeout(() => document.getElementById("push-progress").classList.add("hidden"), 2600);
      }
    }

    function failPushProgress(message) {
      document.getElementById("push-progress-detail").textContent = message || "Update failed";
      document.getElementById("push-progress-results").innerHTML =
        `<div class="rounded-md border border-red-400/35 bg-red-500/10 px-3 py-2 text-red-100">${html(message || "Update failed")}</div>`;
      setPushProgress(100);
      showToast("Update failed", message || "The request did not complete.", "error");
    }

    function renderPolicyRuntime(runtime) {
      if (!runtime) return;
      const blocking = runtime.blocking_rules || [];
      const monitoring = runtime.monitoring_rules || [];
      document.getElementById("runtime-policy-state").textContent = `Policy generation ${runtime.generation} is active`;
      document.getElementById("runtime-policy-detail").textContent =
        `${blocking.length} blocking rules · ${monitoring.length} monitor rules · applied ${formatTime(runtime.last_updated_unix_timestamp_seconds)}`;
    }

    function setActiveView(name) {
      if (name === "readiness") name = "support";
      const knownViews = new Set(["overview", "nodes", "smb", "dns", "security", "audit", "support", "settings"]);
      if (!knownViews.has(name)) name = "overview";
      document.querySelectorAll(".dashboard-view").forEach((section) => {
        section.classList.toggle("active", section.id === `view-${name}`);
      });
      document.querySelectorAll(".top-nav-button").forEach((button) => {
        button.classList.toggle("active", button.dataset.view === name);
      });
      localStorage.setItem("axiomDashboardView", name);
    }

    function actionBadgeClass(action) {
      if (action === "block") return "border-red-400/40 bg-red-500/10 text-red-100";
      if (action === "monitor") return "border-amber-400/40 bg-amber-500/10 text-amber-100";
      if (action === "error") return "border-orange-400/40 bg-orange-500/10 text-orange-100";
      return "border-emerald-400/40 bg-emerald-500/10 text-emerald-100";
    }

    function readinessTone(status) {
      if (status === "pass") return {
        row: "border-emerald-400/30 bg-emerald-500/10",
        badge: "border-emerald-400/40 bg-emerald-500/10 text-emerald-100",
        text: "text-emerald-300",
        label: "pass"
      };
      if (status === "warn") return {
        row: "border-amber-400/30 bg-amber-500/10",
        badge: "border-amber-400/40 bg-amber-500/10 text-amber-100",
        text: "text-amber-300",
        label: "review"
      };
      return {
        row: "border-red-400/35 bg-red-500/10",
        badge: "border-red-400/40 bg-red-500/10 text-red-100",
        text: "text-red-300",
        label: "fix"
      };
    }

    function readinessCheck(status, title, detail, action) {
      return { status, title, detail, action };
    }

    function nodeAgeSeconds(node) {
      return Math.max(0, Math.round(Date.now() / 1000 - Number(node.last_seen_unix_timestamp_seconds || 0)));
    }

    function collectReadinessChecks(data, stats, fleetNodes, dns) {
      const checks = [];
      const warnings = data.deployment_warnings || {};
      const smbWarnings = warnings.smb || [];
      const dnsWarnings = warnings.dns || [];
      const smbNodes = fleetNodes.filter((node) => node.role === "smb_proxy");
      const dnsNodes = fleetNodes.filter((node) => node.role === "dns");
      const staleNodes = fleetNodes.filter((node) => nodeAgeSeconds(node) > 45);
      const pushFailures = fleetNodes.filter((node) => node.last_control_push && !node.last_control_push.accepted);
      const missingPush = fleetNodes.filter((node) => !node.last_control_push);
      const smbRoutes = [
        ...(data.proxy_listeners || []),
        ...fleetNodes.flatMap((node) => node.proxy_listeners || [])
      ];
      const readySmbRoutes = smbRoutes.filter((route) => route.listener_ready);
      const hasSmbCapacity = readySmbRoutes.length > 0 || smbNodes.length > 0;
      const hasDnsCapacity = Boolean(dns?.enabled) || dnsNodes.length > 0;

      checks.push(readinessCheck(
        data.license?.valid ? "pass" : "fail",
        "License entitlement",
        data.license?.message || "License state unavailable",
        data.license?.valid ? "No action needed." : "Install a signed .axlic license before customer release."
      ));

      checks.push(readinessCheck(
        data.security?.https_enabled ? "pass" : "fail",
        "Management portal HTTPS",
        data.security?.https_enabled ? `HTTPS active at ${text(data.security.https_url)}` : "Management portal is currently reachable over HTTP.",
        data.security?.https_enabled ? "No action needed." : "Enable HTTPS under Settings and use a trusted certificate for production."
      ));

      checks.push(readinessCheck(
        data.security?.directory_enabled ? "pass" : "warn",
        "Administrator authentication",
        data.security?.directory_enabled ? `Directory login enabled · ${text(data.security.directory_url)}` : "Local admin login only.",
        data.security?.directory_enabled ? "No action needed." : "Connect AD/LDAP before broader customer rollout, or document local-admin operation clearly."
      ));

      checks.push(readinessCheck(
        fleetNodes.length && !staleNodes.length ? "pass" : fleetNodes.length ? "warn" : "fail",
        "Node enrollment and heartbeat",
        fleetNodes.length ? `${fleetNodes.length} reporting nodes · ${staleNodes.length} stale` : "No remote DNS or SMB nodes are reporting.",
        fleetNodes.length && !staleNodes.length ? "No action needed." : "Verify node service status, enrollment token, and management reachability."
      ));

      checks.push(readinessCheck(
        pushFailures.length ? "fail" : missingPush.length ? "warn" : "pass",
        "Policy push acknowledgement",
        pushFailures.length ? `${pushFailures.length} nodes rejected or missed the last push.` : missingPush.length ? `${missingPush.length} nodes have no recorded policy push yet.` : "All reporting nodes acknowledged their latest control push.",
        pushFailures.length ? "Open Nodes and inspect failed push messages." : missingPush.length ? "Save SMB/DNS/Reputation policy once to establish a baseline acknowledgement." : "No action needed."
      ));

      checks.push(readinessCheck(
        hasSmbCapacity && !smbWarnings.length ? "pass" : hasSmbCapacity ? "warn" : "fail",
        "SMB protection path",
        hasSmbCapacity ? `${readySmbRoutes.length || smbNodes.length} SMB route/node targets available · ${smbWarnings.length} warnings` : "No SMB proxy route or node is available.",
        hasSmbCapacity && !smbWarnings.length ? "No action needed." : "Ensure clients use Axiom as the SMB endpoint and cannot bypass TCP/445 directly to file servers."
      ));

      checks.push(readinessCheck(
        hasDnsCapacity && !dnsWarnings.length ? "pass" : hasDnsCapacity ? "warn" : "warn",
        "DNS security path",
        hasDnsCapacity ? `${dnsNodes.length || 1} DNS node/listener targets available · ${dnsWarnings.length} warnings` : "No DNS node/listener is enabled. This is acceptable for SMB-only deployments.",
        hasDnsCapacity && !dnsWarnings.length ? "No action needed." : "Verify upstream resolvers, avoid forwarding loops, and define DNS policies for customer environments."
      ));

      checks.push(readinessCheck(
        Number(stats.known_bad_reputation_hashes_loaded || 0) > 0 ? "pass" : "warn",
        "Reputation feed on SMB nodes",
        `${Number(stats.known_bad_reputation_hashes_loaded || 0)} known-bad hashes loaded across runtime telemetry.`,
        Number(stats.known_bad_reputation_hashes_loaded || 0) > 0 ? "No action needed." : "Add a known_bad test hash in Reputation Center and confirm SMB nodes acknowledge it."
      ));

      checks.push(readinessCheck(
        Number(stats.audit_events || 0) > 0 || Number(stats.dns_queries || 0) > 0 ? "pass" : "warn",
        "Audit telemetry",
        `${Number(stats.audit_events || 0)} SMB audit events · ${Number(stats.dns_queries || 0)} DNS queries observed.`,
        Number(stats.audit_events || 0) > 0 || Number(stats.dns_queries || 0) > 0 ? "No action needed." : "Run a smoke test through SMB and DNS before release validation."
      ));

      return checks;
    }

    function renderReleaseReadiness(data, stats, fleetNodes, dns) {
      const checks = collectReadinessChecks(data, stats, fleetNodes, dns);
      const passCount = checks.filter((check) => check.status === "pass").length;
      const warnCount = checks.filter((check) => check.status === "warn").length;
      const failCount = checks.filter((check) => check.status === "fail").length;
      const score = Math.round(((passCount + warnCount * 0.5) / Math.max(1, checks.length)) * 100);
      const releaseState = failCount ? "Not ready for production" : warnCount ? "Release candidate with warnings" : "Ready for controlled release";
      const scoreClass = failCount ? "text-red-300" : warnCount ? "text-amber-300" : "text-emerald-300";

      document.getElementById("readiness-summary").textContent =
        `${releaseState} · checked ${checks.length} controls at ${new Date().toLocaleTimeString()}`;
      document.getElementById("readiness-score").textContent = `${score}%`;
      document.getElementById("readiness-score").className = `mt-2 text-4xl font-semibold ${scoreClass}`;
      document.getElementById("readiness-score-detail").textContent =
        failCount ? "Fix blocking issues before release." : warnCount ? "Review warnings before customer rollout." : "Core checks are green.";
      document.getElementById("readiness-fail-count").textContent = failCount;
      document.getElementById("readiness-warn-count").textContent = warnCount;
      document.getElementById("readiness-pass-count").textContent = passCount;

      document.getElementById("readiness-checks").innerHTML = checks.map((check) => {
        const tone = readinessTone(check.status);
        return `
          <article class="rounded-lg border ${tone.row} p-4">
            <div class="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <div class="min-w-0">
                <p class="text-sm font-semibold text-white">${html(check.title)}</p>
                <p class="mt-1 text-sm text-zinc-400">${html(check.detail)}</p>
              </div>
              <span class="w-fit rounded-full border px-2.5 py-1 text-xs font-semibold uppercase ${tone.badge}">${tone.label}</span>
            </div>
            <p class="mt-3 text-xs ${tone.text}">${html(check.action)}</p>
          </article>
        `;
      }).join("");

      const actions = checks
        .filter((check) => check.status !== "pass")
        .slice(0, 6);
      document.getElementById("readiness-actions").innerHTML = actions.length
        ? actions.map((check, index) => {
            const tone = readinessTone(check.status);
            return `
              <div class="rounded-lg border border-zinc-800 bg-zinc-950/60 p-4">
                <p class="text-xs font-semibold uppercase tracking-wider ${tone.text}">Step ${index + 1} · ${tone.label}</p>
                <p class="mt-2 text-sm font-semibold text-white">${html(check.title)}</p>
                <p class="mt-1 text-sm text-zinc-400">${html(check.action)}</p>
              </div>
            `;
          }).join("")
        : `<div class="rounded-lg border border-emerald-400/30 bg-emerald-500/10 p-4 text-sm text-emerald-100">All readiness checks passed. Keep the smoke-test evidence and proceed to packaging/customer documentation.</div>`;
    }

    function renderList(containerId, rows, emptyText) {
      const container = document.getElementById(containerId);
      if (!rows.length) {
        container.innerHTML = `<div class="px-6 py-5 text-sm text-zinc-400">${emptyText}</div>`;
        return;
      }

      container.innerHTML = rows.map((row) => `
        <div class="flex items-start justify-between gap-4 px-6 py-4">
          <div class="min-w-0">
            <p class="truncate text-sm font-semibold text-white">${text(row.title)}</p>
            <p class="mt-1 text-xs text-zinc-500">${text(row.detail)}</p>
          </div>
          <p class="shrink-0 text-sm font-semibold ${row.tone || "text-zinc-300"}">${text(row.value)}</p>
        </div>
      `).join("");
    }

    function renderDeploymentWarnings(warnings) {
      const section = document.getElementById("deployment-warnings-section");
      const smbWarnings = (warnings?.smb || []).map((warning) => ({
        title: "SMB path check",
        detail: warning,
        value: "verify",
        tone: "text-amber-700"
      }));
      const dnsWarnings = (warnings?.dns || []).map((warning) => ({
        title: "DNS resolver check",
        detail: warning,
        value: "verify",
        tone: "text-amber-700"
      }));
      const rows = [...smbWarnings, ...dnsWarnings];
      section.classList.toggle("hidden", rows.length === 0);
      renderList("deployment-warnings", rows, "No deployment warnings.");
    }

    function numberStat(stats, key) {
      return Number((stats || {})[key] || 0);
    }

    function aggregateStats(localStats, fleetNodes) {
      const stats = { ...(localStats || {}) };
      const numericKeys = [
        "total_connections", "active_connections", "inspected_chunks", "inspected_bytes",
        "allowed_chunks", "monitored_chunks", "blocked_chunks", "observed_file_events",
        "audit_events", "stream_bytes_client_to_server", "stream_bytes_server_to_client",
        "bytes_client_to_server", "bytes_server_to_client", "smb_write_requests",
        "smb_write_bytes", "server_side_copy_requests", "completed_file_hashes",
        "known_good_reputation_events", "known_bad_reputation_events", "unknown_reputation_events",
        "known_bad_reputation_hashes_loaded",
        "dns_queries", "dns_udp_queries",
        "dns_tcp_queries", "dns_blocked_queries", "dns_monitored_queries", "dns_cache_hits",
        "dns_upstream_errors", "monitored_threats", "blocked_threats"
      ];

      fleetNodes.forEach((node) => {
        const remote = node.stats || {};
        numericKeys.forEach((key) => {
          stats[key] = numberStat(stats, key) + numberStat(remote, key);
        });
        ["route_stats", "active_connection_details", "file_activity", "recent_threats", "recent_audit_events", "recent_dns_events"].forEach((key) => {
          stats[key] = [...(stats[key] || []), ...(remote[key] || [])];
        });
      });

      ["recent_threats", "recent_audit_events", "recent_dns_events", "active_connection_details", "file_activity"].forEach((key) => {
        stats[key] = (stats[key] || [])
          .slice()
          .sort((left, right) => Number(right.last_activity_unix_timestamp_seconds || right.unix_timestamp_seconds || 0) - Number(left.last_activity_unix_timestamp_seconds || left.unix_timestamp_seconds || 0))
          .slice(0, 160);
      });

      stats.route_stats = stats.route_stats || [];
      return stats;
    }

    function effectiveDnsStatus(localDns, fleetNodes) {
      if (localDns?.enabled) return localDns;
      const dnsNode = fleetNodes.find((node) => node.dns?.enabled);
      return dnsNode?.dns || localDns || {};
    }

    function renderFleetNodes(localNode, fleetNodes) {
      const body = document.getElementById("fleet-nodes-body");
      document.getElementById("fleet-count").textContent = `${fleetNodes.length} reporting nodes`;
      document.getElementById("fleet-state").textContent =
        fleetNodes.length ? `Management role: ${text(localNode?.role)} · latest heartbeat ${formatTime(fleetNodes[0].last_seen_unix_timestamp_seconds)}` : `Management role: ${text(localNode?.role)} · waiting for DNS/SMB nodes`;

      if (!fleetNodes.length) {
        body.innerHTML = `<tr><td colspan="6" class="px-6 py-6 text-sm text-zinc-400">No remote DNS or SMB nodes have enrolled yet.</td></tr>`;
        return;
      }

      const nowSeconds = Date.now() / 1000;
      body.innerHTML = fleetNodes.map((node) => {
        const stats = node.stats || {};
        const age = Math.max(0, Math.round(nowSeconds - Number(node.last_seen_unix_timestamp_seconds || 0)));
        const healthy = age <= 20;
        const wireBytes = Number(stats.stream_bytes_client_to_server || 0) + Number(stats.stream_bytes_server_to_client || 0);
        const dnsQueries = Number(stats.dns_queries || 0);
        const knownBadLoaded = Number(stats.known_bad_reputation_hashes_loaded || 0);
        const trafficTitle = node.role === "dns" ? `${dnsQueries} DNS queries` : formatBytes(wireBytes);
        const push = node.last_control_push || null;
        const pushOk = !push || Boolean(push.accepted);
        const pushDetail = push
          ? `${push.accepted ? "last push ok" : "last push failed"} · ${formatTime(push.pushed_unix_timestamp_seconds)}`
          : "no policy push recorded";
        const pushGenerations = push
          ? [
              push.policy_generation ? `SMB gen ${push.policy_generation}` : null,
              push.dns_policy_generation ? `DNS gen ${push.dns_policy_generation}` : null,
              push.known_bad_reputation_hash_count !== null && push.known_bad_reputation_hash_count !== undefined ? `${push.known_bad_reputation_hash_count} known-bad hashes` : null
            ].filter(Boolean).join(" · ")
          : "";
        const services = [
          (node.proxy_listeners || []).length ? `${(node.proxy_listeners || []).length} SMB routes` : null,
          node.dns?.enabled ? `DNS ${text(node.dns.listen_udp_addr)}` : null,
          node.control_url ? `Control ${text(node.control_url)}` : null
        ].filter(Boolean).join(" · ");

        return `
          <tr class="hover:bg-zinc-800/40">
            <td class="px-6 py-4 text-sm font-medium text-white">
              <p>${text(node.display_name)}</p>
              <p class="mt-1 text-xs text-zinc-500">${text(node.node_id)} · ${text(node.hostname)}</p>
            </td>
            <td class="whitespace-nowrap px-6 py-4 text-sm text-zinc-300">${text(node.role)}</td>
            <td class="whitespace-nowrap px-6 py-4 text-sm">
              <span class="rounded-full border px-2.5 py-1 text-xs font-semibold uppercase ${healthy ? "border-emerald-400/40 bg-emerald-500/10 text-emerald-100" : "border-amber-400/40 bg-amber-500/10 text-amber-100"}">${healthy ? "online" : "stale"}</span>
              <p class="mt-2 text-xs text-zinc-500">${age}s ago · v${text(node.version)}</p>
              <p class="mt-2 text-xs ${pushOk ? "text-emerald-300" : "text-red-300"}">${text(pushDetail)}</p>
              ${pushGenerations ? `<p class="mt-1 text-xs text-zinc-500">${text(pushGenerations)}</p>` : ""}
            </td>
            <td class="whitespace-nowrap px-6 py-4 text-sm text-sky-200">
              <p>${trafficTitle}</p>
              <p class="mt-1 text-xs text-zinc-500">${formatBytes(wireBytes)} wire · ${text(stats.active_connections || 0)} SMB active · ${dnsQueries} DNS queries</p>
            </td>
            <td class="whitespace-nowrap px-6 py-4 text-sm text-red-200">
              <p>${text(stats.blocked_threats || 0)} SMB blocks</p>
              <p class="mt-1 text-xs text-zinc-500">${text(stats.dns_blocked_queries || 0)} DNS blocks · ${knownBadLoaded} known-bad hashes</p>
            </td>
            <td class="px-6 py-4 text-sm text-zinc-300">${text(services)}</td>
          </tr>
        `;
      }).join("");
    }

    function topCounts(items, keyFn, limit = 10) {
      const counts = new Map();
      items.forEach((item) => {
        const key = keyFn(item);
        if (!key) return;
        counts.set(key, (counts.get(key) || 0) + 1);
      });
      return [...counts.entries()]
        .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
        .slice(0, limit)
        .map(([title, value]) => ({ title, value, detail: "recent window" }));
    }

    function renderDnsSummary(dns, dnsEvents, stats) {
      renderList(
        "top-domains",
        topCounts(dnsEvents, (event) => event.query_name),
        "No DNS domains observed yet."
      );

      renderList(
        "top-clients",
        topCounts(dnsEvents, (event) => clientLabel(event.client_addr)),
        "No DNS clients observed yet."
      );

      renderList(
        "blocked-domains",
        dnsEvents
          .filter((event) => event.action === "block")
          .slice()
          .reverse()
          .slice(0, 10)
          .map((event) => ({
            title: event.query_name,
            detail: `${clientLabel(event.client_addr)} · ${text(event.reason)}`,
            value: "blocked",
            tone: "text-red-200"
          })),
        "No DNS blocks recorded in the recent window."
      );

      const upstreamRows = (dns.upstreams || []).map((upstream) => {
        const events = dnsEvents.filter((event) => event.upstream_addr === upstream);
        const avgLatency = events.length
          ? Math.round(events.reduce((sum, event) => sum + Number(event.latency_millis || 0), 0) / events.length)
          : null;
        return {
          title: upstream,
          detail: events.length ? `${events.length} recent queries · avg ${avgLatency} ms` : "configured, waiting for traffic",
          value: events.length ? "healthy" : "standby",
          tone: events.length ? "text-emerald-200" : "text-zinc-400"
        };
      });
      if (!upstreamRows.length && dns.enabled) {
        upstreamRows.push({
          title: "No upstream resolvers configured",
          detail: "DNS forwarding cannot run until an upstream resolver exists.",
          value: "needs setup",
          tone: "text-red-200"
        });
      }
      renderList("upstream-health", upstreamRows, "DNS gateway is disabled.");

      renderList(
        "dns-policy-summary",
        dns.enabled
          ? [
              {
                title: "Block response",
                detail: "How blocked DNS requests are answered.",
                value: dns.block_response
              },
              {
                title: "Threat feeds",
                detail: `${dns.blocked_domains || 0} static blocks · ${dns.monitored_domains || 0} monitored domains · ${dns.local_records || 0} local records`,
                value: (dns.threat_feed_urls || []).length
              },
              {
                title: "Runtime counters",
                detail: `${stats.dns_cache_hits || 0} cache hits · ${stats.dns_upstream_errors || 0} upstream errors`,
                value: `${stats.dns_blocked_queries || 0} blocked`
              }
            ].concat((dns.deployment_warnings || []).map((warning) => ({
              title: "Deployment warning",
              detail: warning,
              value: "check",
              tone: "text-amber-700"
            })))
          : [],
        "DNS policies are disabled."
      );
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
      clientIdentities = data.client_identities || {};
      const fleetNodes = data.fleet_nodes || [];
      lastFleetNodes = fleetNodes;
      const stats = aggregateStats(data.stats, fleetNodes);
      updateLicenseUi(data.license);
      renderFleetNodes(data.node || {}, fleetNodes);
      const forwardedBytes = Number(stats.bytes_client_to_server || 0) + Number(stats.bytes_server_to_client || 0);
      const streamBytes = Number(stats.stream_bytes_client_to_server || 0) + Number(stats.stream_bytes_server_to_client || 0);

      document.getElementById("overview-smb-traffic").textContent = formatBytes(streamBytes);
      document.getElementById("overview-smb-detail").textContent =
        `${formatBytes(forwardedBytes)} forwarded · ${formatBytes(stats.smb_write_bytes || 0)} uploaded · ${stats.active_connections || 0} active`;
      document.getElementById("overview-dns-queries").textContent = stats.dns_queries || 0;
      document.getElementById("overview-dns-detail").textContent =
        `${stats.dns_cache_hits || 0} cache hits · ${stats.dns_upstream_errors || 0} upstream errors`;
      document.getElementById("overview-blocked-smb").textContent = stats.blocked_threats || 0;
      document.getElementById("overview-smb-policy-detail").textContent =
        `${stats.monitored_threats || 0} monitored · ${stats.inspected_chunks || 0} inspected chunks · ${stats.observed_file_events || 0} files`;
      document.getElementById("overview-blocked-dns").textContent = stats.dns_blocked_queries || 0;
      document.getElementById("overview-dns-policy-detail").textContent =
        `${stats.dns_monitored_queries || 0} monitored · ${stats.dns_udp_queries || 0} UDP · ${stats.dns_tcp_queries || 0} TCP`;
      document.getElementById("management-info").textContent = `${data.management_interface} at ${data.management_bind_addr}`;
      document.getElementById("refresh-state").textContent = `PID ${data.process_id} · ${data.config_path} · updated ${new Date().toLocaleTimeString()}`;
      updateTlsSettingsUi(data.security || {}, data.management_bind_addr);
      document.getElementById("directory-status").textContent = data.security?.directory_enabled
        ? `AD login enabled · ${text(data.security.directory_url)}`
        : "Local admin login only";
      document.getElementById("client-identity-status").textContent = data.security?.client_reverse_dns
        ? `${Object.keys(clientIdentities).length} client names resolved`
        : "Client name resolution disabled";
      renderPolicyRuntime(stats.policy_runtime);
      renderDeploymentWarnings(data.deployment_warnings || {});

      const dns = effectiveDnsStatus(data.dns || {}, fleetNodes);
      const dnsEvents = stats.recent_dns_events || [];
      document.getElementById("dns-state").textContent = dns.enabled
        ? `${stats.dns_queries || 0} queries · ${stats.dns_blocked_queries || 0} blocked · ${stats.dns_monitored_queries || 0} monitored`
        : "DNS Security Gateway is disabled";
      document.getElementById("dns-config").textContent = dns.enabled ? `${dns.interface} · ${dns.listen_udp_addr}` : "not configured";
      document.getElementById("dns-listener").textContent = dns.enabled ? `UDP ${dns.listen_udp_addr} · TCP ${dns.listen_tcp_addr}` : "disabled";
      document.getElementById("dns-upstreams").textContent = dns.enabled ? (dns.upstreams || []).join(", ") : "—";
      document.getElementById("dns-policy").textContent = dns.enabled ? `block response: ${dns.block_response}` : "—";
      renderReleaseReadiness(data, stats, fleetNodes, dns);
      renderDnsSummary(dns, dnsEvents, stats);

      const dnsEventsBody = document.getElementById("dns-events-body");
      if (!dnsEvents.length) {
        dnsEventsBody.innerHTML = `<tr><td colspan="7" class="px-6 py-6 text-sm text-zinc-400">No DNS queries recorded yet.</td></tr>`;
      } else {
        dnsEventsBody.innerHTML = dnsEvents.slice().reverse().slice(0, 80).map((event) => {
          const actionClass = actionBadgeClass(event.action);
          return `
            <tr class="hover:bg-zinc-800/40">
              <td class="whitespace-nowrap px-6 py-4 text-sm font-medium text-white">${clientLabel(event.client_addr)} · ${text(event.protocol).toUpperCase()}</td>
              <td class="max-w-xs px-6 py-4 text-sm text-white">
                <p class="truncate">${text(event.query_name)}</p>
                <p class="mt-1 line-clamp-1 text-xs text-zinc-500">${text(event.reason)}</p>
              </td>
              <td class="whitespace-nowrap px-6 py-4 text-sm text-zinc-300">${text(event.query_type)}</td>
              <td class="whitespace-nowrap px-6 py-4 text-sm">
                <span class="rounded-full border px-2.5 py-1 text-xs font-semibold uppercase ${actionClass}">${text(event.action)}</span>
                ${event.cache_hit ? `<p class="mt-2 text-xs text-emerald-500">cache hit</p>` : ""}
              </td>
              <td class="whitespace-nowrap px-6 py-4 text-sm text-cyan-200">${text(event.upstream_addr)}</td>
              <td class="whitespace-nowrap px-6 py-4 text-sm text-zinc-300">${text(event.latency_millis)} ms · rcode ${text(event.response_code)}</td>
              <td class="whitespace-nowrap px-6 py-4 text-xs text-zinc-500">${formatTime(event.unix_timestamp_seconds)}</td>
            </tr>
          `;
        }).join("");
      }

      const liveConnections = stats.active_connection_details || [];
      const liveConnectionsBody = document.getElementById("live-connections-body");
      document.getElementById("live-connection-count").textContent = `${liveConnections.length} live connections`;
      document.getElementById("live-connection-state").textContent = liveConnections.length
        ? `Latest activity ${formatTime(liveConnections[0].last_activity_unix_timestamp_seconds)}`
        : "Waiting for active SMB sessions";

      if (!liveConnections.length) {
        liveConnectionsBody.innerHTML = `<tr><td colspan="8" class="px-6 py-6 text-sm text-zinc-400">No active SMB connections right now.</td></tr>`;
      } else {
        liveConnectionsBody.innerHTML = liveConnections.map((connection) => {
          const wireBytes = Number(connection.stream_bytes_client_to_server || 0) + Number(connection.stream_bytes_server_to_client || 0);
          const forwarded = Number(connection.forwarded_bytes_client_to_server || 0) + Number(connection.forwarded_bytes_server_to_client || 0);
          const blocked = Number(connection.blocked_events || 0) > 0;
          const monitored = Number(connection.monitored_events || 0) > 0;
          const actionClass = blocked ? "border-red-400/40 bg-red-500/10 text-red-100" : monitored ? "border-amber-400/40 bg-amber-500/10 text-amber-100" : "border-emerald-400/40 bg-emerald-500/10 text-emerald-100";
          return `
            <tr class="hover:bg-zinc-800/40">
              <td class="whitespace-nowrap px-6 py-4 text-sm font-medium text-white">${clientLabel(connection.peer_addr)}</td>
              <td class="whitespace-nowrap px-6 py-4 text-sm text-cyan-200">${text(connection.target_addr)}</td>
              <td class="whitespace-nowrap px-6 py-4 text-sm text-zinc-300">${text(connection.route_name)} · ${text(connection.interface)}</td>
              <td class="max-w-xs px-6 py-4 text-sm text-white">
                <p class="truncate">${text(connection.last_file_path)}</p>
                <p class="mt-1 line-clamp-1 text-xs text-zinc-500">${text(connection.last_reason)}</p>
              </td>
              <td class="whitespace-nowrap px-6 py-4 text-sm text-sky-200">${formatBytes(wireBytes)}</td>
              <td class="whitespace-nowrap px-6 py-4 text-sm text-emerald-200">${formatBytes(forwarded)}</td>
              <td class="whitespace-nowrap px-6 py-4 text-sm text-lime-200">${formatBytes(connection.smb_write_bytes || 0)} · ${text(connection.smb_write_requests || 0)} writes</td>
              <td class="whitespace-nowrap px-6 py-4 text-sm text-zinc-300">
                <span class="rounded-full border px-2.5 py-1 text-xs font-semibold uppercase ${actionClass}">${text(connection.last_action)}</span>
                <p class="mt-2 text-xs text-zinc-500">${formatTime(connection.last_activity_unix_timestamp_seconds)}</p>
              </td>
            </tr>
          `;
        }).join("");
      }

      const mappingBody = document.getElementById("mapping-body");
      const routeStats = new Map((stats.route_stats || []).map((route) => [route.route_name, route]));
      const proxyListeners = fleetNodes.flatMap((node) =>
        (node.proxy_listeners || []).map((route) => ({ ...route, node_label: node.display_name || node.node_id }))
      );
      const visibleProxyListeners = proxyListeners.length ? proxyListeners : (data.proxy_listeners || []);
      mappingBody.innerHTML = visibleProxyListeners.map((route) => `
        ${(() => {
          const runtime = routeStats.get(route.name) || {};
          const routeBytes = Number(runtime.bytes_client_to_server || 0) + Number(runtime.bytes_server_to_client || 0);
          const routeStreamBytes = Number(runtime.stream_bytes_client_to_server || 0) + Number(runtime.stream_bytes_server_to_client || 0);
          return `
        <tr class="hover:bg-zinc-800/40">
          <td class="px-4 py-4 text-sm font-medium text-white">
            <p>${text(route.name)}</p>
            <p class="mt-1 text-xs text-zinc-500">${text(route.listen_addr)}${route.node_label ? ` · ${text(route.node_label)}` : ""}</p>
          </td>
          <td class="px-4 py-4 text-sm text-emerald-200">
            <p>${text(route.source_interface)}</p>
            <p class="mt-1 text-xs text-zinc-500">VLAN ${text(route.client_vlan)}</p>
          </td>
          <td class="px-4 py-4 text-sm text-cyan-200">${text(route.target_file_server_addr)}</td>
          <td class="px-4 py-4 text-sm text-zinc-300">
            <p>${formatBytes(routeBytes)} forwarded</p>
            <p class="mt-1 text-xs text-zinc-500">${formatBytes(routeStreamBytes)} wire · ${text(runtime.active_connections || 0)} active</p>
          </td>
        </tr>
          `;
        })()}
      `).join("");

      const fileActivity = stats.file_activity || [];
      const fileActivityBody = document.getElementById("file-activity-body");
      document.getElementById("file-activity-count").textContent = `${fileActivity.length} tracked files`;
      document.getElementById("file-activity-state").textContent = fileActivity.length
        ? `Latest file update ${formatTime(fileActivity[0].last_activity_unix_timestamp_seconds)}`
        : "Waiting for per-file SMB activity";

      if (!fileActivity.length) {
        fileActivityBody.innerHTML = `<tr><td colspan="7" class="px-6 py-6 text-sm text-zinc-400">No file-level SMB activity recorded.</td></tr>`;
      } else {
        fileActivityBody.innerHTML = fileActivity.slice(0, 80).map((activity) => {
          const isBlocked = Number(activity.blocked_events || 0) > 0 || activity.last_action === "block";
          const isMonitored = Number(activity.monitored_events || 0) > 0 || activity.last_action === "monitor";
          const resultClass = isBlocked ? "border-red-400/40 bg-red-500/10 text-red-100" : isMonitored ? "border-amber-400/40 bg-amber-500/10 text-amber-100" : "border-emerald-400/40 bg-emerald-500/10 text-emerald-100";
          return `
            <tr class="hover:bg-zinc-800/40">
              <td class="max-w-xs px-6 py-4 text-sm font-medium text-white">
                <p class="truncate">${text(activity.file_path)}</p>
                <p class="mt-1 text-xs text-zinc-500">${text(activity.route_name)} · ${text(activity.interface)}</p>
              </td>
              <td class="whitespace-nowrap px-6 py-4 text-sm text-zinc-300">${clientLabel(activity.peer_addr)}</td>
              <td class="whitespace-nowrap px-6 py-4 text-sm text-cyan-200">${text(activity.target_addr)}</td>
              <td class="whitespace-nowrap px-6 py-4 text-sm text-lime-200">${formatBytes(activity.smb_write_bytes || 0)} · ${text(activity.smb_write_requests || 0)} writes</td>
              <td class="whitespace-nowrap px-6 py-4 text-sm text-zinc-300">${text(activity.observed_events || 0)} seen · ${text(activity.blocked_events || 0)} blocked · ${text(activity.monitored_events || 0)} monitored</td>
              <td class="min-w-72 px-6 py-4 text-sm text-zinc-300">
                <span class="rounded-full border px-2.5 py-1 text-xs font-semibold uppercase ${resultClass}">${text(activity.last_action)}</span>
                <p class="mt-2 line-clamp-2 text-zinc-400">${text(activity.last_reason)}${activity.last_rule_name ? ` · ${text(activity.last_rule_name)}` : ""}</p>
              </td>
              <td class="whitespace-nowrap px-6 py-4 text-xs text-zinc-500">${formatTime(activity.last_activity_unix_timestamp_seconds)}</td>
            </tr>
          `;
        }).join("");
      }

      const auditLog = document.getElementById("audit-log");
      const smbAuditEvents = (stats.recent_audit_events || []).map((event) => ({
        source: "SMB",
        timestamp: Number(event.unix_timestamp_seconds || 0),
        severity: event.severity,
        kind: event.kind,
        action: event.action,
        subject: event.file_path || text(event.kind).replaceAll("_", " "),
        route: `${text(event.route_name)} · ${text(event.interface)} · ${text(event.direction)}`,
        peer: clientLabel(event.peer_addr),
        target: event.target_addr,
        reason: `${text(event.reason)}${event.rule_name ? ` · ${text(event.rule_name)}` : ""}`
      }));
      const dnsAuditEvents = dnsEvents.map((event) => ({
        source: "DNS",
        timestamp: Number(event.unix_timestamp_seconds || 0),
        severity: event.action === "block" ? "critical" : event.action === "monitor" || event.action === "error" ? "warning" : "info",
        kind: "dns_query",
        action: event.action,
        subject: event.query_name,
        route: `${text(event.protocol).toUpperCase()} · ${text(event.query_type)}${event.cache_hit ? " · cache hit" : ""}`,
        peer: clientLabel(event.client_addr),
        target: event.upstream_addr,
        reason: `${text(event.reason)} · rcode ${text(event.response_code)} · ${text(event.latency_millis)} ms`
      }));
      const globalEvents = [...smbAuditEvents, ...dnsAuditEvents]
        .sort((a, b) => b.timestamp - a.timestamp)
        .slice(0, 120);

      document.getElementById("audit-count").textContent =
        `${globalEvents.length} recent events · ${stats.audit_events || 0} SMB total · ${stats.dns_queries || 0} DNS total`;
      document.getElementById("audit-state").textContent = globalEvents.length
        ? `Latest event ${new Date(globalEvents[0].timestamp * 1000).toLocaleTimeString()}`
        : "Waiting for SMB and DNS activity";

      if (!globalEvents.length) {
        auditLog.innerHTML = `<div class="px-6 py-6 text-sm text-zinc-400">No SMB or DNS activity recorded.</div>`;
      } else {
        auditLog.innerHTML = globalEvents.map((event) => {
          const severityClass = event.severity === "critical" ? "text-red-200" : event.severity === "warning" ? "text-amber-200" : "text-zinc-200";
          const badgeClass = event.action === "block" ? "border-red-400/40 bg-red-500/10 text-red-100" : event.action === "monitor" ? "border-amber-400/40 bg-amber-500/10 text-amber-100" : "border-zinc-700 bg-zinc-950 text-zinc-300";
          const sourceClass = event.source === "DNS" ? "border-sky-400/40 bg-sky-500/10 text-sky-100" : "border-emerald-400/40 bg-emerald-500/10 text-emerald-100";
          return `
            <div class="px-6 py-4">
              <div class="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
                <div class="min-w-0">
                  <div class="flex flex-wrap items-center gap-2">
                    <span class="rounded-full border px-2.5 py-1 text-xs font-semibold uppercase ${sourceClass}">${event.source}</span>
                    <span class="rounded-full border px-2.5 py-1 text-xs font-semibold uppercase ${badgeClass}">${text(event.kind).replaceAll("_", " ")}</span>
                    <span class="text-sm font-semibold ${severityClass}">${text(event.action).toUpperCase()}</span>
                    <span class="text-sm text-zinc-400">${text(event.peer)} → ${text(event.target)}</span>
                  </div>
                  <p class="mt-2 truncate text-sm text-white">${text(event.subject)}</p>
                  <p class="mt-1 text-sm text-zinc-400">${text(event.reason)}</p>
                  <p class="mt-1 text-xs text-zinc-500">${text(event.route)}</p>
                </div>
                <p class="text-xs text-zinc-500">${new Date(event.timestamp * 1000).toLocaleString()}</p>
              </div>
            </div>
          `;
        }).join("");
      }
    }

    function fillModeSelect(id, value) {
      const element = document.getElementById(id);
      element.innerHTML = modes.map((mode) => `<option value="${mode}">${mode}</option>`).join("");
      element.value = value || "disabled";
    }

    function renderSmbPolicySummary(policy) {
      const archiveModes = [
        policy.archive?.rar,
        policy.archive?.seven_zip,
        policy.archive?.zip,
        policy.archive?.encrypted_zip
      ];
      const archiveBlocks = archiveModes.filter((mode) => mode === "block").length;
      const signatureBlocks = (policy.signatures || []).filter((signature) => signature.mode === "block").length;
      const signatureMonitors = (policy.signatures || []).filter((signature) => signature.mode === "monitor").length;

      document.getElementById("policy-summary-archives").textContent =
        `${archiveBlocks}/4 blocking`;
      document.getElementById("policy-summary-signatures").textContent =
        `${signatureBlocks} blocking · ${signatureMonitors} monitor`;
      document.getElementById("policy-summary-entropy").textContent =
        `${text(policy.entropy?.mode)} · threshold ${text(policy.entropy?.threshold)}`;
    }

    async function loadPolicies() {
      const response = await fetch("/api/policies", { headers: authHeaders() });
      if (response.status === 401) {
        localStorage.removeItem("axiomToken");
        window.location.href = "/login";
        return;
      }

      const policy = await response.json();
      renderSmbPolicySummary(policy);
      fillModeSelect("policy-smb-encrypted-payload", policy.smb.encrypted_payload);
      fillModeSelect("policy-rar", policy.archive.rar);
      fillModeSelect("policy-seven-zip", policy.archive.seven_zip);
      fillModeSelect("policy-zip", policy.archive.zip);
      fillModeSelect("policy-encrypted-zip", policy.archive.encrypted_zip);
      fillModeSelect("policy-entropy-mode", policy.entropy.mode);
      document.getElementById("policy-entropy-threshold").value = policy.entropy.threshold;
      document.getElementById("policy-entropy-minimum").value = policy.entropy.minimum_chunk_size;
      document.getElementById("policy-reputation-known-bad-action").value =
        policy.reputation?.known_bad_action || "alert";
      document.getElementById("policy-reputation-cache-ttl").value =
        policy.reputation?.cache_ttl_seconds || 3600;
      document.getElementById("policy-signatures").value = (policy.signatures || [])
        .map((signature) => `${signature.name}|${signature.mode}|${signature.pattern}`)
        .join("\n");
      document.getElementById("policy-state").textContent = "Policies loaded";
    }

    function linesToArray(id) {
      return document.getElementById(id).value
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean);
    }

    async function loadDnsPolicy() {
      const response = await fetch("/api/dns-policy", { headers: authHeaders() });
      if (response.status === 401) {
        localStorage.removeItem("axiomToken");
        window.location.href = "/login";
        return;
      }

      const policy = await response.json();
      fillModeSelect("dns-blocked-action", policy.blocked_domain_action);
      fillModeSelect("dns-monitored-action", policy.monitored_domain_action);
      document.getElementById("dns-block-response").value = policy.block_response || "nxdomain";
      document.getElementById("dns-blocked-domains").value = (policy.blocked_domains || []).join("\n");
      document.getElementById("dns-monitored-domains").value = (policy.monitored_domains || []).join("\n");
      document.getElementById("dns-threat-feeds").value = (policy.threat_feed_urls || []).join("\n");
      document.getElementById("dns-local-records").value = (policy.local_records || [])
        .map((record) => `${record.name}|${record.type}|${record.value}|${record.ttl_seconds || 300}`)
        .join("\n");
      document.getElementById("dns-policy-state").textContent = "DNS policy loaded";
    }

    async function loadReputationCenter() {
      const response = await fetch("/api/reputation", { headers: authHeaders() });
      const payload = await response.json().catch(() => ({ message: "reputation load failed" }));
      if (!response.ok) {
        document.getElementById("reputation-state").textContent = payload.message || "Reputation load failed";
        return;
      }

      reputationEntries = payload.entries || [];
      const summary = payload.summary || {};
      document.getElementById("rep-known-good").textContent = summary.known_good_count || 0;
      document.getElementById("rep-known-bad").textContent = summary.known_bad_count || 0;
      document.getElementById("rep-unknown").textContent = summary.unknown_count || 0;
      document.getElementById("rep-pending-scans").textContent = summary.pending_scans || 0;
      document.getElementById("reputation-state").textContent =
        `${summary.total_entries || reputationEntries.length} entries · ${summary.pending_scans || 0} pending scans`;
      renderReputationTable();
      renderReputationSimpleList("rep-top-seen", payload.top_seen_files || [], "No file reputation hits yet.");
      renderReputationObservations(payload.recent_observations || []);
    }

    function verdictClass(verdict) {
      if (verdict === "known_bad") return "text-red-200 border-red-400/40 bg-red-400/10";
      if (verdict === "known_good") return "text-emerald-200 border-emerald-400/40 bg-emerald-400/10";
      return "text-amber-200 border-amber-400/40 bg-amber-400/10";
    }

    function renderReputationTable() {
      const query = document.getElementById("reputation-search").value.trim().toLowerCase();
      const filter = document.getElementById("reputation-filter").value;
      const entries = reputationEntries
        .filter((entry) => filter === "all" || entry.verdict === filter)
        .filter((entry) => {
          if (!query) return true;
          return [entry.sha256, entry.md5, entry.verdict, entry.source, entry.notes]
            .filter(Boolean)
            .some((value) => String(value).toLowerCase().includes(query));
        })
        .slice(0, 100);

      const body = document.getElementById("reputation-table-body");
      if (!entries.length) {
        body.innerHTML = `<tr><td colspan="8" class="px-6 py-6 text-sm text-zinc-400">No reputation entries matched.</td></tr>`;
        return;
      }

      body.innerHTML = entries.map((entry) => `
        <tr>
          <td class="max-w-xs truncate px-6 py-4 font-mono text-xs text-zinc-200" title="${text(entry.sha256)}">${text(entry.sha256)}</td>
          <td class="px-6 py-4 font-mono text-xs text-zinc-400">${text(entry.md5)}</td>
          <td class="px-6 py-4"><span class="rounded-full border px-2.5 py-1 text-xs font-semibold ${verdictClass(entry.verdict)}">${text(entry.verdict)}</span></td>
          <td class="px-6 py-4 text-sm text-zinc-300">${text(entry.source)}</td>
          <td class="px-6 py-4 text-sm text-zinc-300">${entry.hit_count || 0}</td>
          <td class="px-6 py-4 text-sm text-zinc-400">${formatTime(entry.last_seen)}</td>
          <td class="max-w-sm truncate px-6 py-4 text-sm text-zinc-300" title="${text(entry.notes)}">${text(entry.notes)}</td>
          <td class="px-6 py-4"><button data-rep-delete="${entry.id}" class="rounded-md border border-red-400/40 px-2.5 py-1 text-xs font-semibold text-red-200 hover:bg-red-400/10">Delete</button></td>
        </tr>
      `).join("");

      document.querySelectorAll("[data-rep-delete]").forEach((button) => {
        button.addEventListener("click", () => deleteReputationEntry(button.dataset.repDelete));
      });
    }

    function renderReputationSimpleList(id, entries, emptyText) {
      const container = document.getElementById(id);
      if (!entries.length) {
        container.innerHTML = `<div class="px-6 py-5 text-sm text-zinc-400">${emptyText}</div>`;
        return;
      }
      container.innerHTML = entries.map((entry) => `
        <div class="px-6 py-4">
          <div class="flex items-center justify-between gap-4">
            <p class="truncate font-mono text-xs text-zinc-200">${text(entry.sha256)}</p>
            <span class="rounded-full border px-2.5 py-1 text-xs font-semibold ${verdictClass(entry.verdict)}">${text(entry.verdict)}</span>
          </div>
          <p class="mt-2 text-sm text-zinc-400">${entry.hit_count || 0} hits · last seen ${formatTime(entry.last_seen)}</p>
        </div>
      `).join("");
    }

    function renderReputationObservations(observations) {
      const container = document.getElementById("rep-recent-observations");
      if (!observations.length) {
        container.innerHTML = `<div class="px-6 py-5 text-sm text-zinc-400">No SMB file observations reported yet.</div>`;
        return;
      }
      container.innerHTML = observations.slice(0, 20).map((item) => `
        <div class="px-6 py-4">
          <div class="flex flex-wrap items-center gap-2">
            <span class="rounded-full border px-2.5 py-1 text-xs font-semibold ${verdictClass(item.verdict)}">${text(item.verdict)}</span>
            <p class="text-sm font-semibold text-white">${text(item.file_name)}</p>
          </div>
          <p class="mt-2 text-xs text-zinc-400">${text(item.source_ip)} → ${text(item.target_addr)} · ${formatBytes(item.file_size)} · ${formatTime(item.observed_at)}</p>
          <p class="mt-1 truncate font-mono text-xs text-zinc-500">${text(item.sha256)}</p>
        </div>
      `).join("");
    }

    async function addReputationEntry() {
      const button = document.getElementById("rep-add-button");
      const targets = nodeTargetsFor("smb");
      setButtonBusy(button, true, "Adding");
      beginPushProgress("Syncing reputation feed", targets);
      document.getElementById("reputation-state").textContent = "Adding reputation entry";
      setPushProgress(40, "Saving reputation entry on management server");
      try {
        const response = await fetch("/api/reputation", {
          method: "POST",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({
            sha256: document.getElementById("rep-add-sha256").value.trim(),
            md5: document.getElementById("rep-add-md5").value.trim() || null,
            verdict: document.getElementById("rep-add-verdict").value,
            notes: document.getElementById("rep-add-notes").value.trim(),
            source: "Administrator"
          })
        });
        const payload = await response.json().catch(() => ({ message: "add failed" }));
        if (!response.ok) {
          document.getElementById("reputation-state").textContent = payload.message || "Reputation add failed";
          failPushProgress(payload.message || "Reputation add failed");
          return;
        }
        document.getElementById("rep-add-sha256").value = "";
        document.getElementById("rep-add-md5").value = "";
        document.getElementById("rep-add-notes").value = "";
        document.getElementById("reputation-state").textContent =
          `Reputation entry saved · ${describePushResults(payload.node_push_results)}`;
        completePushProgress(payload.node_push_results, "Reputation entry saved locally");
        await loadReputationCenter();
        await refresh();
      } catch (error) {
        const message = `Reputation add failed: ${error.message || error}`;
        document.getElementById("reputation-state").textContent = message;
        failPushProgress(message);
      } finally {
        setButtonBusy(button, false);
      }
    }

    async function importReputationEntries() {
      const button = document.getElementById("rep-import-button");
      const targets = nodeTargetsFor("smb");
      setButtonBusy(button, true, "Importing");
      beginPushProgress("Importing and syncing reputation feed", targets);
      document.getElementById("reputation-state").textContent = "Importing reputation entries";
      setPushProgress(40, "Parsing and saving imported reputation entries");
      try {
        const response = await fetch("/api/reputation/import", {
          method: "POST",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({
            contents: document.getElementById("rep-import-contents").value,
            source: "Manual Import"
          })
        });
        const payload = await response.json().catch(() => ({ message: "import failed" }));
        if (!response.ok) {
          document.getElementById("reputation-state").textContent = payload.message || "Import failed";
          failPushProgress(payload.message || "Import failed");
          return;
        }
        document.getElementById("reputation-state").textContent =
          `Imported ${payload.imported || 0}, skipped ${payload.skipped || 0} · ${describePushResults(payload.node_push_results)}`;
        completePushProgress(payload.node_push_results, "Reputation import saved locally");
        await loadReputationCenter();
        await refresh();
      } catch (error) {
        const message = `Import failed: ${error.message || error}`;
        document.getElementById("reputation-state").textContent = message;
        failPushProgress(message);
      } finally {
        setButtonBusy(button, false);
      }
    }

    async function deleteReputationEntry(id) {
      if (!confirm("Delete this reputation entry?")) return;
      const targets = nodeTargetsFor("smb");
      beginPushProgress("Removing reputation entry and syncing feed", targets);
      document.getElementById("reputation-state").textContent = "Deleting reputation entry";
      setPushProgress(40, "Removing reputation entry on management server");
      try {
        const response = await fetch(`/api/reputation/${id}`, {
          method: "DELETE",
          headers: authHeaders()
        });
        const payload = await response.json().catch(() => ({ message: "delete failed" }));
        if (!response.ok) {
          document.getElementById("reputation-state").textContent = payload.message || "Delete failed";
          failPushProgress(payload.message || "Delete failed");
          return;
        }
        document.getElementById("reputation-state").textContent =
          `Reputation entry deleted · ${describePushResults(payload.node_push_results)}`;
        completePushProgress(payload.node_push_results, "Reputation entry deleted locally");
        await loadReputationCenter();
        await refresh();
      } catch (error) {
        const message = `Delete failed: ${error.message || error}`;
        document.getElementById("reputation-state").textContent = message;
        failPushProgress(message);
      }
    }

    async function loadEnrollmentToken() {
      const response = await fetch("/api/enrollment-token", { headers: authHeaders() });
      const payload = await response.json().catch(() => ({ message: "token load failed" }));
      if (!response.ok) {
        document.getElementById("enrollment-token-state").textContent = payload.message || "Token load failed";
        return;
      }

      document.getElementById("enrollment-token-value").value = payload.token || "";
      document.getElementById("enrollment-token-preview").textContent = payload.token_preview || "not configured";
      document.getElementById("enrollment-token-state").textContent =
        `${payload.reporting_nodes || 0} reporting nodes · management ${payload.management_url}`;
    }

    async function copyEnrollmentToken() {
      const value = document.getElementById("enrollment-token-value").value;
      if (!value) {
        document.getElementById("enrollment-token-state").textContent = "No enrollment token configured";
        return;
      }
      try {
        await navigator.clipboard.writeText(value);
        document.getElementById("enrollment-token-state").textContent = `Token copied · ${new Date().toLocaleTimeString()}`;
        showToast("Enrollment token copied", "Use it only during trusted node enrollment.", "success");
      } catch (_) {
        document.getElementById("enrollment-token-value").select();
        document.getElementById("enrollment-token-state").textContent = "Token selected";
        showToast("Enrollment token selected", "Copy it manually from the field.", "warning");
      }
    }

    async function rotateEnrollmentToken() {
      if (!confirm("Rotate the node enrollment token? Existing DNS and SMB nodes must be re-enrolled with the new token.")) {
        return;
      }

      document.getElementById("enrollment-token-state").textContent = "Rotating token";
      const response = await fetch("/api/enrollment-token/rotate", {
        method: "POST",
        headers: authHeaders()
      });
      const payload = await response.json().catch(() => ({ message: "token rotation failed" }));
      if (!response.ok) {
        document.getElementById("enrollment-token-state").textContent = payload.message || "Token rotation failed";
        return;
      }

      document.getElementById("enrollment-token-value").value = payload.token || "";
      document.getElementById("enrollment-token-preview").textContent = payload.token_preview || "rotated";
      document.getElementById("enrollment-token-state").textContent = `Token rotated · management ${payload.management_url}`;
      showToast("Enrollment token rotated", "Existing nodes must be re-enrolled with the new token.", "warning");
      await refresh();
    }

    async function copyLicenseRequest() {
      const value = document.getElementById("license-activation-request").value;
      if (!value) {
        document.getElementById("license-install-state").textContent = "Activation request is not ready yet";
        return;
      }

      try {
        await navigator.clipboard.writeText(value);
        document.getElementById("license-install-state").textContent = `Activation request copied · ${new Date().toLocaleTimeString()}`;
        showToast("Activation request copied", "Upload it to the customer portal to issue a license.", "success");
      } catch (_) {
        document.getElementById("license-activation-request").select();
        document.getElementById("license-install-state").textContent = "Activation request selected";
        showToast("Activation request selected", "Copy it manually from the field.", "warning");
      }
    }

    function safeFilePart(value) {
      return text(value)
        .toLowerCase()
        .replace(/[^a-z0-9._-]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 48) || "axiom";
    }

    function downloadTextFile(filename, contents, mimeType) {
      const blob = new Blob([contents], { type: mimeType || "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    }

    function downloadActivationFile() {
      const activationFile = activationFilePayload(latestLicenseStatus);
      if (!activationFile) {
        document.getElementById("license-install-state").textContent = "Activation file is not ready yet";
        return;
      }

      const request = activationFile.activation_request || {};
      const fingerprint = safeFilePart(request.machine_fingerprint || "unknown").slice(0, 12);
      const hostname = safeFilePart(request.hostname || "management");
      const filename = `axiom-${hostname}-${fingerprint}.axact`;
      downloadTextFile(filename, JSON.stringify(activationFile, null, 2), "application/vnd.axiom.activation+json");
      document.getElementById("license-install-state").textContent = `Activation file downloaded · ${new Date().toLocaleTimeString()}`;
      showToast("Activation file downloaded", filename, "success");
    }

    async function submitLicenseText(licenseText, successMessage) {
      if (!licenseText) {
        document.getElementById("license-install-state").textContent = "Choose or paste a signed license package first";
        return;
      }

      document.getElementById("license-install-state").textContent = "Installing license";
      const response = await fetch("/api/license", {
        method: "PUT",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ license_text: licenseText })
      });
      const payload = await response.json().catch(() => ({ message: "license install failed" }));
      if (!response.ok) {
        document.getElementById("license-install-state").textContent = payload.message || "License install failed";
        showToast("License install failed", payload.message || "License install failed", "error");
        return;
      }

      updateLicenseUi(payload);
      document.getElementById("license-install-state").textContent = successMessage || `License installed · ${new Date().toLocaleTimeString()}`;
      showToast("License installed", payload.message || "Axiom license is active.", "success");
      await refresh();
    }

    async function installPastedLicense() {
      const licenseText = document.getElementById("license-install-text").value.trim();
      await submitLicenseText(licenseText, `Pasted license installed · ${new Date().toLocaleTimeString()}`);
      document.getElementById("license-install-text").value = "";
    }

    async function installLicenseFile() {
      const input = document.getElementById("license-file-input");
      const file = input.files && input.files[0];
      if (!file) {
        document.getElementById("license-install-state").textContent = "Choose an .axlic license file first";
        return;
      }

      const licenseText = await file.text();
      await submitLicenseText(licenseText.trim(), `License file ${file.name} installed · ${new Date().toLocaleTimeString()}`);
      input.value = "";
    }

    function readDnsPolicyPayload() {
      const localRecords = linesToArray("dns-local-records").map((line) => {
        const [name, recordType, value, ttl] = line.split("|").map((part) => (part || "").trim());
        return {
          name,
          type: (recordType || "a").toLowerCase(),
          value,
          ttl_seconds: Number(ttl || 300)
        };
      }).filter((record) => record.name && record.value);

      return {
        blocked_domain_action: document.getElementById("dns-blocked-action").value,
        monitored_domain_action: document.getElementById("dns-monitored-action").value,
        blocked_domains: linesToArray("dns-blocked-domains"),
        monitored_domains: linesToArray("dns-monitored-domains"),
        threat_feed_urls: linesToArray("dns-threat-feeds"),
        block_response: document.getElementById("dns-block-response").value,
        sinkhole_ipv4: "0.0.0.0",
        local_records: localRecords
      };
    }

    async function saveDnsPolicy() {
      const button = document.getElementById("save-dns-policy");
      const targets = nodeTargetsFor("dns");
      setButtonBusy(button, true, "Applying");
      beginPushProgress("Applying DNS policy", targets);
      document.getElementById("dns-policy-state").textContent = "Saving DNS policy";
      setPushProgress(42, "Persisting DNS policy on management server");
      try {
        const response = await fetch("/api/dns-policy", {
          method: "PUT",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify(readDnsPolicyPayload())
        });

        const payload = await response.json().catch(() => ({ message: "DNS policy save failed" }));
        if (!response.ok) {
          document.getElementById("dns-policy-state").textContent = payload.message || "DNS policy save failed";
          failPushProgress(payload.message || "DNS policy save failed");
          return;
        }

        setPushProgress(78, "Waiting for node acknowledgements");
        await loadDnsPolicy();
        const pushSummary = describePushResults(payload.node_push_results);
        document.getElementById("dns-policy-state").textContent =
          `Saved and active on PID ${payload.process_id} · generation ${payload.dns_policy_runtime.generation} · ${pushSummary}`;
        completePushProgress(payload.node_push_results, "DNS policy saved locally");
        await refresh();
      } catch (error) {
        const message = `DNS policy save failed: ${error.message || error}`;
        document.getElementById("dns-policy-state").textContent = message;
        failPushProgress(message);
      } finally {
        setButtonBusy(button, false);
      }
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
        reputation: {
          enabled: true,
          known_bad_action: document.getElementById("policy-reputation-known-bad-action").value,
          cache_ttl_seconds: Number(document.getElementById("policy-reputation-cache-ttl").value || 3600)
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
        document.getElementById("policy-reputation-known-bad-action").value = "alert";
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
        document.getElementById("policy-reputation-known-bad-action").value = "alert";
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
        document.getElementById("policy-reputation-known-bad-action").value = "block";
        document.getElementById("policy-entropy-threshold").value = "7.5";
        document.getElementById("policy-entropy-minimum").value = "2048";
      }

      document.getElementById("policy-state").textContent = `${name} preset selected; save to apply`;
    }

    function describePushResults(results) {
      const items = Array.isArray(results) ? results : [];
      if (!items.length) {
        return "no remote nodes targeted";
      }

      const accepted = items.filter((item) => item.accepted).length;
      const failed = items.length - accepted;
      const failures = items
        .filter((item) => !item.accepted)
        .slice(0, 2)
        .map((item) => `${item.node_id}: ${item.message}`)
        .join(" · ");

      if (failed === 0) {
        return `pushed to ${accepted}/${items.length} remote nodes`;
      }

      return `pushed to ${accepted}/${items.length} remote nodes · ${failures}`;
    }

    async function savePolicies() {
      const button = document.getElementById("save-policies");
      const targets = nodeTargetsFor("smb");
      setButtonBusy(button, true, "Applying");
      beginPushProgress("Applying SMB policy and reputation feed", targets);
      document.getElementById("policy-state").textContent = "Saving policies";
      setPushProgress(42, "Persisting SMB policy on management server");
      try {
        const response = await fetch("/api/policies", {
          method: "PUT",
          headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify(readPolicyPayload())
        });

        const payload = await response.json().catch(() => ({ message: "save failed" }));
        if (!response.ok) {
          document.getElementById("policy-state").textContent = payload.message || "Policy save failed";
          failPushProgress(payload.message || "Policy save failed");
          return;
        }

        setPushProgress(78, "Waiting for SMB node acknowledgements");
        await loadPolicies();
        renderPolicyRuntime(payload.policy_runtime);
        const pushSummary = describePushResults(payload.node_push_results);
        document.getElementById("policy-state").textContent =
          `Saved and active on PID ${payload.process_id} · generation ${payload.policy_runtime.generation} · ${pushSummary}`;
        completePushProgress(payload.node_push_results, "SMB policy saved locally");
        await refresh();
      } catch (error) {
        const message = `Policy save failed: ${error.message || error}`;
        document.getElementById("policy-state").textContent = message;
        failPushProgress(message);
      } finally {
        setButtonBusy(button, false);
      }
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
        showToast("Self-test failed", payload.message || "Policy self-test failed.", "error");
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
      showToast("Policy self-test completed", `${(payload.results || []).length} checks evaluated.`, "success");
    }

    async function loadDiagnostics(silent = false) {
      document.getElementById("diagnostics-state").textContent = "Loading diagnostics";
      const response = await fetch("/api/diagnostics", { headers: authHeaders() });
      const payload = await response.json().catch(() => ({ message: "diagnostics failed" }));

      if (!response.ok) {
        document.getElementById("diagnostics-state").textContent = payload.message || "Diagnostics failed";
        if (!silent) showToast("Diagnostics failed", payload.message || "Diagnostics request failed.", "error");
        return null;
      }

      const status = payload.status || {};
      const important = {
        process_id: payload.process_id,
        executable_path: payload.executable_path,
        config_path: payload.config_path,
        node: payload.node,
        fleet_nodes: payload.fleet_nodes,
        deployment_warnings: payload.deployment_warnings,
        proxy_listeners: payload.proxy_listeners,
        dns: payload.dns,
        route_stats: status.route_stats || [],
        active_connection_details: status.active_connection_details || [],
        file_activity: status.file_activity || [],
        recent_dns_events: status.recent_dns_events || [],
        commands: payload.command_outputs
      };

      latestDiagnosticsBundle = {
        format: "axiom_support_bundle_v1",
        generated_at: new Date().toISOString(),
        generated_by: "Axiom Management Console",
        diagnostics: important
      };

      document.getElementById("diagnostics-output").textContent = JSON.stringify(latestDiagnosticsBundle, null, 2);
      document.getElementById("diagnostics-state").textContent = `Diagnostics loaded · ${new Date().toLocaleTimeString()}`;
      if (!silent) showToast("Diagnostics loaded", "Deployment and service state were refreshed.", "success");
      return latestDiagnosticsBundle;
    }

    async function exportSupportBundle() {
      const button = document.getElementById("export-support-bundle");
      setButtonBusy(button, true, "Exporting");
      try {
        const bundle = latestDiagnosticsBundle || await loadDiagnostics(true);
        if (!bundle) {
          showToast("Support bundle failed", "Diagnostics could not be loaded.", "error");
          return;
        }

        const node = bundle.diagnostics?.node || {};
        const label = safeFilePart(node.display_name || node.node_id || node.role || "management");
        const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
        const filename = `axiom-support-${label}-${timestamp}.json`;
        downloadTextFile(filename, JSON.stringify(bundle, null, 2), "application/json");
        document.getElementById("diagnostics-state").textContent = `Support bundle exported · ${new Date().toLocaleTimeString()}`;
        showToast("Support bundle exported", filename, "success");
      } catch (error) {
        const message = `Support bundle export failed: ${error.message || error}`;
        document.getElementById("diagnostics-state").textContent = message;
        showToast("Support bundle failed", message, "error");
      } finally {
        setButtonBusy(button, false);
      }
    }

    function updateTlsSettingsUi(security, bindAddr) {
      const certInput = document.getElementById("tls-cert-path");
      const keyInput = document.getElementById("tls-key-path");
      const nextLink = document.getElementById("tls-next-url");

      if (certInput && security.cert_path && document.activeElement !== certInput && !certInput.value) {
        certInput.value = security.cert_path;
      }
      if (keyInput && security.key_path && document.activeElement !== keyInput && !keyInput.value) {
        keyInput.value = security.key_path;
      }

      document.getElementById("https-status").textContent = security.https_enabled
        ? `HTTPS active at ${bindAddr}`
        : `HTTP active at ${bindAddr}; HTTPS can be enabled here`;

      document.getElementById("tls-restart-command").textContent =
        security.restart_command || "sudo systemctl restart axiom.service";

      const nextUrl = security.https_enabled ? security.https_url : security.http_url;
      if (nextUrl) {
        nextLink.href = nextUrl;
        nextLink.textContent = `Open ${nextUrl}`;
        nextLink.classList.remove("hidden");
      }
    }

    async function saveTlsSettings(enabled) {
      const certPath = document.getElementById("tls-cert-path").value.trim();
      const keyPath = document.getElementById("tls-key-path").value.trim();
      const nextLink = document.getElementById("tls-next-url");

      document.getElementById("https-status").textContent = enabled
        ? "Saving HTTPS settings and restarting Axiom"
        : "Saving HTTP settings and restarting Axiom";

      const response = await fetch("/api/management/tls", {
        method: "PUT",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          enabled,
          cert_path: certPath,
          key_path: keyPath,
          restart_service: true
        })
      });

      const payload = await response.json().catch(() => ({
        message: "TLS settings request failed"
      }));

      if (!response.ok) {
        document.getElementById("https-status").textContent = payload.message || "TLS settings were rejected";
        showToast("TLS update failed", payload.message || "TLS settings were rejected.", "error");
        return;
      }

      if (payload.cert_path) {
        document.getElementById("tls-cert-path").value = payload.cert_path;
      }
      if (payload.key_path) {
        document.getElementById("tls-key-path").value = payload.key_path;
      }

      document.getElementById("https-status").textContent =
        `${payload.message}. Open the updated URL after the service comes back.`;
      if (payload.next_url) {
        nextLink.href = payload.next_url;
        nextLink.textContent = `Open ${payload.next_url}`;
        nextLink.classList.remove("hidden");
      }
      document.getElementById("tls-restart-command").textContent =
        payload.restart_command || "sudo systemctl restart axiom.service";
      showToast(
        enabled ? "HTTPS activation scheduled" : "HTTP mode scheduled",
        payload.next_url ? `Open ${payload.next_url} after restart.` : payload.message,
        "warning"
      );
    }

    function applyTheme(theme) {
      const selected = theme || "system";
      const effective = selected === "system"
        ? (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")
        : selected;
      document.documentElement.dataset.theme = effective;
      document.documentElement.dataset.themePreference = selected;
    }

    function loadLocalSettings() {
      document.getElementById("settings-display-name").value =
        localStorage.getItem("axiomDisplayName") || "Axiom Administrator";
      const theme = localStorage.getItem("axiomTheme") || "system";
      document.getElementById("settings-theme").value = theme;
      applyTheme(theme);
    }

    function saveLocalSettings() {
      localStorage.setItem("axiomDisplayName", document.getElementById("settings-display-name").value.trim() || "Axiom Administrator");
      const theme = document.getElementById("settings-theme").value;
      localStorage.setItem("axiomTheme", theme);
      applyTheme(theme);
      document.getElementById("settings-state").textContent = `Settings saved locally · ${new Date().toLocaleTimeString()}`;
      showToast("Settings saved", "Local display preferences were updated.", "success");
    }

    document.getElementById("logout").addEventListener("click", async () => {
      await fetch("/api/logout", { method: "POST" });
      localStorage.removeItem("axiomToken");
      window.location.href = "/login";
    });
    document.getElementById("save-policies").addEventListener("click", savePolicies);
    document.getElementById("save-dns-policy").addEventListener("click", saveDnsPolicy);
    document.getElementById("run-policy-self-test").addEventListener("click", runPolicySelfTest);
    document.getElementById("load-diagnostics").addEventListener("click", () => loadDiagnostics());
    document.getElementById("export-support-bundle").addEventListener("click", exportSupportBundle);
    document.getElementById("save-settings").addEventListener("click", saveLocalSettings);
    document.getElementById("copy-enrollment-token").addEventListener("click", copyEnrollmentToken);
    document.getElementById("rotate-enrollment-token").addEventListener("click", rotateEnrollmentToken);
    document.getElementById("download-activation-file").addEventListener("click", downloadActivationFile);
    document.getElementById("install-license-file").addEventListener("click", installLicenseFile);
    document.getElementById("copy-license-request").addEventListener("click", copyLicenseRequest);
    document.getElementById("install-license").addEventListener("click", installPastedLicense);
    document.getElementById("enable-https").addEventListener("click", () => saveTlsSettings(true));
    document.getElementById("disable-https").addEventListener("click", () => saveTlsSettings(false));
    document.getElementById("settings-theme").addEventListener("change", (event) => applyTheme(event.target.value));
    document.getElementById("rep-add-button").addEventListener("click", addReputationEntry);
    document.getElementById("rep-import-button").addEventListener("click", importReputationEntries);
    document.getElementById("reputation-search").addEventListener("input", renderReputationTable);
    document.getElementById("reputation-filter").addEventListener("change", renderReputationTable);
    document.querySelectorAll(".top-nav-button").forEach((button) => {
      button.addEventListener("click", () => setActiveView(button.dataset.view));
    });
    document.querySelectorAll(".policy-preset").forEach((button) => {
      button.addEventListener("click", () => applyPreset(button.dataset.preset));
    });

    setActiveView(localStorage.getItem("axiomDashboardView") || "overview");
    loadLocalSettings();
    refresh();
    loadPolicies();
    loadDnsPolicy();
    loadReputationCenter();
    loadEnrollmentToken();
    setInterval(refresh, 2000);
  </script>
</body>
</html>
"##;
