use std::{env, fs, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context;
use axiom_config::{AxiomConfig, DnsConfig, ProxyListenerConfig};
use axiom_core::{RuntimeState, StreamPolicy};
use serde_json::json;
use tokio::task::JoinSet;
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "config/axiom.toml".to_string());
    let config = AxiomConfig::load_from_path(&config_path)
        .with_context(|| format!("failed loading Axiom config from '{config_path}'"))?;

    let config_path = PathBuf::from(config_path);
    let runtime = Arc::new(RuntimeState::new(
        StreamPolicy::from_config(config.policy.clone()),
        config.dns.policy.clone(),
    ));
    let mut tasks = JoinSet::new();

    if config.node.role.runs_management() {
        let web_config = config.clone();
        let web_runtime = Arc::clone(&runtime);
        tasks.spawn(async move {
            axiom_web::run_management_server(config_path, web_config, web_runtime).await
        });
    }

    if config.node.role.runs_smb_proxy() {
        for proxy_listener in config.proxy_listeners.clone() {
            let proxy_runtime = Arc::clone(&runtime);
            tasks.spawn(async move {
                axiom_net::run_proxy_listener(proxy_listener, proxy_runtime).await
            });
        }
    }

    if config.node.role.runs_dns() && config.dns.enabled {
        let dns_config = config.dns.clone();
        let dns_runtime = Arc::clone(&runtime);
        tasks.spawn(async move { axiom_dns::run_dns_gateway(dns_config, dns_runtime).await });
    }

    if config.node.role.runs_agent() {
        let agent_config = config.clone();
        let agent_runtime = Arc::clone(&runtime);
        tasks.spawn(async move { run_node_agent(agent_config, agent_runtime).await });
    }

    info!(
        role = config.node.role.as_str(),
        node_id = config.node.node_id,
        management_interface = config.management.interface,
        management_addr = %config.management.listen_addr(),
        proxy_listener_count = if config.node.role.runs_smb_proxy() { config.proxy_listeners.len() } else { 0 },
        dns_enabled = config.node.role.runs_dns() && config.dns.enabled,
        "Axiom daemon started"
    );

    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal.context("failed waiting for Ctrl+C")?;
            info!("shutdown signal received");
        }
        task_result = tasks.join_next() => {
            match task_result {
                Some(Ok(Ok(()))) => {
                    info!("Axiom task exited cleanly");
                }
                Some(Ok(Err(error))) => {
                    error!(?error, "Axiom task failed");
                    tasks.abort_all();
                    return Err(error);
                }
                Some(Err(error)) => {
                    error!(?error, "Axiom task panicked");
                    tasks.abort_all();
                    return Err(error.into());
                }
                None => {
                    info!("all Axiom tasks exited");
                }
            }
        }
    }

    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    info!("Axiom daemon stopped");
    Ok(())
}

async fn run_node_agent(config: AxiomConfig, runtime: Arc<RuntimeState>) -> anyhow::Result<()> {
    let management_url = config
        .node
        .management_url
        .as_deref()
        .context("node.management_url is required for agent roles")?
        .trim_end_matches('/')
        .to_string();
    let enrollment_token = config
        .node
        .enrollment_token
        .as_deref()
        .context("node.enrollment_token is required for agent roles")?
        .to_string();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(6))
        .user_agent("AxiomNodeAgent/0.1")
        .build()
        .context("failed building node agent HTTP client")?;
    let mut interval = tokio::time::interval(Duration::from_secs(
        config.node.heartbeat_interval_seconds.max(1),
    ));

    info!(
        node_id = config.node.node_id,
        role = config.node.role.as_str(),
        management_url,
        "Axiom node agent started"
    );

    loop {
        interval.tick().await;

        if let Err(error) =
            pull_runtime_config(&client, &management_url, &enrollment_token, &runtime).await
        {
            warn!(
                ?error,
                "failed pulling runtime config from management server"
            );
        }

        if let Err(error) = post_node_report(
            &client,
            &management_url,
            &enrollment_token,
            &config,
            &runtime,
        )
        .await
        {
            warn!(?error, "failed posting node report to management server");
        }
    }
}

async fn pull_runtime_config(
    client: &reqwest::Client,
    management_url: &str,
    enrollment_token: &str,
    runtime: &RuntimeState,
) -> anyhow::Result<()> {
    let response = client
        .get(format!("{management_url}/api/nodes/runtime-config"))
        .bearer_auth(enrollment_token)
        .send()
        .await
        .context("runtime config request failed")?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "management returned HTTP {} for runtime config",
            response.status()
        ));
    }

    let payload: serde_json::Value = response
        .json()
        .await
        .context("failed decoding runtime config response")?;

    if let Some(policy_value) = payload.pointer("/policy_runtime/active_policy") {
        let policy = serde_json::from_value(policy_value.clone())
            .context("failed decoding SMB policy from management")?;
        runtime.update_policy(policy);
    }

    if let Some(dns_policy_value) = payload.pointer("/dns_policy_runtime/active_policy") {
        let dns_policy = serde_json::from_value(dns_policy_value.clone())
            .context("failed decoding DNS policy from management")?;
        runtime.update_dns_policy(dns_policy);
    }

    Ok(())
}

async fn post_node_report(
    client: &reqwest::Client,
    management_url: &str,
    enrollment_token: &str,
    config: &AxiomConfig,
    runtime: &RuntimeState,
) -> anyhow::Result<()> {
    let report = json!({
        "node_id": config.node.node_id,
        "display_name": config.node.display_name,
        "role": config.node.role,
        "hostname": hostname(),
        "version": env!("CARGO_PKG_VERSION"),
        "management_url": config.node.management_url,
        "proxy_listeners": config.proxy_listeners.iter().map(proxy_listener_status).collect::<Vec<_>>(),
        "dns": dns_status(&config.dns),
        "stats": runtime.snapshot(),
    });

    let response = client
        .post(format!("{management_url}/api/nodes/report"))
        .bearer_auth(enrollment_token)
        .json(&report)
        .send()
        .await
        .context("node report request failed")?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "management returned HTTP {} for node report",
            response.status()
        ));
    }

    Ok(())
}

fn proxy_listener_status(listener: &ProxyListenerConfig) -> serde_json::Value {
    json!({
        "name": listener.name,
        "source_interface": listener.source_interface,
        "client_vlan": listener.client_vlan,
        "listen_addr": listener.listen_addr().to_string(),
        "target_file_server_addr": listener.target_addr().to_string(),
    })
}

fn dns_status(dns: &DnsConfig) -> serde_json::Value {
    json!({
        "enabled": dns.enabled,
        "interface": dns.interface,
        "listen_udp_addr": dns.udp_listen_addr().to_string(),
        "listen_tcp_addr": dns.tcp_listen_addr().to_string(),
        "upstream_interface": dns.upstream_interface(),
        "upstreams": dns.upstreams.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "threat_feed_urls": dns.policy.threat_feed_urls,
        "blocked_domains": dns.policy.blocked_domains.len(),
        "monitored_domains": dns.policy.monitored_domains.len(),
        "local_records": dns.policy.local_records.len(),
        "block_response": format!("{:?}", dns.policy.block_response).to_ascii_lowercase(),
        "deployment_warnings": Vec::<String>::new(),
    })
}

fn hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .map(|value| value.trim().to_string())
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("axiom=info,axiom_daemon=info,axiom_dns=info")),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}
