use std::{env, path::PathBuf, sync::Arc};

use anyhow::Context;
use axiom_config::AxiomConfig;
use axiom_core::{RuntimeState, StreamPolicy};
use tokio::task::JoinSet;
use tracing::{error, info};
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

    let web_config = config.clone();
    let web_runtime = Arc::clone(&runtime);
    tasks.spawn(async move {
        axiom_web::run_management_server(config_path, web_config, web_runtime).await
    });

    for proxy_listener in config.proxy_listeners.clone() {
        let proxy_runtime = Arc::clone(&runtime);
        tasks.spawn(
            async move { axiom_net::run_proxy_listener(proxy_listener, proxy_runtime).await },
        );
    }

    if config.dns.enabled {
        let dns_config = config.dns.clone();
        let dns_runtime = Arc::clone(&runtime);
        tasks.spawn(async move { axiom_dns::run_dns_gateway(dns_config, dns_runtime).await });
    }

    info!(
        management_interface = config.management.interface,
        management_addr = %config.management.listen_addr(),
        proxy_listener_count = config.proxy_listeners.len(),
        dns_enabled = config.dns.enabled,
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

fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("axiom=info,axiom_daemon=info,axiom_dns=info")),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}
