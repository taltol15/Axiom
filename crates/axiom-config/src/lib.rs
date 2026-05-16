use std::{
    collections::HashSet,
    fs,
    net::{IpAddr, SocketAddr},
    path::Path,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AxiomConfig {
    pub management: ManagementNicConfig,
    #[serde(default)]
    pub proxy_listeners: Vec<ProxyNicConfig>,
}

impl AxiomConfig {
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;

        let config: Self = toml::from_str(&contents).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.management.validate()?;

        if self.proxy_listeners.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one proxy listener must be configured".to_string(),
            ));
        }

        let mut listener_names = HashSet::new();
        let mut listener_bindings = HashSet::new();

        for listener in &self.proxy_listeners {
            listener.validate()?;

            if !listener_names.insert(listener.name.clone()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate proxy listener name '{}'",
                    listener.name
                )));
            }

            let binding_key = (
                listener.source_interface.clone(),
                listener.listen_ip,
                listener.listen_port,
            );
            if !listener_bindings.insert(binding_key) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate proxy binding on interface '{}' at {}",
                    listener.source_interface,
                    listener.listen_addr()
                )));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ManagementNicConfig {
    pub interface: String,
    pub bind_ip: IpAddr,
    #[serde(default = "default_management_port")]
    pub port: u16,
    pub admin: AdminCredentials,
}

impl ManagementNicConfig {
    pub fn listen_addr(&self) -> SocketAddr {
        SocketAddr::new(self.bind_ip, self.port)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        validate_interface_name(&self.interface, "management interface")?;
        if self.port == 0 {
            return Err(ConfigError::Invalid(
                "management port must be greater than zero".to_string(),
            ));
        }
        self.admin.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdminCredentials {
    pub username: String,
    pub password_hash: String,
}

impl AdminCredentials {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.username.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "management admin username must not be empty".to_string(),
            ));
        }

        if !self.password_hash.starts_with("sha256$") {
            return Err(ConfigError::Invalid(
                "management admin password_hash must use sha256$salt$hash format".to_string(),
            ));
        }

        let parts: Vec<_> = self.password_hash.split('$').collect();
        if parts.len() != 3 || parts[1].is_empty() || parts[2].len() != 64 {
            return Err(ConfigError::Invalid(
                "management admin password_hash must use sha256$salt$64_hex_hash format"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyNicConfig {
    pub name: String,
    pub source_interface: String,
    pub client_vlan: Option<u16>,
    pub listen_ip: IpAddr,
    #[serde(default = "default_smb_port")]
    pub listen_port: u16,
    pub target_file_server_ip: IpAddr,
    #[serde(default = "default_smb_port")]
    pub target_file_server_port: u16,
    #[serde(default = "default_backlog")]
    pub backlog: i32,
}

impl ProxyNicConfig {
    pub fn listen_addr(&self) -> SocketAddr {
        SocketAddr::new(self.listen_ip, self.listen_port)
    }

    pub fn target_addr(&self) -> SocketAddr {
        SocketAddr::new(self.target_file_server_ip, self.target_file_server_port)
    }

    pub fn interface(&self) -> &str {
        &self.source_interface
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.name.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "proxy listener name must not be empty".to_string(),
            ));
        }

        validate_interface_name(&self.source_interface, "proxy source interface")?;

        if self.listen_port == 0 {
            return Err(ConfigError::Invalid(format!(
                "proxy listener '{}' has invalid listen_port 0",
                self.name
            )));
        }

        if self.target_file_server_port == 0 {
            return Err(ConfigError::Invalid(format!(
                "proxy listener '{}' has invalid target_file_server_port 0",
                self.name
            )));
        }

        if self.backlog <= 0 {
            return Err(ConfigError::Invalid(format!(
                "proxy listener '{}' must use a positive backlog",
                self.name
            )));
        }

        Ok(())
    }
}

pub type ProxyListenerConfig = ProxyNicConfig;
pub type ManagementConfig = ManagementNicConfig;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed reading config '{path}': {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("failed parsing config: {0}")]
    Parse(toml::de::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

fn validate_interface_name(interface: &str, label: &str) -> Result<(), ConfigError> {
    if interface.trim().is_empty() {
        return Err(ConfigError::Invalid(format!("{label} must not be empty")));
    }

    if interface.as_bytes().contains(&0) {
        return Err(ConfigError::Invalid(format!(
            "{label} must not contain null bytes"
        )));
    }

    Ok(())
}

fn default_smb_port() -> u16 {
    445
}

fn default_management_port() -> u16 {
    8443
}

fn default_backlog() -> i32 {
    4096
}
