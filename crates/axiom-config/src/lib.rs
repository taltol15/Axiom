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
    pub policy: PolicyConfig,
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
        self.policy.validate()?;

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
pub struct PolicyConfig {
    #[serde(default)]
    pub archive: ArchivePolicyConfig,
    #[serde(default)]
    pub entropy: EntropyPolicyConfig,
    #[serde(default = "default_signatures")]
    pub signatures: Vec<SignaturePolicyConfig>,
}

impl PolicyConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.entropy.validate()?;

        for signature in &self.signatures {
            signature.validate()?;
        }

        Ok(())
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            archive: ArchivePolicyConfig::default(),
            entropy: EntropyPolicyConfig::default(),
            signatures: default_signatures(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ArchivePolicyConfig {
    #[serde(default = "default_block_mode")]
    pub rar: PolicyMode,
    #[serde(default = "default_block_mode")]
    pub seven_zip: PolicyMode,
    #[serde(default = "default_monitor_mode")]
    pub zip: PolicyMode,
    #[serde(default = "default_block_mode")]
    pub encrypted_zip: PolicyMode,
}

impl Default for ArchivePolicyConfig {
    fn default() -> Self {
        Self {
            rar: PolicyMode::Block,
            seven_zip: PolicyMode::Block,
            zip: PolicyMode::Monitor,
            encrypted_zip: PolicyMode::Block,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EntropyPolicyConfig {
    #[serde(default = "default_monitor_mode")]
    pub mode: PolicyMode,
    #[serde(default = "default_entropy_threshold")]
    pub threshold: f64,
    #[serde(default = "default_entropy_minimum_chunk_size")]
    pub minimum_chunk_size: usize,
}

impl EntropyPolicyConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !(0.0..=8.0).contains(&self.threshold) {
            return Err(ConfigError::Invalid(
                "policy.entropy.threshold must be between 0.0 and 8.0".to_string(),
            ));
        }

        if self.minimum_chunk_size == 0 {
            return Err(ConfigError::Invalid(
                "policy.entropy.minimum_chunk_size must be greater than zero".to_string(),
            ));
        }

        Ok(())
    }
}

impl Default for EntropyPolicyConfig {
    fn default() -> Self {
        Self {
            mode: PolicyMode::Monitor,
            threshold: default_entropy_threshold(),
            minimum_chunk_size: default_entropy_minimum_chunk_size(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignaturePolicyConfig {
    pub name: String,
    pub pattern: String,
    #[serde(default = "default_block_mode")]
    pub mode: PolicyMode,
}

impl SignaturePolicyConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.name.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "policy.signatures name must not be empty".to_string(),
            ));
        }

        if self.pattern.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "policy.signatures '{}' pattern must not be empty",
                self.name
            )));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    Disabled,
    Monitor,
    Block,
}

impl PolicyMode {
    pub fn is_enabled(self) -> bool {
        self != Self::Disabled
    }

    pub fn is_blocking(self) -> bool {
        self == Self::Block
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

fn default_block_mode() -> PolicyMode {
    PolicyMode::Block
}

fn default_monitor_mode() -> PolicyMode {
    PolicyMode::Monitor
}

fn default_entropy_threshold() -> f64 {
    7.90
}

fn default_entropy_minimum_chunk_size() -> usize {
    8 * 1024
}

fn default_signatures() -> Vec<SignaturePolicyConfig> {
    vec![
        SignaturePolicyConfig {
            name: "Axiom synthetic test marker".to_string(),
            pattern: "AXIOM_TEST_THREAT".to_string(),
            mode: PolicyMode::Block,
        },
        SignaturePolicyConfig {
            name: "WannaCry marker WNCRY".to_string(),
            pattern: "WNCRY".to_string(),
            mode: PolicyMode::Block,
        },
        SignaturePolicyConfig {
            name: "WannaCry marker WANACRY".to_string(),
            pattern: "WANACRY!".to_string(),
            mode: PolicyMode::Block,
        },
    ]
}
