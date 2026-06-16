use std::{
    collections::HashSet,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
};

use axiom_reputation::KnownBadAction;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AxiomConfig {
    #[serde(default)]
    pub node: NodeConfig,
    pub management: ManagementNicConfig,
    #[serde(default)]
    pub dns: DnsConfig,
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
        self.node.validate()?;
        self.management.validate()?;
        self.policy.validate()?;

        self.dns.validate()?;

        match self.node.role {
            NodeRole::Management => {}
            NodeRole::Dns => {
                if !self.dns.enabled {
                    return Err(ConfigError::Invalid(
                        "dns role requires dns.enabled = true".to_string(),
                    ));
                }
                self.node.validate_agent_registration()?;
            }
            NodeRole::SmbProxy => {
                if self.proxy_listeners.is_empty() {
                    return Err(ConfigError::Invalid(
                        "smb_proxy role requires at least one proxy listener".to_string(),
                    ));
                }
                self.node.validate_agent_registration()?;
            }
            NodeRole::StandaloneLab => {
                if self.proxy_listeners.is_empty() && !self.dns.enabled {
                    return Err(ConfigError::Invalid(
                        "standalone_lab role requires at least one SMB proxy listener or DNS gateway"
                            .to_string(),
                    ));
                }
            }
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
pub struct NodeConfig {
    #[serde(default)]
    pub role: NodeRole,
    #[serde(default = "default_node_id")]
    pub node_id: String,
    #[serde(default = "default_node_display_name")]
    pub display_name: String,
    #[serde(default)]
    pub management_url: Option<String>,
    #[serde(default)]
    pub enrollment_token: Option<String>,
    #[serde(default)]
    pub allow_invalid_management_tls: bool,
    #[serde(default = "default_heartbeat_interval_seconds")]
    pub heartbeat_interval_seconds: u64,
    #[serde(default)]
    pub control: NodeControlConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            role: NodeRole::StandaloneLab,
            node_id: default_node_id(),
            display_name: default_node_display_name(),
            management_url: None,
            enrollment_token: None,
            allow_invalid_management_tls: false,
            heartbeat_interval_seconds: default_heartbeat_interval_seconds(),
            control: NodeControlConfig::default(),
        }
    }
}

impl NodeConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.node_id.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "node.node_id must not be empty".to_string(),
            ));
        }

        if self.display_name.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "node.display_name must not be empty".to_string(),
            ));
        }

        if self.heartbeat_interval_seconds == 0 {
            return Err(ConfigError::Invalid(
                "node.heartbeat_interval_seconds must be greater than zero".to_string(),
            ));
        }

        if let Some(url) = &self.management_url
            && !(url.starts_with("http://") || url.starts_with("https://"))
        {
            return Err(ConfigError::Invalid(
                "node.management_url must start with http:// or https://".to_string(),
            ));
        }

        self.control.validate()?;

        Ok(())
    }

    fn validate_agent_registration(&self) -> Result<(), ConfigError> {
        if self
            .management_url
            .as_deref()
            .unwrap_or_default()
            .is_empty()
        {
            return Err(ConfigError::Invalid(format!(
                "{} role requires node.management_url",
                self.role.as_str()
            )));
        }

        if self
            .enrollment_token
            .as_deref()
            .unwrap_or_default()
            .is_empty()
        {
            return Err(ConfigError::Invalid(format!(
                "{} role requires node.enrollment_token",
                self.role.as_str()
            )));
        }

        if !self.control.enabled {
            return Err(ConfigError::Invalid(format!(
                "{} role requires node.control.enabled = true for management push",
                self.role.as_str()
            )));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NodeControlConfig {
    #[serde(default = "default_node_control_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub interface: String,
    pub bind_ip: Option<IpAddr>,
    #[serde(default = "default_node_control_port")]
    pub port: u16,
}

impl Default for NodeControlConfig {
    fn default() -> Self {
        Self {
            enabled: default_node_control_enabled(),
            interface: String::new(),
            bind_ip: None,
            port: default_node_control_port(),
        }
    }
}

impl NodeControlConfig {
    pub fn listen_addr(&self) -> SocketAddr {
        SocketAddr::new(
            self.bind_ip
                .unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            self.port,
        )
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        validate_interface_name(&self.interface, "node control interface")?;

        if self.bind_ip.is_none() {
            return Err(ConfigError::Invalid(
                "node.control.bind_ip is required when node control is enabled".to_string(),
            ));
        }

        if self.port == 0 {
            return Err(ConfigError::Invalid(
                "node.control.port must be greater than zero".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    Management,
    Dns,
    SmbProxy,
    #[default]
    StandaloneLab,
}

impl NodeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Management => "management",
            Self::Dns => "dns",
            Self::SmbProxy => "smb_proxy",
            Self::StandaloneLab => "standalone_lab",
        }
    }

    pub fn runs_management(self) -> bool {
        matches!(self, Self::Management | Self::StandaloneLab)
    }

    pub fn runs_dns(self) -> bool {
        matches!(self, Self::Dns | Self::StandaloneLab)
    }

    pub fn runs_smb_proxy(self) -> bool {
        matches!(self, Self::SmbProxy | Self::StandaloneLab)
    }

    pub fn runs_agent(self) -> bool {
        matches!(self, Self::Dns | Self::SmbProxy)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub interface: String,
    pub listen_ip: Option<IpAddr>,
    #[serde(default = "default_dns_port")]
    pub udp_port: u16,
    #[serde(default = "default_dns_port")]
    pub tcp_port: u16,
    #[serde(default)]
    pub upstream_interface: Option<String>,
    #[serde(default)]
    pub upstreams: Vec<SocketAddr>,
    #[serde(default = "default_dns_cache_ttl_seconds")]
    pub cache_ttl_seconds: u64,
    #[serde(default = "default_dns_cache_max_entries")]
    pub cache_max_entries: usize,
    #[serde(default = "default_dns_query_timeout_millis")]
    pub query_timeout_millis: u64,
    #[serde(default = "default_dns_threat_feed_refresh_seconds")]
    pub threat_feed_refresh_seconds: u64,
    #[serde(default)]
    pub policy: DnsPolicyConfig,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: String::new(),
            listen_ip: None,
            udp_port: default_dns_port(),
            tcp_port: default_dns_port(),
            upstream_interface: None,
            upstreams: Vec::new(),
            cache_ttl_seconds: default_dns_cache_ttl_seconds(),
            cache_max_entries: default_dns_cache_max_entries(),
            query_timeout_millis: default_dns_query_timeout_millis(),
            threat_feed_refresh_seconds: default_dns_threat_feed_refresh_seconds(),
            policy: DnsPolicyConfig::default(),
        }
    }
}

impl DnsConfig {
    pub fn udp_listen_addr(&self) -> SocketAddr {
        SocketAddr::new(
            self.listen_ip
                .unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            self.udp_port,
        )
    }

    pub fn tcp_listen_addr(&self) -> SocketAddr {
        SocketAddr::new(
            self.listen_ip
                .unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            self.tcp_port,
        )
    }

    pub fn upstream_interface(&self) -> &str {
        self.upstream_interface
            .as_deref()
            .unwrap_or(&self.interface)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        validate_interface_name(&self.interface, "dns interface")?;

        if let Some(interface) = &self.upstream_interface {
            validate_interface_name(interface, "dns upstream interface")?;
        }

        if self.udp_port == 0 || self.tcp_port == 0 {
            return Err(ConfigError::Invalid(
                "dns udp_port and tcp_port must be greater than zero".to_string(),
            ));
        }

        if self.upstreams.is_empty() {
            return Err(ConfigError::Invalid(
                "dns.upstreams must contain at least one upstream DNS server".to_string(),
            ));
        }

        if self.cache_ttl_seconds == 0 {
            return Err(ConfigError::Invalid(
                "dns.cache_ttl_seconds must be greater than zero".to_string(),
            ));
        }

        if self.cache_max_entries == 0 {
            return Err(ConfigError::Invalid(
                "dns.cache_max_entries must be greater than zero".to_string(),
            ));
        }

        if self.query_timeout_millis == 0 {
            return Err(ConfigError::Invalid(
                "dns.query_timeout_millis must be greater than zero".to_string(),
            ));
        }

        self.policy.validate()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsPolicyConfig {
    #[serde(default = "default_block_mode")]
    pub blocked_domain_action: PolicyMode,
    #[serde(default = "default_monitor_mode")]
    pub monitored_domain_action: PolicyMode,
    #[serde(default)]
    pub blocked_domains: Vec<String>,
    #[serde(default)]
    pub monitored_domains: Vec<String>,
    #[serde(default)]
    pub threat_feed_urls: Vec<String>,
    #[serde(default)]
    pub block_response: DnsBlockResponse,
    #[serde(default = "default_dns_sinkhole_ipv4")]
    pub sinkhole_ipv4: Ipv4Addr,
    #[serde(default)]
    pub local_records: Vec<DnsLocalRecordConfig>,
}

impl Default for DnsPolicyConfig {
    fn default() -> Self {
        Self {
            blocked_domain_action: PolicyMode::Block,
            monitored_domain_action: PolicyMode::Monitor,
            blocked_domains: Vec::new(),
            monitored_domains: Vec::new(),
            threat_feed_urls: Vec::new(),
            block_response: DnsBlockResponse::Nxdomain,
            sinkhole_ipv4: default_dns_sinkhole_ipv4(),
            local_records: Vec::new(),
        }
    }
}

impl DnsPolicyConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        for domain in self
            .blocked_domains
            .iter()
            .chain(self.monitored_domains.iter())
        {
            validate_dns_domain(domain)?;
        }

        for url in &self.threat_feed_urls {
            if !(url.starts_with("https://") || url.starts_with("http://")) {
                return Err(ConfigError::Invalid(format!(
                    "dns.policy.threat_feed_urls entry '{url}' must start with http:// or https://"
                )));
            }
        }

        for record in &self.local_records {
            record.validate()?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsLocalRecordConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: DnsRecordType,
    pub value: IpAddr,
    #[serde(default = "default_dns_local_record_ttl_seconds")]
    pub ttl_seconds: u32,
}

impl DnsLocalRecordConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_dns_domain(&self.name)?;

        match (self.record_type, self.value) {
            (DnsRecordType::A, IpAddr::V4(_)) | (DnsRecordType::Aaaa, IpAddr::V6(_)) => {}
            (DnsRecordType::A, _) => {
                return Err(ConfigError::Invalid(format!(
                    "dns.policy.local_records '{}' type A must use an IPv4 value",
                    self.name
                )));
            }
            (DnsRecordType::Aaaa, _) => {
                return Err(ConfigError::Invalid(format!(
                    "dns.policy.local_records '{}' type AAAA must use an IPv6 value",
                    self.name
                )));
            }
        }

        if self.ttl_seconds == 0 {
            return Err(ConfigError::Invalid(format!(
                "dns.policy.local_records '{}' ttl_seconds must be greater than zero",
                self.name
            )));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsRecordType {
    A,
    Aaaa,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsBlockResponse {
    #[default]
    Nxdomain,
    Sinkhole,
    Refused,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub smb: SmbPolicyConfig,
    #[serde(default)]
    pub archive: ArchivePolicyConfig,
    #[serde(default)]
    pub entropy: EntropyPolicyConfig,
    #[serde(default)]
    pub reputation: ReputationPolicyConfig,
    #[serde(default = "default_signatures")]
    pub signatures: Vec<SignaturePolicyConfig>,
}

impl PolicyConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.entropy.validate()?;
        self.reputation.validate()?;

        for signature in &self.signatures {
            signature.validate()?;
        }

        Ok(())
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            smb: SmbPolicyConfig::default(),
            archive: ArchivePolicyConfig::default(),
            entropy: EntropyPolicyConfig::default(),
            reputation: ReputationPolicyConfig::default(),
            signatures: default_signatures(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SmbPolicyConfig {
    #[serde(default = "default_monitor_mode")]
    pub encrypted_payload: PolicyMode,
}

impl Default for SmbPolicyConfig {
    fn default() -> Self {
        Self {
            encrypted_payload: PolicyMode::Monitor,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ArchivePolicyConfig {
    #[serde(default = "default_block_mode")]
    pub rar: PolicyMode,
    #[serde(default = "default_block_mode")]
    pub seven_zip: PolicyMode,
    #[serde(default = "default_block_mode")]
    pub zip: PolicyMode,
    #[serde(default = "default_block_mode")]
    pub encrypted_zip: PolicyMode,
}

impl Default for ArchivePolicyConfig {
    fn default() -> Self {
        Self {
            rar: PolicyMode::Block,
            seven_zip: PolicyMode::Block,
            zip: PolicyMode::Block,
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
pub struct ReputationPolicyConfig {
    #[serde(default = "default_reputation_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub known_bad_action: KnownBadAction,
    #[serde(default = "default_reputation_cache_ttl_seconds")]
    pub cache_ttl_seconds: u64,
}

impl ReputationPolicyConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.cache_ttl_seconds == 0 {
            return Err(ConfigError::Invalid(
                "policy.reputation.cache_ttl_seconds must be greater than zero".to_string(),
            ));
        }

        Ok(())
    }
}

impl Default for ReputationPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: default_reputation_enabled(),
            known_bad_action: KnownBadAction::Alert,
            cache_ttl_seconds: default_reputation_cache_ttl_seconds(),
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
    #[serde(default)]
    pub tls: ManagementTlsConfig,
    #[serde(default)]
    pub directory: DirectoryConfig,
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
        self.tls.validate()?;
        self.directory.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ManagementTlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cert_path: String,
    #[serde(default)]
    pub key_path: String,
}

impl Default for ManagementTlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: String::new(),
            key_path: String::new(),
        }
    }
}

impl ManagementTlsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if self.cert_path.trim().is_empty() || self.key_path.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "management.tls cert_path and key_path are required when TLS is enabled"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DirectoryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub url: String,
    #[serde(default = "default_directory_user_bind_format")]
    pub user_bind_format: String,
    #[serde(default)]
    pub bind_dn: Option<String>,
    #[serde(default)]
    pub bind_password: Option<String>,
    #[serde(default)]
    pub base_dn: String,
    #[serde(default = "default_directory_user_filter")]
    pub user_filter: String,
    #[serde(default)]
    pub required_group_dn: Option<String>,
    #[serde(default = "default_directory_client_reverse_dns")]
    pub client_reverse_dns: bool,
}

impl Default for DirectoryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            user_bind_format: default_directory_user_bind_format(),
            bind_dn: None,
            bind_password: None,
            base_dn: String::new(),
            user_filter: default_directory_user_filter(),
            required_group_dn: None,
            client_reverse_dns: default_directory_client_reverse_dns(),
        }
    }
}

impl DirectoryConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if !(self.url.starts_with("ldap://") || self.url.starts_with("ldaps://")) {
            return Err(ConfigError::Invalid(
                "management.directory.url must start with ldap:// or ldaps://".to_string(),
            ));
        }

        if !self.user_bind_format.contains("{username}") {
            return Err(ConfigError::Invalid(
                "management.directory.user_bind_format must contain {username}".to_string(),
            ));
        }

        if self.base_dn.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "management.directory.base_dn must not be empty when directory auth is enabled"
                    .to_string(),
            ));
        }

        if !self.user_filter.contains("{username}") {
            return Err(ConfigError::Invalid(
                "management.directory.user_filter must contain {username}".to_string(),
            ));
        }

        let bind_dn_present = self
            .bind_dn
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        let bind_password_present = self
            .bind_password
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        if bind_dn_present != bind_password_present {
            return Err(ConfigError::Invalid(
                "management.directory bind_dn and bind_password must be configured together"
                    .to_string(),
            ));
        }

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

fn validate_dns_domain(domain: &str) -> Result<(), ConfigError> {
    let normalized = domain.trim().trim_end_matches('.');
    if normalized.is_empty() || normalized.len() > 253 {
        return Err(ConfigError::Invalid(format!(
            "dns domain '{domain}' must be between 1 and 253 characters"
        )));
    }

    for label in normalized.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ConfigError::Invalid(format!(
                "dns domain '{domain}' contains an invalid label"
            )));
        }

        if label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(ConfigError::Invalid(format!(
                "dns domain '{domain}' contains unsupported characters"
            )));
        }
    }

    Ok(())
}

fn default_smb_port() -> u16 {
    445
}

fn default_dns_port() -> u16 {
    53
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

fn default_reputation_enabled() -> bool {
    true
}

fn default_reputation_cache_ttl_seconds() -> u64 {
    3600
}

fn default_dns_cache_ttl_seconds() -> u64 {
    300
}

fn default_dns_cache_max_entries() -> usize {
    100_000
}

fn default_dns_query_timeout_millis() -> u64 {
    1_500
}

fn default_dns_threat_feed_refresh_seconds() -> u64 {
    3600
}

fn default_dns_sinkhole_ipv4() -> Ipv4Addr {
    Ipv4Addr::new(0, 0, 0, 0)
}

fn default_dns_local_record_ttl_seconds() -> u32 {
    300
}

fn default_node_id() -> String {
    "axiom-local".to_string()
}

fn default_node_display_name() -> String {
    "Axiom Local Node".to_string()
}

fn default_heartbeat_interval_seconds() -> u64 {
    5
}

fn default_node_control_enabled() -> bool {
    false
}

fn default_node_control_port() -> u16 {
    9443
}

fn default_directory_user_bind_format() -> String {
    "{username}".to_string()
}

fn default_directory_user_filter() -> String {
    "(sAMAccountName={username})".to_string()
}

fn default_directory_client_reverse_dns() -> bool {
    true
}

fn default_signatures() -> Vec<SignaturePolicyConfig> {
    vec![
        SignaturePolicyConfig {
            name: "Axiom synthetic test marker".to_string(),
            pattern: "AXIOM_TEST_THREAT".to_string(),
            mode: PolicyMode::Block,
        },
        SignaturePolicyConfig {
            name: "EICAR antivirus test string".to_string(),
            pattern: "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
                .to_string(),
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
