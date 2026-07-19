use std::{
    collections::HashSet,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
};

use axiom_license::LicenseConfig;
use axiom_reputation::KnownBadAction;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DNS_BLOCK_PAGE_LOGO_MAX_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AxiomConfig {
    #[serde(default)]
    pub node: NodeConfig,
    #[serde(default)]
    pub clusters: ClusterManagementConfig,
    pub management: ManagementNicConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub license: LicenseConfig,
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
        self.clusters.validate()?;
        self.management.validate()?;
        self.policy.validate()?;
        self.license
            .validate()
            .map_err(|error| ConfigError::Invalid(error.to_string()))?;

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
    pub cluster: NodeClusterConfig,
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
            cluster: NodeClusterConfig::default(),
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

        self.cluster.validate(self.role)?;

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

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct NodeClusterConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub name: Option<String>,
}

impl NodeClusterConfig {
    fn validate(&self, role: NodeRole) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if !role.runs_agent() {
            return Err(ConfigError::Invalid(
                "node.cluster can only be enabled for dns or smb_proxy roles".to_string(),
            ));
        }

        let name = self.name.as_deref().unwrap_or_default();
        validate_cluster_name(name)
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ClusterManagementConfig {
    #[serde(default)]
    pub groups: Vec<ClusterGroupConfig>,
}

impl ClusterManagementConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        let mut names = HashSet::new();
        let mut assigned_node_ids = HashSet::new();
        for group in &self.groups {
            group.validate()?;
            if !names.insert(group.name.to_ascii_lowercase()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate cluster name '{}'",
                    group.name
                )));
            }
            if !assigned_node_ids.insert(group.source_node_id.clone()) {
                return Err(ConfigError::Invalid(format!(
                    "node '{}' is assigned to more than one cluster",
                    group.source_node_id
                )));
            }
            for member in &group.members {
                if !assigned_node_ids.insert(member.node_id.clone()) {
                    return Err(ConfigError::Invalid(format!(
                        "node '{}' is assigned to more than one cluster",
                        member.node_id
                    )));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClusterGroupConfig {
    pub name: String,
    pub role: NodeRole,
    pub password_hash: String,
    pub source_node_id: String,
    #[serde(default)]
    pub members: Vec<ClusterMemberCredential>,
    #[serde(default)]
    pub traffic_mode: ClusterTrafficMode,
    #[serde(default)]
    pub service_endpoint: Option<String>,
    #[serde(default)]
    pub created_unix_timestamp_seconds: u64,
    #[serde(default)]
    pub service_template: ClusterServiceTemplate,
}

impl ClusterGroupConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_cluster_name(&self.name)?;
        if !matches!(self.role, NodeRole::Dns | NodeRole::SmbProxy) {
            return Err(ConfigError::Invalid(format!(
                "cluster '{}' role must be dns or smb_proxy",
                self.name
            )));
        }
        if !self.password_hash.starts_with("$argon2") {
            return Err(ConfigError::Invalid(format!(
                "cluster '{}' password_hash must use Argon2",
                self.name
            )));
        }
        if self.source_node_id.trim().is_empty() {
            return Err(ConfigError::Invalid(format!(
                "cluster '{}' source_node_id must not be empty",
                self.name
            )));
        }
        if self
            .service_endpoint
            .as_deref()
            .is_some_and(|endpoint| endpoint.trim().is_empty())
        {
            return Err(ConfigError::Invalid(format!(
                "cluster '{}' service_endpoint must not be blank",
                self.name
            )));
        }
        let mut member_ids = HashSet::new();
        let mut member_tokens = HashSet::new();
        for member in &self.members {
            if member.node_id.trim().is_empty() || member.token.len() < 32 {
                return Err(ConfigError::Invalid(format!(
                    "cluster '{}' contains an invalid member credential",
                    self.name
                )));
            }
            if !member_ids.insert(member.node_id.clone())
                || !member_tokens.insert(member.token.clone())
            {
                return Err(ConfigError::Invalid(format!(
                    "cluster '{}' contains duplicate member credentials",
                    self.name
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClusterMemberCredential {
    pub node_id: String,
    pub token: String,
    #[serde(default)]
    pub issued_unix_timestamp_seconds: u64,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClusterTrafficMode {
    #[default]
    ExternalLoadBalancer,
    DnsMultipleAddresses,
    Direct,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClusterServiceTemplate {
    #[serde(default)]
    pub smb_routes: Vec<ClusterSmbRouteTemplate>,
    #[serde(default)]
    pub dns: Option<ClusterDnsTemplate>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClusterSmbRouteTemplate {
    pub name: String,
    #[serde(default)]
    pub client_vlan: Option<u16>,
    #[serde(default = "default_smb_port")]
    pub listen_port: u16,
    pub target_file_server_ip: IpAddr,
    #[serde(default = "default_smb_port")]
    pub target_file_server_port: u16,
    #[serde(default = "default_backlog")]
    pub backlog: i32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClusterDnsTemplate {
    #[serde(default = "default_dns_port")]
    pub udp_port: u16,
    #[serde(default = "default_dns_port")]
    pub tcp_port: u16,
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
}

impl ClusterServiceTemplate {
    pub fn from_config(config: &AxiomConfig) -> Self {
        let smb_routes = config
            .proxy_listeners
            .iter()
            .map(|listener| ClusterSmbRouteTemplate {
                name: listener.name.clone(),
                client_vlan: listener.client_vlan,
                listen_port: listener.listen_port,
                target_file_server_ip: listener.target_file_server_ip,
                target_file_server_port: listener.target_file_server_port,
                backlog: listener.backlog,
            })
            .collect();
        let dns = config.dns.enabled.then(|| ClusterDnsTemplate {
            udp_port: config.dns.udp_port,
            tcp_port: config.dns.tcp_port,
            upstreams: config.dns.upstreams.clone(),
            cache_ttl_seconds: config.dns.cache_ttl_seconds,
            cache_max_entries: config.dns.cache_max_entries,
            query_timeout_millis: config.dns.query_timeout_millis,
            threat_feed_refresh_seconds: config.dns.threat_feed_refresh_seconds,
        });

        Self { smb_routes, dns }
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
    pub block_page: DnsBlockPageConfig,
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
            block_response: DnsBlockResponse::Sinkhole,
            sinkhole_ipv4: default_dns_sinkhole_ipv4(),
            block_page: DnsBlockPageConfig::default(),
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

        self.block_page.validate()?;

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsBlockPageConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_dns_block_page_organization")]
    pub organization_name: String,
    #[serde(default = "default_dns_block_page_title")]
    pub title: String,
    #[serde(default = "default_dns_block_page_message")]
    pub message: String,
    #[serde(default = "default_dns_block_page_primary_color")]
    pub primary_color: String,
    #[serde(default = "default_dns_block_page_support_text")]
    pub support_text: String,
    #[serde(default)]
    pub support_url: String,
    #[serde(default)]
    pub logo_data_url: String,
}

impl Default for DnsBlockPageConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            organization_name: default_dns_block_page_organization(),
            title: default_dns_block_page_title(),
            message: default_dns_block_page_message(),
            primary_color: default_dns_block_page_primary_color(),
            support_text: default_dns_block_page_support_text(),
            support_url: String::new(),
            logo_data_url: String::new(),
        }
    }
}

impl DnsBlockPageConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_text_field(
            "dns.policy.block_page.organization_name",
            &self.organization_name,
            120,
            false,
        )?;
        validate_text_field("dns.policy.block_page.title", &self.title, 200, false)?;
        validate_text_field("dns.policy.block_page.message", &self.message, 2_000, false)?;
        validate_text_field(
            "dns.policy.block_page.support_text",
            &self.support_text,
            500,
            true,
        )?;

        let color = self.primary_color.as_bytes();
        if color.len() != 7
            || color.first() != Some(&b'#')
            || !color[1..].iter().all(u8::is_ascii_hexdigit)
        {
            return Err(ConfigError::Invalid(
                "dns.policy.block_page.primary_color must use #RRGGBB format".to_string(),
            ));
        }

        if !(self.support_url.is_empty()
            || self.support_url.starts_with("https://")
            || self.support_url.starts_with("http://")
            || self.support_url.starts_with("mailto:"))
        {
            return Err(ConfigError::Invalid(
                "dns.policy.block_page.support_url must start with https://, http://, or mailto:"
                    .to_string(),
            ));
        }
        if self.support_url.chars().count() > 2_048 {
            return Err(ConfigError::Invalid(
                "dns.policy.block_page.support_url must not exceed 2048 characters".to_string(),
            ));
        }

        if !self.logo_data_url.is_empty() {
            let encoded = [
                "data:image/png;base64,",
                "data:image/jpeg;base64,",
                "data:image/webp;base64,",
            ]
            .iter()
            .find_map(|prefix| self.logo_data_url.strip_prefix(prefix))
            .ok_or_else(|| {
                ConfigError::Invalid(
                    "dns.policy.block_page.logo_data_url must be a PNG, JPEG, or WebP base64 data URL"
                        .to_string(),
                )
            })?;
            let decoded = STANDARD.decode(encoded).map_err(|_| {
                ConfigError::Invalid(
                    "dns.policy.block_page.logo_data_url contains invalid base64 data".to_string(),
                )
            })?;
            if decoded.is_empty() || decoded.len() > DNS_BLOCK_PAGE_LOGO_MAX_BYTES {
                return Err(ConfigError::Invalid(format!(
                    "dns.policy.block_page.logo_data_url must contain between 1 and {} decoded bytes",
                    DNS_BLOCK_PAGE_LOGO_MAX_BYTES
                )));
            }
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
    Nxdomain,
    #[default]
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

fn validate_cluster_name(name: &str) -> Result<(), ConfigError> {
    let name = name.trim();
    if name.len() < 3 || name.len() > 64 {
        return Err(ConfigError::Invalid(
            "cluster name must contain between 3 and 64 characters".to_string(),
        ));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ConfigError::Invalid(
            "cluster name may only contain letters, numbers, '-' and '_'".to_string(),
        ));
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

fn validate_text_field(
    field_name: &str,
    value: &str,
    maximum_characters: usize,
    allow_empty: bool,
) -> Result<(), ConfigError> {
    let length = value.chars().count();
    if (!allow_empty && value.trim().is_empty()) || length > maximum_characters {
        return Err(ConfigError::Invalid(format!(
            "{field_name} must contain {} to {maximum_characters} characters",
            usize::from(!allow_empty)
        )));
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

fn default_true() -> bool {
    true
}

fn default_dns_block_page_organization() -> String {
    "Axiom Security".to_string()
}

fn default_dns_block_page_title() -> String {
    "Access to this site has been blocked".to_string()
}

fn default_dns_block_page_message() -> String {
    "This domain was blocked by your organization's DNS security policy.".to_string()
}

fn default_dns_block_page_primary_color() -> String {
    "#34f5c5".to_string()
}

fn default_dns_block_page_support_text() -> String {
    "Contact your IT or security team if you believe this is an error.".to_string()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn example_config() -> AxiomConfig {
        toml::from_str(include_str!("../../../config/axiom.example.toml"))
            .expect("example config must parse")
    }

    #[test]
    fn existing_config_defaults_to_no_cluster_membership() {
        let mut source = include_str!("../../../config/axiom.example.toml").to_string();
        source = source.replace("[node.cluster]\nenabled = false\n\n", "");

        let config: AxiomConfig = toml::from_str(&source).expect("legacy config must parse");

        assert!(!config.node.cluster.enabled);
        assert!(config.node.cluster.name.is_none());
        assert!(config.clusters.groups.is_empty());
        config.validate().expect("legacy config must remain valid");
    }

    #[test]
    fn legacy_dns_policy_receives_default_axiom_block_page() {
        let source = r#"
blocked_domain_action = "block"
monitored_domain_action = "monitor"
block_response = "nxdomain"
sinkhole_ipv4 = "0.0.0.0"
"#;

        let policy: DnsPolicyConfig = toml::from_str(source).expect("legacy policy must parse");

        assert!(policy.block_page.enabled);
        assert_eq!(policy.block_page.organization_name, "Axiom Security");
        assert_eq!(policy.block_page.primary_color, "#34f5c5");
        policy.validate().expect("default block page must validate");
    }

    #[test]
    fn dns_block_page_accepts_hebrew_and_embedded_png() {
        let mut policy = DnsPolicyConfig::default();
        policy.block_page.organization_name = "אקסיום אבטחת מידע".to_string();
        policy.block_page.title = "הגישה לאתר נחסמה".to_string();
        policy.block_page.message = "הדומיין נחסם בהתאם למדיניות הארגון.".to_string();
        policy.block_page.logo_data_url = "data:image/png;base64,iVBORw0KGgo=".to_string();

        policy.validate().expect("Hebrew block page must validate");
    }

    #[test]
    fn dns_block_page_rejects_unsafe_logo_and_support_url() {
        let mut policy = DnsPolicyConfig::default();
        policy.block_page.logo_data_url =
            "data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+".to_string();
        assert!(policy.validate().is_err());

        policy.block_page.logo_data_url.clear();
        policy.block_page.support_url = "javascript:alert(1)".to_string();
        assert!(policy.validate().is_err());
    }

    #[test]
    fn service_template_contains_shared_settings_only() {
        let config = example_config();

        let template = ClusterServiceTemplate::from_config(&config);

        assert_eq!(template.smb_routes.len(), config.proxy_listeners.len());
        assert_eq!(
            template.smb_routes[0].target_file_server_ip,
            config.proxy_listeners[0].target_file_server_ip
        );
        assert_eq!(
            template.dns.as_ref().expect("DNS template").upstreams,
            config.dns.upstreams
        );
    }

    #[test]
    fn cluster_membership_is_rejected_for_management_or_lab_roles() {
        let mut config = example_config();
        config.node.cluster = NodeClusterConfig {
            enabled: true,
            name: Some("smb-production".to_string()),
        };

        let error = config
            .validate()
            .expect_err("standalone role cannot join a cluster");

        assert!(
            error
                .to_string()
                .contains("node.cluster can only be enabled")
        );
    }

    #[test]
    fn cluster_member_credentials_must_be_unique() {
        let credential = ClusterMemberCredential {
            node_id: "smb-replica-02".to_string(),
            token: "0123456789abcdef0123456789abcdef".to_string(),
            issued_unix_timestamp_seconds: 1,
        };
        let group = ClusterGroupConfig {
            name: "smb-production".to_string(),
            role: NodeRole::SmbProxy,
            password_hash: "$argon2id$test".to_string(),
            source_node_id: "smb-source-01".to_string(),
            members: vec![credential.clone(), credential],
            traffic_mode: ClusterTrafficMode::ExternalLoadBalancer,
            service_endpoint: Some("smb.example.internal".to_string()),
            created_unix_timestamp_seconds: 1,
            service_template: ClusterServiceTemplate::default(),
        };

        assert!(group.validate().is_err());
    }

    #[test]
    fn node_id_cannot_belong_to_multiple_clusters() {
        let first = ClusterGroupConfig {
            name: "smb-production-a".to_string(),
            role: NodeRole::SmbProxy,
            password_hash: "$argon2id$test-a".to_string(),
            source_node_id: "smb-source-01".to_string(),
            members: Vec::new(),
            traffic_mode: ClusterTrafficMode::ExternalLoadBalancer,
            service_endpoint: None,
            created_unix_timestamp_seconds: 1,
            service_template: ClusterServiceTemplate::default(),
        };
        let mut second = first.clone();
        second.name = "smb-production-b".to_string();
        second.password_hash = "$argon2id$test-b".to_string();

        let clusters = ClusterManagementConfig {
            groups: vec![first, second],
        };

        assert!(clusters.validate().is_err());
    }
}
