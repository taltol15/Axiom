use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const DEFAULT_LICENSE_PATH: &str = "/etc/axiom/license.json";
pub const DEFAULT_LICENSE_STATE_PATH: &str = "/var/lib/axiom/license-state.json";
const DEFAULT_TRIAL_DAYS: u64 = 30;
const DEFAULT_WARN_BEFORE_EXPIRY_DAYS: u64 = 14;
const AXIOM_LICENSE_PUBLIC_KEY_HEX: &str =
    "022f8987061b465a698c27a6b72a2c35419399335718b2a6ed0709df63b7327b";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LicenseConfig {
    #[serde(default = "default_license_enabled")]
    pub enabled: bool,
    #[serde(default = "default_license_path")]
    pub license_path: String,
    #[serde(default = "default_license_state_path")]
    pub state_path: String,
    #[serde(default = "default_trial_days")]
    pub trial_days: u64,
    #[serde(default = "default_warn_before_expiry_days")]
    pub warn_before_expiry_days: u64,
    #[serde(default)]
    pub public_key_hex: Option<String>,
}

impl Default for LicenseConfig {
    fn default() -> Self {
        Self {
            enabled: default_license_enabled(),
            license_path: default_license_path(),
            state_path: default_license_state_path(),
            trial_days: default_trial_days(),
            warn_before_expiry_days: default_warn_before_expiry_days(),
            public_key_hex: None,
        }
    }
}

impl LicenseConfig {
    pub fn validate(&self) -> Result<(), LicenseError> {
        if self.license_path.trim().is_empty() {
            return Err(LicenseError::InvalidConfig(
                "license.license_path must not be empty".to_string(),
            ));
        }

        if self.state_path.trim().is_empty() {
            return Err(LicenseError::InvalidConfig(
                "license.state_path must not be empty".to_string(),
            ));
        }

        if self.trial_days == 0 {
            return Err(LicenseError::InvalidConfig(
                "license.trial_days must be greater than zero".to_string(),
            ));
        }

        if let Some(public_key_hex) = self.public_key_hex.as_deref()
            && !public_key_hex.trim().is_empty()
            && decode_hex_32(public_key_hex.trim()).is_err()
        {
            return Err(LicenseError::InvalidConfig(
                "license.public_key_hex must be a 32-byte hex encoded Ed25519 public key"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LicenseEnvelope {
    pub payload: LicensePayload,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LicensePayload {
    pub license_id: String,
    pub customer_name: String,
    pub edition: String,
    pub issued_at_unix_timestamp_seconds: u64,
    pub expires_at_unix_timestamp_seconds: u64,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub limits: LicenseLimits,
    #[serde(default)]
    pub machine_fingerprint: Option<String>,
    #[serde(default)]
    pub allowed_node_ids: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct LicenseLimits {
    #[serde(default)]
    pub max_smb_nodes: Option<u32>,
    #[serde(default)]
    pub max_dns_nodes: Option<u32>,
    #[serde(default)]
    pub max_protected_clients: Option<u32>,
    #[serde(default)]
    pub max_reputation_entries: Option<u32>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct LicenseUsage {
    pub management_nodes: u32,
    pub smb_nodes: u32,
    pub dns_nodes: u32,
    pub protected_clients: u32,
    pub reputation_entries: u32,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LicenseState {
    Disabled,
    Licensed,
    Trial,
    ExpiringSoon,
    Expired,
    LimitExceeded,
    Invalid,
    Missing,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LicenseStatus {
    pub state: LicenseState,
    pub valid: bool,
    pub licensed: bool,
    pub trial: bool,
    pub message: String,
    pub license_id: Option<String>,
    pub customer_name: Option<String>,
    pub edition: Option<String>,
    pub expires_at_unix_timestamp_seconds: Option<u64>,
    pub days_remaining: Option<i64>,
    pub features: Vec<String>,
    pub limits: LicenseLimits,
    pub usage: LicenseUsage,
    pub machine_fingerprint: String,
    pub activation_request: ActivationRequest,
    pub activation_request_b64: String,
    pub validation_errors: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ActivationRequest {
    pub product: String,
    pub generated_at_unix_timestamp_seconds: u64,
    pub machine_fingerprint: String,
    pub hostname: String,
    pub usage: LicenseUsage,
    pub license_path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct TrialState {
    first_seen_unix_timestamp_seconds: u64,
    last_seen_unix_timestamp_seconds: u64,
    machine_fingerprint: String,
}

#[derive(Debug, Error)]
pub enum LicenseError {
    #[error("invalid license config: {0}")]
    InvalidConfig(String),
    #[error("license file is not valid JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("license signature is invalid")]
    InvalidSignature,
    #[error("license public key is invalid")]
    InvalidPublicKey,
    #[error("license private key is invalid")]
    InvalidPrivateKey,
    #[error("license random source failed: {0}")]
    Random(String),
    #[error("license signature encoding is invalid")]
    InvalidSignatureEncoding,
    #[error("license is not valid for this machine")]
    MachineMismatch,
    #[error("license I/O error at '{path}': {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
}

pub fn evaluate_license(config: &LicenseConfig, usage: LicenseUsage) -> LicenseStatus {
    let now = unix_timestamp_seconds();
    let fingerprint = machine_fingerprint();
    let activation_request = build_activation_request(config, usage.clone(), now, &fingerprint);
    let activation_request_b64 = activation_request_b64(&activation_request);

    if !config.enabled {
        return status(
            LicenseState::Disabled,
            true,
            false,
            false,
            "License checks are disabled for this node".to_string(),
            None,
            usage,
            fingerprint,
            activation_request,
            activation_request_b64,
            Vec::new(),
        );
    }

    match load_license(
        &config.license_path,
        &fingerprint,
        license_public_key_hex(config),
    ) {
        Ok(Some(payload)) => status_from_payload(
            config,
            payload,
            usage,
            now,
            fingerprint,
            activation_request,
            activation_request_b64,
        ),
        Ok(None) => trial_status(
            config,
            usage,
            now,
            fingerprint,
            activation_request,
            activation_request_b64,
        ),
        Err(error) => status(
            LicenseState::Invalid,
            false,
            false,
            false,
            format!("Installed license is invalid: {error}"),
            None,
            usage,
            fingerprint,
            activation_request,
            activation_request_b64,
            vec![error.to_string()],
        ),
    }
}

pub fn install_license_text(
    config: &LicenseConfig,
    license_text: &str,
    usage: LicenseUsage,
) -> Result<LicenseStatus, LicenseError> {
    let fingerprint = machine_fingerprint();
    let normalized = normalize_license_text(license_text)?;
    let envelope: LicenseEnvelope = serde_json::from_str(&normalized)?;
    verify_license_envelope(&envelope, &fingerprint, license_public_key_hex(config))?;

    write_file(&config.license_path, normalized.as_bytes())?;
    Ok(evaluate_license(config, usage))
}

pub fn default_public_key_hex() -> &'static str {
    AXIOM_LICENSE_PUBLIC_KEY_HEX
}

pub fn decode_activation_request_text(value: &str) -> Result<ActivationRequest, LicenseError> {
    let trimmed = value.trim();
    if trimmed.starts_with('{') {
        return serde_json::from_str(trimmed).map_err(LicenseError::Parse);
    }

    let decoded = BASE64
        .decode(trimmed)
        .map_err(|_| LicenseError::InvalidSignatureEncoding)?;
    let decoded_text =
        String::from_utf8(decoded).map_err(|_| LicenseError::InvalidSignatureEncoding)?;
    serde_json::from_str(&decoded_text).map_err(LicenseError::Parse)
}

pub fn generate_signing_key_hex() -> Result<(String, String), LicenseError> {
    let mut private_key = [0_u8; 32];
    getrandom::fill(&mut private_key).map_err(|error| LicenseError::Random(error.to_string()))?;
    let public_key = SigningKey::from_bytes(&private_key).verifying_key();
    Ok((hex(&private_key), hex(public_key.as_bytes())))
}

pub fn public_key_hex_from_private_key_hex(private_key_hex: &str) -> Result<String, LicenseError> {
    let private_key_bytes =
        decode_hex_32(private_key_hex.trim()).map_err(|_| LicenseError::InvalidPrivateKey)?;
    let public_key = SigningKey::from_bytes(&private_key_bytes).verifying_key();
    Ok(hex(public_key.as_bytes()))
}

pub fn sign_license_payload(
    payload: &LicensePayload,
    private_key_hex: &str,
) -> Result<LicenseEnvelope, LicenseError> {
    let private_key_bytes =
        decode_hex_32(private_key_hex.trim()).map_err(|_| LicenseError::InvalidPrivateKey)?;
    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    let payload_bytes = serde_json::to_vec(payload)?;
    let signature = signing_key.sign(&payload_bytes);

    Ok(LicenseEnvelope {
        payload: payload.clone(),
        signature: BASE64.encode(signature.to_bytes()),
    })
}

pub fn encode_license_envelope_b64(envelope: &LicenseEnvelope) -> Result<String, LicenseError> {
    serde_json::to_vec_pretty(envelope)
        .map(|bytes| BASE64.encode(bytes))
        .map_err(LicenseError::Parse)
}

fn load_license(
    license_path: &str,
    machine_fingerprint: &str,
    public_key_hex: &str,
) -> Result<Option<LicensePayload>, LicenseError> {
    let path = Path::new(license_path);
    if !path.exists() {
        return Ok(None);
    }

    let contents = read_to_string(path)?;
    let envelope: LicenseEnvelope = serde_json::from_str(&contents)?;
    verify_license_envelope(&envelope, machine_fingerprint, public_key_hex)?;
    Ok(Some(envelope.payload))
}

fn verify_license_envelope(
    envelope: &LicenseEnvelope,
    machine_fingerprint: &str,
    public_key_hex: &str,
) -> Result<(), LicenseError> {
    if let Some(expected_fingerprint) = &envelope.payload.machine_fingerprint
        && expected_fingerprint != machine_fingerprint
    {
        return Err(LicenseError::MachineMismatch);
    }

    let public_key_bytes =
        decode_hex_32(public_key_hex).map_err(|_| LicenseError::InvalidPublicKey)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key_bytes).map_err(|_| LicenseError::InvalidPublicKey)?;
    let signature_bytes = BASE64
        .decode(envelope.signature.trim())
        .map_err(|_| LicenseError::InvalidSignatureEncoding)?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| LicenseError::InvalidSignatureEncoding)?;
    let signature = Signature::from_bytes(&signature_array);
    let payload_bytes = serde_json::to_vec(&envelope.payload)?;

    verifying_key
        .verify(&payload_bytes, &signature)
        .map_err(|_| LicenseError::InvalidSignature)
}

fn status_from_payload(
    config: &LicenseConfig,
    payload: LicensePayload,
    usage: LicenseUsage,
    now: u64,
    fingerprint: String,
    activation_request: ActivationRequest,
    activation_request_b64: String,
) -> LicenseStatus {
    let mut errors = Vec::new();
    if payload.expires_at_unix_timestamp_seconds <= now {
        errors.push("license has expired".to_string());
    }

    if exceeds(payload.limits.max_smb_nodes, usage.smb_nodes) {
        errors.push(format!(
            "SMB node limit exceeded: used {}, licensed {}",
            usage.smb_nodes,
            payload.limits.max_smb_nodes.unwrap_or_default()
        ));
    }

    if exceeds(payload.limits.max_dns_nodes, usage.dns_nodes) {
        errors.push(format!(
            "DNS node limit exceeded: used {}, licensed {}",
            usage.dns_nodes,
            payload.limits.max_dns_nodes.unwrap_or_default()
        ));
    }

    if exceeds(
        payload.limits.max_protected_clients,
        usage.protected_clients,
    ) {
        errors.push(format!(
            "protected client limit exceeded: used {}, licensed {}",
            usage.protected_clients,
            payload.limits.max_protected_clients.unwrap_or_default()
        ));
    }

    if exceeds(
        payload.limits.max_reputation_entries,
        usage.reputation_entries,
    ) {
        errors.push(format!(
            "reputation entry limit exceeded: used {}, licensed {}",
            usage.reputation_entries,
            payload.limits.max_reputation_entries.unwrap_or_default()
        ));
    }

    let days_remaining = days_until(payload.expires_at_unix_timestamp_seconds, now);
    let state = if payload.expires_at_unix_timestamp_seconds <= now {
        LicenseState::Expired
    } else if !errors.is_empty() {
        LicenseState::LimitExceeded
    } else if days_remaining <= config.warn_before_expiry_days as i64 {
        LicenseState::ExpiringSoon
    } else {
        LicenseState::Licensed
    };
    let valid = matches!(state, LicenseState::Licensed | LicenseState::ExpiringSoon);
    let message = match state {
        LicenseState::Licensed => format!(
            "{} license is active for {}",
            payload.edition, payload.customer_name
        ),
        LicenseState::ExpiringSoon => format!(
            "{} license expires in {} days",
            payload.edition, days_remaining
        ),
        LicenseState::Expired => "License has expired".to_string(),
        LicenseState::LimitExceeded => "License limits are exceeded".to_string(),
        _ => "License status evaluated".to_string(),
    };

    LicenseStatus {
        state,
        valid,
        licensed: true,
        trial: false,
        message,
        license_id: Some(payload.license_id),
        customer_name: Some(payload.customer_name),
        edition: Some(payload.edition),
        expires_at_unix_timestamp_seconds: Some(payload.expires_at_unix_timestamp_seconds),
        days_remaining: Some(days_remaining),
        features: payload.features,
        limits: payload.limits,
        usage,
        machine_fingerprint: fingerprint,
        activation_request,
        activation_request_b64,
        validation_errors: errors,
    }
}

fn trial_status(
    config: &LicenseConfig,
    usage: LicenseUsage,
    now: u64,
    fingerprint: String,
    activation_request: ActivationRequest,
    activation_request_b64: String,
) -> LicenseStatus {
    let trial = load_or_create_trial_state(&config.state_path, now, &fingerprint);
    let mut errors = Vec::new();
    let (state, days_remaining, message) = match trial {
        Ok(trial_state) => {
            let trial_seconds = config.trial_days.saturating_mul(24 * 60 * 60);
            let expires_at = trial_state
                .first_seen_unix_timestamp_seconds
                .saturating_add(trial_seconds);
            let days = days_until(expires_at, now);
            if expires_at <= now {
                (
                    LicenseState::Expired,
                    Some(days),
                    "Trial period expired; install an offline license".to_string(),
                )
            } else {
                (
                    LicenseState::Trial,
                    Some(days),
                    format!("Offline trial active; {} days remaining", days.max(0)),
                )
            }
        }
        Err(error) => {
            errors.push(error.to_string());
            (
                LicenseState::Missing,
                None,
                "No license installed and trial state is unavailable".to_string(),
            )
        }
    };

    let valid = matches!(state, LicenseState::Trial);
    LicenseStatus {
        state,
        valid,
        licensed: false,
        trial: valid,
        message,
        license_id: None,
        customer_name: None,
        edition: Some("trial".to_string()),
        expires_at_unix_timestamp_seconds: None,
        days_remaining,
        features: vec![
            "management".to_string(),
            "smb_protection".to_string(),
            "dns_security".to_string(),
            "reputation".to_string(),
        ],
        limits: LicenseLimits::default(),
        usage,
        machine_fingerprint: fingerprint,
        activation_request,
        activation_request_b64,
        validation_errors: errors,
    }
}

fn status(
    state: LicenseState,
    valid: bool,
    licensed: bool,
    trial: bool,
    message: String,
    payload: Option<LicensePayload>,
    usage: LicenseUsage,
    fingerprint: String,
    activation_request: ActivationRequest,
    activation_request_b64: String,
    validation_errors: Vec<String>,
) -> LicenseStatus {
    LicenseStatus {
        state,
        valid,
        licensed,
        trial,
        message,
        license_id: payload.as_ref().map(|payload| payload.license_id.clone()),
        customer_name: payload
            .as_ref()
            .map(|payload| payload.customer_name.clone()),
        edition: payload.as_ref().map(|payload| payload.edition.clone()),
        expires_at_unix_timestamp_seconds: payload
            .as_ref()
            .map(|payload| payload.expires_at_unix_timestamp_seconds),
        days_remaining: payload.as_ref().map(|payload| {
            days_until(
                payload.expires_at_unix_timestamp_seconds,
                unix_timestamp_seconds(),
            )
        }),
        features: payload
            .as_ref()
            .map(|payload| payload.features.clone())
            .unwrap_or_default(),
        limits: payload
            .as_ref()
            .map(|payload| payload.limits.clone())
            .unwrap_or_default(),
        usage,
        machine_fingerprint: fingerprint,
        activation_request,
        activation_request_b64,
        validation_errors,
    }
}

fn load_or_create_trial_state(
    state_path: &str,
    now: u64,
    fingerprint: &str,
) -> Result<TrialState, LicenseError> {
    let path = Path::new(state_path);
    if path.exists() {
        let contents = read_to_string(path)?;
        let mut state: TrialState = serde_json::from_str(&contents)?;
        state.last_seen_unix_timestamp_seconds = now;
        write_json(path, &state)?;
        return Ok(state);
    }

    let state = TrialState {
        first_seen_unix_timestamp_seconds: now,
        last_seen_unix_timestamp_seconds: now,
        machine_fingerprint: fingerprint.to_string(),
    };
    write_json(path, &state)?;
    Ok(state)
}

fn normalize_license_text(value: &str) -> Result<String, LicenseError> {
    let trimmed = value.trim();
    if trimmed.starts_with('{') {
        let envelope: LicenseEnvelope = serde_json::from_str(trimmed)?;
        return serde_json::to_string_pretty(&envelope).map_err(LicenseError::Parse);
    }

    let decoded = BASE64
        .decode(trimmed)
        .map_err(|_| LicenseError::InvalidSignatureEncoding)?;
    let decoded_text =
        String::from_utf8(decoded).map_err(|_| LicenseError::InvalidSignatureEncoding)?;
    let envelope: LicenseEnvelope = serde_json::from_str(&decoded_text)?;
    serde_json::to_string_pretty(&envelope).map_err(LicenseError::Parse)
}

fn license_public_key_hex(config: &LicenseConfig) -> &str {
    config
        .public_key_hex
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(AXIOM_LICENSE_PUBLIC_KEY_HEX)
}

fn build_activation_request(
    config: &LicenseConfig,
    usage: LicenseUsage,
    now: u64,
    fingerprint: &str,
) -> ActivationRequest {
    ActivationRequest {
        product: "Axiom".to_string(),
        generated_at_unix_timestamp_seconds: now,
        machine_fingerprint: fingerprint.to_string(),
        hostname: hostname(),
        usage,
        license_path: config.license_path.clone(),
    }
}

fn activation_request_b64(request: &ActivationRequest) -> String {
    serde_json::to_vec_pretty(request)
        .map(|bytes| BASE64.encode(bytes))
        .unwrap_or_default()
}

fn machine_fingerprint() -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"axiom-license-v1");
    hasher.update(read_first_existing(&[
        "/etc/machine-id",
        "/var/lib/dbus/machine-id",
    ]));
    hasher.update(hostname());

    let mut macs = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "lo" {
                continue;
            }
            let address_path = entry.path().join("address");
            if let Ok(address) = fs::read_to_string(address_path) {
                let address = address.trim().to_ascii_lowercase();
                if !address.is_empty() && address != "00:00:00:00:00:00" {
                    macs.push(format!("{name}:{address}"));
                }
            }
        }
    }
    macs.sort();
    for mac in macs {
        hasher.update(mac);
    }

    hex(hasher.finalize().as_slice())
}

fn hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "unknown".to_string())
}

fn read_first_existing(paths: &[&str]) -> String {
    paths
        .iter()
        .find_map(|path| fs::read_to_string(path).ok())
        .unwrap_or_default()
}

fn exceeds(limit: Option<u32>, used: u32) -> bool {
    limit.is_some_and(|limit| used > limit)
}

fn days_until(timestamp: u64, now: u64) -> i64 {
    if timestamp >= now {
        ((timestamp - now) / 86_400) as i64
    } else {
        -(((now - timestamp) / 86_400) as i64)
    }
}

fn unix_timestamp_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn read_to_string(path: &Path) -> Result<String, LicenseError> {
    fs::read_to_string(path).map_err(|source| LicenseError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), LicenseError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_file(path, &bytes)
}

fn write_file(path: impl AsRef<Path>, bytes: &[u8]) -> Result<(), LicenseError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| LicenseError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }

    let temp_path = temp_path(path);
    fs::write(&temp_path, bytes).map_err(|source| LicenseError::Io {
        path: temp_path.display().to_string(),
        source,
    })?;
    fs::rename(&temp_path, path).map_err(|source| LicenseError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn temp_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".tmp");
    PathBuf::from(value)
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], ()> {
    let bytes = decode_hex(value)?;
    bytes.try_into().map_err(|_| ())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ()> {
    if !value.len().is_multiple_of(2) {
        return Err(());
    }

    let mut bytes = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let high = hex_value(chunk[0])?;
        let low = hex_value(chunk[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_value(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(()),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn default_license_enabled() -> bool {
    true
}

fn default_license_path() -> String {
    DEFAULT_LICENSE_PATH.to_string()
}

fn default_license_state_path() -> String {
    DEFAULT_LICENSE_STATE_PATH.to_string()
}

fn default_trial_days() -> u64 {
    DEFAULT_TRIAL_DAYS
}

fn default_warn_before_expiry_days() -> u64 {
    DEFAULT_WARN_BEFORE_EXPIRY_DAYS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_license_starts_offline_trial() {
        let base = std::env::temp_dir().join(format!("axiom-license-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        let config = LicenseConfig {
            license_path: base.join("license.json").display().to_string(),
            state_path: base.join("license-state.json").display().to_string(),
            ..LicenseConfig::default()
        };
        let status = evaluate_license(
            &config,
            LicenseUsage {
                management_nodes: 1,
                smb_nodes: 1,
                dns_nodes: 1,
                protected_clients: 12,
                reputation_entries: 4,
            },
        );

        assert_eq!(status.state, LicenseState::Trial);
        assert!(status.valid);
        assert!(status.trial);
        assert!(Path::new(&config.state_path).exists());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn signed_license_installs_with_configured_public_key() {
        let base =
            std::env::temp_dir().join(format!("axiom-license-signed-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        let (private_key_hex, public_key_hex) = generate_signing_key_hex().unwrap();
        let config = LicenseConfig {
            license_path: base.join("license.json").display().to_string(),
            state_path: base.join("license-state.json").display().to_string(),
            public_key_hex: Some(public_key_hex),
            ..LicenseConfig::default()
        };

        let usage = LicenseUsage {
            management_nodes: 1,
            smb_nodes: 1,
            dns_nodes: 1,
            protected_clients: 20,
            reputation_entries: 8,
        };
        let activation = evaluate_license(&config, usage.clone()).activation_request;
        let payload = LicensePayload {
            license_id: "LIC-TEST-001".to_string(),
            customer_name: "Axiom Test Lab".to_string(),
            edition: "lab".to_string(),
            issued_at_unix_timestamp_seconds: unix_timestamp_seconds(),
            expires_at_unix_timestamp_seconds: unix_timestamp_seconds() + 86_400 * 30,
            features: vec!["management".to_string(), "smb_protection".to_string()],
            limits: LicenseLimits {
                max_smb_nodes: Some(3),
                max_dns_nodes: Some(3),
                max_protected_clients: Some(100),
                max_reputation_entries: Some(1_000),
            },
            machine_fingerprint: Some(activation.machine_fingerprint),
            allowed_node_ids: Vec::new(),
            notes: Some("test license".to_string()),
        };
        let envelope = sign_license_payload(&payload, &private_key_hex).unwrap();
        let license_text = serde_json::to_string_pretty(&envelope).unwrap();
        let status = install_license_text(&config, &license_text, usage).unwrap();

        assert_eq!(status.state, LicenseState::Licensed);
        assert!(status.valid);
        assert_eq!(status.license_id.as_deref(), Some("LIC-TEST-001"));

        let _ = fs::remove_dir_all(&base);
    }
}
