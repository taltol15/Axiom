use axiom_config::{DnsPolicyConfig, PolicyConfig};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub node_id: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPolicyBundle {
    pub command_id: String,
    pub issued_unix_timestamp_seconds: u64,
    pub policy: Option<PolicyConfig>,
    pub dns_policy: Option<DnsPolicyConfig>,
    #[serde(default)]
    pub known_bad_reputation_hashes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlApplyResponse {
    pub accepted: bool,
    pub message: String,
    pub applied_unix_timestamp_seconds: u64,
    pub policy_generation: u64,
    pub dns_policy_generation: u64,
}

pub fn encrypt_payload<T: Serialize>(
    node_id: &str,
    shared_secret: &str,
    payload: &T,
) -> anyhow::Result<EncryptedEnvelope> {
    let cipher = cipher_from_secret(shared_secret)?;
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let plaintext = serde_json::to_vec(payload)?;
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|_| anyhow::anyhow!("failed encrypting control payload"))?;

    Ok(EncryptedEnvelope {
        node_id: node_id.to_string(),
        nonce: STANDARD_NO_PAD.encode(nonce),
        ciphertext: STANDARD_NO_PAD.encode(ciphertext),
    })
}

pub fn decrypt_payload<T: DeserializeOwned>(
    shared_secret: &str,
    envelope: &EncryptedEnvelope,
) -> anyhow::Result<T> {
    let cipher = cipher_from_secret(shared_secret)?;
    let nonce_bytes = STANDARD_NO_PAD
        .decode(&envelope.nonce)
        .map_err(|error| anyhow::anyhow!("invalid control nonce encoding: {error}"))?;
    if nonce_bytes.len() != 12 {
        return Err(anyhow::anyhow!("invalid control nonce length"));
    }
    let ciphertext = STANDARD_NO_PAD
        .decode(&envelope.ciphertext)
        .map_err(|error| anyhow::anyhow!("invalid control ciphertext encoding: {error}"))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("control payload authentication failed"))?;

    Ok(serde_json::from_slice(&plaintext)?)
}

fn cipher_from_secret(shared_secret: &str) -> anyhow::Result<ChaCha20Poly1305> {
    if shared_secret.is_empty() {
        return Err(anyhow::anyhow!("empty control shared secret"));
    }

    let mut hasher = Sha256::new();
    hasher.update(b"axiom-control-v1:");
    hasher.update(shared_secret.as_bytes());
    let digest = hasher.finalize();
    ChaCha20Poly1305::new_from_slice(&digest)
        .map_err(|_| anyhow::anyhow!("failed deriving control cipher key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_policy_bundle_round_trips() {
        let bundle = ControlPolicyBundle {
            command_id: "cmd-1".to_string(),
            issued_unix_timestamp_seconds: 42,
            policy: None,
            dns_policy: None,
            known_bad_reputation_hashes: Some(vec!["a".repeat(64)]),
        };

        let envelope = encrypt_payload("dns-node-1", "shared-secret", &bundle).unwrap();
        let decoded: ControlPolicyBundle = decrypt_payload("shared-secret", &envelope).unwrap();

        assert_eq!(decoded.command_id, "cmd-1");
        assert_eq!(decoded.issued_unix_timestamp_seconds, 42);
        assert_eq!(
            decoded.known_bad_reputation_hashes,
            Some(vec!["a".repeat(64)])
        );
    }

    #[test]
    fn decrypt_rejects_wrong_secret() {
        let bundle = ControlPolicyBundle {
            command_id: "cmd-2".to_string(),
            issued_unix_timestamp_seconds: 43,
            policy: None,
            dns_policy: None,
            known_bad_reputation_hashes: None,
        };

        let envelope = encrypt_payload("smb-node-1", "shared-secret", &bundle).unwrap();
        let result = decrypt_payload::<ControlPolicyBundle>("wrong-secret", &envelope);

        assert!(result.is_err());
    }
}
