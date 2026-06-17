use std::{
    env, fs,
    io::{self, Read},
    path::Path,
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use axiom_license::{
    LicenseLimits, LicensePayload, decode_activation_request_text, encode_license_envelope_b64,
    generate_signing_key_hex, public_key_hex_from_private_key_hex, sign_license_payload,
};
use serde_json::json;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let command = args.first().map(String::as_str).unwrap_or("");

    match command {
        "generate-key" => generate_key(),
        "public-key" => print_public_key(&args[1..]),
        "issue" => issue_license(&args[1..]),
        "-h" | "--help" | "help" | "" => {
            print_usage();
            Ok(())
        }
        _ => Err(format!("unknown command '{command}'").into()),
    }
}

fn generate_key() -> Result<(), Box<dyn std::error::Error>> {
    let (private_key_hex, public_key_hex) = generate_signing_key_hex()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "private_key_hex": private_key_hex,
            "public_key_hex": public_key_hex,
            "warning": "Store the private key only in the Axiom license issuing environment. Never commit it to git or install it on customer nodes."
        }))?
    );
    Ok(())
}

fn print_public_key(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let private_key_hex = private_key_from_args(args)?;
    println!("{}", public_key_hex_from_private_key_hex(&private_key_hex)?);
    Ok(())
}

fn issue_license(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let request_path = required(args, "--request")?;
    let request_text = read_text_argument(&request_path)?;
    let activation = decode_activation_request_text(&request_text)?;
    let private_key_hex = private_key_from_args(args)?;
    let now = unix_timestamp_seconds();
    let days = optional_u64(args, "--days")?.unwrap_or(365);
    let expires_at = optional_u64(args, "--expires-at")?
        .unwrap_or_else(|| now.saturating_add(days.saturating_mul(86_400)));
    let customer_name = required(args, "--customer")?;
    let edition = optional(args, "--edition").unwrap_or_else(|| "enterprise".to_string());
    let license_id = optional(args, "--license-id").unwrap_or_else(|| {
        let fingerprint = activation
            .machine_fingerprint
            .chars()
            .take(12)
            .collect::<String>();
        format!("AX-{}-{}", now, fingerprint)
    });
    let features = optional(args, "--features")
        .unwrap_or_else(|| "management,smb_protection,dns_security,reputation".to_string())
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let allowed_node_ids = optional(args, "--allowed-node-ids")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let notes = optional(args, "--notes");
    let machine_fingerprint = if has_flag(args, "--unbound") {
        None
    } else {
        Some(activation.machine_fingerprint)
    };

    let payload = LicensePayload {
        license_id,
        customer_name,
        edition,
        issued_at_unix_timestamp_seconds: now,
        expires_at_unix_timestamp_seconds: expires_at,
        features,
        limits: LicenseLimits {
            max_smb_nodes: optional_u32(args, "--max-smb-nodes")?,
            max_dns_nodes: optional_u32(args, "--max-dns-nodes")?,
            max_protected_clients: optional_u32(args, "--max-protected-clients")?,
            max_reputation_entries: optional_u32(args, "--max-reputation-entries")?,
        },
        machine_fingerprint,
        allowed_node_ids,
        notes,
    };

    let envelope = sign_license_payload(&payload, &private_key_hex)?;
    let output = if has_flag(args, "--base64") {
        encode_license_envelope_b64(&envelope)?
    } else {
        serde_json::to_string_pretty(&envelope)?
    };

    if let Some(output_path) = optional(args, "--output") {
        fs::write(output_path, output)?;
    } else {
        println!("{output}");
    }

    Ok(())
}

fn private_key_from_args(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(value) = optional(args, "--private-key-hex") {
        return Ok(value);
    }

    if let Some(path) = optional(args, "--private-key-file") {
        return Ok(fs::read_to_string(path)?.trim().to_string());
    }

    env::var("AXIOM_LICENSE_PRIVATE_KEY_HEX")
        .map(|value| value.trim().to_string())
        .map_err(|_| {
            "missing signing key; pass --private-key-hex, --private-key-file, or AXIOM_LICENSE_PRIVATE_KEY_HEX".into()
        })
}

fn read_text_argument(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    if value == "-" {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        return Ok(buffer);
    }

    if Path::new(value).exists() {
        return Ok(fs::read_to_string(value)?);
    }

    Ok(value.to_string())
}

fn required(args: &[String], name: &str) -> Result<String, Box<dyn std::error::Error>> {
    optional(args, name).ok_or_else(|| format!("missing required argument {name}").into())
}

fn optional(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|window| window[0] == name)
        .map(|window| window[1].clone())
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|arg| arg == name)
}

fn optional_u32(args: &[String], name: &str) -> Result<Option<u32>, Box<dyn std::error::Error>> {
    optional(args, name)
        .map(|value| value.parse::<u32>().map_err(Into::into))
        .transpose()
}

fn optional_u64(args: &[String], name: &str) -> Result<Option<u64>, Box<dyn std::error::Error>> {
    optional(args, name)
        .map(|value| value.parse::<u64>().map_err(Into::into))
        .transpose()
}

fn unix_timestamp_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn print_usage() {
    eprintln!(
        "Axiom license issuing tool

Usage:
  axiom-license-tool generate-key
  axiom-license-tool public-key --private-key-file /secure/axiom-license.key
  axiom-license-tool issue --request customer.axact --customer \"Customer\" --private-key-file /secure/axiom-license.key --output customer.axlic [options]

Issue options:
  --edition enterprise
  --days 365
  --expires-at <unix_seconds>
  --license-id AX-CUSTOMER-001
  --features management,smb_protection,dns_security,reputation
  --max-smb-nodes 5
  --max-dns-nodes 5
  --max-protected-clients 5000
  --max-reputation-entries 100000
  --allowed-node-ids node-a,node-b
  --notes \"Approved production license\"
  --unbound
  --base64
  --output customer.axlic"
    );
}
