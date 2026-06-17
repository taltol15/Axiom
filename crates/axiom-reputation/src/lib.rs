use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DEFAULT_REPUTATION_DB_PATH: &str = "/var/lib/axiom/reputation.json";
pub const DEFAULT_REPUTATION_AUDIT_LOG_PATH: &str = "/var/log/axiom/reputation-audit.jsonl";
const MAX_RECENT_OBSERVATIONS: usize = 2048;
const MAX_SCAN_QUEUE_ITEMS: usize = 4096;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ReputationVerdict {
    KnownGood,
    KnownBad,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KnownBadAction {
    #[default]
    Alert,
    Block,
    Quarantine,
    Allow,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReputationEntry {
    pub id: u64,
    pub sha256: String,
    pub md5: Option<String>,
    pub verdict: ReputationVerdict,
    pub source: String,
    pub notes: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub last_seen: Option<u64>,
    pub hit_count: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileReputationReport {
    pub node_id: String,
    pub route_name: String,
    pub interface: String,
    pub direction: String,
    pub source_ip: String,
    pub target_addr: String,
    pub destination_share: Option<String>,
    pub source_user: Option<String>,
    pub file_name: String,
    pub extension: Option<String>,
    pub mime_type: Option<String>,
    pub file_size: u64,
    pub creation_time: Option<u64>,
    pub upload_timestamp: u64,
    pub sha256: String,
    pub md5: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileObservation {
    pub id: u64,
    pub sha256: String,
    pub md5: String,
    pub verdict: ReputationVerdict,
    pub node_id: String,
    pub route_name: String,
    pub interface: String,
    pub direction: String,
    pub source_ip: String,
    pub target_addr: String,
    pub destination_share: Option<String>,
    pub source_user: Option<String>,
    pub file_name: String,
    pub extension: Option<String>,
    pub mime_type: Option<String>,
    pub file_size: u64,
    pub creation_time: Option<u64>,
    pub upload_timestamp: u64,
    pub observed_at: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanQueueState {
    Pending,
    Scanning,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScanQueueItem {
    pub id: u64,
    pub sha256: String,
    pub state: ScanQueueState,
    pub provider: String,
    pub attempts: u32,
    pub last_error: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReputationAuditEvent {
    pub unix_timestamp_seconds: u64,
    pub actor: String,
    pub action: String,
    pub entry_id: Option<u64>,
    pub sha256: Option<String>,
    pub old_value: Option<serde_json::Value>,
    pub new_value: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReputationCreateRequest {
    pub sha256: String,
    pub md5: Option<String>,
    pub verdict: ReputationVerdict,
    pub source: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReputationUpdateRequest {
    pub sha256: Option<String>,
    pub md5: Option<String>,
    pub verdict: Option<ReputationVerdict>,
    pub source: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReputationLookupResponse {
    pub verdict: ReputationVerdict,
    pub entry: Option<ReputationEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReputationBulkImportRequest {
    pub contents: String,
    pub source: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReputationBulkImportResponse {
    pub imported: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ReputationSummary {
    pub known_good_count: usize,
    pub known_bad_count: usize,
    pub unknown_count: usize,
    pub total_entries: usize,
    pub pending_scans: usize,
    pub scanning: usize,
    pub completed_scans: usize,
    pub failed_scans: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReputationListResponse {
    pub summary: ReputationSummary,
    pub entries: Vec<ReputationEntry>,
    pub top_seen_files: Vec<ReputationEntry>,
    pub recently_added_entries: Vec<ReputationEntry>,
    pub recent_observations: Vec<FileObservation>,
    pub scan_queue: Vec<ScanQueueItem>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
struct ReputationDatabase {
    next_entry_id: u64,
    next_observation_id: u64,
    next_scan_id: u64,
    entries: Vec<ReputationEntry>,
    observations: Vec<FileObservation>,
    scan_queue: Vec<ScanQueueItem>,
}

#[derive(Debug)]
pub struct ReputationStore {
    db_path: PathBuf,
    audit_log_path: PathBuf,
    db: Mutex<ReputationDatabase>,
}

#[derive(Debug, Error)]
pub enum ReputationError {
    #[error("invalid SHA256 hash")]
    InvalidSha256,
    #[error("invalid MD5 hash")]
    InvalidMd5,
    #[error("reputation entry not found")]
    NotFound,
    #[error("SHA256 already exists")]
    DuplicateSha256,
}

impl ReputationStore {
    pub fn open_default() -> anyhow::Result<Self> {
        Self::open(
            PathBuf::from(DEFAULT_REPUTATION_DB_PATH),
            PathBuf::from(DEFAULT_REPUTATION_AUDIT_LOG_PATH),
        )
    }

    pub fn open(db_path: PathBuf, audit_log_path: PathBuf) -> anyhow::Result<Self> {
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed creating {}", parent.display()))?;
        }
        if let Some(parent) = audit_log_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed creating {}", parent.display()))?;
        }

        let db = if db_path.exists() {
            let contents = fs::read_to_string(&db_path)
                .with_context(|| format!("failed reading {}", db_path.display()))?;
            serde_json::from_str(&contents)
                .with_context(|| format!("failed parsing {}", db_path.display()))?
        } else {
            ReputationDatabase {
                next_entry_id: 1,
                next_observation_id: 1,
                next_scan_id: 1,
                ..ReputationDatabase::default()
            }
        };

        Ok(Self {
            db_path,
            audit_log_path,
            db: Mutex::new(db),
        })
    }

    pub fn lookup(&self, sha256: &str) -> Result<ReputationLookupResponse, ReputationError> {
        let sha256 = normalized_sha256(sha256)?;
        let now = unix_timestamp_seconds();
        let mut db = self.db.lock().expect("reputation db mutex poisoned");
        let mut response = ReputationLookupResponse {
            verdict: ReputationVerdict::Unknown,
            entry: None,
        };

        if let Some(entry) = db.entries.iter_mut().find(|entry| entry.sha256 == sha256) {
            entry.hit_count = entry.hit_count.saturating_add(1);
            entry.last_seen = Some(now);
            entry.updated_at = now;
            response.verdict = entry.verdict;
            response.entry = Some(entry.clone());
            let _ = self.persist_locked(&db);
        }

        Ok(response)
    }

    pub fn list(&self) -> ReputationListResponse {
        let db = self.db.lock().expect("reputation db mutex poisoned");
        let mut entries = db.entries.clone();
        entries.sort_by(|left, right| {
            right
                .updated_at
                .cmp(&left.updated_at)
                .then_with(|| left.sha256.cmp(&right.sha256))
        });

        let mut top_seen_files = db.entries.clone();
        top_seen_files.sort_by(|left, right| {
            right
                .hit_count
                .cmp(&left.hit_count)
                .then_with(|| right.last_seen.cmp(&left.last_seen))
        });
        top_seen_files.truncate(10);

        let mut recently_added_entries = db.entries.clone();
        recently_added_entries.sort_by(|left, right| right.created_at.cmp(&left.created_at));
        recently_added_entries.truncate(10);

        let mut recent_observations = db.observations.clone();
        recent_observations.sort_by(|left, right| right.observed_at.cmp(&left.observed_at));
        recent_observations.truncate(50);

        let mut scan_queue = db.scan_queue.clone();
        scan_queue.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
        scan_queue.truncate(50);

        ReputationListResponse {
            summary: summary(&db),
            entries,
            top_seen_files,
            recently_added_entries,
            recent_observations,
            scan_queue,
        }
    }

    pub fn known_bad_sha256s(&self) -> Vec<String> {
        let db = self.db.lock().expect("reputation db mutex poisoned");
        let mut hashes: Vec<_> = db
            .entries
            .iter()
            .filter(|entry| entry.verdict == ReputationVerdict::KnownBad)
            .map(|entry| entry.sha256.clone())
            .collect();
        hashes.sort();
        hashes
    }

    pub fn create(
        &self,
        request: ReputationCreateRequest,
        actor: &str,
    ) -> Result<ReputationEntry, ReputationError> {
        let sha256 = normalized_sha256(&request.sha256)?;
        let md5 = normalize_optional_md5(request.md5.as_deref())?;
        let mut db = self.db.lock().expect("reputation db mutex poisoned");
        if db.entries.iter().any(|entry| entry.sha256 == sha256) {
            return Err(ReputationError::DuplicateSha256);
        }

        let now = unix_timestamp_seconds();
        let entry = ReputationEntry {
            id: next_id(&mut db.next_entry_id),
            sha256,
            md5,
            verdict: request.verdict,
            source: request
                .source
                .unwrap_or_else(|| "Administrator".to_string()),
            notes: request.notes.unwrap_or_default(),
            created_at: now,
            updated_at: now,
            last_seen: None,
            hit_count: 0,
        };

        db.entries.push(entry.clone());
        let _ = self.persist_locked(&db);
        self.append_audit(ReputationAuditEvent {
            unix_timestamp_seconds: now,
            actor: actor.to_string(),
            action: "create".to_string(),
            entry_id: Some(entry.id),
            sha256: Some(entry.sha256.clone()),
            old_value: None,
            new_value: serde_json::to_value(&entry).ok(),
        });

        Ok(entry)
    }

    pub fn update(
        &self,
        id: u64,
        request: ReputationUpdateRequest,
        actor: &str,
    ) -> Result<ReputationEntry, ReputationError> {
        let mut db = self.db.lock().expect("reputation db mutex poisoned");
        let entry_index = db
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or(ReputationError::NotFound)?;
        let old = db.entries[entry_index].clone();
        let mut updated = old.clone();

        if let Some(sha256) = request.sha256 {
            let sha256 = normalized_sha256(&sha256)?;
            if sha256 != old.sha256 && db.entries.iter().any(|entry| entry.sha256 == sha256) {
                return Err(ReputationError::DuplicateSha256);
            }
            updated.sha256 = sha256;
        }

        if request.md5.is_some() {
            updated.md5 = normalize_optional_md5(request.md5.as_deref())?;
        }

        if let Some(verdict) = request.verdict {
            updated.verdict = verdict;
        }
        if let Some(source) = request.source {
            updated.source = source;
        }
        if let Some(notes) = request.notes {
            updated.notes = notes;
        }

        updated.updated_at = unix_timestamp_seconds();
        db.entries[entry_index] = updated.clone();
        let _ = self.persist_locked(&db);
        self.append_audit(ReputationAuditEvent {
            unix_timestamp_seconds: updated.updated_at,
            actor: actor.to_string(),
            action: "update".to_string(),
            entry_id: Some(updated.id),
            sha256: Some(updated.sha256.clone()),
            old_value: serde_json::to_value(&old).ok(),
            new_value: serde_json::to_value(&updated).ok(),
        });

        Ok(updated)
    }

    pub fn delete(&self, id: u64, actor: &str) -> Result<ReputationEntry, ReputationError> {
        let mut db = self.db.lock().expect("reputation db mutex poisoned");
        let entry_index = db
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or(ReputationError::NotFound)?;
        let removed = db.entries.remove(entry_index);
        let now = unix_timestamp_seconds();
        let _ = self.persist_locked(&db);
        self.append_audit(ReputationAuditEvent {
            unix_timestamp_seconds: now,
            actor: actor.to_string(),
            action: "delete".to_string(),
            entry_id: Some(removed.id),
            sha256: Some(removed.sha256.clone()),
            old_value: serde_json::to_value(&removed).ok(),
            new_value: None,
        });

        Ok(removed)
    }

    pub fn bulk_import(
        &self,
        request: ReputationBulkImportRequest,
        actor: &str,
    ) -> ReputationBulkImportResponse {
        let mut imported = 0;
        let mut skipped = 0;
        let mut errors = Vec::new();
        let source = request
            .source
            .unwrap_or_else(|| "Manual Import".to_string());

        for (line_index, raw_line) in request.contents.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let columns = parse_import_line(line);
            if columns.len() < 2 {
                skipped += 1;
                errors.push(format!(
                    "line {}: expected sha256,verdict,notes",
                    line_index + 1
                ));
                continue;
            }

            let verdict = match parse_verdict(&columns[1]) {
                Some(verdict) => verdict,
                None => {
                    skipped += 1;
                    errors.push(format!("line {}: invalid verdict", line_index + 1));
                    continue;
                }
            };

            let notes = columns.get(2).cloned().unwrap_or_default();
            match self.create(
                ReputationCreateRequest {
                    sha256: columns[0].clone(),
                    md5: None,
                    verdict,
                    source: Some(source.clone()),
                    notes: Some(notes),
                },
                actor,
            ) {
                Ok(_) => imported += 1,
                Err(ReputationError::DuplicateSha256) => skipped += 1,
                Err(error) => {
                    skipped += 1;
                    errors.push(format!("line {}: {error}", line_index + 1));
                }
            }
        }

        ReputationBulkImportResponse {
            imported,
            skipped,
            errors,
        }
    }

    pub fn record_file_report(&self, report: FileReputationReport) -> ReputationVerdict {
        let Ok(sha256) = normalized_sha256(&report.sha256) else {
            return ReputationVerdict::Unknown;
        };
        let md5 = normalized_md5(&report.md5).unwrap_or_else(|_| report.md5.clone());
        let now = unix_timestamp_seconds();
        let mut db = self.db.lock().expect("reputation db mutex poisoned");
        let verdict =
            if let Some(entry) = db.entries.iter_mut().find(|entry| entry.sha256 == sha256) {
                entry.hit_count = entry.hit_count.saturating_add(1);
                entry.last_seen = Some(now);
                entry.updated_at = now;
                entry.verdict
            } else {
                let entry = ReputationEntry {
                    id: next_id(&mut db.next_entry_id),
                    sha256: sha256.clone(),
                    md5: Some(md5.clone()),
                    verdict: ReputationVerdict::Unknown,
                    source: "System".to_string(),
                    notes: "Observed by SMB streaming inspection".to_string(),
                    created_at: now,
                    updated_at: now,
                    last_seen: Some(now),
                    hit_count: 1,
                };
                db.entries.push(entry);
                enqueue_scan_locked(&mut db, &sha256, now);
                ReputationVerdict::Unknown
            };

        let observation_id = next_id(&mut db.next_observation_id);
        db.observations.push(FileObservation {
            id: observation_id,
            sha256,
            md5,
            verdict,
            node_id: report.node_id,
            route_name: report.route_name,
            interface: report.interface,
            direction: report.direction,
            source_ip: report.source_ip,
            target_addr: report.target_addr,
            destination_share: report.destination_share,
            source_user: report.source_user,
            file_name: report.file_name,
            extension: report.extension,
            mime_type: report.mime_type,
            file_size: report.file_size,
            creation_time: report.creation_time,
            upload_timestamp: report.upload_timestamp,
            observed_at: now,
        });

        if db.observations.len() > MAX_RECENT_OBSERVATIONS {
            let drop_count = db.observations.len() - MAX_RECENT_OBSERVATIONS;
            db.observations.drain(..drop_count);
        }

        let _ = self.persist_locked(&db);
        verdict
    }

    fn persist_locked(&self, db: &ReputationDatabase) -> anyhow::Result<()> {
        let serialized =
            serde_json::to_string_pretty(db).context("failed serializing reputation db")?;
        let temp_path = temp_path_for(&self.db_path);
        fs::write(&temp_path, serialized)
            .with_context(|| format!("failed writing {}", temp_path.display()))?;
        fs::rename(&temp_path, &self.db_path).with_context(|| {
            format!(
                "failed replacing {} with {}",
                self.db_path.display(),
                temp_path.display()
            )
        })?;
        Ok(())
    }

    fn append_audit(&self, event: ReputationAuditEvent) {
        let Ok(serialized) = serde_json::to_string(&event) else {
            return;
        };
        let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.audit_log_path)
        else {
            return;
        };
        let _ = writeln!(file, "{serialized}");
    }
}

pub trait ScannerProvider: Send + Sync {
    fn name(&self) -> &'static str;
}

#[derive(Debug, Default)]
pub struct NoopScannerProvider;

impl ScannerProvider for NoopScannerProvider {
    fn name(&self) -> &'static str {
        "noop"
    }
}

fn summary(db: &ReputationDatabase) -> ReputationSummary {
    let mut verdict_counts: HashMap<ReputationVerdict, usize> = HashMap::new();
    for entry in &db.entries {
        *verdict_counts.entry(entry.verdict).or_default() += 1;
    }

    ReputationSummary {
        known_good_count: *verdict_counts
            .get(&ReputationVerdict::KnownGood)
            .unwrap_or(&0),
        known_bad_count: *verdict_counts
            .get(&ReputationVerdict::KnownBad)
            .unwrap_or(&0),
        unknown_count: *verdict_counts
            .get(&ReputationVerdict::Unknown)
            .unwrap_or(&0),
        total_entries: db.entries.len(),
        pending_scans: db
            .scan_queue
            .iter()
            .filter(|item| item.state == ScanQueueState::Pending)
            .count(),
        scanning: db
            .scan_queue
            .iter()
            .filter(|item| item.state == ScanQueueState::Scanning)
            .count(),
        completed_scans: db
            .scan_queue
            .iter()
            .filter(|item| item.state == ScanQueueState::Completed)
            .count(),
        failed_scans: db
            .scan_queue
            .iter()
            .filter(|item| item.state == ScanQueueState::Failed)
            .count(),
    }
}

fn enqueue_scan_locked(db: &mut ReputationDatabase, sha256: &str, now: u64) {
    if db.scan_queue.iter().any(|item| {
        item.sha256 == sha256
            && matches!(
                item.state,
                ScanQueueState::Pending | ScanQueueState::Scanning
            )
    }) {
        return;
    }

    db.scan_queue.push(ScanQueueItem {
        id: next_id(&mut db.next_scan_id),
        sha256: sha256.to_string(),
        state: ScanQueueState::Pending,
        provider: "noop".to_string(),
        attempts: 0,
        last_error: None,
        created_at: now,
        updated_at: now,
    });

    if db.scan_queue.len() > MAX_SCAN_QUEUE_ITEMS {
        let drop_count = db.scan_queue.len() - MAX_SCAN_QUEUE_ITEMS;
        db.scan_queue.drain(..drop_count);
    }
}

fn normalized_sha256(value: &str) -> Result<String, ReputationError> {
    let value = value.trim().to_ascii_lowercase();
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(value)
    } else {
        Err(ReputationError::InvalidSha256)
    }
}

fn normalize_optional_md5(value: Option<&str>) -> Result<Option<String>, ReputationError> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => normalized_md5(value).map(Some),
        None => Ok(None),
    }
}

fn normalized_md5(value: &str) -> Result<String, ReputationError> {
    let value = value.trim().to_ascii_lowercase();
    if value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(value)
    } else {
        Err(ReputationError::InvalidMd5)
    }
}

fn next_id(value: &mut u64) -> u64 {
    let id = (*value).max(1);
    *value = id.saturating_add(1);
    id
}

fn parse_import_line(line: &str) -> Vec<String> {
    line.split(',')
        .map(|part| part.trim().trim_matches('"').to_string())
        .collect()
}

fn parse_verdict(value: &str) -> Option<ReputationVerdict> {
    match value.trim().to_ascii_lowercase().as_str() {
        "known_good" | "good" | "allow" | "trusted" => Some(ReputationVerdict::KnownGood),
        "known_bad" | "bad" | "malicious" | "block" => Some(ReputationVerdict::KnownBad),
        "unknown" => Some(ReputationVerdict::Unknown),
        _ => None,
    }
}

fn temp_path_for(path: &Path) -> PathBuf {
    let mut temp_path = path.to_path_buf();
    temp_path.set_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("json")
    ));
    temp_path
}

pub fn unix_timestamp_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

pub fn cache_expiry_timestamp(ttl_seconds: u64) -> u64 {
    unix_timestamp_seconds().saturating_add(ttl_seconds.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn test_store(name: &str) -> ReputationStore {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "axiom-reputation-test-{}-{name}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        ReputationStore::open(base.join("reputation.json"), base.join("audit.jsonl")).unwrap()
    }

    #[test]
    fn create_and_lookup_updates_hit_tracking() {
        let store = test_store("lookup");
        let sha256 = "a".repeat(64);
        let md5 = "b".repeat(32);

        let created = store
            .create(
                ReputationCreateRequest {
                    sha256: sha256.clone(),
                    md5: Some(md5.clone()),
                    verdict: ReputationVerdict::KnownBad,
                    source: Some("Administrator".to_string()),
                    notes: Some("test malicious file".to_string()),
                },
                "admin",
            )
            .unwrap();
        assert_eq!(created.hit_count, 0);

        let first_lookup = store.lookup(&sha256).unwrap();
        assert_eq!(first_lookup.verdict, ReputationVerdict::KnownBad);
        assert_eq!(first_lookup.entry.unwrap().hit_count, 1);

        let second_lookup = store.lookup(&sha256).unwrap();
        assert_eq!(second_lookup.entry.unwrap().hit_count, 2);
    }

    #[test]
    fn known_bad_feed_contains_only_bad_hashes() {
        let store = test_store("known-bad-feed");
        let bad_sha256 = "1".repeat(64);
        let good_sha256 = "2".repeat(64);

        store
            .create(
                ReputationCreateRequest {
                    sha256: bad_sha256.clone(),
                    md5: None,
                    verdict: ReputationVerdict::KnownBad,
                    source: Some("Administrator".to_string()),
                    notes: None,
                },
                "admin",
            )
            .unwrap();
        store
            .create(
                ReputationCreateRequest {
                    sha256: good_sha256,
                    md5: None,
                    verdict: ReputationVerdict::KnownGood,
                    source: Some("Administrator".to_string()),
                    notes: None,
                },
                "admin",
            )
            .unwrap();

        assert_eq!(store.known_bad_sha256s(), vec![bad_sha256]);
    }

    #[test]
    fn unknown_file_report_creates_entry_observation_and_scan_item() {
        let store = test_store("file-report");
        let sha256 = "c".repeat(64);
        let md5 = "d".repeat(32);

        let verdict = store.record_file_report(FileReputationReport {
            node_id: "smb-node-1".to_string(),
            route_name: "proxy-eth1".to_string(),
            interface: "eth1".to_string(),
            direction: "client_to_server".to_string(),
            source_ip: "10.0.0.2".to_string(),
            target_addr: "10.0.0.10:445".to_string(),
            destination_share: Some("AxiomLabShare".to_string()),
            source_user: None,
            file_name: "sample.bin".to_string(),
            extension: Some("bin".to_string()),
            mime_type: Some("application/octet-stream".to_string()),
            file_size: 42,
            creation_time: None,
            upload_timestamp: unix_timestamp_seconds(),
            sha256: sha256.clone(),
            md5,
        });

        assert_eq!(verdict, ReputationVerdict::Unknown);

        let list = store.list();
        assert_eq!(list.summary.unknown_count, 1);
        assert_eq!(list.summary.pending_scans, 1);
        assert_eq!(list.recent_observations.len(), 1);
        assert_eq!(list.recent_observations[0].sha256, sha256);
        assert_eq!(list.recent_observations[0].file_size, 42);
    }
}
