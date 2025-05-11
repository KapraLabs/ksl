use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use sha3::{Digest, Sha3_256};
use tar::{Archive, Builder};
use flate2::{write::GzEncoder, Compression};
use reqwest;
use semver::{Version, VersionReq};
use crate::ksl_validator_keys::{ValidatorKeyPair, KeyType};
use crate::ksl_kapra_crypto::{KapraCrypto, SignatureScheme};
use tera::{Tera, Context};

/// Update target type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UpdateTarget {
    Validator,
    ContractRuntime,
    ConsensusEngine,
    NetworkStack,
    Custom(String),
}

/// Compatibility map for validator versions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityMap {
    /// Minimum validator version required
    pub min_version: Version,
    /// Maximum validator version supported
    pub max_version: Option<Version>,
    /// Specific version requirements
    pub version_requirements: Vec<VersionReq>,
    /// Excluded versions
    pub excluded_versions: Vec<Version>,
}

/// Update backup
#[derive(Debug)]
pub struct UpdateBackup {
    /// Original binary
    binary: Vec<u8>,
    /// Original metadata
    metadata: UpdateMetadata,
    /// Backup timestamp
    timestamp: DateTime<Utc>,
    /// Backup path
    path: PathBuf,
}

/// Signature rotation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureRotationPolicy {
    /// Active signing keys
    pub active_keys: Vec<ValidatorKeyPair>,
    /// Minimum required signatures
    pub min_signatures: usize,
    /// Rotation interval
    pub rotation_interval: chrono::Duration,
    /// Last rotation timestamp
    pub last_rotation: DateTime<Utc>,
}

/// HTML report configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    /// Report title
    pub title: String,
    /// Report description
    pub description: String,
    /// Include charts
    pub include_charts: bool,
    /// Include logs
    pub include_logs: bool,
    /// Custom CSS
    pub custom_css: Option<String>,
}

/// Update metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateMetadata {
    /// Update version
    pub version: Version,
    /// Update description
    pub description: String,
    /// Binary hash
    pub binary_hash: [u8; 32],
    /// Target component
    pub target: UpdateTarget,
    /// Minimum validator version required
    pub min_validator_version: Version,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Expiration timestamp (optional)
    pub expires_at: Option<DateTime<Utc>>,
    /// Signer public key
    pub signer_pubkey: Vec<u8>,
    /// Update signature
    pub signature: Vec<u8>,
    /// Compatibility map
    pub compatibility: CompatibilityMap,
    /// Required signatures
    pub required_signatures: usize,
    /// Signatures
    pub signatures: Vec<UpdateSignature>,
}

/// Update signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSignature {
    /// Signer public key
    pub signer_pubkey: Vec<u8>,
    /// Signature
    pub signature: Vec<u8>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Update history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateHistoryEntry {
    /// Update ID (hash of metadata)
    pub update_id: String,
    /// Applied timestamp
    pub applied_at: DateTime<Utc>,
    /// Update metadata
    pub metadata: UpdateMetadata,
    /// Application status
    pub status: UpdateStatus,
    /// Error message if failed
    pub error: Option<String>,
}

/// Update status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UpdateStatus {
    Success,
    Failed,
    Reverted,
}

/// Update manager
pub struct UpdateManager {
    /// Update history file path
    history_path: PathBuf,
    /// Update history
    history: Vec<UpdateHistoryEntry>,
    /// Current version
    current_version: Version,
    /// Registry client
    registry_client: Option<UpdateRegistryClient>,
}

/// Update registry client
struct UpdateRegistryClient {
    /// Registry URL
    url: String,
    /// API key (optional)
    api_key: Option<String>,
    /// HTTP client
    client: reqwest::Client,
}

impl UpdateManager {
    /// Creates a new update manager
    pub fn new(history_path: PathBuf, current_version: Version) -> io::Result<Self> {
        let history = if history_path.exists() {
            let content = fs::read_to_string(&history_path)?;
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            Vec::new()
        };

        Ok(UpdateManager {
            history_path,
            history,
            current_version,
            registry_client: None,
        })
    }

    /// Signs an update bundle
    pub fn sign_update(&self, binary_path: &Path, metadata: UpdateMetadata, key_pair: &ValidatorKeyPair) -> io::Result<PathBuf> {
        // Read binary
        let mut binary = Vec::new();
        File::open(binary_path)?.read_to_end(&mut binary)?;

        // Calculate binary hash
        let mut hasher = Sha3_256::new();
        hasher.update(&binary);
        let binary_hash = hasher.finalize();

        // Create metadata with hash
        let mut metadata = metadata;
        metadata.binary_hash.copy_from_slice(&binary_hash);
        metadata.created_at = Utc::now();
        metadata.signer_pubkey = key_pair.public_key.clone();

        // Create message to sign (binary hash + metadata)
        let mut message = Vec::new();
        message.extend_from_slice(&binary_hash);
        message.extend_from_slice(&serde_json::to_vec(&metadata)?);

        // Sign message
        metadata.signature = KapraCrypto::sign_dilithium(&key_pair.private_key, &message)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // Create update bundle
        let output_path = binary_path.with_extension("kslupdate");
        let file = File::create(&output_path)?;
        let encoder = GzEncoder::new(file, Compression::default());
        let mut archive = Builder::new(encoder);

        // Add binary
        let binary_path_in_archive = Path::new("update.bin");
        archive.append_data(binary_path_in_archive, binary_path, &binary)?;

        // Add metadata
        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        archive.append_data(
            Path::new("update.toml"),
            binary_path,
            metadata_json.as_bytes(),
        )?;

        Ok(output_path)
    }

    /// Verifies an update bundle
    pub fn verify_update(&self, update_path: &Path, dry_run: bool) -> Result<UpdateMetadata, String> {
        // Read update bundle
        let file = File::open(update_path)
            .map_err(|e| format!("Failed to open update bundle: {}", e))?;
        let mut archive = Archive::new(file);

        // Extract metadata
        let mut metadata_entry = archive
            .entries()
            .map_err(|e| format!("Failed to read archive: {}", e))?
            .find(|e| {
                e.as_ref()
                    .map(|f| f.path().unwrap_or_default().ends_with("update.toml"))
                    .unwrap_or(false)
            })
            .ok_or_else(|| "Metadata not found in update bundle".to_string())?
            .map_err(|e| format!("Failed to read metadata: {}", e))?;

        let mut metadata_str = String::new();
        metadata_entry
            .read_to_string(&mut metadata_str)
            .map_err(|e| format!("Failed to read metadata: {}", e))?;

        let metadata: UpdateMetadata = toml::from_str(&metadata_str)
            .map_err(|e| format!("Failed to parse metadata: {}", e))?;

        // Verify version
        if metadata.version <= self.current_version {
            return Err("Update version must be greater than current version".to_string());
        }

        // Verify expiration
        if let Some(expires_at) = metadata.expires_at {
            if expires_at < Utc::now() {
                return Err("Update has expired".to_string());
            }
        }

        // Extract binary
        let mut binary_entry = archive
            .entries()
            .map_err(|e| format!("Failed to read archive: {}", e))?
            .find(|e| {
                e.as_ref()
                    .map(|f| f.path().unwrap_or_default().ends_with("update.bin"))
                    .unwrap_or(false)
            })
            .ok_or_else(|| "Binary not found in update bundle".to_string())?
            .map_err(|e| format!("Failed to read binary: {}", e))?;

        let mut binary = Vec::new();
        binary_entry
            .read_to_end(&mut binary)
            .map_err(|e| format!("Failed to read binary: {}", e))?;

        // Verify binary hash
        let mut hasher = Sha3_256::new();
        hasher.update(&binary);
        let binary_hash = hasher.finalize();

        if binary_hash.as_slice() != metadata.binary_hash {
            return Err("Binary hash mismatch".to_string());
        }

        // Verify signature
        let mut message = Vec::new();
        message.extend_from_slice(&metadata.binary_hash);
        message.extend_from_slice(&serde_json::to_vec(&metadata).unwrap());

        if !KapraCrypto::verify_dilithium(&metadata.signer_pubkey, &message, &metadata.signature) {
            return Err("Invalid signature".to_string());
        }

        // Run in sandbox if dry run
        if dry_run {
            self.sandbox_test_update(&binary, &metadata)?;
        }

        Ok(metadata)
    }

    /// Applies an update
    pub fn apply_update(&mut self, update_path: &Path) -> Result<(), String> {
        // Verify update first
        let metadata = self.verify_update(update_path, false)?;

        // Extract binary
        let file = File::open(update_path)
            .map_err(|e| format!("Failed to open update bundle: {}", e))?;
        let mut archive = Archive::new(file);

        let mut binary_entry = archive
            .entries()
            .map_err(|e| format!("Failed to read archive: {}", e))?
            .find(|e| {
                e.as_ref()
                    .map(|f| f.path().unwrap_or_default().ends_with("update.bin"))
                    .unwrap_or(false)
            })
            .ok_or_else(|| "Binary not found in update bundle".to_string())?
            .map_err(|e| format!("Failed to read binary: {}", e))?;

        let mut binary = Vec::new();
        binary_entry
            .read_to_end(&mut binary)
            .map_err(|e| format!("Failed to read binary: {}", e))?;

        // Apply update based on target
        match metadata.target {
            UpdateTarget::Validator => self.apply_validator_update(&binary, &metadata)?,
            UpdateTarget::ContractRuntime => self.apply_runtime_update(&binary, &metadata)?,
            UpdateTarget::ConsensusEngine => self.apply_consensus_update(&binary, &metadata)?,
            UpdateTarget::NetworkStack => self.apply_network_update(&binary, &metadata)?,
            UpdateTarget::Custom(ref name) => self.apply_custom_update(name, &binary, &metadata)?,
        }

        // Update version
        self.current_version = metadata.version.clone();

        // Add to history
        let entry = UpdateHistoryEntry {
            update_id: hex::encode(metadata.binary_hash),
            applied_at: Utc::now(),
            metadata,
            status: UpdateStatus::Success,
            error: None,
        };
        self.history.push(entry);

        // Save history
        self.save_history()?;

        Ok(())
    }

    /// Fetches updates from registry
    pub fn fetch_updates(&self, channel: &str) -> Result<Vec<UpdateMetadata>, String> {
        let channel_string = channel.to_string();
        let client = self.registry_client.as_ref()
            .ok_or_else(|| "Registry client not configured".to_string())?;

        client.fetch_updates(&channel_string)
    }

    /// Runs update in sandbox
    fn sandbox_test_update(&self, binary: &[u8], metadata: &UpdateMetadata) -> Result<(), String> {
        // TODO: Implement sandbox testing
        Ok(())
    }

    /// Applies validator update
    fn apply_validator_update(&self, binary: &[u8], metadata: &UpdateMetadata) -> Result<(), String> {
        // TODO: Implement validator update
        Ok(())
    }

    /// Applies runtime update
    fn apply_runtime_update(&self, binary: &[u8], metadata: &UpdateMetadata) -> Result<(), String> {
        // TODO: Implement runtime update
        Ok(())
    }

    /// Applies consensus update
    fn apply_consensus_update(&self, binary: &[u8], metadata: &UpdateMetadata) -> Result<(), String> {
        // TODO: Implement consensus update
        Ok(())
    }

    /// Applies network update
    fn apply_network_update(&self, binary: &[u8], metadata: &UpdateMetadata) -> Result<(), String> {
        // TODO: Implement network update
        Ok(())
    }

    /// Applies custom update
    fn apply_custom_update(&self, name: &str, binary: &[u8], metadata: &UpdateMetadata) -> Result<(), String> {
        // TODO: Implement custom update
        Ok(())
    }

    /// Saves update history
    fn save_history(&self) -> Result<(), String> {
        let content = serde_json::to_string_pretty(&self.history)
            .map_err(|e| format!("Failed to serialize history: {}", e))?;

        fs::write(&self.history_path, content)
            .map_err(|e| format!("Failed to save history: {}", e))?;

        Ok(())
    }

    /// Creates a backup before applying an update
    fn create_backup(&self, binary: &[u8], metadata: &UpdateMetadata) -> Result<UpdateBackup, String> {
        let backup_dir = self.history_path.parent().unwrap().join("backups");
        fs::create_dir_all(&backup_dir)
            .map_err(|e| format!("Failed to create backup directory: {}", e))?;

        let backup_path = backup_dir.join(format!(
            "backup_{}.bin",
            Utc::now().timestamp()
        ));

        fs::write(&backup_path, binary)
            .map_err(|e| format!("Failed to write backup: {}", e))?;

        Ok(UpdateBackup {
            binary: binary.to_vec(),
            metadata: metadata.clone(),
            timestamp: Utc::now(),
            path: backup_path,
        })
    }

    /// Rolls back a failed update
    pub fn rollback_update(&mut self, backup: UpdateBackup) -> Result<(), String> {
        // Verify backup
        let mut hasher = Sha3_256::new();
        hasher.update(&backup.binary);
        let backup_hash = hasher.finalize();

        if backup_hash.as_slice() != backup.metadata.binary_hash {
            return Err("Backup hash mismatch".to_string());
        }

        // Apply backup based on target
        match backup.metadata.target {
            UpdateTarget::Validator => self.apply_validator_update(&backup.binary, &backup.metadata)?,
            UpdateTarget::ContractRuntime => self.apply_runtime_update(&backup.binary, &backup.metadata)?,
            UpdateTarget::ConsensusEngine => self.apply_consensus_update(&backup.binary, &backup.metadata)?,
            UpdateTarget::NetworkStack => self.apply_network_update(&backup.binary, &backup.metadata)?,
            UpdateTarget::Custom(ref name) => self.apply_custom_update(name, &backup.binary, &backup.metadata)?,
        }

        // Update version
        self.current_version = backup.metadata.version;

        // Add rollback entry to history
        let entry = UpdateHistoryEntry {
            update_id: hex::encode(backup.metadata.binary_hash),
            applied_at: Utc::now(),
            metadata: backup.metadata,
            status: UpdateStatus::Reverted,
            error: None,
        };
        self.history.push(entry);

        // Save history
        self.save_history()?;

        Ok(())
    }

    /// Rotates signing keys
    pub fn rotate_signing_keys(&mut self, policy: &mut SignatureRotationPolicy) -> Result<(), String> {
        if Utc::now() - policy.last_rotation < policy.rotation_interval {
            return Ok(());
        }

        // Remove oldest key if we have more than minimum required
        if policy.active_keys.len() > policy.min_signatures {
            policy.active_keys.remove(0);
        }

        // Generate new key
        let new_key = ValidatorKeyPair::generate();
        policy.active_keys.push(new_key);
        policy.last_rotation = Utc::now();

        Ok(())
    }

    /// Verifies update signatures
    fn verify_signatures(&self, metadata: &UpdateMetadata, policy: &SignatureRotationPolicy) -> Result<bool, String> {
        if metadata.signatures.len() < metadata.required_signatures {
            return Ok(false);
        }

        let mut valid_signatures = 0;
        let message = self.create_signature_message(metadata)?;

        for signature in &metadata.signatures {
            for key in &policy.active_keys {
                if key.public_key == signature.signer_pubkey {
                    if KapraCrypto::verify_dilithium(&key.public_key, &message, &signature.signature) {
                        valid_signatures += 1;
                        break;
                    }
                }
            }
        }

        Ok(valid_signatures >= metadata.required_signatures)
    }

    /// Creates signature message
    fn create_signature_message(&self, metadata: &UpdateMetadata) -> Result<Vec<u8>, String> {
        let mut message = Vec::new();
        message.extend_from_slice(&metadata.binary_hash);
        message.extend_from_slice(&serde_json::to_vec(&metadata.version).unwrap());
        message.extend_from_slice(&serde_json::to_vec(&metadata.target).unwrap());
        Ok(message)
    }

    /// Generates HTML update report
    pub fn generate_html_report(&self, config: &ReportConfig) -> Result<String, String> {
        let mut tera = Tera::default();
        tera.add_raw_template("report", include_str!("../templates/update_report.html"))
            .map_err(|e| format!("Failed to load report template: {}", e))?;

        let mut context = Context::new();
        context.insert("title", &config.title);
        context.insert("description", &config.description);
        context.insert("updates", &self.history);
        
        if config.include_charts {
            let chart_data = self.generate_chart_data()?;
            context.insert("chart_data", &chart_data);
        }

        if config.include_logs {
            let logs = self.collect_update_logs()?;
            context.insert("logs", &logs);
        }

        if let Some(ref css) = config.custom_css {
            context.insert("custom_css", css);
        }

        tera.render("report", &context)
            .map_err(|e| format!("Failed to render report: {}", e))
    }

    /// Generates chart data for report
    fn generate_chart_data(&self) -> Result<serde_json::Value, String> {
        let mut success_count = 0;
        let mut failure_count = 0;
        let mut rollback_count = 0;

        for entry in &self.history {
            match entry.status {
                UpdateStatus::Success => success_count += 1,
                UpdateStatus::Failed => failure_count += 1,
                UpdateStatus::Reverted => rollback_count += 1,
            }
        }

        Ok(serde_json::json!({
            "success": success_count,
            "failure": failure_count,
            "rollback": rollback_count,
            "timeline": self.history.iter().map(|e| {
                serde_json::json!({
                    "timestamp": e.applied_at,
                    "version": e.metadata.version,
                    "status": e.status
                })
            }).collect::<Vec<_>>()
        }))
    }

    /// Collects update logs
    fn collect_update_logs(&self) -> Result<Vec<String>, String> {
        let mut logs = Vec::new();
        for entry in &self.history {
            logs.push(format!(
                "[{}] {} v{} - {}",
                entry.applied_at,
                entry.update_id,
                entry.metadata.version,
                match entry.status {
                    UpdateStatus::Success => "SUCCESS",
                    UpdateStatus::Failed => format!(
                        "FAILED: {}",
                        entry.error.as_ref().unwrap_or(&"Unknown error".to_string())
                    ),
                    UpdateStatus::Reverted => "REVERTED",
                }
            ));
        }
        Ok(logs)
    }

    /// Checks update compatibility
    fn check_compatibility(&self, metadata: &UpdateMetadata) -> Result<bool, String> {
        let compat = &metadata.compatibility;

        // Check version range
        if self.current_version < compat.min_version {
            return Ok(false);
        }
        if let Some(ref max_version) = compat.max_version {
            if self.current_version > *max_version {
                return Ok(false);
            }
        }

        // Check specific requirements
        for req in &compat.version_requirements {
            if !req.matches(&self.current_version) {
                return Ok(false);
            }
        }

        // Check exclusions
        if compat.excluded_versions.contains(&self.current_version) {
            return Ok(false);
        }

        Ok(true)
    }
}

impl UpdateRegistryClient {
    /// Creates a new registry client
    pub fn new(url: String, api_key: Option<String>) -> Self {
        UpdateRegistryClient {
            url,
            api_key,
            client: reqwest::Client::new(),
        }
    }

    /// Fetches updates from registry
    pub async fn fetch_updates(&self, channel: &str) -> Result<Vec<UpdateMetadata>, String> {
        let url = format!("{}/updates/{}", self.url, channel);
        let mut request = self.client.get(&url);

        if let Some(ref api_key) = self.api_key {
            request = request.header("X-API-Key", api_key);
        }

        let response = request
            .send()
            .await
            .map_err(|e| format!("Failed to fetch updates: {}", e))?;

        let updates: Vec<UpdateMetadata> = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse updates: {}", e))?;

        Ok(updates)
    }

    /// Pushes an update to registry
    pub async fn push_update(&self, update_path: &Path) -> Result<(), String> {
        let url = format!("{}/updates", self.url);
        let mut request = self.client.post(&url);

        if let Some(ref api_key) = self.api_key {
            request = request.header("X-API-Key", api_key);
        }

        let file = File::open(update_path)
            .map_err(|e| format!("Failed to open update file: {}", e))?;

        let response = request
            .body(file)
            .send()
            .await
            .map_err(|e| format!("Failed to push update: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("Failed to push update: {}", response.status()));
        }

        Ok(())
    }
}

/// CLI integration
pub fn register_cli_commands(app: App) -> App {
    app.subcommand(
        SubCommand::with_name("updater")
            .about("Update management commands")
            .subcommand(
                SubCommand::with_name("apply")
                    .about("Apply an update")
                    .arg(
                        Arg::with_name("update")
                            .help("Path to update bundle")
                            .required(true),
                    )
                    .arg(
                        Arg::with_name("dry-run")
                            .long("dry-run")
                            .help("Verify update without applying"),
                    ),
            )
            .subcommand(
                SubCommand::with_name("fetch")
                    .about("Fetch updates from registry")
                    .arg(
                        Arg::with_name("channel")
                            .long("channel")
                            .value_name("CHANNEL")
                            .help("Update channel (stable, testnet)")
                            .required(true),
                    ),
            )
            .subcommand(
                SubCommand::with_name("sign")
                    .about("Sign an update bundle")
                    .arg(
                        Arg::with_name("binary")
                            .help("Path to binary")
                            .required(true),
                    )
                    .arg(
                        Arg::with_name("key")
                            .long("key")
                            .value_name("KEY")
                            .help("Path to signing key")
                            .required(true),
                    ),
            ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_sign_and_verify_update() {
        let temp_dir = tempdir().unwrap();
        let binary_path = temp_dir.path().join("test.bin");
        fs::write(&binary_path, b"test binary").unwrap();

        let key_pair = ValidatorKeyPair::generate();
        let manager = UpdateManager::new(
            temp_dir.path().join("history.json"),
            Version::new(1, 0, 0),
        ).unwrap();

        let metadata = UpdateMetadata {
            version: Version::new(1, 1, 0),
            description: "Test update".to_string(),
            binary_hash: [0; 32],
            target: UpdateTarget::Validator,
            min_validator_version: Version::new(1, 0, 0),
            created_at: Utc::now(),
            expires_at: None,
            signer_pubkey: Vec::new(),
            signature: Vec::new(),
            compatibility: CompatibilityMap {
                min_version: Version::new(1, 0, 0),
                max_version: None,
                version_requirements: vec![],
                excluded_versions: vec![],
            },
            required_signatures: 1,
            signatures: vec![],
        };

        let update_path = manager.sign_update(&binary_path, metadata, &key_pair).unwrap();
        assert!(update_path.exists());

        let result = manager.verify_update(&update_path, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hash_mismatch() {
        let temp_dir = tempdir().unwrap();
        let binary_path = temp_dir.path().join("test.bin");
        fs::write(&binary_path, b"test binary").unwrap();

        let key_pair = ValidatorKeyPair::generate();
        let manager = UpdateManager::new(
            temp_dir.path().join("history.json"),
            Version::new(1, 0, 0),
        ).unwrap();

        let mut metadata = UpdateMetadata {
            version: Version::new(1, 1, 0),
            description: "Test update".to_string(),
            binary_hash: [1; 32], // Wrong hash
            target: UpdateTarget::Validator,
            min_validator_version: Version::new(1, 0, 0),
            created_at: Utc::now(),
            expires_at: None,
            signer_pubkey: Vec::new(),
            signature: Vec::new(),
            compatibility: CompatibilityMap {
                min_version: Version::new(1, 0, 0),
                max_version: None,
                version_requirements: vec![],
                excluded_versions: vec![],
            },
            required_signatures: 1,
            signatures: vec![],
        };

        let update_path = manager.sign_update(&binary_path, metadata, &key_pair).unwrap();
        let result = manager.verify_update(&update_path, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("hash mismatch"));
    }

    #[test]
    fn test_expired_update() {
        let temp_dir = tempdir().unwrap();
        let binary_path = temp_dir.path().join("test.bin");
        fs::write(&binary_path, b"test binary").unwrap();

        let key_pair = ValidatorKeyPair::generate();
        let manager = UpdateManager::new(
            temp_dir.path().join("history.json"),
            Version::new(1, 0, 0),
        ).unwrap();

        let metadata = UpdateMetadata {
            version: Version::new(1, 1, 0),
            description: "Test update".to_string(),
            binary_hash: [0; 32],
            target: UpdateTarget::Validator,
            min_validator_version: Version::new(1, 0, 0),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() - chrono::Duration::days(1)),
            signer_pubkey: Vec::new(),
            signature: Vec::new(),
            compatibility: CompatibilityMap {
                min_version: Version::new(1, 0, 0),
                max_version: None,
                version_requirements: vec![],
                excluded_versions: vec![],
            },
            required_signatures: 1,
            signatures: vec![],
        };

        let update_path = manager.sign_update(&binary_path, metadata, &key_pair).unwrap();
        let result = manager.verify_update(&update_path, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
    }

    #[test]
    fn test_update_rollback() {
        let temp_dir = tempdir().unwrap();
        let binary_path = temp_dir.path().join("test.bin");
        fs::write(&binary_path, b"original binary").unwrap();

        let manager = UpdateManager::new(
            temp_dir.path().join("history.json"),
            Version::new(1, 0, 0),
        ).unwrap();

        let metadata = UpdateMetadata {
            version: Version::new(1, 1, 0),
            description: "Test update".to_string(),
            binary_hash: [0; 32],
            target: UpdateTarget::Validator,
            compatibility: CompatibilityMap {
                min_version: Version::new(1, 0, 0),
                max_version: None,
                version_requirements: vec![],
                excluded_versions: vec![],
            },
            required_signatures: 1,
            signatures: vec![],
        };

        let backup = manager.create_backup(b"original binary", &metadata).unwrap();
        assert!(manager.rollback_update(backup).is_ok());
    }

    #[test]
    fn test_signature_rotation() {
        let mut policy = SignatureRotationPolicy {
            active_keys: vec![ValidatorKeyPair::generate()],
            min_signatures: 1,
            rotation_interval: chrono::Duration::hours(24),
            last_rotation: Utc::now() - chrono::Duration::days(1),
        };

        let manager = UpdateManager::new(
            PathBuf::from("history.json"),
            Version::new(1, 0, 0),
        ).unwrap();

        assert!(manager.rotate_signing_keys(&mut policy).is_ok());
        assert_eq!(policy.active_keys.len(), 2);
    }

    #[test]
    fn test_compatibility_check() {
        let manager = UpdateManager::new(
            PathBuf::from("history.json"),
            Version::new(1, 5, 0),
        ).unwrap();

        let metadata = UpdateMetadata {
            version: Version::new(2, 0, 0),
            description: "Test update".to_string(),
            binary_hash: [0; 32],
            target: UpdateTarget::Validator,
            compatibility: CompatibilityMap {
                min_version: Version::new(1, 0, 0),
                max_version: Some(Version::new(2, 0, 0)),
                version_requirements: vec![
                    VersionReq::parse(">= 1.5.0").unwrap(),
                ],
                excluded_versions: vec![],
            },
            required_signatures: 1,
            signatures: vec![],
        };

        assert!(manager.check_compatibility(&metadata).unwrap());
    }

    #[test]
    fn test_html_report() {
        let manager = UpdateManager::new(
            PathBuf::from("history.json"),
            Version::new(1, 0, 0),
        ).unwrap();

        let config = ReportConfig {
            title: "Update Report".to_string(),
            description: "Test report".to_string(),
            include_charts: true,
            include_logs: true,
            custom_css: None,
        };

        let report = manager.generate_html_report(&config).unwrap();
        assert!(report.contains("Update Report"));
    }
} 