// ksl_package_publish.rs
// Enables publishing KSL packages to a registry for community sharing, packaging
// projects into tarballs and uploading them via HTTP.

use crate::ksl_package::{PackageSystem, PackageMetadata};
use crate::ksl_registry::RegistryClient;
use crate::ksl_async::{AsyncRuntime, AsyncResult};
use crate::ksl_errors::{KslError, SourcePosition};
use std::sync::Arc;
use tokio::sync::RwLock;
use reqwest::Client;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use crate::ksl_validator_keys::{ValidatorKeys, Signature};
use crate::ksl_contract::{ContractAbi, ContractFunction};
use crate::ksl_analyzer::{Analyzer, GasStats};
use crate::ksl_package::{PackageLoader, PackageConfig};
use sha2::{Sha256, Digest};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::path::Path;
use flate2::Compress;
use reqwest::StatusCode;
use serde_json::json;
use tar::{Builder, Header};

/// Package publish configuration
#[derive(Debug, Clone)]
pub struct PublishConfig {
    /// Directory containing the package
    pub package_dir: PathBuf,
    /// Remote registry URL (e.g., registry.ksl.dev)
    pub registry_url: String,
    /// Temporary tarball file
    pub output_tarball: PathBuf,
    /// Whether to publish asynchronously
    pub async_publish: bool,
}

/// Package publisher state
#[derive(Debug, Clone)]
pub struct PublishState {
    /// Last published package metadata
    pub last_published: Option<PackageMetadata>,
    /// Publish status cache
    pub status_cache: HashMap<String, bool>,
}

/// Package archive metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct PackageArchive {
    /// Package configuration
    pub config: PackageConfig,
    /// Package files
    pub files: HashMap<PathBuf, Vec<u8>>,
    /// Package signature
    pub signature: Option<String>,
    /// Package hash
    pub hash: String,
    /// Package timestamp
    pub timestamp: DateTime<Utc>,
}

/// Package publisher
pub struct PackagePublisher {
    /// Package loader
    loader: Arc<PackageLoader>,
    /// Validator keys for signing
    validator_keys: Arc<ValidatorKeys>,
    /// Analyzer for gas estimation
    analyzer: Arc<Analyzer>,
    /// Registry client
    registry_client: Arc<reqwest::Client>,
    /// Registry token
    registry_token: Option<String>,
}

impl PackagePublisher {
    /// Create new package publisher
    pub fn new(loader: Arc<PackageLoader>) -> Self {
        PackagePublisher {
            loader,
            validator_keys: Arc::new(ValidatorKeys::new()),
            analyzer: Arc::new(Analyzer::new()),
            registry_client: Arc::new(reqwest::Client::new()),
            registry_token: None,
        }
    }

    /// Set registry token
    pub fn set_registry_token(&mut self, token: String) {
        self.registry_token = Some(token);
    }

    /// Create publishable archive
    pub async fn create_archive(&self, path: &Path) -> AsyncResult<PackageArchive> {
        // Load package configuration
        self.loader.load_config(path).await?;

        // Collect package files
        let mut files = HashMap::new();
        self.collect_files(path, &mut files)?;

        // Calculate package hash
        let mut hasher = Sha256::new();
        for (name, content) in &files {
            hasher.update(name.to_string_lossy().as_bytes());
            hasher.update(content);
        }
        let hash = format!("{:x}", hasher.finalize());

        // Sign package
        let signature = if let Some(keys) = self.validator_keys.get_signing_keys() {
            Some(keys.sign(&hash.as_bytes()))
        } else {
            None
        };

        // Create archive
        let config = self.loader.config.read().await.clone();
        Ok(PackageArchive {
            config,
            files,
            signature,
            hash,
            timestamp: Utc::now(),
        })
    }

    /// Collect package files
    fn collect_files(&self, path: &Path, files: &mut HashMap<PathBuf, Vec<u8>>) -> Result<(), KslError> {
        for entry in fs::read_dir(path)
            .map_err(|e| KslError::io_error(
                format!("Failed to read directory {}: {}", path.display(), e),
                SourcePosition::new(1, 1),
                "E101".to_string()
            ))? {
            let entry = entry
                .map_err(|e| KslError::io_error(
                    format!("Failed to read directory entry: {}", e),
                    SourcePosition::new(1, 1),
                    "E102".to_string()
                ))?;
            let path = entry.path();

            if path.is_dir() {
                self.collect_files(&path, files)?;
            } else {
                let content = fs::read(&path)
                    .map_err(|e| KslError::io_error(
                        format!("Failed to read file {}: {}", path.display(), e),
                        SourcePosition::new(1, 1),
                        "E103".to_string()
                    ))?;
                files.insert(path.strip_prefix(path).unwrap().to_path_buf(), content);
            }
        }
        Ok(())
    }

    /// Create compressed archive
    pub async fn create_compressed_archive(&self, archive: &PackageArchive) -> AsyncResult<Vec<u8>> {
        let mut tar_data = Vec::new();
        let mut builder = Builder::new(&mut tar_data);

        // Add package metadata
        let metadata = serde_json::to_string(&archive)
            .map_err(|e| KslError::serialization_error(
                format!("Failed to serialize package metadata: {}", e),
                SourcePosition::new(1, 1),
                "E201".to_string()
            ))?;
        let mut header = Header::new_gnu();
        header.set_path("metadata.json")
            .map_err(|e| KslError::io_error(
                format!("Failed to set metadata path: {}", e),
                SourcePosition::new(1, 1),
                "E104".to_string()
            ))?;
        header.set_size(metadata.len() as u64);
        header.set_mode(0o644);
        builder.append(&header, metadata.as_bytes())
            .map_err(|e| KslError::io_error(
                format!("Failed to append metadata: {}", e),
                SourcePosition::new(1, 1),
                "E105".to_string()
            ))?;

        // Add package files
        for (path, content) in &archive.files {
            let mut header = Header::new_gnu();
            header.set_path(path)
                .map_err(|e| KslError::io_error(
                    format!("Failed to set file path: {}", e),
                    SourcePosition::new(1, 1),
                    "E106".to_string()
                ))?;
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            builder.append(&header, content.as_slice())
                .map_err(|e| KslError::io_error(
                    format!("Failed to append file: {}", e),
                    SourcePosition::new(1, 1),
                    "E107".to_string()
                ))?;
        }

        builder.finish()
            .map_err(|e| KslError::io_error(
                format!("Failed to finish archive: {}", e),
                SourcePosition::new(1, 1),
                "E108".to_string()
            ))?;

        // Compress the tar archive with gzip
        let mut compressed = Vec::new();
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&tar_data)
            .map_err(|e| KslError::io_error(
                format!("Failed to compress archive: {}", e),
                SourcePosition::new(1, 1),
                "E109".to_string()
            ))?;
        compressed = encoder.finish()
            .map_err(|e| KslError::io_error(
                format!("Failed to finish compression: {}", e),
                SourcePosition::new(1, 1),
                "E110".to_string()
            ))?;

        Ok(compressed)
    }

    /// Publish package to registry
    pub async fn publish_package(&self, path: &Path) -> AsyncResult<()> {
        // Create archive
        let archive = self.create_archive(path).await?;
        let compressed = self.create_compressed_archive(&archive).await?;

        // Verify gas estimates for contracts
        self.verify_contract_gas(&archive).await?;

        // Lint package
        self.lint_package(&archive).await?;

        // Generate ABI docs
        self.generate_abi_docs(&archive).await?;

        // Upload to registry
        let token = self.registry_token.as_ref()
            .ok_or_else(|| KslError::validation_error(
                format!("No registry token provided"),
                SourcePosition::new(1, 1),
                "E201".to_string()
            ))?;

        let response = self.registry_client
            .post(format!("https://registry.ksl.dev/packages/{}/{}/publish", archive.config.name, archive.config.version))
            .header("Authorization", format!("Bearer {}", token))
            .body(compressed)
            .send()
            .await
            .map_err(|e| KslError::network(
                format!("Failed to publish package: {}", e),
                SourcePosition::new(1, 1),
                "E307".to_string()
            ))?;

        if response.status() != StatusCode::OK {
            return Err(KslError::network(
                format!("Failed to publish package: HTTP {}", response.status()),
                SourcePosition::new(1, 1),
                "E308".to_string()
            ));
        }

        Ok(())
    }

    /// Verify gas estimates for contracts
    async fn verify_contract_gas(&self, archive: &PackageArchive) -> AsyncResult<()> {
        for (path, content) in &archive.files {
            if path.extension().map_or(false, |ext| ext == "ksl") {
                let gas_stats = self.analyzer.analyze_gas_usage_from_source(content).await?;
                // Check for unsafe macro combinations
                if content.contains("#[validator]") && content.contains("#[async]") {
                }
                if content.contains("unsafe") && !content.contains("#[allow(unsafe)]") {
                    return Err(KslError::validation_error(
                        format!("Unsafe code in {} without #[allow(unsafe)]", path.display()),
                        SourcePosition::new(1, 1),
                        "E202".to_string()
                    ));
                }
                if gas_stats.gas_utilization > 0.8 {
                    return Err(KslError::validation_error(
                        format!("Contract exceeds gas limit: {} in {}", gas_stats.gas_utilization, path.display()),
                        SourcePosition::new(1, 1),
                        "E208".to_string()
                    ));
                }
            }
        }
        Ok(())
    }

    /// Lint package for unsafe or invalid macro combinations
    async fn lint_package(&self, archive: &PackageArchive) -> AsyncResult<()> {
        for (path, content) in &archive.files {
            if path.extension().map_or(false, |ext| ext == "ksl") {
                // Check for unsafe macro combinations
                let content_str = String::from_utf8_lossy(content);
                if content_str.contains("#[validator]") && content_str.contains("#[async]") {
                    return Err(KslError::validation_error(
                        format!("Invalid macro combination in {}", path.display()),
                        SourcePosition::new(1, 1),
                        "E203".to_string()
                    ));
                }

                // Check for unsafe FFI
                if content_str.contains("unsafe") && !content_str.contains("#[allow(unsafe)]") {
                    return Err(KslError::validation_error(
                        format!("Unsafe code in {} without #[allow(unsafe)]", path.display()),
                        SourcePosition::new(1, 1),
                        "E204".to_string()
                    ));
                }
            }
        }
        Ok(())
    }

    /// Generate ABI documentation for contracts
    async fn generate_abi_docs(&self, archive: &PackageArchive) -> AsyncResult<()> {
        for (path, content) in &archive.files {
            if path.extension().map_or(false, |ext| ext == "ksl") {
                if let Some(abi) = self.analyzer.extract_contract_abi(content).await? {
                    let doc_path = path.with_extension("abi.md");
                    let doc = self.generate_abi_markdown(&abi);
                    fs::write(&doc_path, doc)
                        .map_err(|e| KslError::io_error(
                            format!("Failed to write ABI docs: {}", e),
                            SourcePosition::new(1, 1),
                            "E111".to_string()
                        ))?;
                }
            }
        }
        Ok(())
    }

    /// Generate Markdown documentation for contract ABI
    fn generate_abi_markdown(&self, abi: &ContractAbi) -> String {
        let mut doc = String::new();
        doc.push_str("# Contract ABI\n\n");
        doc.push_str("## Functions\n\n");
        for func in &abi.functions {
            doc.push_str(&format!("### {}\n\n", func.name));
            doc.push_str("```ksl\n");
            doc.push_str(&format!("fn {}({})", func.name, func.params.join(", ")));
            if let Some(ret) = &func.return_type {
                doc.push_str(&format!(" -> {}", ret));
            }
            doc.push_str(";\n```\n\n");
        }
        doc
    }

    /// Yank package version
    pub async fn yank_package(&self, name: &str, version: &str) -> AsyncResult<()> {
        let token = self.registry_token.as_ref()
            .ok_or_else(|| KslError::validation_error(
                format!("No registry token provided"),
                SourcePosition::new(1, 1),
                "E205".to_string()
            ))?;

        let response = self.registry_client
            .post(format!("https://registry.ksl.dev/packages/{}/{}/yank", name, version))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(|e| KslError::network(
                format!("Failed to yank package: {}", e),
                SourcePosition::new(1, 1),
                "E309".to_string()
            ))?;
        
        if response.status() != StatusCode::OK {
            return Err(KslError::network(
                format!("Failed to yank package: HTTP {}", response.status()),
                SourcePosition::new(1, 1),
                "E310".to_string()
            ));
        }

        Ok(())
    }

    /// Deprecate package version
    pub async fn deprecate_package(&self, name: &str, version: &str, reason: &str) -> AsyncResult<()> {
        let token = self.registry_token.as_ref()
            .ok_or_else(|| KslError::validation_error(
                format!("No registry token provided"),
                SourcePosition::new(1, 1),
                "E206".to_string()
            ))?;

        let response = self.registry_client
            .post(format!("https://registry.ksl.dev/packages/{}/{}/deprecate", name, version))
            .header("Authorization", format!("Bearer {}", token))
            .json(&json!({ "reason": reason }))
            .send()
            .await
            .map_err(|e| KslError::network(
                format!("Failed to deprecate package: {}", e),
                SourcePosition::new(1, 1),
                "E311".to_string()
            ))?;

        if response.status() != StatusCode::OK {
            return Err(KslError::network(
                format!("Failed to deprecate package: HTTP {}", response.status()),
                SourcePosition::new(1, 1),
                "E312".to_string()
            ));
        }

        Ok(())
    }

    /// Rollback package version
    pub async fn rollback_package(&self, name: &str, version: &str) -> AsyncResult<()> {
        let token = self.registry_token.as_ref()
            .ok_or_else(|| KslError::validation_error(
                format!("No registry token provided"),
                SourcePosition::new(1, 1),
                "E207".to_string()
            ))?;

        let response = self.registry_client
            .post(format!("https://registry.ksl.dev/packages/{}/{}/rollback", name, version))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(|e| KslError::network(
                format!("Failed to rollback package: {}", e),
                SourcePosition::new(1, 1),
                "E313".to_string()
            ))?;

        if response.status() != StatusCode::OK {
            return Err(KslError::network(
                format!("Failed to rollback package: HTTP {}", response.status()),
                SourcePosition::new(1, 1),
                "E314".to_string()
            ));
        }

        Ok(())
    }
}

/// Public API to publish a KSL package
pub fn publish(package_dir: &PathBuf, registry_url: &str, async_publish: bool) -> Result<(), KslError> {
    let pos = SourcePosition::new(1, 1);
    let output_tarball = package_dir.join("package.tar.gz");
    let config = PublishConfig {
        package_dir: package_dir.clone(),
        registry_url: registry_url.to_string(),
        output_tarball,
        async_publish,
    };
    let mut publisher = PackagePublisher::new(Arc::new(PackageLoader::new()));
    publisher.publish_package(&config.package_dir.as_path())
}

/// Public API to publish a KSL package asynchronously
pub async fn publish_async(package_dir: &PathBuf, registry_url: &str) -> AsyncResult<()> {
    let pos = SourcePosition::new(1, 1);
    let output_tarball = package_dir.join("package.tar.gz");
    let config = PublishConfig {
        package_dir: package_dir.clone(),
        registry_url: registry_url.to_string(),
        output_tarball,
        async_publish: true,
    };
    let mut publisher = PackagePublisher::new(Arc::new(PackageLoader::new()));
    publisher.publish_package(&config.package_dir.as_path())
}

// Assume ksl_package.rs, ksl_registry.rs, ksl_async.rs, and ksl_errors.rs are in the same crate
mod ksl_package {
    pub use super::{PackageSystem, PackageMetadata};
}

mod ksl_registry {
    pub use super::RegistryClient;
}

mod ksl_async {
    pub use super::{AsyncRuntime, AsyncResult};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_publish_async() {
        let temp_dir = TempDir::new().unwrap();
        let package_dir = temp_dir.path().join("package");
        fs::create_dir_all(package_dir.join("src")).unwrap();
        let src_file = package_dir.join("src/main.ksl");
        let mut src = File::create(&src_file).unwrap();
        writeln!(src, "fn main() {{}}").unwrap();

        let metadata_file = package_dir.join("ksl_package.toml");
        let mut file = File::create(&metadata_file).unwrap();
        writeln!(file, "name = \"test\"\nversion = \"1.0.0\"").unwrap();

        let result = publish_async(&package_dir, "http://registry.ksl.dev").await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_publish_sync() {
        let temp_dir = TempDir::new().unwrap();
        let package_dir = temp_dir.path().join("package");
        fs::create_dir_all(package_dir.join("src")).unwrap();
        let src_file = package_dir.join("src/main.ksl");
        let mut src = File::create(&src_file).unwrap();
        writeln!(src, "fn main() {{}}").unwrap();

        let metadata_file = package_dir.join("ksl_package.toml");
        let mut file = File::create(&metadata_file).unwrap();
        writeln!(file, "name = \"test\"\nversion = \"1.0.0\"").unwrap();

        let result = publish(&package_dir, "http://registry.ksl.dev", false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_publish_invalid_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let package_dir = temp_dir.path().join("package");
        fs::create_dir_all(&package_dir).unwrap();
        let metadata_file = package_dir.join("ksl_package.toml");
        let mut file = File::create(&metadata_file).unwrap();
        writeln!(file, "name = \"\"\nversion = \"1.0.0\"").unwrap();

        let result = publish(&package_dir, "http://registry.ksl.dev", false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Package metadata must include name and version"));
    }
}
