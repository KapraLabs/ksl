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
use tar::Builder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use toml;
use serde::{Deserialize, Serialize};

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

/// Package publisher
pub struct PackagePublisher {
    config: PublishConfig,
    package_system: PackageSystem,
    registry_client: RegistryClient,
    async_runtime: Arc<AsyncRuntime>,
    state: Arc<RwLock<PublishState>>,
}

impl PackagePublisher {
    /// Creates a new package publisher instance
    pub fn new(config: PublishConfig) -> Self {
        PackagePublisher {
            config: config.clone(),
            package_system: PackageSystem::new(),
            registry_client: RegistryClient::new(),
            async_runtime: Arc::new(AsyncRuntime::new()),
            state: Arc::new(RwLock::new(PublishState {
                last_published: None,
                status_cache: HashMap::new(),
            })),
        }
    }

    /// Publishes a KSL package to the remote registry asynchronously
    pub async fn publish_async(&mut self) -> AsyncResult<()> {
        let pos = SourcePosition::new(1, 1);

        // Validate package metadata
        let metadata_file = self.config.package_dir.join("ksl_package.toml");
        let metadata_content = fs::read_to_string(&metadata_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to read metadata file {}: {}", metadata_file.display(), e),
                pos,
            ))?;
        let metadata: PackageMetadata = toml::from_str(&metadata_content)
            .map_err(|e| KslError::type_error(
                format!("Failed to parse metadata: {}", e),
                pos,
            ))?;

        if metadata.name.is_empty() || metadata.version.is_empty() {
            return Err(KslError::type_error(
                "Package metadata must include name and version".to_string(),
                pos,
            ));
        }

        // Resolve dependencies asynchronously
        self.package_system.resolve_dependencies_async(&self.config.package_dir).await
            .map_err(|e| KslError::type_error(format!("Dependency resolution failed: {}", e), pos))?;

        // Generate documentation
        let doc_dir = self.config.package_dir.join("docs");
        generate_docgen(&metadata.name, "markdown", doc_dir.clone())
            .map_err(|e| KslError::type_error(format!("Documentation generation failed: {}", e), pos))?;

        // Create tarball
        let tar_gz = File::create(&self.config.output_tarball)
            .map_err(|e| KslError::type_error(
                format!("Failed to create tarball {}: {}", self.config.output_tarball.display(), e),
                pos,
            ))?;
        let enc = GzEncoder::new(tar_gz, Compression::default());
        let mut tar = Builder::new(enc);

        // Add source files
        let src_dir = self.config.package_dir.join("src");
        if src_dir.exists() {
            for entry in fs::read_dir(&src_dir)
                .map_err(|e| KslError::type_error(
                    format!("Failed to read source directory {}: {}", src_dir.display(), e),
                    pos,
                ))?
            {
                let entry = entry?;
                if entry.path().extension().map(|ext| ext == "ksl").unwrap_or(false) {
                    tar.append_path_with_name(&entry.path(), format!("src/{}", entry.file_name().to_string_lossy()))
                        .map_err(|e| KslError::type_error(
                            format!("Failed to add source file {} to tarball: {}", entry.path().display(), e),
                            pos,
                        ))?;
                }
            }
        }

        // Add documentation
        if doc_dir.exists() {
            for entry in fs::read_dir(&doc_dir)
                .map_err(|e| KslError::type_error(
                    format!("Failed to read doc directory {}: {}", doc_dir.display(), e),
                    pos,
                ))?
            {
                let entry = entry?;
                if entry.path().extension().map(|ext| ext == "md").unwrap_or(false) {
                    tar.append_path_with_name(&entry.path(), format!("docs/{}", entry.file_name().to_string_lossy()))
                        .map_err(|e| KslError::type_error(
                            format!("Failed to add doc file {} to tarball: {}", entry.path().display(), e),
                            pos,
                        ))?;
                }
            }
        }

        // Add metadata
        tar.append_path_with_name(&metadata_file, "ksl_package.toml")
            .map_err(|e| KslError::type_error(
                format!("Failed to add metadata to tarball: {}", e),
                pos,
            ))?;

        tar.finish()
            .map_err(|e| KslError::type_error(
                format!("Failed to finalize tarball: {}", e),
                pos,
            ))?;

        // Publish to registry asynchronously
        let tarball_data = fs::read(&self.config.output_tarball)
            .map_err(|e| KslError::type_error(
                format!("Failed to read tarball {}: {}", self.config.output_tarball.display(), e),
                pos,
            ))?;
        let publish_url = format!("{}/publish/{}/{}", self.config.registry_url, metadata.name, metadata.version);
        
        if self.config.async_publish {
            // Schedule async publish task
            let task_id = format!("publish_{}_{}", metadata.name, metadata.version);
            let client = self.async_runtime.client.clone();
            let url = publish_url.clone();
            let data = tarball_data.clone();
            self.async_runtime.schedule_task(task_id.clone(), async move {
                client.post(&url)
                    .body(data)
                    .header("Content-Type", "application/gzip")
                    .send()
                    .await
                    .map_err(|e| KslError::type_error(
                        format!("Failed to publish to registry {}: {}", url, e),
                        pos,
                    ))?
                    .error_for_status()
                    .map_err(|e| KslError::type_error(
                        format!("Registry publish failed: {}", e),
                        pos,
                    ))?;
                Ok(())
            }).await;
            
            // Poll for completion
            self.async_runtime.poll().await?;
        } else {
            // Synchronous publish
            self.registry_client.publish_package(&self.config.package_dir)?;
        }

        // Update state
        let mut state = self.state.write().await;
        state.last_published = Some(metadata.clone());
        state.status_cache.insert(format!("{}@{}", metadata.name, metadata.version), true);

        // Clean up temporary tarball
        fs::remove_file(&self.config.output_tarball)
            .map_err(|e| KslError::type_error(
                format!("Failed to clean up tarball {}: {}", self.config.output_tarball.display(), e),
                pos,
            ))?;

        Ok(())
    }

    /// Synchronous wrapper for package publishing
    pub fn publish(&mut self) -> Result<(), KslError> {
        let runtime = self.async_runtime.clone();
        runtime.block_on(self.publish_async())
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
    let mut publisher = PackagePublisher::new(config);
    publisher.publish()
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
    let mut publisher = PackagePublisher::new(config);
    publisher.publish_async().await
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
