// ksl_registry.rs
// Implements a remote package registry client for KSL to fetch and publish packages.
// Supports async operations, new package formats, and integration with package publishing.

use crate::ksl_package::{PackageMetadata, PackageSystem};
use crate::ksl_package_publish::{PackagePublisher, PublishConfig};
use crate::ksl_async::{AsyncRuntime, AsyncResult};
use crate::ksl_errors::{KslError, SourcePosition};
use reqwest::Client;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tar::Archive;
use toml::Value;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Registry client configuration
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Registry URL (e.g., https://registry.ksl.dev)
    pub url: String,
    /// Cache directory for downloaded packages
    pub cache_dir: PathBuf,
    /// Whether to use async operations
    pub use_async: bool,
}

/// Registry client state
#[derive(Debug, Clone)]
pub struct RegistryState {
    /// Last fetched package
    pub last_fetched: Option<PackageMetadata>,
    /// Package cache
    pub package_cache: HashMap<String, PackageMetadata>,
}

/// Registry client for managing KSL packages
pub struct RegistryClient {
    config: RegistryConfig,
    client: Client,
    package_system: PackageSystem,
    async_runtime: Arc<AsyncRuntime>,
    state: Arc<RwLock<RegistryState>>,
}

impl RegistryClient {
    /// Creates a new registry client
    pub fn new() -> Self {
        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let cache_dir = home_dir.join(".ksl/packages");
        RegistryClient {
            config: RegistryConfig {
                url: "https://registry.ksl.dev".to_string(),
                cache_dir,
                use_async: true,
            },
            client: Client::new(),
            package_system: PackageSystem::new(),
            async_runtime: Arc::new(AsyncRuntime::new()),
            state: Arc::new(RwLock::new(RegistryState {
                last_fetched: None,
                package_cache: HashMap::new(),
            })),
        }
    }

    /// Fetch and install a package from the remote registry asynchronously
    pub async fn fetch_package_async(&mut self, name: &str, version: &str) -> AsyncResult<()> {
        let package_key = format!("{}@{}", name, version);
        let state = self.state.read().await;
        if state.package_cache.contains_key(&package_key) {
            return Ok(()); // Package already in cache
        }
        drop(state);

        // Download package tarball
        let url = format!("{}/{}/{}.tar.gz", self.config.url, name, version);
        let response = self.client.get(&url)
            .send()
            .await
            .map_err(|e| KslError::type_error(
                format!("Failed to fetch package {}@{}: {}", name, version, e),
                SourcePosition::new(1, 1),
            ))?;
        if !response.status().is_success() {
            return Err(KslError::type_error(
                format!("Package {}@{} not found in registry", name, version),
                SourcePosition::new(1, 1),
            ));
        }

        // Extract tarball
        let package_dir = self.config.cache_dir.join(name).join(version);
        fs::create_dir_all(&package_dir)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        let tar_gz = response.bytes()
            .await
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        let tar = flate2::read::GzDecoder::new(&tar_gz[..]);
        let mut archive = Archive::new(tar);
        archive.unpack(&package_dir)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        // Read metadata
        let metadata_file = package_dir.join("ksl_package.toml");
        let metadata_content = fs::read_to_string(&metadata_file)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        let metadata: PackageMetadata = toml::from_str(&metadata_content)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        // Verify metadata
        if metadata.name != name || metadata.version != version {
            return Err(KslError::type_error(
                format!("Mismatched package metadata for {}@{}", name, version),
                SourcePosition::new(1, 1),
            ));
        }

        // Update state
        let mut state = self.state.write().await;
        state.last_fetched = Some(metadata.clone());
        state.package_cache.insert(package_key.clone(), metadata.clone());
        drop(state);

        // Install dependencies
        for (dep_name, dep_version) in &metadata.dependencies {
            self.fetch_package_async(dep_name, dep_version).await?;
        }

        // Install package locally
        self.package_system.install(name, version)?;

        Ok(())
    }

    /// Publish a package to the remote registry asynchronously
    pub async fn publish_package_async(&mut self, package_dir: &Path) -> AsyncResult<()> {
        let metadata_file = package_dir.join("ksl_package.toml");
        let metadata_content = fs::read_to_string(&metadata_file)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        let metadata: PackageMetadata = toml::from_str(&metadata_content)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        // Create tarball
        let tarball_path = package_dir.join(format!("{}-{}.tar.gz", metadata.name, metadata.version));
        let tar_gz = File::create(&tarball_path)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        let enc = flate2::write::GzEncoder::new(tar_gz, flate2::Compression::default());
        let mut tar = tar::Builder::new(enc);
        let src_dir = package_dir.join("src");
        for entry in fs::read_dir(&src_dir)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?
        {
            let entry = entry?;
            let path = entry.path();
            tar.append_path_with_name(&path, path.strip_prefix(package_dir)
                .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?)
                .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        }
        tar.append_path_with_name(&metadata_file, "ksl_package.toml")
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        tar.finish()
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        // Upload tarball
        let url = format!("{}/{}/{}.tar.gz", self.config.url, metadata.name, metadata.version);
        let file = File::open(&tarball_path)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        let response = self.client.post(&url)
            .body(file)
            .send()
            .await
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        if !response.status().is_success() {
            return Err(KslError::type_error(
                format!("Failed to publish package {}@{}", metadata.name, metadata.version),
                SourcePosition::new(1, 1),
            ));
        }

        // Clean up tarball
        fs::remove_file(&tarball_path)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        // Update state
        let mut state = self.state.write().await;
        state.last_fetched = Some(metadata);
        Ok(())
    }

    /// Get the last fetched package metadata
    pub async fn last_fetched(&self) -> Option<PackageMetadata> {
        self.state.read().await.last_fetched.clone()
    }

    /// Get a package from the cache
    pub async fn get_cached_package(&self, name: &str, version: &str) -> Option<PackageMetadata> {
        let package_key = format!("{}@{}", name, version);
        self.state.read().await.package_cache.get(&package_key).cloned()
    }
}

/// Public API to manage packages via the registry
pub async fn fetch_package_async(name: &str, version: &str) -> AsyncResult<()> {
    let mut client = RegistryClient::new();
    client.fetch_package_async(name, version).await
}

pub async fn publish_package_async(package_dir: &Path) -> AsyncResult<()> {
    let mut client = RegistryClient::new();
    client.publish_package_async(package_dir).await
}

// Assume ksl_package.rs, ksl_package_publish.rs, ksl_async.rs, and ksl_errors.rs are in the same crate
mod ksl_package {
    pub use super::{PackageMetadata, PackageSystem};
}

mod ksl_package_publish {
    pub use super::{PackagePublisher, PublishConfig};
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
    use tempfile::TempDir;
    use std::io::Write;

    #[tokio::test]
    async fn test_fetch_package_async() {
        let temp_dir = TempDir::new().unwrap();
        let cache_dir = temp_dir.path().join(".ksl/packages");
        let package_dir = cache_dir.join("mylib").join("1.0.0");
        fs::create_dir_all(&package_dir.join("src")).unwrap();
        let metadata_file = package_dir.join("ksl_package.toml");
        let mut file = File::create(&metadata_file).unwrap();
        writeln!(
            file,
            "[package]\nname = \"mylib\"\nversion = \"1.0.0\"\n[dependencies]\n"
        ).unwrap();
        let module_file = package_dir.join("src").join("utils.ksl");
        let mut module = File::create(&module_file).unwrap();
        writeln!(module, "fn add(x: u32, y: u32): u32 { x + y; }").unwrap();

        let mut client = RegistryClient {
            config: RegistryConfig {
                url: "file://".to_string(),
                cache_dir,
                use_async: true,
            },
            ..RegistryClient::new()
        };
        let result = client.fetch_package_async("mylib", "1.0.0").await;
        assert!(result.is_ok());
        assert!(client.package_system.packages.contains_key("mylib@1.0.0"));
    }

    #[tokio::test]
    async fn test_publish_package_async() {
        let temp_dir = TempDir::new().unwrap();
        let package_dir = temp_dir.path().join("mylib");
        fs::create_dir_all(package_dir.join("src")).unwrap();
        let metadata_file = package_dir.join("ksl_package.toml");
        let mut file = File::create(&metadata_file).unwrap();
        writeln!(
            file,
            "[package]\nname = \"mylib\"\nversion = \"1.0.0\"\n[dependencies]\n"
        ).unwrap();
        let module_file = package_dir.join("src").join("utils.ksl");
        let mut module = File::create(&module_file).unwrap();
        writeln!(module, "fn add(x: u32, y: u32): u32 { x + y; }").unwrap();

        let mut client = RegistryClient {
            config: RegistryConfig {
                url: "file://".to_string(),
                cache_dir: temp_dir.path().join("registry"),
                use_async: true,
            },
            ..RegistryClient::new()
        };
        let result = client.publish_package_async(&package_dir).await;
        assert!(result.is_ok());
        let tarball = package_dir.join("mylib-1.0.0.tar.gz");
        assert!(!tarball.exists()); // Cleaned up after publish
    }

    #[tokio::test]
    async fn test_package_cache() {
        let mut client = RegistryClient::new();
        let result = client.fetch_package_async("test-lib", "1.0.0").await;
        assert!(result.is_ok());
        let cached = client.get_cached_package("test-lib", "1.0.0").await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().name, "test-lib");
    }
}