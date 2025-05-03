// ksl_registry.rs
// Implements a remote package registry client for KSL to fetch and publish packages.

use crate::ksl_package::{PackageMetadata, PackageSystem};
use crate::ksl_errors::{KslError, SourcePosition};
use reqwest::blocking::Client;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tar::Archive;
use toml::Value;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// Registry client configuration
#[derive(Debug)]
struct RegistryConfig {
    url: String, // e.g., https://registry.ksl.dev
    cache_dir: PathBuf, // e.g., ~/.ksl/packages
}

// Registry client state
pub struct RegistryClient {
    config: RegistryConfig,
    client: Client,
    package_system: PackageSystem,
}

impl RegistryClient {
    pub fn new() -> Self {
        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let cache_dir = home_dir.join(".ksl/packages");
        RegistryClient {
            config: RegistryConfig {
                url: "https://registry.ksl.dev".to_string(),
                cache_dir,
            },
            client: Client::new(),
            package_system: PackageSystem::new(),
        }
    }

    // Fetch and install a package from the remote registry
    pub fn fetch_package(&mut self, name: &str, version: &str) -> Result<(), KslError> {
        let package_key = format!("{}@{}", name, version);
        if self.package_system.packages.contains_key(&package_key) {
            return Ok(()); // Package already installed
        }

        // Download package tarball
        let url = format!("{}/{}/{}.tar.gz", self.config.url, name, version);
        let response = self.client.get(&url)
            .send()
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

        // Install dependencies
        for (dep_name, dep_version) in &metadata.dependencies {
            self.fetch_package(dep_name, dep_version)?;
        }

        // Install package locally
        self.package_system.install(name, version)?;

        Ok(())
    }

    // Publish a package to the remote registry
    pub fn publish_package(&mut self, package_dir: &Path) -> Result<(), KslError> {
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

        // Upload tarball (placeholder: simulate upload)
        let url = format!("{}/{}/{}.tar.gz", self.config.url, metadata.name, metadata.version);
        // Simulate HTTP POST (requires authentication in real implementation)
        println!("Simulating upload of {} to {}", tarball_path.display(), url);

        // Clean up tarball
        fs::remove_file(&tarball_path)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        Ok(())
    }
}

// Public API to manage packages via the registry
pub fn fetch_package(name: &str, version: &str) -> Result<(), KslError> {
    let mut client = RegistryClient::new();
    client.fetch_package(name, version)
}

pub fn publish_package(package_dir: &Path) -> Result<(), KslError> {
    let mut client = RegistryClient::new();
    client.publish_package(package_dir)
}

// Assume ksl_package.rs and ksl_errors.rs are in the same crate
mod ksl_package {
    pub use super::{PackageMetadata, PackageSystem};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::io::Write;

    #[test]
    fn test_fetch_package() {
        // Note: Requires a running registry server; simulate with local cache
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
            },
            ..RegistryClient::new()
        };
        let result = client.fetch_package("mylib", "1.0.0");
        assert!(result.is_ok());
        assert!(client.package_system.packages.contains_key("mylib@1.0.0"));
    }

    #[test]
    fn test_publish_package() {
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
            },
            ..RegistryClient::new()
        };
        let result = client.publish_package(&package_dir);
        assert!(result.is_ok());
        let tarball = package_dir.join("mylib-1.0.0.tar.gz");
        assert!(!tarball.exists()); // Cleaned up after publish
    }
}