// ksl_package_publish.rs
// Enables publishing KSL packages to a registry for community sharing, packaging
// projects into tarballs and uploading them via HTTP.

use crate::ksl_package::{PackageSystem, PackageMetadata};
use crate::ksl_docgen::generate_docgen;
use crate::ksl_errors::{KslError, SourcePosition};
use reqwest::blocking::Client;
use tar::Builder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use toml;

// Package publish configuration
#[derive(Debug)]
pub struct PublishConfig {
    package_dir: PathBuf, // Directory containing the package
    registry_url: String, // Remote registry URL (e.g., registry.ksl.dev)
    output_tarball: PathBuf, // Temporary tarball file
}

// Package publisher
pub struct PackagePublisher {
    config: PublishConfig,
    package_system: PackageSystem,
    client: Client,
}

impl PackagePublisher {
    pub fn new(config: PublishConfig) -> Self {
        PackagePublisher {
            config,
            package_system: PackageSystem::new(),
            client: Client::new(),
        }
    }

    // Publish a KSL package to the remote registry
    pub fn publish(&mut self) -> Result<(), KslError> {
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

        // Resolve dependencies
        self.package_system.resolve_dependencies(&self.config.package_dir)
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

        // Publish to registry
        let tarball_data = fs::read(&self.config.output_tarball)
            .map_err(|e| KslError::type_error(
                format!("Failed to read tarball {}: {}", self.config.output_tarball.display(), e),
                pos,
            ))?;
        let publish_url = format!("{}/publish/{}/{}", self.config.registry_url, metadata.name, metadata.version);
        self.client
            .post(&publish_url)
            .body(tarball_data)
            .header("Content-Type", "application/gzip")
            .send()
            .map_err(|e| KslError::type_error(
                format!("Failed to publish to registry {}: {}", publish_url, e),
                pos,
            ))?
            .error_for_status()
            .map_err(|e| KslError::type_error(
                format!("Registry publish failed: {}", e),
                pos,
            ))?;

        // Clean up temporary tarball
        fs::remove_file(&self.config.output_tarball)
            .map_err(|e| KslError::type_error(
                format!("Failed to clean up tarball {}: {}", self.config.output_tarball.display(), e),
                pos,
            ))?;

        Ok(())
    }
}

// Public API to publish a KSL package
pub fn publish(package_dir: &PathBuf, registry_url: &str) -> Result<(), KslError> {
    let pos = SourcePosition::new(1, 1);
    let output_tarball = package_dir.join("package.tar.gz");
    let config = PublishConfig {
        package_dir: package_dir.clone(),
        registry_url: registry_url.to_string(),
        output_tarball,
    };
    let mut publisher = PackagePublisher::new(config);
    publisher.publish()
}

// Assume ksl_package.rs, ksl_docgen.rs, and ksl_errors.rs are in the same crate
mod ksl_package {
    pub use super::{PackageSystem, PackageMetadata};
}

mod ksl_docgen {
    pub use super::generate_docgen;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;

    #[test]
    fn test_publish_invalid_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let package_dir = temp_dir.path().join("package");
        fs::create_dir_all(&package_dir).unwrap();
        let metadata_file = package_dir.join("ksl_package.toml");
        let mut file = File::create(&metadata_file).unwrap();
        writeln!(file, "name = \"\"\nversion = \"1.0.0\"").unwrap();

        let result = publish(&package_dir, "http://registry.ksl.dev");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Package metadata must include name and version"));
    }

    #[test]
    fn test_publish_no_source() {
        let temp_dir = TempDir::new().unwrap();
        let package_dir = temp_dir.path().join("package");
        fs::create_dir_all(&package_dir).unwrap();
        let metadata_file = package_dir.join("ksl_package.toml");
        let mut file = File::create(&metadata_file).unwrap();
        writeln!(file, "name = \"test\"\nversion = \"1.0.0\"").unwrap();

        let result = publish(&package_dir, "http://registry.ksl.dev");
        assert!(result.is_err()); // Fails due to HTTP request (mocked registry)
        assert!(result.unwrap_err().to_string().contains("Failed to publish to registry"));
    }

    #[test]
    fn test_publish_invalid_dir() {
        let temp_dir = TempDir::new().unwrap();
        let package_dir = temp_dir.path().join("nonexistent");

        let result = publish(&package_dir, "http://registry.ksl.dev");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read metadata file"));
    }

    #[test]
    fn test_publish_with_docs() {
        let temp_dir = TempDir::new().unwrap();
        let package_dir = temp_dir.path().join("package");
        fs::create_dir_all(package_dir.join("src")).unwrap();
        let src_file = package_dir.join("src/main.ksl");
        let mut src = File::create(&src_file).unwrap();
        writeln!(src, "fn main() {{}}").unwrap();

        let metadata_file = package_dir.join("ksl_package.toml");
        let mut file = File::create(&metadata_file).unwrap();
        writeln!(file, "name = \"test\"\nversion = \"1.0.0\"").unwrap();

        let result = publish(&package_dir, "http://registry.ksl.dev");
        assert!(result.is_err()); // Fails due to HTTP request (mocked registry)
        assert!(result.unwrap_err().to_string().contains("Failed to publish to registry"));

        // Check that documentation was generated
        let doc_file = package_dir.join("docs/test.md");
        assert!(doc_file.exists());
    }
}
