// ksl_deploy.rs
// Implements packaging and deployment of KSL programs as high-speed standalone
// applications or services for cloud and IoT environments.

use crate::ksl_aot::aot_compile;
use crate::ksl_wasm::generate_wasm;
use crate::ksl_package::{PackageSystem, PackageMetadata};
use crate::ksl_sandbox::run_sandbox;
use crate::ksl_parser::parse;
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::KapraBytecode;
use crate::ksl_errors::{KslError, SourcePosition};
use rusoto_core::Region;
use rusoto_s3::{S3Client, PutObjectRequest, S3};
use async_std::task;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use tar::Builder;
use flate2::write::GzEncoder;
use flate2::Compression;
use reqwest::blocking::Client;
use toml;

// Deployment configuration
#[derive(Debug, Deserialize, Serialize)]
pub struct DeployConfig {
    target: String, // e.g., "aws", "iot"
    aws_region: Option<String>, // e.g., "us-east-1"
    aws_bucket: Option<String>, // S3 bucket for AWS deployment
    iot_endpoint: Option<String>, // HTTP endpoint for IoT device
    output_dir: PathBuf, // Directory for artifacts
}

// Deployment manager
pub struct DeployManager {
    package_system: PackageSystem,
    client: Client,
    s3_client: Option<S3Client>,
    config: DeployConfig,
}

impl DeployManager {
    pub fn new(config: DeployConfig) -> Result<Self, KslError> {
        let pos = SourcePosition::new(1, 1); // To be enhanced
        let s3_client = if config.target == "aws" {
            let region = config.aws_region.as_ref()
                .ok_or_else(|| KslError::type_error("AWS region required for aws target".to_string(), pos))?
                .parse::<Region>()
                .map_err(|e| KslError::type_error(format!("Invalid AWS region: {}", e), pos))?;
            Some(S3Client::new(region))
        } else {
            None
        };

        Ok(DeployManager {
            package_system: PackageSystem::new(),
            client: Client::new(),
            s3_client,
            config,
        })
    }

    // Package and deploy a KSL program
    pub fn deploy(&mut self, file: &PathBuf) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        // Validate environment
        self.validate_environment()?;

        // Resolve dependencies
        let project_dir = file.parent().unwrap_or_else(|| Path::new("."));
        self.package_system.resolve_dependencies(project_dir)
            .map_err(|e| KslError::type_error(format!("Dependency resolution failed: {}", e), pos))?;

        // Compile and bundle
        let artifact_path = self.bundle(file)?;

        // Run in sandbox to ensure security
        run_sandbox(file)
            .map_err(|e| KslError::type_error(
                e.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"),
                pos,
            ))?;

        // Deploy
        match self.config.target.as_str() {
            "aws" => self.deploy_to_aws(&artifact_path)?,
            "iot" => self.deploy_to_iot(&artifact_path)?,
            _ => return Err(KslError::type_error(
                format!("Unsupported deployment target: {}", self.config.target),
                pos,
            )),
        }

        // Clean up artifact
        fs::remove_file(&artifact_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to clean up artifact {}: {}", artifact_path.display(), e),
                pos,
            ))?;

        Ok(())
    }

    // Validate deployment environment
    fn validate_environment(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        match self.config.target.as_str() {
            "aws" => {
                if self.config.aws_bucket.is_none() {
                    return Err(KslError::type_error("AWS bucket required for aws target".to_string(), pos));
                }
                // Check AWS credentials (simplified)
                if std::env::var("AWS_ACCESS_KEY_ID").is_err() || std::env::var("AWS_SECRET_ACCESS_KEY").is_err() {
                    return Err(KslError::type_error("AWS credentials not found".to_string(), pos));
                }
            }
            "iot" => {
                if self.config.iot_endpoint.is_none() {
                    return Err(KslError::type_error("IoT endpoint required for iot target".to_string(), pos));
                }
            }
            _ => return Err(KslError::type_error(
                format!("Unsupported target: {}", self.config.target),
                pos,
            )),
        }
        Ok(())
    }

    // Bundle AOT/WASM binaries and dependencies
    fn bundle(&self, file: &PathBuf) -> Result<PathBuf, KslError> {
        let pos = SourcePosition::new(1, 1);
        let output_dir = &self.config.output_dir;
        fs::create_dir_all(output_dir)
            .map_err(|e| KslError::type_error(
                format!("Failed to create output directory {}: {}", output_dir.display(), e),
                pos,
            ))?;

        // Compile source to bytecode
        let source = fs::read_to_string(file)
            .map_err(|e| KslError::type_error(
                format!("Failed to read file {}: {}", file.display(), e),
                pos,
            ))?;
        let ast = parse(&source)
            .map_err(|e| KslError::type_error(
                format!("Parse error at position {}: {}", e.position, e.message),
                pos,
            ))?;
        check(&ast)
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Type error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
            ))?;
        let bytecode = compile(&ast)
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Compile error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
            ))?;

        // Generate AOT and WASM binaries
        let file_stem = file.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| KslError::type_error("Invalid file name".to_string(), pos))?;
        let aot_path = output_dir.join(format!("{}.o", file_stem));
        let wasm_path = output_dir.join(format!("{}.wasm", file_stem));
        aot_compile(file, &aot_path, "x86_64")
            .map_err(|e| KslError::type_error(format!("AOT compilation failed: {}", e), pos))?;
        let wasm_bytes = generate_wasm(bytecode)
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("WASM error at instruction {}: {}", e.instruction, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
            ))?;
        fs::write(&wasm_path, &wasm_bytes)
            .map_err(|e| KslError::type_error(
                format!("Failed to write WASM binary {}: {}", wasm_path.display(), e),
                pos,
            ))?;

        // Create tarball
        let artifact_path = output_dir.join(format!("{}.tar.gz", file_stem));
        let tar_gz = File::create(&artifact_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to create artifact {}: {}", artifact_path.display(), e),
                pos,
            ))?;
        let enc = GzEncoder::new(tar_gz, Compression::default());
        let mut tar = Builder::new(enc);

        // Add AOT and WASM binaries
        tar.append_path_with_name(&aot_path, format!("bin/{}.o", file_stem))
            .map_err(|e| KslError::type_error(
                format!("Failed to add AOT binary to tar: {}", e),
                pos,
            ))?;
        tar.append_path_with_name(&wasm_path, format!("bin/{}.wasm", file_stem))
            .map_err(|e| KslError::type_error(
                format!("Failed to add WASM binary to tar: {}", e),
                pos,
            ))?;

        // Add dependencies
        let metadata_file = project_dir.join("ksl_package.toml");
        if metadata_file.exists() {
            let metadata_content = fs::read_to_string(&metadata_file)
                .map_err(|e| KslError::type_error(
                    format!("Failed to read metadata {}: {}", metadata_file.display(), e),
                    pos,
                ))?;
            let metadata: PackageMetadata = toml::from_str(&metadata_content)
                .map_err(|e| KslError::type_error(
                    format!("Failed to parse metadata: {}", e),
                    pos,
                ))?;
            for (dep_name, dep_version) in metadata.dependencies {
                let dep_dir = self.package_system.repository.join(&dep_name).join(&dep_version).join("src");
                if dep_dir.exists() {
                    for entry in fs::read_dir(&dep_dir)
                        .map_err(|e| KslError::type_error(
                            format!("Failed to read dependency dir {}: {}", dep_dir.display(), e),
                            pos,
                        ))?
                    {
                        let entry = entry?;
                        if entry.path().extension().map(|ext| ext == "ksl").unwrap_or(false) {
                            tar.append_path_with_name(&entry.path(), format!("deps/{}/{}/{}", dep_name, dep_version, entry.file_name().to_string_lossy()))
                                .map_err(|e| KslError::type_error(
                                    format!("Failed to add dependency {}: {}", entry.path().display(), e),
                                    pos,
                                ))?;
                        }
                    }
                }
            }
        }

        tar.finish()
            .map_err(|e| KslError::type_error(
                format!("Failed to finalize tarball: {}", e),
                pos,
            ))?;

        Ok(artifact_path)
    }

    // Deploy to AWS (S3 for simplicity, extensible to Lambda/EC2)
    fn deploy_to_aws(&self, artifact_path: &PathBuf) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let s3_client = self.s3_client.as_ref()
            .ok_or_else(|| KslError::type_error("S3 client not initialized".to_string(), pos))?;
        let bucket = self.config.aws_bucket.as_ref()
            .ok_or_else(|| KslError::type_error("AWS bucket not specified".to_string(), pos))?;
        let key = artifact_path.file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| KslError::type_error("Invalid artifact name".to_string(), pos))?;

        let mut file = File::open(artifact_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to open artifact {}: {}", artifact_path.display(), e),
                pos,
            ))?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .map_err(|e| KslError::type_error(
                format!("Failed to read artifact {}: {}", artifact_path.display(), e),
                pos,
            ))?;

        let request = PutObjectRequest {
            bucket: bucket.to_string(),
            key: key.to_string(),
            body: Some(contents.into()),
            ..Default::default()
        };

        task::block_on(s3_client.put_object(request))
            .map_err(|e| KslError::type_error(
                format!("Failed to deploy to AWS S3: {}", e),
                pos,
            ))?;

        println!("Deployed to AWS S3: s3://{}/{}", bucket, key);
        Ok(())
    }

    // Deploy to IoT device (simulated HTTP upload)
    fn deploy_to_iot(&self, artifact_path: &PathBuf) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let endpoint = self.config.iot_endpoint.as_ref()
            .ok_or_else(|| KslError::type_error("IoT endpoint not specified".to_string(), pos))?;
        let key = artifact_path.file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| KslError::type_error("Invalid artifact name".to_string(), pos))?;

        let contents = fs::read(artifact_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to read artifact {}: {}", artifact_path.display(), e),
                pos,
            ))?;

        self.client
            .post(endpoint)
            .body(contents)
            .header("Content-Type", "application/gzip")
            .header("X-Artifact-Name", key)
            .send()
            .map_err(|e| KslError::type_error(
                format!("Failed to deploy to IoT endpoint {}: {}", endpoint, e),
                pos,
            ))?;

        println!("Deployed to IoT endpoint: {}", endpoint);
        Ok(())
    }
}

// Public API to deploy a KSL program
pub fn deploy(file: &PathBuf, target: &str, aws_region: Option<String>, aws_bucket: Option<String>, iot_endpoint: Option<String>, output_dir: PathBuf) -> Result<(), KslError> {
    let config = DeployConfig {
        target: target.to_string(),
        aws_region,
        aws_bucket,
        iot_endpoint,
        output_dir,
    };
    let mut manager = DeployManager::new(config)?;
    manager.deploy(file)
}

// Assume ksl_aot.rs, ksl_wasm.rs, ksl_package.rs, ksl_sandbox.rs, ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_bytecode.rs, and ksl_errors.rs are in the same crate
mod ksl_aot {
    pub use super::aot_compile;
}

mod ksl_wasm {
    pub use super::generate_wasm;
}

mod ksl_package {
    pub use super::{PackageSystem, PackageMetadata};
}

mod ksl_sandbox {
    pub use super::run_sandbox;
}

mod ksl_parser {
    pub use super::parse;
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_compiler {
    pub use super::compile;
}

mod ksl_bytecode {
    pub use super::KapraBytecode;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{TempDir, NamedTempFile};

    #[test]
    fn test_bundle() {
        let temp_dir = TempDir::new().unwrap();
        let mut temp_file = NamedTempFile::new_in(&temp_dir).unwrap();
        writeln!(
            temp_file,
            "fn main() { let x: u32 = 42; }"
        ).unwrap();
        let output_dir = temp_dir.path().join("output");
        let config = DeployConfig {
            target: "aws".to_string(),
            aws_region: Some("us-east-1".to_string()),
            aws_bucket: Some("test-bucket".to_string()),
            iot_endpoint: None,
            output_dir: output_dir.clone(),
        };
        let manager = DeployManager::new(config).unwrap();

        let artifact_path = manager.bundle(&temp_file.path().to_path_buf()).unwrap();
        assert!(artifact_path.exists());
        assert!(artifact_path.to_string_lossy().ends_with(".tar.gz"));

        let tar_gz = File::open(&artifact_path).unwrap();
        let tar = GzDecoder::new(tar_gz);
        let mut archive = Archive::new(tar);
        let entries: Vec<_> = archive.entries().unwrap().map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned()).collect();
        assert!(entries.iter().any(|e| e.ends_with(".o")));
        assert!(entries.iter().any(|e| e.ends_with(".wasm")));
    }

    #[test]
    fn test_validate_environment_aws() {
        let config = DeployConfig {
            target: "aws".to_string(),
            aws_region: None,
            aws_bucket: Some("test-bucket".to_string()),
            iot_endpoint: None,
            output_dir: PathBuf::from("output"),
        };
        let manager = DeployManager::new(config);
        assert!(manager.is_err());
        assert!(manager.unwrap_err().to_string().contains("AWS region required"));
    }

    #[test]
    fn test_validate_environment_iot() {
        let config = DeployConfig {
            target: "iot".to_string(),
            aws_region: None,
            aws_bucket: None,
            iot_endpoint: None,
            output_dir: PathBuf::from("output"),
        };
        let manager = DeployManager::new(config);
        assert!(manager.is_err());
        assert!(manager.unwrap_err().to_string().contains("IoT endpoint required"));
    }
}
