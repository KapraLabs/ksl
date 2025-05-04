// ksl_deploy.rs
// Implements packaging and deployment of KSL programs as high-speed standalone
// applications or services for cloud and IoT environments.
// Supports async deployment and contract deployment.

use crate::ksl_aot::aot_compile;
use crate::ksl_wasm::generate_wasm;
use crate::ksl_package::{PackageSystem, PackageMetadata};
use crate::ksl_sandbox::{Sandbox, SandboxPolicy, run_sandbox_async};
use crate::ksl_parser::parse;
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::KapraBytecode;
use crate::ksl_contract::{ContractDeployer, ContractConfig};
use crate::ksl_bundler::{Bundler, BundlerConfig, ModuleFormat};
use crate::ksl_async::{AsyncRuntime, AsyncResult};
use crate::ksl_errors::{KslError, SourcePosition};
use rusoto_core::Region;
use rusoto_s3::{S3Client, PutObjectRequest, S3};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tar::Builder;
use flate2::write::GzEncoder;
use flate2::Compression;
use reqwest::Client;
use toml;

/// Configuration for KSL deployment
#[derive(Debug, Deserialize, Serialize)]
pub struct DeployConfig {
    /// Target platform: "aws", "iot", or "contract"
    pub target: String,
    /// AWS region for cloud deployment
    pub aws_region: Option<String>,
    /// S3 bucket for AWS deployment
    pub aws_bucket: Option<String>,
    /// HTTP endpoint for IoT device
    pub iot_endpoint: Option<String>,
    /// Directory for deployment artifacts
    pub output_dir: PathBuf,
    /// Contract configuration for blockchain deployment
    pub contract_config: Option<ContractConfig>,
    /// Whether to use async deployment
    pub async_deploy: bool,
}

/// State for tracking deployment progress
#[derive(Debug, Default)]
pub struct DeployState {
    /// Number of files processed
    pub files_processed: u64,
    /// Total deployment size
    pub total_size: u64,
    /// Time taken for deployment
    pub deploy_time: std::time::Duration,
    /// Current deployment stage
    pub current_stage: String,
    /// Contract deployment status
    pub contract_status: Option<String>,
}

/// Deployment manager with async support
pub struct DeployManager {
    /// Package system for dependency management
    package_system: Arc<RwLock<PackageSystem>>,
    /// Contract deployer for blockchain deployment
    contract_deployer: Arc<RwLock<ContractDeployer>>,
    /// HTTP client for remote operations
    client: Arc<Client>,
    /// S3 client for AWS deployment
    s3_client: Option<Arc<S3Client>>,
    /// Deployment configuration
    config: DeployConfig,
    /// Async runtime for concurrent operations
    async_runtime: Arc<AsyncRuntime>,
    /// Current deployment state
    state: Arc<RwLock<DeployState>>,
}

impl DeployManager {
    /// Creates a new deployment manager instance
    pub fn new(config: DeployConfig) -> Result<Self, KslError> {
        let pos = SourcePosition::new(1, 1);
        let s3_client = if config.target == "aws" {
            let region = config.aws_region.as_ref()
                .ok_or_else(|| KslError::type_error("AWS region required for aws target".to_string(), pos))?
                .parse::<Region>()
                .map_err(|e| KslError::type_error(format!("Invalid AWS region: {}", e), pos))?;
            Some(Arc::new(S3Client::new(region)))
        } else {
            None
        };

        Ok(DeployManager {
            package_system: Arc::new(RwLock::new(PackageSystem::new())),
            contract_deployer: Arc::new(RwLock::new(ContractDeployer::new())),
            client: Arc::new(Client::new()),
            s3_client,
            config,
            async_runtime: Arc::new(AsyncRuntime::new()),
            state: Arc::new(RwLock::new(DeployState::default())),
        })
    }

    /// Deploy a KSL program asynchronously
    pub async fn deploy_async(&self, file: &PathBuf) -> AsyncResult<()> {
        let pos = SourcePosition::new(1, 1);
        let start_time = std::time::Instant::now();

        // Update state
        let mut state = self.state.write().await;
        state.current_stage = "validating".to_string();
        drop(state);

        // Validate environment
        self.validate_environment_async().await?;

        // Update state
        let mut state = self.state.write().await;
        state.current_stage = "resolving".to_string();
        drop(state);

        // Resolve dependencies
        let project_dir = file.parent().unwrap_or_else(|| Path::new("."));
        let package_system = self.package_system.read().await;
        package_system.resolve_dependencies_async(project_dir).await
            .map_err(|e| KslError::type_error(format!("Dependency resolution failed: {}", e), pos))?;

        // Update state
        let mut state = self.state.write().await;
        state.current_stage = "bundling".to_string();
        drop(state);

        // Bundle using the bundler
        let bundler_config = BundlerConfig {
            input_file: file.clone(),
            target: self.config.target.clone(),
            output_file: self.config.output_dir.join("bundle.kslbin"),
            module_format: ModuleFormat::Standard,
            async_bundle: true,
        };
        let bundler = Bundler::new(bundler_config);
        bundler.bundle_async().await?;

        // Update state
        let mut state = self.state.write().await;
        state.current_stage = "sandboxing".to_string();
        drop(state);

        // Run in sandbox
        let mut sandbox = Sandbox::new(SandboxPolicy::default());
        sandbox.run_sandbox_async(file).await
            .map_err(|e| KslError::type_error(
                e.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"),
                pos,
            ))?;

        // Update state
        let mut state = self.state.write().await;
        state.current_stage = "deploying".to_string();
        drop(state);

        // Deploy based on target
        match self.config.target.as_str() {
            "aws" => self.deploy_to_aws_async(&self.config.output_dir.join("bundle.kslbin")).await?,
            "iot" => self.deploy_to_iot_async(&self.config.output_dir.join("bundle.kslbin")).await?,
            "contract" => {
                if let Some(contract_config) = &self.config.contract_config {
                    let contract_deployer = self.contract_deployer.read().await;
                    let status = contract_deployer.deploy_async(contract_config).await?;
                    let mut state = self.state.write().await;
                    state.contract_status = Some(status);
                } else {
                    return Err(KslError::type_error(
                        "Contract configuration required for contract deployment".to_string(),
                        pos,
                    ));
                }
            }
            _ => return Err(KslError::type_error(
                format!("Unsupported deployment target: {}", self.config.target),
                pos,
            )),
        }

        // Update state
        let mut state = self.state.write().await;
        state.current_stage = "cleaning".to_string();
        state.deploy_time = start_time.elapsed();
        drop(state);

        // Clean up artifact
        fs::remove_file(&self.config.output_dir.join("bundle.kslbin"))
            .map_err(|e| KslError::type_error(
                format!("Failed to clean up artifact: {}", e),
                pos,
            ))?;

        Ok(())
    }

    /// Validate deployment environment asynchronously
    async fn validate_environment_async(&self) -> AsyncResult<()> {
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
            "contract" => {
                if self.config.contract_config.is_none() {
                    return Err(KslError::type_error("Contract configuration required for contract deployment".to_string(), pos));
                }
            }
            _ => return Err(KslError::type_error(
                format!("Unsupported target: {}", self.config.target),
                pos,
            )),
        }
        Ok(())
    }

    /// Deploy to AWS asynchronously
    async fn deploy_to_aws_async(&self, artifact_path: &PathBuf) -> AsyncResult<()> {
        let pos = SourcePosition::new(1, 1);
        let s3_client = self.s3_client.as_ref()
            .ok_or_else(|| KslError::type_error("S3 client not initialized".to_string(), pos))?;
        let bucket = self.config.aws_bucket.as_ref()
            .ok_or_else(|| KslError::type_error("AWS bucket not configured".to_string(), pos))?;

        let artifact = fs::read(artifact_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to read artifact {}: {}", artifact_path.display(), e),
                pos,
            ))?;

        let key = format!("{}/{}", chrono::Utc::now().format("%Y%m%d"), artifact_path.file_name().unwrap().to_string_lossy());
        let request = PutObjectRequest {
            bucket: bucket.clone(),
            key,
            body: Some(artifact.into()),
            ..Default::default()
        };

        s3_client.put_object(request).await
            .map_err(|e| KslError::type_error(format!("Failed to upload to S3: {}", e), pos))?;

        Ok(())
    }

    /// Deploy to IoT device asynchronously
    async fn deploy_to_iot_async(&self, artifact_path: &PathBuf) -> AsyncResult<()> {
        let pos = SourcePosition::new(1, 1);
        let endpoint = self.config.iot_endpoint.as_ref()
            .ok_or_else(|| KslError::type_error("IoT endpoint not configured".to_string(), pos))?;

        let artifact = fs::read(artifact_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to read artifact {}: {}", artifact_path.display(), e),
                pos,
            ))?;

        self.client.post(endpoint)
            .body(artifact)
            .send().await
            .map_err(|e| KslError::type_error(format!("Failed to deploy to IoT device: {}", e), pos))?
            .error_for_status()
            .map_err(|e| KslError::type_error(format!("IoT deployment failed: {}", e), pos))?;

        Ok(())
    }
}

/// Public API to deploy a KSL program asynchronously
pub async fn deploy_async(
    file: &PathBuf,
    target: &str,
    aws_region: Option<String>,
    aws_bucket: Option<String>,
    iot_endpoint: Option<String>,
    output_dir: PathBuf,
    contract_config: Option<ContractConfig>,
) -> AsyncResult<()> {
    let config = DeployConfig {
        target: target.to_string(),
        aws_region,
        aws_bucket,
        iot_endpoint,
        output_dir,
        contract_config,
        async_deploy: true,
    };
    let deployer = DeployManager::new(config)?;
    deployer.deploy_async(file).await
}

// Assume ksl_aot.rs, ksl_wasm.rs, ksl_package.rs, ksl_sandbox.rs, ksl_parser.rs,
// ksl_checker.rs, ksl_compiler.rs, ksl_bytecode.rs, ksl_contract.rs, ksl_bundler.rs,
// ksl_async.rs, and ksl_errors.rs are in the same crate
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
    pub use super::{Sandbox, SandboxPolicy, run_sandbox_async};
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

mod ksl_contract {
    pub use super::{ContractDeployer, ContractConfig};
}

mod ksl_bundler {
    pub use super::{Bundler, BundlerConfig, ModuleFormat};
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

    #[tokio::test]
    async fn test_deploy_aws_async() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let output_dir = temp_dir.path().join("output");
        fs::write(&input_file, r#"
            fn main() {
                println!("Hello, world!");
            }
        "#).unwrap();

        let result = deploy_async(
            &input_file,
            "aws",
            Some("us-east-1".to_string()),
            Some("test-bucket".to_string()),
            None,
            output_dir,
            None,
        ).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_deploy_iot_async() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let output_dir = temp_dir.path().join("output");
        fs::write(&input_file, r#"
            fn main() {
                println!("Hello, world!");
            }
        "#).unwrap();

        let result = deploy_async(
            &input_file,
            "iot",
            None,
            None,
            Some("http://localhost:8080/deploy".to_string()),
            output_dir,
            None,
        ).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_deploy_contract_async() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let output_dir = temp_dir.path().join("output");
        fs::write(&input_file, r#"
            fn main() {
                println!("Hello, world!");
            }
        "#).unwrap();

        let contract_config = ContractConfig {
            network: "testnet".to_string(),
            gas_limit: 1000000,
            ..Default::default()
        };

        let result = deploy_async(
            &input_file,
            "contract",
            None,
            None,
            None,
            output_dir,
            Some(contract_config),
        ).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_deploy_invalid_target() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let output_dir = temp_dir.path().join("output");
        fs::write(&input_file, r#"
            fn main() {
                println!("Hello, world!");
            }
        "#).unwrap();

        let result = deploy_async(
            &input_file,
            "invalid",
            None,
            None,
            None,
            output_dir,
            None,
        ).await;
        assert!(result.is_err());
    }
}
