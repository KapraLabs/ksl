// ksl_config.rs
// Manages global configuration settings for KSL tools, parsing ksl_config.toml,
// supporting environment variable overrides, and providing commands to set values.

use crate::ksl_errors::{KslError, SourcePosition};
use serde::{Deserialize, Serialize};
use toml;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use dirs::home_dir;
use async_trait::async_trait;
use tokio::fs as tokio_fs;
use tokio::io::AsyncWriteExt;

// Configuration structure for KSL tools
#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    // Compiler options
    optimize_level: Option<u8>,
    target_arch: Option<String>,
    enable_wasm: Option<bool>,
    
    // VM options
    vm_memory_limit: Option<u32>,
    vm_stack_size: Option<u32>,
    enable_jit: Option<bool>,
    
    // Deployment options
    aws_region: Option<String>,
    aws_bucket: Option<String>,
    
    // Monitoring options
    prometheus_port: Option<u16>,
    docserver_port: Option<u16>,
    
    // Output options
    output_dir: Option<String>,
}

// Configuration manager
pub struct ConfigManager {
    config_path: PathBuf,
    config: Config,
}

#[async_trait]
pub trait AsyncConfigManager {
    async fn load_async(&mut self) -> Result<&Config, KslError>;
    async fn save_async(&self) -> Result<(), KslError>;
}

impl ConfigManager {
    pub fn new() -> Result<Self, KslError> {
        let pos = SourcePosition::new(1, 1);
        let config_path = home_dir()
            .ok_or_else(|| KslError::type_error("Failed to locate home directory".to_string(), pos))?
            .join(".ksl/config.toml");

        let config = if config_path.exists() {
            let mut file = File::open(&config_path)
                .map_err(|e| KslError::type_error(
                    format!("Failed to open config file {}: {}", config_path.display(), e),
                    pos,
                ))?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .map_err(|e| KslError::type_error(
                    format!("Failed to read config file {}: {}", config_path.display(), e),
                    pos,
                ))?;
            toml::from_str(&contents)
                .map_err(|e| KslError::type_error(
                    format!("Failed to parse config file: {}", e),
                    pos,
                ))?
        } else {
            // Create default config
            let default_config = Config {
                optimize_level: Some(1),
                target_arch: Some("x86_64".to_string()),
                enable_wasm: Some(false),
                vm_memory_limit: Some(1024),
                vm_stack_size: Some(8192),
                enable_jit: Some(true),
                aws_region: None,
                aws_bucket: None,
                prometheus_port: None,
                docserver_port: None,
                output_dir: None,
            };
            let contents = toml::to_string(&default_config)
                .map_err(|e| KslError::type_error(
                    format!("Failed to serialize default config: {}", e),
                    pos,
                ))?;
            fs::create_dir_all(config_path.parent().unwrap())
                .map_err(|e| KslError::type_error(
                    format!("Failed to create config directory {}: {}", config_path.parent().unwrap().display(), e),
                    pos,
                ))?;
            File::create(&config_path)
                .map_err(|e| KslError::type_error(
                    format!("Failed to create config file {}: {}", config_path.display(), e),
                    pos,
                ))?
                .write_all(contents.as_bytes())
                .map_err(|e| KslError::type_error(
                    format!("Failed to write config file {}: {}", config_path.display(), e),
                    pos,
                ))?;
            default_config
        };

        Ok(ConfigManager { config_path, config })
    }

    // Load configuration with environment variable overrides
    pub fn load(&mut self) -> Result<&Config, KslError> {
        let pos = SourcePosition::new(1, 1);

        // Override with environment variables
        if let Ok(region) = std::env::var("KSL_AWS_REGION") {
            self.config.aws_region = Some(region);
        }
        if let Ok(bucket) = std::env::var("KSL_AWS_BUCKET") {
            self.config.aws_bucket = Some(bucket);
        }
        if let Ok(port) = std::env::var("KSL_PROMETHEUS_PORT") {
            let port: u16 = port.parse()
                .map_err(|e| KslError::type_error(
                    format!("Invalid Prometheus port: {}", e),
                    pos,
                ))?;
            self.config.prometheus_port = Some(port);
        }
        if let Ok(port) = std::env::var("KSL_DOCSERVER_PORT") {
            let port: u16 = port.parse()
                .map_err(|e| KslError::type_error(
                    format!("Invalid docserver port: {}", e),
                    pos,
                ))?;
            self.config.docserver_port = Some(port);
        }
        if let Ok(dir) = std::env::var("KSL_OUTPUT_DIR") {
            self.config.output_dir = Some(dir);
        }
        if let Ok(level) = std::env::var("KSL_OPTIMIZE_LEVEL") {
            let level: u8 = level.parse()
                .map_err(|e| KslError::type_error(
                    format!("Invalid optimize level: {}", e),
                    pos,
                ))?;
            self.config.optimize_level = Some(level);
        }
        if let Ok(arch) = std::env::var("KSL_TARGET_ARCH") {
            self.config.target_arch = Some(arch);
        }
        if let Ok(wasm) = std::env::var("KSL_ENABLE_WASM") {
            self.config.enable_wasm = Some(wasm.parse().unwrap_or(false));
        }
        if let Ok(memory) = std::env::var("KSL_VM_MEMORY_LIMIT") {
            self.config.vm_memory_limit = Some(memory.parse().unwrap_or(1024));
        }
        if let Ok(stack) = std::env::var("KSL_VM_STACK_SIZE") {
            self.config.vm_stack_size = Some(stack.parse().unwrap_or(8192));
        }
        if let Ok(jit) = std::env::var("KSL_ENABLE_JIT") {
            self.config.enable_jit = Some(jit.parse().unwrap_or(true));
        }

        Ok(&self.config)
    }

    // Get a configuration value by key
    pub fn get(&self, key: &str) -> Option<String> {
        match key {
            "aws_region" => self.config.aws_region.clone(),
            "aws_bucket" => self.config.aws_bucket.clone(),
            "prometheus_port" => self.config.prometheus_port.map(|p| p.to_string()),
            "docserver_port" => self.config.docserver_port.map(|p| p.to_string()),
            "output_dir" => self.config.output_dir.clone(),
            "optimize_level" => self.config.optimize_level.map(|l| l.to_string()),
            "target_arch" => self.config.target_arch.clone(),
            "enable_wasm" => self.config.enable_wasm.map(|w| w.to_string()),
            "vm_memory_limit" => self.config.vm_memory_limit.map(|m| m.to_string()),
            "vm_stack_size" => self.config.vm_stack_size.map(|s| s.to_string()),
            "enable_jit" => self.config.enable_jit.map(|j| j.to_string()),
            _ => None,
        }
    }

    // Set a configuration value and save to file
    pub fn set(&mut self, key: &str, value: &str) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        match key {
            "aws_region" => {
                self.config.aws_region = Some(value.to_string());
            }
            "aws_bucket" => {
                self.config.aws_bucket = Some(value.to_string());
            }
            "prometheus_port" => {
                let port: u16 = value.parse()
                    .map_err(|e| KslError::type_error(
                        format!("Invalid port: {}", e),
                        pos,
                    ))?;
                if port < 1024 || port > 65535 {
                    return Err(KslError::type_error(
                        "Port must be between 1024 and 65535".to_string(),
                        pos,
                    ));
                }
                self.config.prometheus_port = Some(port);
            }
            "docserver_port" => {
                let port: u16 = value.parse()
                    .map_err(|e| KslError::type_error(
                        format!("Invalid port: {}", e),
                        pos,
                    ))?;
                if port < 1024 || port > 65535 {
                    return Err(KslError::type_error(
                        "Port must be between 1024 and 65535".to_string(),
                        pos,
                    ));
                }
                self.config.docserver_port = Some(port);
            }
            "output_dir" => {
                let path = Path::new(value);
                if !path.exists() {
                    fs::create_dir_all(path)
                        .map_err(|e| KslError::type_error(
                            format!("Failed to create output directory {}: {}", path.display(), e),
                            pos,
                        ))?;
                }
                self.config.output_dir = Some(value.to_string());
            }
            "optimize_level" => {
                let level: u8 = value.parse()
                    .map_err(|e| KslError::type_error(
                        format!("Invalid optimize level: {}", e),
                        pos,
                    ))?;
                if level > 3 {
                    return Err(KslError::type_error(
                        "Optimize level must be between 0 and 3".to_string(),
                        pos,
                    ));
                }
                self.config.optimize_level = Some(level);
            }
            "target_arch" => {
                self.config.target_arch = Some(value.to_string());
            }
            "enable_wasm" => {
                self.config.enable_wasm = Some(value.parse().unwrap_or(false));
            }
            "vm_memory_limit" => {
                let memory: u32 = value.parse()
                    .map_err(|e| KslError::type_error(
                        format!("Invalid memory limit: {}", e),
                        pos,
                    ))?;
                self.config.vm_memory_limit = Some(memory);
            }
            "vm_stack_size" => {
                let stack: u32 = value.parse()
                    .map_err(|e| KslError::type_error(
                        format!("Invalid stack size: {}", e),
                        pos,
                    ))?;
                self.config.vm_stack_size = Some(stack);
            }
            "enable_jit" => {
                self.config.enable_jit = Some(value.parse().unwrap_or(true));
            }
            _ => return Err(KslError::type_error(
                format!("Unknown config key: {}", key),
                pos,
            )),
        }

        // Save updated config
        let contents = toml::to_string(&self.config)
            .map_err(|e| KslError::type_error(
                format!("Failed to serialize config: {}", e),
                pos,
            ))?;
        File::create(&self.config_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to create config file {}: {}", self.config_path.display(), e),
                pos,
            ))?
            .write_all(contents.as_bytes())
            .map_err(|e| KslError::type_error(
                format!("Failed to write config file {}: {}", self.config_path.display(), e),
                pos,
            ))?;

        Ok(())
    }
}

#[async_trait]
impl AsyncConfigManager for ConfigManager {
    /// Asynchronously loads configuration with environment variable overrides
    async fn load_async(&mut self) -> Result<&Config, KslError> {
        let pos = SourcePosition::new(1, 1);

        // Override with environment variables (same as sync version)
        if let Ok(region) = std::env::var("KSL_AWS_REGION") {
            self.config.aws_region = Some(region);
        }
        if let Ok(bucket) = std::env::var("KSL_AWS_BUCKET") {
            self.config.aws_bucket = Some(bucket);
        }
        if let Ok(port) = std::env::var("KSL_PROMETHEUS_PORT") {
            let port: u16 = port.parse()
                .map_err(|e| KslError::type_error(
                    format!("Invalid Prometheus port: {}", e),
                    pos,
                ))?;
            self.config.prometheus_port = Some(port);
        }
        if let Ok(port) = std::env::var("KSL_DOCSERVER_PORT") {
            let port: u16 = port.parse()
                .map_err(|e| KslError::type_error(
                    format!("Invalid docserver port: {}", e),
                    pos,
                ))?;
            self.config.docserver_port = Some(port);
        }
        if let Ok(dir) = std::env::var("KSL_OUTPUT_DIR") {
            self.config.output_dir = Some(dir);
        }
        if let Ok(level) = std::env::var("KSL_OPTIMIZE_LEVEL") {
            let level: u8 = level.parse()
                .map_err(|e| KslError::type_error(
                    format!("Invalid optimize level: {}", e),
                    pos,
                ))?;
            self.config.optimize_level = Some(level);
        }
        if let Ok(arch) = std::env::var("KSL_TARGET_ARCH") {
            self.config.target_arch = Some(arch);
        }
        if let Ok(wasm) = std::env::var("KSL_ENABLE_WASM") {
            self.config.enable_wasm = Some(wasm.parse().unwrap_or(false));
        }
        if let Ok(memory) = std::env::var("KSL_VM_MEMORY_LIMIT") {
            self.config.vm_memory_limit = Some(memory.parse().unwrap_or(1024));
        }
        if let Ok(stack) = std::env::var("KSL_VM_STACK_SIZE") {
            self.config.vm_stack_size = Some(stack.parse().unwrap_or(8192));
        }
        if let Ok(jit) = std::env::var("KSL_ENABLE_JIT") {
            self.config.enable_jit = Some(jit.parse().unwrap_or(true));
        }

        Ok(&self.config)
    }

    /// Asynchronously saves the current configuration to file
    async fn save_async(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let contents = toml::to_string(&self.config)
            .map_err(|e| KslError::type_error(
                format!("Failed to serialize config: {}", e),
                pos,
            ))?;
        
        tokio_fs::create_dir_all(self.config_path.parent().unwrap())
            .await
            .map_err(|e| KslError::type_error(
                format!("Failed to create config directory {}: {}", self.config_path.parent().unwrap().display(), e),
                pos,
            ))?;
            
        let mut file = tokio_fs::File::create(&self.config_path)
            .await
            .map_err(|e| KslError::type_error(
                format!("Failed to create config file {}: {}", self.config_path.display(), e),
                pos,
            ))?;
            
        file.write_all(contents.as_bytes())
            .await
            .map_err(|e| KslError::type_error(
                format!("Failed to write config file {}: {}", self.config_path.display(), e),
                pos,
            ))?;

        Ok(())
    }
}

// Public API to manage configuration
pub fn get_config(key: &str) -> Result<Option<String>, KslError> {
    let mut manager = ConfigManager::new()?;
    manager.load()?;
    Ok(manager.get(key))
}

pub fn set_config(key: &str, value: &str) -> Result<(), KslError> {
    let mut manager = ConfigManager::new()?;
    manager.set(key, value)
}

// Assume ksl_errors.rs is in the same crate
mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_config_new() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        let mut manager = ConfigManager::new();
        manager.config_path = config_path.clone();

        let result = manager.load();
        assert!(result.is_ok());
        assert!(config_path.exists());
        let content = fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("optimize_level = 1"));
    }

    #[test]
    fn test_set_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        let mut manager = ConfigManager::new();
        manager.config_path = config_path.clone();

        let result = manager.set("aws_region", "us-west-2");
        assert!(result.is_ok());
        let content = fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("aws_region = \"us-west-2\""));

        let value = manager.get("aws_region");
        assert_eq!(value, Some("us-west-2".to_string()));
    }

    #[test]
    fn test_set_config_invalid_port() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        let mut manager = ConfigManager::new();
        manager.config_path = config_path;

        let result = manager.set("prometheus_port", "80");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Port must be between 1024 and 65535"));
    }

    #[test]
    fn test_set_config_invalid_key() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        let mut manager = ConfigManager::new();
        manager.config_path = config_path;

        let result = manager.set("invalid_key", "value");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown config key"));
    }

    #[test]
    fn test_env_override() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        let mut manager = ConfigManager::new();
        manager.config_path = config_path;

        std::env::set_var("KSL_AWS_REGION", "us-east-1");
        let result = manager.load();
        assert!(result.is_ok());
        assert_eq!(manager.get("aws_region"), Some("us-east-1".to_string()));
        std::env::remove_var("KSL_AWS_REGION");
    }

    #[tokio::test]
    async fn test_async_load() {
        let mut manager = ConfigManager::new().unwrap();
        assert!(manager.load_async().await.is_ok());
    }

    #[tokio::test]
    async fn test_async_save() {
        let manager = ConfigManager::new().unwrap();
        assert!(manager.save_async().await.is_ok());
    }
}
