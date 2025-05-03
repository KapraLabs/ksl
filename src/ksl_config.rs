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

// Configuration structure for KSL tools
#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    aws_region: Option<String>, // AWS region for ksl_deploy.rs
    aws_bucket: Option<String>, // AWS bucket for ksl_deploy.rs
    prometheus_port: Option<u16>, // Prometheus port for ksl_metrics.rs
    docserver_port: Option<u16>, // Port for ksl_docserver.rs
    output_dir: Option<String>, // Default output directory
    optimize_level: Option<u8>, // Optimization level for ksl_optimizer.rs (0-3)
}

// Configuration manager
pub struct ConfigManager {
    config_path: PathBuf,
    config: Config,
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
                aws_region: None,
                aws_bucket: None,
                prometheus_port: None,
                docserver_port: None,
                output_dir: None,
                optimize_level: Some(1), // Default to basic optimization
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
}
