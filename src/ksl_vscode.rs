// ksl_vscode.rs
// Generates VS Code extension configuration for KSL, providing syntax highlighting,
// snippets, and integration with linting and formatting tools.
// Also supports Language Server Protocol (LSP) features, async command execution,
// and CLI tooling integration.

use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_lsp::{LspServer, LspConfig};
use crate::ksl_async::{AsyncCommand, AsyncContext};
use crate::ksl_cli::{CliTool, CliConfig};
use serde_json::json;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Configuration for VS Code extension
#[derive(Debug)]
pub struct VSCodeConfig {
    /// Output directory (e.g., .vscode/)
    output_dir: PathBuf,
    /// LSP server configuration
    lsp_config: LspConfig,
    /// CLI tool configuration
    cli_config: CliConfig,
    /// Async context for command execution
    async_context: Arc<Mutex<AsyncContext>>,
}

impl VSCodeConfig {
    /// Creates a new VS Code configuration generator
    pub fn new(output_dir: PathBuf, lsp_config: LspConfig, cli_config: CliConfig) -> Self {
        VSCodeConfig {
            output_dir,
            lsp_config,
            cli_config,
            async_context: Arc::new(Mutex::new(AsyncContext::new())),
        }
    }

    /// Generates VS Code configuration files
    pub async fn generate(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        // Create output directory
        fs::create_dir_all(&self.output_dir)
            .map_err(|e| KslError::type_error(
                format!("Failed to create output directory {}: {}", self.output_dir.display(), e),
                pos,
            ))?;

        // Initialize LSP server
        let lsp_server = LspServer::new(self.lsp_config.clone());
        lsp_server.initialize().await?;

        // Initialize CLI tools
        let cli_tool = CliTool::new(self.cli_config.clone());
        cli_tool.initialize().await?;

        // Generate language-configuration.json
        self.generate_language_config()?;

        // Generate snippets.json
        self.generate_snippets()?;

        // Generate settings.json
        self.generate_settings()?;

        // Generate launch.json for debugging
        self.generate_launch_config()?;

        // Generate tasks.json for build tasks
        self.generate_tasks_config()?;

        Ok(())
    }

    /// Generates language-configuration.json for syntax highlighting
    fn generate_language_config(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let config = json!({
            "comments": {
                "lineComment": "//",
                "blockComment": ["/*", "*/"]
            },
            "brackets": [
                ["{", "}"],
                ["(", ")"],
                ["[", "]"]
            ],
            "autoClosingPairs": [
                ["{", "}"],
                ["(", ")"],
                ["[", "]"],
                ["\"", "\""],
                ["'", "'"]
            ],
            "surroundingPairs": [
                ["{", "}"],
                ["(", ")"],
                ["[", "]"],
                ["\"", "\""],
                ["'", "'"]
            ],
            "wordPattern": "[a-zA-Z_][a-zA-Z0-9_]*(?![a-zA-Z0-9_])",
            "indentationRules": {
                "increaseIndentPattern": "^.*\\{[^}\"']*$|^.*\\([^)\"']*$|^.*\\[[^]\"']*$",
                "decreaseIndentPattern": "^\\s*[}\\)\\]]"
            },
            "folding": {
                "markers": {
                    "start": "^\\s*//\\s*#region\\b",
                    "end": "^\\s*//\\s*#endregion\\b"
                }
            }
        });

        let output_path = self.output_dir.join("language-configuration.json");
        File::create(&output_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to create language config file {}: {}", output_path.display(), e),
                pos,
            ))?
            .write_all(serde_json::to_string_pretty(&config)?.as_bytes())
            .map_err(|e| KslError::type_error(
                format!("Failed to write language config file {}: {}", output_path.display(), e),
                pos,
            ))?;

        Ok(())
    }

    /// Generates snippets.json for common KSL patterns
    fn generate_snippets(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let snippets = json!({
            "Blockchain Contract": {
                "prefix": "ksl-blockchain",
                "body": [
                    "/// A simple smart contract for blockchain",
                    "#[verify]",
                    "async fn process_transaction(msg: array<u8, 32>, pubkey: array<u8, 48>, sig: array<u8, 96>): result<bool, string> {",
                    "    bls_verify(msg, pubkey, sig).await",
                    "}",
                    "",
                    "async fn main() {",
                    "    let msg: array<u8, 32> = \"${1:transaction_data}\";",
                    "    let pubkey: array<u8, 48> = \"${2:public_key_data}\";",
                    "    let sig: array<u8, 96> = \"${3:signature_data}\";",
                    "    let valid: result<bool, string> = process_transaction(msg, pubkey, sig).await;",
                    "    valid",
                    "}"
                ],
                "description": "A blockchain smart contract template with async support"
            },
            "AI Matrix Operation": {
                "prefix": "ksl-ai-matrix",
                "body": [
                    "/// Matrix multiplication for AI inference",
                    "async fn matrix_multiply(a: array<array<f64, ${1:4}>, ${1:4}>, b: array<array<f64, ${1:4}>, ${1:4}>): result<array<array<f64, ${1:4}>, ${1:4}>, string> {",
                    "    matrix.mul(a, b).await",
                    "}",
                    "",
                    "async fn main() {",
                    "    let a: array<array<f64, ${1:4}>, ${1:4}> = [[${2:1.0}, ${3:2.0}, ${4:3.0}, ${5:4.0}]; ${1:4}];",
                    "    let b: array<array<f64, ${1:4}>, ${1:4}> = [[${6:5.0}, ${7:6.0}, ${8:7.0}, ${9:8.0}]; ${1:4}];",
                    "    let result: result<array<array<f64, ${1:4}>, ${1:4}>, string> = matrix_multiply(a, b).await;",
                    "    result",
                    "}"
                ],
                "description": "An AI matrix multiplication template with async support"
            },
            "Game Physics": {
                "prefix": "ksl-game-physics",
                "body": [
                    "/// Calculate projectile trajectory",
                    "async fn calculate_trajectory(angle: f64, velocity: f64): result<f64, string> {",
                    "    math.sin(angle) * velocity",
                    "}",
                    "",
                    "async fn main() {",
                    "    let angle: f64 = ${1:45.0};",
                    "    let velocity: f64 = ${2:100.0};",
                    "    let distance: result<f64, string> = calculate_trajectory(angle, velocity).await;",
                    "    distance",
                    "}"
                ],
                "description": "A game physics calculation template with async support"
            },
            "IoT Sensor": {
                "prefix": "ksl-iot-sensor",
                "body": [
                    "/// Process IoT sensor data",
                    "#[allow(sensor)]",
                    "async fn process_sensor(sensor_id: u32): result<f32, string> {",
                    "    device.sensor(sensor_id).await",
                    "}",
                    "",
                    "async fn main() {",
                    "    let sensor_id: u32 = ${1:1};",
                    "    let reading: result<f32, string> = process_sensor(sensor_id).await;",
                    "    reading",
                    "}"
                ],
                "description": "An IoT sensor processing template with async support"
            }
        });

        let output_path = self.output_dir.join("snippets.json");
        File::create(&output_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to create snippets file {}: {}", output_path.display(), e),
                pos,
            ))?
            .write_all(serde_json::to_string_pretty(&snippets)?.as_bytes())
            .map_err(|e| KslError::type_error(
                format!("Failed to write snippets file {}: {}", output_path.display(), e),
                pos,
            ))?;

        Ok(())
    }

    /// Generates settings.json for linting and formatting integration
    fn generate_settings(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let settings = json!({
            "editor.formatOnSave": true,
            "editor.formatOnPaste": false,
            "[ksl]": {
                "editor.defaultFormatter": "ksl_formatter",
                "editor.codeActionsOnSave": {
                    "source.fixAll.ksl_linter": true
                },
                "editor.semanticHighlighting.enabled": true,
                "editor.suggest.showSnippets": true,
                "editor.suggest.showKeywords": true,
                "editor.suggest.showMethods": true,
                "editor.suggest.showFunctions": true,
                "editor.suggest.showVariables": true,
                "editor.suggest.showConstants": true
            },
            "ksl.lsp.enabled": true,
            "ksl.lsp.trace.server": "verbose",
            "ksl.lsp.serverPath": "ksl_lsp",
            "ksl.linter.executablePath": "ksl_linter",
            "ksl.formatter.executablePath": "ksl_formatter",
            "ksl.cli.executablePath": "ksl_cli",
            "ksl.debugger.enabled": true,
            "ksl.debugger.executablePath": "ksl_debugger"
        });

        let output_path = self.output_dir.join("settings.json");
        File::create(&output_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to create settings file {}: {}", output_path.display(), e),
                pos,
            ))?
            .write_all(serde_json::to_string_pretty(&settings)?.as_bytes())
            .map_err(|e| KslError::type_error(
                format!("Failed to write settings file {}: {}", output_path.display(), e),
                pos,
            ))?;

        Ok(())
    }

    /// Generates launch.json for debugging configuration
    fn generate_launch_config(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let launch_config = json!({
            "version": "0.2.0",
            "configurations": [
                {
                    "type": "ksl",
                    "request": "launch",
                    "name": "Debug KSL Program",
                    "program": "${workspaceFolder}/${relativeFile}",
                    "args": [],
                    "cwd": "${workspaceFolder}",
                    "env": {},
                    "stopOnEntry": false,
                    "console": "integratedTerminal"
                }
            ]
        });

        let output_path = self.output_dir.join("launch.json");
        File::create(&output_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to create launch config file {}: {}", output_path.display(), e),
                pos,
            ))?
            .write_all(serde_json::to_string_pretty(&launch_config)?.as_bytes())
            .map_err(|e| KslError::type_error(
                format!("Failed to write launch config file {}: {}", output_path.display(), e),
                pos,
            ))?;

        Ok(())
    }

    /// Generates tasks.json for build tasks
    fn generate_tasks_config(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let tasks_config = json!({
            "version": "2.0.0",
            "tasks": [
                {
                    "label": "Build KSL Program",
                    "type": "shell",
                    "command": "ksl_cli build",
                    "args": ["${file}"],
                    "group": {
                        "kind": "build",
                        "isDefault": true
                    },
                    "presentation": {
                        "reveal": "always",
                        "panel": "shared"
                    },
                    "problemMatcher": ["$ksl"]
                },
                {
                    "label": "Run KSL Program",
                    "type": "shell",
                    "command": "ksl_cli run",
                    "args": ["${file}"],
                    "group": {
                        "kind": "test",
                        "isDefault": true
                    },
                    "presentation": {
                        "reveal": "always",
                        "panel": "shared"
                    }
                }
            ]
        });

        let output_path = self.output_dir.join("tasks.json");
        File::create(&output_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to create tasks config file {}: {}", output_path.display(), e),
                pos,
            ))?
            .write_all(serde_json::to_string_pretty(&tasks_config)?.as_bytes())
            .map_err(|e| KslError::type_error(
                format!("Failed to write tasks config file {}: {}", output_path.display(), e),
                pos,
            ))?;

        Ok(())
    }
}

/// Public API to generate VS Code configuration
pub async fn generate_vscode_config(
    output_dir: PathBuf,
    lsp_config: LspConfig,
    cli_config: CliConfig,
) -> Result<(), KslError> {
    let config = VSCodeConfig::new(output_dir, lsp_config, cli_config);
    config.generate().await
}

// Assume ksl_errors.rs is in the same crate
mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;

    #[test]
    fn test_generate_vscode_config() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().join(".vscode");

        let result = generate_vscode_config(output_dir.clone(), LspConfig::default(), CliConfig::default());
        assert!(result.is_ok());

        // Check language-configuration.json
        let lang_config_path = output_dir.join("language-configuration.json");
        let content = fs::read_to_string(&lang_config_path).unwrap();
        assert!(content.contains("\"lineComment\": \"//\""));
        assert!(content.contains("\"blockComment\": [\"/*\", \"*/\"]"));

        // Check snippets.json
        let snippets_path = output_dir.join("snippets.json");
        let content = fs::read_to_string(&snippets_path).unwrap();
        assert!(content.contains("\"prefix\": \"ksl-blockchain\""));
        assert!(content.contains("\"prefix\": \"ksl-iot-sensor\""));

        // Check settings.json
        let settings_path = output_dir.join("settings.json");
        let content = fs::read_to_string(&settings_path).unwrap();
        assert!(content.contains("\"editor.formatOnSave\": true"));
        assert!(content.contains("\"ksl.linter.executablePath\": \"ksl_linter\""));
    }

    #[test]
    fn test_generate_vscode_config_invalid_dir() {
        let output_dir = PathBuf::from("/invalid/path/.vscode");
        let result = generate_vscode_config(output_dir.clone(), LspConfig::default(), CliConfig::default());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to create output directory"));
    }
}
