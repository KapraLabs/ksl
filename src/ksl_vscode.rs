// ksl_vscode.rs
// Generates VS Code extension configuration for KSL, providing syntax highlighting,
// snippets, and integration with linting and formatting tools.

use crate::ksl_errors::{KslError, SourcePosition};
use serde_json::json;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

// VS Code configuration generator
pub struct VSCodeConfig {
    output_dir: PathBuf, // Output directory (e.g., .vscode/)
}

impl VSCodeConfig {
    pub fn new(output_dir: PathBuf) -> Self {
        VSCodeConfig { output_dir }
    }

    // Generate VS Code configuration files
    pub fn generate(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        // Create output directory
        fs::create_dir_all(&self.output_dir)
            .map_err(|e| KslError::type_error(
                format!("Failed to create output directory {}: {}", self.output_dir.display(), e),
                pos,
            ))?;

        // Generate language-configuration.json
        self.generate_language_config()?;

        // Generate snippets.json
        self.generate_snippets()?;

        // Generate settings.json
        self.generate_settings()?;

        Ok(())
    }

    // Generate language-configuration.json for syntax highlighting
    fn generate_language_config(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let config = json!({
            "comments": {
                "lineComment": "//",
                "blockComment": ["/*", "*/"]
            },
            "brackets": [
                ["{", "}"],
                ["(", ")"]
            ],
            "autoClosingPairs": [
                ["{", "}"],
                ["(", ")"],
                ["\"", "\""]
            ],
            "surroundingPairs": [
                ["{", "}"],
                ["(", ")"],
                ["\"", "\""]
            ],
            "wordPattern": "[a-zA-Z_][a-zA-Z0-9_]*(?![a-zA-Z0-9_])",
            "indentationRules": {
                "increaseIndentPattern": "^.*\\{[^}\"']*$|^.*\\([^)\"']*$",
                "decreaseIndentPattern": "^\\s*[}\\)]"
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

    // Generate snippets.json for common KSL patterns
    fn generate_snippets(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let snippets = json!({
            "Blockchain Contract": {
                "prefix": "ksl-blockchain",
                "body": [
                    "/// A simple smart contract for blockchain",
                    "#[verify]",
                    "fn process_transaction(msg: array<u8, 32>, pubkey: array<u8, 48>, sig: array<u8, 96>): bool {",
                    "    bls_verify(msg, pubkey, sig)",
                    "}",
                    "",
                    "fn main() {",
                    "    let msg: array<u8, 32> = \"${1:transaction_data}\";",
                    "    let pubkey: array<u8, 48> = \"${2:public_key_data}\";",
                    "    let sig: array<u8, 96> = \"${3:signature_data}\";",
                    "    let valid: bool = process_transaction(msg, pubkey, sig);",
                    "    valid",
                    "}"
                ],
                "description": "A blockchain smart contract template"
            },
            "AI Matrix Operation": {
                "prefix": "ksl-ai-matrix",
                "body": [
                    "/// Matrix multiplication for AI inference",
                    "fn matrix_multiply(a: array<array<f64, ${1:4}>, ${1:4}>, b: array<array<f64, ${1:4}>, ${1:4}>): array<array<f64, ${1:4}>, ${1:4}> {",
                    "    matrix.mul(a, b)",
                    "}",
                    "",
                    "fn main() {",
                    "    let a: array<array<f64, ${1:4}>, ${1:4}> = [[${2:1.0}, ${3:2.0}, ${4:3.0}, ${5:4.0}]; ${1:4}];",
                    "    let b: array<array<f64, ${1:4}>, ${1:4}> = [[${6:5.0}, ${7:6.0}, ${8:7.0}, ${9:8.0}]; ${1:4}];",
                    "    let result: array<array<f64, ${1:4}>, ${1:4}> = matrix_multiply(a, b);",
                    "    result",
                    "}"
                ],
                "description": "An AI matrix multiplication template"
            },
            "Game Physics": {
                "prefix": "ksl-game-physics",
                "body": [
                    "/// Calculate projectile trajectory",
                    "fn calculate_trajectory(angle: f64, velocity: f64): f64 {",
                    "    math.sin(angle) * velocity",
                    "}",
                    "",
                    "fn main() {",
                    "    let angle: f64 = ${1:45.0};",
                    "    let velocity: f64 = ${2:100.0};",
                    "    let distance: f64 = calculate_trajectory(angle, velocity);",
                    "    distance",
                    "}"
                ],
                "description": "A game physics calculation template"
            },
            "IoT Sensor": {
                "prefix": "ksl-iot-sensor",
                "body": [
                    "/// Process IoT sensor data",
                    "#[allow(sensor)]",
                    "fn process_sensor(sensor_id: u32): f32 {",
                    "    device.sensor(sensor_id)",
                    "}",
                    "",
                    "fn main() {",
                    "    let sensor_id: u32 = ${1:1};",
                    "    let reading: f32 = process_sensor(sensor_id);",
                    "    reading",
                    "}"
                ],
                "description": "An IoT sensor processing template"
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

    // Generate settings.json for linting and formatting integration
    fn generate_settings(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let settings = json!({
            "editor.formatOnSave": true,
            "editor.formatOnPaste": false,
            "[ksl]": {
                "editor.defaultFormatter": "ksl_formatter",
                "editor.codeActionsOnSave": {
                    "source.fixAll.ksl_linter": true
                }
            },
            "ksl.linter.executablePath": "ksl_linter",
            "ksl.formatter.executablePath": "ksl_formatter"
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
}

// Public API to generate VS Code configuration
pub fn generate_vscode_config(output_dir: PathBuf) -> Result<(), KslError> {
    let config = VSCodeConfig::new(output_dir);
    config.generate()
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

        let result = generate_vscode_config(output_dir.clone());
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
        let result = generate_vscode_config(output_dir.clone());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to create output directory"));
    }
}
