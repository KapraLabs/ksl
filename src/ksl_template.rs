// ksl_template.rs
// Generates boilerplate KSL code for rapid project setup, supporting predefined
// templates for blockchain, AI, gaming, IoT, and custom templates via .ksltemplate.

use crate::ksl_parser::{parse, ParseError};
use crate::ksl_doc::{generate, StdLibFunctionTrait};
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use dirs::home_dir;
use serde::{Deserialize, Serialize};

// Template configuration for custom templates
#[derive(Debug, Deserialize, Serialize)]
pub struct TemplateConfig {
    name: String,
    description: String,
    code: String,
}

// Template registry
pub struct TemplateRegistry {
    templates: HashMap<String, TemplateConfig>,
    custom_dir: PathBuf, // ~/.ksl/templates
}

impl TemplateRegistry {
    pub fn new() -> Self {
        let custom_dir = home_dir().unwrap_or_default().join(".ksl/templates");
        let mut registry = TemplateRegistry {
            templates: HashMap::new(),
            custom_dir,
        };
        registry.load_predefined_templates();
        registry.load_custom_templates();
        registry
    }

    // Load predefined templates for blockchain, AI, gaming, IoT
    fn load_predefined_templates(&mut self) {
        self.templates.insert(
            "blockchain".to_string(),
            TemplateConfig {
                name: "blockchain".to_string(),
                description: "Template for a blockchain smart contract".to_string(),
                code: r#"
/// A simple smart contract for blockchain
#[verify]
fn process_transaction(msg: array<u8, 32>, pubkey: array<u8, 48>, sig: array<u8, 96>): bool {
    bls_verify(msg, pubkey, sig)
}

fn main() {
    let msg: array<u8, 32> = "transaction_data";
    let pubkey: array<u8, 48> = "public_key_data";
    let sig: array<u8, 96> = "signature_data";
    let valid: bool = process_transaction(msg, pubkey, sig);
    valid
}
"#.to_string(),
            },
        );
        self.templates.insert(
            "ai".to_string(),
            TemplateConfig {
                name: "ai".to_string(),
                description: "Template for AI matrix operations".to_string(),
                code: r#"
/// Matrix multiplication for AI inference
fn matrix_multiply(a: array<array<f64, 4>, 4>, b: array<array<f64, 4>, 4>): array<array<f64, 4>, 4> {
    matrix.mul(a, b)
}

fn main() {
    let a: array<array<f64, 4>, 4> = [[1.0, 2.0, 3.0, 4.0]; 4];
    let b: array<array<f64, 4>, 4> = [[5.0, 6.0, 7.0, 8.0]; 4];
    let result: array<array<f64, 4>, 4> = matrix_multiply(a, b);
    result
}
"#.to_string(),
            },
        );
        self.templates.insert(
            "gaming".to_string(),
            TemplateConfig {
                name: "gaming".to_string(),
                description: "Template for game physics".to_string(),
                code: r#"
/// Calculate projectile trajectory
fn calculate_trajectory(angle: f64, velocity: f64): f64 {
    math.sin(angle) * velocity
}

fn main() {
    let angle: f64 = 45.0;
    let velocity: f64 = 100.0;
    let distance: f64 = calculate_trajectory(angle, velocity);
    distance
}
"#.to_string(),
            },
        );
        self.templates.insert(
            "iot".to_string(),
            TemplateConfig {
                name: "iot".to_string(),
                description: "Template for IoT sensor processing".to_string(),
                code: r#"
/// Process IoT sensor data
#[allow(sensor)]
fn process_sensor(sensor_id: u32): f32 {
    device.sensor(sensor_id)
}

fn main() {
    let sensor_id: u32 = 1;
    let reading: f32 = process_sensor(sensor_id);
    reading
}
"#.to_string(),
            },
        );
    }

    // Load custom templates from ~/.ksl/templates
    fn load_custom_templates(&mut self) {
        if !self.custom_dir.exists() {
            return;
        }
        if let Ok(entries) = fs::read_dir(&self.custom_dir) {
            for entry in entries.filter_map(Result::ok) {
                if entry.path().extension().map(|ext| ext == "ksltemplate").unwrap_or(false) {
                    if let Ok(mut file) = File::open(entry.path()) {
                        let mut contents = String::new();
                        if file.read_to_string(&mut contents).is_ok() {
                            let config = TemplateConfig {
                                name: entry.path().file_stem().unwrap().to_string_lossy().into_owned(),
                                description: format!("Custom template {}", entry.path().display()),
                                code: contents,
                            };
                            self.templates.insert(config.name.clone(), config);
                        }
                    }
                }
            }
        }
    }

    // Generate code from a template
    pub fn generate(&self, template_name: &str, output: Option<&PathBuf>) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let template = self.templates.get(template_name)
            .ok_or_else(|| KslError::type_error(
                format!("Template {} not found", template_name),
                pos,
            ))?;

        // Validate syntax
        parse(&template.code)
            .map_err(|e| KslError::type_error(
                format!("Invalid template {}: {}", template_name, e.message),
                SourcePosition::new(e.position, e.position),
            ))?;

        // Format code (simulate ksl_formatter.rs)
        let formatted_code = format_code(&template.code)?;

        // Generate documentation
        let doc_path = output.map(|p| p.with_extension("md"));
        if let Some(doc_path) = &doc_path {
            let temp_file = output.unwrap().with_extension("ksl");
            fs::write(&temp_file, &formatted_code)
                .map_err(|e| KslError::type_error(
                    format!("Failed to write temporary file {}: {}", temp_file.display(), e),
                    pos,
                ))?;
            generate(Some(&temp_file), false, Some(doc_path.parent().unwrap_or_else(|| Path::new("."))))
                .map_err(|e| KslError::type_error(
                    format!("Documentation generation failed: {}", e),
                    pos,
                ))?;
            fs::remove_file(&temp_file)
                .map_err(|e| KslError::type_error(
                    format!("Failed to clean up temporary file {}: {}", temp_file.display(), e),
                    pos,
                ))?;
        }

        // Output code
        if let Some(output_path) = output {
            fs::write(output_path, &formatted_code)
                .map_err(|e| KslError::type_error(
                    format!("Failed to write output {}: {}", output_path.display(), e),
                    pos,
                ))?;
        } else {
            println!("{}", formatted_code);
        }

        Ok(())
    }

    // List available templates
    pub fn list_templates(&self) -> Vec<&TemplateConfig> {
        self.templates.values().collect()
    }
}

// Simulate ksl_formatter.rs
fn format_code(code: &str) -> Result<String, KslError> {
    // Simplified: Add basic indentation
    let mut formatted = String::new();
    let mut indent = 0;
    for line in code.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.ends_with('}') {
            indent = indent.saturating_sub(1);
        }
        formatted.push_str(&"    ".repeat(indent));
        formatted.push_str(trimmed);
        formatted.push('\n');
        if trimmed.ends_with('{') {
            indent += 1;
        }
    }
    Ok(formatted)
}

// Public API to generate a template
pub fn generate_template(template_name: &str, output: Option<&PathBuf>) -> Result<(), KslError> {
    let registry = TemplateRegistry::new();
    registry.generate(template_name, output)
}

// Assume ksl_parser.rs, ksl_doc.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, ParseError};
}

mod ksl_doc {
    pub use super::{generate, StdLibFunctionTrait};
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
    fn test_generate_blockchain_template() {
        let temp_dir = TempDir::new().unwrap();
        let output_file = temp_dir.path().join("contract.ksl");

        let result = generate_template("blockchain", Some(&output_file));
        assert!(result.is_ok());
        assert!(output_file.exists());
        let content = fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("fn process_transaction"));
        assert!(content.contains("bls_verify"));
    }

    #[test]
    fn test_generate_iot_template() {
        let temp_dir = TempDir::new().unwrap();
        let output_file = temp_dir.path().join("iot.ksl");

        let result = generate_template("iot", Some(&output_file));
        assert!(result.is_ok());
        assert!(output_file.exists());
        let content = fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("#[allow(sensor)]"));
        assert!(content.contains("device.sensor"));
    }

    #[test]
    fn test_generate_custom_template() {
        let temp_dir = TempDir::new().unwrap();
        let custom_dir = temp_dir.path().join(".ksl/templates");
        fs::create_dir_all(&custom_dir).unwrap();
        let custom_template = custom_dir.join("custom.ksltemplate");
        let mut file = File::create(&custom_template).unwrap();
        writeln!(file, "fn main() {{ let x: u32 = 42; }}").unwrap();

        let output_file = temp_dir.path().join("custom.ksl");
        let mut registry = TemplateRegistry::new();
        registry.custom_dir = custom_dir;

        let result = registry.generate("custom", Some(&output_file));
        assert!(result.is_ok());
        assert!(output_file.exists());
        let content = fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("let x: u32 = 42"));
    }

    #[test]
    fn test_generate_invalid_template() {
        let result = generate_template("invalid", None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Template invalid not found"));
    }

    #[test]
    fn test_list_templates() {
        let registry = TemplateRegistry::new();
        let templates = registry.list_templates();
        assert!(templates.iter().any(|t| t.name == "blockchain"));
        assert!(templates.iter().any(|t| t.name == "ai"));
        assert!(templates.iter().any(|t| t.name == "gaming"));
        assert!(templates.iter().any(|t| t.name == "iot"));
    }
}
