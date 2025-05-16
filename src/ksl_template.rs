// ksl_template.rs
// Generates boilerplate KSL code for rapid project setup, supporting predefined
// templates for blockchain, AI, gaming, IoT, and custom templates via .ksltemplate.

use crate::ksl_parser::{parse, ParseError};
use crate::ksl_doc::{generate, StdLibFunctionTrait};
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_project::{ProjectConfig, ProjectInitializer};
use crate::ksl_async::{AsyncContext, AsyncCommand};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use dirs::home_dir;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use serde_json::Value as JsonValue;

/// Template configuration for custom templates with async support.
#[derive(Debug, Deserialize, Serialize)]
pub struct TemplateConfig {
    name: String,
    description: String,
    code: String,
    async_support: bool,
    project_config: Option<ProjectConfig>,
}

/// Template registry with async support and project integration.
pub struct TemplateRegistry {
    templates: HashMap<String, TemplateConfig>,
    custom_dir: PathBuf, // ~/.ksl/templates
    async_context: Arc<Mutex<AsyncContext>>,
    project_initializer: Arc<Mutex<ProjectInitializer>>,
}

impl TemplateRegistry {
    /// Creates a new template registry with async support and project integration.
    pub fn new() -> Self {
        let custom_dir = home_dir().unwrap_or_default().join(".ksl/templates");
        let mut registry = TemplateRegistry {
            templates: HashMap::new(),
            custom_dir,
            async_context: Arc::new(Mutex::new(AsyncContext::new())),
            project_initializer: Arc::new(Mutex::new(ProjectInitializer::new())),
        };
        registry.load_predefined_templates();
        registry.load_custom_templates();
        registry
    }

    /// Load predefined templates for blockchain, AI, gaming, IoT with async support.
    fn load_predefined_templates(&mut self) {
        self.templates.insert(
            "blockchain".to_string(),
            TemplateConfig {
                name: "blockchain".to_string(),
                description: "Template for a blockchain smart contract with async support".to_string(),
                code: r#"
/// A smart contract with async transaction processing
#[verify]
async fn process_transaction(msg: array<u8, 32>, pubkey: array<u8, 48>, sig: array<u8, 96>): bool {
    let valid = await bls_verify(msg, pubkey, sig);
    if valid {
        let result = await process_async(msg);
        result
    } else {
        false
    }
}

async fn process_async(msg: array<u8, 32>): bool {
    // Async processing logic
    true
}

fn main() {
    let msg: array<u8, 32> = "transaction_data";
    let pubkey: array<u8, 48> = "public_key_data";
    let sig: array<u8, 96> = "signature_data";
    let valid: bool = await process_transaction(msg, pubkey, sig);
    valid
}
"#.to_string(),
                async_support: true,
                project_config: Some(ProjectConfig {
                    name: "blockchain".to_string(),
                    template: "blockchain".to_string(),
                    version: "0.1.0".to_string(),
                    license: License::MIT,
                }),
            },
        );
        self.templates.insert(
            "ai".to_string(),
            TemplateConfig {
                name: "ai".to_string(),
                description: "Template for AI matrix operations with async support".to_string(),
                code: r#"
/// Matrix multiplication for AI inference with async support
async fn matrix_multiply(a: array<array<f64, 4>, 4>, b: array<array<f64, 4>, 4>): array<array<f64, 4>, 4> {
    let result = await matrix.mul_async(a, b);
    result
}

async fn process_batch(batch: array<array<array<f64, 4>, 4>, 10>): array<array<array<f64, 4>, 4>, 10> {
    let mut results: array<array<array<f64, 4>, 4>, 10> = [[[0.0; 4]; 4]; 10];
    for i in 0..10 {
        results[i] = await matrix_multiply(batch[i], batch[i]);
    }
    results
}

fn main() {
    let a: array<array<f64, 4>, 4> = [[1.0, 2.0, 3.0, 4.0]; 4];
    let b: array<array<f64, 4>, 4> = [[5.0, 6.0, 7.0, 8.0]; 4];
    let result: array<array<f64, 4>, 4> = await matrix_multiply(a, b);
    result
}
"#.to_string(),
                async_support: true,
                project_config: Some(ProjectConfig {
                    name: "ai".to_string(),
                    template: "ai".to_string(),
                    version: "0.1.0".to_string(),
                    license: License::Apache2,
                }),
            },
        );
        self.templates.insert(
            "gaming".to_string(),
            TemplateConfig {
                name: "gaming".to_string(),
                description: "Template for game physics with async support".to_string(),
                code: r#"
/// Calculate projectile trajectory with async physics simulation
async fn calculate_trajectory(angle: f64, velocity: f64): f64 {
    let distance = await physics.simulate(angle, velocity);
    distance
}

async fn update_game_state(state: GameState): GameState {
    let new_state = await physics.update(state);
    new_state
}

struct GameState {
    position: array<f64, 3>,
    velocity: array<f64, 3>,
    rotation: array<f64, 4>,
}

fn main() {
    let angle: f64 = 45.0;
    let velocity: f64 = 100.0;
    let distance: f64 = await calculate_trajectory(angle, velocity);
    distance
}
"#.to_string(),
                async_support: true,
                project_config: Some(ProjectConfig {
                    name: "gaming".to_string(),
                    template: "gaming".to_string(),
                    version: "0.1.0".to_string(),
                    license: License::BSD3,
                }),
            },
        );
        self.templates.insert(
            "iot".to_string(),
            TemplateConfig {
                name: "iot".to_string(),
                description: "Template for IoT sensor processing with async support".to_string(),
                code: r#"
/// Process IoT sensor data with async support
#[allow(sensor)]
async fn process_sensor(sensor_id: u32): f32 {
    let reading = await device.sensor_async(sensor_id);
    reading
}

async fn process_sensor_batch(sensors: array<u32, 10>): array<f32, 10> {
    let mut readings: array<f32, 10> = [0.0; 10];
    for i in 0..10 {
        readings[i] = await process_sensor(sensors[i]);
    }
    readings
}

fn main() {
    let sensor_id: u32 = 1;
    let reading: f32 = await process_sensor(sensor_id);
    reading
}
"#.to_string(),
                async_support: true,
                project_config: Some(ProjectConfig {
                    name: "iot".to_string(),
                    template: "iot".to_string(),
                    version: "0.1.0".to_string(),
                    license: License::MIT,
                }),
            },
        );
    }

    /// Load custom templates from ~/.ksl/templates with async support.
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
                                async_support: true,
                                project_config: None,
                            };
                            self.templates.insert(config.name.clone(), config);
                        }
                    }
                }
            }
        }
    }

    /// Generate code from a template asynchronously.
    pub async fn generate(&self, template_name: &str, output: Option<&PathBuf>) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let template = self.templates.get(template_name)
            .ok_or_else(|| KslError::type_error(
                format!("Template {} not found", template_name),
                pos,
                "E301".to_string(),
            ))?;

        // Validate syntax
        parse(&template.code)
            .map_err(|e| KslError::type_error(
                format!("Invalid template {}: {}", template_name, e.message),
                SourcePosition::new(e.position, e.position),
                "E302".to_string(),
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
                    "E303".to_string(),
                ))?;
            generate(Some(&temp_file), false, Some(doc_path.parent().unwrap_or_else(|| Path::new("."))))
                .map_err(|e| KslError::type_error(
                    format!("Documentation generation failed: {}", e),
                    pos,
                    "E304".to_string(),
                ))?;
            fs::remove_file(&temp_file)
                .map_err(|e| KslError::type_error(
                    format!("Failed to clean up temporary file {}: {}", temp_file.display(), e),
                    pos,
                    "E305".to_string(),
                ))?;
        }

        // Output code
        if let Some(output_path) = output {
            fs::write(output_path, &formatted_code)
                .map_err(|e| KslError::type_error(
                    format!("Failed to write output {}: {}", output_path.display(), e),
                    pos,
                    "E306".to_string(),
                ))?;
        } else {
            println!("{}", formatted_code);
        }

        // Initialize project if template has project config
        if let Some(project_config) = &template.project_config {
            let mut initializer = self.project_initializer.lock().await;
            initializer.init(&project_config.name, &project_config.template).await?;
        }

        // Execute async template tasks
        if template.async_support {
            let mut async_ctx = self.async_context.lock().await;
            let command = AsyncCommand::TemplateRender(template_name.to_string());
            async_ctx.execute_command(command).await?;
        }

        Ok(())
    }

    /// List available templates with async support.
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
