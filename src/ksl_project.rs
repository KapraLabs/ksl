// ksl_project.rs
// Project initialization tool for KSL with templates and scaffolding

use crate::ksl_package::{PackageMetadata, Dependency};
use crate::ksl_config::{ProjectConfig, ConfigManager};
use crate::ksl_async::{AsyncContext, AsyncCommand};
use crate::ksl_errors::{KslError, ErrorType};
use crate::ksl_dep_audit::AuditIssue;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Represents a template for a KSL project (aligned with ksl_template.rs).
#[derive(Debug, Clone)]
pub struct Template {
    name: String,
    description: String,
    package_metadata: PackageMetadata,
    main_ksl: String,     // Content for src/main.ksl
}

impl Template {
    /// Creates a new template with package metadata and main file content.
    pub fn new(name: &str, description: &str, package_metadata: PackageMetadata, main_ksl: &str) -> Self {
        Template {
            name: name.to_string(),
            description: description.to_string(),
            package_metadata,
            main_ksl: main_ksl.to_string(),
        }
    }
}

/// Template registry (simulates ksl_template.rs).
#[derive(Debug, Clone)]
pub struct TemplateRegistry {
    templates: Vec<Template>,
}

impl TemplateRegistry {
    pub fn new() -> Self {
        let mut registry = TemplateRegistry { templates: vec![] };

        // Blockchain template
        registry.templates.push(Template::new(
            "blockchain",
            "A blockchain smart contract project",
            PackageMetadata {
                name: "{name}".to_string(),
                version: "0.1.0".to_string(),
                license: AuditIssue::License("MIT".to_string()),
                dependencies: vec![
                    Dependency::new("blockchain-lib", "^1.0.0"),
                ],
                description: "A blockchain smart contract project".to_string(),
                authors: vec![],
                repository: None,
                documentation: None,
            },
            r#"// src/main.ksl
macro! contract_boilerplate($contract_name: ident, $resource: ident) {
    #[contract]
    contract $contract_name {
        resource $resource { amount: u64 }

        fn transfer(token: $resource, recipient: array<u8, 32>) -> bool {
            true
        }
    }
}

fn main() {
    contract_boilerplate!(MyContract, Token);
    let msg: array<u8, 32] = sha3("blockroot.epoch.validator");
    let ok: bool = bls_verify(msg, [0; 48], [0; 96]);
    if ok == false {
        fail();
    }
}
"#,
        ));

        // AI template
        registry.templates.push(Template::new(
            "ai",
            "An AI model project",
            PackageMetadata {
                name: "{name}".to_string(),
                version: "0.1.0".to_string(),
                license: AuditIssue::License("Apache-2.0".to_string()),
                dependencies: vec![
                    Dependency::new("ai-model", "^2.0.0"),
                    Dependency::new("math-lib", "^1.0.0"),
                ],
                description: "An AI model project".to_string(),
                authors: vec![],
                repository: None,
                documentation: None,
            },
            r#"// src/main.ksl
macro! serialize_model($model_name: ident) {
    fn serialize_$model_name() -> array<u8, 1024> {
        let data: array<u8, 1024> = matrix.mul($model_name.weights, $model_name.biases);
        data
    }
}

struct Model {
    weights: array<u64, 4>,
    biases: array<u64, 4>,
}

fn main() {
    let m: Model = Model {
        weights: [1, 2, 3, 4],
        biases: [5, 6, 7, 8],
    };
    serialize_model!(m);
}
"#,
        ));

        // Game template
        registry.templates.push(Template::new(
            "game",
            "A game project with example logic",
            PackageMetadata {
                name: "{name}".to_string(),
                version: "0.1.0".to_string(),
                license: AuditIssue::License("BSD-3-Clause".to_string()),
                dependencies: vec![
                    Dependency::new("game-physics", "^1.0.0"),
                    Dependency::new("math-lib", "^1.0.0"),
                ],
                description: "A game project with example logic".to_string(),
                authors: vec![],
                repository: None,
                documentation: None,
            },
            r#"// src/main.ksl
macro! log($msg: string) {
    let formatted: string = concat("LOG: ", $msg);
    print(formatted);
}

fn game_loop() {
    let frames: u32 = 1000;
    let mut i: u32 = 0;
    while i < frames {
        log!("Frame ");
        let x: u32 = i + 1;
        i = x;
    }
}

fn main() {
    log!("Starting game...");
    game_loop();
}
"#,
        ));

        registry
    }

    pub fn get_template(&self, name: &str) -> Option<&Template> {
        self.templates.iter().find(|t| t.name == name)
    }
}

/// Project initializer for KSL with async support.
pub struct ProjectInitializer {
    templates: TemplateRegistry,
    config_manager: Arc<Mutex<ConfigManager>>,
    async_context: Arc<Mutex<AsyncContext>>,
}

impl ProjectInitializer {
    /// Creates a new project initializer with async support.
    pub fn new() -> Self {
        ProjectInitializer {
            templates: TemplateRegistry::new(),
            config_manager: Arc::new(Mutex::new(ConfigManager::new())),
            async_context: Arc::new(Mutex::new(AsyncContext::new())),
        }
    }

    /// Initialize a new KSL project asynchronously.
    pub async fn init(&self, name: &str, template_name: &str) -> Result<(), KslError> {
        // Validate project name
        if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(KslError::new(ErrorType::ValidationError, "Project name must be non-empty and contain only alphanumeric characters, '-', or '_'".to_string()));
        }

        // Check if the project directory already exists
        let project_dir = Path::new(name);
        if project_dir.exists() {
            return Err(KslError::new(ErrorType::FileError, format!("Directory '{}' already exists", name)));
        }

        // Find the template
        let template = self.templates.get_template(template_name)
            .ok_or_else(|| KslError::new(ErrorType::TemplateError, format!("Template '{}' not found", template_name)))?;

        // Create the project directory
        fs::create_dir(project_dir)
            .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to create project directory: {}", e)))?;

        // Create the src directory
        let src_dir = project_dir.join("src");
        fs::create_dir(&src_dir)
            .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to create src directory: {}", e)))?;

        // Initialize project configuration
        let mut config = self.config_manager.lock().await;
        let project_config = ProjectConfig {
            name: name.to_string(),
            template: template_name.to_string(),
            version: template.package_metadata.version.clone(),
            license: match template.package_metadata.license {
                AuditIssue::License(s) => s,
                _ => "Unknown".to_string(),
            },
        };
        config.save_project_config(&project_config)
            .await
            .map_err(|e| KslError::new(ErrorType::ConfigError, e.to_string()))?;

        // Write package metadata
        let mut package_metadata = template.package_metadata.clone();
        package_metadata.name = name.to_string();
        let package_toml_path = project_dir.join("ksl_package.toml");
        let mut package_toml_file = File::create(&package_toml_path)
            .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to create ksl_package.toml: {}", e)))?;
        package_toml_file.write_all(package_metadata.to_toml().as_bytes())
            .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to write ksl_package.toml: {}", e)))?;

        // Write src/main.ksl
        let main_ksl_path = src_dir.join("main.ksl");
        let mut main_ksl_file = File::create(&main_ksl_path)
            .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to create src/main.ksl: {}", e)))?;
        main_ksl_file.write_all(template.main_ksl.as_bytes())
            .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to write src/main.ksl: {}", e)))?;

        // Execute async initialization tasks
        let mut async_ctx = self.async_context.lock().await;
        let command = AsyncCommand::ProjectInit(project_config);
        async_ctx.execute_command(command)
            .await
            .map_err(|e| KslError::new(ErrorType::AsyncError, e.to_string()))?;

        Ok(())
    }
}

/// CLI integration for `ksl project init <name> --template <type>` (used by ksl_cli.rs).
pub async fn run_project_init(name: &str, template: &str) -> Result<String, KslError> {
    let initializer = ProjectInitializer::new();
    initializer.init(name, template).await?;
    Ok(format!(
        "Project '{}' initialized successfully with template '{}'.",
        name, template
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn test_project_init_blockchain() {
        let project_name = "test-blockchain";
        let result = run_project_init(project_name, "blockchain");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "Project 'test-blockchain' initialized successfully with template 'blockchain'."
        );

        // Verify the project structure
        assert!(Path::new(project_name).exists());
        assert!(Path::new(&format!("{}/ksl_package.toml", project_name)).exists());
        assert!(Path::new(&format!("{}/src/main.ksl", project_name)).exists());

        // Verify the package.toml content
        let package_toml = fs::read_to_string(format!("{}/ksl_package.toml", project_name)).unwrap();
        assert!(package_toml.contains(&format!("name = \"{}\"", project_name)));
        assert!(package_toml.contains("blockchain-lib"));

        // Verify the main.ksl content
        let main_ksl = fs::read_to_string(format!("{}/src/main.ksl", project_name)).unwrap();
        assert!(main_ksl.contains("contract_boilerplate"));

        // Clean up
        fs::remove_dir_all(project_name).unwrap();
    }

    #[test]
    fn test_project_init_ai() {
        let project_name = "test-ai";
        let result = run_project_init(project_name, "ai");
        assert!(result.is_ok());

        // Verify the package.toml content
        let package_toml = fs::read_to_string(format!("{}/ksl_package.toml", project_name)).unwrap();
        assert!(package_toml.contains("ai-model"));

        // Verify the main.ksl content
        let main_ksl = fs::read_to_string(format!("{}/src/main.ksl", project_name)).unwrap();
        assert!(main_ksl.contains("serialize_model"));

        // Clean up
        fs::remove_dir_all(project_name).unwrap();
    }

    #[test]
    fn test_project_init_game() {
        let project_name = "test-game";
        let result = run_project_init(project_name, "game");
        assert!(result.is_ok());

        // Verify the package.toml content
        let package_toml = fs::read_to_string(format!("{}/ksl_package.toml", project_name)).unwrap();
        assert!(package_toml.contains("game-physics"));

        // Verify the main.ksl content
        let main_ksl = fs::read_to_string(format!("{}/src/main.ksl", project_name)).unwrap();
        assert!(main_ksl.contains("game_loop"));

        // Clean up
        fs::remove_dir_all(project_name).unwrap();
    }

    #[test]
    fn test_project_init_invalid_name() {
        let result = run_project_init("invalid/name", "blockchain");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Project name must be non-empty"));
    }

    #[test]
    fn test_project_init_invalid_template() {
        let result = run_project_init("test-project", "invalid-template");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Template 'invalid-template' not found"));
    }
}