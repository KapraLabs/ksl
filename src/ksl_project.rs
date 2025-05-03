// ksl_project.rs
// Project initialization tool for KSL with templates and scaffolding

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

/// Represents a template for a KSL project (aligned with ksl_template.rs).
#[derive(Debug, Clone)]
pub struct Template {
    name: String,
    description: String,
    package_toml: String, // Content for ksl_package.toml
    main_ksl: String,     // Content for src/main.ksl
}

impl Template {
    pub fn new(name: &str, description: &str, package_toml: &str, main_ksl: &str) -> Self {
        Template {
            name: name.to_string(),
            description: description.to_string(),
            package_toml: package_toml.to_string(),
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
            r#"[package]
name = "{name}"
version = "0.1.0"
license = "MIT"
dependencies = [
    { name = "blockchain-lib", version = "^1.0.0" },
]
"#,
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
            r#"[package]
name = "{name}"
version = "0.1.0"
license = "Apache-2.0"
dependencies = [
    { name = "ai-model", version = "^2.0.0" },
    { name = "math-lib", version = "^1.0.0" },
]
"#,
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
            r#"[package]
name = "{name}"
version = "0.1.0"
license = "BSD-3-Clause"
dependencies = [
    { name = "game-physics", version = "^1.0.0" },
    { name = "math-lib", version = "^1.0.0" },
]
"#,
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

/// Project initializer for KSL.
pub struct ProjectInitializer {
    templates: TemplateRegistry,
}

impl ProjectInitializer {
    pub fn new() -> Self {
        ProjectInitializer {
            templates: TemplateRegistry::new(),
        }
    }

    /// Initialize a new KSL project.
    pub fn init(&self, name: &str, template_name: &str) -> Result<(), String> {
        // Validate project name
        if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err("Project name must be non-empty and contain only alphanumeric characters, '-', or '_'".to_string());
        }

        // Check if the project directory already exists
        let project_dir = Path::new(name);
        if project_dir.exists() {
            return Err(format!("Directory '{}' already exists", name));
        }

        // Find the template
        let template = self.templates.get_template(template_name)
            .ok_or_else(|| format!("Template '{}' not found. Available templates: blockchain, ai, game", template_name))?;

        // Create the project directory
        fs::create_dir(project_dir).map_err(|e| format!("Failed to create project directory: {}", e))?;

        // Create the src directory
        let src_dir = project_dir.join("src");
        fs::create_dir(&src_dir).map_err(|e| format!("Failed to create src directory: {}", e))?;

        // Render and write ksl_package.toml
        let package_toml_content = template.package_toml.replace("{name}", name);
        let package_toml_path = project_dir.join("ksl_package.toml");
        let mut package_toml_file = File::create(&package_toml_path)
            .map_err(|e| format!("Failed to create ksl_package.toml: {}", e))?;
        package_toml_file.write_all(package_toml_content.as_bytes())
            .map_err(|e| format!("Failed to write ksl_package.toml: {}", e))?;

        // Write src/main.ksl
        let main_ksl_path = src_dir.join("main.ksl");
        let mut main_ksl_file = File::create(&main_ksl_path)
            .map_err(|e| format!("Failed to create src/main.ksl: {}", e))?;
        main_ksl_file.write_all(template.main_ksl.as_bytes())
            .map_err(|e| format!("Failed to write src/main.ksl: {}", e))?;

        Ok(())
    }
}

/// CLI integration for `ksl project init <name> --template <type>` (used by ksl_cli.rs).
pub fn run_project_init(name: &str, template: &str) -> Result<String, String> {
    let initializer = ProjectInitializer::new();
    initializer.init(name, template)?;
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