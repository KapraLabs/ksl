// ksl_plugin.rs
// Implements the KSL plugin system for extending the language with custom tools,
// combining lightweight execution, robust security, and flexible extensibility.

use crate::ksl_parser::{parse, AstNode, ParseError};
use crate::ksl_sandbox::Sandbox;
use crate::ksl_module::ModuleSystem;
use crate::ksl_errors::{KslError, SourcePosition};
use libloading::{Library, Symbol};
use std::path::PathBuf;
use std::collections::{HashMap, HashSet};
use std::fs;
use serde::{Deserialize, Serialize};

// Plugin metadata for discoverability
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub commands: Vec<String>,
    pub hooks: Vec<String>,
}

// Plugin context for hooks, providing access to KSL state
#[derive(Clone)]
pub struct PluginContext<'a> {
    pub source_code: String,
    pub ast: &'a [AstNode],
    pub capabilities: HashSet<String>,
}

// Plugin error types
#[derive(Debug)]
pub enum PluginError {
    LoadError(String, SourcePosition),
    SymbolError(String, SourcePosition),
    ExecutionError(String, SourcePosition),
    InvalidMetadata(String, SourcePosition),
    SandboxViolation(String, SourcePosition),
    ParseError(ParseError),
}

impl From<PluginError> for KslError {
    fn from(err: PluginError) -> KslError {
        match err {
            PluginError::LoadError(msg, pos) => KslError::type_error(msg, pos),
            PluginError::SymbolError(msg, pos) => KslError::type_error(msg, pos),
            PluginError::ExecutionError(msg, pos) => KslError::type_error(msg, pos),
            PluginError::InvalidMetadata(msg, pos) => KslError::type_error(msg, pos),
            PluginError::SandboxViolation(msg, pos) => KslError::type_error(msg, pos),
            PluginError::ParseError(e) => KslError::type_error(e.message, SourcePosition::new(e.position, e.position)),
        }
    }
}

// Plugin interface for command and hook registration
pub trait KslPlugin {
    fn metadata(&self) -> PluginMetadata;
    fn execute_command(&self, command: &str, ast: &[AstNode], args: &[String], module_system: &ModuleSystem) -> Result<String, PluginError>;
    fn pre_compile_hook(&self, ast: &mut Vec<AstNode>, context: PluginContext, module_system: &ModuleSystem) -> Result<(), PluginError>;
    fn post_compile_hook(&self, ast: &[AstNode], context: PluginContext, module_system: &ModuleSystem) -> Result<(), PluginError>;
}

// Plugin manager for loading, registering, and executing plugins
pub struct PluginSystem {
    plugins: HashMap<String, Box<dyn KslPlugin>>,
    libraries: Vec<Library>,
    module_system: ModuleSystem,
}

impl PluginSystem {
    pub fn new() -> Self {
        PluginSystem {
            plugins: HashMap::new(),
            libraries: Vec::new(),
            module_system: ModuleSystem::new(),
        }
    }

    // Install a plugin from a shared library
    pub fn install(&mut self, plugin_path: &PathBuf) -> Result<(), PluginError> {
        let pos = SourcePosition::new(1, 1); // To be enhanced with precise positions
        // Load shared library
        let lib = unsafe {
            Library::new(plugin_path).map_err(|e| PluginError::LoadError(
                format!("Failed to load plugin {}: {}", plugin_path.display(), e),
                pos,
            ))?
        };

        // Get plugin factory
        let factory: Symbol<unsafe extern "C" fn() -> *mut dyn KslPlugin> = unsafe {
            lib.get(b"create_plugin").map_err(|e| PluginError::SymbolError(
                format!("Failed to find create_plugin in {}: {}", plugin_path.display(), e),
                pos,
            ))?
        };

        // Create plugin instance
        let plugin = unsafe {
            let plugin_ptr = factory();
            Box::from_raw(plugin_ptr)
        };

        let metadata = plugin.metadata();
        if metadata.name.is_empty() || metadata.version.is_empty() {
            return Err(PluginError::InvalidMetadata(
                "Plugin name or version missing".to_string(),
                pos,
            ));
        }

        if self.plugins.contains_key(&metadata.name) {
            return Err(PluginError::InvalidMetadata(
                format!("Plugin {} already installed", metadata.name),
                pos,
            ));
        }

        // Register plugin
        self.plugins.insert(metadata.name.clone(), plugin);
        self.libraries.push(lib);
        Ok(())
    }

    // Run a plugin command on a KSL file
    pub fn run_plugin(
        &mut self,
        plugin_name: &str,
        command: &str,
        file: &PathBuf,
        args: &[String],
    ) -> Result<String, PluginError> {
        let pos = SourcePosition::new(1, 1); // To be enhanced
        let plugin = self.plugins.get(plugin_name).ok_or_else(|| PluginError::LoadError(
            format!("Plugin {} not found", plugin_name),
            pos,
        ))?;

        let metadata = plugin.metadata();
        if !metadata.commands.contains(&command.to_string()) {
            return Err(PluginError::ExecutionError(
                format!("Command {} not supported by plugin {}", command, plugin_name),
                pos,
            ));
        }

        // Load and parse file
        let source = fs::read_to_string(file)
            .map_err(|e| PluginError::ExecutionError(
                format!("Failed to read file {}: {}", file.display(), e),
                pos,
            ))?;
        let mut ast = parse(&source)
            .map_err(PluginError::ParseError)?;

        // Load modules
        let main_module_name = file.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| PluginError::InvalidMetadata(
                "Invalid main file name".to_string(),
                pos,
            ))?;
        self.module_system.load_module(main_module_name, file)
            .map_err(|e| PluginError::ExecutionError(e.to_string(), pos))?;

        // Extract capabilities from AST
        let capabilities = extract_capabilities(&ast);

        // Run pre-compile hook
        let context = PluginContext {
            source_code: source.clone(),
            ast: &ast,
            capabilities: capabilities.clone(),
        };
        plugin.pre_compile_hook(&mut ast, context.clone(), &self.module_system)?;

        // Run in sandbox
        let mut sandbox = Sandbox::new();
        if !capabilities.iter().all(|cap| matches!(cap.as_str(), "http" | "sensor")) {
            return Err(PluginError::SandboxViolation(
                "Invalid capabilities in AST".to_string(),
                pos,
            ));
        }
        sandbox.run_sandbox(file)
            .map_err(|e| PluginError::SandboxViolation(
                e.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"),
                pos,
            ))?;

        // Execute command
        let result = plugin.execute_command(command, &ast, args, &self.module_system)?;

        // Run post-compile hook
        plugin.post_compile_hook(&ast, context, &self.module_system)?;

        Ok(result)
    }

    // List installed plugins and their metadata
    pub fn list_plugins(&self) -> Vec<PluginMetadata> {
        self.plugins.values().map(|plugin| plugin.metadata()).collect()
    }
}

// Extract capabilities from AST (e.g., #[allow(http)])
fn extract_capabilities(ast: &[AstNode]) -> HashSet<String> {
    let mut capabilities = HashSet::new();
    for node in ast {
        if let AstNode::FnDecl { attributes, .. } = node {
            for attr in attributes {
                if attr.name.starts_with("allow(") && attr.name.ends_with(")") {
                    let cap = attr.name[6..attr.name.len()-1].to_string();
                    capabilities.insert(cap);
                }
            }
        }
    }
    capabilities
}

// Public API for plugin management
pub fn install_plugin(plugin_path: &PathBuf) -> Result<(), PluginError> {
    let mut plugin_system = PluginSystem::new();
    plugin_system.install(plugin_path)
}

pub fn run_plugin_command(
    plugin_name: &str,
    command: &str,
    file: &PathBuf,
    args: &[String],
) -> Result<String, PluginError> {
    let mut plugin_system = PluginSystem::new();
    plugin_system.run_plugin(plugin_name, command, file, args)
}

// Example plugin for testing
#[cfg(test)]
struct TestPlugin;

#[cfg(test)]
impl KslPlugin for TestPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "test_plugin".to_string(),
            version: "0.1.0".to_string(),
            description: "Test plugin for KSL linting and formatting".to_string(),
            commands: vec!["lint".to_string(), "format".to_string()],
            hooks: vec!["pre_compile".to_string(), "post_compile".to_string()],
        }
    }

    fn execute_command(&self, command: &str, ast: &[AstNode], args: &[String], _module_system: &ModuleSystem) -> Result<String, PluginError> {
        let pos = SourcePosition::new(1, 1);
        match command {
            "lint" => {
                let mut warnings = vec![];
                for node in ast {
                    if let AstNode::VarDecl { name, .. } = node {
                        if !name.chars().all(|c| c.is_lowercase() || c == '_') {
                            warnings.push(format!("Variable {} should use snake_case at position {}", name, pos));
                        }
                    }
                }
                Ok(warnings.join("\n"))
            }
            "format" => Ok(format!("Formatted AST with args: {:?}", args)),
            _ => Err(PluginError::ExecutionError(
                format!("Unknown command: {}", command),
                pos,
            )),
        }
    }

    fn pre_compile_hook(&self, ast: &mut Vec<AstNode>, context: PluginContext, _module_system: &ModuleSystem) -> Result<(), PluginError> {
        let pos = SourcePosition::new(1, 1);
        if context.source_code.contains("unsafe") {
            return Err(PluginError::ExecutionError(
                "Unsafe code detected in pre-compile hook".to_string(),
                pos,
            ));
        }
        Ok(())
    }

    fn post_compile_hook(&self, _ast: &[AstNode], context: PluginContext, _module_system: &ModuleSystem) -> Result<(), PluginError> {
        let pos = SourcePosition::new(1, 1);
        if context.capabilities.contains("http") {
            println!("Post-compile: HTTP capability detected");
        }
        Ok(())
    }
}

// Assume ksl_parser.rs, ksl_sandbox.rs, ksl_module.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ParseError};
}

mod ksl_sandbox {
    pub use super::Sandbox;
}

mod ksl_module {
    pub use super::ModuleSystem;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_plugin_install_and_list() {
        let mut plugin_system = PluginSystem::new();
        plugin_system.plugins.insert(
            "test_plugin".to_string(),
            Box::new(TestPlugin),
        );

        let plugins = plugin_system.list_plugins();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name, "test_plugin");
        assert_eq!(plugins[0].version, "0.1.0");
        assert_eq!(plugins[0].commands, vec!["lint", "format"]);
        assert_eq!(plugins[0].hooks, vec!["pre_compile", "post_compile"]);
    }

    #[test]
    fn test_plugin_lint() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "#[allow(http)]\nlet BadName: u32 = 42;\nfn main() { let good_name: u32 = 10; }"
        ).unwrap();

        let mut plugin_system = PluginSystem::new();
        plugin_system.plugins.insert(
            "test_plugin".to_string(),
            Box::new(TestPlugin),
        );

        let result = plugin_system.run_plugin(
            "test_plugin",
            "lint",
            &temp_file.path().to_path_buf(),
            &[],
        );
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("Variable BadName should use snake_case"));
        assert!(!output.contains("good_name"));
    }

    #[test]
    fn test_plugin_format() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "fn main() { let x: u32 = 42; }").unwrap();

        let mut plugin_system = PluginSystem::new();
        plugin_system.plugins.insert(
            "test_plugin".to_string(),
            Box::new(TestPlugin),
        );

        let result = plugin_system.run_plugin(
            "test_plugin",
            "format",
            &temp_file.path().to_path_buf(),
            &["--indent=2".to_string()],
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Formatted AST with args: [\"--indent=2\"]");
    }

    #[test]
    fn test_plugin_hooks() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "#[allow(http)]\nfn main() { let x: u32 = 42; }"
        ).unwrap();

        let mut plugin_system = PluginSystem::new();
        plugin_system.plugins.insert(
            "test_plugin".to_string(),
            Box::new(TestPlugin),
        );

        let result = plugin_system.run_plugin(
            "test_plugin",
            "lint",
            &temp_file.path().to_path_buf(),
            &[],
        );
        assert!(result.is_ok());
        // Post-compile hook prints to stdout, manually verified
    }

    #[test]
    fn test_plugin_unsafe_code() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "fn main() { unsafe_operation(); }").unwrap();

        let mut plugin_system = PluginSystem::new();
        plugin_system.plugins.insert(
            "test_plugin".to_string(),
            Box::new(TestPlugin),
        );

        let result = plugin_system.run_plugin(
            "test_plugin",
            "lint",
            &temp_file.path().to_path_buf(),
            &[],
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PluginError::ExecutionError(ref msg, _) if msg.contains("Unsafe code detected")));
    }

    #[test]
    fn test_invalid_plugin() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut plugin_system = PluginSystem::new();
        let result = plugin_system.run_plugin(
            "unknown_plugin",
            "lint",
            &temp_file.path().to_path_buf(),
            &[],
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PluginError::LoadError(ref msg, _) if msg.contains("Plugin unknown_plugin not found")));
    }
}