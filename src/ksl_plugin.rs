// ksl_plugin.rs
// Implements the KSL plugin system for extending the language with custom tools,
// combining lightweight execution, robust security, and flexible extensibility.
// Supports async execution, enhanced security, and compiler integration.

use crate::ksl_parser::{parse, AstNode, ParseError};
use crate::ksl_sandbox::{Sandbox, SandboxConfig};
use crate::ksl_module::ModuleSystem;
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_async::{AsyncRuntime, AsyncVM};
use crate::ksl_compiler::{Compiler, CompileConfig};
use libloading::{Library, Symbol};
use std::path::PathBuf;
use std::collections::{HashMap, HashSet};
use std::fs;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Enhanced plugin metadata with async support and security features
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PluginMetadata {
    /// Plugin name (e.g., "ksl-lint")
    pub name: String,
    /// Plugin version (e.g., "1.0.0")
    pub version: String,
    /// Plugin description
    pub description: String,
    /// Available plugin commands
    pub commands: Vec<String>,
    /// Available plugin hooks
    pub hooks: Vec<String>,
    /// Required capabilities (e.g., "http", "fs")
    pub required_capabilities: Vec<String>,
    /// Whether the plugin requires async runtime
    pub requires_async: bool,
    /// Security configuration for the plugin
    pub security_config: Option<SandboxConfig>,
}

/// Enhanced plugin context with async support
#[derive(Clone)]
pub struct PluginContext<'a> {
    /// Source code being processed
    pub source_code: String,
    /// AST of the source code
    pub ast: &'a [AstNode],
    /// Available capabilities
    pub capabilities: HashSet<String>,
    /// Async runtime for async operations
    pub async_runtime: Arc<RwLock<AsyncRuntime>>,
    /// Compiler configuration
    pub compiler_config: CompileConfig,
}

/// Enhanced plugin error types with async support
#[derive(Debug)]
pub enum PluginError {
    LoadError(String, SourcePosition),
    SymbolError(String, SourcePosition),
    ExecutionError(String, SourcePosition),
    InvalidMetadata(String, SourcePosition),
    SandboxViolation(String, SourcePosition),
    ParseError(ParseError),
    AsyncError(String, SourcePosition),
    SecurityError(String, SourcePosition),
}

impl From<PluginError> for KslError {
    fn from(err: PluginError) -> KslError {
        match err {
            PluginError::LoadError(msg, pos) => KslError::type_error(msg, pos, "PLUGIN_LOAD_ERROR".to_string()),
            PluginError::SymbolError(msg, pos) => KslError::type_error(msg, pos, "PLUGIN_SYMBOL_ERROR".to_string()),
            PluginError::ExecutionError(msg, pos) => KslError::type_error(msg, pos, "PLUGIN_EXECUTION_ERROR".to_string()),
            PluginError::InvalidMetadata(msg, pos) => KslError::type_error(msg, pos, "PLUGIN_METADATA_ERROR".to_string()),
            PluginError::SandboxViolation(msg, pos) => KslError::type_error(msg, pos, "PLUGIN_SANDBOX_ERROR".to_string()),
            PluginError::ParseError(e) => KslError::type_error(e.message, SourcePosition::new(e.position, e.position), "PLUGIN_PARSE_ERROR".to_string()),
            PluginError::AsyncError(msg, pos) => KslError::type_error(msg, pos, "PLUGIN_ASYNC_ERROR".to_string()),
            PluginError::SecurityError(msg, pos) => KslError::type_error(msg, pos, "PLUGIN_SECURITY_ERROR".to_string()),
        }
    }
}

/// Enhanced plugin interface with async support
pub trait KslPlugin {
    /// Get plugin metadata
    fn metadata(&self) -> PluginMetadata;

    /// Execute a plugin command synchronously
    fn execute_command(&self, command: &str, ast: &[AstNode], args: &[String], module_system: &ModuleSystem) -> Result<String, PluginError>;

    /// Execute a plugin command asynchronously
    async fn execute_command_async(&self, command: &str, ast: &[AstNode], args: &[String], module_system: &ModuleSystem) -> Result<String, PluginError>;

    /// Pre-compile hook for AST transformation
    fn pre_compile_hook(&self, ast: &mut Vec<AstNode>, context: PluginContext, module_system: &ModuleSystem) -> Result<(), PluginError>;

    /// Post-compile hook for code generation
    fn post_compile_hook(&self, ast: &[AstNode], context: PluginContext, module_system: &ModuleSystem) -> Result<(), PluginError>;

    /// Validate plugin security configuration
    fn validate_security(&self, config: &SandboxConfig) -> Result<(), PluginError>;
}

/// Enhanced plugin manager with async support
pub struct PluginSystem {
    plugins: HashMap<String, Box<dyn KslPlugin>>,
    libraries: Vec<Library>,
    module_system: ModuleSystem,
    async_runtime: Arc<RwLock<AsyncRuntime>>,
    sandbox: Sandbox,
}

impl PluginSystem {
    /// Create a new plugin system
    pub fn new() -> Self {
        PluginSystem {
            plugins: HashMap::new(),
            libraries: Vec::new(),
            module_system: ModuleSystem::new(),
            async_runtime: Arc::new(RwLock::new(AsyncRuntime::new())),
            sandbox: Sandbox::new(),
        }
    }

    /// Install a plugin from a shared library
    pub fn install(&mut self, plugin_path: &PathBuf) -> Result<(), PluginError> {
        let pos = SourcePosition::new(1, 1);
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

        // Validate security configuration
        if let Some(config) = &metadata.security_config {
            plugin.validate_security(config)?;
        }

        // Register plugin
        self.plugins.insert(metadata.name.clone(), plugin);
        self.libraries.push(lib);
        Ok(())
    }

    /// Run a plugin command synchronously
    pub fn run_plugin(
        &mut self,
        plugin_name: &str,
        command: &str,
        file: &PathBuf,
        args: &[String],
    ) -> Result<String, PluginError> {
        let pos = SourcePosition::new(1, 1);
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

        // Create plugin context
        let context = PluginContext {
            source_code: source.clone(),
            ast: &ast,
            capabilities: capabilities.clone(),
            async_runtime: self.async_runtime.clone(),
            compiler_config: CompileConfig::default(),
        };

        // Run pre-compile hook
        plugin.pre_compile_hook(&mut ast, context.clone(), &self.module_system)?;

        // Run in sandbox
        let sandbox_config = metadata.security_config.clone().unwrap_or_default();
        self.sandbox.configure(sandbox_config);
        if !capabilities.iter().all(|cap| metadata.required_capabilities.contains(cap)) {
            return Err(PluginError::SandboxViolation(
                "Invalid capabilities in AST".to_string(),
                pos,
            ));
        }
        self.sandbox.run_sandbox(file)
            .map_err(|e| PluginError::SandboxViolation(
                e.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"),
                pos,
            ))?;

        // Execute command
        let result = if metadata.requires_async {
            // Run async command
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(plugin.execute_command_async(command, &ast, args, &self.module_system))?
        } else {
            // Run sync command
            plugin.execute_command(command, &ast, args, &self.module_system)?
        };

        // Run post-compile hook
        plugin.post_compile_hook(&ast, context, &self.module_system)?;

        Ok(result)
    }

    /// List installed plugins and their metadata
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
            required_capabilities: vec!["http".to_string()],
            requires_async: true,
            security_config: Some(SandboxConfig::default()),
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

    async fn execute_command_async(&self, command: &str, ast: &[AstNode], args: &[String], module_system: &ModuleSystem) -> Result<String, PluginError> {
        // Simulate async operation
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        self.execute_command(command, ast, args, module_system)
    }

    fn pre_compile_hook(&self, ast: &mut Vec<AstNode>, context: PluginContext, _module_system: &ModuleSystem) -> Result<(), PluginError> {
        let pos = SourcePosition::new(1, 1);
        if context.source_code.contains("unsafe") {
            return Err(PluginError::SecurityError(
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

    fn validate_security(&self, config: &SandboxConfig) -> Result<(), PluginError> {
        let pos = SourcePosition::new(1, 1);
        if !config.allow_http {
            return Err(PluginError::SecurityError(
                "HTTP capability required but not allowed in sandbox".to_string(),
                pos,
            ));
        }
        Ok(())
    }
}

// Assume ksl_parser.rs, ksl_sandbox.rs, ksl_module.rs, ksl_errors.rs, ksl_async.rs, and ksl_compiler.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ParseError};
}

mod ksl_sandbox {
    pub use super::{Sandbox, SandboxConfig};
}

mod ksl_module {
    pub use super::ModuleSystem;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

mod ksl_async {
    pub use super::{AsyncRuntime, AsyncVM};
}

mod ksl_compiler {
    pub use super::{Compiler, CompileConfig};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_plugin_install_and_list() {
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
        assert!(plugins[0].requires_async);
    }

    #[tokio::test]
    async fn test_plugin_async_execution() {
        let mut plugin_system = PluginSystem::new();
        plugin_system.plugins.insert(
            "test_plugin".to_string(),
            Box::new(TestPlugin),
        );

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "let x = 42;").unwrap();
        let result = plugin_system.run_plugin("test_plugin", "lint", &file.path().to_path_buf(), &[]);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_plugin_security() {
        let mut plugin_system = PluginSystem::new();
        plugin_system.plugins.insert(
            "test_plugin".to_string(),
            Box::new(TestPlugin),
        );

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "unsafe {{ let x = 42; }}").unwrap();
        let result = plugin_system.run_plugin("test_plugin", "lint", &file.path().to_path_buf(), &[]);
        assert!(result.is_err());
    }
}