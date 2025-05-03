// ksl_plugin.rs
// Implements the KSL plugin system for extending the language with custom tools,
// ensuring lightweight and secure execution with minimal runtime overhead.

use crate::ksl_bind::KslBind;
use crate::ksl_parser::{KslParser, ParseError};
use crate::ksl_sandbox::{KslSandbox, SandboxConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use libloading::{Library, Symbol};

// Plugin metadata stored in plugin configuration.
#[derive(Serialize, Deserialize, Clone)]
pub struct PluginMetadata {
    name: String,
    version: String,
    description: String,
    commands: Vec<String>,
    hooks: Vec<String>,
}

// Plugin interface for command and hook registration.
pub trait KslPlugin {
    fn metadata(&self) -> PluginMetadata;
    fn execute_command(&self, command: &str, args: Vec<String>) -> Result<String, PluginError>;
    fn execute_hook(&self, hook: &str, context: PluginContext) -> Result<(), PluginError>;
}

// Context passed to hooks, providing access to KSL state.
#[derive(Serialize, Deserialize, Clone)]
pub struct PluginContext {
    source_code: String,
    ast: Option<String>, // Serialized AST for analysis
    capabilities: Vec<String>, // Allowed capabilities
}

// Errors for plugin operations.
#[derive(Debug)]
pub enum PluginError {
    LoadError(String),
    SymbolError(String),
    ExecutionError(String),
    InvalidMetadata(String),
    SandboxViolation(String),
}

// Manages plugin loading, registration, and execution.
pub struct KslPluginManager {
    plugins: HashMap<String, Arc<PluginInstance>>,
    sandbox: KslSandbox,
    libraries: Vec<Library>, // Keep libraries alive
}

struct PluginInstance {
    metadata: PluginMetadata,
    plugin: Box<dyn KslPlugin>,
}

impl KslPluginManager {
    pub fn new(sandbox_config: SandboxConfig) -> Self {
        KslPluginManager {
            plugins: HashMap::new(),
            sandbox: KslSandbox::new(sandbox_config),
            libraries: Vec::new(),
        }
    }

    // Loads a plugin from a shared library (.so or .dll).
    pub fn load_plugin<P: AsRef<Path>>(
        &mut self,
        path: P,
        parser: &KslParser,
    ) -> Result<(), PluginError> {
        unsafe {
            let library = Library::new(path.as_ref())
                .map_err(|e| PluginError::LoadError(e.to_string()))?;
            
            // Get plugin entry point
            let constructor: Symbol<unsafe extern "C" fn() -> *mut dyn KslPlugin> = library
                .get(b"create_plugin")
                .map_err(|e| PluginError::SymbolError(e.to_string()))?;
            
            let plugin_ptr = constructor();
            let plugin = Box::from_raw(plugin_ptr);
            let metadata = plugin.metadata();

            // Validate metadata
            if metadata.name.is_empty() || metadata.version.is_empty() {
                return Err(PluginError::InvalidMetadata("Name or version missing".into()));
            }

            // Validate plugin code if source is provided
            if let Some(source) = metadata.commands.iter().find(|c| c.contains("source")) {
                let parse_result = parser.parse(source);
                if let Err(ParseError { message, .. }) = parse_result {
                    return Err(PluginError::InvalidMetadata(format!(
                        "Plugin source parse error: {}",
                        message
                    )));
                }
            }

            // Store plugin and keep library alive
            self.plugins.insert(
                metadata.name.clone(),
                Arc::new(PluginInstance {
                    metadata,
                    plugin,
                }),
            );
            self.libraries.push(library);
            Ok(())
        }
    }

    // Executes a plugin command with sandboxed restrictions.
    pub fn execute_command(
        &self,
        plugin_name: &str,
        command: &str,
        args: Vec<String>,
    ) -> Result<String, PluginError> {
        let plugin_instance = self
            .plugins
            .get(plugin_name)
            .ok_or_else(|| PluginError::LoadError(format!("Plugin {} not found", plugin_name)))?;

        if !plugin_instance.metadata.commands.contains(&command.to_string()) {
            return Err(PluginError::ExecutionError(format!(
                "Command {} not registered",
                command
            )));
        }

        // Execute in sandbox
        self.sandbox.execute(|| {
            plugin_instance
                .plugin
                .execute_command(command, args)
                .map_err(|e| PluginError::ExecutionError(format!("Command failed: {:?}", e)))
        })
    }

    // Executes a plugin hook with context, sandboxed for security.
    pub fn execute_hook(
        &self,
        plugin_name: &str,
        hook: &str,
        context: PluginContext,
    ) -> Result<(), PluginError> {
        let plugin_instance = self
            .plugins
            .get(plugin_name)
            .ok_or_else(|| PluginError::LoadError(format!("Plugin {} not found", plugin_name)))?;

        if !plugin_instance.metadata.hooks.contains(&hook.to_string()) {
            return Err(PluginError::ExecutionError(format!(
                "Hook {} not registered",
                hook
            )));
        }

        // Validate capabilities in context
        for cap in &context.capabilities {
            if !self.sandbox.is_capability_allowed(cap) {
                return Err(PluginError::SandboxViolation(format!(
                    "Capability {} not allowed",
                    cap
                )));
            }
        }

        // Execute in sandbox
        self.sandbox.execute(|| {
            plugin_instance
                .plugin
                .execute_hook(hook, context)
                .map_err(|e| PluginError::ExecutionError(format!("Hook failed: {:?}", e)))
        })
    }

    // Lists all loaded plugins and their metadata.
    pub fn list_plugins(&self) -> Vec<PluginMetadata> {
        self.plugins
            .values()
            .map(|instance| instance.metadata.clone())
            .collect()
    }
}

// CLI integration for plugin commands.
pub fn handle_plugin_command(
    manager: &mut KslPluginManager,
    parser: &KslParser,
    args: Vec<String>,
) -> Result<String, PluginError> {
    if args.is_empty() {
        return Err(PluginError::ExecutionError("No plugin command provided".into()));
    }

    match args[0].as_str() {
        "install" => {
            if args.len() < 2 {
                return Err(PluginError::ExecutionError("Plugin path required".into()));
            }
            manager
                .load_plugin(&args[1], parser)
                .map(|_| format!("Plugin {} installed", args[1]))
        }
        "list" => {
            let plugins = manager.list_plugins();
            let output = plugins
                .into_iter()
                .map(|meta| {
                    format!(
                        "{} (v{}): {}",
                        meta.name, meta.version, meta.description
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            Ok(if output.is_empty() {
                "No plugins installed".into()
            } else {
                output
            })
        }
        "execute" => {
            if args.len() < 4 {
                return Err(PluginError::ExecutionError(
                    "Usage: execute <plugin> <command> [args]".into(),
                ));
            }
            manager.execute_command(&args[1], &args[2], args[3..].to_vec())
        }
        _ => Err(PluginError::ExecutionError(format!(
            "Unknown plugin command: {}",
            args[0]
        ))),
    }
}

// Example plugin implementation (for testing or as a template).
pub struct ExamplePlugin;

impl KslPlugin for ExamplePlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "example".into(),
            version: "0.1.0".into(),
            description: "Example KSL plugin".into(),
            commands: vec!["analyze".into(), "format".into()],
            hooks: vec!["pre_compile".into(), "post_compile".into()],
        }
    }

    fn execute_command(&self, command: &str, args: Vec<String>) -> Result<String, PluginError> {
        match command {
            "analyze" => Ok(format!("Analyzing code with args: {:?}", args)),
            "format" => Ok(format!("Formatting code with args: {:?}", args)),
            _ => Err(PluginError::ExecutionError(format!(
                "Unknown command: {}",
                command
            ))),
        }
    }

    fn execute_hook(&self, hook: &str, context: PluginContext) -> Result<(), PluginError> {
        match hook {
            "pre_compile" => {
                println!("Pre-compile hook: Processing source {}", context.source_code);
                Ok(())
            }
            "post_compile" => {
                println!("Post-compile hook: AST {:?}", context.ast);
                Ok(())
            }
            _ => Err(PluginError::ExecutionError(format!("Unknown hook: {}", hook))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_manager() -> KslPluginManager {
        let sandbox_config = SandboxConfig {
            max_memory: 1024 * 1024, // 1 MB
            max_instructions: 100_000,
            allowed_capabilities: vec!["http".into()],
        };
        KslPluginManager::new(sandbox_config)
    }

    #[test]
    fn test_plugin_load_and_execute() {
        let mut manager = create_test_manager();
        let parser = KslParser::new();

        // Simulate plugin loading (using ExamplePlugin directly)
        let plugin = Box::new(ExamplePlugin);
        let metadata = plugin.metadata();
        manager.plugins.insert(
            metadata.name.clone(),
            Arc::new(PluginInstance {
                metadata: metadata.clone(),
                plugin,
            }),
        );

        // Test command execution
        let result = manager
            .execute_command("example", "analyze", vec!["file.ksl".into()])
            .unwrap();
        assert!(result.contains("Analyzing code"));

        // Test hook execution
        let context = PluginContext {
            source_code: "fn main() {}".into(),
            ast: Some("serialized_ast".into()),
            capabilities: vec!["http".into()],
        };
        manager
            .execute_hook("example", "pre_compile", context)
            .unwrap();

        // Test invalid command
        let err = manager
            .execute_command("example", "invalid", vec![])
            .unwrap_err();
        assert!(matches!(err, PluginError::ExecutionError(_)));

        // Test invalid plugin
        let err = manager
            .execute_command("nonexistent", "analyze", vec![])
            .unwrap_err();
        assert!(matches!(err, PluginError::LoadError(_)));
    }

    #[test]
    fn test_plugin_list() {
        let mut manager = create_test_manager();
        let plugin = Box::new(ExamplePlugin);
        let metadata = plugin.metadata();
        manager.plugins.insert(
            metadata.name.clone(),
            Arc::new(PluginInstance {
                metadata: metadata.clone(),
                plugin,
            }),
        );

        let plugins = manager.list_plugins();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name, "example");
        assert_eq!(plugins[0].version, "0.1.0");
    }
}