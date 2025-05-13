// ksl_plugins.rs
// Implements the KSL plugin system for extending the language with custom functionality.
// Supports native opcodes, WASM modules, and built-in host functions.

use crate::ksl_parser::{parse, AstNode, ParseError};
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_bytecode::{KapraBytecode, CompileTarget};
use crate::ksl_module::ModuleSystem;
use crate::ksl_ast::{PluginOp, PluginHandler};
use crate::ksl_types::Type as KSLType;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

/// Plugin specification defining the plugin's interface and capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginSpec {
    /// Plugin name (e.g., "ksl_ai")
    pub name: String,
    /// Namespace for plugin functions (e.g., "ai")
    pub namespace: String,
    /// Plugin version (e.g., "1.0.0")
    pub version: String,
    /// Available plugin operations
    pub ops: Vec<PluginOp>,
}

/// Plugin registry for managing loaded plugins
pub struct PluginRegistry {
    /// Loaded plugins
    plugins: HashMap<String, PluginSpec>,
    /// Module system for plugin dependencies
    module_system: ModuleSystem,
    /// Plugin search paths
    search_paths: Vec<PathBuf>,
    /// Plugin cache
    plugin_cache: HashMap<String, Arc<RwLock<PluginSpec>>>,
}

impl PluginRegistry {
    /// Create a new plugin registry
    pub fn new() -> Self {
        PluginRegistry {
            plugins: HashMap::new(),
            module_system: ModuleSystem::new(),
            search_paths: vec![],
            plugin_cache: HashMap::new(),
        }
    }

    /// Add a plugin search path
    pub fn add_search_path(&mut self, path: PathBuf) {
        self.search_paths.push(path);
    }

    /// Load a plugin from a file
    pub fn load_plugin(&mut self, path: &Path) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        
        // Read plugin manifest
        let manifest_path = path.join("ksl_plugin.toml");
        let manifest = fs::read_to_string(&manifest_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to read plugin manifest: {}", e),
                pos,
            ))?;

        // Parse plugin specification
        let spec: PluginSpec = toml::from_str(&manifest)
            .map_err(|e| KslError::type_error(
                format!("Invalid plugin manifest: {}", e),
                pos,
            ))?;

        // Validate plugin specification
        self.validate_plugin_spec(&spec)?;

        // Load plugin implementation
        let wasm_ops = self.find_ops_with_handler(&spec, "wasm");
        if !wasm_ops.is_empty() {
            // Find the first WASM handler
            let wasm_op = wasm_ops[0];
            let wasm_path = Path::new(&wasm_op.handler.name);
                    let full_path = path.join(wasm_path);
                    self.load_wasm_plugin(&spec, &full_path)?;
        } else {
                // Native plugin
                self.load_native_plugin(&spec, path)?;
        }

        // Register plugin
        self.plugins.insert(spec.name.clone(), spec);
        Ok(())
    }

    /// Validate plugin specification
    fn validate_plugin_spec(&self, spec: &PluginSpec) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);

        // Check for duplicate plugin
        if self.plugins.contains_key(&spec.name) {
            return Err(KslError::type_error(
                format!("Plugin '{}' already loaded", spec.name),
                pos,
            ));
        }

        // Validate namespace
        if spec.namespace.is_empty() {
            return Err(KslError::type_error(
                "Plugin namespace cannot be empty".to_string(),
                pos,
            ));
        }

        // Validate operations
        for op in &spec.ops {
            if op.name.is_empty() {
                return Err(KslError::type_error(
                    "Operation name cannot be empty".to_string(),
                    pos,
                ));
            }

            // Validate handler
            match &op.handler {
                PluginHandler { kind, name } => {
                    match kind.as_str() {
                        "native" => {
                    // Native handlers are validated at runtime
                        },
                        "wasm" => {
                            let path = Path::new(name);
                    if !path.exists() {
                        return Err(KslError::type_error(
                            format!("WASM module not found: {}", path.display()),
                            pos,
                        ));
                    }
                        },
                        "syscall" => {
                    if name.is_empty() {
                        return Err(KslError::type_error(
                            "Syscall name cannot be empty".to_string(),
                            pos,
                        ));
                            }
                        },
                        _ => {
                            return Err(KslError::type_error(
                                format!("Unknown handler kind: {}", kind),
                                pos,
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Load a WASM plugin
    fn load_wasm_plugin(&mut self, spec: &PluginSpec, wasm_path: &Path) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);

        // Load WASM module
        let wasm_bytes = fs::read(wasm_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to read WASM module: {}", e),
                pos,
            ))?;

        // Validate WASM module
        wasmparser::validate(&wasm_bytes)
            .map_err(|e| KslError::type_error(
                format!("Invalid WASM module: {}", e),
                pos,
            ))?;

        // TODO: Initialize WASM runtime and validate exports

        Ok(())
    }

    /// Load a native plugin
    fn load_native_plugin(&mut self, spec: &PluginSpec, path: &Path) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);

        // Load native library
        let lib_path = path.join("lib").join(format!("lib{}.so", spec.name));
        if !lib_path.exists() {
            return Err(KslError::type_error(
                format!("Native library not found: {}", lib_path.display()),
                pos,
            ));
        }

        // TODO: Load native library and validate symbols

        Ok(())
    }

    /// Get a plugin by name
    pub fn get_plugin(&self, name: &str) -> Option<&PluginSpec> {
        self.plugins.get(name)
    }

    /// Get a plugin operation
    pub fn get_operation(&self, plugin_name: &str, op_name: &str) -> Option<&PluginOp> {
        self.plugins.get(plugin_name)
            .and_then(|spec| spec.ops.iter().find(|op| op.name == op_name))
    }

    /// List loaded plugins
    pub fn list_plugins(&self) -> Vec<&PluginSpec> {
        self.plugins.values().collect()
    }

    /// Find operations with specific handler types
    fn find_ops_with_handler(&self, spec: &PluginSpec, handler_kind: &str) -> Vec<&PluginOp> {
        spec.ops.iter()
            .filter(|op| op.handler.kind == handler_kind)
            .collect()
    }
}

/// Public API for plugin management
pub fn load_plugin(path: &Path) -> Result<(), KslError> {
    let mut registry = PluginRegistry::new();
    registry.load_plugin(path)
}

pub fn get_plugin(name: &str) -> Option<PluginSpec> {
    let registry = PluginRegistry::new();
    registry.get_plugin(name).cloned()
}

pub fn list_plugins() -> Vec<PluginSpec> {
    let registry = PluginRegistry::new();
    registry.list_plugins().into_iter().cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_plugin_spec_validation() {
        let spec = PluginSpec {
            name: "test_plugin".to_string(),
            namespace: "test".to_string(),
            version: "1.0.0".to_string(),
            ops: vec![
                PluginOp {
                    name: "test_op".to_string(),
                    signature: vec![KSLType::Str],
                    return_type: KSLType::Bool,
                    handler: PluginHandler {
                        kind: "native".to_string(),
                        name: "test_handler".to_string(),
                    },
                }
            ],
        };

        let registry = PluginRegistry::new();
        assert!(registry.validate_plugin_spec(&spec).is_ok());
    }

    #[test]
    fn test_plugin_loading() {
        let mut temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("ksl_plugin.toml");
        
        let manifest = r#"
            name = "test_plugin"
            namespace = "test"
            version = "1.0.0"
            
            [[ops]]
            name = "test_op"
            signature = ["String"]
            return_type = "Bool"
            handler = { type = "native", name = "test_handler" }
        "#;

        fs::write(&manifest_path, manifest).unwrap();
        
        let result = load_plugin(temp_dir.path());
        assert!(result.is_ok());
    }
} 