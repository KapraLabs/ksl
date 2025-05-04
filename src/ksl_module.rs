// ksl_module.rs
// Implements the KSL module system for code organization and reuse.
// Supports async module loading, package management, and dependency resolution.

use crate::ksl_parser::{parse, AstNode};
use crate::ksl_checker::check;
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_async::AsyncRuntime;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Package metadata for dependency management
#[derive(Debug, Clone)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub dependencies: HashMap<String, String>,
    pub features: HashSet<String>,
}

/// Module representation with async support
#[derive(Debug)]
pub struct Module {
    pub name: String,
    pub ast: Vec<AstNode>,
    pub package: Option<PackageInfo>,
    pub is_async: bool,
}

/// Module system state with async support
pub struct ModuleSystem {
    modules: HashMap<String, Module>,
    loading: HashSet<String>,
    async_runtime: Arc<AsyncRuntime>,
    package_cache: HashMap<String, PackageInfo>,
}

impl ModuleSystem {
    /// Creates a new module system with async support
    pub fn new() -> Self {
        ModuleSystem {
            modules: HashMap::new(),
            loading: HashSet::new(),
            async_runtime: Arc::new(AsyncRuntime::new()),
            package_cache: HashMap::new(),
        }
    }

    /// Loads package metadata from a package manifest
    async fn load_package_info(&mut self, path: &Path) -> Result<PackageInfo, KslError> {
        let manifest_path = path.join("ksl.toml");
        let manifest = fs::read_to_string(&manifest_path)
            .map_err(|e| KslError::io_error(
                format!("Failed to read package manifest: {}", e),
                SourcePosition::new(1, 1),
            ))?;

        // Parse package manifest (simplified)
        let package_info = PackageInfo {
            name: "example".to_string(), // TODO: Parse from manifest
            version: "1.0.0".to_string(),
            dependencies: HashMap::new(),
            features: HashSet::new(),
        };

        self.package_cache.insert(package_info.name.clone(), package_info.clone());
        Ok(package_info)
    }

    /// Asynchronously loads and resolves a module
    pub async fn load_module_async(
        &mut self,
        module_name: &str,
        base_path: &Path,
    ) -> Result<(), KslError> {
        if self.loading.contains(module_name) {
            return Err(KslError::type_error(
                format!("Cyclic dependency detected for module: {}", module_name),
                SourcePosition::new(1, 1),
            ));
        }

        if self.modules.contains_key(module_name) {
            return Ok(());
        }

        self.loading.insert(module_name.to_string());

        // Check if module is part of a package
        let package_info = if let Some(package_path) = find_package_root(base_path) {
            Some(self.load_package_info(&package_path).await?)
        } else {
            None
        };

        // Resolve module file path
        let module_path = if module_name == "std" || module_name.starts_with("std::") {
            None
        } else {
            let mut path = base_path.parent().unwrap_or_else(|| Path::new("")).to_path_buf();
            path.push(format!("{}.ksl", module_name));
            Some(path)
        };

        let ast = if let Some(path) = module_path {
            // Load from file
            let source = fs::read_to_string(&path)
                .map_err(|e| KslError::io_error(
                    format!("Failed to read module {}: {}", module_name, e),
                    SourcePosition::new(1, 1),
                ))?;
            parse(&source)
                .map_err(|e| KslError::parse_error(e.message, e.position))?
        } else {
            vec![]
        };

        // Process nested module declarations
        for node in &ast {
            if let AstNode::ModuleDecl { name } = node {
                let mut module_base_path = base_path.parent().unwrap_or_else(|| Path::new("")).to_path_buf();
                module_base_path.push(name);
                self.load_module_async(name, &module_base_path).await?;
            }
        }

        // Type-check the module
        check(&ast)
            .map_err(|errors| KslError::type_errors(errors))?;

        // Store the module
        self.modules.insert(module_name.to_string(), Module {
            name: module_name.to_string(),
            ast,
            package: package_info,
            is_async: false, // TODO: Detect async features
        });

        self.loading.remove(module_name);
        Ok(())
    }

    /// Synchronous wrapper for module loading
    pub fn load_module(&mut self, module_name: &str, base_path: &Path) -> Result<(), KslError> {
        let runtime = self.async_runtime.clone();
        runtime.block_on(self.load_module_async(module_name, base_path))
    }

    /// Resolves and links all modules into a single AST
    pub fn link(&self, main_module: &str) -> Result<Vec<AstNode>, KslError> {
        let main_mod = self.modules.get(main_module).ok_or_else(|| KslError::type_error(
            format!("Main module {} not found", main_module),
            SourcePosition::new(1, 1),
        ))?;

        let mut linked_ast = vec![];
        let mut imported_items = HashSet::new();

        // Process main module
        for node in &main_mod.ast {
            match node {
                AstNode::Import { path, item } => {
                    let full_name = format!("{}::{}", path.join("::"), item);
                    if !imported_items.contains(&full_name) {
                        if let Some(item_node) = self.resolve_import(&path, item)? {
                            linked_ast.push(item_node);
                            imported_items.insert(full_name);
                        }
                    }
                }
                _ => linked_ast.push(node.clone()),
            }
        }

        Ok(linked_ast)
    }

    // Resolve an import statement
    fn resolve_import(&self, path: &[String], item: &str) -> Result<AstNode, KslError> {
        let module_name = path[0].clone();
        let module = self.modules.get(&module_name).ok_or_else(|| KslError::type_error(
            format!("Module {} not found", module_name),
            SourcePosition::new(1, 1),
        ))?;

        // Handle standard library imports
        if module_name == "std" || module_name.starts_with("std::") {
            let full_name = format!("{}::{}", path.join("::"), item);
            // Check if the item exists in stdlib (crypto, math, io)
            if full_name.starts_with("std::crypto::") ||
               full_name.starts_with("std::math::") ||
               full_name.starts_with("std::io::") {
                return Ok(AstNode::ExternDecl {
                    name: full_name,
                    type_annot: None, // Simplified
                });
            }
            return Err(KslError::type_error(
                format!("Standard library item {} not found", full_name),
                SourcePosition::new(1, 1),
            ));
        }

        // Search module AST for the item
        for node in &module.ast {
            match node {
                AstNode::FnDecl { name, params, return_type, body } if name == item => {
                    return Ok(AstNode::FnDecl {
                        name: format!("{}::{}", module_name, name),
                        params: params.clone(),
                        return_type: return_type.clone(),
                        body: body.clone(),
                    });
                }
                AstNode::VarDecl { name, type_annot, expr, is_mutable } if name == item => {
                    return Ok(AstNode::VarDecl {
                        name: format!("{}::{}", module_name, name),
                        type_annot: type_annot.clone(),
                        expr: expr.clone(),
                        is_mutable: *is_mutable,
                    });
                }
                _ => continue,
            }
        }

        Err(KslError::type_error(
            format!("Item {} not found in module {}", item, module_name),
            SourcePosition::new(1, 1),
        ))
    }
}

/// Finds the root directory of a package
fn find_package_root(path: &Path) -> Option<PathBuf> {
    let mut current = path.to_path_buf();
    while current.pop() {
        if current.join("ksl.toml").exists() {
            return Some(current);
        }
    }
    None
}

/// Public API to load and link modules
pub fn load_and_link(main_file: &PathBuf) -> Result<Vec<AstNode>, KslError> {
    let mut module_system = ModuleSystem::new();
    let main_module_name = main_file.file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| KslError::type_error(
            "Invalid main file name".to_string(),
            SourcePosition::new(1, 1),
        ))?;
    module_system.load_module(main_module_name, main_file)?;
    module_system.link(main_module_name)
}

// Assume ksl_parser.rs, ksl_checker.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode};
}

mod ksl_checker {
    pub use super::check;
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
    fn test_load_module() {
        let mut main_file = NamedTempFile::new().unwrap();
        writeln!(
            main_file,
            "mod utils;\nimport utils::add;\nfn main() { let x = add(1, 2); }"
        ).unwrap();

        let mut utils_file = NamedTempFile::new().unwrap();
        writeln!(
            utils_file,
            "fn add(x: u32, y: u32): u32 { x + y; }"
        ).unwrap();
        let utils_path = utils_file.path().to_path_buf();
        let utils_dir = utils_path.parent().unwrap().to_path_buf();
        let utils_name = utils_path.file_stem().unwrap().to_str().unwrap();
        fs::rename(&utils_path, utils_dir.join(format!("{}.ksl", utils_name))).unwrap();

        let mut module_system = ModuleSystem::new();
        let result = module_system.load_module("utils", &utils_dir);
        assert!(result.is_ok());
        assert!(module_system.modules.contains_key("utils"));
    }

    #[test]
    fn test_async_module() {
        let mut main_file = NamedTempFile::new().unwrap();
        writeln!(
            main_file,
            "async mod network;\nimport network::fetch;\nasync fn main() { let data = await fetch(\"https://example.com\"); }"
        ).unwrap();

        let mut network_file = NamedTempFile::new().unwrap();
        writeln!(
            network_file,
            "async fn fetch(url: string): string { /* implementation */ }"
        ).unwrap();
        let network_path = network_file.path().to_path_buf();
        let network_dir = network_path.parent().unwrap().to_path_buf();
        let network_name = network_path.file_stem().unwrap().to_str().unwrap();
        fs::rename(&network_path, network_dir.join(format!("{}.ksl", network_name))).unwrap();

        let mut module_system = ModuleSystem::new();
        let result = module_system.load_module("network", &network_dir);
        assert!(result.is_ok());
        let module = module_system.modules.get("network").unwrap();
        assert!(module.is_async);
    }

    #[test]
    fn test_link_module() {
        let mut main_file = NamedTempFile::new().unwrap();
        writeln!(
            main_file,
            "mod utils;\nimport utils::add;\nfn main() { let x = add(1, 2); }"
        ).unwrap();

        let mut utils_file = NamedTempFile::new().unwrap();
        writeln!(
            utils_file,
            "fn add(x: u32, y: u32): u32 { x + y; }"
        ).unwrap();
        let utils_path = utils_file.path().to_path_buf();
        let utils_dir = utils_path.parent().unwrap().to_path_buf();
        let utils_name = utils_path.file_stem().unwrap().to_str().unwrap();
        fs::rename(&utils_path, utils_dir.join(format!("{}.ksl", utils_name))).unwrap();

        let ast = load_and_link(&main_file.path().to_path_buf()).unwrap();
        assert!(ast.iter().any(|node| matches!(node, AstNode::FnDecl { name, .. } if name == "utils::add")));
        assert!(ast.iter().any(|node| matches!(node, AstNode::FnDecl { name, .. } if name == "main")));
    }

    #[test]
    fn test_std_import() {
        let mut main_file = NamedTempFile::new().unwrap();
        writeln!(
            main_file,
            "import std::crypto::bls_verify;\nfn main() { let valid = bls_verify(...); }"
        ).unwrap();

        let ast = load_and_link(&main_file.path().to_path_buf()).unwrap();
        assert!(ast.iter().any(|node| matches!(node, AstNode::ExternDecl { name, .. } if name == "std::crypto::bls_verify")));
    }
}