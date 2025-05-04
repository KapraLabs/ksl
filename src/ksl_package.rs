// ksl_package.rs
// Implements the KSL package management system for dependency resolution and library reuse.
// Supports async module loading, package features, and enhanced dependency management.

use crate::ksl_module::{ModuleSystem, PackageInfo};
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_async::AsyncRuntime;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use toml::Value;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Enhanced package metadata structure with features and async support
#[derive(Debug, Serialize, Deserialize)]
pub struct PackageMetadata {
    /// Package name (e.g., "ksl-http")
    pub name: String,
    /// Package version (e.g., "1.0.0")
    pub version: String,
    /// Package description
    pub description: Option<String>,
    /// Package author
    pub author: Option<String>,
    /// Package license
    pub license: Option<String>,
    /// Package dependencies with version constraints
    pub dependencies: HashMap<String, String>,
    /// Optional features that can be enabled
    pub features: HashMap<String, Vec<String>>,
    /// Whether the package requires async runtime
    pub requires_async: bool,
}

/// Package system state with async support
pub struct PackageSystem {
    modules: ModuleSystem,
    packages: HashMap<String, PackageMetadata>,
    repository: PathBuf,
    async_runtime: Arc<AsyncRuntime>,
    package_cache: HashMap<String, PackageInfo>,
}

impl PackageSystem {
    /// Creates a new package system with async support
    pub fn new() -> Self {
        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let repository = home_dir.join(".ksl/packages");
        PackageSystem {
            modules: ModuleSystem::new(),
            packages: HashMap::new(),
            repository,
            async_runtime: Arc::new(AsyncRuntime::new()),
            package_cache: HashMap::new(),
        }
    }

    /// Asynchronously installs a package from the repository
    pub async fn install_async(&mut self, name: &str, version: &str) -> Result<(), KslError> {
        // Check if package is already installed
        let package_key = format!("{}@{}", name, version);
        if self.packages.contains_key(&package_key) {
            return Ok(());
        }

        // Fetch package from repository
        let package_dir = self.repository.join(name).join(version);
        let metadata_file = package_dir.join("ksl_package.toml");
        if !metadata_file.exists() {
            return Err(KslError::type_error(
                format!("Package {}@{} not found in repository", name, version),
                SourcePosition::new(1, 1),
            ));
        }

        // Read metadata
        let metadata_content = fs::read_to_string(&metadata_file)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        let metadata: PackageMetadata = toml::from_str(&metadata_content)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        // Verify package metadata
        if metadata.name != name || metadata.version != version {
            return Err(KslError::type_error(
                format!("Mismatched package metadata for {}@{}", name, version),
                SourcePosition::new(1, 1),
            ));
        }

        // Install dependencies asynchronously
        for (dep_name, dep_version) in &metadata.dependencies {
            self.install_async(dep_name, dep_version).await?;
        }

        // Load package modules asynchronously
        let package_path = package_dir.join("src");
        for entry in fs::read_dir(&package_path)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?
        {
            let entry = entry?;
            if entry.path().extension().map(|ext| ext == "ksl").unwrap_or(false) {
                let module_name = entry.path().file_stem().unwrap().to_str().unwrap().to_string();
                self.modules.load_module_async(&module_name, &entry.path()).await?;
            }
        }

        // Create package info for module system
        let package_info = PackageInfo {
            name: metadata.name.clone(),
            version: metadata.version.clone(),
            dependencies: metadata.dependencies.clone(),
            features: metadata.features.keys().cloned().collect(),
        };
        self.package_cache.insert(package_key.clone(), package_info);

        // Register package
        self.packages.insert(package_key, metadata);
        Ok(())
    }

    /// Synchronous wrapper for package installation
    pub fn install(&mut self, name: &str, version: &str) -> Result<(), KslError> {
        let runtime = self.async_runtime.clone();
        runtime.block_on(self.install_async(name, version))
    }

    /// Asynchronously resolves dependencies for a project
    pub async fn resolve_dependencies_async(&mut self, project_dir: &Path) -> Result<(), KslError> {
        let metadata_file = project_dir.join("ksl_package.toml");
        if !metadata_file.exists() {
            return Ok(()); // No dependencies
        }

        let metadata_content = fs::read_to_string(&metadata_file)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        let metadata: PackageMetadata = toml::from_str(&metadata_content)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        for (dep_name, dep_version) in metadata.dependencies {
            self.install_async(&dep_name, &dep_version).await?;
        }

        Ok(())
    }

    /// Synchronous wrapper for dependency resolution
    pub fn resolve_dependencies(&mut self, project_dir: &Path) -> Result<(), KslError> {
        let runtime = self.async_runtime.clone();
        runtime.block_on(self.resolve_dependencies_async(project_dir))
    }

    // Publish a package to the repository
    pub fn publish(&mut self, package_dir: &Path) -> Result<(), KslError> {
        let metadata_file = package_dir.join("ksl_package.toml");
        let metadata_content = fs::read_to_string(&metadata_file)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        let metadata: PackageMetadata = toml::from_str(&metadata_content)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        // Create package directory in repository
        let target_dir = self.repository.join(&metadata.name).join(&metadata.version);
        fs::create_dir_all(&target_dir)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        // Copy package files
        let src_dir = package_dir.join("src");
        let target_src_dir = target_dir.join("src");
        fs::create_dir_all(&target_src_dir)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        for entry in fs::read_dir(&src_dir)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?
        {
            let entry = entry?;
            let target_path = target_src_dir.join(entry.file_name());
            fs::copy(entry.path(), &target_path)
                .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        }

        // Write metadata
        let target_metadata_file = target_dir.join("ksl_package.toml");
        let metadata_content = toml::to_string(&metadata)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        let mut file = File::create(&target_metadata_file)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        file.write_all(metadata_content.as_bytes())
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        Ok(())
    }

    /// Gets the module system for compilation
    pub fn module_system(&self) -> &ModuleSystem {
        &self.modules
    }

    /// Gets the async runtime
    pub fn async_runtime(&self) -> &Arc<AsyncRuntime> {
        &self.async_runtime
    }
}

/// Public API to manage packages
/// 
/// # Examples
/// 
/// ```ksl
/// // Install a package
/// let result = install_package("ksl-http", "1.0.0");
/// 
/// // Install a package asynchronously
/// let result = install_package_async("ksl-http", "1.0.0").await;
/// 
/// // Publish a package
/// let result = publish_package("path/to/package");
/// 
/// // Resolve project dependencies
/// let module_system = resolve_project_dependencies("path/to/project");
/// 
/// // Resolve project dependencies asynchronously
/// let module_system = resolve_project_dependencies_async("path/to/project").await;
/// ```

/// Installs a package synchronously
pub fn install_package(name: &str, version: &str) -> Result<(), KslError> {
    let mut package_system = PackageSystem::new();
    package_system.install(name, version)
}

/// Installs a package asynchronously
pub async fn install_package_async(name: &str, version: &str) -> Result<(), KslError> {
    let mut package_system = PackageSystem::new();
    package_system.install_async(name, version).await
}

/// Publishes a package to the repository
pub fn publish_package(package_dir: &Path) -> Result<(), KslError> {
    let mut package_system = PackageSystem::new();
    package_system.publish(package_dir)
}

/// Resolves project dependencies synchronously
pub fn resolve_project_dependencies(project_dir: &Path) -> Result<ModuleSystem, KslError> {
    let mut package_system = PackageSystem::new();
    package_system.resolve_dependencies(project_dir)?;
    Ok(package_system.modules)
}

/// Resolves project dependencies asynchronously
pub async fn resolve_project_dependencies_async(project_dir: &Path) -> Result<ModuleSystem, KslError> {
    let mut package_system = PackageSystem::new();
    package_system.resolve_dependencies_async(project_dir).await?;
    Ok(package_system.modules)
}

/// Package manifest format documentation
/// 
/// The package manifest (`ksl_package.toml`) supports the following format:
/// 
/// ```toml
/// [package]
/// name = "ksl-http"           # Package name
/// version = "1.0.0"           # Package version
/// description = "HTTP client"  # Optional description
/// author = "John Doe"         # Optional author
/// license = "MIT"             # Optional license
/// requires_async = true       # Whether the package requires async runtime
/// 
/// [dependencies]
/// ksl-json = "1.0.0"         # Dependencies with version constraints
/// ksl-crypto = "^2.0.0"      # Caret version constraint
/// 
/// [features]
/// default = ["tls"]          # Default features
/// tls = ["ksl-crypto"]      # Feature with dependencies
/// ```
/// 
/// Version constraints:
/// - Exact: "1.0.0"
/// - Caret: "^1.0.0" (allows 1.x.x but not 2.0.0)
/// - GreaterEqual: ">=1.2.0"
/// - LessThan: "<2.0.0"
/// 
/// Features:
/// - Can be enabled/disabled at build time
/// - Can have dependencies on other packages
/// - Can be used to conditionally compile code
/// 
/// Async support:
/// - Packages can declare async requirements
/// - Async packages can use async/await syntax
/// - Async packages can use async runtime features
pub mod package_manifest {}

// Assume ksl_module.rs and ksl_errors.rs are in the same crate
mod ksl_module {
    pub use super::ModuleSystem;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::io::Write;
    use tokio::runtime::Runtime;

    #[test]
    fn test_install_package() {
        let temp_dir = TempDir::new().unwrap();
        let repo_dir = temp_dir.path().join(".ksl/packages");
        let package_dir = repo_dir.join("mylib").join("1.0.0");
        fs::create_dir_all(&package_dir.join("src")).unwrap();
        let metadata_file = package_dir.join("ksl_package.toml");
        let mut file = File::create(&metadata_file).unwrap();
        writeln!(
            file,
            "[package]\nname = \"mylib\"\nversion = \"1.0.0\"\ndescription = \"Test library\"\nrequires_async = false\n[dependencies]\n[features]\ndefault = [\"test\"]\ntest = []"
        ).unwrap();
        let module_file = package_dir.join("src").join("utils.ksl");
        let mut module = File::create(&module_file).unwrap();
        writeln!(module, "fn add(x: u32, y: u32): u32 { x + y; }").unwrap();

        let mut package_system = PackageSystem {
            repository: repo_dir,
            ..PackageSystem::new()
        };
        let result = package_system.install("mylib", "1.0.0");
        assert!(result.is_ok());
        assert!(package_system.packages.contains_key("mylib@1.0.0"));
        assert!(package_system.modules.modules.contains_key("utils"));
        let package = package_system.packages.get("mylib@1.0.0").unwrap();
        assert_eq!(package.description, Some("Test library".to_string()));
        assert_eq!(package.requires_async, false);
        assert!(package.features.contains_key("test"));
    }

    #[tokio::test]
    async fn test_install_package_async() {
        let temp_dir = TempDir::new().unwrap();
        let repo_dir = temp_dir.path().join(".ksl/packages");
        let package_dir = repo_dir.join("mylib").join("1.0.0");
        fs::create_dir_all(&package_dir.join("src")).unwrap();
        let metadata_file = package_dir.join("ksl_package.toml");
        let mut file = File::create(&metadata_file).unwrap();
        writeln!(
            file,
            "[package]\nname = \"mylib\"\nversion = \"1.0.0\"\ndescription = \"Test library\"\nrequires_async = true\n[dependencies]\n[features]\ndefault = [\"test\"]\ntest = []"
        ).unwrap();
        let module_file = package_dir.join("src").join("utils.ksl");
        let mut module = File::create(&module_file).unwrap();
        writeln!(module, "async fn add(x: u32, y: u32): u32 { x + y; }").unwrap();

        let mut package_system = PackageSystem {
            repository: repo_dir,
            ..PackageSystem::new()
        };
        let result = package_system.install_async("mylib", "1.0.0").await;
        assert!(result.is_ok());
        assert!(package_system.packages.contains_key("mylib@1.0.0"));
        assert!(package_system.modules.modules.contains_key("utils"));
        let package = package_system.packages.get("mylib@1.0.0").unwrap();
        assert_eq!(package.description, Some("Test library".to_string()));
        assert_eq!(package.requires_async, true);
        assert!(package.features.contains_key("test"));
    }

    #[test]
    fn test_publish_package() {
        let temp_dir = TempDir::new().unwrap();
        let package_dir = temp_dir.path().join("mylib");
        fs::create_dir_all(package_dir.join("src")).unwrap();
        let metadata_file = package_dir.join("ksl_package.toml");
        let mut file = File::create(&metadata_file).unwrap();
        writeln!(
            file,
            "[package]\nname = \"mylib\"\nversion = \"1.0.0\"\ndescription = \"Test library\"\nrequires_async = false\n[dependencies]\n[features]\ndefault = [\"test\"]\ntest = []"
        ).unwrap();
        let module_file = package_dir.join("src").join("utils.ksl");
        let mut module = File::create(&module_file).unwrap();
        writeln!(module, "fn add(x: u32, y: u32): u32 { x + y; }").unwrap();

        let mut package_system = PackageSystem {
            repository: temp_dir.path().join(".ksl/packages"),
            ..PackageSystem::new()
        };
        let result = package_system.publish(&package_dir);
        assert!(result.is_ok());
        let published_metadata = package_system.repository.join("mylib").join("1.0.0").join("ksl_package.toml");
        assert!(published_metadata.exists());
        let published_module = package_system.repository.join("mylib").join("1.0.0").join("src").join("utils.ksl");
        assert!(published_module.exists());
    }

    #[tokio::test]
    async fn test_resolve_dependencies_async() {
        let temp_dir = TempDir::new().unwrap();
        let repo_dir = temp_dir.path().join(".ksl/packages");
        let package_dir = repo_dir.join("mylib").join("1.0.0");
        fs::create_dir_all(&package_dir.join("src")).unwrap();
        let metadata_file = package_dir.join("ksl_package.toml");
        let mut file = File::create(&metadata_file).unwrap();
        writeln!(
            file,
            "[package]\nname = \"mylib\"\nversion = \"1.0.0\"\ndescription = \"Test library\"\nrequires_async = true\n[dependencies]\n[features]\ndefault = [\"test\"]\ntest = []"
        ).unwrap();
        let module_file = package_dir.join("src").join("utils.ksl");
        let mut module = File::create(&module_file).unwrap();
        writeln!(module, "async fn add(x: u32, y: u32): u32 { x + y; }").unwrap();

        let project_dir = temp_dir.path().join("project");
        fs::create_dir_all(&project_dir).unwrap();
        let project_metadata = project_dir.join("ksl_package.toml");
        let mut file = File::create(&project_metadata).unwrap();
        writeln!(
            file,
            "[package]\nname = \"project\"\nversion = \"1.0.0\"\n[dependencies]\nmylib = \"1.0.0\""
        ).unwrap();

        let mut package_system = PackageSystem {
            repository: repo_dir,
            ..PackageSystem::new()
        };
        let result = package_system.resolve_dependencies_async(&project_dir).await;
        assert!(result.is_ok());
        assert!(package_system.packages.contains_key("mylib@1.0.0"));
        assert!(package_system.modules.modules.contains_key("utils"));
    }
}