// ksl_package.rs
// Implements the KSL package management system for dependency resolution and library reuse.

use crate::ksl_module::ModuleSystem;
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use toml::Value;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// Package metadata structure
#[derive(Debug, Serialize, Deserialize)]
pub struct PackageMetadata {
    pub name: String,
    pub version: String,
    pub dependencies: HashMap<String, String>, // Name -> Version
}

// Package system state
pub struct PackageSystem {
    modules: ModuleSystem,
    packages: HashMap<String, PackageMetadata>, // Installed packages
    repository: PathBuf, // Path to package repository (e.g., ~/.ksl/packages)
}

impl PackageSystem {
    pub fn new() -> Self {
        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let repository = home_dir.join(".ksl/packages");
        PackageSystem {
            modules: ModuleSystem::new(),
            packages: HashMap::new(),
            repository,
        }
    }

    // Install a package from the repository
    pub fn install(&mut self, name: &str, version: &str) -> Result<(), KslError> {
        // Check if package is already installed
        let package_key = format!("{}@{}", name, version);
        if self.packages.contains_key(&package_key) {
            return Ok(());
        }

        // Fetch package from repository (simplified: local file-based)
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

        // Install dependencies
        for (dep_name, dep_version) in &metadata.dependencies {
            self.install(dep_name, dep_version)?;
        }

        // Load package modules
        let package_path = package_dir.join("src");
        for entry in fs::read_dir(&package_path)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?
        {
            let entry = entry?;
            if entry.path().extension().map(|ext| ext == "ksl").unwrap_or(false) {
                let module_name = entry.path().file_stem().unwrap().to_str().unwrap().to_string();
                self.modules.load_module(&module_name, &entry.path())?;
            }
        }

        // Register package
        self.packages.insert(package_key, metadata);
        Ok(())
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

    // Resolve dependencies for a project
    pub fn resolve_dependencies(&mut self, project_dir: &Path) -> Result<(), KslError> {
        let metadata_file = project_dir.join("ksl_package.toml");
        if !metadata_file.exists() {
            return Ok(()); // No dependencies
        }

        let metadata_content = fs::read_to_string(&metadata_file)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        let metadata: PackageMetadata = toml::from_str(&metadata_content)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        for (dep_name, dep_version) in metadata.dependencies {
            self.install(&dep_name, &dep_version)?;
        }

        Ok(())
    }

    // Get the module system for compilation
    pub fn module_system(&self) -> &ModuleSystem {
        &self.modules
    }
}

// Public API to manage packages
pub fn install_package(name: &str, version: &str) -> Result<(), KslError> {
    let mut package_system = PackageSystem::new();
    package_system.install(name, version)
}

pub fn publish_package(package_dir: &Path) -> Result<(), KslError> {
    let mut package_system = PackageSystem::new();
    package_system.publish(package_dir)
}

pub fn resolve_project_dependencies(project_dir: &Path) -> Result<ModuleSystem, KslError> {
    let mut package_system = PackageSystem::new();
    package_system.resolve_dependencies(project_dir)?;
    Ok(package_system.modules)
}

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
            "[package]\nname = \"mylib\"\nversion = \"1.0.0\"\n[dependencies]\n"
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
            "[package]\nname = \"mylib\"\nversion = \"1.0.0\"\n[dependencies]\n"
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

    #[test]
    fn test_resolve_dependencies() {
        let temp_dir = TempDir::new().unwrap();
        let repo_dir = temp_dir.path().join(".ksl/packages");
        let package_dir = repo_dir.join("mylib").join("1.0.0");
        fs::create_dir_all(&package_dir.join("src")).unwrap();
        let metadata_file = package_dir.join("ksl_package.toml");
        let mut file = File::create(&metadata_file).unwrap();
        writeln!(
            file,
            "[package]\nname = \"mylib\"\nversion = \"1.0.0\"\n[dependencies]\n"
        ).unwrap();
        let module_file = package_dir.join("src").join("utils.ksl");
        let mut module = File::create(&module_file).unwrap();
        writeln!(module, "fn add(x: u32, y: u32): u32 { x + y; }").unwrap();

        let project_dir = temp_dir.path().join("project");
        fs::create_dir_all(&project_dir).unwrap();
        let project_metadata_file = project_dir.join("ksl_package.toml");
        let mut project_file = File::create(&project_metadata_file).unwrap();
        writeln!(
            project_file,
            "[package]\nname = \"myproject\"\nversion = \"0.1.0\"\n[dependencies]\nmylib = \"1.0.0\"\n"
        ).unwrap();

        let mut package_system = PackageSystem {
            repository: repo_dir,
            ..PackageSystem::new()
        };
        let result = package_system.resolve_dependencies(&project_dir);
        assert!(result.is_ok());
        assert!(package_system.packages.contains_key("mylib@1.0.0"));
        assert!(package_system.modules.modules.contains_key("utils"));
    }
}