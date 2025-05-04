// ksl_package_version.rs
// Version management and dependency resolution enhancements for KSL packages
// Implements semantic versioning, version constraints, and async dependency resolution.

use crate::ksl_package::{PackageSystem, PackageMetadata};
use crate::ksl_package_publish::{PackagePublisher, PublishConfig};
use crate::ksl_async::{AsyncRuntime, AsyncResult};
use crate::ksl_errors::{KslError, SourcePosition};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

/// Represents a semantic version (e.g., 1.2.3).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SemVer {
    /// Major version (incompatible API changes)
    pub major: u32,
    /// Minor version (backwards-compatible functionality)
    pub minor: u32,
    /// Patch version (backwards-compatible bug fixes)
    pub patch: u32,
}

impl SemVer {
    /// Creates a new semantic version
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        SemVer { major, minor, patch }
    }

    /// Parse a version string (e.g., "1.2.3")
    pub fn parse(version: &str) -> Result<Self, String> {
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 3 {
            return Err(format!("Invalid version format: '{}', expected 'major.minor.patch'", version));
        }

        let major = parts[0].parse::<u32>().map_err(|e| format!("Invalid major version: {}", e))?;
        let minor = parts[1].parse::<u32>().map_err(|e| format!("Invalid minor version: {}", e))?;
        let patch = parts[2].parse::<u32>().map_err(|e| format!("Invalid patch version: {}", e))?;

        Ok(SemVer { major, minor, patch })
    }
}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Represents a version constraint (e.g., ^1.0.0, >=1.2.0)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VersionConstraint {
    /// Exact version match (e.g., "1.0.0")
    Exact(SemVer),
    /// Caret range (e.g., "^1.0.0" allows 1.x.x but not 2.0.0)
    Caret(SemVer),
    /// Greater than or equal to (e.g., ">=1.2.0")
    GreaterEqual(SemVer),
    /// Less than (e.g., "<2.0.0")
    LessThan(SemVer),
}

impl VersionConstraint {
    /// Parse a version constraint (e.g., "^1.0.0")
    pub fn parse(constraint: &str) -> Result<Self, String> {
        if constraint.starts_with('^') {
            let version = SemVer::parse(&constraint[1..])?;
            Ok(VersionConstraint::Caret(version))
        } else if constraint.starts_with(">=") {
            let version = SemVer::parse(&constraint[2..])?;
            Ok(VersionConstraint::GreaterEqual(version))
        } else if constraint.starts_with('<') {
            let version = SemVer::parse(&constraint[1..])?;
            Ok(VersionConstraint::LessThan(version))
        } else {
            let version = SemVer::parse(constraint)?;
            Ok(VersionConstraint::Exact(version))
        }
    }

    /// Check if a version satisfies the constraint
    pub fn satisfies(&self, version: &SemVer) -> bool {
        match self {
            VersionConstraint::Exact(v) => version == v,
            VersionConstraint::Caret(v) => {
                version.major == v.major && version >= v
            }
            VersionConstraint::GreaterEqual(v) => version >= v,
            VersionConstraint::LessThan(v) => version < v,
        }
    }
}

impl fmt::Display for VersionConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionConstraint::Exact(v) => write!(f, "{}", v),
            VersionConstraint::Caret(v) => write!(f, "^{}", v),
            VersionConstraint::GreaterEqual(v) => write!(f, ">={}", v),
            VersionConstraint::LessThan(v) => write!(f, "<{}", v),
        }
    }
}

/// Represents a package with its version and dependencies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    /// Package name
    pub name: String,
    /// Package version
    pub version: SemVer,
    /// Package dependencies with version constraints
    pub dependencies: Vec<(String, VersionConstraint)>,
    /// Package metadata
    pub metadata: Option<PackageMetadata>,
}

impl Package {
    /// Creates a new package
    pub fn new(name: &str, version: SemVer, dependencies: Vec<(String, VersionConstraint)>, metadata: Option<PackageMetadata>) -> Self {
        Package {
            name: name.to_string(),
            version,
            dependencies,
            metadata,
        }
    }
}

/// Package registry state
#[derive(Debug, Clone)]
pub struct RegistryState {
    /// Last published package
    pub last_published: Option<Package>,
    /// Version cache
    pub version_cache: HashMap<String, Vec<Package>>,
}

/// Represents the package registry
#[derive(Debug, Clone)]
pub struct PackageRegistry {
    packages: HashMap<String, Vec<Package>>,
    async_runtime: Arc<AsyncRuntime>,
    state: Arc<RwLock<RegistryState>>,
}

impl PackageRegistry {
    /// Creates a new package registry
    pub fn new() -> Self {
        PackageRegistry {
            packages: HashMap::new(),
            async_runtime: Arc::new(AsyncRuntime::new()),
            state: Arc::new(RwLock::new(RegistryState {
                last_published: None,
                version_cache: HashMap::new(),
            })),
        }
    }

    /// Add a package to the registry asynchronously
    pub async fn publish_async(&mut self, package: Package) -> AsyncResult<()> {
        let mut state = self.state.write().await;
        state.last_published = Some(package.clone());
        state.version_cache.entry(package.name.clone())
            .or_insert_with(Vec::new)
            .push(package.clone());
        
        self.packages.entry(package.name.clone())
            .or_insert_with(Vec::new)
            .push(package);
        Ok(())
    }

    /// Find a package version that satisfies the constraint asynchronously
    pub async fn find_compatible_async(&self, name: &str, constraint: &VersionConstraint) -> AsyncResult<Option<Package>> {
        let state = self.state.read().await;
        if let Some(cached_versions) = state.version_cache.get(name) {
            if let Some(pkg) = cached_versions.iter()
                .filter(|pkg| constraint.satisfies(&pkg.version))
                .max_by_key(|pkg| &pkg.version)
                .cloned()
            {
                return Ok(Some(pkg));
            }
        }
        drop(state);

        if let Some(versions) = self.packages.get(name) {
            if let Some(pkg) = versions.iter()
                .filter(|pkg| constraint.satisfies(&pkg.version))
                .max_by_key(|pkg| &pkg.version)
                .cloned()
            {
                let mut state = self.state.write().await;
                state.version_cache.entry(name.to_string())
                    .or_insert_with(Vec::new)
                    .push(pkg.clone());
                return Ok(Some(pkg));
            }
        }
        Ok(None)
    }
}

/// Dependency resolver for KSL packages
pub struct DependencyResolver {
    registry: PackageRegistry,
    resolved: HashMap<String, Package>,
    visited: HashSet<String>,
    async_runtime: Arc<AsyncRuntime>,
}

impl DependencyResolver {
    /// Creates a new dependency resolver
    pub fn new(registry: PackageRegistry) -> Self {
        DependencyResolver {
            registry,
            resolved: HashMap::new(),
            visited: HashSet::new(),
            async_runtime: Arc::new(AsyncRuntime::new()),
        }
    }

    /// Resolve dependencies for a package asynchronously
    pub async fn resolve_async(&mut self, package: &Package) -> AsyncResult<()> {
        let package_key = format!("{}-{}", package.name, package.version);
        if self.visited.contains(&package_key) {
            return Err(KslError::type_error(
                format!("Dependency cycle detected for package: {}", package.name),
                SourcePosition::new(1, 1),
            ));
        }

        self.visited.insert(package_key.clone());

        for (dep_name, constraint) in &package.dependencies {
            if self.resolved.contains_key(dep_name) {
                let resolved_pkg = self.resolved.get(dep_name).unwrap();
                if !constraint.satisfies(&resolved_pkg.version) {
                    return Err(KslError::type_error(
                        format!(
                            "Version conflict for '{}': required {} but found {}",
                            dep_name, constraint, resolved_pkg.version
                        ),
                        SourcePosition::new(1, 1),
                    ));
                }
                continue;
            }

            let dep_pkg = self.registry.find_compatible_async(dep_name, constraint).await?
                .ok_or_else(|| KslError::type_error(
                    format!("No compatible version found for '{}': {}", dep_name, constraint),
                    SourcePosition::new(1, 1),
                ))?;

            self.resolve_async(&dep_pkg).await?;
            self.resolved.insert(dep_name.clone(), dep_pkg);
        }

        self.visited.remove(&package_key);
        Ok(())
    }

    /// Get the resolved dependencies
    pub fn resolved_dependencies(&self) -> &HashMap<String, Package> {
        &self.resolved
    }
}

/// CLI integration for version management
pub async fn run_package_version_async(package_name: &str, constraint: &str) -> AsyncResult<String> {
    let version_constraint = VersionConstraint::parse(constraint)
        .map_err(|e| KslError::type_error(e, SourcePosition::new(1, 1)))?;

    let mut registry = PackageRegistry::new();
    let mut resolver = DependencyResolver::new(registry.clone());

    // Create a dummy package to resolve dependencies
    let dummy_package = Package::new(
        "dummy",
        SemVer::new(0, 1, 0),
        vec![(package_name.to_string(), version_constraint)],
        None,
    );

    // Resolve dependencies asynchronously
    resolver.resolve_async(&dummy_package).await?;

    // Format the result
    let mut result = String::new();
    for (name, pkg) in resolver.resolved_dependencies() {
        result.push_str(&format!("{}: {}\n", name, pkg.version));
    }
    Ok(result)
}

// Assume ksl_package.rs, ksl_package_publish.rs, ksl_async.rs, and ksl_errors.rs are in the same crate
mod ksl_package {
    pub use super::{PackageSystem, PackageMetadata};
}

mod ksl_package_publish {
    pub use super::{PackagePublisher, PublishConfig};
}

mod ksl_async {
    pub use super::{AsyncRuntime, AsyncResult};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_semver_parse_and_compare() {
        let v1 = SemVer::parse("1.2.3").unwrap();
        let v2 = SemVer::parse("1.2.4").unwrap();
        assert!(v2 > v1);
    }

    #[tokio::test]
    async fn test_version_constraint() {
        let constraint = VersionConstraint::parse("^1.0.0").unwrap();
        let version = SemVer::parse("1.2.3").unwrap();
        assert!(constraint.satisfies(&version));
    }

    #[tokio::test]
    async fn test_dependency_resolution() {
        let mut registry = PackageRegistry::new();
        registry.publish_async(Package::new(
            "test-lib",
            SemVer::new(1, 0, 0),
            vec![],
            None,
        )).await.unwrap();

        let mut resolver = DependencyResolver::new(registry);
        let package = Package::new(
            "test",
            SemVer::new(1, 0, 0),
            vec![("test-lib".to_string(), VersionConstraint::parse("^1.0.0").unwrap())],
            None,
        );
        resolver.resolve_async(&package).await.unwrap();
        assert!(resolver.resolved_dependencies().contains_key("test-lib"));
    }

    #[tokio::test]
    async fn test_version_conflict() {
        let mut registry = PackageRegistry::new();
        registry.publish_async(Package::new(
            "test-lib",
            SemVer::new(2, 0, 0),
            vec![],
            None,
        )).await.unwrap();

        let mut resolver = DependencyResolver::new(registry);
        let package = Package::new(
            "test",
            SemVer::new(1, 0, 0),
            vec![("test-lib".to_string(), VersionConstraint::parse("^1.0.0").unwrap())],
            None,
        );
        let result = resolver.resolve_async(&package).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No compatible version found"));
    }

    #[tokio::test]
    async fn test_run_package_version_async() {
        let result = run_package_version_async("test-lib", "^1.0.0").await;
        assert!(result.is_ok());
    }
}