// ksl_package_version.rs
// Version management and dependency resolution enhancements for KSL packages

use std::collections::{HashMap, HashSet};
use std::fmt;

/// Represents a semantic version (e.g., 1.2.3).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemVer {
    major: u32,
    minor: u32,
    patch: u32,
}

impl SemVer {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        SemVer { major, minor, patch }
    }

    /// Parse a version string (e.g., "1.2.3").
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

/// Represents a version constraint (e.g., ^1.0.0, >=1.2.0).
#[derive(Debug, Clone)]
pub enum VersionConstraint {
    Exact(SemVer),
    Caret(SemVer),      // ^1.0.0: allows 1.x.x but not 2.0.0
    GreaterEqual(SemVer), // >=1.2.0
    LessThan(SemVer),    // <2.0.0
}

impl VersionConstraint {
    /// Parse a version constraint (e.g., "^1.0.0").
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

    /// Check if a version satisfies the constraint.
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

/// Represents a package with its version and dependencies (aligned with ksl_package.rs).
#[derive(Debug, Clone)]
pub struct Package {
    name: String,
    version: SemVer,
    dependencies: Vec<(String, VersionConstraint)>,
}

impl Package {
    pub fn new(name: &str, version: SemVer, dependencies: Vec<(String, VersionConstraint)>) -> Self {
        Package {
            name: name.to_string(),
            version,
            dependencies,
        }
    }
}

/// Represents the package registry (aligned with ksl_package_publish.rs).
#[derive(Debug, Clone)]
pub struct PackageRegistry {
    packages: HashMap<String, Vec<Package>>, // Map package name to list of versions
}

impl PackageRegistry {
    pub fn new() -> Self {
        PackageRegistry {
            packages: HashMap::new(),
        }
    }

    /// Add a package to the registry (used by ksl_package_publish.rs).
    pub fn publish(&mut self, package: Package) {
        self.packages
            .entry(package.name.clone())
            .or_insert_with(Vec::new)
            .push(package);
    }

    /// Find a package version that satisfies the constraint.
    pub fn find_compatible(&self, name: &str, constraint: &VersionConstraint) -> Option<&Package> {
        self.packages.get(name).and_then(|versions| {
            versions
                .iter()
                .filter(|pkg| constraint.satisfies(&pkg.version))
                .max_by_key(|pkg| &pkg.version) // Pick the latest compatible version
        })
    }
}

/// Dependency resolver for KSL packages (integrates with ksl_package.rs).
pub struct DependencyResolver {
    registry: PackageRegistry,
    resolved: HashMap<String, Package>, // Resolved package versions
    visited: HashSet<String>, // Track visited packages to detect cycles
}

impl DependencyResolver {
    pub fn new(registry: PackageRegistry) -> Self {
        DependencyResolver {
            registry,
            resolved: HashMap::new(),
            visited: HashSet::new(),
        }
    }

    /// Resolve dependencies for a package.
    pub fn resolve(&mut self, package: &Package) -> Result<(), String> {
        let package_key = format!("{}-{}", package.name, package.version);
        if self.visited.contains(&package_key) {
            return Err(format!("Dependency cycle detected for package: {}", package.name));
        }

        self.visited.insert(package_key.clone());

        for (dep_name, constraint) in &package.dependencies {
            if self.resolved.contains_key(dep_name) {
                // Already resolved, check compatibility
                let resolved_pkg = self.resolved.get(dep_name).unwrap();
                if !constraint.satisfies(&resolved_pkg.version) {
                    return Err(format!(
                        "Version conflict for '{}': required {} but found {}",
                        dep_name, constraint, resolved_pkg.version
                    ));
                }
                continue;
            }

            // Find a compatible version in the registry
            let dep_pkg = self.registry.find_compatible(dep_name, constraint)
                .ok_or_else(|| format!("No compatible version found for '{}': {}", dep_name, constraint))?;

            // Recursively resolve the dependency
            self.resolve(dep_pkg)?;

            // Add to resolved packages
            self.resolved.insert(dep_name.clone(), dep_pkg.clone());
        }

        self.visited.remove(&package_key);
        Ok(())
    }

    /// Get the resolved dependencies.
    pub fn resolved_dependencies(&self) -> &HashMap<String, Package> {
        &self.resolved
    }
}

/// CLI integration for `ksl package-version <package> --constraint "^1.0.0"` (used by ksl_cli.rs).
pub fn run_package_version(package_name: &str, constraint: &str) -> Result<String, String> {
    // Parse the constraint
    let version_constraint = VersionConstraint::parse(constraint)?;

    // Create a package registry (simplified, in reality this would query a remote registry)
    let mut registry = PackageRegistry::new();

    // Populate the registry with example packages
    registry.publish(Package::new(
        "blockchain-lib",
        SemVer::new(1, 0, 0),
        vec![],
    ));
    registry.publish(Package::new(
        "blockchain-lib",
        SemVer::new(1, 1, 0),
        vec![("crypto-lib".to_string(), VersionConstraint::parse(">=1.0.0")?)]
    ));
    registry.publish(Package::new(
        "crypto-lib",
        SemVer::new(1, 0, 0),
        vec![],
    ));
    registry.publish(Package::new(
        "ai-model",
        SemVer::new(2, 0, 0),
        vec![("math-lib".to_string(), VersionConstraint::parse("^1.0.0")?)]
    ));
    registry.publish(Package::new(
        "math-lib",
        SemVer::new(1, 0, 0),
        vec![],
    ));
    registry.publish(Package::new(
        "game-physics",
        SemVer::new(1, 2, 0),
        vec![("math-lib".to_string(), VersionConstraint::parse(">=1.0.0")?)]
    ));

    // Create a dummy package to resolve dependencies
    let dummy_package = Package::new(
        "dummy",
        SemVer::new(0, 1, 0),
        vec![(package_name.to_string(), version_constraint.clone())],
    );

    // Resolve dependencies
    let mut resolver = DependencyResolver::new(registry);
    resolver.resolve(&dummy_package)?;

    // Find the resolved version of the requested package
    let resolved_pkg = resolver.resolved_dependencies().get(package_name)
        .ok_or_else(|| format!("Package '{}' not found with constraint '{}'", package_name, constraint))?;

    Ok(format!("Resolved '{}': {}", package_name, resolved_pkg.version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semver_parse_and_compare() {
        let v1 = SemVer::parse("1.0.0").unwrap();
        let v2 = SemVer::parse("1.1.0").unwrap();
        assert_eq!(v1, SemVer::new(1, 0, 0));
        assert!(v1 < v2);
    }

    #[test]
    fn test_version_constraint() {
        let constraint = VersionConstraint::parse("^1.0.0").unwrap();
        let v1 = SemVer::parse("1.0.0").unwrap();
        let v2 = SemVer::parse("1.1.0").unwrap();
        let v3 = SemVer::parse("2.0.0").unwrap();
        assert!(constraint.satisfies(&v1));
        assert!(constraint.satisfies(&v2));
        assert!(!constraint.satisfies(&v3));
    }

    #[test]
    fn test_dependency_resolution() {
        let mut registry = PackageRegistry::new();
        registry.publish(Package::new(
            "lib-a",
            SemVer::new(1, 0, 0),
            vec![("lib-b".to_string(), VersionConstraint::parse(">=1.0.0").unwrap())],
        ));
        registry.publish(Package::new(
            "lib-b",
            SemVer::new(1, 0, 0),
            vec![],
        ));

        let package = Package::new(
            "app",
            SemVer::new(0, 1, 0),
            vec![("lib-a".to_string(), VersionConstraint::parse("^1.0.0").unwrap())],
        );

        let mut resolver = DependencyResolver::new(registry);
        assert!(resolver.resolve(&package).is_ok());
        assert_eq!(resolver.resolved.get("lib-a").unwrap().version, SemVer::new(1, 0, 0));
        assert_eq!(resolver.resolved.get("lib-b").unwrap().version, SemVer::new(1, 0, 0));
    }

    #[test]
    fn test_version_conflict() {
        let mut registry = PackageRegistry::new();
        registry.publish(Package::new(
            "lib-a",
            SemVer::new(1, 0, 0),
            vec![("lib-b".to_string(), VersionConstraint::parse(">=1.0.0").unwrap())],
        ));
        registry.publish(Package::new(
            "lib-b",
            SemVer::new(1, 0, 0),
            vec![],
        ));

        let package = Package::new(
            "app",
            SemVer::new(0, 1, 0),
            vec![
                ("lib-a".to_string(), VersionConstraint::parse("^1.0.0").unwrap()),
                ("lib-b".to_string(), VersionConstraint::parse("<1.0.0").unwrap()),
            ],
        );

        let mut resolver = DependencyResolver::new(registry);
        assert!(resolver.resolve(&package).is_err());
    }

    #[test]
    fn test_run_package_version() {
        let result = run_package_version("blockchain-lib", "^1.0.0");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Resolved 'blockchain-lib': 1.1.0");
    }
}