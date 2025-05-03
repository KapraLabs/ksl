// ksl_dep_audit.rs
// Audit KSL package dependencies for security and licensing issues

use std::collections::{HashMap, HashSet};
use std::fmt;

/// Represents a package with its version and dependencies (aligned with ksl_package.rs and ksl_package_version.rs).
#[derive(Debug, Clone)]
pub struct Package {
    name: String,
    version: SemVer,
    dependencies: Vec<(String, VersionConstraint)>,
    license: String, // License of the package (e.g., "MIT", "Apache-2.0")
}

impl Package {
    pub fn new(name: &str, version: SemVer, dependencies: Vec<(String, VersionConstraint)>, license: &str) -> Self {
        Package {
            name: name.to_string(),
            version,
            dependencies,
            license: license.to_string(),
        }
    }
}

/// Represents a semantic version (aligned with ksl_package_version.rs).
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

/// Represents a version constraint (aligned with ksl_package_version.rs).
#[derive(Debug, Clone)]
pub enum VersionConstraint {
    Exact(SemVer),
    Caret(SemVer),
    GreaterEqual(SemVer),
    LessThan(SemVer),
}

impl VersionConstraint {
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

    pub fn satisfies(&self, version: &SemVer) -> bool {
        match self {
            VersionConstraint::Exact(v) => version == v,
            VersionConstraint::Caret(v) => version.major == v.major && version >= v,
            VersionConstraint::GreaterEqual(v) => version >= v,
            VersionConstraint::LessThan(v) => version < v,
        }
    }
}

/// Represents a known vulnerability.
#[derive(Debug, Clone)]
pub struct Vulnerability {
    package_name: String,
    version_range: VersionConstraint,
    description: String,
    remediation: String,
}

impl Vulnerability {
    pub fn new(package_name: &str, version_range: VersionConstraint, description: &str, remediation: &str) -> Self {
        Vulnerability {
            package_name: package_name.to_string(),
            version_range,
            description: description.to_string(),
            remediation: remediation.to_string(),
        }
    }

    pub fn affects(&self, package: &Package) -> bool {
        self.package_name == package.name && self.version_range.satisfies(&package.version)
    }
}

/// Simulated vulnerability database.
#[derive(Debug, Clone)]
pub struct VulnerabilityDatabase {
    vulnerabilities: Vec<Vulnerability>,
}

impl VulnerabilityDatabase {
    pub fn new() -> Self {
        let mut db = VulnerabilityDatabase {
            vulnerabilities: vec![],
        };
        // Populate with example vulnerabilities
        db.vulnerabilities.push(Vulnerability::new(
            "crypto-lib",
            VersionConstraint::parse("<1.1.0").unwrap(),
            "Buffer overflow in cryptographic function",
            "Upgrade to version 1.1.0 or higher",
        ));
        db.vulnerabilities.push(Vulnerability::new(
            "math-lib",
            VersionConstraint::parse("=1.0.0").unwrap(),
            "Integer overflow in matrix multiplication",
            "Upgrade to version 1.0.1 or higher",
        ));
        db
    }

    pub fn find_vulnerabilities(&self, package: &Package) -> Vec<&Vulnerability> {
        self.vulnerabilities
            .iter()
            .filter(|vuln| vuln.affects(package))
            .collect()
    }
}

/// Security analyzer (aligned with ksl_security.rs).
#[derive(Debug, Clone)]
pub struct SecurityAnalyzer {
    // Placeholder for security analysis configuration
}

impl SecurityAnalyzer {
    pub fn new() -> Self {
        SecurityAnalyzer {}
    }

    pub fn analyze(&self, package: &Package) -> Vec<String> {
        let mut issues = vec![];
        // Simplified security analysis (e.g., check for known risky patterns)
        if package.name == "blockchain-lib" && package.version < SemVer::new(1, 1, 0) {
            issues.push("Potential reentrancy vulnerability in blockchain-lib < 1.1.0".to_string());
        }
        issues
    }
}

/// License compliance checker.
#[derive(Debug, Clone)]
pub struct LicenseChecker {
    allowed_licenses: HashSet<String>,
}

impl LicenseChecker {
    pub fn new() -> Self {
        let mut allowed_licenses = HashSet::new();
        allowed_licenses.insert("MIT".to_string());
        allowed_licenses.insert("Apache-2.0".to_string());
        allowed_licenses.insert("BSD-3-Clause".to_string());
        LicenseChecker { allowed_licenses }
    }

    pub fn check(&self, package: &Package) -> Option<String> {
        if !self.allowed_licenses.contains(&package.license) {
            Some(format!(
                "License '{}' for package '{}' is not allowed. Allowed licenses: {:?}", 
                package.license, package.name, self.allowed_licenses
            ))
        } else {
            None
        }
    }
}

/// Represents an audit issue (vulnerability, security, or licensing).
#[derive(Debug, Clone)]
pub enum AuditIssue {
    Vulnerability(Vulnerability),
    Security(String),
    License(String),
}

impl fmt::Display for AuditIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditIssue::Vulnerability(vuln) => write!(
                f,
                "Vulnerability in {}: {}\nRemediation: {}",
                vuln.package_name, vuln.description, vuln.remediation
            ),
            AuditIssue::Security(issue) => write!(f, "Security Issue: {}", issue),
            AuditIssue::License(issue) => write!(f, "License Issue: {}", issue),
        }
    }
}

/// Represents the audit report.
#[derive(Debug, Clone)]
pub struct AuditReport {
    issues: HashMap<String, Vec<AuditIssue>>, // Map package name to list of issues
}

impl AuditReport {
    pub fn new() -> Self {
        AuditReport {
            issues: HashMap::new(),
        }
    }

    pub fn add_issue(&mut self, package_name: &str, issue: AuditIssue) {
        self.issues
            .entry(package_name.to_string())
            .or_insert_with(Vec::new)
            .push(issue);
    }

    pub fn is_clean(&self) -> bool {
        self.issues.is_empty()
    }
}

impl fmt::Display for AuditReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.issues.is_empty() {
            write!(f, "No issues found. All dependencies are safe and compliant.")
        } else {
            writeln!(f, "Dependency Audit Report")?;
            writeln!(f, "=====================")?;
            for (package_name, issues) in &self.issues {
                writeln!(f, "Package: {}", package_name)?;
                for issue in issues {
                    writeln!(f, "- {}", issue)?;
                }
                writeln!(f)?;
            }
            Ok(())
        }
    }
}

/// Dependency auditor for KSL packages.
pub struct DependencyAuditor {
    vuln_db: VulnerabilityDatabase,
    security_analyzer: SecurityAnalyzer,
    license_checker: LicenseChecker,
}

impl DependencyAuditor {
    pub fn new() -> Self {
        DependencyAuditor {
            vuln_db: VulnerabilityDatabase::new(),
            security_analyzer: SecurityAnalyzer::new(),
            license_checker: LicenseChecker::new(),
        }
    }

    /// Audit a package and its dependencies.
    pub fn audit(&self, package: &Package, resolved_deps: &HashMap<String, Package>) -> AuditReport {
        let mut report = AuditReport::new();

        // Audit the root package
        self.audit_package(package, &mut report);

        // Audit all resolved dependencies
        for dep in resolved_deps.values() {
            self.audit_package(dep, &mut report);
        }

        report
    }

    fn audit_package(&self, package: &Package, report: &mut AuditReport) {
        // Check for known vulnerabilities
        let vulnerabilities = self.vuln_db.find_vulnerabilities(package);
        for vuln in vulnerabilities {
            report.add_issue(&package.name, AuditIssue::Vulnerability(vuln.clone()));
        }

        // Perform security analysis
        let security_issues = self.security_analyzer.analyze(package);
        for issue in security_issues {
            report.add_issue(&package.name, AuditIssue::Security(issue));
        }

        // Check license compliance
        if let Some(license_issue) = self.license_checker.check(package) {
            report.add_issue(&package.name, AuditIssue::License(license_issue));
        }
    }
}

/// CLI integration for `ksl dep-audit <project>` (used by ksl_cli.rs).
pub fn run_dep_audit(project: &str) -> Result<String, String> {
    // Create a package registry (simplified, in reality this would query a remote registry)
    let mut registry = PackageRegistry::new();

    // Populate the registry with example packages
    registry.publish(Package::new(
        "blockchain-lib",
        SemVer::parse("1.0.0").unwrap(),
        vec![("crypto-lib".to_string(), VersionConstraint::parse(">=1.0.0").unwrap())],
        "MIT",
    ));
    registry.publish(Package::new(
        "blockchain-lib",
        SemVer::parse("1.1.0").unwrap(),
        vec![("crypto-lib".to_string(), VersionConstraint::parse(">=1.0.0").unwrap())],
        "MIT",
    ));
    registry.publish(Package::new(
        "crypto-lib",
        SemVer::parse("1.0.0").unwrap(),
        vec![],
        "GPL-3.0", // Incompatible license
    ));
    registry.publish(Package::new(
        "ai-model",
        SemVer::parse("2.0.0").unwrap(),
        vec![("math-lib".to_string(), VersionConstraint::parse("^1.0.0").unwrap())],
        "Apache-2.0",
    ));
    registry.publish(Package::new(
        "math-lib",
        SemVer::parse("1.0.0").unwrap(),
        vec![],
        "MIT",
    ));
    registry.publish(Package::new(
        "game-physics",
        SemVer::parse("1.2.0").unwrap(),
        vec![("math-lib".to_string(), VersionConstraint::parse(">=1.0.0").unwrap())],
        "BSD-3-Clause",
    ));

    // Create a project package based on the input
    let project_package = match project {
        "blockchain-project" => Package::new(
            "blockchain-project",
            SemVer::parse("0.1.0").unwrap(),
            vec![("blockchain-lib".to_string(), VersionConstraint::parse("^1.0.0").unwrap())],
            "MIT",
        ),
        "ai-project" => Package::new(
            "ai-project",
            SemVer::parse("0.1.0").unwrap(),
            vec![("ai-model".to_string(), VersionConstraint::parse("^2.0.0").unwrap())],
            "Apache-2.0",
        ),
        "game-project" => Package::new(
            "game-project",
            SemVer::parse("0.1.0").unwrap(),
            vec![("game-physics".to_string(), VersionConstraint::parse("^1.0.0").unwrap())],
            "BSD-3-Clause",
        ),
        _ => return Err(format!("Unknown project: {}", project)),
    };

    // Resolve dependencies (aligned with ksl_package.rs and ksl_package_version.rs)
    let mut resolver = PackageRegistry::new();
    for pkg in registry.packages.values().flatten() {
        resolver.publish(pkg.clone());
    }
    let mut dep_resolver = DependencyResolver::new(resolver);
    dep_resolver.resolve(&project_package)?;

    // Run the audit
    let auditor = DependencyAuditor::new();
    let report = auditor.audit(&project_package, dep_resolver.resolved_dependencies());
    Ok(report.to_string())
}

/// Package registry and dependency resolver (aligned with ksl_package.rs and ksl_package_version.rs).
#[derive(Debug, Clone)]
struct PackageRegistry {
    packages: HashMap<String, Vec<Package>>,
}

impl PackageRegistry {
    pub fn new() -> Self {
        PackageRegistry {
            packages: HashMap::new(),
        }
    }

    pub fn publish(&mut self, package: Package) {
        self.packages
            .entry(package.name.clone())
            .or_insert_with(Vec::new)
            .push(package);
    }
}

struct DependencyResolver {
    registry: PackageRegistry,
    resolved: HashMap<String, Package>,
    visited: HashSet<String>,
}

impl DependencyResolver {
    pub fn new(registry: PackageRegistry) -> Self {
        DependencyResolver {
            registry,
            resolved: HashMap::new(),
            visited: HashSet::new(),
        }
    }

    pub fn resolve(&mut self, package: &Package) -> Result<(), String> {
        let package_key = format!("{}-{}", package.name, package.version);
        if self.visited.contains(&package_key) {
            return Err(format!("Dependency cycle detected for package: {}", package.name));
        }

        self.visited.insert(package_key.clone());

        for (dep_name, constraint) in &package.dependencies {
            if self.resolved.contains_key(dep_name) {
                continue;
            }

            let dep_pkg = self.registry.find_compatible(dep_name, constraint)
                .ok_or_else(|| format!("No compatible version found for '{}': {}", dep_name, constraint))?;
            self.resolve(dep_pkg)?;
            self.resolved.insert(dep_name.clone(), dep_pkg.clone());
        }

        self.visited.remove(&package_key);
        Ok(())
    }

    pub fn resolved_dependencies(&self) -> &HashMap<String, Package> {
        &self.resolved
    }

    fn find_compatible(&self, name: &str, constraint: &VersionConstraint) -> Option<&Package> {
        self.packages.get(name).and_then(|versions| {
            versions
                .iter()
                .filter(|pkg| constraint.satisfies(&pkg.version))
                .max_by_key(|pkg| &pkg.version)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerability_check() {
        let vuln_db = VulnerabilityDatabase::new();
        let package = Package::new(
            "crypto-lib",
            SemVer::parse("1.0.0").unwrap(),
            vec![],
            "MIT",
        );
        let vulnerabilities = vuln_db.find_vulnerabilities(&package);
        assert_eq!(vulnerabilities.len(), 1);
        assert_eq!(vulnerabilities[0].description, "Buffer overflow in cryptographic function");
    }

    #[test]
    fn test_license_check() {
        let checker = LicenseChecker::new();
        let package = Package::new(
            "crypto-lib",
            SemVer::parse("1.0.0").unwrap(),
            vec![],
            "GPL-3.0",
        );
        let issue = checker.check(&package);
        assert!(issue.is_some());
        assert!(issue.unwrap().contains("License 'GPL-3.0' for package 'crypto-lib' is not allowed"));
    }

    #[test]
    fn test_security_analysis() {
        let analyzer = SecurityAnalyzer::new();
        let package = Package::new(
            "blockchain-lib",
            SemVer::parse("1.0.0").unwrap(),
            vec![],
            "MIT",
        );
        let issues = analyzer.analyze(&package);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("Potential reentrancy vulnerability"));
    }

    #[test]
    fn test_dep_audit_blockchain_project() {
        let result = run_dep_audit("blockchain-project");
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.contains("Package: blockchain-lib"));
        assert!(report.contains("Potential reentrancy vulnerability"));
        assert!(report.contains("Package: crypto-lib"));
        assert!(report.contains("License 'GPL-3.0' for package 'crypto-lib' is not allowed"));
        assert!(report.contains("Buffer overflow in cryptographic function"));
    }

    #[test]
    fn test_dep_audit_game_project() {
        let result = run_dep_audit("game-project");
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.contains("No issues found"));
    }
}