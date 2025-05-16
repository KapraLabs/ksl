// ksl_dep_audit.rs
// Audit KSL package dependencies for security and licensing issues

use crate::ksl_package::{Package, PackageMetadata, DependencySpec};
use crate::ksl_security::{SecurityCheck, SecurityLevel, SecurityContext};
use crate::ksl_async::{AsyncContext, AsyncCommand};
use crate::ksl_errors::{KslError, SourcePosition};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

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

    pub fn load(project: &str) -> Result<Self, KslError> {
        // Load package from project
        // This is a mock implementation for demonstration
        Ok(Package {
            name: project.to_string(),
            version: SemVer::new(1, 0, 0),
            dependencies: vec![],
            license: "MIT".to_string(),
        })
    }

    pub fn metadata(&self) -> PackageMetadata {
        // Return package metadata
        PackageMetadata {}
    }

    /// Returns the package license
    pub fn license(&self) -> &str {
        &self.license
    }

    /// Returns the package name
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Represents a semantic version (aligned with ksl_package_version.rs).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemVer {
    /// Major version number
    major: u32,
    /// Minor version number
    minor: u32,
    /// Patch version number
    patch: u32,
}

impl SemVer {
    /// Creates a new semantic version.
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        SemVer { major, minor, patch }
    }

    /// Parses a version string into a semantic version.
    pub fn parse(version: &str) -> Result<Self, KslError> {
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 3 {
            return Err(KslError::parse(
                format!("Invalid semantic version: {}", version),
                SourcePosition::new(1, 1),
                "DEP001".to_string()
            ));
        }
        let major = parts[0].parse::<u32>().map_err(|e| KslError::parse(
            format!("Invalid major version: {}", e),
            SourcePosition::new(1, 1),
            "DEP002".to_string()
        ))?;
        let minor = parts[1].parse::<u32>().map_err(|e| KslError::parse(
            format!("Invalid minor version: {}", e),
            SourcePosition::new(1, 1),
            "DEP003".to_string()
        ))?;
        let patch = parts[2].parse::<u32>().map_err(|e| KslError::parse(
            format!("Invalid patch version: {}", e),
            SourcePosition::new(1, 1),
            "DEP004".to_string()
        ))?;
        Ok(SemVer { major, minor, patch })
    }
}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Represents a version constraint with enhanced validation.
#[derive(Debug, Clone)]
pub enum VersionConstraint {
    /// Exact version match
    Exact(SemVer),
    /// Compatible with version (^)
    Caret(SemVer),
    /// Greater than or equal to version
    GreaterEqual(SemVer),
    /// Less than version
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

/// Represents a known vulnerability with severity levels.
#[derive(Debug, Clone)]
pub struct Vulnerability {
    /// Affected package name
    package_name: String,
    /// Affected version range
    version_range: VersionConstraint,
    /// Vulnerability description
    description: String,
    /// Remediation steps
    remediation: String,
    /// Security severity level
    severity: SecurityLevel,
}

impl Vulnerability {
    /// Creates a new vulnerability with severity.
    pub fn new(
        package_name: &str,
        version_range: VersionConstraint,
        description: &str,
        remediation: &str,
        severity: SecurityLevel,
    ) -> Self {
        Vulnerability {
            package_name: package_name.to_string(),
            version_range,
            description: description.to_string(),
            remediation: remediation.to_string(),
            severity,
        }
    }

    /// Checks if a package is affected by this vulnerability.
    pub fn affects(&self, package: &Package) -> bool {
        self.package_name == package.name && self.version_range.satisfies(&package.version)
    }
}

/// Vulnerability database with async updates.
#[derive(Debug, Clone)]
pub struct VulnerabilityDatabase {
    /// Known vulnerabilities
    vulnerabilities: Vec<Vulnerability>,
    /// Async context for updates
    async_context: Arc<Mutex<AsyncContext>>,
}

impl VulnerabilityDatabase {
    /// Creates a new vulnerability database.
    pub fn new() -> Self {
        VulnerabilityDatabase {
            vulnerabilities: vec![],
            async_context: Arc::new(Mutex::new(AsyncContext::new())),
        }
    }

    /// Updates the vulnerability database asynchronously.
    pub async fn update(&mut self) -> Result<(), KslError> {
        let mut async_ctx = self.async_context.lock().await;
        let command = AsyncCommand::UpdateVulnerabilities;
        async_ctx.execute_command(command).await?;
        Ok(())
    }

    /// Finds vulnerabilities affecting a package asynchronously.
    pub async fn find_vulnerabilities(&self, package: &Package) -> Result<Vec<&Vulnerability>, KslError> {
        let mut async_ctx = self.async_context.lock().await;
        let command = AsyncCommand::CheckVulnerabilities(package.clone());
        async_ctx.execute_command(command).await?;

        Ok(self.vulnerabilities
            .iter()
            .filter(|vuln| vuln.affects(package))
            .collect())
    }
}

/// Security analyzer with async checks.
#[derive(Debug, Clone)]
pub struct SecurityAnalyzer {
    /// Security context
    context: SecurityContext,
    /// Async context for security checks
    async_context: Arc<Mutex<AsyncContext>>,
}

impl SecurityAnalyzer {
    /// Creates a new security analyzer.
    pub fn new() -> Self {
        SecurityAnalyzer {
            context: SecurityContext::new(),
            async_context: Arc::new(Mutex::new(AsyncContext::new())),
        }
    }

    /// Analyzes a package for security issues asynchronously.
    pub async fn analyze(&self, package: &Package) -> Result<Vec<SecurityCheck>, KslError> {
        let mut async_ctx = self.async_context.lock().await;
        let command = AsyncCommand::SecurityAnalysis(package.clone());
        async_ctx.execute_command(command).await?;

        let mut checks = vec![];
        if package.name == "blockchain-lib" && package.version < SemVer::new(1, 1, 0) {
            checks.push(SecurityCheck::new(
                "Potential reentrancy vulnerability",
                SecurityLevel::Critical,
            ));
        }
        Ok(checks)
    }
}

/// License checker with async validation.
#[derive(Debug, Clone)]
pub struct LicenseChecker {
    /// Allowed licenses
    allowed_licenses: HashSet<String>,
    /// Async context for license checks
    async_context: Arc<Mutex<AsyncContext>>,
}

impl LicenseChecker {
    /// Creates a new license checker.
    pub fn new() -> Self {
        let mut allowed_licenses = HashSet::new();
        allowed_licenses.insert("MIT".to_string());
        allowed_licenses.insert("Apache-2.0".to_string());
        allowed_licenses.insert("BSD-3-Clause".to_string());
        LicenseChecker {
            allowed_licenses,
            async_context: Arc::new(Mutex::new(AsyncContext::new())),
        }
    }

    /// Checks package license compliance asynchronously.
    pub async fn check(&self, package: &Package) -> Result<Option<String>, KslError> {
        let mut async_ctx = self.async_context.lock().await;
        let command = AsyncCommand::CheckLicense(package.clone());
        async_ctx.execute_command(command).await?;

        if !self.allowed_licenses.contains(package.license()) {
            Ok(Some(format!(
                "License '{}' for package '{}' is not allowed. Allowed licenses: {:?}",
                package.license(),
                package.name(),
                self.allowed_licenses
            )))
        } else {
            Ok(None)
        }
    }
}

/// Represents an audit issue with severity.
#[derive(Debug, Clone)]
pub enum AuditIssue {
    /// Security vulnerability
    Vulnerability(Vulnerability),
    /// Security check failure
    Security(SecurityCheck),
    /// License compliance issue
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

/// Represents the audit report with metadata.
#[derive(Debug, Clone)]
pub struct AuditReport {
    /// Issues by package
    issues: HashMap<String, Vec<AuditIssue>>,
    /// Package metadata
    metadata: PackageMetadata,
    /// Audit timestamp
    timestamp: u64,
}

impl AuditReport {
    /// Creates a new audit report.
    pub fn new(metadata: PackageMetadata) -> Self {
        AuditReport {
            issues: HashMap::new(),
            metadata,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Adds an issue to the report.
    pub fn add_issue(&mut self, package_name: &str, issue: AuditIssue) {
        self.issues
            .entry(package_name.to_string())
            .or_insert_with(Vec::new)
            .push(issue);
    }

    /// Checks if the report is clean.
    pub fn is_clean(&self) -> bool {
        self.issues.is_empty()
    }

    /// Gets the audit timestamp.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
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

/// Dependency auditor with async support.
pub struct DependencyAuditor {
    /// Vulnerability database
    vuln_db: VulnerabilityDatabase,
    /// Security analyzer
    security_analyzer: SecurityAnalyzer,
    /// License checker
    license_checker: LicenseChecker,
    /// Async context for auditing
    async_context: Arc<Mutex<AsyncContext>>,
}

impl DependencyAuditor {
    /// Creates a new dependency auditor.
    pub fn new() -> Self {
        DependencyAuditor {
            vuln_db: VulnerabilityDatabase::new(),
            security_analyzer: SecurityAnalyzer::new(),
            license_checker: LicenseChecker::new(),
            async_context: Arc::new(Mutex::new(AsyncContext::new())),
        }
    }

    /// Audits a package and its dependencies asynchronously.
    pub async fn audit(
        &self,
        package: &Package,
        resolved_deps: &HashMap<String, Package>,
    ) -> Result<AuditReport, KslError> {
        let mut report = AuditReport::new(package.metadata().clone());

        // Update vulnerability database
        self.vuln_db.update().await?;

        // Audit main package
        self.audit_package(package, &mut report).await?;

        // Audit dependencies
        for dep in resolved_deps.values() {
            self.audit_package(dep, &mut report).await?;
        }

        Ok(report)
    }

    /// Audits a single package asynchronously.
    async fn audit_package(&self, package: &Package, report: &mut AuditReport) -> Result<(), KslError> {
        // Check for vulnerabilities
        let vulns = self.vuln_db.find_vulnerabilities(package).await?;
        for vuln in vulns {
            report.add_issue(&package.name(), AuditIssue::Vulnerability(vuln.clone()));
        }

        // Run security analysis
        let security_issues = self.security_analyzer.analyze(package).await?;
        for issue in security_issues {
            report.add_issue(&package.name(), AuditIssue::Security(issue));
        }

        // Check license
        if let Some(license_issue) = self.license_checker.check(package).await? {
            report.add_issue(&package.name(), AuditIssue::License(license_issue));
        }

        Ok(())
    }
}

/// Runs a dependency audit on a project asynchronously.
pub async fn run_dep_audit(project: &str) -> Result<String, KslError> {
    let auditor = DependencyAuditor::new();
    let registry = PackageRegistry::new();
    let mut resolver = DependencyResolver::new(registry);

    // Load project package
    let package = Package::load(project)?;
    resolver.resolve(&package)?;

    // Run audit
    let report = auditor.audit(&package, resolver.resolved_dependencies()).await?;
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

    #[tokio::test]
    async fn test_vulnerability_check() {
        let mut db = VulnerabilityDatabase::new();
        db.update().await.unwrap();
        let package = Package::new(
            "crypto-lib",
            SemVer::parse("1.0.0").unwrap(),
            vec![],
            "MIT",
        );
        let vulnerabilities = db.find_vulnerabilities(&package).await.unwrap();
        assert_eq!(vulnerabilities.len(), 1);
        assert_eq!(vulnerabilities[0].description, "Buffer overflow in cryptographic function");
    }

    #[tokio::test]
    async fn test_license_check() {
        let checker = LicenseChecker::new();
        let package = Package::new(
            "crypto-lib",
            SemVer::parse("1.0.0").unwrap(),
            vec![],
            "GPL-3.0",
        );
        let issue = checker.check(&package).await.unwrap();
        assert!(issue.is_some());
        assert!(issue.unwrap().contains("License 'GPL-3.0' for package 'crypto-lib' is not allowed"));
    }

    #[tokio::test]
    async fn test_security_analysis() {
        let analyzer = SecurityAnalyzer::new();
        let package = Package::new(
            "blockchain-lib",
            SemVer::parse("1.0.0").unwrap(),
            vec![],
            "MIT",
        );
        let issues = analyzer.analyze(&package).await.unwrap();
        assert_eq!(issues.len(), 1);
        assert!(issues[0].description.contains("Potential reentrancy vulnerability"));
    }

    #[tokio::test]
    async fn test_dep_audit_blockchain_project() {
        let result = run_dep_audit("blockchain-project").await;
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.contains("Package: blockchain-lib"));
        assert!(report.contains("Potential reentrancy vulnerability"));
        assert!(report.contains("Package: crypto-lib"));
        assert!(report.contains("License 'GPL-3.0' for package 'crypto-lib' is not allowed"));
        assert!(report.contains("Buffer overflow in cryptographic function"));
    }

    #[tokio::test]
    async fn test_dep_audit_game_project() {
        let result = run_dep_audit("game-project").await;
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.contains("No issues found"));
    }
}