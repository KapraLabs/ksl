// ksl_community.rs
// Tools for community governance in Kapra Chain ecosystem

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

/// Represents a package (aligned with ksl_package.rs and ksl_package_version.rs).
#[derive(Debug, Clone)]
pub struct Package {
    name: String,
    version: SemVer,
    dependencies: Vec<(String, VersionConstraint)>,
    license: String,
    contributor: String, // Added for community tracking
}

impl Package {
    pub fn new(name: &str, version: SemVer, dependencies: Vec<(String, VersionConstraint)>, license: &str, contributor: &str) -> Self {
        Package {
            name: name.to_string(),
            version,
            dependencies,
            license: license.to_string(),
            contributor: contributor.to_string(),
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

impl std::fmt::Display for SemVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

/// Package review status.
#[derive(Debug, Clone)]
pub enum ReviewStatus {
    Pending,
    Approved,
    Rejected,
}

/// Package review entry.
#[derive(Debug, Clone)]
pub struct PackageReview {
    package: Package,
    status: ReviewStatus,
    reviewer: String,
    comments: Vec<String>,
}

impl PackageReview {
    pub fn new(package: Package, reviewer: String) -> Self {
        PackageReview {
            package,
            status: ReviewStatus::Pending,
            reviewer,
            comments: vec![],
        }
    }
}

/// Contributor guidelines.
#[derive(Debug, Clone)]
pub struct ContributorGuidelines {
    rules: Vec<String>,
}

impl ContributorGuidelines {
    pub fn new() -> Self {
        ContributorGuidelines {
            rules: vec![
                "All packages must include documentation.".to_string(),
                "Code must follow KSL style guidelines.".to_string(),
                "Packages must pass security audits.".to_string(),
                "Contributors must sign commits.".to_string(),
            ],
        }
    }

    pub fn check_compliance(&self, package: &Package) -> Vec<String> {
        let mut violations = vec![];
        // Simplified checks for demo
        if package.license != "MIT" && package.license != "Apache-2.0" && package.license != "BSD-3-Clause" {
            violations.push(format!("Package '{}' uses unsupported license '{}'.", package.name, package.license));
        }
        if package.dependencies.iter().any(|(dep, _)| dep.contains("unsafe")) {
            violations.push(format!("Package '{}' depends on unsafe libraries.", package.name));
        }
        violations
    }

    pub fn to_string(&self) -> String {
        let mut result = "Kapra Chain Contributor Guidelines\n============================\n".to_string();
        for (i, rule) in self.rules.iter().enumerate() {
            result.push_str(&format!("{}. {}\n", i + 1, rule));
        }
        result
    }
}

/// Voting system for protocol changes.
#[derive(Debug, Clone)]
pub struct Voting {
    proposal: String,
    yes_votes: u32,
    no_votes: u32,
    voters: HashSet<String>,
}

impl Voting {
    pub fn new(proposal: &str) -> Self {
        Voting {
            proposal: proposal.to_string(),
            yes_votes: 0,
            no_votes: 0,
            voters: HashSet::new(),
        }
    }

    pub fn vote(&mut self, voter: &str, vote_yes: bool) -> Result<(), String> {
        if self.voters.contains(voter) {
            return Err(format!("{} has already voted.", voter));
        }
        self.voters.insert(voter.to_string());
        if vote_yes {
            self.yes_votes += 1;
        } else {
            self.no_votes += 1;
        }
        Ok(())
    }

    pub fn result(&self) -> (bool, String) {
        let total_votes = self.yes_votes + self.no_votes;
        if total_votes == 0 {
            return (false, "No votes yet.".to_string());
        }
        let yes_percentage = (self.yes_votes as f32 / total_votes as f32) * 100.0;
        if yes_percentage > 50.0 {
            (true, format!("Proposal '{}' passed with {}% yes votes.", self.proposal, yes_percentage))
        } else {
            (false, format!("Proposal '{}' failed with {}% yes votes.", self.proposal, yes_percentage))
        }
    }
}

/// Community governance system for Kapra Chain.
#[derive(Debug)]
pub struct Community {
    reviews: HashMap<String, PackageReview>,
    guidelines: ContributorGuidelines,
    voting: HashMap<String, Voting>,
    registry: HashMap<String, Vec<Package>>, // Aligned with ksl_package_publish.rs
}

impl Community {
    pub fn new() -> Self {
        Community {
            reviews: HashMap::new(),
            guidelines: ContributorGuidelines::new(),
            voting: HashMap::new(),
            registry: HashMap::new(),
        }
    }

    /// Submit a package for review.
    pub fn submit_package(&mut self, package: Package, reviewer: &str) -> Result<(), String> {
        let package_key = format!("{}-{}", package.name, package.version);
        if self.reviews.contains_key(&package_key) {
            return Err(format!("Package '{}' is already under review.", package_key));
        }

        // Check compliance with guidelines
        let violations = self.guidelines.check_compliance(&package);
        if !violations.is_empty() {
            return Err(format!("Package '{}' violates contributor guidelines:\n{}", package_key, violations.join("\n")));
        }

        self.reviews.insert(package_key.clone(), PackageReview::new(package, reviewer.to_string()));
        Ok(())
    }

    /// Review a package.
    pub fn review_package(&mut self, package_name: &str, version: &str, approve: bool, comment: Option<&str>) -> Result<(), String> {
        let package_key = format!("{}-{}", package_name, version);
        let review = self.reviews.get_mut(&package_key)
            .ok_or_else(|| format!("Package '{}' not found for review.", package_key))?;

        if let Some(comment) = comment {
            review.comments.push(comment.to_string());
        }

        review.status = if approve { ReviewStatus::Approved } else { ReviewStatus::Rejected };

        // If approved, publish to registry (aligned with ksl_package_publish.rs)
        if matches!(review.status, ReviewStatus::Approved) {
            let package = review.package.clone();
            self.registry
                .entry(package.name.clone())
                .or_insert_with(Vec::new)
                .push(package);
        }

        Ok(())
    }

    /// Start a new vote for a protocol change.
    pub fn start_vote(&mut self, proposal: &str) -> Result<(), String> {
        if self.voting.contains_key(proposal) {
            return Err(format!("Proposal '{}' already exists.", proposal));
        }
        self.voting.insert(proposal.to_string(), Voting::new(proposal));
        Ok(())
    }

    /// Cast a vote on a proposal.
    pub fn cast_vote(&mut self, proposal: &str, voter: &str, vote_yes: bool) -> Result<String, String> {
        let vote = self.voting.get_mut(proposal)
            .ok_or_else(|| format!("Proposal '{}' not found.", proposal))?;
        vote.vote(voter, vote_yes)?;
        let (passed, message) = vote.result();
        Ok(format!("Vote recorded. Current result: {}", message))
    }

    /// Display contributor guidelines.
    pub fn display_guidelines(&self) -> String {
        self.guidelines.to_string()
    }

    /// Generate a review report.
    pub fn generate_review_report(&self) -> String {
        let mut report = "Kapra Chain Package Review Report\n============================\n\n".to_string();
        if self.reviews.is_empty() {
            report.push_str("No packages under review.\n");
        } else {
            report.push_str(&format!("Total packages under review: {}\n\n", self.reviews.len()));
            for (package_key, review) in &self.reviews {
                report.push_str(&format!(
                    "Package: {}\n  Status: {:?}\n  Reviewer: {}\n  Comments: {}\n\n",
                    package_key,
                    review.status,
                    review.reviewer,
                    if review.comments.is_empty() { "None".to_string() } else { review.comments.join("\n") }
                ));
            }
        }
        report
    }
}

/// CLI integration for community governance (used by ksl_cli.rs).
pub fn run_community_command(command: &str, args: Vec<&str>) -> Result<String, String> {
    let mut community = Community::new();

    match command {
        "submit" => {
            if args.len() != 3 {
                return Err("Usage: ksl community submit <package> <version> <reviewer>".to_string());
            }
            let package_name = args[0];
            let version = SemVer::parse(args[1])?;
            let reviewer = args[2];
            let package = Package::new(
                package_name,
                version,
                vec![],
                "MIT",
                reviewer,
            );
            community.submit_package(package, reviewer)?;
            Ok(format!("Package '{}-{}' submitted for review by {}.", package_name, version, reviewer))
        }
        "review" => {
            if args.len() < 3 || args.len() > 4 {
                return Err("Usage: ksl community review <package> <version> <approve|reject> [comment]".to_string());
            }
            let package_name = args[0];
            let version = args[1];
            let approve = match args[2] {
                "approve" => true,
                "reject" => false,
                _ => return Err("Review action must be 'approve' or 'reject'.".to_string()),
            };
            let comment = if args.len() == 4 { Some(args[3]) } else { None };
            community.submit_package(
                Package::new(package_name, SemVer::parse(version)?, vec![], "MIT", "test_contributor"),
                "test_reviewer",
            )?;
            community.review_package(package_name, version, approve, comment)?;
            let report = community.generate_review_report();
            Ok(format!("Package '{}-{}' reviewed.\n\n{}", package_name, version, report))
        }
        "guidelines" => {
            Ok(community.display_guidelines())
        }
        "vote" => {
            if args.len() != 3 {
                return Err("Usage: ksl community vote <proposal> <voter> <yes|no>".to_string());
            }
            let proposal = args[0];
            let voter = args[1];
            let vote_yes = match args[2] {
                "yes" => true,
                "no" => false,
                _ => return Err("Vote must be 'yes' or 'no'.".to_string()),
            };
            community.start_vote(proposal)?;
            community.cast_vote(proposal, voter, vote_yes)
        }
        _ => Err(format!("Unknown community command: {}", command)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_submission() {
        let mut community = Community::new();
        let package = Package::new(
            "test-package",
            SemVer::new(1, 0, 0),
            vec![],
            "MIT",
            "contributor1",
        );
        let result = community.submit_package(package, "reviewer1");
        assert!(result.is_ok());
        assert!(community.reviews.contains_key("test-package-1.0.0"));
    }

    #[test]
    fn test_package_review_approve() {
        let mut community = Community::new();
        let package = Package::new(
            "test-package",
            SemVer::new(1, 0, 0),
            vec![],
            "MIT",
            "contributor1",
        );
        community.submit_package(package.clone(), "reviewer1").unwrap();
        let result = community.review_package("test-package", "1.0.0", true, Some("Looks good."));
        assert!(result.is_ok());
        let review = community.reviews.get("test-package-1.0.0").unwrap();
        assert!(matches!(review.status, ReviewStatus::Approved));
        assert_eq!(review.comments, vec!["Looks good."]);
        assert!(community.registry.get("test-package").unwrap().contains(&package));
    }

    #[test]
    fn test_package_review_reject() {
        let mut community = Community::new();
        let package = Package::new(
            "test-package",
            SemVer::new(1, 0, 0),
            vec![],
            "MIT",
            "contributor1",
        );
        community.submit_package(package, "reviewer1").unwrap();
        let result = community.review_package("test-package", "1.0.0", false, Some("Needs documentation."));
        assert!(result.is_ok());
        let review = community.reviews.get("test-package-1.0.0").unwrap();
        assert!(matches!(review.status, ReviewStatus::Rejected));
        assert_eq!(review.comments, vec!["Needs documentation."]);
        assert!(!community.registry.contains_key("test-package"));
    }

    #[test]
    fn test_guidelines_check() {
        let mut community = Community::new();
        let package = Package::new(
            "test-package",
            SemVer::new(1, 0, 0),
            vec![("unsafe-lib".to_string(), VersionConstraint::parse("^1.0.0").unwrap())],
            "GPL-3.0",
            "contributor1",
        );
        let result = community.submit_package(package, "reviewer1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("uses unsupported license"));
        assert!(result.unwrap_err().contains("depends on unsafe libraries"));
    }

    #[test]
    fn test_voting() {
        let mut community = Community::new();
        community.start_vote("Upgrade consensus").unwrap();
        community.cast_vote("Upgrade consensus", "voter1", true).unwrap();
        community.cast_vote("Upgrade consensus", "voter2", false).unwrap();
        let vote = community.voting.get("Upgrade consensus").unwrap();
        let (passed, message) = vote.result();
        assert!(!passed);
        assert!(message.contains("failed with 50.0% yes votes"));
    }

    #[test]
    fn test_double_voting() {
        let mut community = Community::new();
        community.start_vote("Upgrade consensus").unwrap();
        community.cast_vote("Upgrade consensus", "voter1", true).unwrap();
        let result = community.cast_vote("Upgrade consensus", "voter1", false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("has already voted"));
    }
}