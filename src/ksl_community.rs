// ksl_community.rs
// Tools for community governance in Kapra Chain ecosystem

use crate::ksl_stdlib_net::{Networking, HttpRequest, HttpResponse, WebSocket};
use crate::ksl_cli::{CliCommand, CliContext};
use crate::ksl_async::{AsyncContext, AsyncCommand};
use crate::ksl_errors::{KslError, SourcePosition};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Represents a package in the community system.
#[derive(Debug, Clone)]
pub struct Package {
    /// Package name
    name: String,
    /// Package version
    version: SemVer,
    /// Package dependencies
    dependencies: Vec<(String, VersionConstraint)>,
    /// Package license
    license: String,
    /// Package contributor
    contributor: String,
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

/// Package review status with notifications.
#[derive(Debug, Clone)]
pub enum ReviewStatus {
    /// Pending review
    Pending,
    /// Approved by reviewer
    Approved,
    /// Rejected with reason
    Rejected(String),
}

/// Package review entry with async notifications.
#[derive(Debug, Clone)]
pub struct PackageReview {
    /// Package being reviewed
    package: Package,
    /// Review status
    status: ReviewStatus,
    /// Reviewer identifier
    reviewer: String,
    /// Review comments
    comments: Vec<String>,
    /// Async context for notifications
    async_context: Arc<Mutex<AsyncContext>>,
}

impl PackageReview {
    /// Creates a new package review.
    pub fn new(package: Package, reviewer: String) -> Self {
        PackageReview {
            package,
            status: ReviewStatus::Pending,
            reviewer,
            comments: vec![],
            async_context: Arc::new(Mutex::new(AsyncContext::new())),
        }
    }

    /// Adds a comment to the review asynchronously.
    pub async fn add_comment(&mut self, comment: String) -> Result<(), KslError> {
        let mut async_ctx = self.async_context.lock().await;
        let command = AsyncCommand::NotifyReviewComment {
            package: self.package.name.clone(),
            comment: comment.clone(),
        };
        async_ctx.execute_command(command).await?;
        self.comments.push(comment);
        Ok(())
    }
}

/// Contributor guidelines with real-time updates.
#[derive(Debug, Clone)]
pub struct ContributorGuidelines {
    /// Guideline rules
    rules: Vec<String>,
    /// Networking for updates
    networking: Networking,
}

impl ContributorGuidelines {
    /// Creates new contributor guidelines.
    pub fn new() -> Self {
        ContributorGuidelines {
            rules: vec![
                "All packages must include documentation.".to_string(),
                "Code must follow KSL style guidelines.".to_string(),
                "Packages must pass security audits.".to_string(),
                "Contributors must sign commits.".to_string(),
            ],
            networking: Networking::new(),
        }
    }

    /// Updates guidelines from remote source asynchronously.
    pub async fn update(&mut self) -> Result<(), KslError> {
        let request = HttpRequest::new("https://ksl.dev/guidelines".to_string());
        let response = self.networking.http_get(request).await?;
        
        if response.status_code != 200 {
            return Err(KslError::network(
                format!("Failed to fetch guidelines: HTTP {}", response.status_code),
                SourcePosition::new(1, 1),
                "E401".to_string()
            ));
        }

        // Parse and update rules
        self.rules = response.body.lines()
            .map(|line| line.to_string())
            .collect();
        Ok(())
    }

    /// Checks package compliance with guidelines asynchronously.
    pub async fn check_compliance(&self, package: &Package) -> Result<Vec<String>, KslError> {
        let request = HttpRequest::new(format!(
            "https://ksl.dev/compliance/check/{}", 
            package.name
        ));
        let response = self.networking.http_get(request).await?;

        if response.status_code != 200 {
            return Err(KslError::network(
                format!("Failed to check compliance: HTTP {}", response.status_code),
                SourcePosition::new(1, 1),
                "E401".to_string()
            ));
        }

        let mut violations = vec![];
        if package.license != "MIT" && package.license != "Apache-2.0" && package.license != "BSD-3-Clause" {
            violations.push(format!("Package '{}' uses unsupported license '{}'.", package.name, package.license));
        }
        if package.dependencies.iter().any(|(dep, _)| dep.contains("unsafe")) {
            violations.push(format!("Package '{}' depends on unsafe libraries.", package.name));
        }
        Ok(violations)
    }
}

/// Voting system with real-time updates.
#[derive(Debug, Clone)]
pub struct Voting {
    /// Proposal being voted on
    proposal: String,
    /// Yes votes count
    yes_votes: u32,
    /// No votes count
    no_votes: u32,
    /// Set of voters
    voters: HashSet<String>,
    /// WebSocket for real-time updates
    websocket: WebSocket,
}

impl Voting {
    /// Creates a new voting session.
    pub fn new(proposal: &str) -> Self {
        Voting {
            proposal: proposal.to_string(),
            yes_votes: 0,
            no_votes: 0,
            voters: HashSet::new(),
            websocket: WebSocket::new("wss://ksl.dev/voting"),
        }
    }

    /// Casts a vote asynchronously.
    pub async fn vote(&mut self, voter: &str, vote_yes: bool) -> Result<(), KslError> {
        if self.voters.contains(voter) {
            return Err(KslError::validation_error(
                format!("{} has already voted.", voter),
                SourcePosition::new(1, 1),
                "E501".to_string()
            ));
        }

        // Send vote through WebSocket
        let vote_msg = format!("{{\"voter\": \"{}\", \"vote\": {}}}", voter, vote_yes);
        self.websocket.send(&vote_msg).await?;

        self.voters.insert(voter.to_string());
        if vote_yes {
            self.yes_votes += 1;
        } else {
            self.no_votes += 1;
        }
        Ok(())
    }

    /// Gets voting result asynchronously.
    pub async fn result(&self) -> Result<(bool, String), KslError> {
        let total_votes = self.yes_votes + self.no_votes;
        if total_votes == 0 {
            return Ok((false, "No votes yet.".to_string()));
        }
        let yes_percentage = (self.yes_votes as f32 / total_votes as f32) * 100.0;
        Ok(if yes_percentage > 50.0 {
            (true, format!("Proposal '{}' passed with {}% yes votes.", self.proposal, yes_percentage))
        } else {
            (false, format!("Proposal '{}' failed with {}% yes votes.", self.proposal, yes_percentage))
        })
    }
}

/// Community governance system with async support.
#[derive(Debug)]
pub struct Community {
    /// Package reviews
    reviews: HashMap<String, PackageReview>,
    /// Contributor guidelines
    guidelines: ContributorGuidelines,
    /// Active votings
    voting: HashMap<String, Voting>,
    /// Package registry
    registry: HashMap<String, Vec<Package>>,
    /// Async context
    async_context: Arc<Mutex<AsyncContext>>,
    /// CLI context
    cli_context: CliContext,
}

impl Community {
    /// Creates a new community system.
    pub fn new() -> Self {
        Community {
            reviews: HashMap::new(),
            guidelines: ContributorGuidelines::new(),
            voting: HashMap::new(),
            registry: HashMap::new(),
            async_context: Arc::new(Mutex::new(AsyncContext::new())),
            cli_context: CliContext::new(),
        }
    }

    /// Submits a package for review asynchronously.
    pub async fn submit_package(&mut self, package: Package, reviewer: &str) -> Result<(), KslError> {
        let package_key = format!("{}-{}", package.name, package.version);
        if self.reviews.contains_key(&package_key) {
                        return Err(KslError::validation_error(                format!("Package '{}' is already under review.", package_key),                SourcePosition::new(1, 1),                "E502".to_string()            ));
        }

        // Check compliance with guidelines
        let violations = self.guidelines.check_compliance(&package).await?;
        if !violations.is_empty() {
                        return Err(KslError::validation_error(                format!("Package '{}' violates contributor guidelines:\n{}",                     package_key,                     violations.join("\n")                ),                SourcePosition::new(1, 1),                "E503".to_string()            ));
        }

        let mut async_ctx = self.async_context.lock().await;
        let command = AsyncCommand::NotifyNewPackage(package.clone());
        async_ctx.execute_command(command).await?;

        self.reviews.insert(package_key.clone(), PackageReview::new(package, reviewer.to_string()));
        Ok(())
    }

    /// Reviews a package asynchronously.
    pub async fn review_package(
        &mut self,
        package_name: &str,
        version: &str,
        approve: bool,
        comment: Option<&str>,
    ) -> Result<(), KslError> {
        let package_key = format!("{}-{}", package_name, version);
        let review = self.reviews.get_mut(&package_key).ok_or_else(|| {
            KslError::not_found_error(
                format!("Package '{}' not found in review queue.", package_key),
                SourcePosition::new(1, 1),
                "E601".to_string()
            )
        })?;

        if let Some(comment_text) = comment {
            review.add_comment(comment_text.to_string()).await?;
        }

        let mut async_ctx = self.async_context.lock().await;
        let command = AsyncCommand::NotifyReviewDecision {
            package: package_name.to_string(),
            approved: approve,
        };
        async_ctx.execute_command(command).await?;

        review.status = if approve {
            ReviewStatus::Approved
        } else {
            ReviewStatus::Rejected(comment.unwrap_or("No reason provided").to_string())
        };

        Ok(())
    }

    /// Starts a new vote asynchronously.
    pub async fn start_vote(&mut self, proposal: &str) -> Result<(), KslError> {
        if self.voting.contains_key(proposal) {
            return Err(KslError::validation_error(
                format!("Voting for proposal '{}' already exists.", proposal),
                SourcePosition::new(1, 1),
                "E504".to_string()
            ));
        }

        let mut async_ctx = self.async_context.lock().await;
        let command = AsyncCommand::NotifyNewVote(proposal.to_string());
        async_ctx.execute_command(command).await?;

        self.voting.insert(proposal.to_string(), Voting::new(proposal));
        Ok(())
    }

    /// Casts a vote asynchronously.
    pub async fn cast_vote(&mut self, proposal: &str, voter: &str, vote_yes: bool) -> Result<String, KslError> {
        let voting = self.voting.get_mut(proposal).ok_or_else(|| {
            KslError::not_found_error(
                format!("Voting for proposal '{}' not found.", proposal),
                SourcePosition::new(1, 1),
                "E602".to_string()
            )
        })?;

        voting.vote(voter, vote_yes).await?;
        let (passed, message) = voting.result().await?;

        let mut async_ctx = self.async_context.lock().await;
        let command = AsyncCommand::NotifyVoteResult {
            proposal: proposal.to_string(),
            passed,
        };
        async_ctx.execute_command(command).await?;

        Ok(message)
    }

    /// Handles CLI commands asynchronously.
    pub async fn handle_command(&mut self, command: CliCommand) -> Result<String, KslError> {
        match command {
            CliCommand::Submit { package, reviewer } => {
                self.submit_package(package, &reviewer).await?;
                Ok("Package submitted successfully.".to_string())
            }
            CliCommand::Review { package, version, approve, comment } => {
                self.review_package(&package, &version, approve, comment.as_deref()).await?;
                Ok("Review submitted successfully.".to_string())
            }
            CliCommand::Vote { proposal, voter, vote_yes } => {
                self.cast_vote(&proposal, &voter, vote_yes).await
            }
            _ => Err(KslError::cli_error(
                "Unsupported command".to_string(),
                SourcePosition::new(1, 1),
                "E701".to_string()
            )),
        }
    }
}

/// Runs a community command asynchronously.
pub async fn run_community_command(command: &str, args: Vec<&str>) -> Result<String, KslError> {
    let mut community = Community::new();
    let cli_command = CliCommand::parse(command, args)?;
    community.handle_command(cli_command).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_package_submission() {
        let mut community = Community::new();
        let package = Package::new(
            "test-pkg",
            SemVer::new(1, 0, 0),
            vec![],
            "MIT",
            "test-contributor",
        );
        let result = community.submit_package(package, "reviewer").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_package_review() {
        let mut community = Community::new();
        let package = Package::new(
            "test-pkg",
            SemVer::new(1, 0, 0),
            vec![],
            "MIT",
            "test-contributor",
        );
        community.submit_package(package, "reviewer").await.unwrap();
        let result = community.review_package("test-pkg", "1.0.0", true, Some("LGTM")).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_voting() {
        let mut community = Community::new();
        community.start_vote("test-proposal").await.unwrap();
        let result = community.cast_vote("test-proposal", "voter1", true).await;
        assert!(result.is_ok());
        assert!(result.unwrap().contains("passed"));
    }
}