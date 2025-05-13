use std::path::{Path, PathBuf};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::ksl_scaffold::{Template, TemplateMetadata};
use crate::ksl_package::Dependency;

/// Lint severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LintSeverity {
    Error,
    Warning,
    Info,
}

/// Lint result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LintResult {
    /// Lint message
    pub message: String,
    /// Severity level
    pub severity: LintSeverity,
    /// File path (if applicable)
    pub file: Option<PathBuf>,
    /// Line number (if applicable)
    pub line: Option<usize>,
    /// Column number (if applicable)
    pub column: Option<usize>,
}

/// Template validation rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRules {
    /// Required files
    pub required_files: Vec<String>,
    /// Required dependencies
    pub required_dependencies: Vec<String>,
    /// Required features
    pub required_features: Vec<String>,
    /// Maximum file size (in bytes)
    pub max_file_size: Option<usize>,
    /// Allowed file extensions
    pub allowed_extensions: Vec<String>,
    /// Required template variables
    pub required_variables: Vec<String>,
}

/// Template validator
pub struct TemplateValidator {
    /// Validation rules
    rules: ValidationRules,
    /// Template path
    template_path: PathBuf,
    /// Template metadata
    metadata: TemplateMetadata,
}

impl TemplateValidator {
    /// Creates a new template validator
    pub fn new(template_path: PathBuf, metadata: TemplateMetadata) -> Self {
        let rules = ValidationRules {
            required_files: vec![
                "main.ksl".to_string(),
                "README.md".to_string(),
                "ksl.toml".to_string(),
            ],
            required_dependencies: vec![
                "ksl_stdlib".to_string(),
            ],
            required_features: vec![],
            max_file_size: Some(1024 * 1024), // 1MB
            allowed_extensions: vec![
                "ksl".to_string(),
                "md".to_string(),
                "toml".to_string(),
                "json".to_string(),
            ],
            required_variables: vec![
                "project_name".to_string(),
                "version".to_string(),
            ],
        };

        TemplateValidator {
            rules,
            template_path,
            metadata,
        }
    }

    /// Validates the template
    pub fn validate(&self) -> Vec<LintResult> {
        let mut results = Vec::new();

        // Check required files
        results.extend(self.check_required_files());

        // Check dependencies
        results.extend(self.check_dependencies());

        // Check features
        results.extend(self.check_features());

        // Check file sizes
        results.extend(self.check_file_sizes());

        // Check file extensions
        results.extend(self.check_file_extensions());

        // Check template variables
        results.extend(self.check_template_variables());

        // Check syntax
        results.extend(self.check_syntax());

        results
    }

    /// Checks for required files
    fn check_required_files(&self) -> Vec<LintResult> {
        let mut results = Vec::new();

        for file in &self.rules.required_files {
            let path = self.template_path.join(file);
            if !path.exists() {
                results.push(LintResult {
                    message: format!("Required file '{}' is missing", file),
                    severity: LintSeverity::Error,
                    file: Some(path),
                    line: None,
                    column: None,
                });
            }
        }

        results
    }

    /// Checks dependencies
    fn check_dependencies(&self) -> Vec<LintResult> {
        let mut results = Vec::new();
        let mut found_deps = HashMap::new();

        for dep in &self.metadata.dependencies {
            found_deps.insert(dep.name.clone(), true);
        }

        for required in &self.rules.required_dependencies {
            if !found_deps.contains_key(required) {
                results.push(LintResult {
                    message: format!("Required dependency '{}' is missing", required),
                    severity: LintSeverity::Error,
                    file: None,
                    line: None,
                    column: None,
                });
            }
        }

        results
    }

    /// Checks features
    fn check_features(&self) -> Vec<LintResult> {
        let mut results = Vec::new();
        let mut found_features = HashMap::new();

        for feature in &self.metadata.required_features {
            found_features.insert(feature.clone(), true);
        }

        for required in &self.rules.required_features {
            if !found_features.contains_key(required) {
                results.push(LintResult {
                    message: format!("Required feature '{}' is missing", required),
                    severity: LintSeverity::Warning,
                    file: None,
                    line: None,
                    column: None,
                });
            }
        }

        results
    }

    /// Checks file sizes
    fn check_file_sizes(&self) -> Vec<LintResult> {
        let mut results = Vec::new();

        if let Some(max_size) = self.rules.max_file_size {
            for entry in walkdir::WalkDir::new(&self.template_path) {
                if let Ok(entry) = entry {
                    if entry.file_type().is_file() {
                        if let Ok(metadata) = entry.metadata() {
                            if metadata.len() > max_size as u64 {
                                results.push(LintResult {
                                    message: format!(
                                        "File '{}' exceeds maximum size of {} bytes",
                                        entry.path().display(),
                                        max_size
                                    ),
                                    severity: LintSeverity::Warning,
                                    file: Some(entry.path().to_path_buf()),
                                    line: None,
                                    column: None,
                                });
                            }
                        }
                    }
                }
            }
        }

        results
    }

    /// Checks file extensions
    fn check_file_extensions(&self) -> Vec<LintResult> {
        let mut results = Vec::new();

        for entry in walkdir::WalkDir::new(&self.template_path) {
            if let Ok(entry) = entry {
                if entry.file_type().is_file() {
                    if let Some(ext) = entry.path().extension() {
                        if let Some(ext_str) = ext.to_str() {
                            if !self.rules.allowed_extensions.contains(&ext_str.to_string()) {
                                results.push(LintResult {
                                    message: format!(
                                        "File '{}' has disallowed extension '{}'",
                                        entry.path().display(),
                                        ext_str
                                    ),
                                    severity: LintSeverity::Warning,
                                    file: Some(entry.path().to_path_buf()),
                                    line: None,
                                    column: None,
                                });
                            }
                        }
                    }
                }
            }
        }

        results
    }

    /// Checks template variables
    fn check_template_variables(&self) -> Vec<LintResult> {
        let results = Vec::new();

        // TODO: Implement template variable checking
        // This would require parsing the template files and checking for required variables

        results
    }

    /// Checks syntax
    fn check_syntax(&self) -> Vec<LintResult> {
        let results = Vec::new();

        // TODO: Implement syntax checking
        // This would require parsing the KSL files and checking for syntax errors

        results
    }
}

/// Template test runner
pub struct TemplateTestRunner {
    /// Template path
    template_path: PathBuf,
    /// Test cases
    test_cases: Vec<TestCase>,
}

/// Test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    /// Test name
    pub name: String,
    /// Input variables
    pub input: HashMap<String, String>,
    /// Expected files
    pub expected_files: Vec<String>,
    /// Expected content patterns
    pub expected_patterns: Vec<String>,
}

impl TemplateTestRunner {
    /// Creates a new test runner
    pub fn new(template_path: PathBuf) -> Self {
        TemplateTestRunner {
            template_path,
            test_cases: Vec::new(),
        }
    }

    /// Adds a test case
    pub fn add_test_case(&mut self, test_case: TestCase) {
        self.test_cases.push(test_case);
    }

    /// Runs all test cases
    pub fn run_tests(&self) -> Vec<TestResult> {
        let mut results = Vec::new();

        for test_case in &self.test_cases {
            results.extend(self.run_test_case(test_case));
        }

        results
    }

    /// Runs a single test case
    fn run_test_case(&self, _test_case: &TestCase) -> Vec<TestResult> {
        let results = Vec::new();

        // TODO: Implement test case running
        // This would require:
        // 1. Creating a temporary directory
        // 2. Running the template with the test case input
        // 3. Checking for expected files and patterns
        // 4. Cleaning up

        results
    }
}

/// Test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    /// Test name
    pub test_name: String,
    /// Success status
    pub success: bool,
    /// Error message (if any)
    pub error: Option<String>,
    /// Generated files
    pub generated_files: Vec<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_required_files_validation() {
        let temp_dir = tempdir().unwrap();
        let metadata = TemplateMetadata {
            name: "test".to_string(),
            description: "Test template".to_string(),
            version: "1.0.0".to_string(),
            dependencies: vec![],
            required_features: vec![],
            source: crate::ksl_scaffold::TemplateSource::Local(PathBuf::from("test")),
        };

        let validator = TemplateValidator::new(temp_dir.path().to_path_buf(), metadata);
        let results = validator.check_required_files();

        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.message.contains("main.ksl")));
    }

    #[test]
    fn test_dependencies_validation() {
        let temp_dir = tempdir().unwrap();
        let metadata = TemplateMetadata {
            name: "test".to_string(),
            description: "Test template".to_string(),
            version: "1.0.0".to_string(),
            dependencies: vec![
                Dependency::new("ksl_stdlib", "^1.0.0"),
            ],
            required_features: vec![],
            source: crate::ksl_scaffold::TemplateSource::Local(PathBuf::from("test")),
        };

        let validator = TemplateValidator::new(temp_dir.path().to_path_buf(), metadata);
        let results = validator.check_dependencies();

        assert!(results.is_empty());
    }

    #[test]
    fn test_file_size_validation() {
        let temp_dir = tempdir().unwrap();
        let metadata = TemplateMetadata {
            name: "test".to_string(),
            description: "Test template".to_string(),
            version: "1.0.0".to_string(),
            dependencies: vec![],
            required_features: vec![],
            source: crate::ksl_scaffold::TemplateSource::Local(PathBuf::from("test")),
        };

        // Create a large file
        let large_file = temp_dir.path().join("large.txt");
        std::fs::write(&large_file, vec![0; 2 * 1024 * 1024]).unwrap();

        let validator = TemplateValidator::new(temp_dir.path().to_path_buf(), metadata);
        let results = validator.check_file_sizes();

        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.message.contains("exceeds maximum size")));
    }
} 