// ksl_docgen.rs
// Generates API documentation for KSL libraries, extracting /// comments and
// producing JSON output with cross-references.

use crate::ksl_parser::{parse, AstNode, ParseError};
use crate::ksl_doc::{StdLibFunctionTrait};
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use tempfile::NamedTempFile;

/// Documentation parameter information.
/// @struct DocParam
/// @field name Parameter name.
/// @field ty Parameter type.
/// @field description Parameter description.
#[derive(Debug, Serialize, Deserialize)]
pub struct DocParam {
    pub name: String,
    pub ty: String,
    pub description: String,
}

/// Documentation return value information.
/// @struct DocReturn
/// @field ty Return type.
/// @field description Return value description.
#[derive(Debug, Serialize, Deserialize)]
pub struct DocReturn {
    pub ty: String,
    pub description: String,
}

/// Documentation item for a function or module.
/// @struct DocItem
/// @field name Item name.
/// @field description Item description.
/// @field params Parameter documentation.
/// @field returns Return value documentation.
/// @field is_async Whether the function is asynchronous.
#[derive(Debug, Serialize, Deserialize)]
pub struct DocItem {
    pub name: String,
    pub description: String,
    pub params: Vec<DocParam>,
    pub returns: DocReturn,
    pub is_async: bool,
}

/// Documentation generator configuration.
/// @struct DocGenConfig
/// @field library Library name.
/// @field output_dir Output directory.
#[derive(Debug)]
pub struct DocGenConfig {
    pub library: String,
    pub output_dir: PathBuf,
}

/// API documentation generator.
/// @struct DocGen
/// @field config Generator configuration.
/// @field cross_references Cross-reference map for function names.
pub struct DocGen {
    config: DocGenConfig,
    cross_references: HashMap<String, String>,
}

impl DocGen {
    /// Creates a new documentation generator.
    /// @param config Generator configuration.
    /// @returns A new `DocGen` instance.
    pub fn new(config: DocGenConfig) -> Self {
        let mut docgen = DocGen {
            config,
            cross_references: HashMap::new(),
        };
        docgen.populate_cross_references();
        docgen
    }

    /// Populates cross-references for standard library functions.
    fn populate_cross_references(&mut self) {
        // Standard library functions
        self.cross_references.insert("sha3".to_string(), "/docs/std#sha3".to_string());
        self.cross_references.insert("bls_verify".to_string(), "/docs/std#bls_verify".to_string());
        self.cross_references.insert("matrix.mul".to_string(), "/docs/std#matrix.mul".to_string());
        self.cross_references.insert("device.sensor".to_string(), "/docs/std#device.sensor".to_string());
        
        // Networking functions
        self.cross_references.insert("tcp.connect".to_string(), "/docs/net#tcp.connect".to_string());
        self.cross_references.insert("udp.send".to_string(), "/docs/net#udp.send".to_string());
        self.cross_references.insert("http.post".to_string(), "/docs/net#http.post".to_string());
    }

    /// Generates documentation for a set of items.
    /// @param items Documentation items to generate.
    /// @returns `Ok(())` if generation succeeds, or `Err` with a `KslError`.
    pub fn generate(&self, items: &[DocItem]) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let output_path = self.config.output_dir.join(format!("{}.json", self.config.library));

        // Create a temporary file first
        let mut temp_file = NamedTempFile::new()
            .map_err(|e| KslError::type_error(
                format!("Failed to create temporary file: {}", e),
                pos,
            ))?;

        // Write JSON to temporary file
        let json = serde_json::to_string_pretty(items)
            .map_err(|e| KslError::type_error(
                format!("Failed to serialize JSON: {}", e),
                pos,
            ))?;
        temp_file.write_all(json.as_bytes())
            .map_err(|e| KslError::type_error(
                format!("Failed to write to temporary file: {}", e),
                pos,
            ))?;

        // Ensure output directory exists
        fs::create_dir_all(&self.config.output_dir)
            .map_err(|e| KslError::type_error(
                format!("Failed to create output directory {}: {}", self.config.output_dir.display(), e),
                pos,
            ))?;

        // Move temporary file to final location
        temp_file.persist(&output_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to move temporary file to {}: {}", output_path.display(), e),
                pos,
            ))?;

        Ok(())
    }
}

/// Generates documentation for a library.
/// @param library Library name.
/// @param output_dir Output directory.
/// @param items Documentation items to generate.
/// @returns `Ok(())` if generation succeeds, or `Err` with a `KslError`.
pub fn generate_docgen(
    library: &str,
    output_dir: PathBuf,
    items: &[DocItem],
) -> Result<(), KslError> {
    let config = DocGenConfig {
        library: library.to_string(),
        output_dir,
    };
    let docgen = DocGen::new(config);
    docgen.generate(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_json() {
        let items = vec![
            DocItem {
                name: "print".to_string(),
                description: "Prints a message to stdout".to_string(),
                params: vec![
                    DocParam {
                        name: "msg".to_string(),
                        ty: "string".to_string(),
                        description: "Message to print".to_string(),
                    },
                ],
                returns: DocReturn {
                    ty: "void".to_string(),
                    description: "No return value".to_string(),
                },
                is_async: false,
            },
        ];

        let temp_dir = tempdir().unwrap();
        let result = generate_docgen(
            "test",
            temp_dir.path().to_path_buf(),
            &items,
        );
        assert!(result.is_ok());

        let output_path = temp_dir.path().join("test.json");
        assert!(output_path.exists());

        let contents = fs::read_to_string(output_path).unwrap();
        let parsed: Vec<DocItem> = serde_json::from_str(&contents).unwrap();
        assert_eq!(parsed, items);
    }

    #[test]
    fn test_generate_invalid_output_dir() {
        let items = vec![
            DocItem {
                name: "print".to_string(),
                description: "Prints a message to stdout".to_string(),
                params: vec![],
                returns: DocReturn {
                    ty: "void".to_string(),
                    description: "No return value".to_string(),
                },
                is_async: false,
            },
        ];

        let result = generate_docgen(
            "test",
            PathBuf::from("/nonexistent/directory"),
            &items,
        );
        assert!(result.is_err());
    }
}