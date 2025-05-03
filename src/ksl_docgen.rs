// ksl_docgen.rs
// Generates API documentation for KSL libraries, extracting /// comments and
// producing HTML or Markdown output with cross-references.

use crate::ksl_parser::{parse, AstNode, ParseError};
use crate::ksl_doc::{StdLibFunctionTrait};
use crate::ksl_errors::{KslError, SourcePosition};
use pulldown_cmark::{html, Parser};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::collections::HashMap;

// Documentation generator configuration
#[derive(Debug)]
pub struct DocGenConfig {
    library: String, // Library name (e.g., "std", "mylib")
    format: String, // Output format: "html" or "markdown"
    output_dir: PathBuf, // Directory for generated docs
}

// API documentation generator
pub struct DocGen {
    config: DocGenConfig,
    cross_references: HashMap<String, String>, // Function name -> URL
}

impl DocGen {
    pub fn new(config: DocGenConfig) -> Self {
        let mut docgen = DocGen {
            config,
            cross_references: HashMap::new(),
        };
        docgen.populate_cross_references();
        docgen
    }

    // Populate cross-references for standard library functions
    fn populate_cross_references(&mut self) {
        // Standard library functions (simplified, can be extended)
        self.cross_references.insert("sha3".to_string(), "/docs/std#sha3".to_string());
        self.cross_references.insert("bls_verify".to_string(), "/docs/std#bls_verify".to_string());
        self.cross_references.insert("matrix.mul".to_string(), "/docs/std#matrix.mul".to_string());
        self.cross_references.insert("device.sensor".to_string(), "/docs/std#device.sensor".to_string());
    }

    // Generate API documentation for a library
    pub fn generate(&self, file: &PathBuf) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        // Read and parse source
        let source = fs::read_to_string(file)
            .map_err(|e| KslError::type_error(
                format!("Failed to read file {}: {}", file.display(), e),
                pos,
            ))?;
        let ast = parse(&source)
            .map_err(|e| KslError::type_error(
                format!("Parse error at position {}: {}", e.position, e.message),
                pos,
            ))?;

        // Generate Markdown
        let mut markdown = String::new();
        markdown.push_str(&format!("# API Documentation for {}\n\n", self.config.library));

        for node in &ast {
            self.document_node(&mut markdown, node)?;
        }

        // Output based on format
        let output_path = self.config.output_dir.join(format!("{}.{}", self.config.library, match self.config.format.as_str() {
            "html" => "html",
            "markdown" => "md",
            _ => "md",
        }));
        fs::create_dir_all(&self.config.output_dir)
            .map_err(|e| KslError::type_error(
                format!("Failed to create output directory {}: {}", self.config.output_dir.display(), e),
                pos,
            ))?;

        if self.config.format == "html" {
            let html = self.markdown_to_html(&markdown);
            File::create(&output_path)
                .map_err(|e| KslError::type_error(
                    format!("Failed to create output file {}: {}", output_path.display(), e),
                    pos,
                ))?
                .write_all(html.as_bytes())
                .map_err(|e| KslError::type_error(
                    format!("Failed to write output file {}: {}", output_path.display(), e),
                    pos,
                ))?;
        } else {
            File::create(&output_path)
                .map_err(|e| KslError::type_error(
                    format!("Failed to create output file {}: {}", output_path.display(), e),
                    pos,
                ))?
                .write_all(markdown.as_bytes())
                .map_err(|e| KslError::type_error(
                    format!("Failed to write output file {}: {}", output_path.display(), e),
                    pos,
                ))?;
        }

        Ok(())
    }

    // Document an AST node
    fn document_node(&self, markdown: &mut String, node: &AstNode) -> Result<(), KslError> {
        match node {
            AstNode::FnDecl { doc, name, params, return_type, .. } => {
                markdown.push_str(&format!("## Function `{}`\n\n", name));
                if let Some(doc) = doc {
                    let mut in_example = false;
                    let mut example_code = String::new();
                    for line in doc.text.lines() {
                        if line.trim().starts_with("@example") {
                            in_example = true;
                            continue;
                        }
                        if in_example {
                            if line.trim().is_empty() {
                                in_example = false;
                                markdown.push_str("### Example\n\n```ksl\n");
                                markdown.push_str(&example_code);
                                markdown.push_str("\n```\n\n");
                                example_code.clear();
                            } else {
                                example_code.push_str(line);
                                example_code.push('\n');
                            }
                        } else {
                            let line = self.add_cross_references(line);
                            markdown.push_str(&line);
                            markdown.push_str("\n\n");
                        }
                    }
                    if in_example {
                        markdown.push_str("### Example\n\n```ksl\n");
                        markdown.push_str(&example_code);
                        markdown.push_str("\n```\n\n");
                    }
                } else {
                    markdown.push_str("No documentation available.\n\n");
                }
                markdown.push_str("**Parameters**:\n");
                if params.is_empty() {
                    markdown.push_str("- None\n");
                } else {
                    for (param_name, param_type) in params {
                        markdown.push_str(&format!("- `{}`: {}\n", param_name, format_type(param_type)));
                    }
                }
                markdown.push_str("\n**Returns**: ");
                markdown.push_str(&format_type(return_type));
                markdown.push_str("\n\n");
            }
            AstNode::ModuleDecl { name } => {
                markdown.push_str(&format!("# Module {}\n\n", name));
            }
            _ => {} // Ignore other nodes
        }
        Ok(())
    }

    // Add cross-references to Markdown text
    fn add_cross_references(&self, line: &str) -> String {
        let mut result = line.to_string();
        for (func, url) in &self.cross_references {
            let link = format!("[`{}`]({})", func, url);
            result = result.replace(&format!("`{}`", func), &link);
        }
        result
    }

    // Convert Markdown to HTML
    fn markdown_to_html(&self, markdown: &str) -> String {
        let parser = Parser::new(markdown);
        let mut html_output = String::new();
        html::push_html(&mut html_output, parser);
        format!(
            r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>KSL API Documentation - {}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #333; }}
        pre {{ background: #f4f4f4; padding: 10px; border-radius: 5px; }}
        code {{ font-family: monospace; }}
        a {{ color: #007bff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    {}
</body>
</html>
            "#,
            self.config.library, html_output
        )
    }
}

// Format a type annotation for display
fn format_type(annot: &TypeAnnotation) -> String {
    match annot {
        TypeAnnotation::Simple(name) => name.clone(),
        TypeAnnotation::Array { element, size } => format!("array<{}, {}>", element, size),
        TypeAnnotation::Result { success, error } => format!("result<{}, {}>", success, error),
    }
}

// Public API to generate API documentation
pub fn generate_docgen(library: &str, format: &str, output_dir: PathBuf) -> Result<(), KslError> {
    let pos = SourcePosition::new(1, 1);
    if format != "html" && format != "markdown" {
        return Err(KslError::type_error(
            format!("Invalid format: {}. Use 'html' or 'markdown'", format),
            pos,
        ));
    }

    let config = DocGenConfig {
        library: library.to_string(),
        format: format.to_string(),
        output_dir,
    };
    let docgen = DocGen::new(config);

    // Determine file to document (simplified: assumes library files are in a standard location)
    let file_path = match library {
        "std" => PathBuf::from("std.ksl"), // Placeholder for standard library source
        _ => PathBuf::from(format!("{}.ksl", library)),
    };

    docgen.generate(&file_path)
}

// Assume ksl_parser.rs, ksl_doc.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ParseError};
}

mod ksl_doc {
    pub use super::StdLibFunctionTrait;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;

    #[test]
    fn test_generate_markdown() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "/// Verifies a transaction\n/// @param msg: Message to verify\n/// @returns: True if valid\n/// @example\n/// let valid = verify_tx(\"data\");\nfn verify_tx(msg: string): bool {{ true }}"
        ).unwrap();

        let output_dir = temp_dir.path().join("docs");
        let result = generate_docgen("test", "markdown", output_dir.clone());
        assert!(result.is_ok());

        let output_path = output_dir.join("test.md");
        let content = fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("# API Documentation for test"));
        assert!(content.contains("## Function `verify_tx`"));
        assert!(content.contains("Verifies a transaction"));
        assert!(content.contains("### Example"));
        assert!(content.contains("```ksl\nlet valid = verify_tx(\"data\");\n```"));
    }

    #[test]
    fn test_generate_html() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "/// Calls `sha3` to hash data\nfn hash_data(data: string): array<u8, 32> {{ sha3(data) }}"
        ).unwrap();

        let output_dir = temp_dir.path().join("docs");
        let result = generate_docgen("test", "html", output_dir.clone());
        assert!(result.is_ok());

        let output_path = output_dir.join("test.html");
        let content = fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("<h1>API Documentation for test</h1>"));
        assert!(content.contains("<h2>Function <code>hash_data</code></h2>"));
        assert!(content.contains("Calls <a href=\"/docs/std#sha3\"><code>sha3</code></a> to hash data"));
    }

    #[test]
    fn test_generate_invalid_format() {
        let temp_dir = TempDir::new().unwrap();
        let result = generate_docgen("test", "invalid", temp_dir.path().to_path_buf());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid format"));
    }

    #[test]
    fn test_generate_invalid_file() {
        let temp_dir = TempDir::new().unwrap();
        let result = generate_docgen("nonexistent", "markdown", temp_dir.path().to_path_buf());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read file"));
    }
}