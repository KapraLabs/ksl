// ksl_typegen.rs
// Generates KSL type definitions from external sources like JSON schemas,
// supporting nested types, arrays, and optional fields for interoperability.
// Also supports async types, FFI type mappings, and comprehensive type generation.

use crate::ksl_parser::{parse, ParseError};
use crate::ksl_checker::check;
use crate::ksl_docgen::generate_docgen;
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_types::{Type, TypeKind, TypeSystem};
use crate::ksl_async::{AsyncType, AsyncContext};
use crate::ksl_ffi::{FFIType, FFIMapping};
use serde_json::{Value as JsonValue};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::collections::{HashMap, HashSet};

/// Configuration for type generation
#[derive(Debug)]
pub struct TypeGenConfig {
    /// Input schema file (e.g., schema.json)
    schema_file: PathBuf,
    /// Output KSL file (e.g., types.ksl)
    output_file: PathBuf,
    /// Source type: "json" or "protobuf"
    source_type: String,
    /// Whether to generate async types
    generate_async: bool,
    /// FFI type mappings for external language integration
    ffi_mappings: HashMap<String, FFIType>,
}

/// Type generator for KSL
pub struct TypeGen {
    config: TypeGenConfig,
    type_system: TypeSystem,
    async_context: Option<AsyncContext>,
}

impl TypeGen {
    /// Creates a new type generator with the given configuration
    pub fn new(config: TypeGenConfig) -> Self {
        let type_system = TypeSystem::new();
        let async_context = if config.generate_async {
            Some(AsyncContext::new())
        } else {
            None
        };
        TypeGen {
            config,
            type_system,
            async_context,
        }
    }

    /// Generates KSL types from the schema
    pub fn generate(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        // Read schema file
        let schema_content = fs::read_to_string(&self.config.schema_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to read schema file {}: {}", self.config.schema_file.display(), e),
                pos,
                "TYPEGEN_READ_ERROR".to_string()
            ))?;

        // Generate types based on source type
        let ksl_code = match self.config.source_type.as_str() {
            "json" => self.generate_from_json(&schema_content)?,
            "protobuf" => return Err(KslError::type_error(
                "Protobuf support not implemented".to_string(),
                pos,
                "TYPEGEN_PROTO_UNSUPPORTED".to_string()
            )),
            _ => return Err(KslError::type_error(
                format!("Unsupported source type: {}", self.config.source_type),
                pos,
                "TYPEGEN_SOURCE_TYPE_ERROR".to_string()
            )),
        };

        // Validate generated code
        let ast = parse(&ksl_code)
            .map_err(|e| KslError::type_error(
                format!("Generated code parse error at position {}: {}", e.position, e.message),
                pos,
                "TYPEGEN_PARSE_ERROR".to_string()
            ))?;
        check(&ast)
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Type error in generated code at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
                "TYPEGEN_CHECK_ERROR".to_string()
            ))?;

        // Write generated code
        File::create(&self.config.output_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to create output file {}: {}", self.config.output_file.display(), e),
                pos,
                "TYPEGEN_FILE_CREATE_ERROR".to_string()
            ))?
            .write_all(ksl_code.as_bytes())
            .map_err(|e| KslError::type_error(
                format!("Failed to write output file {}: {}", self.config.output_file.display(), e),
                pos,
                "TYPEGEN_FILE_WRITE_ERROR".to_string()
            ))?;

        // Generate documentation for the types
        let doc_dir = self.config.output_file.parent().unwrap_or_else(|| PathBuf::from("."));
        generate_docgen("generated_types", "markdown", doc_dir.to_path_buf())
            .map_err(|e| KslError::type_error(format!("Documentation generation failed: {}", e), pos, "TYPEGEN_DOC_ERROR".to_string()))?;

        Ok(())
    }

    /// Generates KSL types from a JSON schema
    fn generate_from_json(&self, schema_content: &str) -> Result<String, KslError> {
        let pos = SourcePosition::new(1, 1);
        let schema_string = schema_content.to_string();
        let schema: JsonValue = serde_json::from_str(&schema_string)
            .map_err(|e| KslError::type_error(
                format!("Failed to parse JSON schema: {}", e),
                pos,
                "TYPEGEN_JSON_PARSE_ERROR".to_string()
            ))?;

        let mut ksl_code = String::new();
        ksl_code.push_str("/// Generated KSL types from JSON schema\n");

        // Process schema as an object
        if let Some(obj) = schema.as_object() {
            if obj.get("type").and_then(|t| t.as_str()) == Some("object") {
                let type_name = obj.get("title")
                    .and_then(|t| t.as_str())
                    .unwrap_or("GeneratedType")
                    .to_string();
                ksl_code.push_str(&format!("/// Type definition for {}\n", type_name));
                
                // Check if type should be async
                let is_async = obj.get("async")
                    .and_then(|a| a.as_bool())
                    .unwrap_or(false);
                
                if is_async && self.config.generate_async {
                    ksl_code.push_str(&format!("async struct {} {{\n", type_name));
                } else {
                    ksl_code.push_str(&format!("struct {} {{\n", type_name));
                }

                let properties = obj.get("properties")
                    .and_then(|p| p.as_object())
                    .ok_or_else(|| KslError::type_error(
                        "Schema must have properties for object type".to_string(),
                        pos,
                        "TYPEGEN_MISSING_PROPERTIES".to_string()
                    ))?;
                let required = obj.get("required")
                    .and_then(|r| r.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<HashSet<&str>>())
                    .unwrap_or_default();

                for (prop_name, prop_schema) in properties {
                    let (ksl_type, is_optional) = self.json_type_to_ksl(prop_schema)?;
                    
                    // Apply FFI mapping if exists
                    let mapped_type = if let Some(ffi_type) = self.config.ffi_mappings.get(&ksl_type) {
                        ffi_type.to_ksl_type()
                    } else {
                        ksl_type
                    };

                    let field_type = if !required.contains(prop_name.as_str()) || is_optional {
                        format!("result<{}, ()>", mapped_type)
                    } else {
                        mapped_type
                    };
                    ksl_code.push_str(&format!("    {}: {},\n", prop_name, field_type));
                }

                ksl_code.push_str("}\n");
            } else {
                return Err(KslError::type_error(
                    "Schema root must be an object type".to_string(),
                    pos,
                    "TYPEGEN_ROOT_TYPE_ERROR".to_string()
                ));
            }
        } else {
            return Err(KslError::type_error(
                "Schema must be a JSON object".to_string(),
                pos,
                "TYPEGEN_SCHEMA_TYPE_ERROR".to_string()
            ));
        }

        Ok(ksl_code)
    }

    /// Converts JSON schema type to KSL type
    fn json_type_to_ksl(&self, schema: &JsonValue) -> Result<(String, bool), KslError> {
        let pos = SourcePosition::new(1, 1);
        let schema_type = schema.get("type")
            .and_then(|t| t.as_str())
            .ok_or_else(|| KslError::type_error(
                "Schema property must have a type".to_string(),
                pos,
                "TYPEGEN_PROPERTY_TYPE_ERROR".to_string()
            ))?;

        match schema_type {
            "string" => Ok(("string".to_string(), false)),
            "integer" => Ok(("u32".to_string(), false)),
            "number" => Ok(("f64".to_string(), false)),
            "boolean" => Ok(("bool".to_string(), false)),
            "array" => {
                let items = schema.get("items")
                    .ok_or_else(|| KslError::type_error(
                        "Array schema must have items".to_string(),
                        pos,
                        "TYPEGEN_ARRAY_ITEMS_ERROR".to_string()
                    ))?;
                let (item_type, is_optional) = self.json_type_to_ksl(items)?;
                let size = schema.get("maxItems")
                    .and_then(|s| s.as_u64())
                    .unwrap_or(10) as u32; // Default size for arrays
                Ok((format!("array<{}, {}>", item_type, size), is_optional))
            }
            "object" => {
                let type_name = schema.get("title")
                    .and_then(|t| t.as_str())
                    .unwrap_or("NestedType")
                    .to_string();
                let mut nested_code = String::new();
                
                // Check if nested type should be async
                let is_async = schema.get("async")
                    .and_then(|a| a.as_bool())
                    .unwrap_or(false);
                
                if is_async && self.config.generate_async {
                    nested_code.push_str(&format!("async struct {} {{\n", type_name));
                } else {
                    nested_code.push_str(&format!("struct {} {{\n", type_name));
                }

                let properties = schema.get("properties")
                    .and_then(|p| p.as_object())
                    .ok_or_else(|| KslError::type_error(
                        "Object schema must have properties".to_string(),
                        pos,
                        "TYPEGEN_OBJECT_PROPERTIES_ERROR".to_string()
                    ))?;
                let required = schema.get("required")
                    .and_then(|r| r.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<HashSet<&str>>())
                    .unwrap_or_default();

                for (prop_name, prop_schema) in properties {
                    let (ksl_type, is_optional) = self.json_type_to_ksl(prop_schema)?;
                    
                    // Apply FFI mapping if exists
                    let mapped_type = if let Some(ffi_type) = self.config.ffi_mappings.get(&ksl_type) {
                        ffi_type.to_ksl_type()
                    } else {
                        ksl_type
                    };

                    let field_type = if !required.contains(prop_name.as_str()) || is_optional {
                        format!("result<{}, ()>", mapped_type)
                    } else {
                        mapped_type
                    };
                    nested_code.push_str(&format!("    {}: {},\n", prop_name, field_type));
                }

                nested_code.push_str("}\n");
                Ok((type_name, false))
            }
            "null" => Ok(("()".to_string(), true)),
            _ => Err(KslError::type_error(
                format!("Unsupported schema type: {}", schema_type),
                pos,
                "TYPEGEN_UNSUPPORTED_TYPE".to_string()
            )),
        }
    }
}

/// Public API to generate KSL types
pub fn typegen(
    schema_file: &PathBuf,
    output_file: PathBuf,
    source_type: &str,
    generate_async: bool,
    ffi_mappings: Option<HashMap<String, FFIType>>,
) -> Result<(), KslError> {
    let pos = SourcePosition::new(1, 1);
    if source_type != "json" && source_type != "protobuf" {
        return Err(KslError::type_error(
            format!("Unsupported source type: {}. Use 'json' or 'protobuf'", source_type),
            pos,
            "TYPEGEN_INVALID_SOURCE_TYPE".to_string()
        ));
    }

    let config = TypeGenConfig {
        schema_file: schema_file.clone(),
        output_file,
        source_type: source_type.to_string(),
        generate_async,
        ffi_mappings: ffi_mappings.unwrap_or_default(),
    };
    let typegen = TypeGen::new(config);
    typegen.generate()
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_docgen.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, ParseError};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_docgen {
    pub use super::generate_docgen;
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
    fn test_typegen_json() {
        let temp_dir = TempDir::new().unwrap();
        let schema_file = temp_dir.path().join("schema.json");
        let mut file = File::create(&schema_file).unwrap();
        writeln!(
            file,
            r#"{{
                "title": "Transaction",
                "type": "object",
                "properties": {{
                    "id": {{ "type": "string" }},
                    "amount": {{ "type": "number" }},
                    "is_valid": {{ "type": "boolean" }},
                    "data": {{ "type": "array", "items": {{ "type": "integer" }}, "maxItems": 5 }}
                }},
                "required": ["id", "amount"]
            }}"#
        ).unwrap();

        let output_file = temp_dir.path().join("types.ksl");
        let result = typegen(&schema_file, output_file.clone(), "json", false, None);
        assert!(result.is_ok());

        let content = fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("struct Transaction {"));
        assert!(content.contains("id: string"));
        assert!(content.contains("amount: f64"));
        assert!(content.contains("is_valid: result<bool, ()>"));
        assert!(content.contains("data: array<u32, 5>"));

        // Check documentation
        let doc_file = temp_dir.path().join("generated_types.md");
        assert!(doc_file.exists());
    }

    #[test]
    fn test_typegen_nested_object() {
        let temp_dir = TempDir::new().unwrap();
        let schema_file = temp_dir.path().join("schema.json");
        let mut file = File::create(&schema_file).unwrap();
        writeln!(
            file,
            r#"{{
                "title": "Message",
                "type": "object",
                "properties": {{
                    "header": {{
                        "title": "Header",
                        "type": "object",
                        "properties": {{
                            "sender": {{ "type": "string" }}
                        }}
                    }}
                }}
            }}"#
        ).unwrap();

        let output_file = temp_dir.path().join("types.ksl");
        let result = typegen(&schema_file, output_file.clone(), "json", false, None);
        assert!(result.is_ok());

        let content = fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("struct Message {"));
        assert!(content.contains("header: Header"));
        assert!(content.contains("struct Header {"));
        assert!(content.contains("sender: string"));
    }

    #[test]
    fn test_typegen_invalid_source_type() {
        let temp_dir = TempDir::new().unwrap();
        let schema_file = temp_dir.path().join("schema.json");
        let output_file = temp_dir.path().join("types.ksl");

        let result = typegen(&schema_file, output_file, "invalid", false, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported source type"));
    }

    #[test]
    fn test_typegen_invalid_schema() {
        let temp_dir = TempDir::new().unwrap();
        let schema_file = temp_dir.path().join("schema.json");
        let mut file = File::create(&schema_file).unwrap();
        writeln!(file, "{{ \"type\": \"invalid\" }}").unwrap();

        let output_file = temp_dir.path().join("types.ksl");
        let result = typegen(&schema_file, output_file, "json", false, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Schema root must be an object type"));
    }
}
