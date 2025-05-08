// ksl_export.rs
// IR to JSON exporter for KSL program auditing

use crate::ksl_ir::{IRProgram, IRExport, IRNode};
use crate::ksl_errors::KslError;
use serde_json::{json, Value};
use std::path::Path;

/// Exports IR program to JSON format
pub fn export_ir_to_json(program: &IRProgram, output_path: &str) -> Result<(), KslError> {
    let export = IRExport::new(program.clone());
    export.export_json(output_path).map_err(|e| {
        KslError::type_error(
            format!("Failed to export IR to JSON: {}", e),
            None,
        )
    })
}

/// Exports IR program to JSON with custom formatting options
pub fn export_ir_to_json_with_options(
    program: &IRProgram,
    output_path: &str,
    pretty: bool,
    include_metadata: bool,
) -> Result<(), KslError> {
    let mut export = IRExport::new(program.clone());
    
    // Customize export based on options
    if !include_metadata {
        export.program.metadata = Default::default();
    }

    let json = if pretty {
        serde_json::to_string_pretty(&export)
    } else {
        serde_json::to_string(&export)
    }.map_err(|e| {
        KslError::type_error(
            format!("Failed to serialize IR to JSON: {}", e),
            None,
        )
    })?;

    std::fs::write(output_path, json).map_err(|e| {
        KslError::type_error(
            format!("Failed to write IR JSON file: {}", e),
            None,
        )
    })
}

/// Exports specific IR nodes to JSON
pub fn export_ir_nodes_to_json(nodes: &[IRNode], output_path: &str) -> Result<(), KslError> {
    let json = serde_json::to_string_pretty(nodes).map_err(|e| {
        KslError::type_error(
            format!("Failed to serialize IR nodes to JSON: {}", e),
            None,
        )
    })?;

    std::fs::write(output_path, json).map_err(|e| {
        KslError::type_error(
            format!("Failed to write IR nodes JSON file: {}", e),
            None,
        )
    })
}

/// Exports IR program to JSON with custom schema
pub fn export_ir_to_json_with_schema(
    program: &IRProgram,
    output_path: &str,
    schema: &str,
) -> Result<(), KslError> {
    let export = IRExport::new(program.clone());
    
    // Create custom schema-based JSON
    let json = json!({
        "schema": schema,
        "program": export.program,
        "export_time": export.export_time,
        "export_version": export.export_version,
    });

    let json_str = serde_json::to_string_pretty(&json).map_err(|e| {
        KslError::type_error(
            format!("Failed to serialize IR with schema to JSON: {}", e),
            None,
        )
    })?;

    std::fs::write(output_path, json_str).map_err(|e| {
        KslError::type_error(
            format!("Failed to write IR JSON file with schema: {}", e),
            None,
        )
    })
}

/// Validates exported JSON against schema
pub fn validate_ir_json(json_path: &str, schema_path: &str) -> Result<bool, KslError> {
    let json_content = std::fs::read_to_string(json_path).map_err(|e| {
        KslError::type_error(
            format!("Failed to read JSON file: {}", e),
            None,
        )
    })?;

    let schema_content = std::fs::read_to_string(schema_path).map_err(|e| {
        KslError::type_error(
            format!("Failed to read schema file: {}", e),
            None,
        )
    })?;

    let json_value: Value = serde_json::from_str(&json_content).map_err(|e| {
        KslError::type_error(
            format!("Failed to parse JSON: {}", e),
            None,
        )
    })?;

    let schema_value: Value = serde_json::from_str(&schema_content).map_err(|e| {
        KslError::type_error(
            format!("Failed to parse schema: {}", e),
            None,
        )
    })?;

    // Basic schema validation
    if let Some(schema) = schema_value.get("schema") {
        if let Some(json_schema) = json_value.get("schema") {
            Ok(schema == json_schema)
        } else {
            Ok(false)
        }
    } else {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ksl_ir::IRNode;

    #[test]
    fn test_export_ir_to_json() {
        let mut program = IRProgram::new("test.ksl");
        program.push(IRNode::Assign("x".to_string(), "42".to_string()));
        
        let result = export_ir_to_json(&program, "test_export.ir.json");
        assert!(result.is_ok());
        
        // Cleanup
        let _ = std::fs::remove_file("test_export.ir.json");
    }

    #[test]
    fn test_export_ir_nodes_to_json() {
        let nodes = vec![
            IRNode::Assign("x".to_string(), "42".to_string()),
            IRNode::Add("y".to_string(), "x".to_string(), "x".to_string()),
        ];
        
        let result = export_ir_nodes_to_json(&nodes, "test_nodes.ir.json");
        assert!(result.is_ok());
        
        // Cleanup
        let _ = std::fs::remove_file("test_nodes.ir.json");
    }

    #[test]
    fn test_export_with_schema() {
        let mut program = IRProgram::new("test.ksl");
        program.push(IRNode::Assign("x".to_string(), "42".to_string()));
        
        let result = export_ir_to_json_with_schema(
            &program,
            "test_schema.ir.json",
            "ksl_ir_v1",
        );
        assert!(result.is_ok());
        
        // Cleanup
        let _ = std::fs::remove_file("test_schema.ir.json");
    }
} 