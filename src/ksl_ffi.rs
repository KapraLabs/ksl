// ksl_ffi.rs
// Provides a Foreign Function Interface (FFI) for calling KSL code from other
// languages and vice versa, generating C-compatible bindings.

use crate::ksl_parser::{parse, AstNode, ExprKind, ParseError};
use crate::ksl_checker::check;
use crate::ksl_security::{analyze_security, SecurityIssue};
use crate::ksl_package::{PackageSystem};
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

// FFI configuration
#[derive(Debug)]
pub struct FfiConfig {
    input_file: PathBuf, // Source KSL file
    output_file: PathBuf, // Output header file (e.g., output.h)
    language: String, // Target language: "c"
}

// FFI generator
pub struct FfiGenerator {
    config: FfiConfig,
    package_system: PackageSystem,
}

impl FfiGenerator {
    pub fn new(config: FfiConfig) -> Self {
        FfiGenerator {
            config,
            package_system: PackageSystem::new(),
        }
    }

    // Generate FFI bindings
    pub fn generate(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        // Read and parse source
        let source = fs::read_to_string(&self.config.input_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to read file {}: {}", self.config.input_file.display(), e),
                pos,
            ))?;
        let ast = parse(&source)
            .map_err(|e| KslError::type_error(
                format!("Parse error at position {}: {}", e.position, e.message),
                pos,
            ))?;

        // Validate source
        check(&ast)
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Type error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
            ))?;

        // Run security analysis
        let security_issues = analyze_security(&self.config.input_file, None)?;
        if !security_issues.is_empty() {
            return Err(KslError::type_error(
                format!("Security issues found: {:?}", security_issues),
                pos,
            ));
        }

        // Generate bindings
        let bindings = match self.config.language.as_str() {
            "c" => self.generate_c_bindings(&ast)?,
            _ => return Err(KslError::type_error(
                format!("Unsupported target language: {}", self.config.language),
                pos,
            )),
        };

        // Write bindings
        File::create(&self.config.output_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to create output file {}: {}", self.config.output_file.display(), e),
                pos,
            ))?
            .write_all(bindings.as_bytes())
            .map_err(|e| KslError::type_error(
                format!("Failed to write output file {}: {}", self.config.output_file.display(), e),
                pos,
            ))?;

        Ok(())
    }

    // Generate C bindings
    fn generate_c_bindings(&self, ast: &[AstNode]) -> Result<String, KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut c_code = String::new();
        c_code.push_str("/* Generated C bindings for KSL */\n");
        c_code.push_str("#ifndef KSL_FFI_H\n");
        c_code.push_str("#define KSL_FFI_H\n\n");
        c_code.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n");

        for node in ast {
            if let AstNode::FnDecl { name, params, return_type, attributes, .. } = node {
                if attributes.iter().any(|attr| attr.name == "ffi") {
                    let c_return_type = ksl_type_to_c(return_type)?;
                    let param_strings: Vec<String> = params.iter()
                        .map(|(name, typ)| Ok(format!("{} {}", ksl_type_to_c(typ)?, name)))
                        .collect::<Result<Vec<String>, KslError>>()?;
                    c_code.push_str(&format!(
                        "{} ksl_{}({});\n",
                        c_return_type,
                        name,
                        param_strings.join(", ")
                    ));
                }
            }
        }

        c_code.push_str("\n#ifdef __cplusplus\n}\n#endif\n");
        c_code.push_str("#endif // KSL_FFI_H\n");
        Ok(c_code)
    }
}

// Convert KSL type to C type
fn ksl_type_to_c(typ: &TypeAnnotation) -> Result<String, KslError> {
    let pos = SourcePosition::new(1, 1);
    match typ {
        TypeAnnotation::Simple(name) => match name.as_str() {
            "u32" => Ok("uint32_t".to_string()),
            "f64" => Ok("double".to_string()),
            "bool" => Ok("bool".to_string()),
            "string" => Ok("const char*".to_string()),
            _ => Err(KslError::type_error(
                format!("Unsupported KSL type for FFI: {}", name),
                pos,
            )),
        },
        TypeAnnotation::Array { element, size } => {
            let c_element = match element.as_str() {
                "u8" => "uint8_t".to_string(),
                _ => return Err(KslError::type_error(
                    format!("Unsupported array element type for FFI: {}", element),
                    pos,
                )),
            };
            Ok(format!("{}[{}]", c_element, size))
        }
        _ => Err(KslError::type_error(
            "Complex types not supported for FFI".to_string(),
            pos,
        )),
    }
}

// Public API to generate FFI bindings
pub fn generate_ffi(input_file: &PathBuf, output_file: PathBuf, language: &str) -> Result<(), KslError> {
    let pos = SourcePosition::new(1, 1);
    if language != "c" {
        return Err(KslError::type_error(
            format!("Unsupported target language: {}. Use 'c'", language),
            pos,
        ));
    }

    let config = FfiConfig {
        input_file: input_file.clone(),
        output_file,
        language: language.to_string(),
    };
    let generator = FfiGenerator::new(config);
    generator.generate()
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_security.rs, ksl_package.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ExprKind, ParseError};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_security {
    pub use super::{analyze_security, SecurityIssue};
}

mod ksl_package {
    pub use super::PackageSystem;
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
    fn test_generate_ffi_c() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "#[ffi]\nfn add(x: u32, y: u32): u32 {{ x + y }}\n#[ffi]\nfn get_data(id: u32): array<u8, 32> {{ [0; 32] }}"
        ).unwrap();

        let output_file = temp_dir.path().join("output.h");
        let result = generate_ffi(&input_file, output_file.clone(), "c");
        assert!(result.is_ok());

        let content = fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("#ifndef KSL_FFI_H"));
        assert!(content.contains("uint32_t ksl_add(uint32_t x, uint32_t y);"));
        assert!(content.contains("uint8_t ksl_get_data(uint32_t id)[32];"));
    }

    #[test]
    fn test_generate_ffi_security_issue() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "#[ffi]\nfn risky() {{ http.get(\"url\"); }}"
        ).unwrap();

        let output_file = temp_dir.path().join("output.h");
        let result = generate_ffi(&input_file, output_file, "c");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Security issues found"));
    }

    #[test]
    fn test_generate_ffi_invalid_language() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "#[ffi]\nfn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        let output_file = temp_dir.path().join("output.h");
        let result = generate_ffi(&input_file, output_file, "invalid");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported target language"));
    }

    #[test]
    fn test_generate_ffi_invalid_file() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("nonexistent.ksl");
        let output_file = temp_dir.path().join("output.h");

        let result = generate_ffi(&input_file, output_file, "c");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read file"));
    }
}