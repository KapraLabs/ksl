// ksl_ffi.rs
// Provides a Foreign Function Interface (FFI) for calling KSL code from other
// languages and vice versa, generating C-compatible bindings with async support.

use crate::ksl_parser::{parse, AstNode, ExprKind, ParseError, TypeAnnotation};
use crate::ksl_checker::check;
use crate::ksl_security::{analyze_security, SecurityIssue};
use crate::ksl_package::{PackageSystem};
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_types::{Type, TypeError};
use crate::ksl_async::{AsyncRuntime, AsyncVM};
use crate::kapra_vm::{KapraVM, KapraBytecode};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// FFI configuration with async support
/// @struct FfiConfig
/// @field input_file Source KSL file
/// @field output_file Output header file (e.g., output.h)
/// @field language Target language (e.g., "c")
/// @field enable_async Whether to enable async FFI calls
#[derive(Debug)]
pub struct FfiConfig {
    input_file: PathBuf,
    output_file: PathBuf,
    language: String,
    enable_async: bool,
}

/// FFI generator with async and VM support
/// @struct FfiGenerator
/// @field config FFI configuration
/// @field package_system Package system for dependency resolution
/// @field async_runtime Async runtime for async FFI calls
/// @field vm Virtual machine for executing KSL code
pub struct FfiGenerator {
    config: FfiConfig,
    package_system: PackageSystem,
    async_runtime: Arc<RwLock<AsyncRuntime>>,
    vm: Option<KapraVM>,
}

impl FfiGenerator {
    /// Creates a new FFI generator with the given configuration
    /// @param config FFI configuration
    /// @returns A new `FfiGenerator` instance
    pub fn new(config: FfiConfig) -> Self {
        FfiGenerator {
            config,
            package_system: PackageSystem::new(),
            async_runtime: Arc::new(RwLock::new(AsyncRuntime::new())),
            vm: None,
        }
    }

    /// Generates FFI bindings with async support
    /// @returns `Ok(())` if generation succeeds, or `Err` with a `KslError`
    pub async fn generate_async(&mut self) -> Result<(), KslError> {
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

        // Initialize VM if async is enabled
        if self.config.enable_async {
            let bytecode = self.package_system.compile(&ast)?;
            self.vm = Some(KapraVM::new_with_async(bytecode));
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

    /// Generates C bindings with async support
    /// @param ast AST nodes to generate bindings for
    /// @returns Generated C code as a string
    fn generate_c_bindings(&self, ast: &[AstNode]) -> Result<String, KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut c_code = String::new();
        c_code.push_str("/* Generated C bindings for KSL */\n");
        c_code.push_str("#ifndef KSL_FFI_H\n");
        c_code.push_str("#define KSL_FFI_H\n\n");
        c_code.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n");

        // Add async support headers if enabled
        if self.config.enable_async {
            c_code.push_str("#include <stdbool.h>\n");
            c_code.push_str("#include <stdint.h>\n\n");
            c_code.push_str("// Async callback type\n");
            c_code.push_str("typedef void (*ksl_async_callback)(void* user_data, const char* result);\n\n");
        }

        for node in ast {
            match node {
                AstNode::FnDecl { name, params, return_type, attributes, .. } => {
                    if attributes.iter().any(|attr| attr.name == "ffi") {
                        let is_async = attributes.iter().any(|attr| attr.name == "async");
                        let c_return_type = ksl_type_to_c(return_type)?;
                        let param_strings: Vec<String> = params.iter()
                            .map(|(name, typ)| Ok(format!("{} {}", ksl_type_to_c(typ)?, name)))
                            .collect::<Result<Vec<String>, KslError>>()?;

                        if is_async && self.config.enable_async {
                            // Generate async function signature
                            c_code.push_str(&format!(
                                "void ksl_{}_async({}, ksl_async_callback callback, void* user_data);\n",
                                name,
                                param_strings.join(", ")
                            ));
                        } else {
                            // Generate sync function signature
                            c_code.push_str(&format!(
                                "{} ksl_{}({});\n",
                                c_return_type,
                                name,
                                param_strings.join(", ")
                            ));
                        }
                    }
                }
                AstNode::AsyncFnDecl { name, params, return_type, attributes, .. } => {
                    if attributes.iter().any(|attr| attr.name == "ffi") && self.config.enable_async {
                        let c_return_type = ksl_type_to_c(return_type)?;
                        let param_strings: Vec<String> = params.iter()
                            .map(|(name, typ)| Ok(format!("{} {}", ksl_type_to_c(typ)?, name)))
                            .collect::<Result<Vec<String>, KslError>>()?;

                        c_code.push_str(&format!(
                            "void ksl_{}_async({}, ksl_async_callback callback, void* user_data);\n",
                            name,
                            param_strings.join(", ")
                        ));
                    }
                }
                _ => {}
            }
        }

        c_code.push_str("\n#ifdef __cplusplus\n}\n#endif\n");
        c_code.push_str("#endif // KSL_FFI_H\n");
        Ok(c_code)
    }

    /// Executes an async FFI call
    /// @param name Function name
    /// @param args Function arguments
    /// @param callback Async callback
    /// @param user_data User data for callback
    /// @returns `Ok(())` if execution succeeds, or `Err` with a `KslError`
    pub async fn execute_async(
        &mut self,
        name: &str,
        args: &[Value],
        callback: Box<dyn FnOnce(Result<Value, KslError>)>,
        user_data: *mut std::ffi::c_void,
    ) -> Result<(), KslError> {
        if !self.config.enable_async {
            return Err(KslError::type_error(
                "Async FFI calls are not enabled".to_string(),
                SourcePosition::new(1, 1),
            ));
        }

        let vm = self.vm.as_mut().ok_or_else(|| KslError::type_error(
            "VM not initialized".to_string(),
            SourcePosition::new(1, 1),
        ))?;

        // Execute function in VM
        vm.run_with_async(&self.async_runtime).await?;

        // Call callback with result
        callback(Ok(Value::Void)); // Simplified for now
        Ok(())
    }
}

// Convert KSL type to C type with new type mappings
fn ksl_type_to_c(typ: &TypeAnnotation) -> Result<String, KslError> {
    let pos = SourcePosition::new(1, 1);
    match typ {
        TypeAnnotation::Simple(name) => match name.as_str() {
            "u8" => Ok("uint8_t".to_string()),
            "u16" => Ok("uint16_t".to_string()),
            "u32" => Ok("uint32_t".to_string()),
            "u64" => Ok("uint64_t".to_string()),
            "i8" => Ok("int8_t".to_string()),
            "i16" => Ok("int16_t".to_string()),
            "i32" => Ok("int32_t".to_string()),
            "i64" => Ok("int64_t".to_string()),
            "f32" => Ok("float".to_string()),
            "f64" => Ok("double".to_string()),
            "bool" => Ok("bool".to_string()),
            "string" => Ok("const char*".to_string()),
            "void" => Ok("void".to_string()),
            _ => Err(KslError::type_error(
                format!("Unsupported KSL type for FFI: {}", name),
                pos,
            )),
        },
        TypeAnnotation::Array { element, size } => {
            let c_element = match element.as_str() {
                "u8" => "uint8_t".to_string(),
                "u16" => "uint16_t".to_string(),
                "u32" => "uint32_t".to_string(),
                "i8" => "int8_t".to_string(),
                "i16" => "int16_t".to_string(),
                "i32" => "int32_t".to_string(),
                "f32" => "float".to_string(),
                "f64" => "double".to_string(),
                _ => return Err(KslError::type_error(
                    format!("Unsupported array element type for FFI: {}", element),
                    pos,
                )),
            };
            Ok(format!("{}[{}]", c_element, size))
        }
        TypeAnnotation::Result { success, error } => {
            let c_success = ksl_type_to_c(success)?;
            let c_error = ksl_type_to_c(error)?;
            Ok(format!("struct ksl_result {{ {} success; {} error; bool is_error; }}", c_success, c_error))
        }
        _ => Err(KslError::type_error(
            "Complex types not supported for FFI".to_string(),
            pos,
        )),
    }
}

// Public API to generate FFI bindings with async support
pub async fn generate_ffi_async(
    input_file: &PathBuf,
    output_file: PathBuf,
    language: &str,
    enable_async: bool,
) -> Result<(), KslError> {
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
        enable_async,
    };
    let mut generator = FfiGenerator::new(config);
    generator.generate_async().await
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_security.rs, ksl_package.rs, ksl_types.rs,
// ksl_async.rs, kapra_vm.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ExprKind, ParseError, TypeAnnotation};
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

mod ksl_types {
    pub use super::{Type, TypeError};
}

mod ksl_async {
    pub use super::{AsyncRuntime, AsyncVM};
}

mod kapra_vm {
    pub use super::{KapraVM, KapraBytecode};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;
    use tokio::runtime::Runtime;

    #[tokio::test]
    async fn test_generate_ffi_c_async() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "#[ffi]\n#[async]\nfn fetch(url: string): result<string, error> {{ let data = await http.get(url); }}\n#[ffi]\nfn add(x: u32, y: u32): u32 {{ x + y }}"
        ).unwrap();

        let output_file = temp_dir.path().join("output.h");
        let result = generate_ffi_async(&input_file, output_file.clone(), "c", true).await;
        assert!(result.is_ok());

        let content = fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("#ifndef KSL_FFI_H"));
        assert!(content.contains("void ksl_fetch_async(const char* url, ksl_async_callback callback, void* user_data);"));
        assert!(content.contains("uint32_t ksl_add(uint32_t x, uint32_t y);"));
    }

    #[tokio::test]
    async fn test_generate_ffi_security_issue() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "#[ffi]\nfn risky() {{ http.get(\"url\"); }}"
        ).unwrap();

        let output_file = temp_dir.path().join("output.h");
        let result = generate_ffi_async(&input_file, output_file, "c", true).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Security issues found"));
    }

    #[tokio::test]
    async fn test_generate_ffi_invalid_language() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "#[ffi]\nfn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        let output_file = temp_dir.path().join("output.h");
        let result = generate_ffi_async(&input_file, output_file, "invalid", true).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported target language"));
    }
}