// ksl_bundler.rs
// Bundles KSL projects into single-file executables for simplified distribution,
// supporting WASM and native targets with optimized bundle size.
// Supports async bundling and new module formats.

use crate::ksl_parser::{parse, ParseError};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_optimizer::{optimize};
use crate::ksl_wasm::generate_wasm;
use crate::ksl_aot::aot_compile;
use crate::ksl_package::{PackageSystem, PackageMetadata};
use crate::ksl_module::{ModuleFormat, ModuleSystem};
use crate::ksl_async::{AsyncRuntime, AsyncResult};
use crate::ksl_errors::{KslError, SourcePosition};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use toml;

/// Configuration for the KSL bundler
#[derive(Debug)]
pub struct BundlerConfig {
    /// Main KSL source file to bundle
    pub input_file: PathBuf,
    /// Target platform: "wasm" or "native"
    pub target: String,
    /// Output bundled file path
    pub output_file: PathBuf,
    /// Module format to use
    pub module_format: ModuleFormat,
    /// Whether to use async bundling
    pub async_bundle: bool,
}

/// State for tracking bundling progress
#[derive(Debug, Default)]
pub struct BundleState {
    /// Number of files processed
    pub files_processed: u64,
    /// Total bundle size
    pub total_size: u64,
    /// Time taken for bundling
    pub bundle_time: std::time::Duration,
    /// Current module being processed
    pub current_module: Option<String>,
}

/// Bundler for KSL projects with async support
pub struct Bundler {
    /// Bundler configuration
    config: BundlerConfig,
    /// Package system for dependency management
    package_system: Arc<RwLock<PackageSystem>>,
    /// Module system for format handling
    module_system: Arc<RwLock<ModuleSystem>>,
    /// Async runtime for concurrent operations
    async_runtime: Arc<AsyncRuntime>,
    /// Current bundling state
    state: Arc<RwLock<BundleState>>,
}

impl Bundler {
    /// Creates a new bundler instance
    pub fn new(config: BundlerConfig) -> Self {
        Bundler {
            config,
            package_system: Arc::new(RwLock::new(PackageSystem::new())),
            module_system: Arc::new(RwLock::new(ModuleSystem::new())),
            async_runtime: Arc::new(AsyncRuntime::new()),
            state: Arc::new(RwLock::new(BundleState::default())),
        }
    }

    /// Bundle a KSL project asynchronously
    pub async fn bundle_async(&self) -> AsyncResult<()> {
        let pos = SourcePosition::new(1, 1);
        let start_time = std::time::Instant::now();

        // Resolve dependencies
        let project_dir = self.config.input_file.parent().unwrap_or_else(|| Path::new("."));
        let package_system = self.package_system.read().await;
        let resolved_deps = package_system.resolve_dependencies_async(project_dir).await
            .map_err(|e| KslError::type_error(format!("Dependency resolution failed: {}", e), pos, "E0001".to_string()))?;

        // Read main source file
        let source = fs::read_to_string(&self.config.input_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to read file {}: {}", self.config.input_file.display(), e),
                pos,
                "E0002".to_string()
            ))?;
        let ast = parse(&source)
            .map_err(|e| KslError::type_error(
                format!("Parse error at position {}: {}", e.position, e.message),
                pos,
                "E0003".to_string()
            ))?;
        check(&ast[..])
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Type error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
                "E0004".to_string()
            ))?;
        let mut bytecode = compile(ast.as_slice())
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Compile error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
                "E0005".to_string()
            ))?;

        // Optimize bytecode
        optimize(&mut bytecode)
            .map_err(|e| KslError::type_error(format!("Bytecode optimization failed: {:?}", e), pos, "E0006".to_string()))?;

        // Generate target binary
        let binary_data = match self.config.target.as_str() {
            "wasm" => {
                generate_wasm(bytecode)
                    .map_err(|errors| KslError::type_error(
                        errors.into_iter()
                            .map(|e| format!("WASM error at instruction {}: {}", e.instruction, e.message))
                            .collect::<Vec<_>>()
                            .join("\n"),
                        pos,
                        "E0007".to_string()
                    ))?
            }
            "native" => {
                let temp_file = self.config.output_file.with_extension("o");
                aot_compile(&self.config.input_file, &temp_file, "x86_64")
                    .map_err(|e| KslError::type_error(format!("AOT compilation failed: {}", e), pos, "E0008".to_string()))?;
                fs::read(&temp_file)
                    .map_err(|e| KslError::type_error(
                        format!("Failed to read AOT binary {}: {}", temp_file.display(), e),
                        pos,
                        "E0009".to_string()
                    ))?
            }
            _ => return Err(KslError::type_error(
                format!("Unsupported target: {}", self.config.target),
                pos,
                "E0010".to_string()
            )),
        };

        // Collect dependency source code
        let mut dep_sources = Vec::new();
        let metadata_file = project_dir.join("ksl_package.toml");
        if metadata_file.exists() {
            let metadata_content = fs::read_to_string(&metadata_file)
                .map_err(|e| KslError::type_error(
                    format!("Failed to read metadata {}: {}", metadata_file.display(), e),
                    pos,
                    "E0011".to_string()
                ))?;
            let metadata: PackageMetadata = toml::from_str(&metadata_content)
                .map_err(|e| KslError::type_error(
                    format!("Failed to parse metadata: {}", e),
                    pos,
                    "E0012".to_string()
                ))?;

            for (dep_name, dep_version) in metadata.dependencies {
                let dep_dir = package_system.repository.join(&dep_name).join(&dep_version).join("src");
                if dep_dir.exists() {
                    let dep_source = fs::read_to_string(&dep_dir)
                        .map_err(|e| KslError::type_error(
                            format!("Failed to read dependency source {}: {}", dep_dir.display(), e),
                            pos,
                            "E0013".to_string()
                        ))?;
                    dep_sources.push((dep_name.clone(), dep_version.clone(), dep_source));
                }
            }
        }

        // Create bundle
        let mut bundle = Vec::new();
        // Add header (magic number + target + module format)
        bundle.extend_from_slice(b"KSLBIN");
        bundle.extend_from_slice(self.config.target.as_bytes());
        bundle.push(0); // Separator
        bundle.extend_from_slice(self.config.module_format.to_string().as_bytes());
        bundle.push(0); // Separator

        // Add binary data (compressed)
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&binary_data)?;
        let compressed_binary = encoder.finish()?;
        let binary_len = compressed_binary.len() as u32;
        bundle.extend_from_slice(&binary_len.to_le_bytes());
        bundle.extend_from_slice(&compressed_binary);

        // Add dependency sources (compressed)
        let mut dep_data = Vec::new();
        for (name, version, source) in dep_sources {
            dep_data.extend_from_slice(name.as_bytes());
            dep_data.push(0);
            dep_data.extend_from_slice(version.as_bytes());
            dep_data.push(0);
            dep_data.extend_from_slice(source.as_bytes());
            dep_data.push(0);
        }
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&dep_data)?;
        let compressed_deps = encoder.finish()?;
        let deps_len = compressed_deps.len() as u32;
        bundle.extend_from_slice(&deps_len.to_le_bytes());
        bundle.extend_from_slice(&compressed_deps);

        // Update state
        let mut state = self.state.write().await;
        state.files_processed = dep_sources.len() as u64 + 1; // +1 for main file
        state.total_size = bundle.len() as u64;
        state.bundle_time = start_time.elapsed();

        // Write bundle to output file
        if let Some(output_file) = &self.config.output_file {
            fs::write(output_file, &bundle)
                .map_err(|e| KslError::type_error(
                    format!("Failed to write output file {}: {}", output_file.display(), e),
                    pos,
                    "E0014".to_string()
                ))?;
        }

        Ok(())
    }
}

/// Public API to bundle a KSL project asynchronously
pub async fn bundle_async(input_file: &PathBuf, target: &str, output_file: PathBuf, module_format: ModuleFormat) -> AsyncResult<()> {
    let config = BundlerConfig {
        input_file: input_file.clone(),
        target: target.to_string(),
        output_file,
        module_format,
        async_bundle: true,
    };
    let bundler = Bundler::new(config);
    bundler.bundle_async().await
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_optimizer.rs, ksl_wasm.rs, ksl_aot.rs,
// ksl_package.rs, ksl_module.rs, ksl_async.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, ParseError};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_compiler {
    pub use super::compile;
}

mod ksl_optimizer {
    pub use super::optimize;
}

mod ksl_wasm {
    pub use super::generate_wasm;
}

mod ksl_aot {
    pub use super::aot_compile;
}

mod ksl_package {
    pub use super::{PackageSystem, PackageMetadata};
}

mod ksl_module {
    pub use super::{ModuleFormat, ModuleSystem};
}

mod ksl_async {
    pub use super::{AsyncRuntime, AsyncResult};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_bundle_wasm_async() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let output_file = temp_dir.path().join("output.kslbin");
        fs::write(&input_file, r#"
            fn main() {
                println!("Hello, world!");
            }
        "#).unwrap();

        let result = bundle_async(
            &input_file,
            "wasm",
            output_file.clone(),
            ModuleFormat::Standard,
        ).await;
        assert!(result.is_ok());

        // Verify bundle contents
        let mut bundle = Vec::new();
        File::open(&output_file).unwrap().read_to_end(&mut bundle).unwrap();
        assert!(bundle.starts_with(b"KSLBIN"));
    }

    #[tokio::test]
    async fn test_bundle_native_async() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let output_file = temp_dir.path().join("output.kslbin");
        fs::write(&input_file, r#"
            fn main() {
                println!("Hello, world!");
            }
        "#).unwrap();

        let result = bundle_async(
            &input_file,
            "native",
            output_file.clone(),
            ModuleFormat::Standard,
        ).await;
        assert!(result.is_ok());

        // Verify bundle contents
        let mut bundle = Vec::new();
        File::open(&output_file).unwrap().read_to_end(&mut bundle).unwrap();
        assert!(bundle.starts_with(b"KSLBIN"));
    }

    #[tokio::test]
    async fn test_bundle_invalid_target() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let output_file = temp_dir.path().join("output.kslbin");
        fs::write(&input_file, r#"
            fn main() {
                println!("Hello, world!");
            }
        "#).unwrap();

        let result = bundle_async(
            &input_file,
            "invalid",
            output_file,
            ModuleFormat::Standard,
        ).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_bundle_invalid_file() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("nonexistent.ksl");
        let output_file = temp_dir.path().join("output.kslbin");

        let result = bundle_async(
            &input_file,
            "wasm",
            output_file,
            ModuleFormat::Standard,
        ).await;
        assert!(result.is_err());
    }
}
