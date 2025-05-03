// ksl_bundler.rs
// Bundles KSL projects into single-file executables for simplified distribution,
// supporting WASM and native targets with optimized bundle size.

use crate::ksl_parser::{parse, ParseError};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_optimizer::{optimize};
use crate::ksl_wasm::generate_wasm;
use crate::ksl_aot::aot_compile;
use crate::ksl_package::{PackageSystem, PackageMetadata};
use crate::ksl_errors::{KslError, SourcePosition};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use toml;

// Bundler configuration
#[derive(Debug)]
pub struct BundlerConfig {
    input_file: PathBuf, // Main KSL source file
    target: String, // Target: "wasm" or "native"
    output_file: PathBuf, // Output bundled file (e.g., app.kslbin)
}

// Bundler for KSL projects
pub struct Bundler {
    config: BundlerConfig,
    package_system: PackageSystem,
}

impl Bundler {
    pub fn new(config: BundlerConfig) -> Self {
        Bundler {
            config,
            package_system: PackageSystem::new(),
        }
    }

    // Bundle a KSL project into a single executable
    pub fn bundle(&mut self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        // Resolve dependencies
        let project_dir = self.config.input_file.parent().unwrap_or_else(|| PathBuf::from("."));
        self.package_system.resolve_dependencies(project_dir)
            .map_err(|e| KslError::type_error(format!("Dependency resolution failed: {}", e), pos))?;

        // Compile main file to bytecode
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
        check(&ast)
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Type error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
            ))?;
        let mut bytecode = compile(&ast)
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Compile error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
            ))?;

        // Optimize bytecode
        optimize(&mut bytecode, 3) // Use highest optimization level
            .map_err(|e| KslError::type_error(format!("Bytecode optimization failed: {}", e), pos))?;

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
                    ))?
            }
            "native" => {
                let temp_file = self.config.output_file.with_extension("o");
                aot_compile(&self.config.input_file, &temp_file, "x86_64")
                    .map_err(|e| KslError::type_error(format!("AOT compilation failed: {}", e), pos))?;
                fs::read(&temp_file)
                    .map_err(|e| KslError::type_error(
                        format!("Failed to read AOT binary {}: {}", temp_file.display(), e),
                        pos,
                    ))?
            }
            _ => return Err(KslError::type_error(
                format!("Unsupported target: {}", self.config.target),
                pos,
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
                ))?;
            let metadata: PackageMetadata = toml::from_str(&metadata_content)
                .map_err(|e| KslError::type_error(
                    format!("Failed to parse metadata: {}", e),
                    pos,
                ))?;
            for (dep_name, dep_version) in metadata.dependencies {
                let dep_dir = self.package_system.repository.join(&dep_name).join(&dep_version).join("src");
                if dep_dir.exists() {
                    for entry in fs::read_dir(&dep_dir)
                        .map_err(|e| KslError::type_error(
                            format!("Failed to read dependency dir {}: {}", dep_dir.display(), e),
                            pos,
                        ))?
                    {
                        let entry = entry?;
                        if entry.path().extension().map(|ext| ext == "ksl").unwrap_or(false) {
                            let dep_source = fs::read_to_string(&entry.path())
                                .map_err(|e| KslError::type_error(
                                    format!("Failed to read dependency file {}: {}", entry.path().display(), e),
                                    pos,
                                ))?;
                            dep_sources.push((dep_name.clone(), dep_version.clone(), dep_source));
                        }
                    }
                }
            }
        }

        // Create bundle
        let mut bundle = Vec::new();
        // Add header (simplified: magic number + target)
        bundle.extend_from_slice(b"KSLBIN");
        bundle.extend_from_slice(self.config.target.as_bytes());
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

        // Write bundle to output file
        File::create(&self.config.output_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to create output file {}: {}", self.config.output_file.display(), e),
                pos,
            ))?
            .write_all(&bundle)
            .map_err(|e| KslError::type_error(
                format!("Failed to write output file {}: {}", self.config.output_file.display(), e),
                pos,
            ))?;

        Ok(())
    }
}

// Public API to bundle a KSL project
pub fn bundle(input_file: &PathBuf, target: &str, output_file: PathBuf) -> Result<(), KslError> {
    let config = BundlerConfig {
        input_file: input_file.clone(),
        target: target.to_string(),
        output_file,
    };
    let mut bundler = Bundler::new(config);
    bundler.bundle()
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_optimizer.rs, ksl_wasm.rs, ksl_aot.rs, ksl_package.rs, and ksl_errors.rs are in the same crate
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

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;

    #[test]
    fn test_bundle_wasm() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        let output_file = temp_dir.path().join("app.kslbin");
        let result = bundle(&input_file, "wasm", output_file.clone());
        assert!(result.is_ok());
        assert!(output_file.exists());

        let content = fs::read(&output_file).unwrap();
        assert!(content.starts_with(b"KSLBINwasm\0"));
    }

    #[test]
    fn test_bundle_native() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        let output_file = temp_dir.path().join("app.kslbin");
        let result = bundle(&input_file, "native", output_file.clone());
        assert!(result.is_ok());
        assert!(output_file.exists());

        let content = fs::read(&output_file).unwrap();
        assert!(content.starts_with(b"KSLBINnative\0"));
    }

    #[test]
    fn test_bundle_invalid_target() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        let output_file = temp_dir.path().join("app.kslbin");
        let result = bundle(&input_file, "invalid", output_file);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported target"));
    }

    #[test]
    fn test_bundle_invalid_file() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("nonexistent.ksl");
        let output_file = temp_dir.path().join("app.kslbin");

        let result = bundle(&input_file, "wasm", output_file);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read file"));
    }
}
