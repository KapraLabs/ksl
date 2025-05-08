// ksl_cli.rs
// Command-line interface for compiling and running KSL programs.
// Provides tools for development, testing, and documentation generation.

use clap::{Parser, Subcommand, ValueEnum};
use std::fs;
use std::path::PathBuf;

use crate::ksl_parser::{parse, AstNode, ExprKind};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::KapraBytecode;
use crate::kapra_vm::run;
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_docgen::generate_docs;
use crate::ksl_debugger::Debugger;

/// Compilation optimization level
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum OptLevel {
    /// No optimization
    O0,
    /// Basic optimization
    O1,
    /// Aggressive optimization
    O2,
    /// Maximum optimization
    O3,
}

/// Compilation target
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Target {
    /// Native execution
    Native,
    /// WebAssembly
    Wasm,
    /// JIT compilation
    Jit,
}

/// CLI arguments
#[derive(Parser)]
#[command(name = "ksl")]
#[command(about = "KapraScript Language CLI", long_about = None)]
#[command(version = "1.0.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compile a KSL file to KapraBytecode
    Compile {
        /// Input KSL file
        #[arg(short, long)]
        file: PathBuf,
        /// Output file for bytecode (optional, defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Optimization level
        #[arg(short, long, value_enum, default_value_t = OptLevel::O2)]
        opt_level: OptLevel,
        /// Compilation target
        #[arg(short, long, value_enum, default_value_t = Target::Native)]
        target: Target,
        /// Enable async support
        #[arg(short, long)]
        async: bool,
        /// Enable JIT compilation
        #[arg(short, long)]
        jit: bool,
        /// Enable debug mode
        #[arg(short = 'D', long)]
        debug: bool,
    },
    /// Run a KSL file
    Run {
        /// Input KSL file
        #[arg(short, long)]
        file: PathBuf,
        /// Enable async support
        #[arg(short, long)]
        async: bool,
        /// Enable JIT compilation
        #[arg(short, long)]
        jit: bool,
        /// Enable debug mode
        #[arg(short = 'D', long)]
        debug: bool,
    },
    /// Generate documentation
    Doc {
        /// Input KSL file or directory
        #[arg(short, long)]
        input: PathBuf,
        /// Output directory for documentation
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Generate documentation for private items
        #[arg(short, long)]
        private: bool,
    },
}

/// Main CLI entry point
pub fn run_cli() -> Result<(), KslError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Compile { file, output, opt_level, target, async, jit, debug } => {
            compile_file(&file, output.as_ref(), opt_level, target, async, jit, debug)
        }
        Commands::Run { file, async, jit, debug } => {
            run_file(&file, async, jit, debug)
        }
        Commands::Doc { input, output, private } => {
            generate_docs(&input, output.as_ref(), private)
        }
    }
}

/// Compile a KSL file to bytecode with enhanced options
fn compile_file(
    file: &PathBuf,
    output: Option<&PathBuf>,
    opt_level: OptLevel,
    target: Target,
    async_support: bool,
    jit: bool,
    debug: bool,
) -> Result<(), KslError> {
    // Read source file
    let source = fs::read_to_string(file)
        .map_err(|e| KslError::io_error(
            format!("Failed to read file {}: {}", file.display(), e),
            SourcePosition::new(1, 1),
        ))?;

    // Parse
    let ast = parse(&source)
        .map_err(|e| KslError::parse_error(e.message, e.position))?;

    // Type-check
    check(&ast)
        .map_err(|errors| KslError::type_errors(errors))?;

    // Compile with options
    let bytecode = compile(&ast)
        .map_err(|errors| KslError::compile_errors(errors))?;

    // Apply optimizations based on level
    let bytecode = match opt_level {
        OptLevel::O0 => bytecode,
        OptLevel::O1 => bytecode.optimize_basic(),
        OptLevel::O2 => bytecode.optimize_aggressive(),
        OptLevel::O3 => bytecode.optimize_max(),
    };

    // Enable debug mode if requested
    if debug {
        println!("Debug mode enabled");
        // Initialize debugger
        let debugger = Debugger::new(file)?;
        debugger.attach_bytecode(&bytecode)?;
    }

    // Output bytecode
    match output {
        Some(out_file) => {
            let bytes = bytecode.encode();
            fs::write(out_file, bytes)
                .map_err(|e| KslError::io_error(
                    format!("Failed to write output file {}: {}", out_file.display(), e),
                    SourcePosition::new(1, 1),
                ))?;
            println!("Compiled to {}", out_file.display());
        }
        None => {
            // Print as hex for debugging
            let bytes = bytecode.encode();
            let hex = bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
            println!("Bytecode:\n{}", hex);
        }
    }

    Ok(())
}

/// Run a KSL file with enhanced options
fn run_file(file: &PathBuf, async_support: bool, jit: bool, debug: bool) -> Result<(), KslError> {
    // Read source file
    let source = fs::read_to_string(file)
        .map_err(|e| KslError::io_error(
            format!("Failed to read file {}: {}", file.display(), e),
            SourcePosition::new(1, 1),
        ))?;

    // Parse
    let ast = parse(&source)
        .map_err(|e| KslError::parse_error(e.message, e.position))?;

    // Type-check
    check(&ast)
        .map_err(|errors| KslError::type_errors(errors))?;

    // Compile
    let bytecode = compile(&ast)
        .map_err(|errors| KslError::compile_errors(errors))?;

    // Run with options
    if jit {
        run_jit(bytecode, async_support, debug)
    } else {
        run(bytecode, async_support, debug)
    }
}

// Assume other modules are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ExprKind};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_compiler {
    pub use super::compile;
}

mod ksl_bytecode {
    pub use super::KapraBytecode;
}

mod kapra_vm {
    pub use super::run;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

mod ksl_docgen {
    pub use super::generate_docs;
}

mod ksl_debugger {
    pub use super::Debugger;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_compile() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "let x: u32 = 42;\nfn main(): u32 {{ x }}"
        ).unwrap();

        let result = compile_file(
            &temp_file.path().to_path_buf(),
            None,
            OptLevel::O2,
            Target::Native,
            false,
            false,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_compile_async() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "async fn main() { let data = await http.get(\"https://example.com\"); }"
        ).unwrap();

        let result = compile_file(
            &temp_file.path().to_path_buf(),
            None,
            OptLevel::O2,
            Target::Native,
            true,
            false,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_compile_jit() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "let x: u32 = 42;\nfn main(): u32 {{ x }}"
        ).unwrap();

        let result = compile_file(
            &temp_file.path().to_path_buf(),
            None,
            OptLevel::O2,
            Target::Jit,
            false,
            true,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_compile_output() {
        // Create a temporary KSL file
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "let x: u32 = 42;\nfn main(): u32 {{ x }}"
        ).unwrap();

        // Compile to output file
        let output_file = NamedTempFile::new().unwrap();
        let result = compile_file(
            &temp_file.path().to_path_buf(),
            Some(&output_file.path().to_path_buf()),
            OptLevel::O2,
            Target::Native,
            false,
            false,
            false,
        );
        assert!(result.is_ok());
        assert!(output_file.path().exists());
    }

    #[test]
    fn test_run() {
        // Create a temporary KSL file
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "let x: u32 = 42;\nfn main(): u32 {{ x }}"
        ).unwrap();

        // Run the program
        let result = run_file(&temp_file.path().to_path_buf(), false, false, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_error() {
        // Create a temporary KSL file with invalid syntax
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "let x: u32 = ;").unwrap();

        // Expect parse error
        let result = run_file(&temp_file.path().to_path_buf(), false, false, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Parse error"));
    }
}