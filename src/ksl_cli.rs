// ksl_cli.rs
// Command-line interface for compiling and running KSL programs.

use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;

use crate::ksl_parser::{parse, AstNode, ExprKind};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::KapraBytecode;
use crate::kapra_vm::run;

// CLI arguments
#[derive(Parser)]
#[command(name = "ksl")]
#[command(about = "KapraScript Language CLI", long_about = None)]
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
    },
    /// Run a KSL file
    Run {
        /// Input KSL file
        #[arg(short, long)]
        file: PathBuf,
    },
}

// Main CLI entry point
pub fn run_cli() -> Result<(), String> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Compile { file, output } => {
            compile_file(&file, output.as_ref())
        }
        Commands::Run { file } => {
            run_file(&file)
        }
    }
}

// Compile a KSL file to bytecode
fn compile_file(file: &PathBuf, output: Option<&PathBuf>) -> Result<(), String> {
    // Read source file
    let source = fs::read_to_string(file)
        .map_err(|e| format!("Failed to read file {}: {}", file.display(), e))?;

    // Parse
    let ast = parse(&source)
        .map_err(|e| format!("Parse error at position {}: {}", e.position, e.message))?;

    // Type-check
    check(&ast)
        .map_err(|errors| {
            errors
                .into_iter()
                .map(|e| format!("Type error at position {}: {}", e.position, e.message))
                .collect::<Vec<_>>()
                .join("\n")
        })?;

    // Compile
    let bytecode = compile(&ast)
        .map_err(|errors| {
            errors
                .into_iter()
                .map(|e| format!("Compile error at position {}: {}", e.position, e.message))
                .collect::<Vec<_>>()
                .join("\n")
        })?;

    // Output bytecode
    match output {
        Some(out_file) => {
            let bytes = bytecode.encode();
            fs::write(out_file, bytes)
                .map_err(|e| format!("Failed to write output file {}: {}", out_file.display(), e))?;
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

// Run a KSL file
fn run_file(file: &PathBuf) -> Result<(), String> {
    // Read source file
    let source = fs::read_to_string(file)
        .map_err(|e| format!("Failed to read file {}: {}", file.display(), e))?;

    // Parse
    let ast = parse(&source)
        .map_err(|e| format!("Parse error at position {}: {}", e.position, e.message))?;

    // Type-check
    check(&ast)
        .map_err(|errors| {
            errors
                .into_iter()
                .map(|e| format!("Type error at position {}: {}", e.position, e.message))
                .collect::<Vec<_>>()
                .join("\n")
        })?;

    // Compile
    let bytecode = compile(&ast)
        .map_err(|errors| {
            errors
                .into_iter()
                .map(|e| format!("Compile error at position {}: {}", e.position, e.message))
                .collect::<Vec<_>>()
                .join("\n")
        })?;

    // Run
    run(bytecode)
        .map_err(|e| format!("Runtime error at instruction {}: {}", e.pc, e.message))?;

    println!("Program executed successfully");
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_compile() {
        // Create a temporary KSL file
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "let x: u32 = 42;\nfn main(): u32 {{ x }}"
        ).unwrap();

        // Compile to stdout
        let result = compile_file(&temp_file.path().to_path_buf(), None);
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
        let result = run_file(&temp_file.path().to_path_buf());
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_error() {
        // Create a temporary KSL file with invalid syntax
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "let x: u32 = ;").unwrap();

        // Expect parse error
        let result = run_file(&temp_file.path().to_path_buf());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Parse error"));
    }
}