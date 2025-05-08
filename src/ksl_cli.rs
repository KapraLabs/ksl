// ksl_cli.rs
// Command-line interface for compiling and running KSL programs.
// Provides tools for development, testing, and documentation generation.

use clap::{Parser, Subcommand, ValueEnum, App, Arg, SubCommand};
use std::fs;
use std::path::PathBuf;
use std::process;
use structopt::StructOpt;

use crate::ksl_parser::{parse, AstNode, ExprKind};
use crate::ksl_checker::check;
use crate::ksl_compiler::{compile, CompilerOptions};
use crate::ksl_bytecode::KapraBytecode;
use crate::kapra_vm::run;
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_docgen::generate_docs;
use crate::ksl_debugger::Debugger;
use crate::ksl_repl::Repl;
use crate::ksl_analyzer::analyze;
use crate::ksl_fuzzer::fuzz;
use crate::ksl_hot_reload::HotReloader;
use crate::ksl_contract_verifier::verify_contract;
use crate::ksl_package::Package;
use crate::ksl_package_publish::publish_package;
use crate::ksl_bind::generate_bindings;
use crate::ksl_plugin::load_plugin;
use crate::ksl_stdlib::print;
use crate::ksl_stdlib_net::http_get;
use crate::ksl_stdlib_crypto::hash;
use crate::ksl_kapra_crypto::sign;
use crate::ksl_kapra_consensus::ConsensusRuntime;
use crate::ksl_kapra_shard::ShardRuntime;
use crate::ksl_kapra_scheduler::Scheduler;
use crate::ksl_ai::run_model;
use crate::ksl_iot::device_comm;
use crate::ksl_game::render;
use crate::ksl_template::generate_template;
use crate::ksl_doc_lsp::start_lsp;
use crate::ksl_analyzer::profile;
use crate::ksl_jit::compile_jit;
use crate::ksl_aot::compile_aot;
use crate::ksl_generics::compile_generic;
use crate::ksl_macros::expand_macro;
use crate::ksl_contract::deploy_contract;
use crate::ksl_kapra_shard::run_shard_benchmark;
use crate::ksl_metrics::{BlockResult, log_metrics};
use tokio::runtime::Runtime;
use std::sync::Arc;

mod ksl_bench;

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
        /// Emit IR representation to .ksl.ir file
        #[arg(short, long)]
        emit_ir: bool,
        /// Specify custom path for IR output file
        #[arg(short, long)]
        ir_output: Option<PathBuf>,
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
        Commands::Compile { file, output, opt_level, target, async_support, jit, debug, emit_ir, ir_output } => {
            compile_file(&file, output.as_ref(), opt_level, target, async_support, jit, debug, emit_ir, ir_output)
        }
        Commands::Run { file, async_support, jit, debug } => {
            run_file(&file, async_support, jit, debug)
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
    emit_ir: bool,
    ir_output: Option<PathBuf>,
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

    // Set up compiler options
    let mut options = CompilerOptions::default();
    options.source_file = file.to_string_lossy().into_owned();
    options.opt_level = match opt_level {
        OptLevel::O0 => 0,
        OptLevel::O1 => 1,
        OptLevel::O2 => 2,
        OptLevel::O3 => 3,
    };
    options.target = match target {
        Target::Native => "native".to_string(),
        Target::Wasm => "wasm".to_string(),
        Target::Jit => "jit".to_string(),
    };
    options.async_support = async_support;
    options.jit = jit;
    options.debug = debug;
    options.emit_ir = emit_ir;
    options.ir_output_path = ir_output.map(|p| p.to_string_lossy().into_owned());

    // If IR output is enabled but no path specified, use default
    if options.emit_ir && options.ir_output_path.is_none() {
        let ir_path = file.with_extension("ksl.ir");
        options.ir_output_path = Some(ir_path.to_string_lossy().into_owned());
    }

    // Compile with options
    let mut bytecode = compile(&ast, &options)
        .map_err(|errors| KslError::compile_errors(errors))?;

    // Apply optimizations based on level
    bytecode = match opt_level {
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

mod ksl_repl {
    pub use super::Repl;
}

mod ksl_analyzer {
    pub use super::analyze;
}

mod ksl_fuzzer {
    pub use super::fuzz;
}

mod ksl_hot_reload {
    pub use super::HotReloader;
}

mod ksl_contract_verifier {
    pub use super::verify_contract;
}

mod ksl_package {
    pub use super::Package;
}

mod ksl_package_publish {
    pub use super::publish_package;
}

mod ksl_bind {
    pub use super::generate_bindings;
}

mod ksl_plugin {
    pub use super::load_plugin;
}

mod ksl_stdlib {
    pub use super::print;
}

mod ksl_stdlib_net {
    pub use super::http_get;
}

mod ksl_stdlib_crypto {
    pub use super::hash;
}

mod ksl_kapra_crypto {
    pub use super::sign;
}

mod ksl_kapra_consensus {
    pub use super::ConsensusRuntime;
}

mod ksl_kapra_shard {
    pub use super::ShardRuntime;
}

mod ksl_kapra_scheduler {
    pub use super::Scheduler;
}

mod ksl_ai {
    pub use super::run_model;
}

mod ksl_iot {
    pub use super::device_comm;
}

mod ksl_game {
    pub use super::render;
}

mod ksl_template {
    pub use super::generate_template;
}

mod ksl_doc_lsp {
    pub use super::start_lsp;
}

mod ksl_analyzer {
    pub use super::profile;
}

mod ksl_jit {
    pub use super::compile_jit;
}

mod ksl_aot {
    pub use super::compile_aot;
}

mod ksl_generics {
    pub use super::compile_generic;
}

mod ksl_macros {
    pub use super::expand_macro;
}

mod ksl_contract {
    pub use super::deploy_contract;
}

mod ksl_kapra_shard {
    pub use super::run_shard_benchmark;
}

mod ksl_metrics {
    pub use super::{BlockResult, log_metrics};
}

mod ksl_bench {
    pub use super::run_benchmark;
}

#[derive(StructOpt)]
#[structopt(name = "ksl", about = "KSL compiler and runtime")]
struct Opt {
    /// Input file to compile and run
    #[structopt(parse(from_os_str))]
    input: Option<PathBuf>,

    /// Output file for compiled bytecode
    #[structopt(short, long, parse(from_os_str))]
    output: Option<PathBuf>,

    /// Run in REPL mode
    #[structopt(short, long)]
    repl: bool,

    /// Generate documentation
    #[structopt(short, long)]
    doc: bool,

    /// Run static analysis
    #[structopt(short, long)]
    analyze: bool,

    /// Run fuzzing tests
    #[structopt(short, long)]
    fuzz: bool,

    /// Enable hot reloading
    #[structopt(short, long)]
    hot_reload: bool,

    /// Verify smart contract
    #[structopt(short, long)]
    verify: bool,

    /// Package management command
    #[structopt(short, long)]
    package: Option<String>,

    /// Publish package
    #[structopt(short, long)]
    publish: bool,

    /// Generate language bindings
    #[structopt(short, long)]
    bind: bool,

    /// Load plugin
    #[structopt(short, long)]
    plugin: Option<String>,

    /// Run LSP server
    #[structopt(short, long)]
    lsp: bool,

    /// Profile performance
    #[structopt(short, long)]
    profile: bool,

    /// Use JIT compilation
    #[structopt(short, long)]
    jit: bool,

    /// Use AOT compilation
    #[structopt(short, long)]
    aot: bool,

    /// Compile generic code
    #[structopt(short, long)]
    generic: bool,

    /// Expand macro
    #[structopt(short, long)]
    macro: bool,

    /// Deploy smart contract
    #[structopt(short, long)]
    deploy: bool,

    /// Run shard benchmark
    #[structopt(short, long)]
    benchmark: bool,
}

fn main() {
    let opt = Opt::from_args();

    // Handle benchmark option
    if opt.benchmark {
        println!("Starting full benchmark suite...");
        ksl_bench::run_benchmark();
        return;
    }

    // Rest of the main function implementation...
    // ... existing code ...
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
            false,
            None,
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
            false,
            None,
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
            false,
            None,
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
            false,
            None,
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