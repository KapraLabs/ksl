// ksl_profile.rs
// Extends ksl_analyzer.rs with advanced profiling for rapid performance optimization,
// providing call graph analysis, memory leak detection, and visual flame graphs.

use crate::ksl_parser::{parse, AstNode, ParseError};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode};
use crate::kapra_vm::{KapraVM, RuntimeError};
use crate::ksl_errors::{KslError, SourcePosition};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Instant, Duration};
use inferno::flamegraph::{from_lines, Options as FlamegraphOptions};

// Profiling data collected during execution
#[derive(Debug)]
pub struct ProfileData {
    call_graph: HashMap<String, CallNode>, // Function name -> call details
    memory_allocations: HashMap<usize, MemoryAllocation>, // Allocation ID -> details
    total_duration: Duration, // Total execution time
}

// Call graph node for a function
#[derive(Debug, Clone)]
pub struct CallNode {
    name: String,
    calls: HashMap<String, u64>, // Callee -> call count
    duration: Duration, // Total time spent in function
}

// Memory allocation details
#[derive(Debug, Clone)]
pub struct MemoryAllocation {
    size: usize, // Bytes allocated
    line: usize, // Source line (approximate)
    freed: bool, // Whether allocation was freed
}

// Profiling report summarizing performance
#[derive(Debug)]
pub struct ProfileReport {
    call_graph: HashMap<String, CallNode>,
    memory_leaks: Vec<MemoryAllocation>,
    total_duration: Duration,
}

impl ProfileReport {
    // Generate a text-based report
    pub fn to_string(&self, source: &str) -> String {
        let mut report = format!(
            "Profiling Report:\nTotal Execution Time: {:.2?}\n\nCall Graph:\n",
            self.total_duration
        );

        for (name, node) in &self.call_graph {
            report.push_str(&format!("Function {} (Duration: {:.2?})\n", name, node.duration));
            for (callee, count) in &node.calls {
                report.push_str(&format!("  -> {}: {} calls\n", callee, count));
            }
        }

        report.push_str("\nMemory Leaks:\n");
        if self.memory_leaks.is_empty() {
            report.push_str("No memory leaks detected.\n");
        } else {
            for alloc in &self.memory_leaks {
                report.push_str(&format!(
                    "Leak: {} bytes at line {}\n",
                    alloc.size, alloc.line
                ));
            }
        }

        report
    }

    // Generate a flame graph
    pub fn to_flamegraph(&self, output_path: &PathBuf) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut lines = vec![];
        for (name, node) in &self.call_graph {
            let stack = format!("{} {}", name, node.duration.as_nanos());
            lines.push(stack);
            for (callee, count) in &node.calls {
                let stack = format!("{};{} {}", name, callee, count);
                lines.push(stack);
            }
        }

        let mut file = File::create(output_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to create flamegraph {}: {}", output_path.display(), e),
                pos,
            ))?;
        let options = FlamegraphOptions::default();
        from_lines(&mut options, lines.iter().map(|s| s.as_str()), &mut file)
            .map_err(|e| KslError::type_error(
                format!("Failed to generate flamegraph: {}", e),
                pos,
            ))?;

        Ok(())
    }
}

// Profiler for collecting and analyzing performance data
pub struct Profiler {
    bytecode: KapraBytecode,
    source: String,
    line_map: HashMap<usize, usize>, // Instruction index -> source line
}

impl Profiler {
    pub fn new(file: &PathBuf) -> Result<Self, KslError> {
        let pos = SourcePosition::new(1, 1);
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
        check(&ast)
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Type error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
            ))?;
        let bytecode = compile(&ast)
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Compile error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
            ))?;

        // Build line map (simplified, to be enhanced with ksl_analyzer.rs)
        let line_map = build_line_map(&ast, &bytecode);

        Ok(Profiler {
            bytecode,
            source,
            line_map,
        })
    }

    // Collect profiling data
    pub fn collect_profile(&self) -> Result<ProfileData, KslError> {
        let mut vm = KapraVM::new_with_profiling(self.bytecode.clone());
        let start = Instant::now();
        run_program_with_profiling(&mut vm, &self.source)?;
        let total_duration = start.elapsed();

        let call_graph = vm.get_call_graph();
        let memory_allocations = vm.get_memory_allocations();

        Ok(ProfileData {
            call_graph,
            memory_allocations,
            total_duration,
        })
    }

    // Generate profiling report
    pub fn generate_report(&self, data: &ProfileData, flamegraph_path: Option<&PathBuf>) -> Result<ProfileReport, KslError> {
        let mut memory_leaks = vec![];
        for alloc in data.memory_allocations.values() {
            if !alloc.freed {
                memory_leaks.push(alloc.clone());
            }
        }

        let report = ProfileReport {
            call_graph: data.call_graph.clone(),
            memory_leaks,
            total_duration: data.total_duration,
        };

        if let Some(path) = flamegraph_path {
            report.to_flamegraph(path)?;
        }

        Ok(report)
    }
}

// Extend KapraVM for profiling
trait ProfileVM {
    fn new_with_profiling(bytecode: KapraBytecode) -> Self;
    fn get_call_graph(&self) -> HashMap<String, CallNode>;
    fn get_memory_allocations(&self) -> HashMap<usize, MemoryAllocation>;
}

impl ProfileVM for KapraVM {
    fn new_with_profiling(bytecode: KapraBytecode) -> Self {
        let mut vm = KapraVM::new(bytecode);
        vm.profiling_data = Some(ProfilingData {
            call_stack: vec![],
            call_graph: HashMap::new(),
            allocations: HashMap::new(),
            current_alloc_id: 0,
        });
        vm
    }

    fn get_call_graph(&self) -> HashMap<String, CallNode> {
        self.profiling_data.as_ref().unwrap().call_graph.clone()
    }

    fn get_memory_allocations(&self) -> HashMap<usize, MemoryAllocation> {
        self.profiling_data.as_ref().unwrap().allocations.clone()
    }
}

// Profiling data structure for KapraVM
struct ProfilingData {
    call_stack: Vec<(String, Instant)>, // (Function, Start Time)
    call_graph: HashMap<String, CallNode>,
    allocations: HashMap<usize, MemoryAllocation>,
    current_alloc_id: usize,
}

// Run program with profiling
fn run_program_with_profiling(vm: &mut KapraVM, source: &str) -> Result<(), KslError> {
    let pos = SourcePosition::new(1, 1);
    let ast = parse(source)
        .map_err(|e| KslError::type_error(
            format!("Parse error at position {}: {}", e.position, e.message),
            pos,
        ))?;
    // Simulate ksl_bench.rs execution
    vm.run()
        .map_err(|e| KslError::type_error(
            format!("Execution error: {}", e),
            pos,
        ))?;
    Ok(())
}

// Build line map (simplified, to be enhanced with ksl_analyzer.rs)
fn build_line_map(ast: &[AstNode], bytecode: &KapraBytecode) -> HashMap<usize, usize> {
    let mut line_map = HashMap::new();
    let mut current_line = 1;

    for (instr_idx, _instr) in bytecode.instructions.iter().enumerate() {
        line_map.insert(instr_idx, current_line);
        current_line += 1;
    }

    line_map
}

// Public API to run profiling
pub fn run_profile(file: &PathBuf, flamegraph_path: Option<&PathBuf>) -> Result<ProfileReport, KslError> {
    let profiler = Profiler::new(file)?;
    let profile_data = profiler.collect_profile()?;
    let report = profiler.generate_report(&profile_data, flamegraph_path)?;

    // Output text report
    println!("{}", report.to_string(&profiler.source));

    Ok(report)
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_bytecode.rs, kapra_vm.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ParseError};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_compiler {
    pub use super::compile;
}

mod ksl_bytecode {
    pub use super::{KapraBytecode, KapraInstruction, KapraOpCode};
}

mod kapra_vm {
    pub use super::{KapraVM, RuntimeError};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_profile_basic() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn main() { let x: u32 = 42; sha3(\"data\"); }"
        ).unwrap();

        let report = run_profile(&temp_file.path().to_path_buf(), None).unwrap();
        assert!(report.total_duration > Duration::from_secs(0));
        assert!(report.call_graph.contains_key("main"));
        assert!(report.call_graph.contains_key("sha3"));
        assert!(report.memory_leaks.is_empty());
    }

    #[test]
    fn test_profile_flamegraph() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn main() { let x: u32 = 42; sha3(\"data\"); }"
        ).unwrap();
        let output_path = temp_file.path().parent().unwrap().join("flamegraph.svg");

        let report = run_profile(&temp_file.path().to_path_buf(), Some(&output_path)).unwrap();
        assert!(output_path.exists());
        assert!(report.call_graph.contains_key("main"));
    }

    #[test]
    fn test_profile_invalid_file() {
        let invalid_file = PathBuf::from("nonexistent.ksl");
        let result = run_profile(&invalid_file, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read file"));
    }
}
