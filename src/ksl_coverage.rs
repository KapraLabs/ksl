// ksl_coverage.rs
// Implements code coverage measurement for KSL tests, tracking executed bytecode
// instructions and generating rapid line/branch coverage reports.

use crate::ksl_parser::{parse, AstNode, ParseError};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_test::{run_tests, TestResult};
use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode};
use crate::kapra_vm::{KapraVM, RuntimeError};
use crate::ksl_errors::{KslError, SourcePosition};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

/// Coverage data collected during test execution
#[derive(Debug, Serialize, Deserialize)]
pub struct CoverageData {
    /// Indices of executed bytecode instructions
    executed_instructions: HashSet<usize>,
    /// Instruction index -> source line number mapping
    line_map: HashMap<usize, usize>,
    /// Instruction index -> (branch_line, taken) mapping
    branch_map: HashMap<usize, Vec<(usize, bool)>>,
    /// Coverage data for networking operations
    networking_coverage: HashMap<String, usize>,
    /// Coverage data for async operations
    async_coverage: HashMap<String, usize>,
}

/// Coverage report summarizing line, branch, networking, and async coverage
#[derive(Debug, Serialize, Deserialize)]
pub struct CoverageReport {
    /// Set of covered source lines
    covered_lines: HashSet<usize>,
    /// Set of all source lines
    total_lines: HashSet<usize>,
    /// Set of covered branches (line, taken)
    covered_branches: HashSet<(usize, bool)>,
    /// Set of all branches (line, taken)
    total_branches: HashSet<(usize, bool)>,
    /// Coverage data for networking operations
    networking_coverage: HashMap<String, usize>,
    /// Coverage data for async operations
    async_coverage: HashMap<String, usize>,
}

impl CoverageReport {
    /// Generate a human-readable coverage report
    pub fn to_string(&self, source: &str) -> String {
        let line_coverage = self.covered_lines.len() as f32 / self.total_lines.len().max(1) as f32 * 100.0;
        let branch_coverage = self.covered_branches.len() as f32 / self.total_branches.len().max(1) as f32 * 100.0;

        let mut report = format!(
            "Coverage Report:\nLine Coverage: {:.2}% ({}/{} lines)\nBranch Coverage: {:.2}% ({}/{} branches)\n\n",
            line_coverage, self.covered_lines.len(), self.total_lines.len(),
            branch_coverage, self.covered_branches.len(), self.total_branches.len()
        );

        // Add networking coverage
        if !self.networking_coverage.is_empty() {
            report.push_str("\nNetworking Coverage:\n");
            for (op, count) in &self.networking_coverage {
                report.push_str(&format!("  {}: {} executions\n", op, count));
            }
        }

        // Add async coverage
        if !self.async_coverage.is_empty() {
            report.push_str("\nAsync Coverage:\n");
            for (op, count) in &self.async_coverage {
                report.push_str(&format!("  {}: {} executions\n", op, count));
            }
        }

        // Annotate source code with coverage
        report.push_str("\nSource Code Coverage:\n");
        for (line_num, line) in source.lines().enumerate().map(|(i, l)| (i + 1, l)) {
            let is_covered = self.covered_lines.contains(&line_num);
            report.push_str(&format!(
                "{:4} [{}] {}\n",
                line_num,
                if is_covered { "X" } else { " " },
                line
            ));
        }

        report
    }

    /// Generate a JSON coverage report
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Export coverage data for debugging
    pub fn export_for_debug(&self) -> (HashSet<usize>, HashSet<(usize, bool)>) {
        (self.covered_lines.clone(), self.covered_branches.clone())
    }
}

// Coverage analyzer
pub struct CoverageAnalyzer {
    bytecode: KapraBytecode,
    source: String,
    line_map: HashMap<usize, usize>,
    branch_map: HashMap<usize, Vec<(usize, bool)>>,
}

impl CoverageAnalyzer {
    /// Create a new CoverageAnalyzer for the given file
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

        // Build line and branch maps
        let (line_map, branch_map) = build_coverage_maps(&ast, &bytecode);

        Ok(CoverageAnalyzer {
            bytecode,
            source,
            line_map,
            branch_map,
        })
    }

    /// Run tests and collect coverage data
    pub fn collect_coverage(&self) -> Result<CoverageData, KslError> {
        let mut vm = KapraVM::new_with_coverage(self.bytecode.clone());
        let executed_instructions = run_tests_with_coverage(&mut vm, &self.source)?;

        // Track networking and async operations
        let mut networking_coverage = HashMap::new();
        let mut async_coverage = HashMap::new();

        for (instr_idx, instr) in self.bytecode.instructions.iter().enumerate() {
            if executed_instructions.contains(&instr_idx) {
                // Track networking operations
                if matches!(instr.opcode, 
                    KapraOpCode::HttpGet | 
                    KapraOpCode::HttpPost | 
                    KapraOpCode::HttpPut | 
                    KapraOpCode::HttpDelete |
                    KapraOpCode::TcpConnect |
                    KapraOpCode::TcpListen |
                    KapraOpCode::TcpAccept |
                    KapraOpCode::TcpSend |
                    KapraOpCode::TcpReceive
                ) {
                    let op_name = format!("{:?}", instr.opcode);
                    *networking_coverage.entry(op_name).or_insert(0) += 1;
                }

                // Track async operations
                if matches!(instr.opcode,
                    KapraOpCode::AsyncStart |
                    KapraOpCode::AsyncAwait |
                    KapraOpCode::AsyncResolve
                ) {
                    let op_name = format!("{:?}", instr.opcode);
                    *async_coverage.entry(op_name).or_insert(0) += 1;
                }
            }
        }

        Ok(CoverageData {
            executed_instructions,
            line_map: self.line_map.clone(),
            branch_map: self.branch_map.clone(),
            networking_coverage,
            async_coverage,
        })
    }

    /// Generate coverage report from collected data
    pub fn generate_report(&self, data: &CoverageData) -> CoverageReport {
        let mut covered_lines = HashSet::new();
        let mut covered_branches = HashSet::new();
        let mut total_lines = HashSet::new();
        let mut total_branches = HashSet::new();

        // Collect covered lines
        for (instr_idx, line) in &data.line_map {
            total_lines.insert(*line);
            if data.executed_instructions.contains(instr_idx) {
                covered_lines.insert(*line);
            }
        }

        // Collect covered branches
        for (instr_idx, branches) in &data.branch_map {
            for (line, taken) in branches {
                total_branches.insert((*line, *taken));
                if data.executed_instructions.contains(instr_idx) {
                    covered_branches.insert((*line, *taken));
                }
            }
        }

        CoverageReport {
            covered_lines,
            total_lines,
            covered_branches,
            total_branches,
            networking_coverage: data.networking_coverage.clone(),
            async_coverage: data.async_coverage.clone(),
        }
    }
}

// Extend KapraVM to track coverage
trait CoverageVM {
    fn new_with_coverage(bytecode: KapraBytecode) -> Self;
    fn get_executed_instructions(&self) -> &HashSet<usize>;
}

impl CoverageVM for KapraVM {
    fn new_with_coverage(bytecode: KapraBytecode) -> Self {
        let mut vm = KapraVM::new(bytecode);
        vm.coverage_data = Some(HashSet::new()); // Assuming KapraVM has a coverage_data field
        vm
    }

    fn get_executed_instructions(&self) -> &HashSet<usize> {
        self.coverage_data.as_ref().unwrap()
    }
}

// Run tests with coverage tracking
fn run_tests_with_coverage(vm: &mut KapraVM, source: &str) -> Result<HashSet<usize>, KslError> {
    let pos = SourcePosition::new(1, 1);
    let ast = parse(source)
        .map_err(|e| KslError::type_error(
            format!("Parse error at position {}: {}", e.position, e.message),
            pos,
        ))?;
    run_tests(&ast, vm)
        .map_err(|e| KslError::type_error(
            format!("Test execution error: {}", e),
            pos,
        ))?;
    Ok(vm.get_executed_instructions().clone())
}

// Build line and branch maps from AST and bytecode
fn build_coverage_maps(ast: &[AstNode], bytecode: &KapraBytecode) -> (HashMap<usize, usize>, HashMap<usize, Vec<(usize, bool)>>) {
    let mut line_map = HashMap::new();
    let mut branch_map = HashMap::new();
    let mut current_line = 1;

    // Track networking and async operations
    let mut networking_ops = HashSet::new();
    let mut async_ops = HashSet::new();

    // Simplified mapping: assume instructions correspond to AST nodes
    for (instr_idx, instr) in bytecode.instructions.iter().enumerate() {
        line_map.insert(instr_idx, current_line);
        
        // Track networking operations
        if matches!(instr.opcode, 
            KapraOpCode::HttpGet | 
            KapraOpCode::HttpPost | 
            KapraOpCode::HttpPut | 
            KapraOpCode::HttpDelete |
            KapraOpCode::TcpConnect |
            KapraOpCode::TcpListen |
            KapraOpCode::TcpAccept |
            KapraOpCode::TcpSend |
            KapraOpCode::TcpReceive
        ) {
            networking_ops.insert(instr_idx);
        }

        // Track async operations
        if matches!(instr.opcode,
            KapraOpCode::AsyncStart |
            KapraOpCode::AsyncAwait |
            KapraOpCode::AsyncResolve
        ) {
            async_ops.insert(instr_idx);
        }

        if instr.opcode == KapraOpCode::Jump {
            branch_map.insert(instr_idx, vec![(current_line, true), (current_line, false)]);
        }
        current_line += 1;
    }

    // Traverse AST to refine line mapping (placeholder for precise mapping)
    for node in ast {
        match node {
            AstNode::FnDecl { body, .. } => {
                for _ in body {
                    current_line += 1;
                }
            }
            AstNode::If { .. } => {
                // Add branches for if/else
                branch_map.entry(current_line).or_insert_with(Vec::new).push((current_line, true));
                branch_map.entry(current_line).or_insert_with(Vec::new).push((current_line, false));
                current_line += 1;
            }
            _ => current_line += 1,
        }
    }

    (line_map, branch_map)
}

// Public API to run coverage analysis
pub fn run_coverage(file: &PathBuf, output: Option<&PathBuf>, format: &str) -> Result<CoverageReport, KslError> {
    let analyzer = CoverageAnalyzer::new(file)?;
    let coverage_data = analyzer.collect_coverage()?;
    let report = analyzer.generate_report(&coverage_data);

    // Output report in specified format
    if let Some(output_path) = output {
        let report_str = match format {
            "json" => report.to_json(),
            _ => report.to_string(&analyzer.source),
        };
        fs::write(output_path, report_str)
            .map_err(|e| KslError::type_error(
                format!("Failed to write coverage report to {}: {}", output_path.display(), e),
                SourcePosition::new(1, 1),
            ))?;
    } else {
        match format {
            "json" => println!("{}", report.to_json()),
            _ => println!("{}", report.to_string(&analyzer.source)),
        }
    }

    Ok(report)
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_test.rs, ksl_bytecode.rs, kapra_vm.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ParseError};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_compiler {
    pub use super::compile;
}

mod ksl_test {
    pub use super::{run_tests, TestResult};
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
    fn test_coverage_basic() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "#[test]\nfn test_add() { let x: u32 = 42; assert(x + x == 84); }"
        ).unwrap();

        let report = run_coverage(&temp_file.path().to_path_buf(), None, "").unwrap();
        assert!(!report.covered_lines.is_empty());
        assert_eq!(report.total_lines.len(), report.covered_lines.len()); // All lines covered
        assert!(report.covered_branches.is_empty()); // No branches in test
    }

    #[test]
    fn test_coverage_with_branches() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "#[test]\nfn test_cond() { let x: u32 = 42; if x > 0 { x; } else { 0; } }"
        ).unwrap();

        let report = run_coverage(&temp_file.path().to_path_buf(), None, "").unwrap();
        assert!(!report.covered_lines.is_empty());
        assert!(report.covered_branches.iter().any(|b| b.1)); // True branch taken
        assert!(!report.covered_branches.iter().any(|b| !b.1)); // False branch not taken
    }

    #[test]
    fn test_coverage_output() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "#[test]\nfn test_simple() { let x: u32 = 42; }"
        ).unwrap();
        let output_file = temp_file.path().parent().unwrap().join("coverage.txt");

        let report = run_coverage(&temp_file.path().to_path_buf(), Some(&output_file), "").unwrap();
        let report_content = fs::read_to_string(&output_file).unwrap();
        assert!(report_content.contains("Line Coverage"));
        assert!(report_content.contains("[X]"));
    }

    #[test]
    fn test_coverage_invalid_file() {
        let invalid_file = PathBuf::from("nonexistent.ksl");
        let result = run_coverage(&invalid_file, None, "");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read file"));
    }

    #[test]
    fn test_coverage_networking_ops() {
        let mut temp_file = NamedTempFile::new().unwrap();
        write!(
            temp_file,
            r#"
            fn test_http() {{
                let response = http.get("https://example.com");
                print(response);
            }}

            fn test_tcp() {{
                let socket = tcp.connect("localhost:8080");
                socket.send("Hello");
                let response = socket.receive();
                print(response);
            }}
            "#
        ).unwrap();

        let report = run_coverage(&temp_file.path().to_path_buf(), None, "").unwrap();
        assert!(!report.networking_coverage.is_empty());
        assert!(report.networking_coverage.contains_key("HttpGet"));
        assert!(report.networking_coverage.contains_key("TcpConnect"));
        assert!(report.networking_coverage.contains_key("TcpSend"));
        assert!(report.networking_coverage.contains_key("TcpReceive"));
    }

    #[test]
    fn test_coverage_async_ops() {
        let mut temp_file = NamedTempFile::new().unwrap();
        write!(
            temp_file,
            r#"
            fn test_async() {{
                async fn fetch_data() {{
                    let response = http.get("https://example.com");
                    return response;
                }}

                let future = fetch_data();
                let result = await future;
                print(result);
            }}
            "#
        ).unwrap();

        let report = run_coverage(&temp_file.path().to_path_buf(), None, "").unwrap();
        assert!(!report.async_coverage.is_empty());
        assert!(report.async_coverage.contains_key("AsyncStart"));
        assert!(report.async_coverage.contains_key("AsyncAwait"));
        assert!(report.async_coverage.contains_key("AsyncResolve"));
    }

    #[test]
    fn test_coverage_json_format() {
        let mut temp_file = NamedTempFile::new().unwrap();
        write!(
            temp_file,
            r#"
            fn test_coverage() {{
                print("Hello, World!");
            }}
            "#
        ).unwrap();

        let report = run_coverage(&temp_file.path().to_path_buf(), None, "json").unwrap();
        let json_str = report.to_json();
        assert!(json_str.contains("\"covered_lines\""));
        assert!(json_str.contains("\"total_lines\""));
        assert!(json_str.contains("\"covered_branches\""));
        assert!(json_str.contains("\"total_branches\""));
        assert!(json_str.contains("\"networking_coverage\""));
        assert!(json_str.contains("\"async_coverage\""));
    }
}