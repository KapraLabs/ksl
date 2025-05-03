// ksl_coverage.rs
// Implements code coverage measurement for KSL tests, tracking executed bytecode
// instructions and generating rapid line/branch coverage reports.

use crate::ksl_parser::{parse, AstNode, ParseError};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_test::{run_tests, TestResult};
use crate::ksl_bytecode::{KapraBytecode, KapraInstruction};
use crate::kapra_vm::{KapraVM, RuntimeError};
use crate::ksl_errors::{KslError, SourcePosition};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

// Coverage data collected during test execution
#[derive(Debug)]
pub struct CoverageData {
    executed_instructions: HashSet<usize>, // Indices of executed bytecode instructions
    line_map: HashMap<usize, usize>, // Instruction index -> source line number
    branch_map: HashMap<usize, Vec<(usize, bool)>> // Instruction index -> (branch_line, taken)
}

// Coverage report summarizing line and branch coverage
#[derive(Debug)]
pub struct CoverageReport {
    covered_lines: HashSet<usize>,
    total_lines: HashSet<usize>,
    covered_branches: HashSet<(usize, bool)>,
    total_branches: HashSet<(usize, bool)>,
}

impl CoverageReport {
    // Generate a human-readable coverage report
    pub fn to_string(&self, source: &str) -> String {
        let line_coverage = self.covered_lines.len() as f32 / self.total_lines.len().max(1) as f32 * 100.0;
        let branch_coverage = self.covered_branches.len() as f32 / self.total_branches.len().max(1) as f32 * 100.0;

        let mut report = format!(
            "Coverage Report:\nLine Coverage: {:.2}% ({}/{} lines)\nBranch Coverage: {:.2}% ({}/{} branches)\n\n",
            line_coverage, self.covered_lines.len(), self.total_lines.len(),
            branch_coverage, self.covered_branches.len(), self.total_branches.len()
        );

        // Annotate source code with coverage
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

    // Export coverage data for debugging (e.g., ksl_debug.rs)
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
    pub fn new(file: &PathBuf) -> Result<Self, KslError> {
        let pos = SourcePosition::new(1, 1); // To be enhanced with precise positions
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

    // Run tests and collect coverage data
    pub fn collect_coverage(&self) -> Result<CoverageData, KslError> {
        let mut vm = KapraVM::new_with_coverage(self.bytecode.clone());
        let executed_instructions = run_tests_with_coverage(&mut vm, &self.source)?;

        Ok(CoverageData {
            executed_instructions,
            line_map: self.line_map.clone(),
            branch_map: self.branch_map.clone(),
        })
    }

    // Generate coverage report from collected data
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

    // Simplified mapping: assume instructions correspond to AST nodes
    for (instr_idx, instr) in bytecode.instructions.iter().enumerate() {
        line_map.insert(instr_idx, current_line);
        if instr.opcode == KapraOpCode::Jump {
            // Assume Jump instructions represent branches
            branch_map.insert(instr_idx, vec![(current_line, true), (current_line, false)]);
        }
        current_line += 1; // Increment line per instruction (to be refined with ksl_parser.rs)
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
pub fn run_coverage(file: &PathBuf, output: Option<&PathBuf>) -> Result<CoverageReport, KslError> {
    let analyzer = CoverageAnalyzer::new(file)?;
    let coverage_data = analyzer.collect_coverage()?;
    let report = analyzer.generate_report(&coverage_data);

    // Output report
    if let Some(output_path) = output {
        let report_str = report.to_string(&analyzer.source);
        fs::write(output_path, report_str)
            .map_err(|e| KslError::type_error(
                format!("Failed to write coverage report to {}: {}", output_path.display(), e),
                SourcePosition::new(1, 1),
            ))?;
    } else {
        println!("{}", report.to_string(&analyzer.source));
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

        let report = run_coverage(&temp_file.path().to_path_buf(), None).unwrap();
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

        let report = run_coverage(&temp_file.path().to_path_buf(), None).unwrap();
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

        let report = run_coverage(&temp_file.path().to_path_buf(), Some(&output_file)).unwrap();
        let report_content = fs::read_to_string(&output_file).unwrap();
        assert!(report_content.contains("Line Coverage"));
        assert!(report_content.contains("[X]"));
    }

    #[test]
    fn test_coverage_invalid_file() {
        let invalid_file = PathBuf::from("nonexistent.ksl");
        let result = run_coverage(&invalid_file, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read file"));
    }
}