// ksl_benchmark.rs
// Provides a dedicated benchmarking tool to measure KSL program performance,
// running benchmarks with configurable iterations and exporting results.

use crate::ksl_parser::{parse, ParseError};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::kapra_vm::{KapraVM, RuntimeError};
use crate::ksl_optimizer::optimize;
use crate::ksl_profile::{ProfileData, run_profile};
use crate::ksl_errors::{KslError, SourcePosition};
use serde_json::json;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

// Benchmark configuration
#[derive(Debug)]
pub struct BenchmarkConfig {
    input_file: PathBuf, // Source file to benchmark
    iterations: u32, // Number of iterations
    output_format: String, // Output format: "csv" or "json"
    output_path: Option<PathBuf>, // Optional path for benchmark results
    optimize: bool, // Whether to apply optimization
}

// Benchmark result
#[derive(Debug)]
struct BenchmarkResult {
    total_duration: Duration, // Total execution time
    avg_duration: Duration, // Average time per iteration
    profile_data: Option<ProfileData>, // Optional profiling data
}

// Benchmark tool
pub struct BenchmarkTool {
    config: BenchmarkConfig,
}

impl BenchmarkTool {
    pub fn new(config: BenchmarkConfig) -> Self {
        BenchmarkTool { config }
    }

    // Run benchmarks and return results
    pub fn run(&self) -> Result<BenchmarkResult, KslError> {
        let pos = SourcePosition::new(1, 1);
        // Compile source to bytecode
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

        // Optimize if specified
        if self.config.optimize {
            optimize(&mut bytecode, 3) // Use highest optimization level
                .map_err(|e| KslError::type_error(format!("Bytecode optimization failed: {}", e), pos))?;
        }

        // Run benchmark
        let mut vm = KapraVM::new(bytecode.clone());
        let start = Instant::now();
        for _ in 0..self.config.iterations {
            vm.run()
                .map_err(|e| KslError::type_error(format!("Execution error: {}", e), pos))?;
            vm.reset(); // Reset VM state for next iteration
        }
        let total_duration = start.elapsed();
        let avg_duration = total_duration / self.config.iterations;

        // Collect profiling data
        let profile_data = if self.config.iterations <= 1000 { // Limit profiling for large iterations
            Some(run_profile(&self.config.input_file, None)?)
        } else {
            None
        };

        let result = BenchmarkResult {
            total_duration,
            avg_duration,
            profile_data,
        };

        // Export results
        if let Some(output_path) = &self.config.output_path {
            match self.config.output_format.as_str() {
                "csv" => {
                    let mut content = String::new();
                    content.push_str("Total Duration (ms),Average Duration (ns),Iterations\n");
                    content.push_str(&format!(
                        "{},{},{}\n",
                        result.total_duration.as_millis(),
                        result.avg_duration.as_nanos(),
                        self.config.iterations
                    ));
                    File::create(output_path)
                        .map_err(|e| KslError::type_error(
                            format!("Failed to create output file {}: {}", output_path.display(), e),
                            pos,
                        ))?
                        .write_all(content.as_bytes())
                        .map_err(|e| KslError::type_error(
                            format!("Failed to write output file {}: {}", output_path.display(), e),
                            pos,
                        ))?;
                }
                "json" => {
                    let json_data = json!({
                        "total_duration_ms": result.total_duration.as_millis(),
                        "average_duration_ns": result.avg_duration.as_nanos(),
                        "iterations": self.config.iterations,
                        "profile_data": result.profile_data.as_ref().map(|data| json!({
                            "total_duration_ms": data.total_duration.as_millis(),
                            "call_graph": data.call_graph
                        }))
                    });
                    File::create(output_path)
                        .map_err(|e| KslError::type_error(
                            format!("Failed to create output file {}: {}", output_path.display(), e),
                            pos,
                        ))?
                        .write_all(serde_json::to_string_pretty(&json_data)?.as_bytes())
                        .map_err(|e| KslError::type_error(
                            format!("Failed to write output file {}: {}", output_path.display(), e),
                            pos,
                        ))?;
                }
                _ => return Err(KslError::type_error(
                    format!("Unsupported output format: {}", self.config.output_format),
                    pos,
                )),
            }
        } else {
            println!(
                "Benchmark Results:\nTotal Duration: {:.2?}\nAverage Duration: {}ns\nIterations: {}\n",
                result.total_duration,
                result.avg_duration.as_nanos(),
                self.config.iterations
            );
            if let Some(profile_data) = &result.profile_data {
                println!("Profiling Data:\nTotal Duration: {:.2?}\nCall Graph: {:?}", profile_data.total_duration, profile_data.call_graph);
            }
        }

        Ok(result)
    }
}

// Public API to run benchmarks
pub fn benchmark(input_file: &PathBuf, iterations: u32, output_format: &str, output_path: Option<PathBuf>, optimize: bool) -> Result<BenchmarkResult, KslError> {
    let pos = SourcePosition::new(1, 1);
    if iterations == 0 {
        return Err(KslError::type_error("Iterations must be greater than 0".to_string(), pos));
    }
    if output_format != "csv" && output_format != "json" {
        return Err(KslError::type_error(
            format!("Invalid output format: {}. Use 'csv' or 'json'", output_format),
            pos,
        ));
    }

    let config = BenchmarkConfig {
        input_file: input_file.clone(),
        iterations,
        output_format: output_format.to_string(),
        output_path,
        optimize,
    };
    let tool = BenchmarkTool::new(config);
    tool.run()
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, kapra_vm.rs, ksl_optimizer.rs, ksl_profile.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, ParseError};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_compiler {
    pub use super::compile;
}

mod kapra_vm {
    pub use super::{KapraVM, RuntimeError};
}

mod ksl_optimizer {
    pub use super::optimize;
}

mod ksl_profile {
    pub use super::{ProfileData, run_profile};
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
    fn test_benchmark_csv() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        let output_path = temp_dir.path().join("results.csv");
        let result = benchmark(&input_file, 1000, "csv", Some(output_path.clone()), false);
        assert!(result.is_ok());
        let result = result.unwrap();

        assert!(result.total_duration > Duration::from_secs(0));
        assert!(result.avg_duration > Duration::from_nanos(0));

        let content = fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("Total Duration (ms),Average Duration (ns),Iterations"));
        assert!(content.contains("1000"));
    }

    #[test]
    fn test_benchmark_json() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        let output_path = temp_dir.path().join("results.json");
        let result = benchmark(&input_file, 100, "json", Some(output_path.clone()), true);
        assert!(result.is_ok());
        let result = result.unwrap();

        assert!(result.total_duration > Duration::from_secs(0));
        assert!(result.avg_duration > Duration::from_nanos(0));
        assert!(result.profile_data.is_some());

        let content = fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("\"iterations\": 100"));
        assert!(content.contains("\"call_graph\""));
    }

    #[test]
    fn test_benchmark_invalid_iterations() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        let result = benchmark(&input_file, 0, "csv", None, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Iterations must be greater than 0"));
    }

    #[test]
    fn test_benchmark_invalid_format() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        let result = benchmark(&input_file, 1000, "invalid", None, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid output format"));
    }
}
