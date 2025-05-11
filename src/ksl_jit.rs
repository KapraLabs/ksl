// ksl_jit.rs
// JIT compiler with speculative optimizations and profile-guided recompilation

use crate::ksl_ast::{AstNode, Expr, Function, Type, Stmt};
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_llvm::LLVMCodegen;
use crate::ksl_analyzer::PerformanceMetrics;
use inkwell::context::Context;
use inkwell::execution_engine::{ExecutionEngine, JitFunction};
use inkwell::module::Module;
use inkwell::OptimizationLevel;
use inkwell::targets::{InitializationConfig, Target};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use log::{debug, info, warn};
use std::path::PathBuf;

/// Threshold for considering a function "hot"
const HOT_FUNCTION_THRESHOLD: u64 = 1000;
/// Time between profiling checks
const PROFILING_INTERVAL: Duration = Duration::from_secs(60);

type GenericJitFunction = unsafe extern "C" fn() -> i64;

/// Profile data for a function
#[derive(Debug, Clone)]
struct FunctionProfile {
    call_count: u64,
    total_time: Duration,
    avg_time: Duration,
    last_compiled: Instant,
    speculation_success: u64,
    speculation_failure: u64,
}

impl FunctionProfile {
    fn new() -> Self {
        FunctionProfile {
            call_count: 0,
            total_time: Duration::new(0, 0),
            avg_time: Duration::new(0, 0),
            last_compiled: Instant::now(),
            speculation_success: 0,
            speculation_failure: 0,
        }
    }

    fn update(&mut self, execution_time: Duration) {
        self.call_count += 1;
        self.total_time += execution_time;
        self.avg_time = self.total_time / self.call_count as u32;
    }

    fn is_hot(&self) -> bool {
        self.call_count > HOT_FUNCTION_THRESHOLD
    }

    fn should_recompile(&self) -> bool {
        self.is_hot() && self.last_compiled.elapsed() > PROFILING_INTERVAL
    }

    fn record_speculation(&mut self, success: bool) {
        if success {
            self.speculation_success += 1;
        } else {
            self.speculation_failure += 1;
        }
    }

    fn speculation_success_rate(&self) -> f64 {
        let total = self.speculation_success + self.speculation_failure;
        if total == 0 {
            0.0
        } else {
            self.speculation_success as f64 / total as f64
        }
    }
}

/// Speculative optimization for a function
#[derive(Debug)]
enum SpeculativeOpt {
    Inline {
        callee: String,
        success_rate: f64,
    },
    LoopUnroll {
        loop_id: usize,
        unroll_factor: usize,
        success_rate: f64,
    },
}

/// Simple debugger for JIT code
struct Debugger {
    /// Debug source file path
    source_file: PathBuf,
    /// Current breakpoints
    breakpoints: HashMap<String, Vec<usize>>,
    /// Current state of execution
    current_function: Option<String>,
}

impl Debugger {
    /// Create a new debugger
    fn new(source_file: &PathBuf) -> Result<Self, KslError> {
        Ok(Debugger {
            source_file: source_file.clone(),
            breakpoints: HashMap::new(),
            current_function: None,
        })
    }

    /// Check if a function has breakpoints
    fn has_breakpoint(&self, function_name: &str) -> bool {
        self.breakpoints.contains_key(function_name)
    }

    /// Handle a breakpoint when hit
    fn handle_breakpoint(&self) -> Result<(), KslError> {
        // Simplified implementation - would actually wait for user input in a real debugger
        debug!("Breakpoint hit, continuing execution");
        Ok(())
    }

    /// Notify the debugger that a function is being entered
    fn notify_function_entry(&mut self, function_name: &str) -> Result<(), KslError> {
        self.current_function = Some(function_name.to_string());
        debug!("Entering function: {}", function_name);
        Ok(())
    }

    /// Notify the debugger that a function is being exited
    fn notify_function_exit(&mut self, function_name: &str) -> Result<(), KslError> {
        self.current_function = None;
        debug!("Exiting function: {}", function_name);
        Ok(())
    }
}

/// JIT compiler with profiling and speculative optimizations
pub struct JITCompiler {
    context: Context,
    execution_engine: ExecutionEngine,
    function_cache: HashMap<String, JitFunction<GenericJitFunction>>,
    profile_data: Arc<Mutex<HashMap<String, FunctionProfile>>>,
    speculative_opts: HashMap<String, Vec<SpeculativeOpt>>,
    metrics: PerformanceMetrics,
    debug_mode: bool,
    debugger: Option<Arc<Mutex<Debugger>>>,
}

impl JITCompiler {
    /// Creates a new JIT compiler
    pub fn new(debug_mode: bool) -> Result<Self, KslError> {
        // Initialize LLVM targets
        Target::initialize_native(&InitializationConfig::default())
            .map_err(|e| KslError::type_error(
                format!("Failed to initialize LLVM targets: {}", e),
                SourcePosition::new(1, 1),
            ))?;

        let context = Context::create();
        let module = context.create_module("ksl_jit");
        let execution_engine = module.create_jit_execution_engine(OptimizationLevel::Aggressive)
            .map_err(|e| KslError::type_error(
                format!("Failed to create execution engine: {}", e),
                SourcePosition::new(1, 1),
            ))?;

        let debugger = if debug_mode {
            Some(Arc::new(Mutex::new(Debugger::new(
                &PathBuf::from("jit_debug.ksl")
            )?)))
        } else {
            None
        };

        Ok(JITCompiler {
            context,
            execution_engine,
            function_cache: HashMap::new(),
            profile_data: Arc::new(Mutex::new(HashMap::new())),
            speculative_opts: HashMap::new(),
            metrics: PerformanceMetrics::default(),
            debug_mode,
            debugger,
        })
    }

    /// Compiles and executes a function with profiling and debug support
    pub fn run_function(&mut self, function: &Function) -> Result<i64, KslError> {
        let start_time = Instant::now();

        // If in debug mode, notify debugger before execution
        if self.debug_mode {
            if let Some(debugger) = &self.debugger {
                let mut debugger = debugger.lock().unwrap();
                debugger.notify_function_entry(&function.name)?;
            }
        }

        let result = self.run_function_internal(function)?;
        let execution_time = start_time.elapsed();

        // Update profile data
        let mut profiles = self.profile_data.lock().unwrap();
        let profile = profiles.entry(function.name.clone()).or_insert_with(FunctionProfile::new);
        profile.update(execution_time);

        // Check if function needs recompilation
        if profile.should_recompile() {
            debug!("Recompiling hot function: {}", function.name);
            self.recompile_function(function)?;
            profile.last_compiled = Instant::now();
        }

        // If in debug mode, notify debugger after execution
        if self.debug_mode {
            if let Some(debugger) = &self.debugger {
                let mut debugger = debugger.lock().unwrap();
                debugger.notify_function_exit(&function.name)?;
            }
        }

        Ok(result)
    }

    /// Internal function execution with speculation and debug support
    fn run_function_internal(&mut self, function: &Function) -> Result<i64, KslError> {
        // If in debug mode, check for breakpoints
        if self.debug_mode {
            if let Some(debugger) = &self.debugger {
                let debugger = debugger.lock().unwrap();
                if debugger.has_breakpoint(&function.name) {
                    debug!("Hit breakpoint in function: {}", function.name);
                    // Wait for debugger commands
                    debugger.handle_breakpoint()?;
                }
            }
        }

        // Check if function is already compiled
        if let Some(jit_fn) = self.function_cache.get(&function.name) {
            // Execute with speculation
            let result = unsafe { jit_fn.call() };
            self.update_speculation_stats(&function.name, true);
            return Ok(result);
        }

        // Compile function with current speculative optimizations
        let module = self.context.create_module(&function.name);
        let mut codegen = LLVMCodegen::new(&self.context, &function.name);

        // Apply speculative optimizations
        if let Some(opts) = self.speculative_opts.get(&function.name) {
            for opt in opts {
                self.apply_speculation(&mut codegen, opt)?;
            }
        }

        // Generate code
        codegen.generate(&[AstNode::Function(function.clone())], Some(&self.metrics))?;

        // Add to execution engine
        let jit_fn = unsafe {
            self.execution_engine.get_function(&function.name)
                .map_err(|e| KslError::type_error(
                    format!("Failed to get JIT function: {}", e),
                    SourcePosition::new(1, 1),
                ))?
        };

        self.function_cache.insert(function.name.clone(), jit_fn);
        
        // Execute
        let result = unsafe { jit_fn.call() };
        Ok(result)
    }

    /// Recompiles a function with updated profiling data
    fn recompile_function(&mut self, function: &Function) -> Result<(), KslError> {
        debug!("Starting function recompilation: {}", function.name);

        // Create new module for recompilation
        let module = self.context.create_module(&function.name);
        let mut codegen = LLVMCodegen::new(&self.context, &function.name);

        // Update performance metrics
        self.update_metrics(&function.name);

        // Apply optimizations based on profiling
        self.apply_profile_optimizations(&mut codegen, &function.name)?;

        // Generate optimized code
        codegen.generate(&[AstNode::Function(function.clone())], Some(&self.metrics))?;

        // Update function cache
        let jit_fn = unsafe {
            self.execution_engine.get_function(&function.name)
                .map_err(|e| KslError::type_error(
                    format!("Failed to get JIT function: {}", e),
                    SourcePosition::new(1, 1),
                ))?
        };

        self.function_cache.insert(function.name.clone(), jit_fn);
        debug!("Completed function recompilation: {}", function.name);

        Ok(())
    }

    /// Updates performance metrics based on profiling data
    fn update_metrics(&mut self, function_name: &str) {
        let profiles = self.profile_data.lock().unwrap();
        if let Some(profile) = profiles.get(function_name) {
            if profile.is_hot() {
                self.metrics.hot_functions.insert(function_name.to_string());
            }
            
            // Update speculation success rates
            if let Some(opts) = self.speculative_opts.get(function_name) {
                for opt in opts {
                    match opt {
                        SpeculativeOpt::Inline { callee, success_rate } => {
                            self.metrics.inline_candidates.insert(callee.clone());
                        }
                        SpeculativeOpt::LoopUnroll { loop_id, unroll_factor, success_rate } => {
                            self.metrics.unroll_candidates.insert(*loop_id);
                        }
                    }
                }
            }
        }
    }

    /// Applies optimizations based on profiling data
    fn apply_profile_optimizations(
        &self,
        codegen: &mut LLVMCodegen,
        function_name: &str,
    ) -> Result<(), KslError> {
        let profiles = self.profile_data.lock().unwrap();
        if let Some(profile) = profiles.get(function_name) {
            // Add aggressive inlining for frequently called functions
            if profile.call_count > HOT_FUNCTION_THRESHOLD * 2 {
                codegen.add_aggressive_inlining()?;
            }

            // Add loop unrolling for hot loops
            if profile.avg_time > Duration::from_micros(100) {
                codegen.add_loop_unrolling()?;
            }

            // Add vectorization for array operations
            if self.metrics.has_array_operations(function_name) {
                codegen.add_vectorization()?;
            }
        }

        Ok(())
    }

    /// Applies a speculative optimization
    fn apply_speculation(
        &self,
        codegen: &mut LLVMCodegen,
        opt: &SpeculativeOpt,
    ) -> Result<(), KslError> {
        match opt {
            SpeculativeOpt::Inline { callee, success_rate } => {
                if *success_rate > 0.8 {
                    codegen.add_function_inlining(callee)?;
                }
            }
            SpeculativeOpt::LoopUnroll { loop_id, unroll_factor, success_rate } => {
                if *success_rate > 0.7 {
                    codegen.add_loop_unrolling_with_factor(*loop_id, *unroll_factor)?;
                }
            }
        }
        Ok(())
    }

    /// Updates speculation statistics
    fn update_speculation_stats(&mut self, function_name: &str, success: bool) {
        let mut profiles = self.profile_data.lock().unwrap();
        if let Some(profile) = profiles.get_mut(function_name) {
            profile.record_speculation(success);

            // Update speculation strategies based on success rate
            if let Some(opts) = self.speculative_opts.get_mut(function_name) {
                opts.retain(|opt| {
                    match opt {
                        SpeculativeOpt::Inline { success_rate, .. } => {
                            *success_rate = profile.speculation_success_rate();
                            *success_rate > 0.5 // Keep if success rate is above 50%
                        }
                        SpeculativeOpt::LoopUnroll { success_rate, .. } => {
                            *success_rate = profile.speculation_success_rate();
                            *success_rate > 0.4 // Keep if success rate is above 40%
                        }
                    }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ksl_ast::{Expr, Literal};

    #[test]
    fn test_jit_simple_function() {
        let mut jit = JITCompiler::new(false).unwrap();
        
        let function = Function {
            name: "test".to_string(),
            params: vec![],
            return_type: Some(Type::Int),
            is_public: true,
            body: vec![
                Stmt::ExprStmt(Expr::Literal(Literal::Int(42))),
            ],
            attributes: vec![],
        };

        let result = jit.run_function(&function).unwrap();
        assert_eq!(result, 42);
    }

    #[test]
    fn test_jit_hot_recompilation() {
        let mut jit = JITCompiler::new(false).unwrap();
        
        let function = Function {
            name: "hot_fn".to_string(),
            params: vec![],
            return_type: Some(Type::Int),
            is_public: true,
            body: vec![
                Stmt::ExprStmt(Expr::Literal(Literal::Int(1))),
            ],
            attributes: vec![],
        };

        // Run function many times to trigger recompilation
        for _ in 0..HOT_FUNCTION_THRESHOLD + 1 {
            jit.run_function(&function).unwrap();
        }

        let profiles = jit.profile_data.lock().unwrap();
        let profile = profiles.get("hot_fn").unwrap();
        assert!(profile.is_hot());
    }

    #[test]
    fn test_jit_speculation() {
        let mut jit = JITCompiler::new(false).unwrap();
        
        // Create a function with a loop
        let function = Function {
            name: "loop_fn".to_string(),
            params: vec![],
            return_type: Some(Type::Int),
            is_public: true,
            body: vec![
                // Simulated loop
                Stmt::ExprStmt(Expr::Loop {
                    id: 1,
                    count: 10,
                    body: vec![
                        Expr::Literal(Literal::Int(1)),
                    ],
                }),
            ],
            attributes: vec![],
        };

        // Add speculative optimization
        jit.speculative_opts.insert(
            "loop_fn".to_string(),
            vec![
                SpeculativeOpt::LoopUnroll {
                    loop_id: 1,
                    unroll_factor: 4,
                    success_rate: 0.9,
                },
            ],
        );

        let result = jit.run_function(&function).unwrap();
        assert_eq!(result, 10); // Sum of loop iterations

        let profiles = jit.profile_data.lock().unwrap();
        let profile = profiles.get("loop_fn").unwrap();
        assert!(profile.speculation_success > 0);
    }
}