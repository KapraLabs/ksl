/// ksl_repl.rs
/// Implements an interactive Read-Eval-Print Loop (REPL) for KSL programs.
/// 
/// Key Features:
/// - Interactive command-line interface for KSL development
/// - Support for all KSL language features including async/await
/// - Integration with compiler and debugger
/// - Comprehensive error handling and reporting
/// 
/// Usage:
/// ```ksl
/// // Start the REPL
/// let repl = Repl::new();
/// repl.run()?;
/// 
/// // Example commands:
/// ksl> let x: u32 = 42;
/// ksl> fn add(a: u32, b: u32): u32 { a + b; }
/// ksl> #[async] fn fetch() { let data = http.get("https://example.com"); }
/// ksl> :debug // Enter debug mode
/// ksl> :quit // Exit REPL
/// ```

use crate::ksl_parser::{parse, AstNode, ExprKind};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode};
use crate::kapra_vm::{KapraVM, run};
use crate::ksl_module::ModuleSystem;
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_async::{AsyncConfig, AsyncRuntime, AsyncProcessor};
use crate::ksl_debug::{Debugger, DebugCommand};
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::collections::HashMap;
use std::path::PathBuf;
use std::fs::{self, File};
use std::io::Write;
use tokio::runtime::Runtime;
use wasmtime::*;
use std::sync::Arc;
use crate::ksl_network::NetworkManager;
use crate::ksl_value::Value;
use crate::ksl_async_vm::AsyncVM;
use tempdir::TempDir;

/// REPL state
pub struct Repl {
    module_system: ModuleSystem,
    vm: KapraVM,
    bytecode: KapraBytecode,
    variables: HashMap<String, u8>, // Variable name to register
    functions: HashMap<String, u32>, // Function name to instruction index
    async_runtime: AsyncRuntime,
    debugger: Option<Debugger>,
    is_debug_mode: bool,
    loaded_modules: HashMap<String, ModuleInfo>, // Track loaded modules
    wasm_engine: Option<Engine>,
    wasm_store: Option<Store<()>>,
    wasm_instances: HashMap<String, Instance>,
}

/// Module information
#[derive(Clone, Debug)]
struct ModuleInfo {
    name: String,
    path: PathBuf,
    module_type: ModuleType,
    version: String,
    state: ModuleState,
    wasm_path: Option<PathBuf>, // Path to .wasm file if available
}

#[derive(Clone, Debug, PartialEq)]
enum ModuleType {
    Validator,
    Contract,
    Library,
    WasmContract, // New variant for WASM contracts
}

#[derive(Clone, Debug, PartialEq)]
enum ModuleState {
    Active,
    Paused,
    Error(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    // Add actual variants as needed, or use a placeholder for now
    Placeholder,
}

impl Type {
    pub fn satisfies_constraint(&self, _constraint: &Type) -> bool {
        // Placeholder: always return true
        true
    }
}

impl std::fmt::Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Type::Placeholder => write!(f, "Placeholder"),
        }
    }
}

pub struct TypeSystem;

impl TypeSystem {
    pub fn satisfies_constraint(_ty: &Type, _constraint: &Type) -> bool {
        // Placeholder: always return true
        true
    }

    pub fn implements_trait(_ty: &Type, _trait_name: &str) -> bool {
        // Placeholder: always return true
        true
    }
}

impl Repl {
    /// Creates a new REPL instance
    pub fn new() -> Self {
        let bytecode = KapraBytecode::new();
        let vm = KapraVM::new(bytecode.clone());
        let wasm_engine = Some(Engine::default());
        let wasm_store = wasm_engine.as_ref().map(|engine| Store::new(engine));
        
        Repl {
            module_system: ModuleSystem::new(),
            vm,
            bytecode,
            variables: HashMap::new(),
            functions: HashMap::new(),
            async_runtime: AsyncRuntime::new(),
            debugger: None,
            is_debug_mode: false,
            loaded_modules: HashMap::new(),
            wasm_engine,
            wasm_store,
            wasm_instances: HashMap::new(),
        }
    }

    /// Creates a new REPL instance with configuration
    pub fn new_with_config(config: ReplConfig) -> Self {
        let bytecode = KapraBytecode::new();
        let vm = KapraVM::new(bytecode.clone());
        let wasm_engine = Some(Engine::default());
        let wasm_store = wasm_engine.as_ref().map(|engine| Store::new(engine));
        
        Repl {
            module_system: ModuleSystem::new(),
            vm,
            bytecode,
            variables: HashMap::new(),
            functions: HashMap::new(),
            async_runtime: AsyncRuntime::new(),
            debugger: None,
            is_debug_mode: config.debug_mode,
            loaded_modules: HashMap::new(),
            wasm_engine,
            wasm_store,
            wasm_instances: HashMap::new(),
        }
    }

    /// Starts the REPL
    pub async fn run(&mut self) -> Result<(), String> {
        let mut rl = Editor::<()>::new();
        println!("KSL REPL (type :help for commands)");

        loop {
            let readline = rl.readline("ksl> ");
            match readline {
                Ok(line) => {
                    rl.add_history_entry(line.as_str());
                    if line.trim().starts_with(':') {
                        match self.handle_command(&line.trim()[1..]).await {
                            Ok(should_continue) => if !should_continue { break; },
                            Err(e) => println!("Error: {}", e),
                        }
                        continue;
                    }
                    match self.process_input(&line).await {
                        Ok(result) => {
                            if let Some(value) = result {
                                println!("=> {}", value);
                            }
                        }
                        Err(e) => println!("Error: {}", e),
                    }
                }
                Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => break,
                Err(err) => return Err(format!("Readline error: {}", err)),
            }
        }

        Ok(())
    }

    /// Handles REPL commands
    async fn handle_command(&mut self, command: &str) -> Result<bool, String> {
        let parts: Vec<&str> = command.split_whitespace().collect();
        match parts.get(0).map(|s| *s) {
            Some("exit") | Some("quit") => {
                Ok(false)
            }
            Some("help") => {
                println!("Available commands:");
                println!("  exit, quit - Exit the REPL");
                println!("  help - Show this help message");
                println!("  clear - Clear the variables and functions");
                println!("  load <file> - Load and execute KSL code from a file");
                println!("  save <file> - Save the current session to a file");
                println!("  debug - Enter debug mode");
                println!("  async - List active async tasks");
                println!("  vars - List defined variables");
                println!("  funcs - List defined functions");
                println!("  module list - List all loaded modules");
                println!("  module show <name> - Show module details");
                println!("  reload validator - Reload validator module");
                println!("  reload contract <name> - Reload contract module");
                println!("  patch contract <name> <path> - Patch contract from path");
                println!("  wasm load <contract_name> <path.wasm> - Load WASM contract");
                println!("  wasm call <contract_name> <func> [args...] - Call WASM function");
                Ok(true)
            }
            Some("reload") => {
                match parts.get(1).map(|s| *s) {
                    Some("validator") => {
                        self.reload_validator()?;
                        println!("Validator module reloaded successfully");
                        Ok(true)
                    }
                    Some("contract") => {
                        if let Some(contract_name) = parts.get(2) {
                            // Check if it's a WASM contract
                            let wasm_path = PathBuf::from(format!("./build/{}.wasm", contract_name));
                            if wasm_path.exists() {
                                self.reload_wasm_contract(contract_name, &wasm_path)?;
                                println!("WASM contract '{}' reloaded successfully", contract_name);
                            } else {
                                self.reload_contract(contract_name)?;
                                println!("Contract '{}' reloaded successfully", contract_name);
                            }
                            Ok(true)
                        } else {
                            println!("Usage: :reload contract <name>");
                            Ok(true)
                        }
                    }
                    _ => {
                        println!("Usage: :reload [validator|contract <name>]");
                        Ok(true)
                    }
                }
            }
            Some("patch") => {
                if parts.len() >= 5 && parts[1] == "contract" && parts[3] == "--path" {
                    let contract_name = parts[2];
                    let path = PathBuf::from(parts[4]);
                    
                    // Check if it's a WASM file
                    if path.extension().map_or(false, |ext| ext == "wasm") {
                        self.patch_wasm_contract(contract_name, path.clone())?;
                        println!("WASM contract '{}' patched successfully from {}", contract_name, path.display());
                    } else {
                        self.patch_contract(contract_name, path.clone())?;
                        println!("Contract '{}' patched successfully from {}", contract_name, path.display());
                    }
                    Ok(true)
                } else {
                    println!("Usage: :patch contract <name> --path <path>");
                    Ok(true)
                }
            }
            Some("list") => {
                if parts.get(1) == Some(&"modules") {
                    self.list_modules();
                    Ok(true)
                } else {
                    println!("Usage: :list modules");
                    Ok(true)
                }
            }
            Some("show") => {
                if parts.len() >= 3 && parts[1] == "module" {
                    let module_name = parts[2];
                    self.show_module(module_name);
                    Ok(true)
                } else {
                    println!("Usage: :show module <name>");
                    Ok(true)
                }
            }
            Some("reset") => {
                *self = Self::new();
                println!("REPL state reset");
                Ok(true)
            }
            Some("debug") => {
                self.is_debug_mode = true;
                self.debugger = Some(Debugger::new(&PathBuf::from("repl.ksl"))?);
                println!("Debug mode enabled");
                Ok(true)
            }
            Some("async") => {
                let tasks = self.async_runtime.tasks.lock().await;
                println!("Active async tasks:");
                for (id, handle) in &*tasks {
                    println!("  {}: {}", id, if handle.is_finished() { "completed" } else { "running" });
                }
                Ok(true)
            }
            Some("vars") => {
                println!("Variables:");
                for (name, reg) in &self.variables {
                    println!("  {}: {:?}", name, self.vm.registers[*reg as usize]);
                }
                Ok(true)
            }
            Some("funcs") => {
                println!("Functions:");
                for (name, index) in &self.functions {
                    println!("  {}: instruction {}", name, index);
                }
                Ok(true)
            }
            _ => Err(format!("Unknown command: {}", command)),
        }
    }

    /// Reload validator module
    fn reload_validator(&mut self) -> Result<(), String> {
        // Save validator state
        if let Some(module) = self.loaded_modules.get("validator") {
            self.vm.save_contract_state("validator")
                .map_err(|e| format!("Failed to save validator state: {}", e))?;
        }

        // Reload validator bytecode
        let validator_path = PathBuf::from("./build/validator.so");
        if !validator_path.exists() {
            return Err("Validator module not found".to_string());
        }

        // Load and compile new validator code
        let new_bytecode = self.load_module_bytecode(&validator_path)?;
        
        // Update VM with new bytecode
        self.vm.reload_bytecode(new_bytecode, None, None)
            .map_err(|e| format!("Failed to reload validator: {}", e))?;

        // Restore validator state
        if let Some(module) = self.loaded_modules.get("validator") {
            self.vm.restore_contract_state("validator")
                .map_err(|e| format!("Failed to restore validator state: {}", e))?;
        }

        // Update module info
        self.loaded_modules.insert("validator".to_string(), ModuleInfo {
            name: "validator".to_string(),
            path: validator_path,
            module_type: ModuleType::Validator,
            version: "latest".to_string(),
            state: ModuleState::Active,
            wasm_path: None,
        });

        Ok(())
    }

    /// Reload contract module
    fn reload_contract(&mut self, contract_name: &str) -> Result<(), String> {
        // Save contract state
        if let Some(module) = self.loaded_modules.get(contract_name) {
            self.vm.save_contract_state(contract_name)
                .map_err(|e| format!("Failed to save contract state: {}", e))?;
        }

        // Reload contract bytecode
        let contract_path = PathBuf::from(format!("./build/{}.so", contract_name));
        if !contract_path.exists() {
            return Err(format!("Contract {} not found", contract_name));
        }

        // Load and compile new contract code
        let new_bytecode = self.load_module_bytecode(&contract_path)?;
        
        // Update VM with new bytecode
        self.vm.reload_bytecode(new_bytecode, None, None)
            .map_err(|e| format!("Failed to reload contract: {}", e))?;

        // Restore contract state
        if let Some(module) = self.loaded_modules.get(contract_name) {
            self.vm.restore_contract_state(contract_name)
                .map_err(|e| format!("Failed to restore contract state: {}", e))?;
        }

        // Update module info
        self.loaded_modules.insert(contract_name.to_string(), ModuleInfo {
            name: contract_name.to_string(),
            path: contract_path,
            module_type: ModuleType::Contract,
            version: "latest".to_string(),
            state: ModuleState::Active,
            wasm_path: None,
        });

        Ok(())
    }

    /// Patch contract from path
    fn patch_contract(&mut self, contract_name: &str, path: PathBuf) -> Result<(), String> {
        if !path.exists() {
            return Err(format!("Path not found: {}", path.display()));
        }

        // Save contract state
        if let Some(module) = self.loaded_modules.get(contract_name) {
            self.vm.save_contract_state(contract_name)
                .map_err(|e| format!("Failed to save contract state: {}", e))?;
        }

        // Load and compile new contract code
        let new_bytecode = self.load_module_bytecode(&path)?;
        
        // Update VM with new bytecode
        self.vm.reload_bytecode(new_bytecode, None, None)
            .map_err(|e| format!("Failed to patch contract: {}", e))?;

        // Restore contract state
        if let Some(module) = self.loaded_modules.get(contract_name) {
            self.vm.restore_contract_state(contract_name)
                .map_err(|e| format!("Failed to restore contract state: {}", e))?;
        }

        // Update module info
        self.loaded_modules.insert(contract_name.to_string(), ModuleInfo {
            name: contract_name.to_string(),
            path: path.clone(),
            module_type: ModuleType::Contract,
            version: "patched".to_string(),
            state: ModuleState::Active,
            wasm_path: None,
        });

        Ok(())
    }

    /// List all loaded modules
    fn list_modules(&self) {
        println!("Loaded modules:");
        for (name, info) in &self.loaded_modules {
            let state_str = match &info.state {
                ModuleState::Active => "active",
                ModuleState::Paused => "paused",
                ModuleState::Error(e) => "error",
            };
            println!("  {} ({})", name, state_str);
            println!("    Type: {:?}", info.module_type);
            println!("    Version: {}", info.version);
            println!("    Path: {}", info.path.display());
        }
    }

    /// Show module details
    fn show_module(&self, module_name: &str) {
        if let Some(info) = self.loaded_modules.get(module_name) {
            println!("Module: {}", info.name);
            println!("Type: {:?}", info.module_type);
            println!("Version: {}", info.version);
            println!("Path: {}", info.path.display());
            println!("State: {:?}", info.state);
            
            match info.module_type {
                ModuleType::WasmContract => {
                    println!("\nWASM Contract Info:");
                    if let Some(wasm_path) = &info.wasm_path {
                        println!("  WASM file: {}", wasm_path.display());
                    }
                    if let Some(instance) = self.wasm_instances.get(module_name) {
                        println!("  Instance active: yes");
                        // Add any available exports or memory info
                        if let Ok(exports) = instance.exports(&self.wasm_store.as_ref().unwrap()) {
                            println!("  Exports:");
                            for export in exports {
                                println!("    {}", export.name());
                            }
                        }
                    }
                }
                ModuleType::Validator => {
                    println!("\nValidator Info:");
                    if let Ok(globals) = self.vm.get_globals() {
                        println!("  Active validators: {:?}", globals.get("active_validators"));
                        println!("  Pending blocks: {:?}", globals.get("pending_blocks"));
                    }
                }
                ModuleType::Contract => {
                    println!("\nContract Info:");
                    if let Ok(globals) = self.vm.get_globals() {
                        println!("  Contract name: {:?}", globals.get("contract_name"));
                        println!("  Contract version: {:?}", globals.get("contract_version"));
                    }
                }
                ModuleType::Library => {
                    println!("\nLibrary Info:");
                    if let Some(exports) = self.module_system.get_exports(&info.name) {
                        println!("  Exports:");
                        for export in exports {
                            println!("    {}", export);
                        }
                    }
                }
            }
        } else {
            println!("Module '{}' not found", module_name);
        }
    }

    /// Load module bytecode from path
    fn load_module_bytecode(&self, path: &PathBuf) -> Result<KapraBytecode, String> {
        let source = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read module: {}", e))?;
        
        let ast = parse(&source)
            .map_err(|e| format!("Failed to parse module: {}", e))?;
        
        check(ast.as_slice())
            .map_err(|errors| errors.into_iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("\n"))?;
        
        compile(ast.as_slice())
            .map_err(|errors| errors.into_iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("\n"))
    }

    /// Process user input and execute it
    async fn process_input(&mut self, input: &str) -> Result<Option<String>, String> {
        // Skip empty input
        if input.trim().is_empty() {
            return Ok(None);
        }

        // Create a temporary file for the input
        let temp_dir = TempDir::new().map_err(|e| e.to_string())?;
        let temp_file = temp_dir.path().join("input.ksl");
        fs::write(&temp_file, input).map_err(|e| e.to_string())?;

        // Parse input
        let ast = parse(input)
            .map_err(|e| format!("Parse error at position {}: {}", e.position, e.message))?;

        // Type-check
        check(ast.as_slice())
            .map_err(|errors| errors.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"))?;

        // Handle async functions
        if ast.iter().any(|node| matches!(node, AstNode::AsyncFnDecl { .. })) {
            let processor = AsyncProcessor::new(AsyncConfig {
                input_file: temp_file.clone(),
                output_file: None,
            });
            processor.process().await
                .map_err(|e| e.to_string())?;
            return Ok(None);
        }

        // Compile
        let new_bytecode = compile(ast.as_slice())
            .map_err(|errors| errors.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"))?;

        // Update state
        for node in &ast {
            match node {
                AstNode::VarDecl { name, .. } => {
                    if let Some(reg) = self.variables.get(name) {
                        self.variables.insert(name.clone(), *reg);
                    } else {
                        let reg = self.vm.next_register().ok_or("No free registers")?;
                        self.variables.insert(name.clone(), reg);
                    }
                }
                AstNode::FnDecl { name, .. } => {
                    let fn_index = self.bytecode.instructions.len() as u32;
                    self.functions.insert(name.clone(), fn_index);
                }
                AstNode::Import { path, item } => {
                    self.module_system.resolve_import(path, item)
                        .map_err(|e| e.to_string())?;
                }
                _ => {}
            }
        }

        // Merge bytecode
        self.bytecode.instructions.extend(new_bytecode.instructions);
        self.vm = KapraVM::new(self.bytecode.clone());

        // Execute
        let result = run(self.bytecode.clone())
            .map_err(|e| format!("Runtime error at instruction {}: {}", e.pc, e.message))?;

        // Get result for expressions
        let output = if let Some(AstNode::Expr { .. }) = ast.last() {
            let last_reg = self.vm.registers.iter().rposition(|r| !r.is_empty())
                .map(|i| i as u8);
            if let Some(reg) = last_reg {
                let value = &self.vm.registers[reg as usize];
                Some(format!("{:?}", value)) // Simplified: format as byte array
            } else {
                None
            }
        } else {
            None
        };

        Ok(output)
    }

    /// Reload a WASM contract
    fn reload_wasm_contract(&mut self, contract_name: &str, wasm_path: &PathBuf) -> Result<(), String> {
        // Save contract state if needed
        if let Some(module) = self.loaded_modules.get(contract_name) {
            self.vm.save_contract_state(contract_name)
                .map_err(|e| format!("Failed to save contract state: {}", e))?;
        }

        // Load WASM module
        let engine = self.wasm_engine.as_ref()
            .ok_or_else(|| "WASM engine not initialized".to_string())?;
        let module = Module::from_file(engine, wasm_path)
            .map_err(|e| format!("Failed to load WASM module: {}", e))?;
        
        // Create new instance
        let mut store = self.wasm_store.take()
            .ok_or_else(|| "WASM store not initialized".to_string())?;
        let instance = Instance::new(&mut store, &module, &[])
            .map_err(|e| format!("Failed to instantiate WASM module: {}", e))?;

        // Update instances
        self.wasm_instances.insert(contract_name.to_string(), instance);
        self.wasm_store = Some(store);

        // Restore contract state if needed
        if let Some(module) = self.loaded_modules.get(contract_name) {
            self.vm.restore_contract_state(contract_name)
                .map_err(|e| format!("Failed to restore contract state: {}", e))?;
        }

        // Update module info
        self.loaded_modules.insert(contract_name.to_string(), ModuleInfo {
            name: contract_name.to_string(),
            path: wasm_path.clone(),
            module_type: ModuleType::WasmContract,
            version: "latest".to_string(),
            state: ModuleState::Active,
            wasm_path: Some(wasm_path.clone()),
        });

        Ok(())
    }

    /// Patch a WASM contract
    fn patch_wasm_contract(&mut self, contract_name: &str, path: PathBuf) -> Result<(), String> {
        if !path.exists() {
            return Err(format!("WASM file not found: {}", path.display()));
        }

        // Save contract state if needed
        if let Some(module) = self.loaded_modules.get(contract_name) {
            self.vm.save_contract_state(contract_name)
                .map_err(|e| format!("Failed to save contract state: {}", e))?;
        }

        // Load new WASM module
        let engine = self.wasm_engine.as_ref()
            .ok_or_else(|| "WASM engine not initialized".to_string())?;
        let module = Module::from_file(engine, &path)
            .map_err(|e| format!("Failed to load WASM module: {}", e))?;
        
        // Create new instance
        let mut store = self.wasm_store.take()
            .ok_or_else(|| "WASM store not initialized".to_string())?;
        let instance = Instance::new(&mut store, &module, &[])
            .map_err(|e| format!("Failed to instantiate WASM module: {}", e))?;

        // Update instances
        self.wasm_instances.insert(contract_name.to_string(), instance);
        self.wasm_store = Some(store);

        // Restore contract state if needed
        if let Some(module) = self.loaded_modules.get(contract_name) {
            self.vm.restore_contract_state(contract_name)
                .map_err(|e| format!("Failed to restore contract state: {}", e))?;
        }

        // Update module info
        self.loaded_modules.insert(contract_name.to_string(), ModuleInfo {
            name: contract_name.to_string(),
            path: path.clone(),
            module_type: ModuleType::WasmContract,
            version: "patched".to_string(),
            state: ModuleState::Active,
            wasm_path: Some(path),
        });

        Ok(())
    }

    /// Evaluate code asynchronously with network support
    pub async fn eval_async(&mut self, code: &str, network: &Arc<NetworkManager>, runtime: &Arc<AsyncRuntime>) -> Result<Value, String> {
        // Parse code
        let ast = parse(code)
            .map_err(|e| format!("Parse error at position {}: {}", e.position, e.message))?;
        
        // Type check
        check(ast.as_slice())
            .map_err(|errors| errors.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"))?;
            
        // Check for async code
        let has_async = ast.iter().any(|node| matches!(node, AstNode::AsyncFnDecl { .. }));
        
        if has_async {
            // Handle async code
            let async_vm = AsyncVM::new(self.bytecode.clone(), runtime.clone());
            let result = async_vm.execute_async(code, network).await
                .map_err(|e| e.to_string())?;
            return Ok(result);
        } else {
            // Handle synchronous code
            let bytecode = compile(ast.as_slice())
                .map_err(|errors| errors.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"))?;
                
            self.vm = KapraVM::new(bytecode.clone());
            let result = run(self.vm.clone())
                .map_err(|e| format!("Runtime error: {}", e.message))?;
                
            // Get result value
            let value = Value::String(format!("{:?}", result));
            Ok(value)
        }
    }
}

/// Public API to start the REPL
pub async fn start_repl() -> Result<(), String> {
    let mut repl = Repl::new();
    repl.run().await
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_bytecode.rs, kapra_vm.rs, ksl_module.rs, ksl_errors.rs, ksl_async.rs, and ksl_debug.rs are in the same crate
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
    pub use super::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
}

mod kapra_vm {
    pub use super::{KapraVM, run};
}

mod ksl_module {
    pub use super::ModuleSystem;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

mod ksl_async {
    pub use super::{AsyncConfig, AsyncRuntime, AsyncProcessor};
}

mod ksl_debug {
    pub use super::{Debugger, DebugCommand};
}

mod ksl_network {
    pub use super::NetworkManager;
}

mod ksl_value {
    pub use super::Value;
}

mod ksl_async_vm {
    pub use super::AsyncVM;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repl_expression() {
        let mut repl = Repl::new();
        let result = repl.process_input("42 + 1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("[43, 0, 0, 0]".to_string())); // u32: 43 in LE bytes
    }

    #[test]
    fn test_repl_variable() {
        let mut repl = Repl::new();
        let result = repl.process_input("let x: u32 = 42;");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        let result = repl.process_input("x");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("[42, 0, 0, 0]".to_string()));
    }

    #[test]
    fn test_repl_function() {
        let mut repl = Repl::new();
        let result = repl.process_input("fn add(x: u32, y: u32): u32 { x + y; }");
        assert!(result.is_ok());
        let result = repl.process_input("add(1, 2)");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("[3, 0, 0, 0]".to_string()));
    }

    #[tokio::test]
    async fn test_repl_async() {
        let mut repl = Repl::new();
        let result = repl.process_input("#[async] fn fetch() { let data = http.get(\"https://example.com\"); }");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}