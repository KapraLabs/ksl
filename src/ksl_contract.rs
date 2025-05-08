// ksl_contract.rs
// Specialized compiler for blockchain smart contracts, generating optimized bytecode
// and WASM for Ethereum and Solana with gas limits and deterministic execution.

//! Smart contract functionality for KSL, enabling blockchain integration.
//! 
//! This module provides functionality for compiling, executing, and managing smart contracts
//! in the KSL language. It supports both synchronous and asynchronous contract execution,
//! cryptographic signing, and integration with various blockchain platforms.
//! 
//! # Contract Syntax
//! 
//! ```ksl
//! // Basic contract
//! contract MyContract {
//!     // State variables
//!     let owner: address;
//!     let balance: u64;
//! 
//!     // Constructor
//!     init(initial_owner: address) {
//!         owner = initial_owner;
//!         balance = 0;
//!     }
//! 
//!     // Transaction function
//!     #[transaction]
//!     fn transfer(to: address, amount: u64) {
//!         require(balance >= amount, "Insufficient balance");
//!         balance -= amount;
//!         // Emit event
//!         emit Transfer(owner, to, amount);
//!     }
//! 
//!     // Async function
//!     #[async]
//!     fn fetch_price(): u64 {
//!         let price = await oracle.get_price();
//!         return price;
//!     }
//! }
//! ```

use crate::ksl_parser::{parse, AstNode, ParseError};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_wasm::generate_wasm;
use crate::ksl_aot::aot_compile;
use crate::ksl_sandbox::run_sandbox;
use crate::ksl_verifier::verify;
use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode};
use crate::ksl_types::{Type, ContractType, Address, Hash};
use crate::ksl_kapra_crypto::{sign, verify_signature, KeyPair};
use crate::ksl_async::{AsyncRuntime, AsyncResult};
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use async_trait::async_trait;
use tokio::fs as tokio_fs;
use tokio::io::AsyncWriteExt;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use inkwell::context::Context;
use inkwell::module::Module;
use inkwell::builder::Builder;
use inkwell::execution_engine::{ExecutionEngine, JitFunction};
use inkwell::targets::{Target, TargetMachine, InitializationConfig};
use inkwell::OptimizationLevel;
use inkwell::values::{FunctionValue, BasicValueEnum};
use crate::ksl_contract_verifier::{ContractVerifier, VerificationResult, SecurityCheck};
use crate::ksl_types::{Type, Value};
use crate::ksl_ast::{AstNode, ContractAst};
use crate::ksl_errors::{KslError, SourcePosition};
use serde::{Serialize, Deserialize};
use chrono::{Utc, DateTime};
use bincode;

/// Enhanced contract compilation configuration
#[derive(Debug)]
pub struct ContractConfig {
    target: String, // e.g., "ethereum", "solana"
    gas_limit: u64, // Maximum instructions (simulating gas)
    output_dir: PathBuf, // Directory for artifacts
    signer: Option<KeyPair>, // Optional signer for contract deployment
    
    // New fields for LLVM support
    pub compilation_mode: CompilationMode,
    pub optimization_level: OptimizationLevel,
    pub enable_llvm: bool,
    pub security_profile: SecurityProfile,
}

/// Contract execution state
#[derive(Debug)]
pub struct ContractState {
    address: Address,
    balance: u64,
    storage: HashMap<String, Type>,
    events: Vec<ContractEvent>,
}

/// Contract event
#[derive(Debug)]
pub struct ContractEvent {
    name: String,
    data: Vec<Type>,
}

/// Contract compiler
pub struct ContractCompiler {
    /// LLVM context
    llvm_context: Option<Context>,
    /// Contract registry
    registry: Arc<RwLock<ContractRegistry>>,
    /// Contract verifier
    verifier: Arc<ContractVerifier>,
    /// Compilation metrics
    metrics: CompilationMetrics,
    /// Configuration
    config: ContractConfig,
    /// Async runtime
    runtime: AsyncRuntime,
}

/// Contract registry for managing compiled contracts
#[derive(Debug)]
pub struct ContractRegistry {
    /// Compiled contract modules
    modules: HashMap<ContractId, ContractModule>,
    /// Contract namespaces
    namespaces: HashMap<String, Vec<ContractId>>,
    /// Contract dependencies
    dependencies: HashMap<ContractId, Vec<ContractId>>,
}

/// Contract version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractVersion {
    /// Major version
    pub major: u32,
    /// Minor version
    pub minor: u32,
    /// Patch version
    pub patch: u32,
    /// Build metadata
    pub build: String,
    /// Version timestamp
    pub timestamp: DateTime<Utc>,
}

/// Contract state migration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateMigration {
    /// Source version
    pub from_version: ContractVersion,
    /// Target version
    pub to_version: ContractVersion,
    /// Migration function name
    pub migration_fn: String,
    /// Migration dependencies
    pub dependencies: Vec<String>,
}

/// Contract module containing compiled code
#[derive(Debug)]
pub struct ContractModule {
    /// Contract ID
    id: ContractId,
    /// Contract namespace
    namespace: String,
    /// LLVM module
    llvm_module: Option<Module>,
    /// WASM binary
    wasm_binary: Option<Vec<u8>>,
    /// Native binary
    native_binary: Option<Vec<u8>>,
    /// Contract ABI
    abi: ContractAbi,
    /// Compilation mode
    compilation_mode: CompilationMode,
    /// Security profile
    security_profile: SecurityProfile,
    /// Gas model
    gas_model: GasModel,
    /// Metadata
    metadata: ContractMetadata,
    /// Current version
    version: ContractVersion,
    /// Available migrations
    migrations: Vec<StateMigration>,
    /// State hooks
    state_hooks: HashMap<String, Vec<String>>,
}

/// Contract identifier
pub type ContractId = [u8; 32];

/// Contract ABI
#[derive(Debug, Clone)]
pub struct ContractAbi {
    /// Contract functions
    functions: Vec<ContractFunction>,
    /// Contract events
    events: Vec<ContractEvent>,
    /// Contract storage layout
    storage: Vec<StorageLayout>,
}

/// Contract function
#[derive(Debug, Clone)]
pub struct ContractFunction {
    /// Function name
    name: String,
    /// Function parameters
    params: Vec<(String, Type)>,
    /// Return type
    return_type: Type,
    /// Function visibility
    visibility: Visibility,
    /// Gas limit
    gas_limit: u64,
}

/// Storage layout
#[derive(Debug, Clone)]
pub struct StorageLayout {
    /// Field name
    name: String,
    /// Field type
    field_type: Type,
    /// Storage slot
    slot: u64,
    /// Field offset
    offset: u32,
}

/// Compilation mode for contracts
#[derive(Debug, Clone, PartialEq)]
pub enum CompilationMode {
    /// Traditional bytecode compilation
    Bytecode,
    /// LLVM-based ahead-of-time compilation
    Aot {
        target: String,
        opt_level: OptimizationLevel,
    },
    /// LLVM-based just-in-time compilation
    Jit {
        opt_level: OptimizationLevel,
        speculative: bool,
    },
}

/// Security profile
#[derive(Debug, Clone)]
pub struct SecurityProfile {
    /// Allowed system calls
    allowed_syscalls: Vec<String>,
    /// Memory limits
    memory_limits: MemoryLimits,
    /// Call depth limit
    max_call_depth: u32,
    /// Static analysis checks
    static_checks: Vec<SecurityCheck>,
}

/// Memory limits
#[derive(Debug, Clone)]
pub struct MemoryLimits {
    /// Maximum memory pages
    max_pages: u32,
    /// Maximum stack size
    max_stack: u32,
    /// Maximum allocation size
    max_allocation: u32,
}

/// Gas model
#[derive(Debug, Clone)]
pub struct GasModel {
    /// Base cost
    base_cost: u64,
    /// Operation costs
    op_costs: HashMap<String, u64>,
    /// Memory expansion cost
    memory_expansion_cost: u64,
    /// Storage cost
    storage_cost: u64,
}

/// Contract metadata
#[derive(Debug, Clone)]
pub struct ContractMetadata {
    /// Contract name
    name: String,
    /// Contract version
    version: String,
    /// Contract author
    author: String,
    /// Contract description
    description: String,
    /// Source code hash
    source_hash: [u8; 32],
    /// Compilation timestamp
    timestamp: u64,
}

/// Function visibility
#[derive(Debug, Clone, PartialEq)]
pub enum Visibility {
    /// Public function
    Public,
    /// Private function
    Private,
    /// External function
    External,
}

/// Compilation metrics
#[derive(Debug, Default)]
pub struct CompilationMetrics {
    /// Total contracts compiled
    total_compiled: u64,
    /// Total WASM size
    total_wasm_size: u64,
    /// Total native size
    total_native_size: u64,
    /// Average compilation time
    avg_compilation_time_ms: u64,
}

impl ContractCompiler {
    /// Creates a new contract compiler
    pub fn new(config: ContractConfig) -> Self {
        // Initialize LLVM if enabled
        if config.enable_llvm {
            Target::initialize_all(&InitializationConfig::default());
        }

        ContractCompiler {
            config,
            runtime: AsyncRuntime::new(),
            llvm_context: if config.enable_llvm { Some(Context::create()) } else { None },
            verifier: Arc::new(ContractVerifier::new()),
            metrics: CompilationMetrics::default(),
            registry: Arc::new(RwLock::new(ContractRegistry::new())),
        }
    }

    /// Compiles a contract
    pub fn compile_contract(&self, file: &PathBuf) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        
        // Read and parse source (keep existing code)
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

        // Verify contract (keep existing code)
        verify(&ast)?;

        // New: Perform additional security checks if enabled
        if let Some(profile) = &self.config.security_profile {
            self.verifier.verify_contract(&ast, &profile.static_checks)?;
        }

        match self.config.compilation_mode {
            CompilationMode::Bytecode => {
                // Existing bytecode path
                let bytecode = compile(&ast)?;
        let optimized_bytecode = optimize_bytecode(&bytecode, self.config.gas_limit)?;

        // Generate output based on target
                self.generate_target_output(file, &optimized_bytecode)?
            }
            CompilationMode::Aot { target, opt_level } => {
                // New LLVM AOT path
                let module = self.generate_llvm_ir(&ast)?;
                let binary = self.compile_aot(&module, &target, opt_level)?;
                
                // Write output
        let file_stem = file.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| KslError::type_error("Invalid file name".to_string(), pos))?;
                
                let output_path = if target.contains("wasm32") {
                    self.config.output_dir.join(format!("{}.wasm", file_stem))
                } else {
                    self.config.output_dir.join(format!("{}.o", file_stem))
                };

                fs::write(&output_path, binary)?;
            }
            CompilationMode::Jit { opt_level, speculative } => {
                // New LLVM JIT path
                let module = self.generate_llvm_ir(&ast)?;
                let _engine = self.compile_jit(&module, opt_level, speculative)?;
                
                // JIT compilation doesn't produce output files
            }
        }

        Ok(())
    }

    /// Verifies a contract
    fn verify_contract(&self, ast: &ContractAst, profile: &SecurityProfile) -> Result<(), KslError> {
        // Perform static analysis
        let verification = self.verifier.verify_contract(ast, &profile.static_checks)?;
        
        match verification {
            VerificationResult::Success => Ok(()),
            VerificationResult::Failure(errors) => {
                Err(KslError::contract_error(
                    format!("Contract verification failed: {:?}", errors),
                    SourcePosition::new(1, 1),
                ))
            }
        }
    }

    /// Generates LLVM IR from AST
    fn generate_llvm_ir(&self, ast: &ContractAst) -> Result<Module, KslError> {
        let context = self.llvm_context.as_ref()
            .ok_or_else(|| KslError::type_error("LLVM not enabled".to_string(), SourcePosition::new(1, 1)))?;
        
        let module = context.create_module("contract");
        let builder = context.create_builder();

        // Create main function
        let fn_type = context.void_type().fn_type(&[], false);
        let function = module.add_function("main", fn_type, None);
        let basic_block = context.append_basic_block(function, "entry");
        builder.position_at_end(basic_block);

        // Generate IR for each node
        for node in &ast.nodes {
            self.generate_node_ir(&builder, node)?;
        }

        // Verify module
        if module.verify().is_err() {
            return Err(KslError::type_error("Invalid LLVM module".to_string(), SourcePosition::new(1, 1)));
        }

        Ok(module)
    }

    /// Generates IR for an AST node
    fn generate_node_ir(&self, builder: &Builder, node: &AstNode) -> Result<BasicValueEnum, KslError> {
        match node {
            // Implement IR generation for each node type
            _ => Err(KslError::type_error("Unsupported AST node".to_string(), SourcePosition::new(1, 1))),
        }
    }

    /// Compiles contract using AOT
    fn compile_aot(
        &self,
        module: &Module,
        target: &str,
        opt_level: OptimizationLevel,
    ) -> Result<Vec<u8>, KslError> {
        let target = Target::from_triple(target)?;
        let target_machine = target.create_target_machine(
            target,
            "generic",
            "",
            opt_level,
            inkwell::targets::RelocMode::Default,
            inkwell::targets::CodeModel::Default,
        ).ok_or_else(|| KslError::type_error("Failed to create target machine".to_string(), SourcePosition::new(1, 1)))?;

        let obj_bytes = target_machine.write_to_memory_buffer(module)?;
        Ok(obj_bytes.as_slice().to_vec())
    }

    /// Compiles contract using JIT
    fn compile_jit(
        &self,
        module: &Module,
        opt_level: OptimizationLevel,
        speculative: bool,
    ) -> Result<ExecutionEngine, KslError> {
        let execution_engine = module.create_jit_execution_engine(opt_level)?;
        
        if speculative {
            execution_engine.enable_speculative_execution();
        }

        Ok(execution_engine)
    }

    /// Generates WASM binary
    fn generate_wasm(&self, module: &Module) -> Result<Vec<u8>, KslError> {
        // Implement WASM generation
        Ok(vec![])
    }

    /// Generates a new contract ID
    fn generate_contract_id(&self) -> ContractId {
        let mut id = [0u8; 32];
        rand::thread_rng().fill(&mut id);
        id
    }
}

impl ContractRegistry {
    /// Creates a new contract registry
    pub fn new() -> Self {
        ContractRegistry {
            modules: HashMap::new(),
            namespaces: HashMap::new(),
            dependencies: HashMap::new(),
        }
    }

    /// Registers a contract module with versioning
    pub fn register_contract_with_version(&mut self, module: ContractModule) -> Result<(), KslError> {
        let id = module.id;
        let namespace = module.namespace.clone();
        let version = module.version.clone();

        // Check for version conflicts
        if let Some(existing) = self.modules.get(&id) {
            if existing.version == version {
                return Err(KslError::runtime_error(
                    format!("Contract version {} already registered", version.major),
                    None,
                ));
            }
        }

        // Add to modules
        self.modules.insert(id, module);

        // Add to namespace
        self.namespaces
            .entry(namespace)
            .or_insert_with(Vec::new)
            .push(id);

        Ok(())
    }

    /// Gets a contract module by version
    pub fn get_contract_by_version(&self, id: &ContractId, version: &ContractVersion) -> Option<&ContractModule> {
        self.modules.get(id).filter(|m| m.version == *version)
    }

    /// Migrates a contract to a new version
    pub fn migrate_contract(&mut self, id: &ContractId, target_version: &ContractVersion) -> Result<(), KslError> {
        let module = self.modules.get(id).ok_or_else(|| 
            KslError::runtime_error("Contract not found".to_string(), None)
        )?;

        // Create new module with target version
        let mut new_module = module.clone();
        new_module.version = target_version.clone();

        // Migrate state if needed
        if let Some(state) = self.get_contract_state(id)? {
            let mut migrated_state = state.clone();
            new_module.migrate_state(&mut migrated_state, target_version)?;
            self.save_contract_state(id, &migrated_state)?;
        }

        // Register new version
        self.register_contract_with_version(new_module)?;

        Ok(())
    }
}

impl ContractModule {
    /// Creates a new contract module
    pub fn new(
        id: ContractId,
        namespace: String,
        version: ContractVersion,
    ) -> Self {
        ContractModule {
            id,
            namespace,
            llvm_module: None,
            wasm_binary: None,
            native_binary: None,
            abi: ContractAbi::default(),
            compilation_mode: CompilationMode::Debug,
            security_profile: SecurityProfile::default(),
            gas_model: GasModel::default(),
            metadata: ContractMetadata::default(),
            version,
            migrations: Vec::new(),
            state_hooks: HashMap::new(),
        }
    }

    /// Adds a state migration
    pub fn add_migration(&mut self, migration: StateMigration) {
        self.migrations.push(migration);
    }

    /// Gets available migrations for a target version
    pub fn get_migrations_for_version(&self, target_version: &ContractVersion) -> Vec<&StateMigration> {
        self.migrations.iter()
            .filter(|m| m.to_version == *target_version)
            .collect()
    }

    /// Adds a state hook
    pub fn add_state_hook(&mut self, hook_type: &str, hook_fn: &str) {
        self.state_hooks
            .entry(hook_type.to_string())
            .or_insert_with(Vec::new)
            .push(hook_fn.to_string());
    }

    /// Gets state hooks for a type
    pub fn get_state_hooks(&self, hook_type: &str) -> Vec<&str> {
        self.state_hooks
            .get(hook_type)
            .map(|hooks| hooks.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    /// Migrates contract state to a new version
    pub fn migrate_state(&self, state: &mut ContractState, target_version: &ContractVersion) -> Result<(), KslError> {
        // Get applicable migrations
        let migrations = self.get_migrations_for_version(target_version);
        
        // Apply migrations in order
        for migration in migrations {
            // Execute migration function
            if let Some(wasm) = &self.wasm_binary {
                let engine = wasmtime::Engine::default();
                let store = wasmtime::Store::new(&engine);
                let module = wasmtime::Module::new(&engine, wasm)?;
                let instance = wasmtime::Instance::new(&store, &module, &[])?;
                
                // Get migration function
                let migrate_fn = instance.get_typed_func::<(Vec<u8>,), Vec<u8>>(&migration.migration_fn)?;
                
                // Serialize current state
                let state_bytes = bincode::serialize(state)?;
                
                // Execute migration
                let new_state_bytes = migrate_fn.call(state_bytes)?;
                
                // Deserialize new state
                *state = bincode::deserialize(&new_state_bytes)?;
            }
        }
        
        // Update state version
        state.version = target_version.major as u64;
        
        Ok(())
    }
}

impl Default for ContractAbi {
    fn default() -> Self {
        ContractAbi {
            functions: Vec::new(),
            events: Vec::new(),
            storage: Vec::new(),
        }
    }
}

impl Default for SecurityProfile {
    fn default() -> Self {
        SecurityProfile {
            allowed_syscalls: Vec::new(),
            memory_limits: MemoryLimits::default(),
            max_call_depth: 1024,
            static_checks: Vec::new(),
        }
    }
}

impl Default for MemoryLimits {
    fn default() -> Self {
        MemoryLimits {
            max_pages: 16,
            max_stack: 1024 * 1024,
            max_allocation: 32 * 1024 * 1024,
        }
    }
}

impl Default for GasModel {
    fn default() -> Self {
        GasModel {
            base_cost: 100,
            op_costs: HashMap::new(),
            memory_expansion_cost: 1,
            storage_cost: 100,
        }
    }
}

impl Default for ContractMetadata {
    fn default() -> Self {
        ContractMetadata {
            name: String::new(),
            version: String::new(),
            author: String::new(),
            description: String::new(),
            source_hash: [0u8; 32],
            timestamp: 0,
        }
    }
}

#[async_trait]
pub trait AsyncContractExecutor {
    async fn execute_async(&self, contract: &ContractState, function: &str, args: Vec<Type>) -> AsyncResult<Type>;
}

#[async_trait]
impl AsyncContractExecutor for ContractCompiler {
    async fn execute_async(&self, contract: &ContractState, function: &str, args: Vec<Type>) -> AsyncResult<Type> {
        self.runtime.execute_async(contract, function, args).await
    }
}

// Optimize bytecode for blockchain execution
fn optimize_bytecode(bytecode: &KapraBytecode, gas_limit: u64) -> Result<KapraBytecode, KslError> {
    let pos = SourcePosition::new(1, 1);
    let mut optimized = KapraBytecode::new();
    let mut instruction_count = 0;

    for instr in &bytecode.instructions {
        // Enforce gas limit
        instruction_count += match instr.opcode {
            KapraOpCode::Sha3 | KapraOpCode::BlsVerify => 100, // High-cost operations
            KapraOpCode::Add | KapraOpCode::Sub | KapraOpCode::Mul => 5, // Arithmetic
            _ => 1, // Other instructions
        };
        if instruction_count > gas_limit {
            return Err(KslError::type_error(
                format!("Gas limit {} exceeded: {} instructions", gas_limit, instruction_count),
                pos,
            ));
        }

        // Optimize: Skip redundant Mov instructions (simplified)
        if let KapraOpCode::Mov = instr.opcode {
            if let Some(prev_instr) = optimized.instructions.last() {
                if prev_instr.opcode == KapraOpCode::Mov && prev_instr.operands == instr.operands {
                    continue;
                }
            }
        }

        // Enforce deterministic execution (no time.now)
        if instr.opcode == KapraOpCode::Mov {
            if let Some(operand) = instr.operands.get(1) {
                if let crate::ksl_bytecode::Operand::Immediate(data) = operand {
                    if data.len() == 8 && instr.type_info == Some(crate::ksl_types::Type::U64) {
                        return Err(KslError::type_error(
                            "Non-deterministic time.now call detected".to_string(),
                            pos,
                        ));
                    }
                }
            }
        }

        optimized.instructions.push(instr.clone());
    }

    Ok(optimized)
}

// Public API to compile a blockchain smart contract
pub fn compile_contract(file: &PathBuf, target: &str, gas_limit: u64, output_dir: PathBuf, signer: Option<KeyPair>) -> Result<(), KslError> {
    let config = ContractConfig {
        target: target.to_string(),
        gas_limit,
        output_dir,
        signer,
        compilation_mode: CompilationMode::Bytecode,
        optimization_level: OptimizationLevel::Default,
        enable_llvm: false,
        security_profile: SecurityProfile::default(),
    };
    let compiler = ContractCompiler::new(config);
    compiler.compile_contract(file)
}

// Public API to execute a contract function asynchronously
pub async fn execute_contract_async(contract: &ContractState, function: &str, args: Vec<Type>) -> AsyncResult<Type> {
    let compiler = ContractCompiler::new(ContractConfig {
        target: String::new(),
        gas_limit: 0,
        output_dir: PathBuf::new(),
        signer: None,
        compilation_mode: CompilationMode::Bytecode,
        optimization_level: OptimizationLevel::Default,
        enable_llvm: false,
        security_profile: SecurityProfile::default(),
    });
    compiler.execute_async(contract, function, args).await
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_wasm.rs, ksl_aot.rs, ksl_sandbox.rs, ksl_verifier.rs, ksl_bytecode.rs, ksl_types.rs, ksl_kapra_crypto.rs, ksl_async.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ParseError};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_compiler {
    pub use super::compile;
}

mod ksl_wasm {
    pub use super::generate_wasm;
}

mod ksl_aot {
    pub use super::aot_compile;
}

mod ksl_sandbox {
    pub use super::run_sandbox;
}

mod ksl_verifier {
    pub use super::verify;
}

mod ksl_bytecode {
    pub use super::{KapraBytecode, KapraInstruction, KapraOpCode};
}

mod ksl_types {
    pub use super::{Type, ContractType, Address, Hash};
}

mod ksl_kapra_crypto {
    pub use super::{sign, verify_signature, KeyPair};
}

mod ksl_async {
    pub use super::{AsyncRuntime, AsyncResult};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{TempDir, NamedTempFile};

    #[test]
    fn test_compile_contract_ethereum() {
        let temp_dir = TempDir::new().unwrap();
        let mut temp_file = NamedTempFile::new_in(&temp_dir).unwrap();
        writeln!(
            temp_file,
            "#[verify]\nfn main() { let hash: array<u8, 32> = sha3(\"data\"); }"
        ).unwrap();
        let output_dir = temp_dir.path().join("output");

        let result = compile_contract(&temp_file.path().to_path_buf(), "ethereum", 1000, output_dir.clone(), None);
        assert!(result.is_ok());
        let wasm_path = output_dir.join(format!("{}.wasm", temp_file.path().file_stem().unwrap().to_str().unwrap()));
        assert!(wasm_path.exists());
    }

    #[test]
    fn test_compile_contract_gas_limit_exceeded() {
        let temp_dir = TempDir::new().unwrap();
        let mut temp_file = NamedTempFile::new_in(&temp_dir).unwrap();
        writeln!(
            temp_file,
            "#[verify]\nfn main() { loop { } }"
        ).unwrap();
        let output_dir = temp_dir.path().join("output");

        let result = compile_contract(&temp_file.path().to_path_buf(), "ethereum", 100, output_dir, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Gas limit"));
    }

    #[test]
    fn test_compile_contract_non_deterministic() {
        let temp_dir = TempDir::new().unwrap();
        let mut temp_file = NamedTempFile::new_in(&temp_dir).unwrap();
        writeln!(
            temp_file,
            "#[verify]\nfn main() { let now: u64 = time.now(); }"
        ).unwrap();
        let output_dir = temp_dir.path().join("output");

        let result = compile_contract(&temp_file.path().to_path_buf(), "ethereum", 1000, output_dir, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Non-deterministic"));
    }

    #[tokio::test]
    async fn test_execute_contract_async() {
        let contract = ContractState {
            address: Address::new([0; 20]),
            balance: 1000,
            storage: HashMap::new(),
            events: Vec::new(),
        };
        let result = execute_contract_async(&contract, "get_balance", vec![]).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Type::U64(1000));
    }

    #[test]
    fn test_llvm_compilation() {
        let temp_dir = TempDir::new().unwrap();
        let mut temp_file = NamedTempFile::new_in(&temp_dir).unwrap();
        writeln!(
            temp_file,
            "#[verify]\nfn main() { let x: u64 = 42; }"
        ).unwrap();
        
        let config = ContractConfig {
            target: "wasm32-unknown-unknown".to_string(),
            gas_limit: 1000,
            output_dir: temp_dir.path().to_path_buf(),
            signer: None,
            compilation_mode: CompilationMode::Aot {
                target: "wasm32-unknown-unknown".to_string(),
                opt_level: OptimizationLevel::Default,
            },
            optimization_level: OptimizationLevel::Default,
            enable_llvm: true,
            security_profile: SecurityProfile::default(),
        };

        let compiler = ContractCompiler::new(config);
        let result = compiler.compile_contract(&temp_file.path().to_path_buf());
        assert!(result.is_ok());
    }

    #[test]
    fn test_jit_compilation() {
        let temp_dir = TempDir::new().unwrap();
        let mut temp_file = NamedTempFile::new_in(&temp_dir).unwrap();
        writeln!(
            temp_file,
            "#[verify]\nfn main() { let x: u64 = 42; }"
        ).unwrap();
        
        let config = ContractConfig {
            target: "native".to_string(),
            gas_limit: 1000,
            output_dir: temp_dir.path().to_path_buf(),
            signer: None,
            compilation_mode: CompilationMode::Jit {
                opt_level: OptimizationLevel::Default,
                speculative: true,
            },
            optimization_level: OptimizationLevel::Default,
            enable_llvm: true,
            security_profile: SecurityProfile::default(),
        };

        let compiler = ContractCompiler::new(config);
        let result = compiler.compile_contract(&temp_file.path().to_path_buf());
        assert!(result.is_ok());
    }
}