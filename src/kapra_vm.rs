// kapra_vm.rs
// Implements KapraVM 2.0 to execute KapraBytecode 2.0 for KSL programs.

use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
use crate::ksl_types::Type;
use crate::ksl_kapra_crypto::{KapraCrypto, FixedArray};
// Add these imports based on error messages
use crate::ksl_value::Value; 
use crate::ksl_errors::{KslError, SourcePosition}; 
use crate::ksl_smart_account::SmartAccount;
use crate::ksl_metrics::MetricsCollector;
use crate::ksl_hot_reload::HotReloadableVM;
use crate::ksl_coverage::CoverageVM;
use crate::ksl_metrics::MetricsVM;
use crate::ksl_simulator::{SimVM, Simulator};
use crate::ksl_stdlib_net::NetworkingState;
use crate::ksl_async::AsyncState;
// End of added imports
use crate::ksl_hot_reload::HotReloadState;
use crate::ksl_coverage::CoverageData;
use crate::ksl_metrics::MetricsData;
use crate::ksl_simulator::SimulationData;
use crate::ksl_data_blob::{KSLDataBlob, DataBlobMemoryManager, DataBlobOpCode};
use std::collections::{HashMap, HashSet, VecDeque};
use sha3::{Digest, Sha3_256, Sha3_512};
use crate::ksl_stdlib_net::NetStdLib;
use crate::ksl_async::AsyncRuntime;
use std::sync::Arc;
use std::fs::{self, File};
use std::path::PathBuf;
use bincode::{serialize, deserialize};
use serde::{Serialize, Deserialize};
use blst::min_pk::*;
use std::time::Instant;

// Re-export dependencies
mod ksl_bytecode {
    pub use super::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
}

mod ksl_types {
    pub use super::Type;
}

mod ksl_kapra_crypto {
    pub use super::{KapraCrypto, FixedArray};
}

mod ksl_hot_reload {
    pub use super::HotReloadState;
}

mod ksl_coverage {
    pub use super::CoverageData;
}

mod ksl_metrics {
    pub use super::MetricsData;
}

mod ksl_simulator {
    pub use super::SimulationData;
}

/// Runtime error type for KapraVM.
#[derive(Debug, PartialEq)]
pub struct RuntimeError {
    pub message: String,
    pub pc: usize, // Program counter at error
}

/// Delegated authentication context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedContext {
    pub delegator: FixedArray<32>, // Original signer
    pub delegatee: FixedArray<32>, // Temporary auth key
    pub expires_at: u64,           // Block height or tx-scope
}

/// Represents a single action in a transaction batch
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxAction {
    pub to: FixedArray<32>,
    pub data: Vec<u8>,        // Serialized bytecode or function call
    pub gas: u64,
}

/// Transaction execution context
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionContext {
    pub sender: FixedArray<32>,
    pub actions: Vec<TxAction>, // Batch of actions
    pub sponsor: Option<FixedArray<32>>,
    pub gas_limit: u64,
    pub tx_id: u64,
}

/// Represents the execution result of a single action
#[derive(Debug, Clone)]
pub struct ActionResult {
    pub to: FixedArray<32>,
    pub gas_used: u64,
    pub success: bool,
    pub error: Option<String>,
}

/// Contract metadata for version tracking and upgrades
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractMetadata {
    pub contract_id: FixedArray<32>,
    pub version: u32,
    pub version_hash: FixedArray<32>,
    pub changelog: String,
    pub upgrade_key: FixedArray<32>,
    pub deprecated: bool,
    pub upgrade_guardians: Vec<FixedArray<32>>,
}

/// Virtual machine state for executing KapraBytecode.
pub struct KapraVM {
    registers: Vec<u64>,
    stack: Vec<(usize, HashMap<u8, Vec<u8>>)>, // (return_pc, saved_registers)
    pc: usize, // Program counter
    memory: Vec<u8>, // Heap for immediates
    next_mem_addr: u64, // Next free memory address
    bytecode: KapraBytecode, // Program to execute
    halted: bool, // Halt flag
    pending_async: Vec<(u8, u32)>, // (dst_reg, func_index) for async calls
    state: Option<HotReloadState>, // Hot reload state
    coverage_data: Option<HashSet<usize>>, // Coverage tracking
    metrics_data: Option<MetricsData>, // Metrics tracking
    simulation_data: Option<SimulationData>, // Simulation data
    crypto: KapraCrypto, // Crypto module
    net_stdlib: Option<NetStdLib>, // Networking standard library
    runtime: Option<Arc<AsyncRuntime>>, // Async runtime
    debug_mode: bool,
    gas_used: u64, // Gas used so far
    gas_limit: u64, // Gas limit for execution
    auth_stack: Vec<DelegatedContext>, // Stack of delegated auth contexts
    current_sender: Option<FixedArray<32>>, // Current transaction sender
    gas_charged_to: FixedArray<32>, // Defaults to tx.sender unless overridden
    smart_accounts: HashMap<FixedArray<32>, SmartAccount>, // Smart account storage
    tx_context: TransactionContext,
    postconditions: Option<KapraBytecode>, // Postcondition block bytecode
    state_snapshot: Option<HashMap<FixedArray<32>, SmartAccount>>, // For rollback
    contract_registry: HashMap<FixedArray<32>, ContractMetadata>,
    contract_bytecode: HashMap<FixedArray<32>, KapraBytecode>,
    data_blob_manager: DataBlobMemoryManager,
}

/// Contract state that can be serialized
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractState {
    /// Contract name
    pub name: String,
    /// Contract memory
    pub memory: Vec<u8>,
    /// Contract globals
    pub globals: HashMap<String, Vec<u8>>,
    /// Contract stack
    pub stack: Vec<(usize, HashMap<u8, Vec<u8>>)>,
    /// Contract registers
    pub registers: HashMap<usize, Vec<u8>>,
    /// Contract heap
    pub heap: HashMap<usize, u8>,
    /// Contract version
    pub version: u64,
}

/// Generates unique transaction IDs
#[derive(Default)]
pub struct TransactionIdGenerator {
    next_id: u64,
}

impl TransactionIdGenerator {
    pub fn new() -> Self {
        Self { next_id: 1 }
    }

    pub fn next(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

impl KapraVM {
    /// Creates a new KapraVM instance.
    /// @param bytecode The bytecode program to execute.
    /// @param runtime Optional async runtime for networking operations.
    /// @param gas_limit Optional gas limit for execution.
    /// @returns A new `KapraVM` instance.
    /// @example
    /// ```ksl
    /// let bytecode = KapraBytecode::new();
    /// let vm = KapraVM::new(bytecode, None, None);
    /// ```
    pub fn new(bytecode: KapraBytecode, runtime: Option<Arc<AsyncRuntime>>, gas_limit: Option<u64>) -> Self {
        let net_stdlib = runtime.as_ref().map(|r| NetStdLib::new(r.clone()));
        KapraVM {
            registers: vec![0; 256],
            stack: Vec::new(),
            pc: 0,
            memory: vec![0; 65536],
            next_mem_addr: 0,
            bytecode,
            halted: false,
            pending_async: Vec::new(),
            state: None,
            coverage_data: None,
            metrics_data: None,
            simulation_data: None,
            crypto: KapraCrypto::new(false), // Default to non-embedded mode
            net_stdlib,
            runtime,
            debug_mode: false,
            gas_used: 0,
            gas_limit: gas_limit.unwrap_or(u64::MAX),
            auth_stack: Vec::new(),
            current_sender: None,
            gas_charged_to: FixedArray([0; 32]),
            smart_accounts: HashMap::new(),
            tx_context: TransactionContext {
                sender: FixedArray([0; 32]),
                actions: Vec::new(),
                sponsor: None,
                gas_limit: 0,
                tx_id: 0,
            },
            postconditions: None,
            state_snapshot: None,
            contract_registry: HashMap::new(),
            contract_bytecode: HashMap::new(),
            data_blob_manager: DataBlobMemoryManager::new(),
        }
    }

    /// Creates a new KapraVM instance with a transaction ID generator
    pub fn new_with_tx_generator(bytecode: KapraBytecode, runtime: Option<Arc<AsyncRuntime>>, gas_limit: Option<u64>) -> (Self, TransactionIdGenerator) {
        let vm = KapraVM::new(bytecode, runtime, gas_limit);
        let generator = TransactionIdGenerator::new();
        (vm, generator)
    }

    pub fn enable_debug(&mut self) {
        self.debug_mode = true;
    }

    /// Runs the bytecode program.
    /// @returns `Ok(())` if execution succeeds, or `Err` with a `RuntimeError`.
    /// @example
    /// ```ksl
    /// let mut vm = KapraVM::new(bytecode, None, None);
    /// vm.run().unwrap();
    /// ```
    pub fn run(&mut self) -> Result<(), RuntimeError> {
        while !self.halted && self.pc < self.bytecode.instructions.len() {
            let instr = &self.bytecode.instructions[self.pc];
            self.execute_instruction(instr, self.runtime.is_some())?;
            self.pc += 1;
        }
        // Clear auth stack after transaction
        self.auth_stack.clear();
        Ok(())
    }

    fn print_debug_info(&self) {
        println!("PC: {}", self.pc);
        println!("Current instruction: {:?}", self.bytecode.instructions[self.pc]);
        println!("Registers: {:?}", self.registers);
    }

    /// Executes a single instruction.
    /// @param instr The instruction to execute.
    /// @returns `Ok(())` if execution succeeds, or `Err` with a `RuntimeError`.
    fn execute_instruction(&mut self, instr: &KapraInstruction, async_support: bool) -> Result<(), RuntimeError> {
        // Track executed instruction for coverage if enabled
        if let Some(ref mut coverage) = self.coverage_data {
            coverage.insert(self.pc);
        }

        // Add gas cost for this instruction
        let gas_cost = match instr.opcode {
            KapraOpCode::Add | KapraOpCode::Sub | KapraOpCode::Mul => 1,
            KapraOpCode::BlsVerify | KapraOpCode::DilithiumVerify => 10,
            KapraOpCode::Sha3 | KapraOpCode::Sha3_512 => 5,
            KapraOpCode::AsyncCall | KapraOpCode::TcpConnect | KapraOpCode::UdpSend => 5,
            KapraOpCode::HttpPost | KapraOpCode::HttpGet => 10,
            _ => 1,
        };
        self.charge_gas(gas_cost)?;

        if self.debug_mode {
            self.print_debug_info();
        }

        match instr.opcode {
            KapraOpCode::Mov => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let src = self.get_operand_value(&instr.operands[1], instr.type_info.as_ref(), self.pc)?;
                self.registers[dst as usize] = src;
            }
            KapraOpCode::Add => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let a = self.get_u32(&instr.operands[1], self.pc)?;
                let b = self.get_u32(&instr.operands[2], self.pc)?;
                self.registers[dst as usize] = (a + b).to_le_bytes().to_vec();
            }
            KapraOpCode::Sub => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let a = self.get_u32(&instr.operands[1], self.pc)?;
                let b = self.get_u32(&instr.operands[2], self.pc)?;
                self.registers[dst as usize] = (a - b).to_le_bytes().to_vec();
            }
            KapraOpCode::Mul => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let a = self.get_u32(&instr.operands[1], self.pc)?;
                let b = self.get_u32(&instr.operands[2], self.pc)?;
                self.registers[dst as usize] = (a * b).to_le_bytes().to_vec();
            }
            KapraOpCode::Halt => {
                self.halted = true;
            }
            KapraOpCode::Fail => {
                return Err(RuntimeError {
                    message: "Program failed explicitly".to_string(),
                    pc: self.pc,
                });
            }
            KapraOpCode::Jump => {
                let offset = self.get_u32(&instr.operands[0], self.pc)? as usize;
                if offset >= self.bytecode.instructions.len() {
                    return Err(RuntimeError {
                        message: "Invalid jump offset".to_string(),
                        pc: self.pc,
                    });
                }
                self.pc = offset - 1; // -1 because pc increments after
            }
            KapraOpCode::Call => {
                let fn_index = self.get_u32(&instr.operands[0], self.pc)? as usize;
                if fn_index >= self.bytecode.instructions.len() {
                    return Err(RuntimeError {
                        message: "Invalid function index".to_string(),
                        pc: self.pc,
                    });
                }
                let saved_registers: HashMap<u8, Vec<u8>> = self
                    .registers
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| !r.is_empty())
                    .map(|(i, r)| (i as u8, r.clone()))
                    .collect();
                self.stack.push((self.pc + 1, saved_registers));
                self.pc = fn_index - 1; // -1 because pc increments after
            }
            KapraOpCode::Return => {
                if let Some((return_pc, saved_registers)) = self.stack.pop() {
                    self.registers = vec![0; 256];
                    for (reg, value) in saved_registers {
                        self.registers[reg as usize] = value;
                    }
                    self.pc = return_pc - 1; // -1 because pc increments after
                } else {
                    self.halted = true;
                }
            }
            KapraOpCode::Sha3 => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let src = self.get_operand_value(&instr.operands[1], instr.type_info.as_ref(), self.pc)?;
                let mut hasher = Sha3_256::new();
                hasher.update(&src);
                let result = hasher.finalize();
                self.registers[dst as usize] = result.to_vec();
            }
            KapraOpCode::Sha3_512 => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let src = self.get_operand_value(&instr.operands[1], instr.type_info.as_ref(), self.pc)?;
                let mut hasher = Sha3_512::new();
                hasher.update(&src);
                let result = hasher.finalize();
                self.registers[dst as usize] = result.to_vec();
            }
            KapraOpCode::Kaprekar => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let src = self.get_operand_value(&instr.operands[1], instr.type_info.as_ref(), self.pc)?;
                let input = u32::from_le_bytes(src.try_into().map_err(|_| RuntimeError {
                    message: "Invalid Kaprekar input".to_string(),
                    pc: self.pc,
                })?);
                let result = kaprekar_step(input);
                self.registers[dst as usize] = result.to_le_bytes().to_vec();
            }
            KapraOpCode::BlsVerify => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let msg = self.get_operand_value(&instr.operands[1], Some(&Type::Array(Box::new(Type::U8), 32)), self.pc)?;
                let pubkey = self.get_operand_value(&instr.operands[2], Some(&Type::Array(Box::new(Type::U8), 96)), self.pc)?;
                let sig = self.get_operand_value(&instr.operands[3], Some(&Type::Array(Box::new(Type::U8), 48)), self.pc)?;
                
                // Convert to FixedArray
                let msg_array: [u8; 32] = msg.try_into().map_err(|_| RuntimeError {
                    message: "Invalid message size for BLS".to_string(),
                    pc: self.pc,
                })?;
                let pubkey_array: [u8; 96] = pubkey.try_into().map_err(|_| RuntimeError {
                    message: "Invalid pubkey size for BLS".to_string(),
                    pc: self.pc,
                })?;
                let sig_array: [u8; 48] = sig.try_into().map_err(|_| RuntimeError {
                    message: "Invalid signature size for BLS".to_string(),
                    pc: self.pc,
                })?;
                
                let result = self.crypto.bls_verify(
                    &FixedArray::new(msg_array),
                    &FixedArray::new(pubkey_array),
                    &FixedArray::new(sig_array),
                );
                self.registers[dst as usize] = (result as u32).to_le_bytes().to_vec();
            }
            KapraOpCode::DilithiumVerify => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let msg = self.get_operand_value(&instr.operands[1], Some(&Type::Array(Box::new(Type::U8), 32)), self.pc)?;
                let pubkey = self.get_operand_value(&instr.operands[2], Some(&Type::Array(Box::new(Type::U8), 1312)), self.pc)?;
                let sig = self.get_operand_value(&instr.operands[3], Some(&Type::Array(Box::new(Type::U8), 2420)), self.pc)?;
                // Convert to FixedArray
                let msg_array: [u8; 32] = msg.try_into().map_err(|_| RuntimeError {
                    message: "Invalid message size for Dilithium".to_string(),
                    pc: self.pc,
                })?;
                let pubkey_array: [u8; 1312] = pubkey.try_into().map_err(|_| RuntimeError {
                    message: "Invalid pubkey size for Dilithium".to_string(),
                    pc: self.pc,
                })?;
                let sig_array: [u8; 2420] = sig.try_into().map_err(|_| RuntimeError {
                    message: "Invalid signature size for Dilithium".to_string(),
                    pc: self.pc,
                })?;
                let result = self.crypto.dil_verify(
                    &FixedArray::new(msg_array),
                    &FixedArray::new(pubkey_array),
                    &FixedArray::new(sig_array),
                );
                self.registers[dst as usize] = (result as u32).to_le_bytes().to_vec();
            }
            KapraOpCode::MerkleVerify => {
                // Placeholder: ksl_kapra_crypto.rs lacks merkle_verify
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let _root = self.get_operand_value(&instr.operands[1], Some(&Type::Array(Box::new(Type::U8), 32)), self.pc)?;
                let _proof = self.get_operand_value(&instr.operands[2], Some(&Type::Array(Box::new(Type::U8), 0)), self.pc)?;
                self.registers[dst as usize] = 1u32.to_le_bytes().to_vec(); // Always true
            }
            KapraOpCode::AsyncCall => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let func_index = self.get_u32(&instr.operands[1], self.pc)? as u32;
                self.pending_async.push((dst, func_index));
                // Simulate async result (e.g., for fetch)
                let result = vec![b'r', b'e', b's', b'u', b'l', b't']; // Dummy "result" string
                self.registers[dst as usize] = result;
            }
            KapraOpCode::TcpConnect => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let host = self.get_string(&instr.operands[1], self.pc)?;
                let port = self.get_u32(&instr.operands[2], self.pc)?;

                if let Some(net) = &self.net_stdlib {
                    self.pending_async.push((dst, self.pc as u32));
                    let result = net.execute("tcp.connect", vec![
                        Value::String(host),
                        Value::U32(port),
                    ])?;
                    self.registers[dst as usize] = self.encode_result(result)?;
                } else {
                    return Err(RuntimeError {
                        message: "Networking not available".to_string(),
                        pc: self.pc,
                    });
                }
            }
            KapraOpCode::UdpSend => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let host = self.get_string(&instr.operands[1], self.pc)?;
                let port = self.get_u32(&instr.operands[2], self.pc)?;
                let data = self.get_array(&instr.operands[3], self.pc)?;

                if let Some(net) = &self.net_stdlib {
                    self.pending_async.push((dst, self.pc as u32));
                    let result = net.execute("udp.send", vec![
                        Value::String(host),
                        Value::U32(port),
                        Value::Array(data, 1024),
                    ])?;
                    self.registers[dst as usize] = self.encode_result(result)?;
                } else {
                    return Err(RuntimeError {
                        message: "Networking not available".to_string(),
                        pc: self.pc,
                    });
                }
            }
            KapraOpCode::HttpPost => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let url = self.get_string(&instr.operands[1], self.pc)?;
                let data = self.get_string(&instr.operands[2], self.pc)?;

                if let Some(net) = &self.net_stdlib {
                    self.pending_async.push((dst, self.pc as u32));
                    let result = net.execute("http.post", vec![
                        Value::String(url),
                        Value::String(data),
                    ])?;
                    self.registers[dst as usize] = self.encode_result(result)?;
                } else {
                    return Err(RuntimeError {
                        message: "Networking not available".to_string(),
                        pc: self.pc,
                    });
                }
            }
            KapraOpCode::HttpGet => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let url = self.get_string(&instr.operands[1], self.pc)?;

                if let Some(net) = &self.net_stdlib {
                    self.pending_async.push((dst, self.pc as u32));
                    let result = net.execute("http.get", vec![
                        Value::String(url),
                    ])?;
                    self.registers[dst as usize] = self.encode_result(result)?;
                } else {
                    return Err(RuntimeError {
                        message: "Networking not available".to_string(),
                        pc: self.pc,
                    });
                }
            }
            KapraOpCode::Print => {
                let src = self.get_register(&instr.operands[0], self.pc)?;
                let value = self.registers[src as usize].clone();
                println!("{}", String::from_utf8_lossy(&value));
            }
            KapraOpCode::Assert => {
                let condition_reg = self.get_register(&instr.operands[0], self.pc)?;
                let condition = self.registers[condition_reg as usize].clone();
                let is_true = !condition.is_empty() && condition[0] != 0;
                
                if !is_true {
                    return Err(RuntimeError {
                        message: "Assertion failed".to_string(),
                        pc: self.pc,
                    });
                }
            }
            KapraOpCode::Auth => {
                let delegatee_reg = self.get_register(&instr.operands[0], self.pc)?;
                let delegatee_bytes = self.registers[delegatee_reg as usize].clone();
                
                if delegatee_bytes.len() != 32 {
                    return Err(RuntimeError {
                        message: "Invalid delegatee address format".to_string(),
                        pc: self.pc,
                    });
                }
                
                // Convert to fixed array
                let mut delegatee = [0u8; 32];
                delegatee.copy_from_slice(&delegatee_bytes);
                
                // Push to auth stack if sender is set
                if let Some(sender) = &self.current_sender {
                    self.auth_stack.push(DelegatedContext {
                        delegator: *sender,
                        delegatee: FixedArray(delegatee),
                        expires_at: 0, // Scope-limited to current transaction
                    });
                } else {
                    return Err(RuntimeError {
                        message: "No transaction sender for auth delegation".to_string(),
                        pc: self.pc,
                    });
                }
            }
            KapraOpCode::AuthCall => {
                // Similar to Call but with delegated auth
                if self.auth_stack.is_empty() {
                    return Err(RuntimeError {
                        message: "No delegated auth context available".to_string(),
                        pc: self.pc,
                    });
                }
                
                let fn_index = self.get_u32(&instr.operands[0], self.pc)? as usize;
                if fn_index >= self.bytecode.instructions.len() {
                    return Err(RuntimeError {
                        message: "Invalid function index".to_string(),
                        pc: self.pc,
                    });
                }
                
                let saved_registers: HashMap<u8, Vec<u8>> = self
                    .registers
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| !r.is_empty())
                    .map(|(i, r)| (i as u8, r.clone()))
                    .collect();
                    
                self.stack.push((self.pc + 1, saved_registers));
                self.pc = fn_index - 1; // -1 because pc increments after
            }
            KapraOpCode::Verify => {
                // Mark beginning of postcondition block
                // No actual execution here - used by static analysis
            }
            KapraOpCode::DeviceSensor => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let id = self.get_operand_value(&instr.operands[1], instr.type_info.as_ref(), self.pc)?;
                // Simulate device sensor reading
                let reading = match String::from_utf8_lossy(&id).as_ref() {
                    "temperature" => vec![0x1A, 0x00, 0x00, 0x00], // 26°C - binary representation of 26u32
                    "humidity" => vec![0x32, 0x00, 0x00, 0x00],    // 50% - binary representation of 50u32
                    "pressure" => vec![0x05, 0x04, 0x00, 0x00],    // 1029 hPa - binary representation of 1029u32
                    _ => vec![0x00, 0x00, 0x00, 0x00],            // Unknown sensor
                };
                self.registers[dst as usize] = reading;
            }
            KapraOpCode::Sin => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let src = self.get_operand_value(&instr.operands[1], instr.type_info.as_ref(), self.pc)?;
                // Convert bytes to f64
                let f = f64::from_le_bytes(src.try_into().map_err(|_| RuntimeError {
                    message: "Invalid floating point value".to_string(),
                    pc: self.pc,
                })?);
                let result = f.sin();
                self.registers[dst as usize] = result.to_le_bytes().to_vec();
            }
            KapraOpCode::Cos => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let src = self.get_operand_value(&instr.operands[1], instr.type_info.as_ref(), self.pc)?;
                // Convert bytes to f64
                let f = f64::from_le_bytes(src.try_into().map_err(|_| RuntimeError {
                    message: "Invalid floating point value".to_string(),
                    pc: self.pc,
                })?);
                let result = f.cos();
                self.registers[dst as usize] = result.to_le_bytes().to_vec();
            }
            KapraOpCode::Sqrt => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let src = self.get_operand_value(&instr.operands[1], instr.type_info.as_ref(), self.pc)?;
                // Convert bytes to f64
                let f = f64::from_le_bytes(src.try_into().map_err(|_| RuntimeError {
                    message: "Invalid floating point value".to_string(),
                    pc: self.pc,
                })?);
                let result = f.sqrt();
                self.registers[dst as usize] = result.to_le_bytes().to_vec();
            }
            KapraOpCode::MatrixMul => {
                // Simplified matrix multiplication
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let _a = self.get_operand_value(&instr.operands[1], instr.type_info.as_ref(), self.pc)?;
                let _b = self.get_operand_value(&instr.operands[2], instr.type_info.as_ref(), self.pc)?;
                
                // Placeholder: actual matrix multiplication would be complex
                let result = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
                self.registers[dst as usize] = result;
            }
            KapraOpCode::TensorReduce => {
                // Simplified tensor reduction
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let _src = self.get_operand_value(&instr.operands[1], instr.type_info.as_ref(), self.pc)?;
                
                // Placeholder: actual tensor reduction would be complex
                let result = vec![42, 0, 0, 0]; // Result as u32
                self.registers[dst as usize] = result;
            }
            KapraOpCode::PluginCall { plugin, op } => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let arg = self.get_operand_value(&instr.operands[1], instr.type_info.as_ref(), self.pc)?;
                
                // Simulate plugin call
                let result = format!("Plugin {} called op {} with arg size {}", plugin, op, arg.len()).into_bytes();
                self.registers[dst as usize] = result;
            }
            KapraOpCode::CallSyscall { name } => {
                let reg = self.get_register(&instr.operands[0], self.pc)?;
                
                // Simulate syscall
                let result = format!("Syscall {} called", name).into_bytes();
                self.registers[reg as usize] = result;
            }
            // Handle custom data blob operations
            op => {
                // Check if this is a data blob operation (based on opcode)
                let opcode_val = op.encode();
                if opcode_val >= 0x70 && opcode_val <= 0x72 {
                    self.execute_data_blob_op(instr)
                } else {
                    Err(RuntimeError {
                        message: format!("Unknown opcode: {:?}", op),
                        pc: self.pc,
                    })
                }
            }
        }
        Ok(())
    }

    /// Executes a data blob operation
    fn execute_data_blob_op(&mut self, instr: &KapraInstruction) -> Result<(), RuntimeError> {
        let opcode = DataBlobOpCode::from(instr.opcode);
        match opcode {
            DataBlobOpCode::Load => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let src = self.get_operand_value(&instr.operands[1], instr.type_info.as_ref(), self.pc)?;
                
                // Load blob from memory
                let blob_ptr = u64::from_le_bytes(src.try_into().map_err(|_| RuntimeError {
                    message: "Invalid blob pointer".to_string(),
                    pc: self.pc,
                })?);
                
                // Find the blob in manager
                let blob = self.data_blob_manager.blobs.iter()
                    .find(|b| Arc::as_ptr(b) as u64 == blob_ptr)
                    .ok_or_else(|| RuntimeError {
                        message: "Invalid data blob reference".to_string(),
                        pc: self.pc,
                    })?;
                
                // Store blob data in register
                self.registers[dst as usize] = blob.data.clone();
            }
            DataBlobOpCode::Store => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let data = self.get_operand_value(&instr.operands[1], instr.type_info.as_ref(), self.pc)?;
                let element_type = instr.type_info.as_ref().ok_or_else(|| RuntimeError {
                    message: "Missing element type for data blob".to_string(),
                    pc: self.pc,
                })?;
                
                // Create and allocate new blob
                let blob = KSLDataBlob::new(data, element_type.clone(), 8);
                let arc_blob = self.data_blob_manager.allocate(blob).map_err(|e| RuntimeError {
                    message: e.to_string(),
                    pc: self.pc,
                })?;
                
                // Store blob pointer in register
                let ptr = Arc::as_ptr(&arc_blob) as u64;
                self.registers[dst as usize] = ptr.to_le_bytes().to_vec();
            }
            DataBlobOpCode::Verify => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let src = self.get_operand_value(&instr.operands[1], instr.type_info.as_ref(), self.pc)?;
                
                // Get blob pointer
                let blob_ptr = u64::from_le_bytes(src.try_into().map_err(|_| RuntimeError {
                    message: "Invalid blob pointer".to_string(),
                    pc: self.pc,
                })?);
                
                // Find and verify blob
                let blob = self.data_blob_manager.blobs.iter()
                    .find(|b| Arc::as_ptr(b) as u64 == blob_ptr)
                    .ok_or_else(|| RuntimeError {
                        message: "Invalid data blob reference".to_string(),
                        pc: self.pc,
                    })?;
                
                let is_valid = blob.verify();
                self.registers[dst as usize] = (is_valid as u32).to_le_bytes().to_vec();
            }
        }
        Ok(())
    }

    /// Gets the register index from an operand.
    /// @param operand The operand to process.
    /// @param pc The current program counter for error reporting.
    /// @returns The register index, or `Err` if invalid.
    fn get_register(&self, operand: &Operand, pc: usize) -> Result<u8, RuntimeError> {
        match operand {
            Operand::Register(reg) if *reg < 16 => Ok(*reg),
            _ => Err(RuntimeError {
                message: "Invalid register".to_string(),
                pc,
            }),
        }
    }

    /// Gets a u32 value from an operand.
    /// @param operand The operand to process.
    /// @param pc The current program counter for error reporting.
    /// @returns The u32 value, or `Err` if invalid.
    fn get_u32(&self, operand: &Operand, pc: usize) -> Result<u32, RuntimeError> {
        let bytes = self.get_operand_value(operand, Some(&Type::U32), pc)?;
        Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| RuntimeError {
            message: "Invalid u32 value".to_string(),
            pc,
        })?))
    }

    /// Gets the value of an operand (register or immediate).
    /// @param operand The operand to process.
    /// @param type_info The expected type, if any.
    /// @param pc The current program counter for error reporting.
    /// @returns The operand's value as bytes, or `Err` if invalid.
    fn get_operand_value(
        &self,
        operand: &Operand,
        type_info: Option<&Type>,
        pc: usize,
    ) -> Result<Vec<u8>, RuntimeError> {
        match operand {
            Operand::Register(reg) if *reg < 16 => Ok(self.registers[*reg as usize].to_le_bytes().to_vec()),
            Operand::Immediate(data) => Ok(data.clone()),
            _ => Err(RuntimeError {
                message: "Invalid operand".to_string(),
                pc,
            }),
        }
    }

    fn get_string(&self, operand: &Operand, pc: usize) -> Result<String, RuntimeError> {
        let bytes = self.get_operand_value(operand, Some(&Type::String), pc)?;
        String::from_utf8(bytes).map_err(|_| RuntimeError {
            message: "Invalid UTF-8 string".to_string(),
            pc,
        })
    }

    fn get_array(&self, operand: &Operand, pc: usize) -> Result<Vec<Value>, RuntimeError> {
        let bytes = self.get_operand_value(operand, Some(&Type::Array(Box::new(Type::U8), 1024)), pc)?;
        Ok(bytes.into_iter().map(|b| Value::U32(b as u32)).collect())
    }

    /// Runs the VM with async support.
    /// @param runtime The async runtime to use.
    /// @returns `Ok(())` if execution succeeds, or `Err` with a `RuntimeError`.
    pub async fn run_with_async(&mut self, runtime: &AsyncRuntime) -> Result<(), RuntimeError> {
        while !self.halted && self.pc < self.bytecode.instructions.len() {
            let instruction = &self.bytecode.instructions[self.pc];
            
            // Record coverage
            if let Some(coverage) = self.coverage_data.as_mut() {
                coverage.insert(self.pc);
            }

            // Handle async operations
            match instruction.opcode {
                KapraOpCode::TcpConnect | KapraOpCode::UdpSend | 
                KapraOpCode::HttpPost | KapraOpCode::HttpGet => {
                    self.execute_instruction(instruction, true)?;
                    // Wait for async operation to complete
                    if let Some((dst_reg, _)) = self.pending_async.last() {
                        runtime.poll().await.map_err(|e| RuntimeError {
                            message: format!("Async operation failed: {}", e),
                            pc: self.pc,
                        })?;
                        self.pending_async.pop();
                    }
                }
                _ => {
                    self.execute_instruction(instruction, true)?;
                }
            }
            self.pc += 1;
        }
        Ok(())
    }

    /// Reloads bytecode while preserving networking state.
    /// @param new_bytecode The new bytecode to load.
    /// @returns `Ok(())` if reload succeeds, or `Err` with a `KslError`.
    fn reload_bytecode(&mut self, new_bytecode: KapraBytecode) -> Result<(), KslError> {
        // Save networking state
        let net_stdlib = self.net_stdlib.take();
        let runtime = self.runtime.take();
        let pending_async = std::mem::take(&mut self.pending_async);

        // Update bytecode
        self.bytecode = new_bytecode;
        self.pc = 0;
        self.halted = false;

        // Restore networking state
        self.net_stdlib = net_stdlib;
        self.runtime = runtime;
        self.pending_async = pending_async;

        Ok(())
    }

    /// Encodes a result value into bytes.
    /// @param value The value to encode.
    /// @returns The encoded bytes.
    fn encode_result(&self, value: Value) -> Result<Vec<u8>, RuntimeError> {
        match value {
            Value::U32(n) => Ok(n.to_le_bytes().to_vec()),
            Value::String(s) => Ok(s.into_bytes()),
            Value::Array(data, _) => {
                let mut bytes = Vec::new();
                for value in data {
                    match value {
                        Value::U32(n) if n <= 255 => bytes.push(n as u8),
                        _ => return Err(RuntimeError {
                            message: "Invalid array element".to_string(),
                            pc: self.pc,
                        }),
                    }
                }
                Ok(bytes)
            }
            _ => Err(RuntimeError {
                message: "Unsupported result type".to_string(),
                pc: self.pc,
            }),
        }
    }

    /// Saves contract state to a file
    pub fn save_contract_state(&self, name: &str) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        
        // Create state directory if it doesn't exist
        let state_dir = PathBuf::from("./state");
        fs::create_dir_all(&state_dir).map_err(|e| KslError::runtime(
            format!("Failed to create state directory: {}", e),
            self.pc, // Use program counter for the instruction position
            "KVM001".to_string()
        ))?;

        // Create contract state
        let state = ContractState {
            name: name.to_string(),
            memory: self.memory.clone(),
            globals: self.state.as_ref()
                .map(|s| s.globals.iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect())
                .unwrap_or_default(),
            stack: self.stack.clone(),
            registers: self.registers.iter()
                .enumerate()
                .map(|(i, v)| (i, v.clone()))
                .collect(),
            heap: self.memory.iter()
                .enumerate()
                .map(|(i, &b)| (i, b))
                .collect(),
            version: 1, // TODO: Track version from contract metadata
        };

        // Serialize state
        let bytes = serialize(&state).map_err(|e| KslError::runtime(
            format!("Failed to serialize contract state: {}", e),
            self.pc,
            "KVM002".to_string()
        ))?;

        // Write to file
        let file_path = state_dir.join(format!("{}.state", name));
        fs::write(&file_path, bytes).map_err(|e| KslError::runtime(
            format!("Failed to write state file: {}", e),
            self.pc, 
            "KVM003".to_string()
        ))?;

        Ok(())
    }

    /// Restores contract state from a file
    pub fn restore_contract_state(&mut self, name: &str) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        
        // Read state file
        let file_path = PathBuf::from("./state").join(format!("{}.state", name));
        let bytes = fs::read(&file_path).map_err(|e| KslError::runtime(
            format!("Failed to read state file: {}", e),
            self.pc,
            "KVM004".to_string()
        ))?;

        // Deserialize state
        let state: ContractState = deserialize(&bytes).map_err(|e| KslError::runtime(
            format!("Failed to deserialize contract state: {}", e),
            self.pc,
            "KVM005".to_string()
        ))?;

        // Restore memory
        self.memory = state.memory;

        // Restore globals
        if let Some(vm_state) = &mut self.state {
            vm_state.globals = state.globals;
        }

        // Restore stack
        self.stack = state.stack;

        // Restore registers
        for (reg_id, value) in state.registers {
            if reg_id < self.registers.len() {
                self.registers[reg_id] = value;
            }
        }

        // Restore heap
        for (addr, value) in state.heap {
            if addr < self.memory.len() {
                self.memory[addr] = value;
            }
        }

        Ok(())
    }

    /// Gets the current gas usage.
    pub fn gas_used(&self) -> u64 {
        self.gas_used
    }

    /// Gets the gas limit.
    pub fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    /// Sets a new gas limit.
    pub fn set_gas_limit(&mut self, limit: u64) {
        self.gas_limit = limit;
    }

    /// Resets gas usage to 0.
    pub fn reset_gas(&mut self) {
        self.gas_used = 0;
    }

    /// Charges gas for an operation
    fn charge_gas(&mut self, amount: u64) -> Result<(), RuntimeError> {
        self.gas_used += amount;
        if self.gas_used > self.gas_limit {
            return Err(RuntimeError {
                message: "Gas limit exceeded".to_string(),
                pc: self.pc,
            });
        }
        
        // Charge to smart account if applicable
        if let Some(account) = self.get_smart_account_mut(&self.gas_charged_to) {
            if account.gas_balance < amount {
                return Err(RuntimeError {
                    message: "Insufficient gas balance".to_string(),
                    pc: self.pc,
                });
            }
            account.gas_balance -= amount;
        }
        
        Ok(())
    }

    /// Sets up gas sponsorship for a transaction
    fn setup_gas_sponsorship(&mut self) -> Result<(), RuntimeError> {
        let sender = self.current_sender.ok_or_else(|| RuntimeError {
            message: "No current sender set".to_string(),
            pc: self.pc,
        })?;

        // Get the sender's smart account
        let account = self.smart_accounts.get(&sender)
            .ok_or_else(|| RuntimeError {
                message: format!("No smart account found for sender {:?}", sender),
                pc: self.pc,
            })?;

        // Check if there's a sponsor and if the gas limit is within bounds
        if let Some(sponsor) = account.sponsor {
            if account.limit >= self.gas_limit {
                self.gas_charged_to = sponsor;
            }
        } else {
            self.gas_charged_to = sender;
        }

        Ok(())
    }

    /// Creates a new smart account
    pub fn create_smart_account(&mut self, address: FixedArray<32>, initial_balance: u64) -> Result<(), RuntimeError> {
        if self.smart_accounts.contains_key(&address) {
            return Err(RuntimeError {
                message: format!("Smart account already exists for address {:?}", address),
                pc: self.pc,
            });
        }

        let account = SmartAccount::new(initial_balance);
        self.smart_accounts.insert(address, account);
        Ok(())
    }

    /// Gets a smart account
    pub fn get_smart_account(&self, address: &FixedArray<32>) -> Option<&SmartAccount> {
        self.smart_accounts.get(address)
    }

    /// Gets a mutable smart account
    pub fn get_smart_account_mut(&mut self, address: &FixedArray<32>) -> Option<&mut SmartAccount> {
        self.smart_accounts.get_mut(address)
    }

    /// Runs a transaction with multiple actions and returns detailed results
    pub fn run_transaction_with_logging(&mut self, tx_context: TransactionContext) -> Result<Vec<ActionResult>, RuntimeError> {
        let mut results = Vec::new();
        self.tx_context = tx_context;
        
        for action in &self.tx_context.actions {
            // Reset VM state for new action
            self.pc = 0;
            self.gas_used = 0;
            self.bytecode = KapraBytecode::from_bytes(&action.data)?;
            self.tx_context.gas_limit = action.gas;
            
            // Set up gas sponsorship
            self.gas_charged_to = self.resolve_gas_payer()?;
            
            // Execute the action
            let result = self.run(false, false);
            
            // Log the result
            results.push(ActionResult {
                to: action.to,
                gas_used: self.gas_used,
                success: result.is_ok(),
                error: result.err().map(|e| e.message),
            });
            
            if result.is_err() {
                return Err(RuntimeError {
                    message: format!("Atomic batch failed at action to {:?}", action.to),
                    pc: self.pc,
                });
            }
        }
        
        Ok(results)
    }

    /// Resolves who should pay for gas based on sponsorship rules
    fn resolve_gas_payer(&self) -> Result<FixedArray<32>, RuntimeError> {
        let sender = self.tx_context.sender;
        let account = self.smart_accounts.get(&sender)
            .ok_or_else(|| RuntimeError {
                message: format!("No smart account found for sender {:?}", sender),
                pc: self.pc,
            })?;

        if let Some(sponsor) = account.sponsor {
            if account.limit >= self.tx_context.gas_limit {
                return Ok(sponsor);
            }
        }

        Ok(sender)
    }

    /// Creates a new VM instance for executing a single action
    pub fn clone_for_action(&self, action: &TxAction) -> Result<Self, RuntimeError> {
        let mut new_vm = self.clone();
        new_vm.bytecode = KapraBytecode::from_bytes(&action.data)?;
        new_vm.gas_limit = action.gas;
        new_vm.gas_used = 0;
        new_vm.pc = 0;
        Ok(new_vm)
    }

    /// Runs a transaction with an auto-generated ID
    pub fn run_transaction_with_id(&mut self, tx_context: TransactionContext, tx_id: u64) -> Result<(), RuntimeError> {
        let mut context = tx_context;
        context.tx_id = tx_id;
        self.run_transaction(context)
    }

    /// Takes a snapshot of the current state for potential rollback
    fn take_state_snapshot(&mut self) {
        self.state_snapshot = Some(self.smart_accounts.clone());
    }

    /// Rolls back to the last state snapshot
    fn rollback_state(&mut self) {
        if let Some(snapshot) = self.state_snapshot.take() {
            self.smart_accounts = snapshot;
        }
    }

    /// Executes the postcondition block
    fn execute_postconditions(&mut self) -> Result<(), RuntimeError> {
        if let Some(postcode) = &self.postconditions {
            let saved_bytecode = self.bytecode.clone();
            let saved_pc = self.pc;
            
            self.bytecode = postcode.clone();
            self.pc = 0;

            let result = self.run(false, false);
            
            // Restore original bytecode and PC
            self.bytecode = saved_bytecode;
            self.pc = saved_pc;
            
            result
        } else {
            Ok(())
        }
    }

    /// Runs a transaction with multiple actions and postcondition verification
    pub fn run_transaction(&mut self, tx_context: TransactionContext) -> Result<(), RuntimeError> {
        self.tx_context = tx_context;
        
        for action in &self.tx_context.actions {
            // Reset VM state for new action
            self.pc = 0;
            self.gas_used = 0;
            self.bytecode = KapraBytecode::from_bytes(&action.data)?;
            self.tx_context.gas_limit = action.gas;
            
            // Set up gas sponsorship
            self.gas_charged_to = self.resolve_gas_payer()?;
            
            // Take state snapshot before execution
            self.take_state_snapshot();
            
            // Execute the action
            let result = self.run(false, false);
            if result.is_err() {
                self.rollback_state();
                return Err(RuntimeError {
                    message: format!("Atomic batch failed at action to {:?}", action.to),
                    pc: self.pc,
                });
            }

            // Execute postconditions
            let verify_result = self.execute_postconditions();
            if verify_result.is_err() {
                self.rollback_state();
                return Err(RuntimeError {
                    message: format!("Postcondition failed for action to {:?}", action.to),
                    pc: self.pc,
                });
            }
        }
        
        Ok(())
    }

    /// Sets the postcondition block for the current transaction
    pub fn set_postconditions(&mut self, postcode: KapraBytecode) {
        self.postconditions = Some(postcode);
    }

    /// Deploys a new contract
    pub fn deploy_contract(
        &mut self,
        bytecode: KapraBytecode,
        sender: FixedArray<32>,
        changelog: String,
    ) -> Result<FixedArray<32>, RuntimeError> {
        // Generate contract address from sender and bytecode
        let mut hasher = Sha3_256::new();
        hasher.update(&sender.0);
        hasher.update(&bytecode.to_bytes());
        let contract_id = FixedArray(hasher.finalize().into());

        // Create metadata
        let metadata = ContractMetadata {
            contract_id,
            version: 1,
            version_hash: self.hash_bytecode(&bytecode),
            changelog,
            upgrade_key: sender,
            deprecated: false,
            upgrade_guardians: Vec::new(),
        };

        // Store contract data
        self.contract_registry.insert(contract_id, metadata);
        self.contract_bytecode.insert(contract_id, bytecode);

        Ok(contract_id)
    }

    /// Upgrades an existing contract
    pub fn upgrade_contract(
        &mut self,
        contract_id: FixedArray<32>,
        new_bytecode: KapraBytecode,
        new_version: u32,
        changelog: String,
    ) -> Result<(), RuntimeError> {
        let sender = self.current_sender.ok_or_else(|| RuntimeError {
            message: "No current sender set".to_string(),
            pc: self.pc,
        })?;

        let metadata = self.contract_registry.get_mut(&contract_id)
            .ok_or_else(|| RuntimeError {
                message: format!("Contract not found: {:?}", contract_id),
                pc: self.pc,
            })?;

        // Check authorization
        if sender != metadata.upgrade_key {
            // Check if sender is a guardian
            if !metadata.upgrade_guardians.contains(&sender) {
                return Err(RuntimeError {
                    message: "Unauthorized upgrade".to_string(),
                    pc: self.pc,
                });
            }
        }

        // Validate version
        if new_version <= metadata.version {
            return Err(RuntimeError {
                message: "Version must increase".to_string(),
                pc: self.pc,
            });
        }

        // Update metadata
        metadata.version = new_version;
        metadata.version_hash = self.hash_bytecode(&new_bytecode);
        metadata.changelog = changelog;

        // Update bytecode
        self.contract_bytecode.insert(contract_id, new_bytecode);

        Ok(())
    }

    /// Gets contract metadata
    pub fn get_contract_metadata(&self, contract_id: FixedArray<32>) -> Result<ContractMetadata, RuntimeError> {
        self.contract_registry.get(&contract_id)
            .cloned()
            .ok_or_else(|| RuntimeError {
                message: format!("Contract not found: {:?}", contract_id),
                pc: self.pc,
            })
    }

    /// Marks a contract as deprecated
    pub fn deprecate_contract(&mut self, contract_id: FixedArray<32>) -> Result<(), RuntimeError> {
        let sender = self.current_sender.ok_or_else(|| RuntimeError {
            message: "No current sender set".to_string(),
            pc: self.pc,
        })?;

        let metadata = self.contract_registry.get_mut(&contract_id)
            .ok_or_else(|| RuntimeError {
                message: format!("Contract not found: {:?}", contract_id),
                pc: self.pc,
            })?;

        if sender != metadata.upgrade_key {
            return Err(RuntimeError {
                message: "Unauthorized deprecation".to_string(),
                pc: self.pc,
            });
        }

        metadata.deprecated = true;
        Ok(())
    }

    /// Adds an upgrade guardian
    pub fn add_upgrade_guardian(&mut self, contract_id: FixedArray<32>, guardian: FixedArray<32>) -> Result<(), RuntimeError> {
        let sender = self.current_sender.ok_or_else(|| RuntimeError {
            message: "No current sender set".to_string(),
            pc: self.pc,
        })?;

        let metadata = self.contract_registry.get_mut(&contract_id)
            .ok_or_else(|| RuntimeError {
                message: format!("Contract not found: {:?}", contract_id),
                pc: self.pc,
            })?;

        if sender != metadata.upgrade_key {
            return Err(RuntimeError {
                message: "Unauthorized guardian addition".to_string(),
                pc: self.pc,
            });
        }

        if !metadata.upgrade_guardians.contains(&guardian) {
            metadata.upgrade_guardians.push(guardian);
        }

        Ok(())
    }

    /// Removes an upgrade guardian
    pub fn remove_upgrade_guardian(&mut self, contract_id: FixedArray<32>, guardian: FixedArray<32>) -> Result<(), RuntimeError> {
        let sender = self.current_sender.ok_or_else(|| RuntimeError {
            message: "No current sender set".to_string(),
            pc: self.pc,
        })?;

        let metadata = self.contract_registry.get_mut(&contract_id)
            .ok_or_else(|| RuntimeError {
                message: format!("Contract not found: {:?}", contract_id),
                pc: self.pc,
            })?;

        if sender != metadata.upgrade_key {
            return Err(RuntimeError {
                message: "Unauthorized guardian removal".to_string(),
                pc: self.pc,
            });
        }

        metadata.upgrade_guardians.retain(|&g| g != guardian);
        Ok(())
    }

    /// Hashes bytecode for version tracking
    fn hash_bytecode(&self, bytecode: &KapraBytecode) -> FixedArray<32> {
        let mut hasher = Sha3_256::new();
        hasher.update(&bytecode.to_bytes());
        FixedArray(hasher.finalize().into())
    }
}

/// Simplified Kaprekar step (for u32 input).
fn kaprekar_step(input: u32) -> u32 {
    let mut digits = input.to_string().chars().collect::<Vec<_>>();
    while digits.len() < 4 {
        digits.push('0');
    }
    digits.sort();
    let asc = digits.iter().collect::<String>().parse::<u32>().unwrap();
    digits.reverse();
    let desc = digits.iter().collect::<String>().parse::<u32>().unwrap();
    desc - asc
}

/// Public API to run bytecode.
/// @param bytecode The bytecode program to execute.
/// @returns `Ok(())` if execution succeeds, or `Err` with a `RuntimeError`.
/// @example
/// ```ksl
/// let bytecode = KapraBytecode::new();
/// run(bytecode).unwrap();
/// ```
pub fn run(bytecode: KapraBytecode, async_support: bool, debug_mode: bool) -> Result<(), KslError> {
    let mut vm = KapraVM::new(bytecode, None, None);
    if debug_mode {
        vm.enable_debug();
    }
    vm.run()?;
    Ok(())
}

// Implement HotReloadableVM trait
impl ksl_hot_reload::HotReloadableVM for KapraVM {
    fn new_with_state(bytecode: KapraBytecode) -> Self {
        let mut vm = KapraVM::new(bytecode, None, None);
        vm.state = Some(HotReloadState {
            globals: HashMap::new(),
            networking_state: NetworkingState::default(),
            async_state: AsyncState::default(),
            preserved_registers: HashMap::new(),
            preserved_stack: Vec::new(),
            preserved_heap: HashMap::new(),
        });
        vm
    }

    fn run_with_state(&mut self) -> Result<(), RuntimeError> {
        self.run(true, self.debug_mode)?;
        Ok(())
    }

    fn reload_bytecode(
        &mut self,
        new_bytecode: KapraBytecode,
        networking_state: Option<NetworkingState>,
        async_state: Option<AsyncState>,
    ) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);

        // Save current state if we have a contract name
        if let Some(state) = &self.state {
            if let Some(contract_name) = state.globals.get("__contract_name") {
                if let Ok(name) = String::from_utf8(contract_name.clone()) {
                    self.save_contract_state(&name)?;
                }
            }
        }

        // Preserve current state
        let preserved_state = if let Some(state) = &self.state {
            HotReloadState {
                globals: state.globals.clone(),
                networking_state: networking_state.unwrap_or_else(|| state.networking_state.clone()),
                async_state: async_state.unwrap_or_else(|| state.async_state.clone()),
                preserved_registers: self.registers.iter()
                    .enumerate()
                    .map(|(i, v)| (i, v.clone()))
                    .collect(),
                preserved_stack: self.stack.clone(),
                preserved_heap: self.memory.iter().map(|&b| b as u8).collect(),
            }
        } else {
            HotReloadState {
                globals: HashMap::new(),
                networking_state: networking_state.unwrap_or_default(),
                async_state: async_state.unwrap_or_default(),
                preserved_registers: HashMap::new(),
                preserved_stack: Vec::new(),
                preserved_heap: HashMap::new(),
            }
        };

        // Update bytecode
        self.bytecode = new_bytecode;
        self.pc = 0; // Reset program counter

        // Restore preserved state
        self.state = Some(preserved_state.clone());

        // Restore registers that exist in both old and new bytecode
        for (reg_id, value) in preserved_state.preserved_registers {
            if reg_id < self.registers.len() {
                self.registers[reg_id] = value;
            }
        }

        // Restore stack if compatible
        if self.validate_stack_compatibility(&preserved_state.preserved_stack)? {
            self.stack = preserved_state.preserved_stack;
        }

        // Restore heap
        self.memory = preserved_state.preserved_heap.iter().map(|&b| b as u8).collect();

        // Restore contract state if we have a contract name
        if let Some(state) = &self.state {
            if let Some(contract_name) = state.globals.get("__contract_name") {
                if let Ok(name) = String::from_utf8(contract_name.clone()) {
                    self.restore_contract_state(&name)?;
                }
            }
        }

        // Validate restored state
        self.validate_state()?;

        Ok(())
    }
}

// Implement CoverageVM trait
impl ksl_coverage::CoverageVM for KapraVM {
    fn new_with_coverage(bytecode: KapraBytecode) -> Self {
        let mut vm = KapraVM::new(bytecode, None, None);
        vm.coverage_data = Some(HashSet::new());
        vm
    }

    fn get_executed_instructions(&self) -> &HashSet<usize> {
        self.coverage_data.as_ref().unwrap()
    }
}

// Implement MetricsVM trait
impl ksl_metrics::MetricsVM for KapraVM {
    fn new_with_metrics(bytecode: KapraBytecode) -> Self {
        let mut vm = KapraVM::new(bytecode, None, None);
        vm.metrics_data = Some(MetricsData {
            memory_usage: 0,
        });
        vm
    }

    fn get_memory_usage(&self) -> usize {
        let register_size = self.registers.iter().map(|r| r.len()).sum::<usize>();
        let stack_size = self.stack.iter().map(|(_, regs)| regs.values().map(|v| v.len()).sum::<usize>()).sum::<usize>();
        let memory_size = self.memory.values().map(|v| v.len()).sum::<usize>();
        register_size + stack_size + memory_size
    }
}

// Implement SimVM trait
impl ksl_simulator::SimVM for KapraVM {
    fn new_with_simulation(bytecode: KapraBytecode) -> Self {
        let mut vm = KapraVM::new(bytecode, None, None);
        vm.simulation_data = Some(SimulationData {
            tx_index: 0,
            sensor_reading: None,
        });
        vm
    }

    fn simulate_instruction(&mut self, instr: &KapraInstruction, simulator: &mut ksl_simulator::Simulator) -> Result<(), RuntimeError> {
        match instr.opcode {
            KapraOpCode::Sha3 | KapraOpCode::BlsVerify | KapraOpCode::DilithiumVerify | KapraOpCode::MerkleVerify => {
                if simulator.config.env == "blockchain" {
                    if let Some(tx) = simulator.blockchain_txs.get(self.simulation_data.as_ref().unwrap().tx_index) {
                        simulator.logs.push(format!("Processed transaction ID {}", tx.id));
                        self.simulation_data.as_mut().unwrap().tx_index += 1;
                    }
                }
            }
            _ => {}
        }
        self.execute_instruction(instr)
    }
}

impl KapraVM {
    /// Get current globals
    pub fn get_globals(&self) -> Result<HashMap<String, Value>, KslError> {
        Ok(self.state.as_ref()
            .map(|s| s.globals.clone())
            .unwrap_or_default())
    }

    /// Set globals
    pub fn set_globals(&mut self, globals: HashMap<String, Value>) -> Result<(), KslError> {
        if let Some(state) = self.state.as_mut() {
            state.globals = globals;
        }
        Ok(())
    }

    /// Pause operations for a module
    pub fn pause_operations(&mut self, module_name: &str) -> Result<(), KslError> {
        // Pause any operations associated with the module
        if let Some(state) = self.state.as_mut() {
            // Pause networking operations
            for conn in state.networking_state.http_connections.values_mut() {
                if conn.module == module_name {
                    conn.state = ConnectionState::Paused;
                }
            }
            for conn in state.networking_state.tcp_connections.values_mut() {
                if conn.module == module_name {
                    conn.state = ConnectionState::Paused;
                }
            }

            // Pause async operations
            for op in state.async_state.active_operations.values_mut() {
                if op.module == module_name {
                    op.state = AsyncStateType::Paused;
                }
            }
        }
        Ok(())
    }

    /// Resume operations for a module
    pub fn resume_operations(&mut self, module_name: &str) -> Result<(), KslError> {
        // Resume paused operations for the module
        if let Some(state) = self.state.as_mut() {
            // Resume networking operations
            for conn in state.networking_state.http_connections.values_mut() {
                if conn.module == module_name && conn.state == ConnectionState::Paused {
                    conn.state = ConnectionState::Connected;
                }
            }
            for conn in state.networking_state.tcp_connections.values_mut() {
                if conn.module == module_name && conn.state == ConnectionState::Paused {
                    conn.state = ConnectionState::Connected;
                }
            }

            // Resume async operations
            for op in state.async_state.active_operations.values_mut() {
                if op.module == module_name && op.state == AsyncStateType::Paused {
                    op.state = AsyncStateType::Pending;
                }
            }
        }
        Ok(())
    }

    /// Validate stack compatibility
    fn validate_stack_compatibility(&self, preserved_stack: &Vec<Value>) -> Result<bool, KslError> {
        // Check if stack types are compatible with current bytecode
        for (i, value) in preserved_stack.iter().enumerate() {
            if let Some(expected_type) = self.bytecode.get_stack_type(i) {
                if !value.matches_type(expected_type) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Validate restored state
    fn validate_state(&self) -> Result<(), KslError> {
        if let Some(state) = &self.state {
            // Validate globals
            for (name, value) in &state.globals {
                if let Some(expected_type) = self.bytecode.get_global_type(name) {
                    if !value.matches_type(expected_type) {
                        return Err(KslError::type_error(
                            format!("Invalid type for global variable {}", name),
                            None,
                        ));
                    }
                }
            }

            // Validate registers
            for (reg_id, value) in &state.preserved_registers {
                if let Some(expected_type) = self.bytecode.get_register_type(*reg_id) {
                    if !value.matches_type(expected_type) {
                        return Err(KslError::type_error(
                            format!("Invalid type for register {}", reg_id),
                            None,
                        ));
                    }
                }
            }

            // Validate heap references
            for (addr, value) in &state.preserved_heap {
                if !self.validate_heap_reference(*addr, value)? {
                    return Err(KslError::runtime_error(
                        format!("Invalid heap reference at address {}", addr),
                        None,
                    ));
                }
            }
        }
        Ok(())
    }

    /// Validate heap reference
    fn validate_heap_reference(&self, addr: usize, value: &Value) -> Result<bool, KslError> {
        // Check if heap reference is valid in current bytecode
        if let Some(heap_type) = self.bytecode.get_heap_type(addr) {
            Ok(value.matches_type(heap_type))
        } else {
            Ok(false)
        }
    }
}

#[derive(Clone)]
struct HotReloadState {
    globals: HashMap<String, Value>,
    networking_state: NetworkingState,
    async_state: AsyncState,
    preserved_registers: HashMap<usize, Vec<u8>>,
    preserved_stack: Vec<Value>,
    preserved_heap: HashMap<usize, Value>,
}

#[derive(Clone, PartialEq)]
enum ConnectionState {
    Connected,
    Connecting,
    Closed,
    Paused,
}

#[derive(Clone, PartialEq)]
enum AsyncStateType {
    Pending,
    Completed,
    Failed(String),
    Paused,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ksl_bytecode::KapraBytecode;
    use tokio::runtime::Runtime;
    use blst::min_pk::*;
    use std::time::Instant;

    #[test]
    fn run_arithmetic() {
        let mut bytecode = KapraBytecode::new();
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(0),
                Operand::Immediate(42u32.to_le_bytes().to_vec()),
            ],
            Some(Type::U32),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Add,
            vec![
                Operand::Register(1),
                Operand::Register(0),
                Operand::Register(0),
            ],
            Some(Type::U32),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let mut vm = KapraVM::new(bytecode, None, None);
        vm.run().unwrap();
        assert_eq!(
            vm.registers[1],
            84u32.to_le_bytes().to_vec(),
            "Expected y = 42 + 42 = 84"
        );
    }

    #[test]
    fn run_function_call() {
        let mut bytecode = KapraBytecode::new();
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Add,
            vec![
                Operand::Register(2),
                Operand::Register(0),
                Operand::Register(1),
            ],
            Some(Type::U32),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Return,
            vec![],
            None,
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(0),
                Operand::Immediate(42u32.to_le_bytes().to_vec()),
            ],
            Some(Type::U32),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(1),
                Operand::Immediate(10u32.to_le_bytes().to_vec()),
            ],
            Some(Type::U32),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Call,
            vec![Operand::Immediate(0u32.to_le_bytes().to_vec())],
            None,
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let mut vm = KapraVM::new(bytecode, None, None);
        vm.run().unwrap();
        assert_eq!(
            vm.registers[2],
            52u32.to_le_bytes().to_vec(),
            "Expected add(42, 10) = 52"
        );
    }

    #[test]
    fn run_sha3() {
        let mut bytecode = KapraBytecode::new();
        let input = "test".as_bytes().to_vec();
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(0), Operand::Immediate(input)],
            Some(Type::String),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Sha3,
            vec![Operand::Register(1), Operand::Register(0)],
            Some(Type::Array(Box::new(Type::U8), 32)),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let mut vm = KapraVM::new(bytecode, None, None);
        vm.run().unwrap();
        let mut hasher = Sha3_256::new();
        hasher.update("test");
        let expected = hasher.finalize().to_vec();
        assert_eq!(vm.registers[1], expected, "Expected SHA3-256('test')");
    }

    #[test]
    fn run_dilithium_verify() {
        let mut bytecode = KapraBytecode::new();
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(0), Operand::Immediate(vec![0; 32])],
            Some(Type::Array(Box::new(Type::U8), 32)),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(1), Operand::Immediate(vec![0; 1312])],
            Some(Type::Array(Box::new(Type::U8), 1312)),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(2), Operand::Immediate(vec![0; 2420])],
            Some(Type::Array(Box::new(Type::U8), 2420)),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::DilithiumVerify,
            vec![
                Operand::Register(3),
                Operand::Register(0),
                Operand::Register(1),
                Operand::Register(2),
            ],
            Some(Type::U32),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let mut vm = KapraVM::new(bytecode, None, None);
        vm.run().unwrap();
        assert_eq!(
            vm.registers[3],
            1u32.to_le_bytes().to_vec(),
            "Expected Dilithium verify to return true"
        );
    }

    #[test]
    fn run_async_call() {
        let mut bytecode = KapraBytecode::new();
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::AsyncCall,
            vec![
                Operand::Register(0),
                Operand::Immediate(1u32.to_le_bytes().to_vec()),
            ],
            Some(Type::Option(Box::new(Type::String))),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let mut vm = KapraVM::new(bytecode, None, None);
        vm.run().unwrap();
        assert_eq!(
            vm.registers[0],
            vec![b'r', b'e', b's', b'u', b'l', b't'],
            "Expected async call to return 'result'"
        );
        assert_eq!(vm.pending_async, vec![(0, 1)]);
    }

    #[test]
    fn test_hot_reload() {
        let mut bytecode = KapraBytecode::new();
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(0),
                Operand::Immediate(42u32.to_le_bytes().to_vec()),
            ],
            Some(Type::U32),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let mut vm = KapraVM::new_with_state(bytecode.clone());
        vm.registers[1] = 100u32.to_le_bytes().to_vec(); // Set state
        let new_bytecode = bytecode; // Same bytecode for simplicity
        vm.reload_bytecode(new_bytecode, None, None).unwrap();
        assert_eq!(vm.pc, 0, "Program counter should reset");
        assert_eq!(
            vm.registers[1],
            100u32.to_le_bytes().to_vec(),
            "State should be preserved"
        );
    }

    #[test]
    fn test_coverage() {
        let mut bytecode = KapraBytecode::new();
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(0),
                Operand::Immediate(42u32.to_le_bytes().to_vec()),
            ],
            Some(Type::U32),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let mut vm = KapraVM::new_with_coverage(bytecode);
        vm.run().unwrap();
        let executed = vm.get_executed_instructions();
        assert!(executed.contains(&0), "Instruction 0 should be executed");
        assert!(executed.contains(&1), "Instruction 1 should be executed");
    }

    #[tokio::test]
    async fn test_http_get() {
        let runtime = Arc::new(AsyncRuntime::new());
        let mut bytecode = KapraBytecode::new();
        
        // Build test program
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::HttpGet,
            vec![
                Operand::Register(0),
                Operand::Immediate("https://httpbin.org/get".as_bytes().to_vec()),
            ],
            Some(Type::Result {
                ok: Box::new(Type::String),
                err: Box::new(Type::Error),
            }),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let mut vm = KapraVM::new(bytecode, Some(runtime.clone()), None);
        let result = vm.run_with_async(&runtime).await;
        assert!(result.is_ok());
        
        // Check response
        let response = String::from_utf8(vm.registers[0].clone()).unwrap();
        assert!(response.contains("httpbin.org"));
    }

    #[tokio::test]
    async fn test_http_post() {
        let runtime = Arc::new(AsyncRuntime::new());
        let mut bytecode = KapraBytecode::new();
        
        // Build test program
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::HttpPost,
            vec![
                Operand::Register(0),
                Operand::Immediate("https://httpbin.org/post".as_bytes().to_vec()),
                Operand::Immediate("{\"test\": true}".as_bytes().to_vec()),
            ],
            Some(Type::Result {
                ok: Box::new(Type::String),
                err: Box::new(Type::Error),
            }),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let mut vm = KapraVM::new(bytecode, Some(runtime.clone()), None);
        let result = vm.run_with_async(&runtime).await;
        assert!(result.is_ok());
        
        // Check response
        let response = String::from_utf8(vm.registers[0].clone()).unwrap();
        assert!(response.contains("\"test\": true"));
    }

    #[tokio::test]
    async fn test_tcp_connect() {
        let runtime = Arc::new(AsyncRuntime::new());
        let mut bytecode = KapraBytecode::new();
        
        // Build test program
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::TcpConnect,
            vec![
                Operand::Register(0),
                Operand::Immediate("localhost".as_bytes().to_vec()),
                Operand::Immediate(8080u32.to_le_bytes().to_vec()),
            ],
            Some(Type::Result {
                ok: Box::new(Type::U32),
                err: Box::new(Type::Error),
            }),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let mut vm = KapraVM::new(bytecode, Some(runtime.clone()), None);
        let result = vm.run_with_async(&runtime).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_udp_send() {
        let runtime = Arc::new(AsyncRuntime::new());
        let mut bytecode = KapraBytecode::new();
        
        // Build test program
        let data = vec![1u8, 2, 3, 4, 5];
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::UdpSend,
            vec![
                Operand::Register(0),
                Operand::Immediate("localhost".as_bytes().to_vec()),
                Operand::Immediate(8080u32.to_le_bytes().to_vec()),
                Operand::Immediate(data.clone()),
            ],
            Some(Type::Result {
                ok: Box::new(Type::U32),
                err: Box::new(Type::Error),
            }),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let mut vm = KapraVM::new(bytecode, Some(runtime.clone()), None);
        let result = vm.run_with_async(&runtime).await;
        assert!(result.is_ok());
        
        // Check bytes sent
        let bytes_sent = u32::from_le_bytes(vm.registers[0][..4].try_into().unwrap());
        assert_eq!(bytes_sent as usize, data.len());
    }

    #[test]
    fn test_print() {
        let mut bytecode = KapraBytecode::new();
        
        // Build test program
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Print,
            vec![
                Operand::Register(0),
                Operand::Immediate("Hello, world!".as_bytes().to_vec()),
            ],
            Some(Type::Void),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let mut vm = KapraVM::new(bytecode, None, None);
        let result = vm.run();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_reload_with_networking() {
        let runtime = Arc::new(AsyncRuntime::new());
        let mut original_bytecode = KapraBytecode::new();
        
        // Original program with HTTP GET
        original_bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::HttpGet,
            vec![
                Operand::Register(0),
                Operand::Immediate("https://httpbin.org/get".as_bytes().to_vec()),
            ],
            Some(Type::Result {
                ok: Box::new(Type::String),
                err: Box::new(Type::Error),
            }),
        ));

        let mut vm = KapraVM::new(original_bytecode, Some(runtime.clone()), None);
        
        // Create new bytecode
        let mut new_bytecode = KapraBytecode::new();
        new_bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::HttpPost,
            vec![
                Operand::Register(0),
                Operand::Immediate("https://httpbin.org/post".as_bytes().to_vec()),
                Operand::Immediate("{\"reloaded\": true}".as_bytes().to_vec()),
            ],
            Some(Type::Result {
                ok: Box::new(Type::String),
                err: Box::new(Type::Error),
            }),
        ));

        // Reload bytecode
        vm.reload_bytecode(new_bytecode, None, None).unwrap();
        
        // Run new program
        let result = vm.run_with_async(&runtime).await;
        assert!(result.is_ok());
        
        // Check response
        let response = String::from_utf8(vm.registers[0].clone()).unwrap();
        assert!(response.contains("\"reloaded\": true"));
    }

    #[test]
    fn test_gas_metering() {
        // Create bytecode with various operations
        let mut bytecode = KapraBytecode::new();
        
        // Add some instructions with different gas costs
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(0), Operand::Immediate(vec![42])],
            Some(Type::U32),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Add,
            vec![
                Operand::Register(1),
                Operand::Register(0),
                Operand::Register(0),
            ],
            Some(Type::U32),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Sha3,
            vec![Operand::Register(2), Operand::Register(1)],
            Some(Type::Array(Box::new(Type::U8), 32)),
        ));

        // Test with sufficient gas
        let mut vm = KapraVM::new(bytecode.clone(), None, Some(200));
        let result = vm.run(false, false);
        assert!(result.is_ok());
        assert_eq!(vm.gas_used(), 55); // 2 + 3 + 50

        // Test with insufficient gas
        let mut vm = KapraVM::new(bytecode, None, Some(50));
        let result = vm.run(false, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Gas limit exceeded"));
    }

    #[test]
    fn test_gas_reset() {
        let mut bytecode = KapraBytecode::new();
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(0), Operand::Immediate(vec![42])],
            Some(Type::U32),
        ));

        let mut vm = KapraVM::new(bytecode, None, Some(100));
        vm.run(false, false).unwrap();
        assert_eq!(vm.gas_used(), 2);

        vm.reset_gas();
        assert_eq!(vm.gas_used(), 0);
    }

    #[test]
    fn test_gas_limit_update() {
        let mut bytecode = KapraBytecode::new();
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Sha3,
            vec![Operand::Register(0), Operand::Register(1)],
            Some(Type::Array(Box::new(Type::U8), 32)),
        ));

        let mut vm = KapraVM::new(bytecode, None, Some(40));
        let result = vm.run(false, false);
        assert!(result.is_err()); // Should fail with 40 gas limit

        vm.set_gas_limit(60);
        vm.reset_gas();
        let result = vm.run(false, false);
        assert!(result.is_ok()); // Should succeed with 60 gas limit
    }

    #[test]
    fn test_bls_verify() {
        use blst::min_pk::*;

        // Generate a keypair
        let ikm = b"test-key";
        let sk = SecretKey::key_gen(ikm);
        let pk = sk.sk_to_pk();

        // Create a message and sign it
        let message = b"test message";
        let sig = sk.sign(message, &[], &pk, b"KSL_BLS_SIG");

        // Convert to bytes
        let msg_bytes = message.to_vec();
        let pk_bytes = pk.to_bytes();
        let sig_bytes = sig.to_bytes();

        // Create bytecode
        let mut bytecode = KapraBytecode::new();
        
        // Load message
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(0),
                Operand::Immediate(msg_bytes),
            ],
            Some(Type::Array(Box::new(Type::U8), 32)),
        ));

        // Load public key
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(1),
                Operand::Immediate(pk_bytes.to_vec()),
            ],
            Some(Type::Array(Box::new(Type::U8), 96)),
        ));

        // Load signature
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(2),
                Operand::Immediate(sig_bytes.to_vec()),
            ],
            Some(Type::Array(Box::new(Type::U8), 48)),
        ));

        // Verify signature
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::BlsVerify,
            vec![
                Operand::Register(3),
                Operand::Register(0),
                Operand::Register(1),
                Operand::Register(2),
            ],
            Some(Type::U32),
        ));

        // Halt
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        // Run VM
        let mut vm = KapraVM::new(bytecode, None, None);
        vm.run(false, false).unwrap();

        // Check result
        let result = u32::from_le_bytes(vm.registers[3][..4].try_into().unwrap());
        assert_eq!(result, 1, "BLS verification should succeed");

        // Test with invalid signature
        let mut invalid_sig = sig_bytes;
        invalid_sig[0] ^= 1; // Flip a bit

        let mut bytecode = KapraBytecode::new();
        
        // Load message
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(0),
                Operand::Immediate(msg_bytes),
            ],
            Some(Type::Array(Box::new(Type::U8), 32)),
        ));

        // Load public key
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(1),
                Operand::Immediate(pk_bytes.to_vec()),
            ],
            Some(Type::Array(Box::new(Type::U8), 96)),
        ));

        // Load invalid signature
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(2),
                Operand::Immediate(invalid_sig.to_vec()),
            ],
            Some(Type::Array(Box::new(Type::U8), 48)),
        ));

        // Verify signature
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::BlsVerify,
            vec![
                Operand::Register(3),
                Operand::Register(0),
                Operand::Register(1),
                Operand::Register(2),
            ],
            Some(Type::U32),
        ));

        // Halt
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        // Run VM
        let mut vm = KapraVM::new(bytecode, None, None);
        vm.run(false, false).unwrap();

        // Check result
        let result = u32::from_le_bytes(vm.registers[3][..4].try_into().unwrap());
        assert_eq!(result, 0, "BLS verification should fail with invalid signature");
    }

    #[test]
    fn benchmark_vm_bls_verify() {
        // Generate a keypair
        let ikm = b"test-key";
        let sk = SecretKey::key_gen(ikm);
        let pk = sk.sk_to_pk();

        // Create a message and sign it
        let message = b"test message";
        let sig = sk.sign(message, &[], &pk, DST);

        // Convert to bytes
        let msg_bytes = message.to_vec();
        let pk_bytes = pk.to_bytes();
        let sig_bytes = sig.to_bytes();

        // Create bytecode for BLS verification
        let mut bytecode = Vec::new();
        
        // Load message into register 1
        bytecode.extend_from_slice(&[KapraOpCode::Load as u8]);
        bytecode.extend_from_slice(&1u8.to_le_bytes());
        bytecode.extend_from_slice(&msg_bytes);
        
        // Load public key into register 2
        bytecode.extend_from_slice(&[KapraOpCode::Load as u8]);
        bytecode.extend_from_slice(&2u8.to_le_bytes());
        bytecode.extend_from_slice(&pk_bytes);
        
        // Load signature into register 3
        bytecode.extend_from_slice(&[KapraOpCode::Load as u8]);
        bytecode.extend_from_slice(&3u8.to_le_bytes());
        bytecode.extend_from_slice(&sig_bytes);
        
        // Perform BLS verification, store result in register 0
        bytecode.extend_from_slice(&[KapraOpCode::BlsVerify as u8]);
        bytecode.extend_from_slice(&0u8.to_le_bytes());
        bytecode.extend_from_slice(&1u8.to_le_bytes());
        bytecode.extend_from_slice(&2u8.to_le_bytes());
        bytecode.extend_from_slice(&3u8.to_le_bytes());

        // Create VM
        let mut vm = KapraVM::new(Some(1000000)); // Set gas limit to 1M

        // Warm up
        for _ in 0..10 {
            vm.reset();
            vm.load_bytecode(&bytecode);
            vm.run().unwrap();
        }

        // Benchmark
        let iterations = 100;
        let start = Instant::now();
        for _ in 0..iterations {
            vm.reset();
            vm.load_bytecode(&bytecode);
            vm.run().unwrap();
        }
        let duration = start.elapsed();
        let avg_time = duration.as_nanos() as f64 / iterations as f64;
        println!("Average VM BLS verification time: {:.2} ns", avg_time);
        println!("Average VM BLS verification time: {:.2} ms", avg_time / 1_000_000.0);

        // Verify performance meets requirements
        assert!(avg_time < 100_000_000.0, "VM BLS verification should complete in < 100ms");
    }

    #[test]
    fn test_auth_delegation() {
        let mut bytecode = KapraBytecode::new();
        
        // Create test addresses
        let delegator = [1u8; 32];
        let delegatee = [2u8; 32];
        let target = [3u8; 32];
        
        // Set up AUTH instruction
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Auth,
            vec![Operand::Immediate(delegatee.to_vec())],
            Some(Type::Array(Box::new(Type::U8), 32)),
        ));
        
        // Set up AUTHCALL instruction
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::AuthCall,
            vec![Operand::Immediate(target.to_vec())],
            Some(Type::Array(Box::new(Type::U8), 32)),
        ));
        
        let mut vm = KapraVM::new(bytecode, None, None);
        vm.current_sender = Some(FixedArray(delegator));
        
        // Run the VM
        vm.run().unwrap();
        
        // Verify auth stack is cleared after transaction
        assert!(vm.auth_stack.is_empty());
    }

    #[test]
    fn test_auth_call_without_delegation() {
        let mut bytecode = KapraBytecode::new();
        
        // Set up AUTHCALL instruction without prior AUTH
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::AuthCall,
            vec![Operand::Immediate([1u8; 32].to_vec())],
            Some(Type::Array(Box::new(Type::U8), 32)),
        ));
        
        let mut vm = KapraVM::new(bytecode, None, None);
        
        // Run should fail due to no delegation
        assert!(vm.run().is_err());
    }

    #[test]
    fn test_nested_delegation() {
        let mut bytecode = KapraBytecode::new();
        
        // Create test addresses
        let delegator = [1u8; 32];
        let delegatee1 = [2u8; 32];
        let delegatee2 = [3u8; 32];
        let target = [4u8; 32];
        
        // Set up nested AUTH instructions
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Auth,
            vec![Operand::Immediate(delegatee1.to_vec())],
            Some(Type::Array(Box::new(Type::U8), 32)),
        ));
        
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Auth,
            vec![Operand::Immediate(delegatee2.to_vec())],
            Some(Type::Array(Box::new(Type::U8), 32)),
        ));
        
        // Set up AUTHCALL instruction
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::AuthCall,
            vec![Operand::Immediate(target.to_vec())],
            Some(Type::Array(Box::new(Type::U8), 32)),
        ));
        
        let mut vm = KapraVM::new(bytecode, None, None);
        vm.current_sender = Some(FixedArray(delegator));
        
        // Run the VM
        vm.run().unwrap();
        
        // Verify auth stack is cleared after transaction
        assert!(vm.auth_stack.is_empty());
    }

    #[test]
    fn test_gas_sponsorship() {
        let mut vm = KapraVM::new(KapraBytecode::new(), None, Some(1000));
        
        // Create accounts
        let sender = FixedArray([1; 32]);
        let sponsor = FixedArray([2; 32]);
        
        vm.create_smart_account(sender, 100).unwrap();
        vm.create_smart_account(sponsor, 1000).unwrap();
        
        // Set up sponsorship
        let mut sender_account = vm.get_smart_account_mut(&sender).unwrap();
        sender_account.set_sponsor(sponsor, 500);
        
        // Set current sender and setup sponsorship
        vm.current_sender = Some(sender);
        vm.setup_gas_sponsorship().unwrap();
        
        // Verify gas is charged to sponsor
        assert_eq!(vm.gas_charged_to, sponsor);
        
        // Charge some gas
        vm.charge_gas(100).unwrap();
        
        // Verify balances
        let sponsor_account = vm.get_smart_account(&sponsor).unwrap();
        assert_eq!(sponsor_account.balance, 900); // 1000 - 100
        
        let sender_account = vm.get_smart_account(&sender).unwrap();
        assert_eq!(sender_account.balance, 100); // Unchanged
    }

    #[test]
    fn test_gas_sponsorship_limit() {
        let mut vm = KapraVM::new(KapraBytecode::new(), None, Some(1000));
        
        // Create accounts
        let sender = FixedArray([1; 32]);
        let sponsor = FixedArray([2; 32]);
        
        vm.create_smart_account(sender, 100).unwrap();
        vm.create_smart_account(sponsor, 1000).unwrap();
        
        // Set up sponsorship with limit less than gas limit
        let mut sender_account = vm.get_smart_account_mut(&sender).unwrap();
        sender_account.set_sponsor(sponsor, 500);
        
        // Set current sender and setup sponsorship
        vm.current_sender = Some(sender);
        vm.setup_gas_sponsorship().unwrap();
        
        // Verify gas is charged to sender (since limit < gas_limit)
        assert_eq!(vm.gas_charged_to, sender);
    }

    #[test]
    fn test_remove_sponsor() {
        let mut vm = KapraVM::new(KapraBytecode::new(), None, Some(1000));
        
        // Create accounts
        let sender = FixedArray([1; 32]);
        let sponsor = FixedArray([2; 32]);
        
        vm.create_smart_account(sender, 100).unwrap();
        vm.create_smart_account(sponsor, 1000).unwrap();
        
        // Set up sponsorship
        let mut sender_account = vm.get_smart_account_mut(&sender).unwrap();
        sender_account.set_sponsor(sponsor, 500);
        
        // Remove sponsor
        sender_account.remove_sponsor();
        
        // Set current sender and setup sponsorship
        vm.current_sender = Some(sender);
        vm.setup_gas_sponsorship().unwrap();
        
        // Verify gas is charged to sender (since no sponsor)
        assert_eq!(vm.gas_charged_to, sender);
    }

    #[test]
    fn test_atomic_batch_success() {
        let mut vm = KapraVM::new(KapraBytecode::new(), None, Some(10000));
        
        // Create test accounts
        let sender = FixedArray([1; 32]);
        let target1 = FixedArray([2; 32]);
        let target2 = FixedArray([3; 32]);
        
        vm.create_smart_account(sender, 1000).unwrap();
        
        // Create bytecode for two actions
        let mut action1_bytecode = KapraBytecode::new();
        action1_bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(0), Operand::Immediate(vec![42])],
            Some(Type::U32),
        ));
        
        let mut action2_bytecode = KapraBytecode::new();
        action2_bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(1), Operand::Immediate(vec![24])],
            Some(Type::U32),
        ));
        
        // Create transaction context
        let tx_context = TransactionContext {
            sender,
            actions: vec![
                TxAction {
                    to: target1,
                    data: action1_bytecode.to_bytes(),
                    gas: 5000,
                },
                TxAction {
                    to: target2,
                    data: action2_bytecode.to_bytes(),
                    gas: 3000,
                },
            ],
            sponsor: None,
            gas_limit: 10000,
            tx_id: 1,
        };
        
        // Execute batch
        let result = vm.run_transaction(tx_context);
        assert!(result.is_ok());
        
        // Verify both actions were executed
        assert_eq!(vm.registers[0], vec![42]);
        assert_eq!(vm.registers[1], vec![24]);
    }

    #[test]
    fn test_batch_failure_reverts_all() {
        let mut vm = KapraVM::new(KapraBytecode::new(), None, Some(10000));
        
        // Create test accounts
        let sender = FixedArray([1; 32]);
        let target1 = FixedArray([2; 32]);
        let target2 = FixedArray([3; 32]);
        
        vm.create_smart_account(sender, 1000).unwrap();
        
        // Create bytecode for two actions
        let mut action1_bytecode = KapraBytecode::new();
        action1_bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(0), Operand::Immediate(vec![42])],
            Some(Type::U32),
        ));
        
        let mut action2_bytecode = KapraBytecode::new();
        action2_bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Fail, // This will cause the second action to fail
            vec![],
            None,
        ));
        
        // Create transaction context
        let tx_context = TransactionContext {
            sender,
            actions: vec![
                TxAction {
                    to: target1,
                    data: action1_bytecode.to_bytes(),
                    gas: 5000,
                },
                TxAction {
                    to: target2,
                    data: action2_bytecode.to_bytes(),
                    gas: 3000,
                },
            ],
            sponsor: None,
            gas_limit: 10000,
            tx_id: 1,
        };
        
        // Execute batch
        let result = vm.run_transaction(tx_context);
        assert!(result.is_err());
        
        // Verify first action's state was reverted
        assert_eq!(vm.registers[0], vec![0]); // Should be back to initial state
    }

    #[test]
    fn test_batch_with_sponsor() {
        let mut vm = KapraVM::new(KapraBytecode::new(), None, Some(10000));
        
        // Create test accounts
        let sender = FixedArray([1; 32]);
        let sponsor = FixedArray([2; 32]);
        let target = FixedArray([3; 32]);
        
        vm.create_smart_account(sender, 100).unwrap();
        vm.create_smart_account(sponsor, 1000).unwrap();
        
        // Set up sponsorship
        let mut sender_account = vm.get_smart_account_mut(&sender).unwrap();
        sender_account.set_sponsor(sponsor, 5000);
        
        // Create bytecode for action
        let mut action_bytecode = KapraBytecode::new();
        action_bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(0), Operand::Immediate(vec![42])],
            Some(Type::U32),
        ));
        
        // Create transaction context
        let tx_context = TransactionContext {
            sender,
            actions: vec![
                TxAction {
                    to: target,
                    data: action_bytecode.to_bytes(),
                    gas: 3000,
                },
            ],
            sponsor: Some(sponsor),
            gas_limit: 5000,
            tx_id: 1,
        };
        
        // Execute batch
        let result = vm.run_transaction(tx_context);
        assert!(result.is_ok());
        
        // Verify gas was charged to sponsor
        let sponsor_account = vm.get_smart_account(&sponsor).unwrap();
        assert_eq!(sponsor_account.balance, 700); // 1000 - 300 gas
        
        let sender_account = vm.get_smart_account(&sender).unwrap();
        assert_eq!(sender_account.balance, 100); // Unchanged
    }

    #[test]
    fn test_transaction_id_generator() {
        let mut generator = TransactionIdGenerator::new();
        assert_eq!(generator.next(), 1);
        assert_eq!(generator.next(), 2);
        assert_eq!(generator.next(), 3);
    }

    #[test]
    fn test_transaction_with_logging() {
        let mut vm = KapraVM::new(KapraBytecode::new(), None, Some(10000));
        
        // Create test accounts
        let sender = FixedArray([1; 32]);
        let target1 = FixedArray([2; 32]);
        let target2 = FixedArray([3; 32]);
        
        vm.create_smart_account(sender, 1000).unwrap();
        
        // Create bytecode for two actions
        let mut action1_bytecode = KapraBytecode::new();
        action1_bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(0), Operand::Immediate(vec![42])],
            Some(Type::U32),
        ));
        
        let mut action2_bytecode = KapraBytecode::new();
        action2_bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(1), Operand::Immediate(vec![24])],
            Some(Type::U32),
        ));
        
        // Create transaction context
        let tx_context = TransactionContext {
            sender,
            actions: vec![
                TxAction {
                    to: target1,
                    data: action1_bytecode.to_bytes(),
                    gas: 5000,
                },
                TxAction {
                    to: target2,
                    data: action2_bytecode.to_bytes(),
                    gas: 3000,
                },
            ],
            sponsor: None,
            gas_limit: 10000,
            tx_id: 1,
        };
        
        // Execute batch with logging
        let results = vm.run_transaction_with_logging(tx_context).unwrap();
        
        // Verify results
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].to, target1);
        assert!(results[0].success);
        assert!(results[0].error.is_none());
        assert_eq!(results[1].to, target2);
        assert!(results[1].success);
        assert!(results[1].error.is_none());
    }

    #[test]
    fn test_dynamic_sponsorship() {
        let mut vm = KapraVM::new(KapraBytecode::new(), None, Some(10000));
        
        // Create test accounts
        let sender = FixedArray([1; 32]);
        let default_sponsor = FixedArray([2; 32]);
        let dynamic_sponsor = FixedArray([3; 32]);
        let target = FixedArray([4; 32]);
        
        vm.create_smart_account(sender, 100).unwrap();
        vm.create_smart_account(default_sponsor, 1000).unwrap();
        vm.create_smart_account(dynamic_sponsor, 2000).unwrap();
        
        // Set up default sponsorship
        let mut sender_account = vm.get_smart_account_mut(&sender).unwrap();
        sender_account.set_sponsor(default_sponsor, 5000);
        
        // Create bytecode for action
        let mut action_bytecode = KapraBytecode::new();
        action_bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(0), Operand::Immediate(vec![42])],
            Some(Type::U32),
        ));
        
        // Create transaction context with dynamic sponsor
        let tx_context = TransactionContext {
            sender,
            actions: vec![
                TxAction {
                    to: target,
                    data: action_bytecode.to_bytes(),
                    gas: 3000,
                },
            ],
            sponsor: Some(dynamic_sponsor), // Override default sponsor
            gas_limit: 5000,
            tx_id: 1,
        };
        
        // Execute batch
        let result = vm.run_transaction(tx_context);
        assert!(result.is_ok());
        
        // Verify gas was charged to dynamic sponsor
        let dynamic_sponsor_account = vm.get_smart_account(&dynamic_sponsor).unwrap();
        assert_eq!(dynamic_sponsor_account.balance, 1700); // 2000 - 300 gas
        
        let default_sponsor_account = vm.get_smart_account(&default_sponsor).unwrap();
        assert_eq!(default_sponsor_account.balance, 1000); // Unchanged
        
        let sender_account = vm.get_smart_account(&sender).unwrap();
        assert_eq!(sender_account.balance, 100); // Unchanged
    }

    #[test]
    fn test_postcondition_success() {
        let runtime = Arc::new(Runtime::new().unwrap());
        let mut vm = KapraVM::new(KapraBytecode::new(), Some(runtime.clone()), Some(1000));

        // Create test accounts
        let sender = FixedArray::from([1u8; 32]);
        let recipient = FixedArray::from([2u8; 32]);
        vm.create_smart_account(sender, 1000);
        vm.create_smart_account(recipient, 0);

        // Create bytecode that transfers 100 and sets a value
        let mut bytecode = KapraBytecode::new();
        bytecode.push(KapraOpCode::Push(100));
        bytecode.push(KapraOpCode::Store(0));
        bytecode.push(KapraOpCode::Push(100));
        bytecode.push(KapraOpCode::Transfer(recipient));

        // Create postcondition bytecode that verifies the transfer
        let mut postcode = KapraBytecode::new();
        postcode.push(KapraOpCode::Load(0));
        postcode.push(KapraOpCode::Push(100));
        postcode.push(KapraOpCode::Assert);

        vm.set_postconditions(postcode);

        let tx_context = TransactionContext {
            sender,
            actions: vec![TxAction {
                to: recipient,
                data: bytecode.to_bytes(),
                gas: 1000,
            }],
            sponsor: None,
            gas_limit: 1000,
            tx_id: 1,
        };

        let result = vm.run_transaction(tx_context);
        assert!(result.is_ok());

        // Verify the transfer happened
        let recipient_account = vm.get_smart_account(recipient).unwrap();
        assert_eq!(recipient_account.balance, 100);
    }

    #[test]
    fn test_postcondition_failure() {
        let runtime = Arc::new(Runtime::new().unwrap());
        let mut vm = KapraVM::new(KapraBytecode::new(), Some(runtime.clone()), Some(1000));

        // Create test accounts
        let sender = FixedArray::from([1u8; 32]);
        let recipient = FixedArray::from([2u8; 32]);
        vm.create_smart_account(sender, 1000);
        vm.create_smart_account(recipient, 0);

        // Create bytecode that transfers 100
        let mut bytecode = KapraBytecode::new();
        bytecode.push(KapraOpCode::Push(100));
        bytecode.push(KapraOpCode::Transfer(recipient));

        // Create postcondition bytecode that expects 200
        let mut postcode = KapraBytecode::new();
        postcode.push(KapraOpCode::Push(200));
        postcode.push(KapraOpCode::Assert);

        vm.set_postconditions(postcode);

        let tx_context = TransactionContext {
            sender,
            actions: vec![TxAction {
                to: recipient,
                data: bytecode.to_bytes(),
                gas: 1000,
            }],
            sponsor: None,
            gas_limit: 1000,
            tx_id: 1,
        };

        let result = vm.run_transaction(tx_context);
        assert!(result.is_err());

        // Verify the transfer was rolled back
        let recipient_account = vm.get_smart_account(recipient).unwrap();
        assert_eq!(recipient_account.balance, 0);
    }

    #[test]
    fn test_postcondition_in_batch() {
        let runtime = Arc::new(Runtime::new().unwrap());
        let mut vm = KapraVM::new(KapraBytecode::new(), Some(runtime.clone()), Some(1000));

        // Create test accounts
        let sender = FixedArray::from([1u8; 32]);
        let recipient1 = FixedArray::from([2u8; 32]);
        let recipient2 = FixedArray::from([3u8; 32]);
        vm.create_smart_account(sender, 1000);
        vm.create_smart_account(recipient1, 0);
        vm.create_smart_account(recipient2, 0);

        // Create bytecode for first action
        let mut bytecode1 = KapraBytecode::new();
        bytecode1.push(KapraOpCode::Push(100));
        bytecode1.push(KapraOpCode::Transfer(recipient1));

        // Create bytecode for second action
        let mut bytecode2 = KapraBytecode::new();
        bytecode2.push(KapraOpCode::Push(200));
        bytecode2.push(KapraOpCode::Transfer(recipient2));

        // Create postcondition bytecode that verifies both transfers
        let mut postcode = KapraBytecode::new();
        postcode.push(KapraOpCode::Push(100));
        postcode.push(KapraOpCode::Assert);
        postcode.push(KapraOpCode::Push(200));
        postcode.push(KapraOpCode::Assert);

        vm.set_postconditions(postcode);

        let tx_context = TransactionContext {
            sender,
            actions: vec![
                TxAction {
                    to: recipient1,
                    data: bytecode1.to_bytes(),
                    gas: 500,
                },
                TxAction {
                    to: recipient2,
                    data: bytecode2.to_bytes(),
                    gas: 500,
                },
            ],
            sponsor: None,
            gas_limit: 1000,
            tx_id: 1,
        };

        let result = vm.run_transaction(tx_context);
        assert!(result.is_ok());

        // Verify both transfers happened
        let recipient1_account = vm.get_smart_account(recipient1).unwrap();
        let recipient2_account = vm.get_smart_account(recipient2).unwrap();
        assert_eq!(recipient1_account.balance, 100);
        assert_eq!(recipient2_account.balance, 200);
    }

    #[test]
    fn test_sponsor_gas_on_failure() {
        let runtime = Arc::new(Runtime::new().unwrap());
        let mut vm = KapraVM::new(KapraBytecode::new(), Some(runtime.clone()), Some(1000));

        // Create test accounts
        let sender = FixedArray::from([1u8; 32]);
        let sponsor = FixedArray::from([2u8; 32]);
        let recipient = FixedArray::from([3u8; 32]);
        vm.create_smart_account(sender, 1000);
        vm.create_smart_account(sponsor, 2000);
        vm.create_smart_account(recipient, 0);

        // Set up sponsorship
        let sponsor_account = vm.get_smart_account_mut(&sender).unwrap();
        sponsor_account.set_sponsor(sponsor, 1000);

        // Create bytecode that transfers 100
        let mut bytecode = KapraBytecode::new();
        bytecode.push(KapraOpCode::Push(100));
        bytecode.push(KapraOpCode::Transfer(recipient));

        // Create postcondition bytecode that will fail
        let mut postcode = KapraBytecode::new();
        postcode.push(KapraOpCode::Push(200)); // Expect 200 but we only transferred 100
        postcode.push(KapraOpCode::Assert);

        vm.set_postconditions(postcode);

        let tx_context = TransactionContext {
            sender,
            actions: vec![TxAction {
                to: recipient,
                data: bytecode.to_bytes(),
                gas: 1000,
            }],
            sponsor: Some(sponsor),
            gas_limit: 1000,
            tx_id: 1,
        };

        let result = vm.run_transaction(tx_context);
        assert!(result.is_err());

        // Verify the transfer was rolled back
        let recipient_account = vm.get_smart_account(&recipient).unwrap();
        assert_eq!(recipient_account.balance, 0);

        // Verify gas was charged to sponsor even though transaction failed
        let sponsor_account = vm.get_smart_account(&sponsor).unwrap();
        assert_eq!(sponsor_account.balance, 1700); // 2000 - 300 gas
    }

    #[test]
    fn test_manual_verify_assert() {
        let runtime = Arc::new(Runtime::new().unwrap());
        let mut vm = KapraVM::new(KapraBytecode::new(), Some(runtime.clone()), Some(1000));

        // Create test accounts
        let sender = FixedArray::from([1u8; 32]);
        let recipient = FixedArray::from([2u8; 32]);
        vm.create_smart_account(sender, 1000);
        vm.create_smart_account(recipient, 0);

        // Create bytecode that uses Verify and Assert manually
        let mut bytecode = KapraBytecode::new();
        bytecode.push(KapraOpCode::Push(100));
        bytecode.push(KapraOpCode::Store(0)); // Store 100 in register 0
        bytecode.push(KapraOpCode::Verify); // Start verify block
        bytecode.push(KapraOpCode::Load(0)); // Load value from register 0
        bytecode.push(KapraOpCode::Push(100)); // Push expected value
        bytecode.push(KapraOpCode::Assert); // Assert they are equal
        bytecode.push(KapraOpCode::Push(100));
        bytecode.push(KapraOpCode::Transfer(recipient));

        let tx_context = TransactionContext {
            sender,
            actions: vec![TxAction {
                to: recipient,
                data: bytecode.to_bytes(),
                gas: 1000,
            }],
            sponsor: None,
            gas_limit: 1000,
            tx_id: 1,
        };

        let result = vm.run_transaction(tx_context);
        assert!(result.is_ok());

        // Verify the transfer happened
        let recipient_account = vm.get_smart_account(&recipient).unwrap();
        assert_eq!(recipient_account.balance, 100);
    }

    #[test]
    fn test_contract_deployment() {
        let mut vm = KapraVM::new(KapraBytecode::new(), None, Some(1000));
        
        // Create test account
        let sender = FixedArray([1; 32]);
        vm.create_smart_account(sender, 1000).unwrap();
        vm.current_sender = Some(sender);

        // Create test bytecode
        let mut bytecode = KapraBytecode::new();
        bytecode.push(KapraOpCode::Push(42));
        bytecode.push(KapraOpCode::Halt);

        // Deploy contract
        let contract_id = vm.deploy_contract(
            bytecode.clone(),
            sender,
            "Initial deployment".to_string(),
        ).unwrap();

        // Verify metadata
        let metadata = vm.get_contract_metadata(contract_id).unwrap();
        assert_eq!(metadata.version, 1);
        assert_eq!(metadata.upgrade_key, sender);
        assert!(!metadata.deprecated);
        assert!(metadata.upgrade_guardians.is_empty());

        // Verify bytecode is stored
        assert!(vm.contract_bytecode.contains_key(&contract_id));
    }

    #[test]
    fn test_contract_upgrade() {
        let mut vm = KapraVM::new(KapraBytecode::new(), None, Some(1000));
        
        // Create test accounts
        let sender = FixedArray([1; 32]);
        let guardian = FixedArray([2; 32]);
        vm.create_smart_account(sender, 1000).unwrap();
        vm.create_smart_account(guardian, 1000).unwrap();
        vm.current_sender = Some(sender);

        // Deploy initial contract
        let mut bytecode = KapraBytecode::new();
        bytecode.push(KapraOpCode::Push(42));
        bytecode.push(KapraOpCode::Halt);

        let contract_id = vm.deploy_contract(
            bytecode.clone(),
            sender,
            "Initial deployment".to_string(),
        ).unwrap();

        // Add guardian
        vm.add_upgrade_guardian(contract_id, guardian).unwrap();

        // Upgrade as guardian
        vm.current_sender = Some(guardian);
        let mut new_bytecode = KapraBytecode::new();
        new_bytecode.push(KapraOpCode::Push(43));
        new_bytecode.push(KapraOpCode::Halt);

        vm.upgrade_contract(
            contract_id,
            new_bytecode.clone(),
            2,
            "Upgrade to v2".to_string(),
        ).unwrap();

        // Verify metadata
        let metadata = vm.get_contract_metadata(contract_id).unwrap();
        assert_eq!(metadata.version, 2);
        assert_eq!(metadata.upgrade_key, sender);
        assert!(!metadata.deprecated);
        assert!(metadata.upgrade_guardians.contains(&guardian));

        // Verify new bytecode is stored
        assert_eq!(vm.contract_bytecode.get(&contract_id).unwrap(), &new_bytecode);
    }

    #[test]
    fn test_unauthorized_upgrade() {
        let mut vm = KapraVM::new(KapraBytecode::new(), None, Some(1000));
        
        // Create test accounts
        let sender = FixedArray([1; 32]);
        let unauthorized = FixedArray([2; 32]);
        vm.create_smart_account(sender, 1000).unwrap();
        vm.create_smart_account(unauthorized, 1000).unwrap();
        vm.current_sender = Some(sender);

        // Deploy contract
        let mut bytecode = KapraBytecode::new();
        bytecode.push(KapraOpCode::Push(42));
        bytecode.push(KapraOpCode::Halt);

        let contract_id = vm.deploy_contract(
            bytecode.clone(),
            sender,
            "Initial deployment".to_string(),
        ).unwrap();

        // Try to upgrade as unauthorized user
        vm.current_sender = Some(unauthorized);
        let mut new_bytecode = KapraBytecode::new();
        new_bytecode.push(KapraOpCode::Push(43));
        new_bytecode.push(KapraOpCode::Halt);

        let result = vm.upgrade_contract(
            contract_id,
            new_bytecode,
            2,
            "Unauthorized upgrade".to_string(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_downgrade_prevention() {
        let mut vm = KapraVM::new(KapraBytecode::new(), None, Some(1000));
        
        // Create test account
        let sender = FixedArray([1; 32]);
        vm.create_smart_account(sender, 1000).unwrap();
        vm.current_sender = Some(sender);

        // Deploy contract
        let mut bytecode = KapraBytecode::new();
        bytecode.push(KapraOpCode::Push(42));
        bytecode.push(KapraOpCode::Halt);

        let contract_id = vm.deploy_contract(
            bytecode.clone(),
            sender,
            "Initial deployment".to_string(),
        ).unwrap();

        // Try to upgrade to same version
        let result = vm.upgrade_contract(
            contract_id,
            bytecode,
            1,
            "Same version upgrade".to_string(),
        );
        assert!(result.is_err());

        // Try to upgrade to lower version
        let mut new_bytecode = KapraBytecode::new();
        new_bytecode.push(KapraOpCode::Push(43));
        new_bytecode.push(KapraOpCode::Halt);

        let result = vm.upgrade_contract(
            contract_id,
            new_bytecode,
            0,
            "Downgrade attempt".to_string(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_contract_deprecation() {
        let mut vm = KapraVM::new(KapraBytecode::new(), None, Some(1000));
        
        // Create test accounts
        let sender = FixedArray([1; 32]);
        let unauthorized = FixedArray([2; 32]);
        vm.create_smart_account(sender, 1000).unwrap();
        vm.create_smart_account(unauthorized, 1000).unwrap();
        vm.current_sender = Some(sender);

        // Deploy contract
        let mut bytecode = KapraBytecode::new();
        bytecode.push(KapraOpCode::Push(42));
        bytecode.push(KapraOpCode::Halt);

        let contract_id = vm.deploy_contract(
            bytecode.clone(),
            sender,
            "Initial deployment".to_string(),
        ).unwrap();

        // Deprecate contract
        vm.deprecate_contract(contract_id).unwrap();

        // Verify metadata
        let metadata = vm.get_contract_metadata(contract_id).unwrap();
        assert!(metadata.deprecated);

        // Try to deprecate as unauthorized user
        vm.current_sender = Some(unauthorized);
        let result = vm.deprecate_contract(contract_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_guardian_management() {
        let mut vm = KapraVM::new(KapraBytecode::new(), None, Some(1000));
        
        // Create test accounts
        let sender = FixedArray([1; 32]);
        let guardian = FixedArray([2; 32]);
        let unauthorized = FixedArray([3; 32]);
        vm.create_smart_account(sender, 1000).unwrap();
        vm.create_smart_account(guardian, 1000).unwrap();
        vm.create_smart_account(unauthorized, 1000).unwrap();
        vm.current_sender = Some(sender);

        // Deploy contract
        let mut bytecode = KapraBytecode::new();
        bytecode.push(KapraOpCode::Push(42));
        bytecode.push(KapraOpCode::Halt);

        let contract_id = vm.deploy_contract(
            bytecode.clone(),
            sender,
            "Initial deployment".to_string(),
        ).unwrap();

        // Add guardian
        vm.add_upgrade_guardian(contract_id, guardian).unwrap();

        // Verify guardian was added
        let metadata = vm.get_contract_metadata(contract_id).unwrap();
        assert!(metadata.upgrade_guardians.contains(&guardian));

        // Try to add guardian as unauthorized user
        vm.current_sender = Some(unauthorized);
        let result = vm.add_upgrade_guardian(contract_id, unauthorized);
        assert!(result.is_err());

        // Remove guardian as authorized user
        vm.current_sender = Some(sender);
        vm.remove_upgrade_guardian(contract_id, guardian).unwrap();

        // Verify guardian was removed
        let metadata = vm.get_contract_metadata(contract_id).unwrap();
        assert!(!metadata.upgrade_guardians.contains(&guardian));
    }
}
