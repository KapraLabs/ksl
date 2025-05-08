// kapra_vm.rs
// Implements KapraVM 2.0 to execute KapraBytecode 2.0 for KSL programs.

use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
use crate::ksl_types::Type;
use crate::ksl_kapra_crypto::{KapraCrypto, FixedArray};
use crate::ksl_hot_reload::HotReloadState;
use crate::ksl_coverage::CoverageData;
use crate::ksl_metrics::MetricsData;
use crate::ksl_simulator::SimulationData;
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
        }
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
                if self.metrics_data.is_some() {
                    ksl_metrics::MetricsCollector::increment_counter("arithmetic_ops");
                }
            }
            KapraOpCode::Sub => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let a = self.get_u32(&instr.operands[1], self.pc)?;
                let b = self.get_u32(&instr.operands[2], self.pc)?;
                self.registers[dst as usize] = (a - b).to_le_bytes().to_vec();
                if self.metrics_data.is_some() {
                    ksl_metrics::MetricsCollector::increment_counter("arithmetic_ops");
                }
            }
            KapraOpCode::Mul => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let a = self.get_u32(&instr.operands[1], self.pc)?;
                let b = self.get_u32(&instr.operands[2], self.pc)?;
                self.registers[dst as usize] = (a * b).to_le_bytes().to_vec();
                if self.metrics_data.is_some() {
                    ksl_metrics::MetricsCollector::increment_counter("arithmetic_ops");
                }
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
                if self.metrics_data.is_some() {
                    ksl_metrics::MetricsCollector::increment_counter("function_calls");
                }
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
                if self.metrics_data.is_some() {
                    ksl_metrics::MetricsCollector::increment_counter("crypto_ops");
                }
            }
            KapraOpCode::Sha3_512 => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let src = self.get_operand_value(&instr.operands[1], instr.type_info.as_ref(), self.pc)?;
                let mut hasher = Sha3_512::new();
                hasher.update(&src);
                let result = hasher.finalize();
                self.registers[dst as usize] = result.to_vec();
                if self.metrics_data.is_some() {
                    ksl_metrics::MetricsCollector::increment_counter("crypto_ops");
                }
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
                if self.metrics_data.is_some() {
                    ksl_metrics::MetricsCollector::increment_counter("crypto_ops");
                }
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
                if self.metrics_data.is_some() {
                    ksl_metrics::MetricsCollector::increment_counter("crypto_ops");
                }
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
                if self.metrics_data.is_some() {
                    ksl_metrics::MetricsCollector::increment_counter("crypto_ops");
                }
            }
            KapraOpCode::MerkleVerify => {
                // Placeholder: ksl_kapra_crypto.rs lacks merkle_verify
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let _root = self.get_operand_value(&instr.operands[1], Some(&Type::Array(Box::new(Type::U8), 32)), self.pc)?;
                let _proof = self.get_operand_value(&instr.operands[2], Some(&Type::Array(Box::new(Type::U8), 0)), self.pc)?;
                self.registers[dst as usize] = 1u32.to_le_bytes().to_vec(); // Always true
                if self.metrics_data.is_some() {
                    ksl_metrics::MetricsCollector::increment_counter("crypto_ops");
                }
                // Log warning
                if self.metrics_data.is_some() {
                    ksl_metrics::MetricsCollector::increment_counter("merkle_verify_placeholder_used");
                }
            }
            KapraOpCode::AsyncCall => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let func_index = self.get_u32(&instr.operands[1], self.pc)? as u32;
                self.pending_async.push((dst, func_index));
                // Simulate async result (e.g., for fetch)
                let result = vec![b'r', b'e', b's', b'u', b'l', b't']; // Dummy "result" string
                self.registers[dst as usize] = result;
                if self.metrics_data.is_some() {
                    ksl_metrics::MetricsCollector::increment_counter("async_calls");
                }
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
                let msg = self.get_string(&instr.operands[1], self.pc)?;
                println!("{}", msg);
                self.registers[self.get_register(&instr.operands[0], self.pc)? as usize] = Vec::new();
            }
            KapraOpCode::Assert => {
                let cond = self.get_register(&instr.operands[0], self.pc)?;
                let value = u32::from_le_bytes(
                    self.registers[cond as usize]
                        .as_slice()
                        .try_into()
                        .map_err(|_| RuntimeError {
                            message: "Invalid condition value".to_string(),
                            pc: self.pc,
                        })?
                );
                
                if value == 0 {
                    return Err(RuntimeError {
                        message: "Assertion failed".to_string(),
                        pc: self.pc,
                    });
                }

                if self.metrics_data.is_some() {
                    ksl_metrics::MetricsCollector::increment_counter("assertions");
                }
            }
            KapraOpCode::Auth => {
                let delegatee = self.get_operand_value(&instr.operands[0], Some(&Type::Array(Box::new(Type::U8), 32)), self.pc)?;
                let delegatee: [u8; 32] = delegatee.try_into().map_err(|_| RuntimeError {
                    message: "Invalid delegatee address".to_string(),
                    pc: self.pc,
                })?;

                let delegator = self.current_sender.ok_or_else(|| RuntimeError {
                    message: "No current sender for delegation".to_string(),
                    pc: self.pc,
                })?;

                self.auth_stack.push(DelegatedContext {
                    delegator,
                    delegatee: FixedArray(delegatee),
                    expires_at: self.tx_context.tx_id, // Use tx_id as expiration
                });

                if self.metrics_data.is_some() {
                    ksl_metrics::MetricsCollector::increment_counter("auth_delegations");
                }
            }
            KapraOpCode::AuthCall => {
                let target = self.get_operand_value(&instr.operands[0], Some(&Type::Array(Box::new(Type::U8), 32)), self.pc)?;
                let target: [u8; 32] = target.try_into().map_err(|_| RuntimeError {
                    message: "Invalid target address".to_string(),
                    pc: self.pc,
                })?;

                let delegate = self.auth_stack.last().ok_or_else(|| RuntimeError {
                    message: "No delegated context for auth call".to_string(),
                    pc: self.pc,
                })?;

                // Save current sender
                let saved_sender = self.current_sender;
                
                // Set delegated sender
                self.current_sender = Some(delegate.delegatee);

                // Execute the call
                let result = self.execute_contract(FixedArray(target));

                // Restore original sender
                self.current_sender = saved_sender;

                result?;

                if self.metrics_data.is_some() {
                    ksl_metrics::MetricsCollector::increment_counter("auth_calls");
                }
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
        fs::create_dir_all(&state_dir).map_err(|e| KslError::runtime_error(
            format!("Failed to create state directory: {}", e),
            None,
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
        let bytes = serialize(&state).map_err(|e| KslError::runtime_error(
            format!("Failed to serialize contract state: {}", e),
            None,
        ))?;

        // Write to file
        let file_path = state_dir.join(format!("{}.bin", name));
        fs::write(&file_path, bytes).map_err(|e| KslError::runtime_error(
            format!("Failed to write contract state: {}", e),
            None,
        ))?;

        Ok(())
    }

    /// Restores contract state from a file
    pub fn restore_contract_state(&mut self, name: &str) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        
        // Read state file
        let file_path = PathBuf::from("./state").join(format!("{}.bin", name));
        let bytes = fs::read(&file_path).map_err(|e| KslError::runtime_error(
            format!("Failed to read contract state: {}", e),
            None,
        ))?;

        // Deserialize state
        let state: ContractState = deserialize(&bytes).map_err(|e| KslError::runtime_error(
            format!("Failed to deserialize contract state: {}", e),
            None,
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
}
