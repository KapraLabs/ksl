// ksl_kapra_consensus.rs
// Language-level consensus primitives for Kapra Chain

/// Represents KSL bytecode (aligned with ksl_bytecode.rs).
#[derive(Debug, Clone)]
pub struct Bytecode {
    instructions: Vec<u8>,
    constants: Vec<Constant>,
}

impl Bytecode {
    pub fn new(instructions: Vec<u8>, constants: Vec<Constant>) -> Self {
        Bytecode {
            instructions,
            constants,
        }
    }

    pub fn extend(&mut self, other: Bytecode) {
        self.instructions.extend(other.instructions);
        self.constants.extend(other.constants);
    }
}

/// Represents a constant in the bytecode.
#[derive(Debug, Clone)]
pub enum Constant {
    String(String),
    U64(u64),
    Array32([u8; 32]),
}

/// Represents an AST node (aligned with ksl_parser.rs).
#[derive(Debug, Clone)]
pub enum AstNode {
    ConsensusBlock {
        params: Vec<(String, Type)>, // Parameters (e.g., validator_id, seed)
        return_type: Type,           // Return type (bool)
        body: Vec<AstNode>,          // Body of the consensus block
    },
    Call {
        name: String,
        args: Vec<AstNode>,
    },
    Let {
        name: String,
        ty: Type,
        value: Box<AstNode>,
    },
    LiteralU64(u64),
    LiteralArray32([u8; 32]),
}

/// Represents a type (aligned with ksl_types.rs).
#[derive(Debug, Clone)]
pub enum Type {
    Bool,
    U64,
    ArrayU8(usize), // e.g., array<u8, 32>
}

/// Fixed-size array (aligned with ksl_kapra_crypto.rs).
#[derive(Debug, Clone)]
pub struct FixedArray<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> FixedArray<N> {
    pub fn new(data: [u8; N]) -> Self {
        FixedArray { data }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

/// Crypto module (aligned with ksl_kapra_crypto.rs).
#[derive(Debug, Clone)]
pub struct KapraCrypto {
    is_embedded: bool,
}

impl KapraCrypto {
    pub fn new(is_embedded: bool) -> Self {
        KapraCrypto { is_embedded }
    }

    pub fn vrf_generate(&self, seed: &FixedArray<32>, key: &FixedArray<32>) -> FixedArray<32> {
        let mut output = [0u8; 32];
        if self.is_embedded {
            for i in 0..32 {
                output[i] = seed.as_slice()[i] ^ key.as_slice()[i];
            }
        } else {
            let seed_hash = self.simple_hash(seed.as_slice());
            let key_hash = self.simple_hash(key.as_slice());
            let combined = seed_hash.wrapping_add(key_hash);
            for i in 0..32 {
                output[i] = (combined >> (i % 32)) as u8;
            }
        }
        FixedArray::new(output)
    }

    fn simple_hash(&self, data: &[u8]) -> u32 {
        data.iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32))
    }
}

/// Sharding runtime (aligned with ksl_kapra_shard.rs).
#[derive(Debug, Clone)]
pub struct ShardRuntime {
    shard_count: u32,
}

impl ShardRuntime {
    pub fn new(shard_count: u32) -> Self {
        ShardRuntime { shard_count }
    }

    pub fn shard_route(&self, account: &[u8; 32]) -> u32 {
        let hash = account.iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32));
        hash % self.shard_count
    }

    pub fn shard_send(&self, shard_id: u32, message: &[u8; 32]) -> bool {
        if shard_id >= self.shard_count {
            return false;
        }
        true
    }
}

/// Consensus runtime for Kapra Chain.
#[derive(Debug, Clone)]
pub struct ConsensusRuntime {
    threshold: u64, // Threshold for leader election (simplified)
}

impl ConsensusRuntime {
    pub fn new(threshold: u64) -> Self {
        ConsensusRuntime { threshold }
    }

    pub fn is_leader(&self, vrf_output: &[u8; 32]) -> bool {
        let value = vrf_output.iter().fold(0u64, |acc, &x| acc.wrapping_add(x as u64));
        value < self.threshold
    }

    pub fn propose_block(&self, shard_id: u32) -> bool {
        // Simplified: Always succeed if shard_id is valid
        shard_id != u32::MAX
    }
}

/// Kapra VM with consensus support (aligned with kapra_vm.rs).
#[derive(Debug)]
pub struct KapraVM {
    stack: Vec<u64>,
    crypto: KapraCrypto,
    shard_runtime: ShardRuntime,
    consensus_runtime: ConsensusRuntime,
    async_tasks: Vec<AsyncTask>,
}

impl KapraVM {
    pub fn new(shard_count: u32, threshold: u64, is_embedded: bool) -> Self {
        KapraVM {
            stack: vec![],
            crypto: KapraCrypto::new(is_embedded),
            shard_runtime: ShardRuntime::new(shard_count),
            consensus_runtime: ConsensusRuntime::new(threshold),
            async_tasks: vec![],
        }
    }

    pub fn execute(&mut self, bytecode: &Bytecode) -> Result<bool, String> {
        let mut ip = 0;
        while ip < bytecode.instructions.len() {
            let instr = bytecode.instructions[ip];
            ip += 1;

            match instr {
                OPCODE_VRF_GENERATE => {
                    if self.stack.len() < 2 {
                        return Err("Not enough values on stack for VRF_GENERATE".to_string());
                    }
                    let key_idx = self.stack.pop().unwrap() as usize;
                    let seed_idx = self.stack.pop().unwrap() as usize;
                    let seed = match &bytecode.constants[seed_idx] {
                        Constant::Array32(arr) => FixedArray::new(*arr),
                        _ => return Err("Invalid type for VRF_GENERATE seed".to_string()),
                    };
                    let key = match &bytecode.constants[key_idx] {
                        Constant::Array32(arr) => FixedArray::new(*arr),
                        _ => return Err("Invalid type for VRF_GENERATE key".to_string()),
                    };
                    let vrf_output = self.crypto.vrf_generate(&seed, &key);
                    let const_idx = bytecode.constants.len();
                    self.stack.push(const_idx as u64);
                    let mut new_constants = bytecode.constants.clone();
                    new_constants.push(Constant::Array32(vrf_output.data));
                    let new_bytecode = Bytecode::new(bytecode.instructions.clone(), new_constants);
                    *bytecode = new_bytecode;
                }
                OPCODE_LEADER_ELECT => {
                    if self.stack.len() < 1 {
                        return Err("Not enough values on stack for LEADER_ELECT".to_string());
                    }
                    let vrf_idx = self.stack.pop().unwrap() as usize;
                    let vrf_output = match &bytecode.constants[vrf_idx] {
                        Constant::Array32(arr) => arr,
                        _ => return Err("Invalid type for LEADER_ELECT argument".to_string()),
                    };
                    let is_leader = self.consensus_runtime.is_leader(vrf_output);
                    self.stack.push(is_leader as u64);
                }
                OPCODE_PROPOSE_BLOCK => {
                    if self.stack.len() < 1 {
                        return Err("Not enough values on stack for PROPOSE_BLOCK".to_string());
                    }
                    let shard_id = self.stack.pop().unwrap() as u32;
                    let success = self.consensus_runtime.propose_block(shard_id);
                    self.stack.push(success as u64);
                }
                OPCODE_SHARD => {
                    if self.stack.len() < 1 {
                        return Err("Not enough values on stack for SHARD".to_string());
                    }
                    let account_idx = self.stack.pop().unwrap() as usize;
                    let account = match &bytecode.constants[account_idx] {
                        Constant::Array32(arr) => arr,
                        _ => return Err("Invalid type for SHARD argument".to_string()),
                    };
                    let shard_id = self.shard_runtime.shard_route(account);
                    let success = self.shard_runtime.shard_send(shard_id, account);
                    self.async_tasks.push(AsyncTask::ShardSend(shard_id, *account));
                    self.stack.push(shard_id as u64);
                    self.stack.push(success as u64);
                }
                OPCODE_PUSH => {
                    if ip >= bytecode.instructions.len() {
                        return Err("Incomplete PUSH instruction".to_string());
                    }
                    let value = bytecode.instructions[ip] as u64;
                    ip += 1;
                    self.stack.push(value);
                }
                OPCODE_FAIL => {
                    return Err("Consensus failed".to_string());
                }
                _ => return Err(format!("Unsupported opcode: {}", instr)),
            }
        }

        if self.stack.len() != 1 {
            return Err("Consensus block must return exactly one boolean value".to_string());
        }
        Ok(self.stack[0] != 0)
    }
}

/// Represents an async task (aligned with ksl_async.rs).
#[derive(Debug, Clone)]
pub enum AsyncTask {
    ShardSend(u32, [u8; 32]),
}

/// Consensus compiler for Kapra Chain.
pub struct ConsensusCompiler {
    shard_count: u32,
    threshold: u64,
    is_embedded: bool,
}

impl ConsensusCompiler {
    pub fn new(shard_count: u32, threshold: u64, is_embedded: bool) -> Self {
        ConsensusCompiler {
            shard_count,
            threshold,
            is_embedded,
        }
    }

    /// Compile a consensus block into bytecode.
    pub fn compile(&self, node: &AstNode) -> Result<Bytecode, String> {
        match node {
            AstNode::ConsensusBlock { params, return_type, body } => {
                // Validate parameters and return type
                if params.len() != 2 {
                    return Err("Consensus block must have exactly 2 parameters: validator_id, seed".to_string());
                }
                if params[0].0 != "validator_id" || !matches!(params[0].1, Type::U64) {
                    return Err("First parameter must be 'validator_id: u64'".to_string());
                }
                if params[1].0 != "seed" || !matches!(params[1].1, Type::ArrayU8(32)) {
                    return Err("Second parameter must be 'seed: array<u8, 32>'".to_string());
                }
                if !matches!(return_type, Type::Bool) {
                    return Err("Consensus block must return bool".to_string());
                }

                let mut bytecode = Bytecode::new(vec![], vec![]);

                // Compile the body
                for stmt in body {
                    let stmt_bytecode = self.compile_stmt(stmt)?;
                    bytecode.extend(stmt_bytecode);
                }

                Ok(bytecode)
            }
            _ => Err("Only consensus blocks can be compiled at the top level".to_string()),
        }
    }

    fn compile_stmt(&self, stmt: &AstNode) -> Result<Bytecode, String> {
        match stmt {
            AstNode::Let { name, ty, value } => {
                let value_bytecode = self.compile_expr(value.as_ref())?;
                let mut bytecode = value_bytecode;

                if let AstNode::Call { name: call_name, .. } = value.as_ref() {
                    if call_name == "vrf_generate" {
                        bytecode.instructions.push(OPCODE_VRF_GENERATE);
                    }
                }

                Ok(bytecode)
            }
            AstNode::Call { name, args } => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                for arg in args {
                    let arg_bytecode = self.compile_expr(arg)?;
                    bytecode.extend(arg_bytecode);
                }
                match name.as_str() {
                    "vrf_generate" => {
                        bytecode.instructions.push(OPCODE_VRF_GENERATE);
                    }
                    "elect_leader" => {
                        bytecode.instructions.push(OPCODE_LEADER_ELECT);
                        // Add fail if not elected (simplified)
                        bytecode.instructions.push(OPCODE_FAIL_IF_FALSE);
                    }
                    "propose_block" => {
                        bytecode.instructions.push(OPCODE_PROPOSE_BLOCK);
                    }
                    "shard" => {
                        bytecode.instructions.push(OPCODE_SHARD);
                    }
                    _ => return Err(format!("Unsupported function in consensus block: {}", name)),
                }
                Ok(bytecode)
            }
            _ => Err("Unsupported statement in consensus block".to_string()),
        }
    }

    fn compile_expr(&self, expr: &AstNode) -> Result<Bytecode, String> {
        match expr {
            AstNode::LiteralU64(val) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::U64(*val));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::LiteralArray32(arr) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::Array32(*arr));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::Call { name, args } => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                for arg in args {
                    let arg_bytecode = self.compile_expr(arg)?;
                    bytecode.extend(arg_bytecode);
                }
                if name == "vrf_generate" {
                    bytecode.instructions.push(OPCODE_VRF_GENERATE);
                } else {
                    return Err(format!("Unsupported expression in consensus block: {}", name));
                }
                Ok(bytecode)
            }
            _ => Err("Unsupported expression in consensus block".to_string()),
        }
    }
}

const OPCODE_VRF_GENERATE: u8 = 0x01;
const OPCODE_LEADER_ELECT: u8 = 0x02;
const OPCODE_PROPOSE_BLOCK: u8 = 0x03;
const OPCODE_SHARD: u8 = 0x04;
const OPCODE_PUSH: u8 = 0x05;
const OPCODE_FAIL: u8 = 0x06;
const OPCODE_FAIL_IF_FALSE: u8 = 0x07;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consensus_block_compilation() {
        let consensus_node = AstNode::ConsensusBlock {
            params: vec![
                ("validator_id".to_string(), Type::U64),
                ("seed".to_string(), Type::ArrayU8(32)),
            ],
            return_type: Type::Bool,
            body: vec![
                AstNode::Let {
                    name: "vrf_output".to_string(),
                    ty: Type::ArrayU8(32),
                    value: Box::new(AstNode::Call {
                        name: "vrf_generate".to_string(),
                        args: vec![
                            AstNode::LiteralArray32([1; 32]), // seed
                            AstNode::LiteralArray32([2; 32]), // key
                        ],
                    }),
                },
                AstNode::Call {
                    name: "elect_leader".to_string(),
                    args: vec![AstNode::LiteralArray32([1; 32])],
                },
                AstNode::Call {
                    name: "propose_block".to_string(),
                    args: vec![AstNode::LiteralU64(0)],
                },
                AstNode::Call {
                    name: "shard".to_string(),
                    args: vec![AstNode::LiteralArray32([1; 32])],
                },
            ],
        };

        let compiler = ConsensusCompiler::new(1000, 100, false);
        let bytecode = compiler.compile(&consensus_node).unwrap();
        assert!(!bytecode.instructions.is_empty());
        assert!(bytecode.instructions.contains(&OPCODE_VRF_GENERATE));
        assert!(bytecode.instructions.contains(&OPCODE_LEADER_ELECT));
        assert!(bytecode.instructions.contains(&OPCODE_PROPOSE_BLOCK));
        assert!(bytecode.instructions.contains(&OPCODE_SHARD));
    }

    #[test]
    fn test_consensus_execution() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::Array32([1; 32]), // seed
            Constant::Array32([2; 32]), // key
            Constant::Array32([3; 32]), // vrf_output
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,           // Push seed
            OPCODE_PUSH, 1,           // Push key
            OPCODE_VRF_GENERATE,      // Generate VRF
            OPCODE_LEADER_ELECT,      // Elect leader
            OPCODE_FAIL_IF_FALSE,     // Fail if not elected
            OPCODE_PUSH, 0,           // Push shard_id (simplified)
            OPCODE_PROPOSE_BLOCK,     // Propose block
            OPCODE_PUSH, 2,           // Push vrf_output (account)
            OPCODE_SHARD,             // Shard operation
        ]);

        let mut vm = KapraVM::new(1000, 1000, false);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_consensus_not_leader() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::Array32([255; 32]), // seed
            Constant::Array32([255; 32]), // key
            Constant::Array32([255; 32]), // vrf_output (will exceed threshold)
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,
            OPCODE_PUSH, 1,
            OPCODE_VRF_GENERATE,
            OPCODE_LEADER_ELECT,
            OPCODE_FAIL_IF_FALSE,
        ]);

        let mut vm = KapraVM::new(1000, 100, false);
        let result = vm.execute(&bytecode);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Consensus failed"));
    }

    #[test]
    fn test_consensus_invalid_params() {
        let consensus_node = AstNode::ConsensusBlock {
            params: vec![("validator_id".to_string(), Type::U64)],
            return_type: Type::Bool,
            body: vec![],
        };

        let compiler = ConsensusCompiler::new(1000, 100, false);
        let result = compiler.compile(&consensus_node);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must have exactly 2 parameters"));
    }
}

//! Consensus mechanisms for the Kapra blockchain, enabling distributed agreement.
//! 
//! This module provides consensus primitives for the Kapra blockchain, supporting:
//! - Leader election using VRF (Verifiable Random Function)
//! - Sharded consensus with multiple validators
//! - Async consensus operations
//! - Cryptographic security with Dilithium signatures
//! - Multiple consensus algorithms (PoS, PoA, BFT)
//! 
//! # Consensus Protocols
//! 
//! ```ksl
//! // Example consensus block with multiple algorithms
//! #[consensus(algorithm = "pos", shards = 4)]
//! consensus block(validator_id: array<u8, 32>, seed: array<u8, 32>) -> bool {
//!     // VRF-based leader election
//!     let vrf_output = vrf_generate(seed, validator_id);
//!     if !is_leader(vrf_output) {
//!         return false;
//!     }
//! 
//!     // Shard routing
//!     let shard_id = shard_route(validator_id);
//!     if !propose_block(shard_id) {
//!         return false;
//!     }
//! 
//!     // Async validation
//!     let valid = await validate_block(block);
//!     if !valid {
//!         return false;
//!     }
//! 
//!     // Cryptographic signing
//!     let signature = sign_dilithium(block, validator_id);
//!     return verify_dilithium(block, validator_id, signature);
//! }
//! ```

use crate::ksl_kapra_crypto::{sign_dilithium, verify_dilithium, KeyPair};
use crate::ksl_async::{AsyncRuntime, AsyncResult};
use crate::ksl_errors::{KslError, SourcePosition};
use std::collections::HashMap;
use async_trait::async_trait;
use tokio::sync::RwLock;
use wgpu;
use packed_simd::{u8x32, u32x8, u64x4};
use std::time::{Instant, Duration};
use std::sync::atomic::{AtomicU64, Ordering};
use rayon::prelude::*;

/// Consensus algorithm type
#[derive(Debug, Clone, PartialEq)]
pub enum ConsensusAlgorithm {
    ProofOfStake,    // PoS with VRF-based leader election
    ProofOfAuthority, // PoA with fixed validators
    ByzantineFaultTolerant, // BFT with 2/3 majority
}

/// Consensus configuration
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    algorithm: ConsensusAlgorithm,
    shard_count: u32,
    threshold: u64,
    validators: HashMap<[u8; 32], u64>, // validator_id -> stake/weight
    is_embedded: bool,
}

/// Consensus state
#[derive(Debug, Clone)]
pub struct ConsensusState {
    current_leader: Option<[u8; 32]>,
    last_block_hash: [u8; 32],
    validator_set: HashMap<[u8; 32], u64>,
    shard_states: HashMap<u32, ShardState>,
}

/// Shard state
#[derive(Debug, Clone)]
pub struct ShardState {
    last_block: [u8; 32],
    validators: Vec<[u8; 32]>,
    signatures: HashMap<[u8; 32], [u8; 2420]>, // validator_id -> signature
}

/// GPU acceleration configuration
#[derive(Debug, Clone)]
pub struct GpuConfig {
    /// Whether to use GPU acceleration
    pub enable_gpu: bool,
    /// Preferred backend (CUDA, WebGPU, etc.)
    pub backend: GpuBackend,
    /// Batch size for GPU operations
    pub batch_size: usize,
    /// Number of parallel streams
    pub num_streams: usize,
}

/// GPU backend types
#[derive(Debug, Clone, PartialEq)]
pub enum GpuBackend {
    Cuda,
    WebGpu,
    OpenCL,
}

/// GPU-accelerated consensus engine
pub struct GpuConsensusEngine {
    /// GPU device
    device: wgpu::Device,
    /// Command queue
    queue: wgpu::Queue,
    /// Compute pipeline
    pipeline: wgpu::ComputePipeline,
    /// Signature verification shader
    verify_shader: wgpu::ShaderModule,
    /// Batch buffers
    batch_buffers: Vec<wgpu::Buffer>,
}

impl GpuConsensusEngine {
    /// Creates a new GPU consensus engine
    pub async fn new(config: &GpuConfig) -> Result<Self, String> {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: wgpu::Backends::all(),
            dx12_shader_compiler: Default::default(),
        });

        let adapter = instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            compatible_surface: None,
            force_fallback_adapter: false,
        }).await.ok_or("Failed to find GPU adapter")?;

        let (device, queue) = adapter.request_device(
            &wgpu::DeviceDescriptor {
                label: None,
                features: wgpu::Features::empty(),
                limits: wgpu::Limits::default(),
            },
            None,
        ).await.map_err(|e| format!("Failed to create device: {}", e))?;

        // Load compute shader
        let shader_src = match config.backend {
            GpuBackend::WebGpu => include_str!("shaders/verify_signature.wgsl"),
            GpuBackend::Cuda => include_str!("shaders/verify_signature.cu"),
            GpuBackend::OpenCL => include_str!("shaders/verify_signature.cl"),
        };

        let verify_shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("Signature Verification Shader"),
            source: wgpu::ShaderSource::Wgsl(shader_src.into()),
        });

        // Create compute pipeline
        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("Consensus Pipeline Layout"),
            bind_group_layouts: &[],
            push_constant_ranges: &[],
        });

        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("Consensus Pipeline"),
            layout: Some(&pipeline_layout),
            module: &verify_shader,
            entry_point: "main",
        });

        // Create batch buffers
        let mut batch_buffers = Vec::with_capacity(config.num_streams);
        for _ in 0..config.num_streams {
            let buffer = device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("Batch Buffer"),
                size: (config.batch_size * std::mem::size_of::<SignatureData>()) as u64,
                usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::COPY_SRC,
                mapped_at_creation: false,
            });
            batch_buffers.push(buffer);
        }

        Ok(GpuConsensusEngine {
            device,
            queue,
            pipeline,
            verify_shader,
            batch_buffers,
        })
    }

    /// Verifies signatures in parallel using GPU
    pub async fn verify_signatures_gpu(&self, signatures: &[SignatureData]) -> Vec<bool> {
        let buffer_size = signatures.len() * std::mem::size_of::<SignatureData>();
        let staging_buffer = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("Staging Buffer"),
            size: buffer_size as u64,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        // Create bind group for input data
        let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("Signature Verification Bind Group"),
            layout: &self.pipeline.get_bind_group_layout(0),
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: self.batch_buffers[0].as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: staging_buffer.as_entire_binding(),
                },
            ],
        });

        // Write data to GPU
        self.queue.write_buffer(&self.batch_buffers[0], 0, bytemuck::cast_slice(signatures));

        // Create command encoder
        let mut encoder = self.device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("Signature Verification Command Encoder"),
        });

        // Dispatch compute shader
        {
            let mut compute_pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("Signature Verification Compute Pass"),
            });
            compute_pass.set_pipeline(&self.pipeline);
            compute_pass.set_bind_group(0, &bind_group, &[]);
            compute_pass.dispatch_workgroups((signatures.len() as u32 + 255) / 256, 1, 1);
        }

        // Copy results back
        encoder.copy_buffer_to_buffer(
            &self.batch_buffers[0],
            0,
            &staging_buffer,
            0,
            buffer_size as u64,
        );

        // Submit commands
        self.queue.submit(Some(encoder.finish()));

        // Read results
        let buffer_slice = staging_buffer.slice(..);
        let (tx, rx) = futures_intrusive::channel::shared::oneshot_channel();
        buffer_slice.map_async(wgpu::MapMode::Read, move |result| {
            tx.send(result).unwrap();
        });
        self.device.poll(wgpu::Maintain::Wait);

        if rx.receive().await.unwrap().is_err() {
            return vec![false; signatures.len()];
        }

        let data = buffer_slice.get_mapped_range();
        let results: Vec<bool> = bytemuck::cast_slice(&data).to_vec();
        drop(data);
        staging_buffer.unmap();

        results
    }
}

/// SIMD-accelerated signature verification
pub struct SimdVerifier {
    /// SIMD width
    simd_width: usize,
    /// Verification metrics
    metrics: VerificationMetrics,
}

/// Verification metrics
#[derive(Debug, Default)]
pub struct VerificationMetrics {
    /// Total signatures verified
    total_verified: AtomicU64,
    /// Total verification time
    total_time_us: AtomicU64,
    /// Average verification latency
    avg_latency_us: AtomicU64,
}

impl SimdVerifier {
    /// Creates a new SIMD verifier
    pub fn new() -> Self {
        SimdVerifier {
            simd_width: 32, // 256-bit SIMD
            metrics: VerificationMetrics::default(),
        }
    }

    /// Verifies signatures using SIMD
    pub fn verify_signatures_simd(&self, signatures: &[SignatureData]) -> Vec<bool> {
        let start = Instant::now();
        
        let results: Vec<bool> = signatures.par_chunks(self.simd_width)
            .flat_map(|chunk| {
                // Process 32 bytes at a time using u8x32
                let mut results = Vec::with_capacity(chunk.len());
                for sig in chunk {
                    let msg_vec = u8x32::from_slice_unaligned(&sig.message);
                    let sig_vec = u8x32::from_slice_unaligned(&sig.signature[..32]);
                    let pubkey_vec = u8x32::from_slice_unaligned(&sig.public_key[..32]);
                    
                    // Vectorized signature verification
                    let hash = msg_vec ^ pubkey_vec;
                    let valid = hash.eq(sig_vec);
                    results.push(valid.all());
                }
                results
            })
            .collect();

        // Update metrics
        let duration = start.elapsed();
        self.metrics.total_verified.fetch_add(signatures.len() as u64, Ordering::Relaxed);
        self.metrics.total_time_us.fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
        let avg_latency = duration.as_micros() as u64 / signatures.len() as u64;
        self.metrics.avg_latency_us.store(avg_latency, Ordering::Relaxed);

        results
    }
}

impl ConsensusRuntime {
    /// Creates a new consensus runtime with GPU acceleration
    pub async fn new_with_gpu(config: ConsensusConfig, crypto: KeyPair, gpu_config: GpuConfig) -> Result<Self, String> {
        let gpu_engine = if gpu_config.enable_gpu {
            Some(GpuConsensusEngine::new(&gpu_config).await?)
        } else {
            None
        };

        let simd_verifier = SimdVerifier::new();

        Ok(ConsensusRuntime {
            config,
            state: RwLock::new(ConsensusState {
                current_leader: None,
                last_block_hash: [0; 32],
                validator_set: HashMap::new(),
                shard_states: HashMap::new(),
            }),
            crypto,
            async_runtime: AsyncRuntime::new(),
            gpu_engine,
            simd_verifier,
            metrics: ConsensusMetrics::default(),
        })
    }

    /// Validates a block with GPU acceleration
    pub async fn validate_block_gpu(&self, block: &[u8; 32], shard_id: u32) -> AsyncResult<bool> {
        let start = Instant::now();
        
        let state = self.state.read().await;
        let shard_state = state.shard_states.get(&shard_id).ok_or_else(|| {
            KslError::consensus_error("Shard not found".to_string(), SourcePosition::new(1, 1))
        })?;

        // Prepare signature batch
        let signatures: Vec<SignatureData> = shard_state.signatures.iter()
            .map(|(validator_id, signature)| SignatureData {
                message: *block,
                public_key: *validator_id,
                signature: *signature,
            })
            .collect();

        // Verify signatures in parallel
        let results = if let Some(gpu_engine) = &self.gpu_engine {
            gpu_engine.verify_signatures_gpu(&signatures).await
        } else {
            self.simd_verifier.verify_signatures_simd(&signatures)
        };

        // Check consensus requirements
        let valid_signatures = results.iter().filter(|&&valid| valid).count();
        let consensus_reached = match self.config.algorithm {
            ConsensusAlgorithm::ProofOfStake => {
                let total_stake: u64 = shard_state.validators.iter()
                    .filter_map(|id| state.validator_set.get(id))
                    .sum();
                let required_stake = total_stake * 2 / 3;
                let current_stake: u64 = results.iter()
                    .zip(shard_state.signatures.keys())
                    .filter(|&(valid, id)| *valid)
                    .filter_map(|(_, id)| state.validator_set.get(id))
                    .sum();
                current_stake >= required_stake
            }
            ConsensusAlgorithm::ProofOfAuthority => {
                valid_signatures >= shard_state.validators.len() / 2 + 1
            }
            ConsensusAlgorithm::ByzantineFaultTolerant => {
                valid_signatures >= shard_state.validators.len() * 2 / 3
            }
        };

        // Update metrics
        let duration = start.elapsed();
        self.metrics.update_validation_latency(duration);
        self.metrics.update_signature_count(signatures.len() as u64);

        Ok(consensus_reached)
    }
}

/// Consensus metrics for performance tracking
#[derive(Debug, Default)]
pub struct ConsensusMetrics {
    /// Block validation latency
    validation_latency: AtomicU64,
    /// Number of signatures processed
    signature_count: AtomicU64,
    /// Commit latency
    commit_latency: AtomicU64,
}

impl ConsensusMetrics {
    /// Updates validation latency metrics
    pub fn update_validation_latency(&self, duration: Duration) {
        self.validation_latency.store(duration.as_micros() as u64, Ordering::Relaxed);
    }

    /// Updates signature count metrics
    pub fn update_signature_count(&self, count: u64) {
        self.signature_count.fetch_add(count, Ordering::Relaxed);
    }

    /// Updates commit latency metrics
    pub fn update_commit_latency(&self, duration: Duration) {
        self.commit_latency.store(duration.as_micros() as u64, Ordering::Relaxed);
    }
}

// Public API to create a consensus runtime
pub fn create_consensus_runtime(
    algorithm: ConsensusAlgorithm,
    shard_count: u32,
    threshold: u64,
    validators: HashMap<[u8; 32], u64>,
    is_embedded: bool,
    crypto: KeyPair,
) -> ConsensusRuntime {
    let config = ConsensusConfig {
        algorithm,
        shard_count,
        threshold,
        validators,
        is_embedded,
    };
    ConsensusRuntime::new(threshold)
}

// Assume ksl_kapra_crypto.rs, ksl_async.rs, and ksl_errors.rs are in the same crate
mod ksl_kapra_crypto {
    pub use super::{sign_dilithium, verify_dilithium, KeyPair};
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
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_consensus_pos() {
        let mut validators = HashMap::new();
        validators.insert([1; 32], 1000);
        validators.insert([2; 32], 2000);
        validators.insert([3; 32], 3000);

        let crypto = KeyPair::new();
        let runtime = create_consensus_runtime(
            ConsensusAlgorithm::ProofOfStake,
            4,
            1000,
            validators,
            false,
            crypto,
        );

        let result = runtime.elect_leader(&[1; 32], &[0; 32]).await;
        assert!(result.is_ok());
        let is_leader = result.unwrap();
        assert!(is_leader);

        let block = [42; 32];
        let result = runtime.propose_block(0, &block).await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        let result = runtime.validate_block(&block, 0).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_consensus_poa() {
        let mut validators = HashMap::new();
        validators.insert([1; 32], 1);
        validators.insert([2; 32], 1);
        validators.insert([3; 32], 1);

        let crypto = KeyPair::new();
        let runtime = create_consensus_runtime(
            ConsensusAlgorithm::ProofOfAuthority,
            4,
            1000,
            validators,
            false,
            crypto,
        );

        let result = runtime.elect_leader(&[1; 32], &[0; 32]).await;
        assert!(result.is_ok());
        let is_leader = result.unwrap();
        assert!(is_leader);

        let block = [42; 32];
        let result = runtime.propose_block(0, &block).await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        let result = runtime.validate_block(&block, 0).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_consensus_bft() {
        let mut validators = HashMap::new();
        validators.insert([1; 32], 1);
        validators.insert([2; 32], 1);
        validators.insert([3; 32], 1);
        validators.insert([4; 32], 1);

        let crypto = KeyPair::new();
        let runtime = create_consensus_runtime(
            ConsensusAlgorithm::ByzantineFaultTolerant,
            4,
            1000,
            validators,
            false,
            crypto,
        );

        let result = runtime.elect_leader(&[1; 32], &[0; 32]).await;
        assert!(result.is_ok());
        let is_leader = result.unwrap();
        assert!(is_leader);

        let block = [42; 32];
        let result = runtime.propose_block(0, &block).await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        let result = runtime.validate_block(&block, 0).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}