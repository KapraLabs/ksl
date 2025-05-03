// ksl_kapra_scheduler.rs
// Resource-aware scheduling for Kapra Chain validators on constrained devices

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
    Array64([u8; 64]),
    Array1024([u8; 1024]),
    Array1312([u8; 1312]),
    Array2420([u8; 2420]),
}

/// Represents an AST node (aligned with ksl_parser.rs).
#[derive(Debug, Clone)]
pub enum AstNode {
    ScheduleBlock {
        params: Vec<(String, Type)>, // Parameters (e.g., priority)
        return_type: Type,           // Return type (bool)
        body: Vec<AstNode>,          // Body of the schedule block
    },
    Call {
        name: String,
        args: Vec<AstNode>,
    },
    LiteralU32(u32),
    LiteralArray32([u8; 32]),
    LiteralArray64([u8; 64]),
    LiteralArray1024([u8; 1024]),
    LiteralArray1312([u8; 1312]),
    LiteralArray2420([u8; 2420]),
}

/// Represents a type (aligned with ksl_types.rs).
#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    Bool,
    U32,
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

    pub fn dil_verify(
        &self,
        message: &FixedArray<32>,
        pubkey: &FixedArray<1312>,
        signature: &FixedArray<2420>,
    ) -> bool {
        let msg_hash = message.as_slice().iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32));
        let pubkey_sum = pubkey.as_slice().iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32));
        let sig_sum = signature.as_slice().iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32));
        msg_hash == (pubkey_sum ^ sig_sum)
    }

    pub fn sha3(&self, input: &[u8]) -> FixedArray<32> {
        let mut output = [0u8; 32];
        for i in 0..32 {
            output[i] = input.iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32)) as u8;
        }
        FixedArray::new(output)
    }
}

/// ZKP runtime (aligned with ksl_kapra_zkp.rs).
#[derive(Debug, Clone)]
pub struct ZkpRuntime {
    is_embedded: bool,
}

impl ZkpRuntime {
    pub fn new(is_embedded: bool) -> Self {
        ZkpRuntime { is_embedded }
    }

    pub fn generate_proof(&self, statement: &FixedArray<32>, witness: &FixedArray<32>) -> FixedArray<64> {
        let mut proof = [0u8; 64];
        for i in 0..32 {
            proof[i] = statement.as_slice()[i] ^ witness.as_slice()[i];
            proof[i + 32] = proof[i];
        }
        if self.is_embedded {
            for i in 0..64 {
                proof[i] = proof[i] & 0x0F;
            }
        }
        FixedArray::new(proof)
    }

    pub fn verify_proof(&self, statement: &FixedArray<32>, proof: &FixedArray<64>) -> bool {
        let expected = statement.as_slice().iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32));
        let proof_sum = proof.as_slice()[0..32].iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32));
        expected == proof_sum
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

/// Runtime metrics (aligned with ksl_runtime_monitor.rs).
#[derive(Debug, Clone)]
pub struct RuntimeMetrics {
    instruction_count: u64,
    stack_size: usize,
}

impl RuntimeMetrics {
    pub fn new() -> Self {
        RuntimeMetrics {
            instruction_count: 0,
            stack_size: 0,
        }
    }

    pub fn record_instruction(&mut self) {
        self.instruction_count += 1;
    }

    pub fn record_stack_change(&mut self, delta: i32) {
        self.stack_size = (self.stack_size as i32 + delta) as usize;
    }
}

/// Resource limits for scheduling.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    max_instructions: u64,
    max_stack_size: usize,
}

impl ResourceLimits {
    pub fn new() -> Self {
        ResourceLimits {
            max_instructions: 100_000, // Per task
            max_stack_size: 512,       // 512 bytes (64 u64s)
        }
    }

    pub fn check(&self, metrics: &RuntimeMetrics) -> Option<String> {
        if metrics.instruction_count > self.max_instructions {
            return Some(format!(
                "Instruction count limit exceeded: {} (max: {})",
                metrics.instruction_count, self.max_instructions
            ));
        }
        if metrics.stack_size > self.max_stack_size {
            return Some(format!(
                "Stack size limit exceeded: {} bytes (max: {} bytes)",
                metrics.stack_size, self.max_stack_size
            ));
        }
        None
    }
}

/// Scheduler for Kapra Chain tasks.
#[derive(Debug, Clone)]
pub struct Scheduler {
    tasks: Vec<(u32, Bytecode)>, // (priority, task bytecode)
    limits: ResourceLimits,
}

impl Scheduler {
    pub fn new(limits: ResourceLimits) -> Self {
        Scheduler {
            tasks: vec![],
            limits,
        }
    }

    pub fn add_task(&mut self, priority: u32, task: Bytecode) {
        self.tasks.push((priority, task));
    }

    pub fn schedule(&mut self) -> Vec<Bytecode> {
        // Sort tasks by priority (higher priority first)
        self.tasks.sort_by(|a, b| b.0.cmp(&a.0));
        self.tasks.iter().map(|(_, task)| task.clone()).collect()
    }
}

/// Kapra VM with scheduling support (aligned with kapra_vm.rs).
#[derive(Debug)]
pub struct KapraVM {
    stack: Vec<u64>,
    crypto: KapraCrypto,
    zkp_runtime: ZkpRuntime,
    shard_runtime: ShardRuntime,
    metrics: RuntimeMetrics,
    limits: ResourceLimits,
    async_tasks: Vec<AsyncTask>,
}

impl KapraVM {
    pub fn new(shard_count: u32, is_embedded: bool) -> Self {
        KapraVM {
            stack: vec![],
            crypto: KapraCrypto::new(is_embedded),
            zkp_runtime: ZkpRuntime::new(is_embedded),
            shard_runtime: ShardRuntime::new(shard_count),
            metrics: RuntimeMetrics::new(),
            limits: ResourceLimits::new(),
            async_tasks: vec![],
        }
    }

    pub fn execute(&mut self, bytecode: &Bytecode) -> Result<bool, String> {
        let mut ip = 0;
        while ip < bytecode.instructions.len() {
            let instr = bytecode.instructions[ip];
            ip += 1;

            self.metrics.record_instruction();
            if let Some(violation) = self.limits.check(&self.metrics) {
                return Err(format!("Resource limit exceeded: {}", violation));
            }

            match instr {
                OPCODE_SCHEDULE => {
                    if ip >= bytecode.instructions.len() {
                        return Err("Incomplete SCHEDULE instruction".to_string());
                    }
                    let priority = bytecode.instructions[ip] as u32;
                    ip += 1;
                    let task_idx = bytecode.instructions[ip] as usize;
                    ip += 1;
                    let task_bytecode = match &bytecode.constants[task_idx] {
                        Constant::String(task_code) => {
                            // Simplified: Parse task bytecode (in reality, this would be precompiled)
                            Bytecode::new(task_code.as_bytes().to_vec(), vec![])
                        }
                        _ => return Err("Invalid type for SCHEDULE task".to_string()),
                    };

                    let mut scheduler = Scheduler::new(self.limits.clone());
                    scheduler.add_task(priority, task_bytecode);
                    let scheduled_tasks = scheduler.schedule();

                    // Execute scheduled tasks
                    for task in scheduled_tasks {
                        let mut task_vm = KapraVM::new(self.shard_runtime.shard_count, self.crypto.is_embedded);
                        task_vm.execute(&task)?;
                    }
                    self.stack.push(1); // Success
                }
                OPCODE_VALIDATE_BLOCK => {
                    if self.stack.len() < 3 {
                        return Err("Not enough values on stack for VALIDATE_BLOCK".to_string());
                    }
                    let sig_idx = self.stack.pop().unwrap() as usize;
                    let pubkey_idx = self.stack.pop().unwrap() as usize;
                    let block_idx = self.stack.pop().unwrap() as usize;
                    let block = match &bytecode.constants[block_idx] {
                        Constant::Array1024(arr) => arr,
                        _ => return Err("Invalid type for VALIDATE_BLOCK block".to_string()),
                    };
                    let pubkey = match &bytecode.constants[pubkey_idx] {
                        Constant::Array1312(arr) => FixedArray::new(*arr),
                        _ => return Err("Invalid type for VALIDATE_BLOCK pubkey".to_string()),
                    };
                    let signature = match &bytecode.constants[sig_idx] {
                        Constant::Array2420(arr) => FixedArray::new(*arr),
                        _ => return Err("Invalid type for VALIDATE_BLOCK signature".to_string()),
                    };
                    let msg = self.crypto.sha3(&block[..]);
                    let valid = self.crypto.dil_verify(&msg, &pubkey, &signature);
                    let const_idx = bytecode.constants.len();
                    self.stack.push(const_idx as u64);
                    let mut new_constants = bytecode.constants.clone();
                    new_constants.push(Constant::Array32(msg.data));
                    let new_bytecode = Bytecode::new(bytecode.instructions.clone(), new_constants);
                    *bytecode = new_bytecode;
                    self.stack.push(valid as u64);
                }
                OPCODE_KAPREKAR => {
                    if self.stack.len() < 1 {
                        return Err("Not enough values on stack for KAPREKAR".to_string());
                    }
                    let input_idx = self.stack.pop().unwrap() as usize;
                    let input = match &bytecode.constants[input_idx] {
                        Constant::Array32(arr) => &arr[0..4],
                        _ => return Err("Invalid type for KAPREKAR argument".to_string()),
                    };
                    let result = self.kaprekar(input);
                    self.stack.push(result as u64);
                }
                OPCODE_ZKP => {
                    if self.stack.len() < 2 {
                        return Err("Not enough values on stack for ZKP".to_string());
                    }
                    let witness_idx = self.stack.pop().unwrap() as usize;
                    let statement_idx = self.stack.pop().unwrap() as usize;
                    let statement = match &bytecode.constants[statement_idx] {
                        Constant::Array32(arr) => FixedArray::new(*arr),
                        _ => return Err("Invalid type for ZKP statement".to_string()),
                    };
                    let witness = match &bytecode.constants[witness_idx] {
                        Constant::Array32(arr) => FixedArray::new(*arr),
                        _ => return Err("Invalid type for ZKP witness".to_string()),
                    };
                    let proof = self.zkp_runtime.generate_proof(&statement, &witness);
                    let valid = self.zkp_runtime.verify_proof(&statement, &proof);
                    let const_idx = bytecode.constants.len();
                    self.stack.push(const_idx as u64);
                    self.stack.push(valid as u64);
                    let mut new_constants = bytecode.constants.clone();
                    new_constants.push(Constant::Array64(proof.data));
                    let new_bytecode = Bytecode::new(bytecode.instructions.clone(), new_constants);
                    *bytecode = new_bytecode;
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
                    self.metrics.record_stack_change(8);
                    self.stack.push(value);
                }
                OPCODE_FAIL => {
                    return Err("Task execution failed".to_string());
                }
                _ => return Err(format!("Unsupported opcode: {}", instr)),
            }
        }

        if self.stack.len() != 1 {
            return Err("Schedule block must return exactly one boolean value".to_string());
        }
        Ok(self.stack[0] != 0)
    }

    fn kaprekar(&self, input: &[u8]) -> u16 {
        if input.len() != 4 {
            return 0;
        }
        let num = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
        if num == 0 {
            0
        } else {
            6174
        }
    }
}

/// Represents an async task (aligned with ksl_async.rs).
#[derive(Debug, Clone)]
pub enum AsyncTask {
    ShardSend(u32, [u8; 32]),
}

/// Scheduler compiler for Kapra Chain.
pub struct SchedulerCompiler {
    shard_count: u32,
    is_embedded: bool,
}

impl SchedulerCompiler {
    pub fn new(shard_count: u32, is_embedded: bool) -> Self {
        SchedulerCompiler {
            shard_count,
            is_embedded,
        }
    }

    /// Compile a schedule block into bytecode.
    pub fn compile(&self, node: &AstNode) -> Result<Bytecode, String> {
        match node {
            AstNode::ScheduleBlock { params, return_type, body } => {
                // Validate parameters and return type
                if params.len() != 1 {
                    return Err("Schedule block must have exactly 1 parameter: priority".to_string());
                }
                if params[0].0 != "priority" || !matches!(params[0].1, Type::U32) {
                    return Err("Parameter must be 'priority: u32'".to_string());
                }
                if !matches!(return_type, Type::Bool) {
                    return Err("Schedule block must return bool".to_string());
                }

                let mut bytecode = Bytecode::new(vec![], vec![]);
                let mut task_bytecode = Bytecode::new(vec![], vec![]);

                // Compile the priority
                if let Some(AstNode::LiteralU32(priority)) = body.first() {
                    bytecode.instructions.push(OPCODE_SCHEDULE);
                    bytecode.instructions.push(*priority as u8);
                } else {
                    return Err("First statement in schedule block must be a priority literal".to_string());
                }

                // Compile the body into a task
                for stmt in body.iter().skip(1) {
                    let stmt_bytecode = self.compile_stmt(stmt)?;
                    task_bytecode.extend(stmt_bytecode);
                }

                // Add the task to constants
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::String(format!("{:?}", task_bytecode.instructions)));
                bytecode.instructions.push(const_idx as u8);

                Ok(bytecode)
            }
            _ => Err("Only schedule blocks can be compiled at the top level".to_string()),
        }
    }

    fn compile_stmt(&self, stmt: &AstNode) -> Result<Bytecode, String> {
        match stmt {
            AstNode::Call { name, args } => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                for arg in args {
                    let arg_bytecode = self.compile_expr(arg)?;
                    bytecode.extend(arg_bytecode);
                }
                match name.as_str() {
                    "validate_block" => {
                        bytecode.instructions.push(OPCODE_VALIDATE_BLOCK);
                        bytecode.instructions.push(OPCODE_FAIL_IF_FALSE);
                    }
                    "zkp" => {
                        bytecode.instructions.push(OPCODE_ZKP);
                        bytecode.instructions.push(OPCODE_FAIL_IF_FALSE);
                    }
                    "shard" => {
                        bytecode.instructions.push(OPCODE_SHARD);
                    }
                    _ => return Err(format!("Unsupported function in schedule block: {}", name)),
                }
                Ok(bytecode)
            }
            _ => Err("Unsupported statement in schedule block".to_string()),
        }
    }

    fn compile_expr(&self, expr: &AstNode) -> Result<Bytecode, String> {
        match expr {
            AstNode::LiteralU32(val) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, *val as u8]);
                Ok(bytecode)
            }
            AstNode::LiteralArray32(arr) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::Array32(*arr));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::LiteralArray64(arr) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::Array64(*arr));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::LiteralArray1024(arr) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::Array1024(*arr));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::LiteralArray1312(arr) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::Array1312(*arr));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::LiteralArray2420(arr) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::Array2420(*arr));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            _ => Err("Unsupported expression in schedule block".to_string()),
        }
    }
}

const OPCODE_SCHEDULE: u8 = 0x01;
const OPCODE_VALIDATE_BLOCK: u8 = 0x02;
const OPCODE_KAPREKAR: u8 = 0x03;
const OPCODE_ZKP: u8 = 0x04;
const OPCODE_SHARD: u8 = 0x05;
const OPCODE_PUSH: u8 = 0x06;
const OPCODE_FAIL: u8 = 0x07;
const OPCODE_FAIL_IF_FALSE: u8 = 0x08;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schedule_block_compilation() {
        let schedule_node = AstNode::ScheduleBlock {
            params: vec![("priority".to_string(), Type::U32)],
            return_type: Type::Bool,
            body: vec![
                AstNode::LiteralU32(10), // Priority
                AstNode::Call {
                    name: "validate_block".to_string(),
                    args: vec![
                        AstNode::LiteralArray1024([1; 1024]),
                        AstNode::LiteralArray1312([2; 1312]),
                        AstNode::LiteralArray2420([3; 2420]),
                    ],
                },
                AstNode::Call {
                    name: "zkp".to_string(),
                    args: vec![
                        AstNode::LiteralArray32([4; 32]),
                        AstNode::LiteralArray32([5; 32]),
                    ],
                },
                AstNode::Call {
                    name: "shard".to_string(),
                    args: vec![AstNode::LiteralArray32([4; 32])],
                },
            ],
        };

        let compiler = SchedulerCompiler::new(1000, false);
        let bytecode = compiler.compile(&schedule_node).unwrap();
        assert!(!bytecode.instructions.is_empty());
        assert!(bytecode.instructions.contains(&OPCODE_SCHEDULE));
        assert!(bytecode.instructions.contains(&OPCODE_VALIDATE_BLOCK));
        assert!(bytecode.instructions.contains(&OPCODE_ZKP));
        assert!(bytecode.instructions.contains(&OPCODE_SHARD));
    }

    #[test]
    fn test_schedule_execution() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::Array1024([1; 1024]), // block
            Constant::Array1312([2; 1312]), // pubkey
            Constant::Array2420([3; 2420]), // signature
            Constant::Array32([4; 32]),     // statement
            Constant::Array32([5; 32]),     // witness
            Constant::Array64([6; 64]),     // proof
            Constant::String("VALIDATE_BLOCK ZKP SHARD".to_string()), // Task bytecode (simplified)
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_SCHEDULE,
            10, // Priority
            6,  // Task index
        ]);

        let mut vm = KapraVM::new(1000, false);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_schedule_resource_limit() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::Array1024([1; 1024]),
            Constant::Array1312([2; 1312]),
            Constant::Array2420([3; 2420]),
            Constant::String("VALIDATE_BLOCK".repeat(100_000).to_string()), // Exceed instruction limit
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_SCHEDULE,
            10,
            3,
        ]);

        let mut vm = KapraVM::new(1000, false);
        let result = vm.execute(&bytecode);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Resource limit exceeded"));
    }

    #[test]
    fn test_schedule_invalid_params() {
        let schedule_node = AstNode::ScheduleBlock {
            params: vec![],
            return_type: Type::Bool,
            body: vec![],
        };

        let compiler = SchedulerCompiler::new(1000, false);
        let result = compiler.compile(&schedule_node);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must have exactly 1 parameter"));
    }
}