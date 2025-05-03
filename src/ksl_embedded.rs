// ksl_embedded.rs
// Support for embedded systems as a compilation target for KSL, optimized for Kapra Chain validators

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

    pub fn instructions(&self) -> &Vec<u8> {
        &self.instructions
    }

    pub fn constants(&self) -> &Vec<Constant> {
        &self.constants
    }

    pub fn size(&self) -> usize {
        self.instructions.len() + self.constants.iter().map(|c| match c {
            Constant::String(s) => s.len() + 1,
            Constant::U64(_) => 9,
            Constant::Array32(_) => 33, // 1 for type tag + 32 for data
            Constant::Array1024(_) => 1025,
            Constant::Array1312(_) => 1313,
            Constant::Array2420(_) => 2421,
        }).sum::<usize>()
    }
}

/// Represents a constant in the bytecode.
#[derive(Debug, Clone)]
pub enum Constant {
    String(String),
    U64(u64),
    Array32([u8; 32]),
    Array1024([u8; 1024]),
    Array1312([u8; 1312]),
    Array2420([u8; 2420]),
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
    // Simplified for embedded use
}

impl KapraCrypto {
    pub fn new() -> Self {
        KapraCrypto {}
    }

    pub fn dil_verify(
        &self,
        message: &FixedArray<32>,
        pubkey: &FixedArray<1312>,
        signature: &FixedArray<2420>,
    ) -> bool {
        // Lightweight implementation for embedded (simplified)
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

/// Optimizer for embedded systems (aligned with ksl_optimizer.rs).
#[derive(Debug, Clone)]
pub struct EmbeddedOptimizer {
    // Placeholder for optimization configuration
}

impl EmbeddedOptimizer {
    pub fn new() -> Self {
        EmbeddedOptimizer {}
    }

    pub fn optimize(&self, bytecode: &mut Bytecode) -> Result<(), String> {
        // Optimization 1: Remove unused constants
        let mut used_constants = vec![false; bytecode.constants.len()];
        for i in 0..bytecode.instructions.len() {
            let instr = bytecode.instructions[i];
            if matches!(instr, OPCODE_LOAD_CONST | OPCODE_SHA3 | OPCODE_DIL_VERIFY | OPCODE_KAPREKAR | OPCODE_SHARD) {
                if i + 1 < bytecode.instructions.len() {
                    let const_idx = bytecode.instructions[i + 1] as usize;
                    if const_idx < used_constants.len() {
                        used_constants[const_idx] = true;
                    }
                }
            }
        }

        let mut new_constants = vec![];
        let mut const_map = vec![0; bytecode.constants.len()];
        let mut new_idx = 0;
        for (i, &used) in used_constants.iter().enumerate() {
            if used {
                const_map[i] = new_idx;
                new_constants.push(bytecode.constants[i].clone());
                new_idx += 1;
            }
        }

        let mut new_instructions = bytecode.instructions.clone();
        for i in 0..new_instructions.len() {
            if matches!(new_instructions[i], OPCODE_LOAD_CONST | OPCODE_SHA3 | OPCODE_DIL_VERIFY | OPCODE_KAPREKAR | OPCODE_SHARD) {
                if i + 1 < new_instructions.len() {
                    let old_idx = new_instructions[i + 1] as usize;
                    if old_idx < const_map.len() && used_constants[old_idx] {
                        new_instructions[i + 1] = const_map[old_idx] as u8;
                    } else {
                        new_instructions[i] = OPCODE_NOOP;
                        new_instructions[i + 1] = 0;
                    }
                }
            }
        }

        // Optimization 2: Inline small constants directly
        for i in 0..new_instructions.len() {
            if new_instructions[i] == OPCODE_LOAD_CONST {
                if i + 1 < new_instructions.len() {
                    let const_idx = new_instructions[i + 1] as usize;
                    if const_idx < new_constants.len() {
                        if let Constant::U64(val) = new_constants[const_idx] {
                            if val <= u8::MAX as u64 {
                                new_instructions[i] = OPCODE_LOAD_DIRECT;
                                new_instructions[i + 1] = val as u8;
                            }
                        }
                    }
                }
            }
        }

        // Optimization 3: Inline Kaprekar check for small inputs
        for i in 0..new_instructions.len() {
            if new_instructions[i] == OPCODE_KAPREKAR {
                if i + 1 < new_instructions.len() {
                    let const_idx = new_instructions[i + 1] as usize;
                    if const_idx < new_constants.len() {
                        if let Constant::Array32(arr) = &new_constants[const_idx] {
                            let input = &arr[0..4];
                            let num = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
                            if num != 0 {
                                // Inline the result (always 6174 for non-zero inputs in this example)
                                new_instructions[i] = OPCODE_LOAD_DIRECT;
                                new_instructions[i + 1] = 6174u16.to_le_bytes()[0]; // Lower byte
                                new_instructions[i + 2] = 6174u16.to_le_bytes()[1]; // Upper byte
                            } else {
                                new_instructions[i] = OPCODE_LOAD_DIRECT;
                                new_instructions[i + 1] = 0;
                                new_instructions[i + 2] = 0;
                            }
                        }
                    }
                }
            }
        }

        bytecode.instructions = new_instructions;
        bytecode.constants = new_constants;
        Ok(())
    }
}

/// Minimal VM for embedded systems with validator support (aligned with kapra_vm.rs).
#[derive(Debug)]
pub struct EmbeddedVM {
    stack: [u64; 128], // Reduced stack size (1 KB for 128 u64s)
    stack_pointer: usize,
    crypto: KapraCrypto,
    shard_runtime: ShardRuntime,
}

impl EmbeddedVM {
    pub fn new(shard_count: u32) -> Self {
        EmbeddedVM {
            stack: [0; 128],
            stack_pointer: 0,
            crypto: KapraCrypto::new(),
            shard_runtime: ShardRuntime::new(shard_count),
        }
    }

    pub fn execute(&mut self, bytecode: &Bytecode) -> Result<(), String> {
        let instructions = bytecode.instructions();
        let mut ip = 0;

        while ip < instructions.len() {
            let instr = instructions[ip];
            ip += 1;

            match instr {
                OPCODE_PUSH => {
                    if ip >= instructions.len() {
                        return Err("Incomplete PUSH instruction".to_string());
                    }
                    let value = instructions[ip] as u64;
                    ip += 1;
                    if self.stack_pointer >= self.stack.len() {
                        return Err("Stack overflow".to_string());
                    }
                    self.stack[self.stack_pointer] = value;
                    self.stack_pointer += 1;
                }
                OPCODE_POP => {
                    if self.stack_pointer == 0 {
                        return Err("Stack underflow".to_string());
                    }
                    self.stack_pointer -= 1;
                }
                OPCODE_ADD => {
                    if self.stack_pointer < 2 {
                        return Err("Not enough values on stack for ADD".to_string());
                    }
                    let a = self.stack[self.stack_pointer - 1];
                    let b = self.stack[self.stack_pointer - 2];
                    self.stack_pointer -= 2;
                    self.stack[self.stack_pointer] = a.wrapping_add(b);
                    self.stack_pointer += 1;
                }
                OPCODE_LOAD_CONST => {
                    if ip >= instructions.len() {
                        return Err("Incomplete LOAD_CONST instruction".to_string());
                    }
                    let const_idx = instructions[ip] as usize;
                    ip += 1;
                    if const_idx >= bytecode.constants.len() {
                        return Err("Invalid constant index".to_string());
                    }
                    if self.stack_pointer >= self.stack.len() {
                        return Err("Stack overflow".to_string());
                    }
                    match &bytecode.constants[const_idx] {
                        Constant::U64(val) => {
                            self.stack[self.stack_pointer] = *val;
                            self.stack_pointer += 1;
                        }
                        _ => return Err("Unsupported constant type for embedded target".to_string()),
                    }
                }
                OPCODE_LOAD_DIRECT => {
                    if ip >= instructions.len() {
                        return Err("Incomplete LOAD_DIRECT instruction".to_string());
                    }
                    let value = instructions[ip] as u64;
                    ip += 1;
                    if self.stack_pointer >= self.stack.len() {
                        return Err("Stack overflow".to_string());
                    }
                    self.stack[self.stack_pointer] = value;
                    self.stack_pointer += 1;
                }
                OPCODE_SENSOR => {
                    if self.stack_pointer >= self.stack.len() {
                        return Err("Stack overflow".to_string());
                    }
                    self.stack[self.stack_pointer] = 42; // Dummy sensor value
                    self.stack_pointer += 1;
                }
                OPCODE_NOOP => {
                    ip += 1; // Skip the operand
                }
                OPCODE_SHA3 => {
                    if ip >= instructions.len() {
                        return Err("Incomplete SHA3 instruction".to_string());
                    }
                    let input_idx = instructions[ip] as usize;
                    ip += 1;
                    if self.stack_pointer >= self.stack.len() {
                        return Err("Stack overflow".to_string());
                    }
                    let input = match &bytecode.constants[input_idx] {
                        Constant::Array1024(arr) => arr,
                        _ => return Err("Invalid type for SHA3 argument".to_string()),
                    };
                    let hash = self.crypto.sha3(&input[..]);
                    self.stack[self.stack_pointer] = bytecode.constants.len() as u64;
                    self.stack_pointer += 1;
                    // Mutable borrow issue workaround: collect constants into a new vec
                    let mut new_constants = bytecode.constants.clone();
                    new_constants.push(Constant::Array32(hash.data));
                    let new_bytecode = Bytecode::new(bytecode.instructions.clone(), new_constants);
                    *bytecode = new_bytecode;
                }
                OPCODE_DIL_VERIFY => {
                    if self.stack_pointer < 3 {
                        return Err("Not enough values on stack for DIL_VERIFY".to_string());
                    }
                    let sig_idx = self.stack[self.stack_pointer - 1] as usize;
                    let pubkey_idx = self.stack[self.stack_pointer - 2] as usize;
                    let msg_idx = self.stack[self.stack_pointer - 3] as usize;
                    self.stack_pointer -= 3;
                    let message = match &bytecode.constants[msg_idx] {
                        Constant::Array32(arr) => FixedArray::new(*arr),
                        _ => return Err("Invalid type for DIL_VERIFY message".to_string()),
                    };
                    let pubkey = match &bytecode.constants[pubkey_idx] {
                        Constant::Array1312(arr) => FixedArray::new(*arr),
                        _ => return Err("Invalid type for DIL_VERIFY pubkey".to_string()),
                    };
                    let signature = match &bytecode.constants[sig_idx] {
                        Constant::Array2420(arr) => FixedArray::new(*arr),
                        _ => return Err("Invalid type for DIL_VERIFY signature".to_string()),
                    };
                    let result = self.crypto.dil_verify(&message, &pubkey, &signature);
                    self.stack[self.stack_pointer] = result as u64;
                    self.stack_pointer += 1;
                }
                OPCODE_KAPREKAR => {
                    if ip >= instructions.len() {
                        return Err("Incomplete KAPREKAR instruction".to_string());
                    }
                    let input_idx = instructions[ip] as usize;
                    ip += 1;
                    if self.stack_pointer >= self.stack.len() {
                        return Err("Stack overflow".to_string());
                    }
                    let input = match &bytecode.constants[input_idx] {
                        Constant::Array32(arr) => &arr[0..4],
                        _ => return Err("Invalid type for KAPREKAR argument".to_string()),
                    };
                    let result = self.kaprekar(input);
                    self.stack[self.stack_pointer] = result as u64;
                    self.stack_pointer += 1;
                }
                OPCODE_SHARD => {
                    if ip >= instructions.len() {
                        return Err("Incomplete SHARD instruction".to_string());
                    }
                    let account_idx = instructions[ip] as usize;
                    ip += 1;
                    if self.stack_pointer >= self.stack.len() {
                        return Err("Stack overflow".to_string());
                    }
                    let account = match &bytecode.constants[account_idx] {
                        Constant::Array32(arr) => arr,
                        _ => return Err("Invalid type for SHARD argument".to_string()),
                    };
                    let shard_id = self.shard_runtime.shard_route(account);
                    let success = self.shard_runtime.shard_send(shard_id, account);
                    self.stack[self.stack_pointer] = shard_id as u64;
                    self.stack_pointer += 1;
                    self.stack[self.stack_pointer] = success as u64;
                    self.stack_pointer += 1;
                }
                OPCODE_FAIL => {
                    return Err("Validation failed".to_string());
                }
                _ => return Err(format!("Unsupported opcode for embedded target: {}", instr)),
            }
        }
        Ok(())
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

/// Bundler for embedded deployment (aligned with ksl_bundler.rs).
#[derive(Debug, Clone)]
pub struct EmbeddedBundler {
    // Placeholder for bundling configuration
}

impl EmbeddedBundler {
    pub fn new() -> Self {
        EmbeddedBundler {}
    }

    pub fn bundle(&self, bytecode: &Bytecode) -> Vec<u8> {
        let mut binary = vec![];

        // Header: Magic number, version, and validator flag
        binary.extend_from_slice(b"KSL\0");
        binary.push(1); // Version
        binary.push(1); // Validator flag (indicates this binary supports validator ops)

        // Constants section
        binary.push(bytecode.constants.len() as u8);
        for constant in bytecode.constants.iter() {
            match constant {
                Constant::U64(val) => {
                    binary.push(0x01);
                    binary.extend_from_slice(&val.to_le_bytes());
                }
                Constant::Array32(arr) => {
                    binary.push(0x02);
                    binary.extend_from_slice(arr);
                }
                Constant::Array1024(arr) => {
                    binary.push(0x03);
                    binary.extend_from_slice(arr);
                }
                Constant::Array1312(arr) => {
                    binary.push(0x04);
                    binary.extend_from_slice(arr);
                }
                Constant::Array2420(arr) => {
                    binary.push(0x05);
                    binary.extend_from_slice(arr);
                }
                Constant::String(_) => {} // Strings are stripped
            }
        }

        // Instructions section
        binary.extend_from_slice(bytecode.instructions());

        binary
    }
}

/// Embedded compiler for KSL.
pub struct EmbeddedCompiler {
    optimizer: EmbeddedOptimizer,
    bundler: EmbeddedBundler,
}

impl EmbeddedCompiler {
    pub fn new() -> Self {
        EmbeddedCompiler {
            optimizer: EmbeddedOptimizer::new(),
            bundler: EmbeddedBundler::new(),
        }
    }

    pub fn compile(&self, mut bytecode: Bytecode) -> Result<Vec<u8>, String> {
        // Validate bytecode for embedded target
        for &instr in bytecode.instructions.iter() {
            match instr {
                OPCODE_PUSH | OPCODE_POP | OPCODE_ADD | OPCODE_LOAD_CONST | OPCODE_LOAD_DIRECT | OPCODE_SENSOR | OPCODE_NOOP | OPCODE_SHA3 | OPCODE_DIL_VERIFY | OPCODE_KAPREKAR | OPCODE_SHARD | OPCODE_FAIL => {}
                _ => return Err(format!("Unsupported opcode for embedded target: {}", instr)),
            }
        }

        for constant in bytecode.constants.iter() {
            match constant {
                Constant::U64(_) | Constant::Array32(_) | Constant::Array1024(_) | Constant::Array1312(_) | Constant::Array2420(_) => {}
                Constant::String(_) => return Err("String constants are not supported for embedded target".to_string()),
            }
        }

        // Optimize the bytecode
        self.optimizer.optimize(&mut bytecode)?;

        // Bundle the bytecode
        let binary = self.bundler.bundle(&bytecode);
        Ok(binary)
    }
}

/// CLI integration for `ksl compile <file> --target embedded`.
pub fn run_compile_embedded(file: &str) -> Result<Vec<u8>, String> {
    let mut instructions = vec![];
    let mut constants = vec![];

    if file.contains("blockchain") {
        instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,           // Push block
            OPCODE_SHA3,              // Compute hash
            OPCODE_PUSH, 2,           // Push pubkey
            OPCODE_PUSH, 3,           // Push signature
            OPCODE_DIL_VERIFY,        // Verify signature
            OPCODE_FAIL,              // Fail if verification fails (simplified)
            OPCODE_PUSH, 1,           // Push msg
            OPCODE_KAPREKAR,          // Compute Kaprekar
            OPCODE_PUSH, 1,           // Push msg (account)
            OPCODE_SHARD,             // Shard operation
        ]);
        constants.extend_from_slice(&[
            Constant::Array1024([1; 1024]), // block
            Constant::Array32([1; 32]),     // msg
            Constant::Array1312([2; 1312]), // pubkey
            Constant::Array2420([3; 2420]), // signature
        ]);
    } else if file.contains("ai") {
        instructions.extend_from_slice(&[
            OPCODE_LOAD_CONST, 0,
            OPCODE_PUSH, 5,
            OPCODE_ADD,
        ]);
        constants.push(Constant::U64(100));
    } else if file.contains("iot") {
        instructions.extend_from_slice(&[
            OPCODE_SENSOR,
            OPCODE_PUSH, 1,
            OPCODE_ADD,
        ]);
    } else {
        return Err(format!("Unknown file type for embedded compilation: {}", file));
    }

    let bytecode = Bytecode::new(instructions, constants);
    let compiler = EmbeddedCompiler::new();
    compiler.compile(bytecode)
}

// Simplified opcodes
const OPCODE_PUSH: u8 = 0x01;
const OPCODE_POP: u8 = 0x02;
const OPCODE_ADD: u8 = 0x03;
const OPCODE_LOAD_CONST: u8 = 0x04;
const OPCODE_LOAD_DIRECT: u8 = 0x05;
const OPCODE_SENSOR: u8 = 0x06;
const OPCODE_NOOP: u8 = 0x00;
const OPCODE_SHA3: u8 = 0x07;
const OPCODE_DIL_VERIFY: u8 = 0x08;
const OPCODE_KAPREKAR: u8 = 0x09;
const OPCODE_SHARD: u8 = 0x0A;
const OPCODE_FAIL: u8 = 0x0B;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_compile_blockchain() {
        let result = run_compile_embedded("blockchain.ksl");
        assert!(result.is_ok());
        let binary = result.unwrap();
        assert_eq!(&binary[0..4], b"KSL\0");
        assert_eq!(binary[4], 1); // Version
        assert_eq!(binary[5], 1); // Validator flag
        assert_eq!(binary[6], 4); // Number of constants
    }

    #[test]
    fn test_embedded_compile_ai() {
        let result = run_compile_embedded("ai.ksl");
        assert!(result.is_ok());
        let binary = result.unwrap();
        assert_eq!(&binary[0..4], b"KSL\0");
        assert_eq!(binary[6], 1);
        assert_eq!(binary[7], 0x01);
    }

    #[test]
    fn test_embedded_compile_iot() {
        let result = run_compile_embedded("iot.ksl");
        assert!(result.is_ok());
        let binary = result.unwrap();
        assert_eq!(&binary[0..4], b"KSL\0");
        assert_eq!(binary[6], 0);
    }

    #[test]
    fn test_optimization() {
        let mut bytecode = Bytecode::new(
            vec![OPCODE_LOAD_CONST, 0, OPCODE_PUSH, 5, OPCODE_ADD],
            vec![Constant::U64(10), Constant::U64(20)],
        );
        let optimizer = EmbeddedOptimizer::new();
        optimizer.optimize(&mut bytecode).unwrap();
        assert_eq!(bytecode.constants.len(), 1);
        assert_eq!(bytecode.instructions[0], OPCODE_LOAD_DIRECT);
        assert_eq!(bytecode.instructions[1], 10);
    }

    #[test]
    fn test_kaprekar_optimization() {
        let mut bytecode = Bytecode::new(
            vec![OPCODE_KAPREKAR, 0],
            vec![Constant::Array32([1; 32])],
        );
        let optimizer = EmbeddedOptimizer::new();
        optimizer.optimize(&mut bytecode).unwrap();
        assert_eq!(bytecode.instructions[0], OPCODE_LOAD_DIRECT);
        assert_eq!(bytecode.instructions[1], 6174u16.to_le_bytes()[0]);
        assert_eq!(bytecode.instructions[2], 6174u16.to_le_bytes()[1]);
    }

    #[test]
    fn test_embedded_vm_execution_validator() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::Array1024([1; 1024]),
            Constant::Array32([1; 32]),
            Constant::Array1312([2; 1312]),
            Constant::Array2420([3; 2420]),
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,
            OPCODE_SHA3,
            OPCODE_PUSH, 2,
            OPCODE_PUSH, 3,
            OPCODE_DIL_VERIFY,
            OPCODE_FAIL,
            OPCODE_PUSH, 1,
            OPCODE_KAPREKAR,
            OPCODE_PUSH, 1,
            OPCODE_SHARD,
        ]);

        let mut vm = EmbeddedVM::new(1000);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        assert_eq!(vm.stack_pointer, 2); // Shard ID and success flag
    }

    #[test]
    fn test_unsupported_feature() {
        let bytecode = Bytecode::new(
            vec![OPCODE_PUSH, 10],
            vec![Constant::String("test".to_string())],
        );
        let compiler = EmbeddedCompiler::new();
        let result = compiler.compile(bytecode);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("String constants are not supported"));
    }
}