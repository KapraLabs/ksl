// ksl_iot.rs
// IoT-specific primitives for Kapra Chain and standalone IoT applications

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
    U32(u32),
    ArrayU8(usize, Vec<u8>), // e.g., array<u8, 32>
}

/// Represents an AST node (aligned with ksl_parser.rs).
#[derive(Debug, Clone)]
pub enum AstNode {
    DeviceCommBlock {
        params: Vec<(String, Type)>, // Parameters (e.g., topic, message)
        return_type: Type,           // Return type (bool)
        body: Vec<AstNode>,          // Body of the device_comm block
    },
    PowerManageBlock {
        params: Vec<(String, Type)>, // Parameters (e.g., sleep_duration)
        return_type: Type,           // Return type (bool)
        body: Vec<AstNode>,          // Body of the power_manage block
    },
    Call {
        name: String,
        args: Vec<AstNode>,
    },
    LiteralU32(u32),
    LiteralArrayU8(usize, Vec<u8>),
}

/// Represents a type (aligned with ksl_types.rs).
#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    Bool,
    U32,
    ArrayU8(usize), // e.g., array<u8, 32>
}

/// IoT runtime for Kapra Chain.
#[derive(Debug, Clone)]
pub struct IoTRuntime {
    is_embedded: bool,
    power_state: PowerState,
}

impl IoTRuntime {
    pub fn new(is_embedded: bool) -> Self {
        IoTRuntime {
            is_embedded,
            power_state: PowerState::Awake,
        }
    }

    /// Publish a message to a topic (simplified CoAP implementation).
    pub fn publish(&self, topic: &Vec<u8>, message: &Vec<u8>) -> bool {
        // Simulated CoAP publish (in reality, this would use net.udp_send from ksl_stdlib_net.rs)
        if self.power_state != PowerState::Awake {
            return false;
        }
        topic.len() == message.len() // Simplified success condition
    }

    /// Sleep for a duration (in milliseconds).
    pub fn sleep(&mut self, duration: u32) -> bool {
        if self.power_state != PowerState::Awake {
            return false;
        }
        self.power_state = PowerState::Asleep(duration);
        true
    }

    /// Wake up the device.
    pub fn wake(&mut self) -> bool {
        match self.power_state {
            PowerState::Asleep(_) => {
                self.power_state = PowerState::Awake;
                true
            }
            PowerState::Awake => false,
        }
    }

    /// Read sensor data (aligned with ksl_stdlib_io.rs).
    pub fn read_sensor(&self, sensor_id: u32) -> Vec<u8> {
        if self.power_state != PowerState::Awake {
            return vec![0; 8];
        }
        // Simulated sensor data
        let mut data = vec![0u8; 8];
        for i in 0..8 {
            data[i] = (sensor_id as u8).wrapping_add(i as u8);
        }
        data
    }
}

/// Power state of the device.
#[derive(Debug, Clone, PartialEq)]
pub enum PowerState {
    Awake,
    Asleep(u32), // Duration in milliseconds
}

/// Kapra VM with IoT support (aligned with kapra_vm.rs).
#[derive(Debug)]
pub struct KapraVM {
    stack: Vec<u64>,
    iot_runtime: IoTRuntime,
    async_tasks: Vec<AsyncTask>,
}

impl KapraVM {
    pub fn new(is_embedded: bool) -> Self {
        KapraVM {
            stack: vec![],
            iot_runtime: IoTRuntime::new(is_embedded),
            async_tasks: vec![],
        }
    }

    pub fn execute(&mut self, bytecode: &Bytecode) -> Result<bool, String> {
        let mut ip = 0;
        while ip < bytecode.instructions.len() {
            let instr = bytecode.instructions[ip];
            ip += 1;

            match instr {
                OPCODE_PUBLISH => {
                    if self.stack.len() < 2 {
                        return Err("Not enough values on stack for PUBLISH".to_string());
                    }
                    let message_idx = self.stack.pop().unwrap() as usize;
                    let topic_idx = self.stack.pop().unwrap() as usize;
                    let topic = match &bytecode.constants[topic_idx] {
                        Constant::ArrayU8(_, data) => data,
                        _ => return Err("Invalid type for PUBLISH topic".to_string()),
                    };
                    let message = match &bytecode.constants[message_idx] {
                        Constant::ArrayU8(_, data) => data,
                        _ => return Err("Invalid type for PUBLISH message".to_string()),
                    };
                    let success = self.iot_runtime.publish(topic, message);
                    self.async_tasks.push(AsyncTask::Publish(topic.clone(), message.clone()));
                    self.stack.push(success as u64);
                }
                OPCODE_SLEEP => {
                    if self.stack.len() < 1 {
                        return Err("Not enough values on stack for SLEEP".to_string());
                    }
                    let duration = self.stack.pop().unwrap() as u32;
                    let success = self.iot_runtime.sleep(duration);
                    self.stack.push(success as u64);
                }
                OPCODE_WAKE => {
                    let success = self.iot_runtime.wake();
                    self.stack.push(success as u64);
                }
                OPCODE_READ_SENSOR => {
                    if self.stack.len() < 1 {
                        return Err("Not enough values on stack for READ_SENSOR".to_string());
                    }
                    let sensor_id = self.stack.pop().unwrap() as u32;
                    let data = self.iot_runtime.read_sensor(sensor_id);
                    let const_idx = bytecode.constants.len();
                    self.stack.push(const_idx as u64);
                    let mut new_constants = bytecode.constants.clone();
                    new_constants.push(Constant::ArrayU8(data.len(), data));
                    let new_bytecode = Bytecode::new(bytecode.instructions.clone(), new_constants);
                    *bytecode = new_bytecode;
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
                    return Err("IoT operation failed".to_string());
                }
                _ => return Err(format!("Unsupported opcode: {}", instr)),
            }
        }

        if self.stack.len() != 1 {
            return Err("IoT block must return exactly one boolean value".to_string());
        }
        Ok(self.stack[0] != 0)
    }
}

/// Represents an async task (aligned with ksl_async.rs).
#[derive(Debug, Clone)]
pub enum AsyncTask {
    Publish(Vec<u8>, Vec<u8>),
}

/// IoT compiler for Kapra Chain.
pub struct IoTCompiler {
    is_embedded: bool,
}

impl IoTCompiler {
    pub fn new(is_embedded: bool) -> Self {
        IoTCompiler { is_embedded }
    }

    /// Compile an IoT block into bytecode.
    pub fn compile(&self, node: &AstNode) -> Result<Bytecode, String> {
        match node {
            AstNode::DeviceCommBlock { params, return_type, body } => {
                // Validate parameters and return type
                if params.len() != 2 {
                    return Err("DeviceComm block must have exactly 2 parameters: topic, message".to_string());
                }
                if params[0].0 != "topic" || !matches!(params[0].1, Type::ArrayU8(32)) {
                    return Err("First parameter must be 'topic: array<u8, 32]'".to_string());
                }
                if params[1].0 != "message" || !matches!(params[1].1, Type::ArrayU8(32)) {
                    return Err("Second parameter must be 'message: array<u8, 32]'".to_string());
                }
                if !matches!(return_type, Type::Bool) {
                    return Err("DeviceComm block must return bool".to_string());
                }

                let mut bytecode = Bytecode::new(vec![], vec![]);

                // Compile the body
                for stmt in body {
                    let stmt_bytecode = self.compile_stmt(stmt)?;
                    bytecode.extend(stmt_bytecode);
                }

                Ok(bytecode)
            }
            AstNode::PowerManageBlock { params, return_type, body } => {
                // Validate parameters and return type
                if params.len() != 1 {
                    return Err("PowerManage block must have exactly 1 parameter: sleep_duration".to_string());
                }
                if params[0].0 != "sleep_duration" || !matches!(params[0].1, Type::U32) {
                    return Err("Parameter must be 'sleep_duration: u32'".to_string());
                }
                if !matches!(return_type, Type::Bool) {
                    return Err("PowerManage block must return bool".to_string());
                }

                let mut bytecode = Bytecode::new(vec![], vec![]);

                // Compile the body
                for stmt in body {
                    let stmt_bytecode = self.compile_stmt(stmt)?;
                    bytecode.extend(stmt_bytecode);
                }

                Ok(bytecode)
            }
            _ => Err("Only IoT blocks can be compiled at the top level".to_string()),
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
                    "publish" => {
                        bytecode.instructions.push(OPCODE_PUBLISH);
                    }
                    "sleep" => {
                        bytecode.instructions.push(OPCODE_SLEEP);
                    }
                    "wake" => {
                        bytecode.instructions.push(OPCODE_WAKE);
                    }
                    "device.sensor" => {
                        bytecode.instructions.push(OPCODE_READ_SENSOR);
                    }
                    _ => return Err(format!("Unsupported function in IoT block: {}", name)),
                }
                Ok(bytecode)
            }
            _ => Err("Unsupported statement in IoT block".to_string()),
        }
    }

    fn compile_expr(&self, expr: &AstNode) -> Result<Bytecode, String> {
        match expr {
            AstNode::LiteralU32(val) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::U32(*val));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::LiteralArrayU8(size, data) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::ArrayU8(*size, data.clone()));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::Call { name, args } => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                for arg in args {
                    let arg_bytecode = self.compile_expr(arg)?;
                    bytecode.extend(arg_bytecode);
                }
                if name == "publish" {
                    bytecode.instructions.push(OPCODE_PUBLISH);
                } else if name == "sleep" {
                    bytecode.instructions.push(OPCODE_SLEEP);
                } else if name == "wake" {
                    bytecode.instructions.push(OPCODE_WAKE);
                } else if name == "device.sensor" {
                    bytecode.instructions.push(OPCODE_READ_SENSOR);
                } else {
                    return Err(format!("Unsupported expression in IoT block: {}", name));
                }
                Ok(bytecode)
            }
            _ => Err("Unsupported expression in IoT block".to_string()),
        }
    }
}

const OPCODE_PUBLISH: u8 = 0x01;
const OPCODE_SLEEP: u8 = 0x02;
const OPCODE_WAKE: u8 = 0x03;
const OPCODE_READ_SENSOR: u8 = 0x04;
const OPCODE_PUSH: u8 = 0x05;
const OPCODE_FAIL: u8 = 0x06;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_comm_block_compilation() {
        let device_comm_node = AstNode::DeviceCommBlock {
            params: vec![
                ("topic".to_string(), Type::ArrayU8(32)),
                ("message".to_string(), Type::ArrayU8(32)),
            ],
            return_type: Type::Bool,
            body: vec![
                AstNode::Call {
                    name: "publish".to_string(),
                    args: vec![
                        AstNode::LiteralArrayU8(32, vec![1; 32]),
                        AstNode::LiteralArrayU8(32, vec![2; 32]),
                    ],
                },
            ],
        };

        let compiler = IoTCompiler::new(false);
        let bytecode = compiler.compile(&device_comm_node).unwrap();
        assert!(!bytecode.instructions.is_empty());
        assert!(bytecode.instructions.contains(&OPCODE_PUBLISH));
    }

    #[test]
    fn test_power_manage_block_compilation() {
        let power_manage_node = AstNode::PowerManageBlock {
            params: vec![("sleep_duration".to_string(), Type::U32)],
            return_type: Type::Bool,
            body: vec![
                AstNode::Call {
                    name: "sleep".to_string(),
                    args: vec![AstNode::LiteralU32(1000)],
                },
                AstNode::Call {
                    name: "wake".to_string(),
                    args: vec![],
                },
            ],
        };

        let compiler = IoTCompiler::new(false);
        let bytecode = compiler.compile(&power_manage_node).unwrap();
        assert!(!bytecode.instructions.is_empty());
        assert!(bytecode.instructions.contains(&OPCODE_SLEEP));
        assert!(bytecode.instructions.contains(&OPCODE_WAKE));
    }

    #[test]
    fn test_device_comm_execution() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::ArrayU8(32, vec![1; 32]), // topic
            Constant::ArrayU8(32, vec![2; 32]), // message
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,           // Push topic
            OPCODE_PUSH, 1,           // Push message
            OPCODE_PUBLISH,           // Publish message
        ]);

        let mut vm = KapraVM::new(false);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(vm.async_tasks.len(), 1);
    }

    #[test]
    fn test_power_manage_execution() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 1000,        // Push sleep duration
            OPCODE_SLEEP,             // Sleep
            OPCODE_WAKE,              // Wake
        ]);

        let mut vm = KapraVM::new(false);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(vm.iot_runtime.power_state, PowerState::Awake);
    }

    #[test]
    fn test_sensor_reading() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 1,           // Push sensor_id
            OPCODE_READ_SENSOR,       // Read sensor data
        ]);

        let mut vm = KapraVM::new(false);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(bytecode.constants.len(), 1);
        let sensor_data = match &bytecode.constants[0] {
            Constant::ArrayU8(_, data) => data,
            _ => panic!("Invalid sensor data"),
        };
        assert_eq!(sensor_data, &vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_invalid_device_comm_params() {
        let device_comm_node = AstNode::DeviceCommBlock {
            params: vec![("topic".to_string(), Type::ArrayU8(32))],
            return_type: Type::Bool,
            body: vec![],
        };

        let compiler = IoTCompiler::new(false);
        let result = compiler.compile(&device_comm_node);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must have exactly 2 parameters"));
    }
}