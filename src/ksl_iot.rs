// ksl_iot.rs
// IoT-specific primitives for Kapra Chain and standalone IoT applications
// This module provides IoT support for KSL, enabling device communication and control.
// It integrates with ksl_stdlib_net.rs for networking, ksl_embedded.rs for device compatibility,
// and ksl_async.rs for asynchronous operations.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

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

/// IoT runtime for Kapra Chain with async support.
#[derive(Debug, Clone)]
pub struct IoTRuntime {
    is_embedded: bool,
    power_state: PowerState,
    net_client: Arc<Mutex<Option<NetClient>>>,
}

impl IoTRuntime {
    /// Creates a new IoT runtime instance.
    /// 
    /// # Arguments
    /// * `is_embedded` - Whether the runtime is running on an embedded device
    /// * `net_client` - Optional network client for communication
    pub fn new(is_embedded: bool, net_client: Option<NetClient>) -> Self {
        IoTRuntime {
            is_embedded,
            power_state: PowerState::Awake,
            net_client: Arc::new(Mutex::new(net_client)),
        }
    }

    /// Asynchronously publishes a message to a topic using the configured network protocol.
    /// 
    /// # Arguments
    /// * `topic` - The topic to publish to
    /// * `message` - The message to publish
    /// 
    /// # Returns
    /// A boolean indicating success or failure
    pub async fn publish(&self, topic: &[u8], message: &[u8]) -> bool {
        if self.power_state != PowerState::Awake {
            return false;
        }

        if let Some(client) = &*self.net_client.lock().await {
            match client.send(topic, message).await {
                Ok(_) => true,
                Err(_) => false,
            }
        } else {
            false
        }
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

    /// Asynchronously reads sensor data with error handling.
    /// 
    /// # Arguments
    /// * `sensor_id` - The ID of the sensor to read
    /// 
    /// # Returns
    /// A Result containing the sensor data or an error
    pub async fn read_sensor(&self, sensor_id: u32) -> Result<Vec<u8>, IoTRuntimeError> {
        if self.power_state != PowerState::Awake {
            return Err(IoTRuntimeError::DeviceAsleep);
        }

        // Simulated async sensor reading
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        let mut data = vec![0u8; 8];
        for i in 0..8 {
            data[i] = (sensor_id as u8).wrapping_add(i as u8);
        }
        Ok(data)
    }
}

/// Power state of the device.
#[derive(Debug, Clone, PartialEq)]
pub enum PowerState {
    Awake,
    Asleep(u32), // Duration in milliseconds
}

/// Network client for IoT communication.
#[derive(Debug, Clone)]
pub struct NetClient {
    protocol: NetworkProtocol,
    endpoint: String,
}

impl NetClient {
    /// Creates a new network client.
    /// 
    /// # Arguments
    /// * `protocol` - The network protocol to use
    /// * `endpoint` - The endpoint to connect to
    pub fn new(protocol: NetworkProtocol, endpoint: String) -> Self {
        NetClient { protocol, endpoint }
    }

    /// Sends data using the configured protocol.
    /// 
    /// # Arguments
    /// * `topic` - The topic to send to
    /// * `message` - The message to send
    /// 
    /// # Returns
    /// A Result indicating success or failure
    pub async fn send(&self, topic: &[u8], message: &[u8]) -> Result<(), IoTRuntimeError> {
        match self.protocol {
            NetworkProtocol::CoAP => {
                // Implement CoAP protocol
                Ok(())
            }
            NetworkProtocol::MQTT => {
                // Implement MQTT protocol
                Ok(())
            }
            NetworkProtocol::Custom => {
                // Implement custom protocol
                Ok(())
            }
        }
    }
}

/// Supported network protocols for IoT communication.
#[derive(Debug, Clone, Copy)]
pub enum NetworkProtocol {
    CoAP,
    MQTT,
    Custom,
}

/// Errors that can occur during IoT runtime operations.
#[derive(Debug, Clone)]
pub enum IoTRuntimeError {
    DeviceAsleep,
    NetworkError(String),
    SensorError(String),
}

/// Kapra VM with IoT support and async capabilities.
#[derive(Debug)]
pub struct KapraVM {
    stack: Vec<u64>,
    iot_runtime: IoTRuntime,
    async_tasks: Vec<AsyncTask>,
}

impl KapraVM {
    /// Creates a new Kapra VM instance with IoT support.
    /// 
    /// # Arguments
    /// * `is_embedded` - Whether the VM is running on an embedded device
    /// * `net_client` - Optional network client for communication
    pub fn new(is_embedded: bool, net_client: Option<NetClient>) -> Self {
        KapraVM {
            stack: vec![],
            iot_runtime: IoTRuntime::new(is_embedded, net_client),
            async_tasks: vec![],
        }
    }

    /// Executes IoT bytecode with async support.
    /// 
    /// # Arguments
    /// * `bytecode` - The bytecode to execute
    /// 
    /// # Returns
    /// A Result containing the execution result or an error
    pub async fn execute(&mut self, bytecode: &Bytecode) -> Result<bool, String> {
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
                    let success = self.iot_runtime.publish(topic, message).await;
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
                    match self.iot_runtime.read_sensor(sensor_id).await {
                        Ok(data) => {
                            let const_idx = bytecode.constants.len();
                            self.stack.push(const_idx as u64);
                            let mut new_constants = bytecode.constants.clone();
                            new_constants.push(Constant::ArrayU8(data.len(), data));
                            let new_bytecode = Bytecode::new(bytecode.instructions.clone(), new_constants);
                            *bytecode = new_bytecode;
                        }
                        Err(e) => return Err(format!("Sensor read error: {:?}", e)),
                    }
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

        let mut vm = KapraVM::new(false, None);
        let result = vm.execute(&bytecode).await;
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

        let mut vm = KapraVM::new(false, None);
        let result = vm.execute(&bytecode).await;
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

        let mut vm = KapraVM::new(false, None);
        let result = vm.execute(&bytecode).await;
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