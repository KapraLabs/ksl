// ksl_simulator.rs
// Simulates KSL program execution in virtual environments for rapid testing,
// emulating blockchain transactions, network latency, and sensor inputs with low overhead.
// 
// Features:
// - Blockchain transaction simulation with configurable latency
// - IoT sensor data simulation with network delay
// - HTTP request/response simulation
// - Network latency and error simulation
// - Comprehensive logging and metrics
// 
// Usage:
//   let config = SimConfig {
//       env: "blockchain".to_string(),
//       blockchain_latency: Some(Duration::from_millis(100)),
//       iot_sensor_data: Some(vec![1.0, 2.0, 3.0]),
//       network_delay: Some(Duration::from_millis(50)),
//       http_responses: Some(vec![
//           HttpResponse { status: 200, body: "OK".to_string() },
//           HttpResponse { status: 404, body: "Not Found".to_string() },
//       ]),
//       log_path: Some(PathBuf::from("simulation.log")),
//   };
//   let result = simulate(&file_path, config)?;

use crate::ksl_parser::{parse, AstNode, ParseError};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::{KapraBytecode, KapraOpCode, KapraInstruction};
use crate::kapra_vm::{KapraVM, RuntimeError};
use crate::ksl_sandbox::Sandbox;
use crate::ksl_errors::{KslError, SourcePosition};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use rand::Rng;

/// HTTP response for simulation
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
    pub headers: HashMap<String, String>,
}

impl Default for HttpResponse {
    fn default() -> Self {
        HttpResponse {
            status: 200,
            body: "OK".to_string(),
            headers: HashMap::new(),
        }
    }
}

/// Network simulation configuration
#[derive(Debug, Deserialize, Serialize)]
pub struct NetworkConfig {
    /// Simulated network latency
    pub latency: Duration,
    /// Probability of network errors (0.0 to 1.0)
    pub error_rate: f32,
    /// Maximum number of concurrent connections
    pub max_connections: u32,
    /// Bandwidth limit in bytes per second
    pub bandwidth_limit: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            latency: Duration::from_millis(50),
            error_rate: 0.1,
            max_connections: 10,
            bandwidth_limit: 1024 * 1024, // 1 MB/s
        }
    }
}

/// Simulation environment configuration
#[derive(Debug, Deserialize, Serialize)]
pub struct SimConfig {
    /// Simulation environment type (e.g., "blockchain", "iot", "network")
    pub env: String,
    /// Simulated blockchain transaction latency
    pub blockchain_latency: Option<Duration>,
    /// Mock sensor readings for IoT simulation
    pub iot_sensor_data: Option<Vec<f32>>,
    /// Network simulation configuration
    pub network_config: Option<NetworkConfig>,
    /// Predefined HTTP responses for simulation
    pub http_responses: Option<Vec<HttpResponse>>,
    /// Path for simulation logs
    pub log_path: Option<PathBuf>,
}

// Simulated blockchain transaction
#[derive(Debug, Clone)]
struct BlockchainTx {
    id: u64,
    data: Vec<u8>,
    timestamp: Instant,
}

// Simulated IoT sensor
#[derive(Debug, Clone)]
struct Sensor {
    id: u32,
    readings: VecDeque<f32>,
}

/// Simulated HTTP request
#[derive(Debug, Clone)]
struct HttpRequest {
    url: String,
    method: String,
    headers: HashMap<String, String>,
    body: Option<Vec<u8>>,
    timestamp: Instant,
}

/// Network simulation state
#[derive(Debug)]
struct NetworkState {
    active_connections: u32,
    total_bytes_sent: u64,
    total_bytes_received: u64,
    request_queue: VecDeque<HttpRequest>,
    response_queue: VecDeque<HttpResponse>,
}

impl Default for NetworkState {
    fn default() -> Self {
        NetworkState {
            active_connections: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            request_queue: VecDeque::new(),
            response_queue: VecDeque::new(),
        }
    }
}

/// Simulation state
pub struct Simulator {
    config: SimConfig,
    vm: KapraVM,
    blockchain_txs: VecDeque<BlockchainTx>,
    sensors: HashMap<u32, Sensor>,
    network_state: NetworkState,
    logs: Vec<String>,
}

impl Simulator {
    pub fn new(config: SimConfig, bytecode: KapraBytecode) -> Self {
        let vm = KapraVM::new_with_simulation(bytecode);
        let sensors = config.iot_sensor_data.as_ref().map(|data| {
            let mut map = HashMap::new();
            map.insert(1, Sensor {
                id: 1,
                readings: data.clone().into_iter().collect(),
            });
            map
        }).unwrap_or_default();

        Simulator {
            config,
            vm,
            blockchain_txs: VecDeque::new(),
            sensors,
            network_state: NetworkState::default(),
            logs: vec![],
        }
    }

    // Run simulation in a sandboxed environment
    pub fn run(&mut self, file: &PathBuf) -> Result<Vec<String>, KslError> {
        let pos = SourcePosition::new(1, 1);
        // Validate sandbox
        let mut sandbox = Sandbox::new();
        sandbox.run_sandbox(file)
            .map_err(|e| KslError::type_error(
                e.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"),
                pos,
            ))?;

        // Simulate execution
        match self.config.env.as_str() {
            "blockchain" => self.simulate_blockchain(),
            "iot" => self.simulate_iot(),
            "network" => self.simulate_network(),
            _ => Err(KslError::type_error(
                format!("Unsupported environment: {}", self.config.env),
                pos,
            )),
        }?;

        // Write logs if specified
        if let Some(log_path) = &self.config.log_path {
            fs::write(log_path, self.logs.join("\n"))
                .map_err(|e| KslError::type_error(
                    format!("Failed to write logs to {}: {}", log_path.display(), e),
                    pos,
                ))?;
        }

        Ok(self.logs.clone())
    }

    // Simulate blockchain environment
    fn simulate_blockchain(&mut self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let latency = self.config.blockchain_latency.unwrap_or(Duration::from_millis(100));
        self.logs.push("Simulating blockchain environment".to_string());

        // Simulate transactions
        for i in 0..5 {
            let tx = BlockchainTx {
                id: i + 1,
                data: rand::thread_rng().gen::<[u8; 32]>().to_vec(),
                timestamp: Instant::now(),
            };
            self.blockchain_txs.push_back(tx);
            self.logs.push(format!("Enqueued transaction ID {}", i + 1));
            std::thread::sleep(latency);
        }

        // Run VM with simulated inputs
        self.vm.run()
            .map_err(|e| KslError::type_error(
                format!("Blockchain simulation error: {}", e),
                pos,
            ))?;

        Ok(())
    }

    // Simulate IoT environment
    fn simulate_iot(&mut self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let delay = self.config.network_config.as_ref().map(|config| config.latency).unwrap_or(Duration::from_millis(50));
        self.logs.push("Simulating IoT environment".to_string());

        // Simulate sensor readings
        if let Some(sensor) = self.sensors.get_mut(&1) {
            while let Some(reading) = sensor.readings.pop_front() {
                self.logs.push(format!("Sensor ID 1 reading: {}", reading));
                std::thread::sleep(delay);
            }
        }

        // Run VM with simulated inputs
        self.vm.run()
            .map_err(|e| KslError::type_error(
                format!("IoT simulation error: {}", e),
                pos,
            ))?;

        Ok(())
    }

    // Simulate network environment
    fn simulate_network(&mut self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let network_config = self.config.network_config.as_ref().unwrap_or(&NetworkConfig::default());
        self.logs.push("Simulating network environment".to_string());

        // Process HTTP requests
        while let Some(request) = self.network_state.request_queue.pop_front() {
            // Check connection limit
            if self.network_state.active_connections >= network_config.max_connections {
                self.logs.push("Connection limit reached".to_string());
                continue;
            }

            // Simulate network latency
            std::thread::sleep(network_config.latency);

            // Simulate network errors
            if rand::thread_rng().gen::<f32>() < network_config.error_rate {
                self.logs.push(format!("Network error for request to {}", request.url));
                continue;
            }

            // Get response from predefined responses or generate default
            let response = self.config.http_responses.as_ref()
                .and_then(|responses| responses.get(0))
                .cloned()
                .unwrap_or_default();

            // Update network state
            self.network_state.active_connections += 1;
            self.network_state.total_bytes_sent += request.body.as_ref().map(|b| b.len() as u64).unwrap_or(0);
            self.network_state.total_bytes_received += response.body.len() as u64;

            // Log request/response
            self.logs.push(format!(
                "HTTP {} {} -> {} {}",
                request.method,
                request.url,
                response.status,
                response.body
            ));

            // Queue response
            self.network_state.response_queue.push_back(response);
            self.network_state.active_connections -= 1;
        }

        // Run VM with simulated inputs
        self.vm.run()
            .map_err(|e| KslError::type_error(
                format!("Network simulation error: {}", e),
                pos,
            ))?;

        Ok(())
    }
}

// Extend KapraVM for simulation
trait SimVM {
    fn new_with_simulation(bytecode: KapraBytecode) -> Self;
    fn simulate_instruction(&mut self, instr: &KapraInstruction, simulator: &mut Simulator) -> Result<(), RuntimeError>;
}

impl SimVM for KapraVM {
    fn new_with_simulation(bytecode: KapraBytecode) -> Self {
        let mut vm = KapraVM::new(bytecode);
        vm.simulation_data = Some(SimulationData {
            tx_index: 0,
            sensor_reading: None,
            http_response: None,
        });
        vm
    }

    fn simulate_instruction(&mut self, instr: &KapraInstruction, simulator: &mut Simulator) -> Result<(), RuntimeError> {
        match instr.opcode {
            KapraOpCode::Sha3 | KapraOpCode::BlsVerify => {
                if simulator.config.env == "blockchain" {
                    if let Some(tx) = simulator.blockchain_txs.get(self.simulation_data.as_ref().unwrap().tx_index) {
                        simulator.logs.push(format!("Processed transaction ID {}", tx.id));
                        self.simulation_data.as_mut().unwrap().tx_index += 1;
                    }
                }
            }
            KapraOpCode::DeviceSensor => {
                if simulator.config.env == "iot" {
                    if let Some(sensor) = simulator.sensors.get(&1) {
                        if let Some(reading) = sensor.readings.front() {
                            self.simulation_data.as_mut().unwrap().sensor_reading = Some(*reading);
                            simulator.logs.push(format!("Simulated sensor reading: {}", reading));
                        }
                    }
                }
            }
            KapraOpCode::HttpGet => {
                if simulator.config.env == "network" {
                    if let Some(response) = simulator.network_state.response_queue.pop_front() {
                        self.simulation_data.as_mut().unwrap().http_response = Some(response);
                        simulator.logs.push("Processed HTTP response".to_string());
                    }
                }
            }
            _ => {}
        }
        self.execute_instruction(instr)
    }
}

// Simulation data for KapraVM
struct SimulationData {
    tx_index: usize,
    sensor_reading: Option<f32>,
    http_response: Option<HttpResponse>,
}

// Public API to run simulation
pub fn simulate(file: &PathBuf, env: &str, blockchain_latency: Option<Duration>, iot_sensor_data: Option<Vec<f32>>, network_delay: Option<Duration>, log_path: Option<PathBuf>) -> Result<Vec<String>, KslError> {
    let pos = SourcePosition::new(1, 1);
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
    check(&ast)
        .map_err(|errors| KslError::type_error(
            errors.into_iter()
                .map(|e| format!("Type error at position {}: {}", e.position, e.message))
                .collect::<Vec<_>>()
                .join("\n"),
            pos,
        ))?;
    let bytecode = compile(&ast)
        .map_err(|errors| KslError::type_error(
            errors.into_iter()
                .map(|e| format!("Compile error at position {}: {}", e.position, e.message))
                .collect::<Vec<_>>()
                .join("\n"),
            pos,
        ))?;

    let config = SimConfig {
        env: env.to_string(),
        blockchain_latency,
        iot_sensor_data,
        network_delay,
        log_path,
    };
    let mut simulator = Simulator::new(config, bytecode);
    simulator.run(file)
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_bytecode.rs, kapra_vm.rs, ksl_sandbox.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ParseError};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_compiler {
    pub use super::compile;
}

mod ksl_bytecode {
    pub use super::{KapraBytecode, KapraOpCode, KapraInstruction};
}

mod kapra_vm {
    pub use super::{KapraVM, RuntimeError};
}

mod ksl_sandbox {
    pub use super::Sandbox;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_simulate_blockchain() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn main() { 
                let tx = blockchain.new_tx();
                let hash = sha3(tx);
                assert(bls_verify(hash));
            }"
        ).unwrap();

        let config = SimConfig {
            env: "blockchain".to_string(),
            blockchain_latency: Some(Duration::from_millis(100)),
            iot_sensor_data: None,
            network_config: None,
            http_responses: None,
            log_path: None,
        };

        let result = simulate(&temp_file.path().to_path_buf(), config);
        assert!(result.is_ok());
        let logs = result.unwrap();
        assert!(logs.iter().any(|log| log.contains("Processed transaction")));
    }

    #[test]
    fn test_simulate_iot() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn main() { 
                let reading = device.sensor();
                assert(reading > 0.0);
            }"
        ).unwrap();

        let config = SimConfig {
            env: "iot".to_string(),
            blockchain_latency: None,
            iot_sensor_data: Some(vec![1.0, 2.0, 3.0]),
            network_config: None,
            http_responses: None,
            log_path: None,
        };

        let result = simulate(&temp_file.path().to_path_buf(), config);
        assert!(result.is_ok());
        let logs = result.unwrap();
        assert!(logs.iter().any(|log| log.contains("Simulated sensor reading")));
    }

    #[test]
    fn test_simulate_network() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn main() { 
                let response = http.get(\"https://example.com\");
                assert(response.status == 200);
            }"
        ).unwrap();

        let config = SimConfig {
            env: "network".to_string(),
            blockchain_latency: None,
            iot_sensor_data: None,
            network_config: Some(NetworkConfig {
                latency: Duration::from_millis(50),
                error_rate: 0.0,
                max_connections: 10,
                bandwidth_limit: 1024 * 1024,
            }),
            http_responses: Some(vec![HttpResponse::default()]),
            log_path: None,
        };

        let result = simulate(&temp_file.path().to_path_buf(), config);
        assert!(result.is_ok());
        let logs = result.unwrap();
        assert!(logs.iter().any(|log| log.contains("HTTP GET")));
    }

    #[test]
    fn test_simulate_network_errors() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn main() { 
                let response = http.get(\"https://example.com\");
                assert(response.status == 200);
            }"
        ).unwrap();

        let config = SimConfig {
            env: "network".to_string(),
            blockchain_latency: None,
            iot_sensor_data: None,
            network_config: Some(NetworkConfig {
                latency: Duration::from_millis(50),
                error_rate: 1.0, // Always fail
                max_connections: 10,
                bandwidth_limit: 1024 * 1024,
            }),
            http_responses: Some(vec![HttpResponse::default()]),
            log_path: None,
        };

        let result = simulate(&temp_file.path().to_path_buf(), config);
        assert!(result.is_ok());
        let logs = result.unwrap();
        assert!(logs.iter().any(|log| log.contains("Network error")));
    }

    #[test]
    fn test_simulate_connection_limit() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn main() { 
                for i in 0..20 {
                    let _ = http.get(\"https://example.com\");
                }
            }"
        ).unwrap();

        let config = SimConfig {
            env: "network".to_string(),
            blockchain_latency: None,
            iot_sensor_data: None,
            network_config: Some(NetworkConfig {
                latency: Duration::from_millis(50),
                error_rate: 0.0,
                max_connections: 5,
                bandwidth_limit: 1024 * 1024,
            }),
            http_responses: Some(vec![HttpResponse::default()]),
            log_path: None,
        };

        let result = simulate(&temp_file.path().to_path_buf(), config);
        assert!(result.is_ok());
        let logs = result.unwrap();
        assert!(logs.iter().any(|log| log.contains("Connection limit reached")));
    }

    #[test]
    fn test_simulate_log_output() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn main() { 
                let response = http.get(\"https://example.com\");
                let reading = device.sensor();
            }"
        ).unwrap();

        let log_file = NamedTempFile::new().unwrap();
        let config = SimConfig {
            env: "network".to_string(),
            blockchain_latency: None,
            iot_sensor_data: Some(vec![1.0]),
            network_config: Some(NetworkConfig::default()),
            http_responses: Some(vec![HttpResponse::default()]),
            log_path: Some(log_file.path().to_path_buf()),
        };

        let result = simulate(&temp_file.path().to_path_buf(), config);
        assert!(result.is_ok());
        assert!(log_file.path().exists());
    }

    #[test]
    fn test_simulate_invalid_env() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn main() { }"
        ).unwrap();

        let config = SimConfig {
            env: "invalid".to_string(),
            blockchain_latency: None,
            iot_sensor_data: None,
            network_config: None,
            http_responses: None,
            log_path: None,
        };

        let result = simulate(&temp_file.path().to_path_buf(), config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported environment"));
    }
}
