// ksl_simulator.rs
// Simulates KSL program execution in virtual environments for rapid testing,
// emulating blockchain transactions, network latency, and sensor inputs with low overhead.

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

// Simulation environment configuration
#[derive(Debug, Deserialize, Serialize)]
pub struct SimConfig {
    env: String, // e.g., "blockchain", "iot"
    blockchain_latency: Option<Duration>, // Simulated transaction latency
    iot_sensor_data: Option<Vec<f32>>, // Mock sensor readings
    network_delay: Option<Duration>, // Simulated network latency
    log_path: Option<PathBuf>, // Path for simulation logs
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

// Simulation state
pub struct Simulator {
    config: SimConfig,
    vm: KapraVM,
    blockchain_txs: VecDeque<BlockchainTx>,
    sensors: HashMap<u32, Sensor>,
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
        let delay = self.config.network_delay.unwrap_or(Duration::from_millis(50));
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
            _ => {}
        }
        self.execute_instruction(instr)
    }
}

// Simulation data for KapraVM
struct SimulationData {
    tx_index: usize,
    sensor_reading: Option<f32>,
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
            "#[allow(http)]\nfn main() { sha3(\"data\"); }"
        ).unwrap();

        let logs = simulate(
            &temp_file.path().to_path_buf(),
            "blockchain",
            Some(Duration::from_millis(10)),
            None,
            None,
            None,
        ).unwrap();
        assert!(logs.iter().any(|log| log.contains("Simulating blockchain environment")));
        assert!(logs.iter().any(|log| log.contains("Enqueued transaction ID")));
    }

    #[test]
    fn test_simulate_iot() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "#[allow(sensor)]\nfn main() { device.sensor(1); }"
        ).unwrap();

        let logs = simulate(
            &temp_file.path().to_path_buf(),
            "iot",
            None,
            Some(vec![25.0, 26.0]),
            Some(Duration::from_millis(10)),
            None,
        ).unwrap();
        assert!(logs.iter().any(|log| log.contains("Simulating IoT environment")));
        assert!(logs.iter().any(|log| log.contains("Sensor ID 1 reading")));
    }

    #[test]
    fn test_simulate_log_output() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "#[allow(http)]\nfn main() { sha3(\"data\"); }"
        ).unwrap();
        let log_path = temp_file.path().parent().unwrap().join("sim.log");

        let logs = simulate(
            &temp_file.path().to_path_buf(),
            "blockchain",
            Some(Duration::from_millis(10)),
            None,
            None,
            Some(log_path.clone()),
        ).unwrap();
        let log_content = fs::read_to_string(&log_path).unwrap();
        assert!(log_content.contains("Simulating blockchain environment"));
        assert_eq!(logs.len(), log_content.lines().count());
    }

    #[test]
    fn test_simulate_invalid_env() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "fn main() {}").unwrap();

        let result = simulate(
            &temp_file.path().to_path_buf(),
            "invalid",
            None,
            None,
            None,
            None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported environment"));
    }
}
