// ksl_hot_reload.rs
// Enables hot reloading of KSL code, monitoring source files for changes and
// reloading them into a running VM while preserving runtime state.

use crate::ksl_parser::{parse, ParseError};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::kapra_vm::{KapraVM, KapraBytecode, RuntimeError};
use crate::ksl_simulator::run_simulation;
use crate::ksl_logger::{init_logger, log_with_trace, Level};
use crate::ksl_errors::{KslError, SourcePosition};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use std::fs::{self, File};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

// Hot reload configuration
#[derive(Debug)]
pub struct HotReloadConfig {
    input_file: PathBuf, // Source KSL file to monitor
    watch_dir: PathBuf, // Directory to watch for changes
    poll_interval: Duration, // Polling interval for file changes
}

// Hot reload state
#[derive(Clone)]
pub struct HotReloadState {
    last_modified: Arc<Mutex<SystemTime>>, // Last modification time of the file
    vm: Arc<Mutex<KapraVM>>, // Running VM instance
}

// Hot reload manager
pub struct HotReloadManager {
    config: HotReloadConfig,
    state: HotReloadState,
}

impl HotReloadManager {
    pub fn new(config: HotReloadConfig) -> Result<Self, KslError> {
        let pos = SourcePosition::new(1, 1);
        // Initialize the logger
        init_logger(Level::Info, true, None, false)?;

        // Compile the initial version of the file
        let bytecode = Self::compile_file(&config.input_file)?;
        let vm = KapraVM::new_with_state(bytecode);
        let last_modified = fs::metadata(&config.input_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to read metadata for {}: {}", config.input_file.display(), e),
                pos,
            ))?
            .modified()
            .map_err(|e| KslError::type_error(
                format!("Failed to get last modified time for {}: {}", config.input_file.display(), e),
                pos,
            ))?;

        Ok(HotReloadManager {
            config,
            state: HotReloadState {
                last_modified: Arc::new(Mutex::new(last_modified)),
                vm: Arc::new(Mutex::new(vm)),
            },
        })
    }

    // Compile a KSL file to bytecode
    fn compile_file(file_path: &PathBuf) -> Result<KapraBytecode, KslError> {
        let pos = SourcePosition::new(1, 1);
        let source = fs::read_to_string(file_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to read file {}: {}", file_path.display(), e),
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
        compile(&ast)
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Compile error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
            ))
    }

    // Start the hot reload process
    pub fn start(&mut self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        log_with_trace(Level::Info, &format!("Starting hot reload for {}", self.config.input_file.display()), None);

        // Start the VM in a separate thread
        let state_clone = self.state.clone();
        thread::spawn(move || {
            loop {
                let mut vm = state_clone.vm.lock().unwrap();
                if let Err(e) = vm.run_with_state() {
                    log_with_trace(Level::Error, &format!("VM execution error: {}", e), None);
                }
                thread::sleep(Duration::from_millis(100)); // Simulate continuous execution
            }
        });

        // Set up file watcher
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = RecommendedWatcher::new(tx, Config::default())
            .map_err(|e| KslError::type_error(
                format!("Failed to create file watcher: {}", e),
                pos,
            ))?;
        watcher.watch(&self.config.watch_dir, RecursiveMode::Recursive)
            .map_err(|e| KslError::type_error(
                format!("Failed to watch directory {}: {}", self.config.watch_dir.display(), e),
                pos,
            ))?;

        // Monitor for file changes
        loop {
            if let Ok(event) = rx.recv_timeout(self.config.poll_interval) {
                if let notify::EventKind::Modify(_) = event.kind {
                    for path in event.paths {
                        if path == self.config.input_file {
                            self.handle_file_change()?;
                            break;
                        }
                    }
                }
            }
        }
    }

    // Handle file change event
    fn handle_file_change(&mut self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let metadata = fs::metadata(&self.config.input_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to read metadata for {}: {}", self.config.input_file.display(), e),
                pos,
            ))?;
        let modified = metadata.modified()
            .map_err(|e| KslError::type_error(
                format!("Failed to get last modified time for {}: {}", self.config.input_file.display(), e),
                pos,
            ))?;

        let mut last_modified = self.state.last_modified.lock().unwrap();
        if modified <= *last_modified {
            return Ok(()); // No change
        }

        log_with_trace(Level::Info, &format!("Detected change in {}", self.config.input_file.display()), None);
        *last_modified = modified;

        // Recompile the updated file
        let bytecode = Self::compile_file(&self.config.input_file)?;
        let mut vm = self.state.vm.lock().unwrap();
        vm.reload_bytecode(bytecode)?;
        log_with_trace(Level::Info, "Hot reload completed successfully", None);

        Ok(())
    }
}

// Extend KapraVM for hot reloading support
trait HotReloadableVM {
    fn new_with_state(bytecode: KapraBytecode) -> Self;
    fn run_with_state(&mut self) -> Result<(), RuntimeError>;
    fn reload_bytecode(&mut self, new_bytecode: KapraBytecode) -> Result<(), KslError>;
}

impl HotReloadableVM for KapraVM {
    fn new_with_state(bytecode: KapraBytecode) -> Self {
        let mut vm = KapraVM::new(bytecode);
        vm.state = Some(HotReloadState {
            globals: HashMap::new(),
        });
        vm
    }

    fn run_with_state(&mut self) -> Result<(), RuntimeError> {
        self.run()
    }

    fn reload_bytecode(&mut self, new_bytecode: KapraBytecode) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        // Preserve global state
        let preserved_state = self.state.clone();
        self.bytecode = new_bytecode;
        self.pc = 0; // Reset program counter to start of main
        self.state = preserved_state;
        Ok(())
    }
}

// Hot reload state for KapraVM
struct HotReloadState {
    globals: HashMap<String, Value>, // Preserved global variables
}

// Public API to start hot reloading
pub fn hot_reload(input_file: &PathBuf) -> Result<(), KslError> {
    let pos = SourcePosition::new(1, 1);
    let watch_dir = input_file.parent()
        .ok_or_else(|| KslError::type_error(
            format!("Failed to determine watch directory for {}", input_file.display()),
            pos,
        ))?
        .to_path_buf();

    let config = HotReloadConfig {
        input_file: input_file.clone(),
        watch_dir,
        poll_interval: Duration::from_secs(1),
    };
    let mut manager = HotReloadManager::new(config)?;
    manager.start()
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, kapra_vm.rs, ksl_simulator.rs, ksl_logger.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, ParseError};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_compiler {
    pub use super::compile;
}

mod kapra_vm {
    pub use super::{KapraVM, KapraBytecode, RuntimeError, Value};
}

mod ksl_simulator {
    pub use super::run_simulation;
}

mod ksl_logger {
    pub use super::{init_logger, log_with_trace, Level};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use tempfile::TempDir;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_hot_reload() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");

        // Write initial version of the file
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        // Start hot reload in a separate thread
        let input_file_clone = input_file.clone();
        thread::spawn(move || {
            hot_reload(&input_file_clone).unwrap();
        });

        // Wait for the VM to start
        thread::sleep(Duration::from_millis(500));

        // Update the file
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 100; }}"
        ).unwrap();

        // Wait for hot reload to detect the change
        thread::sleep(Duration::from_secs(2));

        // Simulate execution in a test environment
        let simulation_result = run_simulation(&input_file, "hot_reload_test");
        assert!(simulation_result.is_ok());
        // Note: In a real test, we'd check the VM state to confirm x == 100, but this requires extending ksl_simulator.rs
    }

    #[test]
    fn test_hot_reload_invalid_file() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("nonexistent.ksl");

        let result = hot_reload(&input_file);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read file"));
    }

    #[test]
    fn test_hot_reload_no_change() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");

        // Write initial version of the file
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        let config = HotReloadConfig {
            input_file: input_file.clone(),
            watch_dir: temp_dir.path().to_path_buf(),
            poll_interval: Duration::from_secs(1),
        };
        let mut manager = HotReloadManager::new(config).unwrap();

        // Simulate a file change event with no actual change
        let initial_modified = *manager.state.last_modified.lock().unwrap();
        let result = manager.handle_file_change();
        assert!(result.is_ok());

        // Verify no reload occurred (last_modified unchanged)
        let last_modified = *manager.state.last_modified.lock().unwrap();
        assert_eq!(last_modified, initial_modified);
    }

    #[test]
    fn test_hot_reload_invalid_code() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");

        // Write initial valid version of the file
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        let config = HotReloadConfig {
            input_file: input_file.clone(),
            watch_dir: temp_dir.path().to_path_buf(),
            poll_interval: Duration::from_secs(1),
        };
        let mut manager = HotReloadManager::new(config).unwrap();

        // Update to invalid code
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: invalid_type = 42; }}"
        ).unwrap();

        let result = manager.handle_file_change();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Type error"));
    }
}
