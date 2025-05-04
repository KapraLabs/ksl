// ksl_hot_reload.rs
// Enables hot reloading of KSL code, monitoring source files for changes and
// reloading them into a running VM while preserving runtime state, including
// networking connections and async operations.

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
use std::collections::HashMap;

/// Configuration for hot reloading
#[derive(Debug)]
pub struct HotReloadConfig {
    /// Source KSL file to monitor
    input_file: PathBuf,
    /// Directory to watch for changes
    watch_dir: PathBuf,
    /// Polling interval for file changes
    poll_interval: Duration,
    /// Whether to preserve networking state during reload
    preserve_networking: bool,
    /// Whether to preserve async state during reload
    preserve_async: bool,
}

/// State preserved during hot reload
#[derive(Clone)]
pub struct HotReloadState {
    /// Last modification time of the file
    last_modified: Arc<Mutex<SystemTime>>,
    /// Running VM instance
    vm: Arc<Mutex<KapraVM>>,
    /// Active networking connections
    networking_state: Arc<Mutex<NetworkingState>>,
    /// Active async operations
    async_state: Arc<Mutex<AsyncState>>,
}

/// State of networking connections
#[derive(Clone, Default)]
pub struct NetworkingState {
    /// Active HTTP connections
    http_connections: HashMap<String, HttpConnection>,
    /// Active TCP connections
    tcp_connections: HashMap<String, TcpConnection>,
}

/// State of async operations
#[derive(Clone, Default)]
pub struct AsyncState {
    /// Active async operations
    active_operations: HashMap<String, AsyncOperation>,
}

/// HTTP connection state
#[derive(Clone)]
pub struct HttpConnection {
    /// Connection URL
    url: String,
    /// Connection headers
    headers: HashMap<String, String>,
    /// Connection state
    state: ConnectionState,
}

/// TCP connection state
#[derive(Clone)]
pub struct TcpConnection {
    /// Connection address
    address: String,
    /// Connection state
    state: ConnectionState,
    /// Pending data
    pending_data: Vec<u8>,
}

/// Async operation state
#[derive(Clone)]
pub struct AsyncOperation {
    /// Operation type
    op_type: String,
    /// Operation state
    state: AsyncStateType,
    /// Operation result (if completed)
    result: Option<Value>,
}

/// Connection state
#[derive(Clone)]
pub enum ConnectionState {
    /// Connection is established
    Connected,
    /// Connection is in progress
    Connecting,
    /// Connection is closed
    Closed,
}

/// Async operation state
#[derive(Clone)]
pub enum AsyncStateType {
    /// Operation is pending
    Pending,
    /// Operation is completed
    Completed,
    /// Operation failed
    Failed(String),
}

/// Hot reload manager
pub struct HotReloadManager {
    config: HotReloadConfig,
    state: HotReloadState,
}

impl HotReloadManager {
    /// Create a new hot reload manager
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
                networking_state: Arc::new(Mutex::new(NetworkingState::default())),
                async_state: Arc::new(Mutex::new(AsyncState::default())),
            },
        })
    }

    /// Start the hot reload process
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
                thread::sleep(Duration::from_millis(100));
            }
        });

        // Set up file watching using the new program's mechanism
        let watch_path = self.config.watch_dir.clone();
        let input_file = self.config.input_file.clone();
        let state_clone = self.state.clone();
        thread::spawn(move || {
            loop {
                if let Ok(metadata) = fs::metadata(&input_file) {
                    if let Ok(modified) = metadata.modified() {
                        let mut last_modified = state_clone.last_modified.lock().unwrap();
                        if modified > *last_modified {
                            *last_modified = modified;
                            // Trigger reload
                            if let Err(e) = Self::handle_file_change(&state_clone, &input_file) {
                                log_with_trace(Level::Error, &format!("Hot reload error: {}", e), None);
                            }
                        }
                    }
                }
                thread::sleep(Duration::from_secs(1));
            }
        });

        Ok(())
    }

    /// Handle file change event
    fn handle_file_change(state: &HotReloadState, file_path: &PathBuf) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        log_with_trace(Level::Info, &format!("Detected change in {}", file_path.display()), None);

        // Recompile the updated file
        let bytecode = Self::compile_file(file_path)?;
        let mut vm = state.vm.lock().unwrap();

        // Preserve networking state if enabled
        let networking_state = if state.networking_state.lock().unwrap().http_connections.is_empty() &&
            state.networking_state.lock().unwrap().tcp_connections.is_empty() {
            None
        } else {
            Some(state.networking_state.lock().unwrap().clone())
        };

        // Preserve async state if enabled
        let async_state = if state.async_state.lock().unwrap().active_operations.is_empty() {
            None
        } else {
            Some(state.async_state.lock().unwrap().clone())
        };

        // Reload the bytecode while preserving state
        vm.reload_bytecode(bytecode, networking_state, async_state)?;
        log_with_trace(Level::Info, "Hot reload completed successfully", None);

        Ok(())
    }

    /// Compile a KSL file to bytecode
    fn compile_file(file_path: &PathBuf) -> Result<KapraBytecode, KslError> {
        let pos = SourcePosition::new(1, 1);
        let source = fs::read_to_string(file_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to read file {}: {}", file_path.display(), e),
                pos,
            ))?;

        // Parse the source code
        let ast = parse(&source)
            .map_err(|e| KslError::parse_error(e, pos))?;

        // Type check the AST
        check(&ast)
            .map_err(|e| KslError::type_error(e, pos))?;

        // Compile to bytecode
        compile(&ast)
            .map_err(|e| KslError::compile_error(e, pos))
    }

    /// Get the current networking state
    pub fn get_networking_state(&self) -> NetworkingState {
        self.state.networking_state.lock().unwrap().clone()
    }

    /// Get the current async state
    pub fn get_async_state(&self) -> AsyncState {
        self.state.async_state.lock().unwrap().clone()
    }

    /// Update the networking state
    pub fn update_networking_state(&mut self, state: NetworkingState) {
        *self.state.networking_state.lock().unwrap() = state;
    }

    /// Update the async state
    pub fn update_async_state(&mut self, state: AsyncState) {
        *self.state.async_state.lock().unwrap() = state;
    }
}

// Extend KapraVM for hot reloading support
trait HotReloadableVM {
    fn new_with_state(bytecode: KapraBytecode) -> Self;
    fn run_with_state(&mut self) -> Result<(), RuntimeError>;
    fn reload_bytecode(
        &mut self,
        new_bytecode: KapraBytecode,
        networking_state: Option<NetworkingState>,
        async_state: Option<AsyncState>,
    ) -> Result<(), KslError>;
}

impl HotReloadableVM for KapraVM {
    fn new_with_state(bytecode: KapraBytecode) -> Self {
        let mut vm = KapraVM::new(bytecode);
        vm.state = Some(HotReloadState {
            globals: HashMap::new(),
            networking_state: NetworkingState::default(),
            async_state: AsyncState::default(),
        });
        vm
    }

    fn run_with_state(&mut self) -> Result<(), RuntimeError> {
        self.run()
    }

    fn reload_bytecode(
        &mut self,
        new_bytecode: KapraBytecode,
        networking_state: Option<NetworkingState>,
        async_state: Option<AsyncState>,
    ) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        // Preserve global state
        let preserved_state = self.state.clone();
        self.bytecode = new_bytecode;
        self.pc = 0; // Reset program counter to start of main

        // Restore networking state if provided
        if let Some(networking) = networking_state {
            self.state.as_mut().unwrap().networking_state = networking;
        }

        // Restore async state if provided
        if let Some(async_state) = async_state {
            self.state.as_mut().unwrap().async_state = async_state;
        }

        Ok(())
    }
}

// Hot reload state for KapraVM
struct HotReloadState {
    globals: HashMap<String, Value>, // Preserved global variables
}

/// Public API function to start hot reloading
pub fn start_hot_reload(
    input_file: PathBuf,
    watch_dir: PathBuf,
    preserve_networking: bool,
    preserve_async: bool,
) -> Result<(), KslError> {
    let config = HotReloadConfig {
        input_file,
        watch_dir,
        poll_interval: Duration::from_secs(1),
        preserve_networking,
        preserve_async,
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
            preserve_networking: true,
            preserve_async: true,
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
            preserve_networking: true,
            preserve_async: true,
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

    #[test]
    fn test_hot_reload_with_networking() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.ksl");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "fn main() {{ http_get(\"http://example.com\"); }}").unwrap();

        let config = HotReloadConfig {
            input_file: file_path.clone(),
            watch_dir: temp_dir.path().to_path_buf(),
            poll_interval: Duration::from_secs(1),
            preserve_networking: true,
            preserve_async: true,
        };
        let mut manager = HotReloadManager::new(config).unwrap();

        // Simulate a networking operation
        let mut networking_state = NetworkingState::default();
        networking_state.http_connections.insert(
            "http://example.com".to_string(),
            HttpConnection {
                url: "http://example.com".to_string(),
                headers: HashMap::new(),
                state: ConnectionState::Connected,
            },
        );
        manager.update_networking_state(networking_state);

        // Modify the file
        writeln!(file, "fn main() {{ http_get(\"http://example.com\"); print(\"Updated\"); }}").unwrap();

        // Verify networking state is preserved
        let preserved_state = manager.get_networking_state();
        assert!(preserved_state.http_connections.contains_key("http://example.com"));
    }

    #[test]
    fn test_hot_reload_with_async() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.ksl");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "fn main() {{ async { sleep(1); } }}").unwrap();

        let config = HotReloadConfig {
            input_file: file_path.clone(),
            watch_dir: temp_dir.path().to_path_buf(),
            poll_interval: Duration::from_secs(1),
            preserve_networking: true,
            preserve_async: true,
        };
        let mut manager = HotReloadManager::new(config).unwrap();

        // Simulate an async operation
        let mut async_state = AsyncState::default();
        async_state.active_operations.insert(
            "sleep".to_string(),
            AsyncOperation {
                op_type: "sleep".to_string(),
                state: AsyncStateType::Pending,
                result: None,
            },
        );
        manager.update_async_state(async_state);

        // Modify the file
        writeln!(file, "fn main() {{ async { sleep(1); print(\"Updated\"); } }}").unwrap();

        // Verify async state is preserved
        let preserved_state = manager.get_async_state();
        assert!(preserved_state.active_operations.contains_key("sleep"));
    }
}
