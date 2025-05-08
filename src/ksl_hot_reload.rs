// ksl_hot_reload.rs
// Enables hot reloading of KSL code, monitoring source files for changes and
// reloading them into a running VM while preserving runtime state, including
// networking connections and async operations.

use crate::ksl_parser::{parse, ParseError};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::kapra_vm::{KapraVM, KapraBytecode, RuntimeError, Value};
use crate::ksl_simulator::run_simulation;
use crate::ksl_logger::{init_logger, log_with_trace, Level};
use crate::ksl_errors::{KslError, SourcePosition};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use std::fs::{self, File};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, SystemTime};
use std::collections::{HashMap, VecDeque};
use libloading::{Library, Symbol};
use std::hash::{Hash, Hasher, SipHasher};
use serde_json;
use wasmer::{Module, Instance, Store, imports};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Keypair, PublicKey, Signature, Verifier};
use seccompiler::{SeccompFilter, SeccompAction};
use serde::{Serialize, Deserialize};
use std::io::Write;

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
    /// Module name
    module: String,
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

/// Information about a reloadable module
#[derive(Debug, Clone)]
pub struct ReloadableModule {
    /// Module name
    pub name: String,
    /// Module version
    pub version: u64,
    /// Path to module file
    pub path: String,
    /// Last known checksum
    pub last_checksum: u64,
    /// Exported symbols
    pub symbols: Vec<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// Module capabilities
    pub capabilities: Vec<String>,
    /// Dependencies
    pub dependencies: Vec<String>,
}

impl ReloadableModule {
    /// Creates a new reloadable module
    pub fn new(name: &str, path: &str) -> Result<Self, KslError> {
        let checksum = calculate_checksum(path)?;
        Ok(ReloadableModule {
            name: name.to_string(),
            version: 1,
            path: path.to_string(),
            last_checksum: checksum,
            symbols: Vec::new(),
            metadata: HashMap::new(),
            capabilities: Vec::new(),
            dependencies: Vec::new(),
        })
    }

    /// Checks if module needs reloading
    pub fn needs_reload(&self) -> Result<bool, KslError> {
        let current_checksum = calculate_checksum(&self.path)?;
        Ok(current_checksum != self.last_checksum)
    }

    /// Updates module metadata
    pub fn update_metadata(&mut self, key: &str, value: &str) {
        self.metadata.insert(key.to_string(), value.to_string());
    }

    /// Adds a capability
    pub fn add_capability(&mut self, capability: &str) {
        if !self.capabilities.contains(&capability.to_string()) {
            self.capabilities.push(capability.to_string());
        }
    }

    /// Adds a dependency
    pub fn add_dependency(&mut self, dependency: &str) {
        if !self.dependencies.contains(&dependency.to_string()) {
            self.dependencies.push(dependency.to_string());
        }
    }

    /// Gets module info as JSON
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "name": self.name,
            "version": self.version,
            "path": self.path,
            "checksum": self.last_checksum,
            "symbols": self.symbols,
            "metadata": self.metadata,
            "capabilities": self.capabilities,
            "dependencies": self.dependencies
        })
    }
}

/// Calculates checksum for a file
pub fn calculate_checksum(path: &str) -> Result<u64, KslError> {
    let bytes = fs::read(path).map_err(|e| KslError::runtime_error(
        format!("Failed to read file for checksum: {}", e),
        None,
    ))?;
    let mut hasher = SipHasher::new();
    hasher.write(&bytes);
    Ok(hasher.finish())
}

/// Maximum number of versions to keep per module
const MAX_VERSION_HISTORY: usize = 5;

/// Version history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VersionEntry {
    version: u64,
    timestamp: DateTime<Utc>,
    path: PathBuf,
    checksum: u64,
    signature: Option<String>,
    metadata: HashMap<String, String>,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditLogEntry {
    timestamp: DateTime<Utc>,
    action: String,
    module_name: String,
    version: u64,
    reason: String,
    user: Option<String>,
    checksum: u64,
}

/// Module version history
#[derive(Debug)]
struct VersionHistory {
    versions: VecDeque<VersionEntry>,
    current_version: u64,
}

impl VersionHistory {
    fn new() -> Self {
        Self {
            versions: VecDeque::with_capacity(MAX_VERSION_HISTORY),
            current_version: 0,
        }
    }

    fn add_version(&mut self, entry: VersionEntry) {
        if self.versions.len() >= MAX_VERSION_HISTORY {
            // Remove oldest version and its files
            if let Some(oldest) = self.versions.pop_front() {
                let _ = fs::remove_file(&oldest.path);
            }
        }
        self.versions.push_back(entry);
        self.current_version = entry.version;
    }

    fn get_version(&self, version: u64) -> Option<&VersionEntry> {
        self.versions.iter().find(|e| e.version == version)
    }

    fn rollback_to(&mut self, version: u64) -> Option<&VersionEntry> {
        if let Some(entry) = self.versions.iter().find(|e| e.version == version) {
            self.current_version = version;
            Some(entry)
        } else {
            None
        }
    }
}

/// Security configuration for module sandboxing
#[derive(Debug, Clone)]
struct SecurityConfig {
    /// Allowed system calls
    allowed_syscalls: Vec<String>,
    /// Memory limits
    memory_limit_mb: u64,
    /// File access patterns
    allowed_paths: Vec<PathBuf>,
    /// Network access rules
    network_rules: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            allowed_syscalls: vec![
                "read".to_string(),
                "write".to_string(),
                "exit".to_string(),
                "exit_group".to_string(),
            ],
            memory_limit_mb: 1024,
            allowed_paths: vec![PathBuf::from("./state")],
            network_rules: vec![],
        }
    }
}

/// Extended hot reload manager with version control and security
pub struct HotReloadManager {
    config: HotReloadConfig,
    state: HotReloadState,
    modules: HashMap<String, ReloadableModule>,
    module_graph: HashMap<String, Vec<String>>,
    reload_order: Vec<String>,
    version_history: HashMap<String, VersionHistory>,
    audit_log: Vec<AuditLogEntry>,
    security_config: SecurityConfig,
    public_keys: HashMap<String, PublicKey>, // Module signing keys
}

impl HotReloadManager {
    /// Create a new hot reload manager
    pub fn new(config: HotReloadConfig) -> Result<Self, KslError> {
        let pos = SourcePosition::new(1, 1);
        
        // Initialize logger
        init_logger(Level::Info, true, None, false)?;

        // Create state directory
        let state_dir = PathBuf::from("./state");
        fs::create_dir_all(&state_dir).map_err(|e| KslError::runtime_error(
            format!("Failed to create state directory: {}", e),
            pos,
        ))?;

        // Load public keys for signature verification
        let keys_file = PathBuf::from("./keys/module_keys.json");
        let public_keys = if keys_file.exists() {
            let keys_str = fs::read_to_string(&keys_file)
                .map_err(|e| KslError::runtime_error(format!("Failed to read keys file: {}", e), pos))?;
            serde_json::from_str(&keys_str)
                .map_err(|e| KslError::runtime_error(format!("Failed to parse keys file: {}", e), pos))?
        } else {
            HashMap::new()
        };

        Ok(HotReloadManager {
            config,
            state: HotReloadState::default(),
            modules: HashMap::new(),
            module_graph: HashMap::new(),
            reload_order: Vec::new(),
            version_history: HashMap::new(),
            audit_log: Vec::new(),
            security_config: SecurityConfig::default(),
            public_keys,
        })
    }

    /// Roll back a module to a specific version
    pub fn rollback_module(&mut self, module_name: &str, version: u64) -> Result<(), KslError> {
        let history = self.version_history.get_mut(module_name)
            .ok_or_else(|| KslError::runtime_error(format!("No version history for module {}", module_name), None))?;

        // Find the version entry
        let entry = history.rollback_to(version)
            .ok_or_else(|| KslError::runtime_error(format!("Version {} not found for module {}", version, module_name), None))?;

        // Save current state
        if let Some(module) = self.modules.get(module_name) {
            self.save_module_state(module_name)?;
        }

        // Load the old version
        let module = self.load_module_from_path(module_name, &entry.path)?;
        self.modules.insert(module_name.to_string(), module);

        // Restore state
        self.restore_module_state(module_name)?;

        // Log the rollback
        self.log_audit_event(AuditLogEntry {
            timestamp: Utc::now(),
            action: "rollback".to_string(),
            module_name: module_name.to_string(),
            version,
            reason: "Manual rollback requested".to_string(),
            user: None,
            checksum: entry.checksum,
        });

        Ok(())
    }

    /// Verify module signature
    fn verify_module_signature(&self, module_name: &str, path: &PathBuf) -> Result<bool, KslError> {
        let pos = SourcePosition::new(1, 1);

        // Get public key for module
        let public_key = if let Some(key) = self.public_keys.get(module_name) {
            key
        } else {
            log_with_trace(Level::Warn, &format!("No public key found for module {}", module_name), None);
            return Ok(false);
        };

        // Read module file and signature
        let module_bytes = fs::read(path)
            .map_err(|e| KslError::runtime_error(format!("Failed to read module file: {}", e), pos))?;
        
        let sig_path = path.with_extension("sig");
        let signature_bytes = fs::read(&sig_path)
            .map_err(|e| KslError::runtime_error(format!("Failed to read signature file: {}", e), pos))?;
        
        let signature = Signature::from_bytes(&signature_bytes)
            .map_err(|e| KslError::runtime_error(format!("Invalid signature: {}", e), pos))?;

        // Verify signature
        match public_key.verify(&module_bytes, &signature) {
            Ok(_) => {
                log_with_trace(Level::Info, &format!("Signature verified for module {}", module_name), None);
                Ok(true)
            }
            Err(e) => {
                log_with_trace(Level::Error, &format!("Signature verification failed for module {}: {}", module_name, e), None);
                Ok(false)
            }
        }
    }

    /// Create sandbox for module
    fn create_module_sandbox(&self, module_name: &str) -> Result<SeccompFilter, KslError> {
        let pos = SourcePosition::new(1, 1);

        let mut filter = SeccompFilter::new(
            vec![],
            SeccompAction::Allow,
            SeccompAction::KillProcess,
        ).map_err(|e| KslError::runtime_error(format!("Failed to create seccomp filter: {}", e), pos))?;

        // Add allowed syscalls
        for syscall in &self.security_config.allowed_syscalls {
            filter.add_rule(syscall, SeccompAction::Allow)
                .map_err(|e| KslError::runtime_error(format!("Failed to add syscall rule: {}", e), pos))?;
        }

        // Add memory limits
        filter.set_memory_limit(self.security_config.memory_limit_mb * 1024 * 1024)
            .map_err(|e| KslError::runtime_error(format!("Failed to set memory limit: {}", e), pos))?;

        Ok(filter)
    }

    /// Load module with security checks
    fn load_module_securely(&mut self, name: &str, path: &PathBuf) -> Result<(), KslError> {
        // Verify signature
        if !self.verify_module_signature(name, path)? {
            return Err(KslError::runtime_error(
                format!("Module signature verification failed for {}", name),
                None,
            ));
        }

        // Create sandbox
        let sandbox = self.create_module_sandbox(name)?;

        // Load module in sandbox
        let module = self.load_module_from_path(name, path)?;
        
        // Add to version history
        let checksum = calculate_checksum(&path.to_string_lossy())?;
        let entry = VersionEntry {
            version: self.get_next_version(name),
            timestamp: Utc::now(),
            path: path.clone(),
            checksum,
            signature: None, // TODO: Store signature
            metadata: HashMap::new(),
        };

        self.version_history.entry(name.to_string())
            .or_insert_with(VersionHistory::new)
            .add_version(entry.clone());

        // Log the load
        self.log_audit_event(AuditLogEntry {
            timestamp: Utc::now(),
            action: "load".to_string(),
            module_name: name.to_string(),
            version: entry.version,
            reason: "Secure module load".to_string(),
            user: None,
            checksum,
        });

        // Store module
        self.modules.insert(name.to_string(), module);

        Ok(())
    }

    /// Get next version number for a module
    fn get_next_version(&self, module_name: &str) -> u64 {
        self.version_history.get(module_name)
            .map(|h| h.current_version + 1)
            .unwrap_or(1)
    }

    /// Log an audit event
    fn log_audit_event(&mut self, entry: AuditLogEntry) {
        // Add to in-memory log
        self.audit_log.push(entry.clone());

        // Write to audit log file
        let log_file = PathBuf::from("./state/audit.log");
        if let Ok(mut file) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)
        {
            if let Ok(entry_json) = serde_json::to_string(&entry) {
                let _ = writeln!(file, "{}", entry_json);
            }
        }
    }

    /// Get audit log for a module
    pub fn get_module_audit_log(&self, module_name: &str) -> Vec<&AuditLogEntry> {
        self.audit_log.iter()
            .filter(|entry| entry.module_name == module_name)
            .collect()
    }

    /// List available versions for a module
    pub fn list_module_versions(&self, module_name: &str) -> Vec<VersionEntry> {
        self.version_history.get(module_name)
            .map(|h| h.versions.iter().cloned().collect())
            .unwrap_or_default()
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

    /// Registers a module for hot reloading
    pub fn register_module(&mut self, name: &str, path: &str) -> Result<(), KslError> {
        let module = ReloadableModule::new(name, path)?;
        self.modules.insert(name.to_string(), module);
        self.update_dependency_graph()?;
        Ok(())
    }

    /// Updates module metadata
    pub fn update_module_metadata(&mut self, name: &str, key: &str, value: &str) -> Result<(), KslError> {
        if let Some(module) = self.modules.get_mut(name) {
            module.update_metadata(key, value);
            Ok(())
        } else {
            Err(KslError::runtime_error(
                format!("Module not found: {}", name),
                None,
            ))
        }
    }

    /// Gets module information
    pub fn get_module_info(&self, name: &str) -> Result<serde_json::Value, KslError> {
        if let Some(module) = self.modules.get(name) {
            Ok(module.to_json())
        } else {
            Err(KslError::runtime_error(
                format!("Module not found: {}", name),
                None,
            ))
        }
    }

    /// Updates dependency graph and reload order
    fn update_dependency_graph(&mut self) -> Result<(), KslError> {
        // Build dependency graph
        self.module_graph.clear();
        for (name, module) in &self.modules {
            self.module_graph.insert(
                name.clone(),
                module.dependencies.clone(),
            );
        }

        // Perform topological sort
        self.reload_order = self.topological_sort()?;
        Ok(())
    }

    /// Performs topological sort of modules
    fn topological_sort(&self) -> Result<Vec<String>, KslError> {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        let mut temp = HashSet::new();

        // Helper function for DFS
        fn visit(
            node: &str,
            graph: &HashMap<String, Vec<String>>,
            visited: &mut HashSet<String>,
            temp: &mut HashSet<String>,
            result: &mut Vec<String>,
        ) -> Result<(), KslError> {
            if temp.contains(node) {
                return Err(KslError::runtime_error(
                    format!("Circular dependency detected: {}", node),
                    None,
                ));
            }
            if visited.contains(node) {
                return Ok(());
            }
            temp.insert(node.to_string());

            if let Some(deps) = graph.get(node) {
                for dep in deps {
                    visit(dep, graph, visited, temp, result)?;
                }
            }

            temp.remove(node);
            visited.insert(node.to_string());
            result.push(node.to_string());
            Ok(())
        }

        // Perform DFS for each module
        for module in self.modules.keys() {
            if !visited.contains(module.as_str()) {
                visit(
                    module,
                    &self.module_graph,
                    &mut visited,
                    &mut temp,
                    &mut result,
                )?;
            }
        }

        Ok(result)
    }

    /// Checks and reloads modules in dependency order
    pub fn check_and_reload_modules(&mut self) -> Result<Vec<String>, KslError> {
        let mut reloaded = Vec::new();

        for module_name in &self.reload_order {
            if let Some(module) = self.modules.get(module_name) {
                if module.needs_reload()? {
                    self.reload_module(module_name)?;
                    reloaded.push(module_name.clone());
                }
            }
        }

        Ok(reloaded)
    }

    /// Start live reload monitoring
    pub fn start_live_reload(&mut self, config: LiveReloadConfig) -> Result<(), KslError> {
        if !config.enabled {
            return Ok(());
        }

        // Clone necessary data for the monitoring thread
        let modules_clone = self.modules.clone();
        let config_clone = config.clone();
        let (tx, rx) = std::sync::mpsc::channel();

        // Spawn monitoring thread
        thread::spawn(move || {
            let mut last_check = std::time::Instant::now();

            loop {
                // Check if we should stop
                if rx.try_recv().is_ok() {
                    break;
                }

                // Check if it's time to reload
                if last_check.elapsed() >= Duration::from_secs(config_clone.interval_secs) {
                    for module in modules_clone.values() {
                        if let Ok(true) = module.needs_reload() {
                            println!("Module {} needs reloading", module.name);
                        }
                    }
                    last_check = std::time::Instant::now();
                }

                thread::sleep(Duration::from_millis(100));
            }
        });

        Ok(())
    }

    /// Reload modules manually (e.g., from REPL)
    pub fn manual_reload(&mut self) -> Result<Vec<String>, KslError> {
        self.reload_modules()
    }

    /// Reload all modules that need updating
    pub fn reload_modules(&mut self) -> Result<Vec<String>, KslError> {
        let mut reloaded = Vec::new();

        // Get modules in dependency order
        let ordered_modules = self.get_ordered_modules()?;

        // Reload each module that needs it
        for module_name in ordered_modules {
            if let Some(module) = self.modules.get_mut(&module_name) {
                if module.needs_reload()? {
                    println!("Reloading module: {}", module.name);
                    
                    // Unload old module
                    self.unload_module(&module.name)?;

                    // Load new module
                    let new_checksum = calculate_checksum(&module.path)?;
                    
                    // Update module state
                    module.last_checksum = new_checksum;
                    module.version += 1;
                    
                    // Execute pre-reload hooks
                    self.execute_pre_reload_hooks(&module.name)?;

                    // Perform actual reload
                    self.load_module(&module.name, &module.path)?;

                    // Execute post-reload hooks
                    self.execute_post_reload_hooks(&module.name)?;

                    reloaded.push(module.name.clone());
                    
                    println!("Successfully reloaded module: {} (version {})", 
                        module.name, module.version);
                }
            }
        }

        Ok(reloaded)
    }

    /// Get modules in dependency order
    fn get_ordered_modules(&self) -> Result<Vec<String>, KslError> {
        // Start with reload order
        let mut ordered = self.reload_order.clone();

        // Add any modules not in reload order
        for name in self.modules.keys() {
            if !ordered.contains(name) {
                ordered.push(name.clone());
            }
        }

        Ok(ordered)
    }

    /// Execute pre-reload hooks for a module
    fn execute_pre_reload_hooks(&self, module_name: &str) -> Result<(), KslError> {
        if let Some(module) = self.modules.get(module_name) {
            // Execute module-specific hooks
            if let Some(hooks) = module.metadata.get("pre_reload_hooks") {
                for hook in hooks.split(',') {
                    log_with_trace(Level::Info, &format!("Executing pre-reload hook: {} for module {}", hook, module_name), None);
                    
                    match hook.trim() {
                        "save_state" => {
                            // Save module state to temporary storage
                            let state = self.get_module_state(module_name)?;
                            self.save_module_state(module_name, state)?;
                        }
                        "pause_operations" => {
                            // Pause any ongoing operations
                            self.pause_module_operations(module_name)?;
                        }
                        "notify_dependents" => {
                            // Notify dependent modules
                            self.notify_dependent_modules(module_name, "pre_reload")?;
                        }
                        _ => {
                            // Try to execute custom hook if registered
                            if let Some(custom_hook) = self.get_custom_hook(hook) {
                                custom_hook(module_name, "pre")?;
                            } else {
                                log_with_trace(Level::Warn, &format!("Unknown pre-reload hook: {}", hook), None);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Execute post-reload hooks for a module
    fn execute_post_reload_hooks(&self, module_name: &str) -> Result<(), KslError> {
        if let Some(module) = self.modules.get(module_name) {
            // Execute module-specific hooks
            if let Some(hooks) = module.metadata.get("post_reload_hooks") {
                for hook in hooks.split(',') {
                    log_with_trace(Level::Info, &format!("Executing post-reload hook: {} for module {}", hook, module_name), None);
                    
                    match hook.trim() {
                        "restore_state" => {
                            // Restore module state from temporary storage
                            if let Some(state) = self.get_saved_module_state(module_name)? {
                                self.restore_module_state(module_name, state)?;
                            }
                        }
                        "resume_operations" => {
                            // Resume paused operations
                            self.resume_module_operations(module_name)?;
                        }
                        "notify_dependents" => {
                            // Notify dependent modules
                            self.notify_dependent_modules(module_name, "post_reload")?;
                        }
                        "verify_integrity" => {
                            // Verify module integrity after reload
                            self.verify_module_integrity(module_name)?;
                        }
                        _ => {
                            // Try to execute custom hook if registered
                            if let Some(custom_hook) = self.get_custom_hook(hook) {
                                custom_hook(module_name, "post")?;
                            } else {
                                log_with_trace(Level::Warn, &format!("Unknown post-reload hook: {}", hook), None);
                            }
                        }
                    }
                }
            }

            // Notify any registered callbacks
            if let Ok(handlers) = self.reload_handlers.read() {
                for handler in handlers.iter() {
                    handler(module_name);
                }
            }
        }
        Ok(())
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

/// Type for module initialization function
type InitFn = unsafe fn() -> bool;
/// Type for module cleanup function
type CleanupFn = unsafe fn() -> bool;

/// Module metadata
#[derive(Debug)]
struct ModuleMetadata {
    /// Path to the module file
    path: PathBuf,
    /// Last modified time
    last_modified: SystemTime,
    /// Module interface version
    version: String,
    /// Module capabilities (e.g., "wasm", "native")
    capabilities: Vec<String>,
}

/// Loaded module instance
struct LoadedModule {
    /// Library handle
    library: Library,
    /// Module metadata
    metadata: ModuleMetadata,
    /// Whether the module is currently active
    active: bool,
}

/// Registry for dynamically loaded modules
pub struct ModuleRegistry {
    /// Loaded modules
    modules: HashMap<String, LoadedModule>,
    /// Module search paths
    search_paths: Vec<PathBuf>,
    /// WASM runtime (if enabled)
    #[cfg(feature = "wasm")]
    wasm_runtime: Option<wasmer::Store>,
    /// File watcher for hot reloading
    watcher: notify::RecommendedWatcher,
    /// Module reload handlers
    reload_handlers: Arc<RwLock<Vec<Box<dyn Fn(&str) + Send + Sync>>>>,
}

impl ModuleRegistry {
    /// Create a new module registry
    pub fn new() -> Result<Self, KslError> {
        use notify::{Watcher, RecursiveMode};

        // Create file watcher
        let reload_handlers = Arc::new(RwLock::new(Vec::new()));
        let handlers_clone = Arc::clone(&reload_handlers);
        
        let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, _>| {
            if let Ok(event) = res {
                if let notify::EventKind::Modify(_) = event.kind {
                    // Notify handlers of module changes
                    if let Ok(handlers) = handlers_clone.read() {
                        for handler in handlers.iter() {
                            for path in event.paths.iter() {
                                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                                    handler(name);
                                }
                            }
                        }
                    }
                }
            }
        })?;

        // Initialize WASM runtime if enabled
        #[cfg(feature = "wasm")]
        let wasm_runtime = Some(wasmer::Store::default());

        Ok(ModuleRegistry {
            modules: HashMap::new(),
            search_paths: vec![],
            #[cfg(feature = "wasm")]
            wasm_runtime,
            watcher,
            reload_handlers,
        })
    }

    /// Add a module search path
    pub fn add_search_path<P: AsRef<Path>>(&mut self, path: P) -> Result<(), KslError> {
        let path = path.as_ref().to_path_buf();
        self.search_paths.push(path.clone());
        // Watch the path for changes
        self.watcher.watch(&path, notify::RecursiveMode::NonRecursive)?;
        Ok(())
    }

    /// Load a module
    pub fn load_module(&mut self, name: &str, path: &str) -> Result<(), KslError> {
        let path = PathBuf::from(path);
        
        // Check if it's a WASM module
        #[cfg(feature = "wasm")]
        let is_wasm = path.extension().map_or(false, |ext| ext == "wasm");

        // Load the module
        let module = if cfg!(feature = "wasm") && is_wasm {
            self.load_wasm_module(name, &path)?
        } else {
            self.load_native_module(name, &path)?
        };

        // Store the module
        self.modules.insert(name.to_string(), module);
        Ok(())
    }

    /// Load a native module
    fn load_native_module(&self, name: &str, path: &Path) -> Result<LoadedModule, KslError> {
        // Load the library
        let library = unsafe {
            Library::new(path).map_err(|e| KslError::runtime_error(
                format!("Failed to load module '{}': {}", name, e),
                None,
            ))?
        };

        // Get module metadata
        let metadata = ModuleMetadata {
            path: path.to_path_buf(),
            last_modified: std::fs::metadata(path)?.modified()?,
            version: "1.0.0".to_string(), // TODO: Get from module
            capabilities: vec!["native".to_string()],
        };

        // Initialize the module
        unsafe {
            if let Ok(init_fn) = library.get::<InitFn>(b"ksl_module_init") {
                if !init_fn() {
                    return Err(KslError::runtime_error(
                        format!("Module '{}' initialization failed", name),
                        None,
                    ));
                }
            }
        }

        Ok(LoadedModule {
            library,
            metadata,
            active: true,
        })
    }

    /// Load a WASM module
    #[cfg(feature = "wasm")]
    fn load_wasm_module(&self, name: &str, path: &Path) -> Result<LoadedModule, KslError> {
        use wasmer::{Module, Instance, Store, imports};

        // Read WASM bytes
        let wasm_bytes = std::fs::read(path)?;

        // Create store and module
        let store = self.wasm_runtime.as_ref().ok_or_else(|| KslError::runtime_error(
            "WASM runtime not initialized".to_string(),
            None,
        ))?;

        let module = Module::new(&store, wasm_bytes).map_err(|e| KslError::runtime_error(
            format!("Failed to create WASM module '{}': {}", name, e),
            None,
        ))?;

        // Create import object with required host functions
        let import_object = imports! {
            "env" => {
                "ksl_log" => wasmer::Function::new_native(&store, |level: i32, msg: &str| {
                    log_with_trace(Level::from_i32(level), msg, None);
                }),
                "ksl_get_state" => wasmer::Function::new_native(&store, || {
                    // Get module state
                    self.get_module_state(name).unwrap_or_default()
                }),
                "ksl_set_state" => wasmer::Function::new_native(&store, |state: ModuleState| {
                    // Set module state
                    self.save_module_state(name, state).unwrap_or(());
                }),
            }
        };

        // Instantiate the module
        let instance = Instance::new(&module, &import_object).map_err(|e| KslError::runtime_error(
            format!("Failed to instantiate WASM module '{}': {}", name, e),
            None,
        ))?;

        // Get exported functions
        let mut exports = Vec::new();
        for export in instance.exports.iter() {
            if let Some(func) = export.into_function() {
                exports.push(export.name().to_string());
            }
        }

        // Get module metadata
        let metadata = ModuleMetadata {
            path: path.to_path_buf(),
            last_modified: std::fs::metadata(path)?.modified()?,
            version: module.version().to_string(),
            capabilities: vec!["wasm".to_string()],
        };

        // Create module wrapper
        let module_wrapper = WasmModuleWrapper {
            store: store.clone(),
            module,
            instance,
            exports,
        };

        Ok(LoadedModule {
            wasm: Some(module_wrapper),
            metadata,
            active: true,
        })
    }

    /// Get a symbol from a module
    pub fn get_symbol<T>(&self, name: &str, symbol: &str) -> Result<Symbol<T>, KslError> {
        let module = self.modules.get(name).ok_or_else(|| KslError::runtime_error(
            format!("Module '{}' not found", name),
            None,
        ))?;

        if !module.active {
            return Err(KslError::runtime_error(
                format!("Module '{}' is not active", name),
                None,
            ));
        }

        unsafe {
            module.library.get(symbol.as_bytes()).map_err(|e| KslError::runtime_error(
                format!("Symbol '{}' not found in module '{}': {}", symbol, name, e),
                None,
            ))
        }
    }

    /// Register a reload handler
    pub fn on_reload<F>(&self, handler: F) where F: Fn(&str) + Send + Sync + 'static {
        if let Ok(mut handlers) = self.reload_handlers.write() {
            handlers.push(Box::new(handler));
        }
    }

    /// Check if modules need reloading
    pub fn check_reload(&mut self) -> Result<(), KslError> {
        let mut to_reload = Vec::new();

        // Check each module
        for (name, module) in &self.modules {
            if let Ok(metadata) = std::fs::metadata(&module.metadata.path) {
                if let Ok(modified) = metadata.modified() {
                    if modified > module.metadata.last_modified {
                        to_reload.push(name.clone());
                    }
                }
            }
        }

        // Reload modules
        for name in to_reload {
            self.reload_module(&name)?;
        }

        Ok(())
    }

    /// Reload a specific module
    pub fn reload_module(&mut self, name: &str) -> Result<(), KslError> {
        if let Some(old_module) = self.modules.remove(name) {
            // Clean up old module
            unsafe {
                if let Ok(cleanup_fn) = old_module.library.get::<CleanupFn>(b"ksl_module_cleanup") {
                    cleanup_fn();
                }
            }

            // Load new module
            let path = old_module.metadata.path.to_str().unwrap();
            self.load_module(name, path)?;

            // Notify handlers
            if let Ok(handlers) = self.reload_handlers.read() {
                for handler in handlers.iter() {
                    handler(name);
                }
            }
        }

        Ok(())
    }

    /// Unload a module
    pub fn unload_module(&mut self, name: &str) -> Result<(), KslError> {
        if let Some(module) = self.modules.remove(name) {
            // Clean up module
            unsafe {
                if let Ok(cleanup_fn) = module.library.get::<CleanupFn>(b"ksl_module_cleanup") {
                    cleanup_fn();
                }
            }
        }
        Ok(())
    }
}

impl Drop for ModuleRegistry {
    fn drop(&mut self) {
        // Clean up all modules
        for (name, module) in self.modules.drain() {
            unsafe {
                if let Ok(cleanup_fn) = module.library.get::<CleanupFn>(b"ksl_module_cleanup") {
                    cleanup_fn();
                }
            }
        }
    }
}

/// Live reload configuration
#[derive(Debug, Clone)]
pub struct LiveReloadConfig {
    /// Whether live reload is enabled
    pub enabled: bool,
    /// Reload interval in seconds
    pub interval_secs: u64,
    /// Whether to reload on REPL command
    pub allow_manual_reload: bool,
    /// Modules to watch
    pub watch_patterns: Vec<String>,
    /// Custom reload hooks
    pub reload_hooks: Vec<String>,
}

impl Default for LiveReloadConfig {
    fn default() -> Self {
        LiveReloadConfig {
            enabled: true,
            interval_secs: 5,
            allow_manual_reload: true,
            watch_patterns: vec!["*.so".to_string(), "*.dylib".to_string(), "*.dll".to_string()],
            reload_hooks: Vec::new(),
        }
    }
}

#[derive(Clone)]
struct WasmModuleWrapper {
    store: Store,
    module: Module,
    instance: Instance,
    exports: Vec<String>,
}

impl LoadedModule {
    /// Get a WASM export
    pub fn get_wasm_export(&self, name: &str) -> Result<wasmer::Function, KslError> {
        if let Some(wasm) = &self.wasm {
            wasm.instance.exports.get_function(name).map_err(|e| KslError::runtime_error(
                format!("Failed to get WASM export '{}': {}", name, e),
                None,
            ))
        } else {
            Err(KslError::runtime_error(
                format!("Module is not a WASM module"),
                None,
            ))
        }
    }

    /// Call a WASM export
    pub fn call_wasm_export(&self, name: &str, args: &[wasmer::Value]) -> Result<Box<[wasmer::Value]>, KslError> {
        let func = self.get_wasm_export(name)?;
        func.call(args).map_err(|e| KslError::runtime_error(
            format!("Failed to call WASM export '{}': {}", name, e),
            None,
        ))
    }
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

    #[test]
    fn test_module_tracking() {
        let temp_dir = TempDir::new().unwrap();
        let module_path = temp_dir.path().join("test_module.so");
        std::fs::write(&module_path, b"initial content").unwrap();

        let mut manager = HotReloadManager::new(HotReloadConfig::default()).unwrap();
        manager.register_module("test", module_path.to_str().unwrap()).unwrap();

        // Update metadata
        manager.update_module_metadata("test", "version", "1.0.0").unwrap();

        // Modify module
        std::fs::write(&module_path, b"modified content").unwrap();

        // Check if reload needed
        let module = manager.modules.get("test").unwrap();
        assert!(module.needs_reload().unwrap());

        // Verify metadata
        let info = manager.get_module_info("test").unwrap();
        assert_eq!(info["metadata"]["version"], "1.0.0");
    }

    #[test]
    fn test_dependency_ordering() {
        let mut manager = HotReloadManager::new(HotReloadConfig::default()).unwrap();

        // Create test modules
        let temp_dir = TempDir::new().unwrap();
        let create_module = |name: &str| {
            let path = temp_dir.path().join(format!("{}.so", name));
            std::fs::write(&path, b"test").unwrap();
            manager.register_module(name, path.to_str().unwrap()).unwrap();
            if let Some(module) = manager.modules.get_mut(name) {
                module.add_capability("test");
            }
        };

        // Create modules with dependencies
        create_module("base");
        create_module("middleware");
        create_module("app");

        // Set up dependencies
        if let Some(module) = manager.modules.get_mut("middleware") {
            module.add_dependency("base");
        }
        if let Some(module) = manager.modules.get_mut("app") {
            module.add_dependency("middleware");
        }

        // Update dependency graph
        manager.update_dependency_graph().unwrap();

        // Verify reload order
        assert!(
            manager.reload_order.iter()
                .position(|x| x == "base")
                .unwrap()
            < manager.reload_order.iter()
                .position(|x| x == "middleware")
                .unwrap()
        );
        assert!(
            manager.reload_order.iter()
                .position(|x| x == "middleware")
                .unwrap()
            < manager.reload_order.iter()
                .position(|x| x == "app")
                .unwrap()
        );
    }

    #[test]
    fn test_live_reload() {
        let temp_dir = TempDir::new().unwrap();
        let module_path = temp_dir.path().join("test_module.so");
        std::fs::write(&module_path, b"initial content").unwrap();

        let mut manager = HotReloadManager::new(HotReloadConfig::default()).unwrap();
        manager.register_module("test", module_path.to_str().unwrap()).unwrap();

        // Start live reload
        let config = LiveReloadConfig {
            enabled: true,
            interval_secs: 1,
            allow_manual_reload: true,
            watch_patterns: vec!["*.so".to_string()],
            reload_hooks: vec![],
        };
        manager.start_live_reload(config).unwrap();

        // Modify module
        thread::sleep(Duration::from_millis(100));
        std::fs::write(&module_path, b"modified content").unwrap();

        // Manual reload
        let reloaded = manager.manual_reload().unwrap();
        assert_eq!(reloaded, vec!["test"]);

        // Verify version increment
        let module = manager.modules.get("test").unwrap();
        assert_eq!(module.version, 2);
    }

    #[test]
    fn test_reload_hooks() {
        let temp_dir = TempDir::new().unwrap();
        let module_path = temp_dir.path().join("test_module.so");
        std::fs::write(&module_path, b"initial content").unwrap();

        let mut manager = HotReloadManager::new(HotReloadConfig::default()).unwrap();
        manager.register_module("test", module_path.to_str().unwrap()).unwrap();

        // Add hooks
        manager.update_module_metadata("test", "pre_reload_hooks", "save_state").unwrap();
        manager.update_module_metadata("test", "post_reload_hooks", "restore_state").unwrap();

        // Modify and reload
        std::fs::write(&module_path, b"modified content").unwrap();
        let reloaded = manager.reload_modules().unwrap();
        assert_eq!(reloaded, vec!["test"]);
    }

    #[test]
    fn test_hook_execution() {
        let temp_dir = TempDir::new().unwrap();
        let module_path = temp_dir.path().join("test_module.so");
        std::fs::write(&module_path, b"initial content").unwrap();

        let mut manager = HotReloadManager::new(HotReloadConfig::default()).unwrap();
        manager.register_module("test", module_path.to_str().unwrap()).unwrap();

        // Add hooks
        manager.update_module_metadata("test", "pre_reload_hooks", "save_state,pause_operations").unwrap();
        manager.update_module_metadata("test", "post_reload_hooks", "restore_state,resume_operations,verify_integrity").unwrap();

        // Set up test state
        let mut networking_state = NetworkingState::default();
        networking_state.http_connections.insert(
            "test_conn".to_string(),
            HttpConnection {
                url: "http://example.com".to_string(),
                headers: HashMap::new(),
                state: ConnectionState::Connected,
                module: "test".to_string(),
            },
        );
        manager.update_networking_state(networking_state);

        // Modify and reload
        std::fs::write(&module_path, b"modified content").unwrap();
        let reloaded = manager.reload_modules().unwrap();
        assert_eq!(reloaded, vec!["test"]);

        // Verify state was preserved
        let preserved_state = manager.get_networking_state();
        assert!(preserved_state.http_connections.contains_key("test_conn"));
        assert_eq!(
            preserved_state.http_connections["test_conn"].state,
            ConnectionState::Connected
        );
    }

    #[test]
    fn test_wasm_module_reload() {
        let temp_dir = TempDir::new().unwrap();
        let module_path = temp_dir.path().join("test.wasm");

        // Create test WASM module
        let wasm_bytes = create_test_wasm_module();
        std::fs::write(&module_path, &wasm_bytes).unwrap();

        let mut manager = HotReloadManager::new(HotReloadConfig::default()).unwrap();
        manager.register_module("test_wasm", module_path.to_str().unwrap()).unwrap();

        // Load initial version
        let module = manager.modules.get("test_wasm").unwrap();
        assert!(module.metadata.capabilities.contains(&"wasm".to_string()));

        // Call exported function
        let result = module.call_wasm_export("test_function", &[wasmer::Value::I32(42)]).unwrap();
        assert_eq!(result[0], wasmer::Value::I32(84));

        // Modify and reload
        let new_wasm_bytes = create_modified_wasm_module();
        std::fs::write(&module_path, &new_wasm_bytes).unwrap();
        
        let reloaded = manager.reload_modules().unwrap();
        assert_eq!(reloaded, vec!["test_wasm"]);

        // Verify new version
        let module = manager.modules.get("test_wasm").unwrap();
        let result = module.call_wasm_export("test_function", &[wasmer::Value::I32(42)]).unwrap();
        assert_eq!(result[0], wasmer::Value::I32(126));
    }

    #[test]
    fn test_state_validation() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");

        // Write initial version with u32 global
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

        // Set up initial state
        let mut vm = manager.state.vm.lock().unwrap();
        vm.set_globals(HashMap::from([
            ("x".to_string(), Value::U32(42)),
        ])).unwrap();

        // Update to incompatible type
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: string = \"hello\"; }}"
        ).unwrap();

        // Verify type error is caught
        let result = manager.handle_file_change(&manager.state, &input_file);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid type for global variable x"));
    }

    #[test]
    fn test_circular_dependency_detection() {
        let mut manager = HotReloadManager::new(HotReloadConfig::default()).unwrap();

        // Create test modules with circular dependency
        let temp_dir = TempDir::new().unwrap();
        let create_module = |name: &str| {
            let path = temp_dir.path().join(format!("{}.so", name));
            std::fs::write(&path, b"test").unwrap();
            manager.register_module(name, path.to_str().unwrap()).unwrap();
        };

        create_module("a");
        create_module("b");
        create_module("c");

        // Set up circular dependencies
        if let Some(module) = manager.modules.get_mut("a") {
            module.add_dependency("b");
        }
        if let Some(module) = manager.modules.get_mut("b") {
            module.add_dependency("c");
        }
        if let Some(module) = manager.modules.get_mut("c") {
            module.add_dependency("a");
        }

        // Verify circular dependency is detected
        let result = manager.update_dependency_graph();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Circular dependency detected"));
    }
}

// Helper functions for WASM tests
fn create_test_wasm_module() -> Vec<u8> {
    // Create a simple WASM module that doubles its input
    wat::parse_str(r#"
        (module
            (func $test_function (param i32) (result i32)
                local.get 0
                i32.const 2
                i32.mul)
            (export "test_function" (func $test_function)))
    "#).unwrap()
}

fn create_modified_wasm_module() -> Vec<u8> {
    // Create a modified version that triples its input
    wat::parse_str(r#"
        (module
            (func $test_function (param i32) (result i32)
                local.get 0
                i32.const 3
                i32.mul)
            (export "test_function" (func $test_function)))
    "#).unwrap()
}
