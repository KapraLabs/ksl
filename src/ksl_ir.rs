// ksl_ir.rs
// Intermediate Representation (IR) for KSL program auditing

use serde::{Serialize, Deserialize};
use std::fmt;
use crate::ksl_kapra_crypto::FixedArray;
use crate::ksl_types::Type;
use crate::kapra_vm::ContractMetadata;
use std::collections::HashMap;

/// IR node types for program analysis and auditing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IRNode {
    // Core operations
    Assign(String, String),                    // dst, src
    Add(String, String, String),               // dst, src1, src2
    Sub(String, String, String),               // dst, src1, src2
    Mul(String, String, String),               // dst, src1, src2
    
    // Control flow
    Jump(String),                              // label
    Call(String, Vec<String>),                 // function, args
    Return(Option<String>),                    // optional value
    Branch(String, String, String),            // condition, true_label, false_label
    
    // Memory operations
    Load(String, String),                      // dst, address
    Store(String, String),                     // address, value
    
    // Verification
    Assert(String),                            // condition
    Verify(String, String),                    // condition, message
    
    // Crypto operations
    Sha3(String, String),                      // dst, src
    Sha3_512(String, String),                  // dst, src
    BlsVerify(String, String, String, String), // dst, msg, pubkey, sig
    DilithiumVerify(String, String, String, String), // dst, msg, pubkey, sig
    MerkleVerify(String, String, String),      // dst, root, proof
    
    // Async operations
    AsyncCall(String, String, Vec<String>),    // dst, function, args
    Await(String),                             // handle
    
    // Labels and metadata
    Label(String),                             // label name
    Comment(String),                           // comment text
    Location(usize, usize),                    // line, column
}

/// Program structure containing IR nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IRProgram {
    /// Program instructions
    pub instructions: Vec<IRNode>,
    /// Program metadata
    pub metadata: IRMetadata,
}

/// Metadata for the IR program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IRMetadata {
    /// Source file name
    pub source_file: String,
    /// Compilation timestamp
    pub timestamp: u64,
    /// Compiler version
    pub compiler_version: String,
    /// Target platform
    pub target: String,
    /// Optimization level
    pub opt_level: u8,
    /// Debug info enabled
    pub debug_info: bool,
}

impl IRProgram {
    /// Creates a new IR program
    pub fn new(source_file: &str) -> Self {
        IRProgram {
            instructions: Vec::new(),
            metadata: IRMetadata {
                source_file: source_file.to_string(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                compiler_version: env!("CARGO_PKG_VERSION").to_string(),
                target: "default".to_string(),
                opt_level: 0,
                debug_info: true,
            },
        }
    }

    /// Adds an instruction to the program
    pub fn push(&mut self, node: IRNode) {
        self.instructions.push(node);
    }

    /// Sets optimization level
    pub fn set_opt_level(&mut self, level: u8) {
        self.metadata.opt_level = level;
    }

    /// Sets target platform
    pub fn set_target(&mut self, target: &str) {
        self.metadata.target = target.to_string();
    }

    /// Sets debug info flag
    pub fn set_debug_info(&mut self, enabled: bool) {
        self.metadata.debug_info = enabled;
    }

    /// Exports program to JSON
    pub fn export_json(&self, path: &str) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)
    }

    /// Imports program from JSON
    pub fn import_json(path: &str) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&json)?)
    }
}

impl fmt::Display for IRNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IRNode::Assign(dst, src) => write!(f, "{} = {}", dst, src),
            IRNode::Add(dst, src1, src2) => write!(f, "{} = {} + {}", dst, src1, src2),
            IRNode::Sub(dst, src1, src2) => write!(f, "{} = {} - {}", dst, src1, src2),
            IRNode::Mul(dst, src1, src2) => write!(f, "{} = {} * {}", dst, src1, src2),
            IRNode::Jump(label) => write!(f, "jump {}", label),
            IRNode::Call(func, args) => write!(f, "call {} ({})", func, args.join(", ")),
            IRNode::Return(None) => write!(f, "return"),
            IRNode::Return(Some(val)) => write!(f, "return {}", val),
            IRNode::Branch(cond, t, e) => write!(f, "branch {} ? {} : {}", cond, t, e),
            IRNode::Load(dst, addr) => write!(f, "{} = load {}", dst, addr),
            IRNode::Store(addr, val) => write!(f, "store {} = {}", addr, val),
            IRNode::Assert(cond) => write!(f, "assert {}", cond),
            IRNode::Verify(cond, msg) => write!(f, "verify {} \"{}\"", cond, msg),
            IRNode::Sha3(dst, src) => write!(f, "{} = sha3({})", dst, src),
            IRNode::Sha3_512(dst, src) => write!(f, "{} = sha3_512({})", dst, src),
            IRNode::BlsVerify(dst, msg, pk, sig) => write!(f, "{} = bls_verify({}, {}, {})", dst, msg, pk, sig),
            IRNode::DilithiumVerify(dst, msg, pk, sig) => write!(f, "{} = dil_verify({}, {}, {})", dst, msg, pk, sig),
            IRNode::MerkleVerify(dst, root, proof) => write!(f, "{} = merkle_verify({}, {})", dst, root, proof),
            IRNode::AsyncCall(dst, func, args) => write!(f, "{} = async {} ({})", dst, func, args.join(", ")),
            IRNode::Await(handle) => write!(f, "await {}", handle),
            IRNode::Label(name) => write!(f, "{}:", name),
            IRNode::Comment(text) => write!(f, "// {}", text),
            IRNode::Location(line, col) => write!(f, "@{}:{}", line, col),
        }
    }
}

/// Export format for IR programs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IRExport {
    /// Program IR
    pub program: IRProgram,
    /// Export timestamp
    pub export_time: u64,
    /// Export version
    pub export_version: String,
}

impl IRExport {
    /// Creates a new IR export
    pub fn new(program: IRProgram) -> Self {
        IRExport {
            program,
            export_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            export_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Exports to JSON file
    pub fn export_json(&self, path: &str) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)
    }

    /// Imports from JSON file
    pub fn import_json(path: &str) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&json)?)
    }
}

/// Capability group definitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityGroup {
    pub name: String,
    pub capabilities: Vec<String>,
    pub description: String,
}

/// Capability configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityConfig {
    /// Whether capabilities are enforced
    pub enforce_capabilities: bool,
    /// Chain-level disabled capabilities
    pub disabled_capabilities: Vec<String>,
    /// Predefined capability groups
    pub capability_groups: HashMap<String, CapabilityGroup>,
    /// Dynamic capability requests allowed
    pub allow_dynamic_requests: bool,
}

impl Default for CapabilityConfig {
    fn default() -> Self {
        let mut groups = HashMap::new();
        groups.insert(
            "sensitive".to_string(),
            CapabilityGroup {
                name: "sensitive".to_string(),
                capabilities: vec!["fs".to_string(), "crypto".to_string(), "auth".to_string()],
                description: "High-security operations requiring careful auditing".to_string(),
            }
        );
        groups.insert(
            "network".to_string(),
            CapabilityGroup {
                name: "network".to_string(),
                capabilities: vec!["http".to_string(), "tcp".to_string(), "udp".to_string()],
                description: "Network communication capabilities".to_string(),
            }
        );
        groups.insert(
            "compute".to_string(),
            CapabilityGroup {
                name: "compute".to_string(),
                capabilities: vec!["wasm".to_string(), "ai".to_string(), "gpu".to_string()],
                description: "Compute-intensive operations".to_string(),
            }
        );

        CapabilityConfig {
            enforce_capabilities: true,
            disabled_capabilities: Vec::new(),
            capability_groups: groups,
            allow_dynamic_requests: false,
        }
    }
}

/// Core IR structure representing a KSL contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KSLIR {
    pub contract_name: String,
    pub version: u32,
    pub bytecode_hash: FixedArray<32>,
    pub entrypoints: Vec<KSLFunctionIR>,
    pub global_variables: Vec<KSLGlobalIR>,
    pub postconditions: Vec<KSLPostconditionIR>,
    pub metadata: Option<ContractMetadata>,
    pub security_audit: Option<SecurityAudit>,
    pub test_coverage: Option<TestCoverage>,
    /// List of imported plugins
    pub plugins: Vec<String>,
    /// Function definitions
    pub functions: HashMap<String, FunctionIR>,
    /// Global variables
    pub globals: HashMap<String, GlobalIR>,
    /// Plugin operations
    pub plugin_ops: HashMap<String, PluginOpIR>,
    /// Supported capabilities for this contract
    pub supported_capabilities: Vec<String>,
    /// Dynamic capability requests
    pub dynamic_capabilities: Vec<String>,
    /// Capability configuration
    pub capability_config: CapabilityConfig,
}

/// IR representation of a function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KSLFunctionIR {
    pub name: String,
    pub args: Vec<KSLType>,
    pub return_type: Option<KSLType>,
    pub gas_estimate: u64,
    pub opcodes: Vec<String>,
    pub doc: Option<String>,
    pub visibility: FunctionVisibility,
    pub modifiers: Vec<FunctionModifier>,
    pub error_handling: Option<ErrorHandling>,
    pub location: Option<SourceLocation>,
    pub documentation: Option<Documentation>,
    /// Required capabilities for this function
    pub required_capabilities: Vec<String>,
}

/// IR representation of a global variable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KSLGlobalIR {
    pub name: String,
    pub type_: KSLType,
    pub doc: Option<String>,
    pub visibility: GlobalVisibility,
    pub initial_value: Option<String>,
    pub location: Option<SourceLocation>,
    pub documentation: Option<Documentation>,
}

/// IR representation of a postcondition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KSLPostconditionIR {
    pub expression: String,
    pub line: usize,
    pub doc: Option<String>,
    pub severity: PostconditionSeverity,
    pub dependencies: Vec<String>,
}

/// Security audit information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAudit {
    pub auditor: String,
    pub date: String,
    pub findings: Vec<SecurityFinding>,
    pub recommendations: Vec<String>,
    pub risk_level: RiskLevel,
}

/// Test coverage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCoverage {
    pub total_lines: usize,
    pub covered_lines: usize,
    pub branch_coverage: f64,
    pub uncovered_lines: Vec<usize>,
    pub test_cases: Vec<TestCase>,
}

/// Function visibility modifiers
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FunctionVisibility {
    Public,
    Private,
    Internal,
    External,
}

/// Global variable visibility
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GlobalVisibility {
    Public,
    Private,
    Constant,
}

/// Function modifiers
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FunctionModifier {
    View,
    Pure,
    Payable,
    OnlyOwner,
    OnlyGuardian,
    ReentrantGuard,
}

/// Postcondition severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PostconditionSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Risk levels for security findings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Security finding details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub title: String,
    pub description: String,
    pub risk_level: RiskLevel,
    pub affected_lines: Vec<usize>,
    pub recommendation: String,
}

/// Test case information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    pub name: String,
    pub description: String,
    pub covered_lines: Vec<usize>,
    pub assertions: Vec<String>,
    pub status: TestStatus,
}

/// Test case status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TestStatus {
    Passed,
    Failed,
    Skipped,
}

/// Error handling information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorHandling {
    pub error_types: Vec<String>,
    pub recovery_strategies: Vec<String>,
    pub fallback_behavior: String,
}

/// KSL type representation in IR
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KSLType {
    pub name: String,
    pub is_array: bool,
    pub array_size: Option<usize>,
    pub is_optional: bool,
    pub generic_params: Vec<KSLType>,
}

/// Source location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: String,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

/// Documentation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Documentation {
    pub description: String,
    pub params: Vec<ParamDoc>,
    pub returns: Option<String>,
    pub examples: Vec<String>,
    pub see_also: Vec<String>,
}

/// Parameter documentation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamDoc {
    pub name: String,
    pub description: String,
}

/// List of supported capabilities
pub const SUPPORTED_CAPABILITIES: &[&str] = &[
    "crypto",   // Cryptographic operations
    "network",  // Network access
    "storage",  // Persistent storage
    "fs",       // File system access
    "wasm",     // WebAssembly execution
    "game",     // Game engine features
    "ai",       // AI/ML operations
    "iot",      // IoT device access
];

impl KSLIR {
    /// Creates a new KSLIR instance
    pub fn new(contract_name: String, version: u32) -> Self {
        Self {
            contract_name,
            version,
            bytecode_hash: FixedArray([0; 32]),
            entrypoints: Vec::new(),
            global_variables: Vec::new(),
            postconditions: Vec::new(),
            metadata: None,
            security_audit: None,
            test_coverage: None,
            plugins: Vec::new(),
            functions: HashMap::new(),
            globals: HashMap::new(),
            plugin_ops: HashMap::new(),
            supported_capabilities: Vec::new(),
            dynamic_capabilities: Vec::new(),
            capability_config: CapabilityConfig::default(),
        }
    }

    /// Adds a function to the IR
    pub fn add_function(&mut self, function: KSLFunctionIR) {
        self.entrypoints.push(function);
    }

    /// Adds a global variable to the IR
    pub fn add_global(&mut self, global: KSLGlobalIR) {
        self.global_variables.push(global);
    }

    /// Adds a postcondition to the IR
    pub fn add_postcondition(&mut self, postcondition: KSLPostconditionIR) {
        self.postconditions.push(postcondition);
    }

    /// Sets the contract metadata
    pub fn set_metadata(&mut self, metadata: ContractMetadata) {
        self.metadata = Some(metadata);
    }

    /// Sets the security audit information
    pub fn set_security_audit(&mut self, audit: SecurityAudit) {
        self.security_audit = Some(audit);
    }

    /// Sets the test coverage information
    pub fn set_test_coverage(&mut self, coverage: TestCoverage) {
        self.test_coverage = Some(coverage);
    }

    /// Updates the bytecode hash
    pub fn update_bytecode_hash(&mut self, hash: FixedArray<32>) {
        self.bytecode_hash = hash;
    }

    /// Serializes the IR to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        #[derive(Serialize)]
        struct IRExport<'a> {
            contract_name: &'a str,
            version: u32,
            bytecode_hash: String,
            capabilities: &'a Vec<String>,
            functions: Vec<FunctionExport<'a>>,
            globals: Vec<GlobalExport<'a>>,
        }

        #[derive(Serialize)]
        struct FunctionExport<'a> {
            name: &'a str,
            args: &'a Vec<KSLType>,
            return_type: Option<&'a KSLType>,
            required_capabilities: &'a Vec<String>,
            gas_estimate: u64,
            visibility: &'a FunctionVisibility,
            doc: Option<&'a str>,
        }

        #[derive(Serialize)]
        struct GlobalExport<'a> {
            name: &'a str,
            type_: &'a KSLType,
            visibility: &'a GlobalVisibility,
        }

        let functions: Vec<FunctionExport> = self.entrypoints.iter()
            .map(|f| FunctionExport {
                name: &f.name,
                args: &f.args,
                return_type: f.return_type.as_ref(),
                required_capabilities: &f.required_capabilities,
                gas_estimate: f.gas_estimate,
                visibility: &f.visibility,
                doc: f.doc.as_deref(),
            })
            .collect();

        let globals: Vec<GlobalExport> = self.global_variables.iter()
            .map(|g| GlobalExport {
                name: &g.name,
                type_: &g.type_,
                visibility: &g.visibility,
            })
            .collect();

        let export = IRExport {
            contract_name: &self.contract_name,
            version: self.version,
            bytecode_hash: hex::encode(self.bytecode_hash.0),
            capabilities: &self.supported_capabilities,
            functions,
            globals,
        };

        serde_json::to_string_pretty(&export)
    }

    /// Deserializes the IR from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Validates required capabilities against supported ones
    pub fn validate_capabilities(&self, required: &[String]) -> Result<(), String> {
        if !self.capability_config.enforce_capabilities {
            return Ok(());
        }

        // Expand capability groups
        let mut expanded_required = Vec::new();
        for cap in required {
            if let Some(group) = self.capability_config.capability_groups.get(cap) {
                expanded_required.extend(group.capabilities.clone());
            } else {
                expanded_required.push(cap.clone());
            }
        }

        // Check against disabled capabilities
        for cap in &expanded_required {
            if self.capability_config.disabled_capabilities.contains(cap) {
                return Err(format!("Capability {} is disabled at chain level", cap));
            }
        }

        // Check against supported capabilities
        for cap in &expanded_required {
            if !SUPPORTED_CAPABILITIES.contains(&cap.as_str()) {
                return Err(format!("Unsupported capability: {}", cap));
            }
            if !self.supported_capabilities.contains(cap) {
                return Err(format!("Capability not enabled for contract: {}", cap));
            }
        }

        Ok(())
    }

    /// Request a dynamic capability
    pub fn request_capability(&mut self, capability: String) -> Result<(), String> {
        if !self.capability_config.allow_dynamic_requests {
            return Err("Dynamic capability requests are not allowed".to_string());
        }

        if self.capability_config.disabled_capabilities.contains(&capability) {
            return Err(format!("Capability {} is disabled at chain level", capability));
        }

        if !SUPPORTED_CAPABILITIES.contains(&capability.as_str()) {
            return Err(format!("Unsupported capability: {}", capability));
        }

        if !self.dynamic_capabilities.contains(&capability) {
            self.dynamic_capabilities.push(capability);
        }

        Ok(())
    }

    /// Generates an ABI from the IR
    pub fn generate_abi(&self) -> HashMap<String, serde_json::Value> {
        let mut abi = HashMap::new();
        
        // Add contract metadata
        abi.insert("name".to_string(), serde_json::Value::String(self.contract_name.clone()));
        abi.insert("version".to_string(), serde_json::Value::Number(serde_json::Number::from(self.version)));
        abi.insert("bytecodeHash".to_string(), serde_json::Value::String(hex::encode(self.bytecode_hash.0)));

        // Add supported capabilities
        abi.insert("capabilities".to_string(), serde_json::Value::Array(
            self.supported_capabilities.iter()
                .map(|cap| serde_json::Value::String(cap.clone()))
                .collect()
        ));

        // Add functions with capabilities
        let functions: Vec<serde_json::Value> = self.entrypoints.iter()
            .map(|f| {
                let mut func = serde_json::Map::new();
                func.insert("name".to_string(), serde_json::Value::String(f.name.clone()));
                func.insert("args".to_string(), serde_json::Value::Array(
                    f.args.iter().map(|arg| serde_json::Value::String(arg.name.clone())).collect()
                ));
                if let Some(ret) = &f.return_type {
                    func.insert("returnType".to_string(), serde_json::Value::String(ret.name.clone()));
                }
                func.insert("gasEstimate".to_string(), serde_json::Value::Number(serde_json::Number::from(f.gas_estimate)));
                func.insert("requiredCapabilities".to_string(), serde_json::Value::Array(
                    f.required_capabilities.iter()
                        .map(|cap| serde_json::Value::String(cap.clone()))
                        .collect()
                ));
                serde_json::Value::Object(func)
            })
            .collect();
        abi.insert("functions".to_string(), serde_json::Value::Array(functions));

        // Add globals
        let globals: Vec<serde_json::Value> = self.global_variables.iter()
            .map(|g| {
                let mut global = serde_json::Map::new();
                global.insert("name".to_string(), serde_json::Value::String(g.name.clone()));
                global.insert("type".to_string(), serde_json::Value::String(g.type_.name.clone()));
                serde_json::Value::Object(global)
            })
            .collect();
        abi.insert("globals".to_string(), serde_json::Value::Array(globals));

        // Add capability configuration
        let mut cap_config = serde_json::Map::new();
        cap_config.insert("enforceCapabilities".to_string(), 
            serde_json::Value::Bool(self.capability_config.enforce_capabilities));
        cap_config.insert("disabledCapabilities".to_string(), 
            serde_json::Value::Array(
                self.capability_config.disabled_capabilities.iter()
                    .map(|cap| serde_json::Value::String(cap.clone()))
                    .collect()
            ));
        cap_config.insert("allowDynamicRequests".to_string(),
            serde_json::Value::Bool(self.capability_config.allow_dynamic_requests));

        // Add capability groups
        let groups: Vec<serde_json::Value> = self.capability_config.capability_groups.iter()
            .map(|(name, group)| {
                let mut map = serde_json::Map::new();
                map.insert("name".to_string(), serde_json::Value::String(name.clone()));
                map.insert("capabilities".to_string(), 
                    serde_json::Value::Array(
                        group.capabilities.iter()
                            .map(|cap| serde_json::Value::String(cap.clone()))
                            .collect()
                    ));
                map.insert("description".to_string(), 
                    serde_json::Value::String(group.description.clone()));
                serde_json::Value::Object(map)
            })
            .collect();
        cap_config.insert("groups".to_string(), serde_json::Value::Array(groups));

        abi.insert("capabilityConfig".to_string(), serde_json::Value::Object(cap_config));

        // Add dynamic capabilities
        abi.insert("dynamicCapabilities".to_string(), 
            serde_json::Value::Array(
                self.dynamic_capabilities.iter()
                    .map(|cap| serde_json::Value::String(cap.clone()))
                    .collect()
            ));

        abi
    }

    /// Gets function at a specific location
    pub fn get_function_at_location(&self, file: &str, line: usize, column: usize) -> Option<&KSLFunctionIR> {
        self.entrypoints.iter().find(|f| {
            if let Some(loc) = &f.location {
                loc.file == file 
                && line >= loc.start_line 
                && line <= loc.end_line
                && (line != loc.start_line || column >= loc.start_column)
                && (line != loc.end_line || column <= loc.end_column)
            } else {
                false
            }
        })
    }

    /// Gets all symbols with their locations
    pub fn get_all_symbols(&self) -> Vec<(String, SourceLocation, SymbolKind)> {
        let mut symbols = Vec::new();
        
        // Add functions
        for func in &self.entrypoints {
            if let Some(loc) = &func.location {
                symbols.push((
                    func.name.clone(),
                    loc.clone(),
                    SymbolKind::Function
                ));
            }
        }

        // Add globals
        for global in &self.global_variables {
            if let Some(loc) = &global.location {
                symbols.push((
                    global.name.clone(),
                    loc.clone(),
                    SymbolKind::Variable
                ));
            }
        }

        symbols
    }

    /// Gets hover information for a location
    pub fn get_hover_info(&self, file: &str, line: usize, column: usize) -> Option<String> {
        // Try to find function first
        if let Some(func) = self.get_function_at_location(file, line, column) {
            let mut info = String::new();
            
            // Add signature
            info.push_str(&format!("function {}(", func.name));
            info.push_str(&func.args.iter()
                .map(|arg| arg.name.clone())
                .collect::<Vec<_>>()
                .join(", "));
            info.push_str(")");
            if let Some(ret) = &func.return_type {
                info.push_str(&format!(" -> {}", ret.name));
            }
            info.push_str("\n\n");

            // Add documentation if available
            if let Some(docs) = &func.documentation {
                info.push_str(&docs.description);
                info.push_str("\n\n");
                
                if !docs.params.is_empty() {
                    info.push_str("Parameters:\n");
                    for param in &docs.params {
                        info.push_str(&format!("- {}: {}\n", param.name, param.description));
                    }
                    info.push_str("\n");
                }

                if let Some(returns) = &docs.returns {
                    info.push_str(&format!("Returns:\n{}\n\n", returns));
                }

                if !docs.examples.is_empty() {
                    info.push_str("Examples:\n");
                    for example in &docs.examples {
                        info.push_str(&format!("```ksl\n{}\n```\n", example));
                    }
                }
            }

            // Add gas estimate
            info.push_str(&format!("\nGas Estimate: {}", func.gas_estimate));

            return Some(info);
        }

        // Try to find global variable
        for global in &self.global_variables {
            if let Some(loc) = &global.location {
                if loc.file == file 
                && line >= loc.start_line 
                && line <= loc.end_line
                && (line != loc.start_line || column >= loc.start_column)
                && (line != loc.end_line || column <= loc.end_column) {
                    let mut info = String::new();
                    
                    // Add type information
                    info.push_str(&format!("{}: {}\n", global.name, global.type_.name));
                    
                    // Add visibility
                    info.push_str(&format!("Visibility: {:?}\n", global.visibility));
                    
                    // Add documentation if available
                    if let Some(docs) = &global.documentation {
                        info.push_str("\n");
                        info.push_str(&docs.description);
                    }

                    return Some(info);
                }
            }
        }

        None
    }

    /// Add a plugin to the IR
    pub fn add_plugin(&mut self, name: String) {
        if !self.plugins.contains(&name) {
            self.plugins.push(name);
        }
    }

    /// Add a plugin operation to the IR
    pub fn add_plugin_op(&mut self, op: PluginOpIR) {
        let key = format!("{}::{}", op.plugin, op.name);
        self.plugin_ops.insert(key, op);
    }

    /// Get a plugin operation by name
    pub fn get_plugin_op(&self, plugin: &str, name: &str) -> Option<&PluginOpIR> {
        let key = format!("{}::{}", plugin, name);
        self.plugin_ops.get(&key)
    }

    /// Validates required capabilities against supported ones
    pub fn validate_capabilities(&self, required: &[String]) -> Result<(), String> {
        for cap in required {
            if !SUPPORTED_CAPABILITIES.contains(&cap.as_str()) {
                return Err(format!("Unsupported capability: {}", cap));
            }
            if !self.supported_capabilities.contains(cap) {
                return Err(format!("Capability not enabled for contract: {}", cap));
            }
        }
        Ok(())
    }

    /// Adds a supported capability
    pub fn add_capability(&mut self, capability: String) -> Result<(), String> {
        if !SUPPORTED_CAPABILITIES.contains(&capability.as_str()) {
            return Err(format!("Unsupported capability: {}", capability));
        }
        if !self.supported_capabilities.contains(&capability) {
            self.supported_capabilities.push(capability);
        }
        Ok(())
    }

    /// Checks if a capability is supported
    pub fn has_capability(&self, capability: &str) -> bool {
        self.supported_capabilities.contains(&capability.to_string())
    }
}

/// Symbol kinds for LSP integration
#[derive(Debug, Clone, PartialEq)]
pub enum SymbolKind {
    Function,
    Variable,
    Type,
    Event,
    Error,
}

/// Function IR
#[derive(Debug, Clone)]
pub struct FunctionIR {
    pub name: String,
    pub params: Vec<ParamIR>,
    pub return_type: TypeIR,
    pub body: Vec<StatementIR>,
    pub is_async: bool,
}

/// Parameter IR
#[derive(Debug, Clone)]
pub struct ParamIR {
    pub name: String,
    pub type_: TypeIR,
}

/// Type IR
#[derive(Debug, Clone)]
pub enum TypeIR {
    Basic(String),
    Array(Box<TypeIR>),
    Map(Box<TypeIR>, Box<TypeIR>),
    Custom(String),
}

/// Statement IR
#[derive(Debug, Clone)]
pub enum StatementIR {
    VarDecl {
        name: String,
        type_: Option<TypeIR>,
        expr: ExpressionIR,
    },
    Expr(ExpressionIR),
    Return(Option<ExpressionIR>),
    If {
        condition: ExpressionIR,
        then_branch: Vec<StatementIR>,
        else_branch: Option<Vec<StatementIR>>,
    },
    PluginCall {
        plugin: String,
        op: String,
        args: Vec<ExpressionIR>,
    },
}

/// Expression IR
#[derive(Debug, Clone)]
pub enum ExpressionIR {
    Ident(String),
    Number(String),
    String(String),
    BinaryOp {
        op: String,
        left: Box<ExpressionIR>,
        right: Box<ExpressionIR>,
    },
    Call {
        name: String,
        args: Vec<ExpressionIR>,
    },
    PluginOp {
        plugin: String,
        op: String,
        args: Vec<ExpressionIR>,
    },
}

/// Global variable IR
#[derive(Debug, Clone)]
pub struct GlobalIR {
    pub name: String,
    pub type_: TypeIR,
    pub value: Option<ExpressionIR>,
}

/// Plugin operation IR
#[derive(Debug, Clone)]
pub struct PluginOpIR {
    pub plugin: String,
    pub name: String,
    pub signature: Vec<TypeIR>,
    pub return_type: TypeIR,
    pub handler: PluginHandlerIR,
}

/// Plugin handler IR
#[derive(Debug, Clone)]
pub enum PluginHandlerIR {
    Native(String),
    Wasm(String),
    Syscall(String),
}

impl KSLFunctionIR {
    /// Validates required capabilities
    pub fn validate_capabilities(&self, ir: &KSLIR) -> Result<(), String> {
        ir.validate_capabilities(&self.required_capabilities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ir_creation() {
        let mut ir = KSLIR::new("test_contract", 1);
        ir.add_plugin("ksl_ai".to_string());
        assert!(ir.plugins.contains(&"ksl_ai".to_string()));
    }

    #[test]
    fn test_plugin_op() {
        let mut ir = KSLIR::new("test_contract", 1);
        let op = PluginOpIR {
            plugin: "ksl_ai".to_string(),
            name: "infer".to_string(),
            signature: vec![TypeIR::Basic("String".to_string())],
            return_type: TypeIR::Basic("Float".to_string()),
            handler: PluginHandlerIR::Native("infer_handler".to_string()),
        };
        ir.add_plugin_op(op);
        assert!(ir.get_plugin_op("ksl_ai", "infer").is_some());
    }

    #[test]
    fn test_capability_validation() {
        let mut ir = KSLIR::new("test_contract", 1);
        ir.add_capability("crypto".to_string()).unwrap();
        ir.add_capability("network".to_string()).unwrap();

        // Test valid capabilities
        assert!(ir.validate_capabilities(&vec!["crypto".to_string()]).is_ok());
        assert!(ir.validate_capabilities(&vec!["network".to_string()]).is_ok());

        // Test invalid capability
        assert!(ir.validate_capabilities(&vec!["invalid".to_string()]).is_err());

        // Test missing capability
        assert!(ir.validate_capabilities(&vec!["ai".to_string()]).is_err());
    }

    #[test]
    fn test_function_capabilities() {
        let mut ir = KSLIR::new("test_contract", 1);
        ir.add_capability("crypto".to_string()).unwrap();

        let func = KSLFunctionIR {
            name: "test_func".to_string(),
            args: vec![],
            return_type: None,
            gas_estimate: 0,
            opcodes: vec![],
            doc: None,
            visibility: FunctionVisibility::Public,
            modifiers: vec![],
            error_handling: None,
            location: None,
            documentation: None,
            required_capabilities: vec!["crypto".to_string()],
        };

        assert!(func.validate_capabilities(&ir).is_ok());
    }

    #[test]
    fn test_abi_generation_with_capabilities() {
        let mut ir = KSLIR::new("test_contract", 1);
        ir.add_capability("crypto".to_string()).unwrap();
        ir.add_capability("network".to_string()).unwrap();

        let mut func = KSLFunctionIR {
            name: "send_data".to_string(),
            args: vec![],
            return_type: None,
            gas_estimate: 1000,
            opcodes: vec![],
            doc: Some("Send data over network".to_string()),
            visibility: FunctionVisibility::Public,
            modifiers: vec![],
            error_handling: None,
            location: None,
            documentation: None,
            required_capabilities: vec!["network".to_string(), "crypto".to_string()],
        };

        ir.add_function(func);

        let abi = ir.generate_abi();
        
        // Check contract capabilities
        let caps = abi.get("capabilities").unwrap().as_array().unwrap();
        assert!(caps.contains(&serde_json::Value::String("crypto".to_string())));
        assert!(caps.contains(&serde_json::Value::String("network".to_string())));

        // Check function capabilities
        let funcs = abi.get("functions").unwrap().as_array().unwrap();
        let func = &funcs[0].as_object().unwrap();
        let func_caps = func.get("requiredCapabilities").unwrap().as_array().unwrap();
        assert!(func_caps.contains(&serde_json::Value::String("network".to_string())));
        assert!(func_caps.contains(&serde_json::Value::String("crypto".to_string())));
    }

    #[test]
    fn test_ir_json_export_with_capabilities() {
        let mut ir = KSLIR::new("test_contract", 1);
        ir.add_capability("crypto".to_string()).unwrap();

        let func = KSLFunctionIR {
            name: "sign_data".to_string(),
            args: vec![],
            return_type: None,
            gas_estimate: 500,
            opcodes: vec![],
            doc: Some("Sign data using crypto".to_string()),
            visibility: FunctionVisibility::Public,
            modifiers: vec![],
            error_handling: None,
            location: None,
            documentation: None,
            required_capabilities: vec!["crypto".to_string()],
        };

        ir.add_function(func);

        let json = ir.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Check contract capabilities
        assert!(parsed["capabilities"].as_array().unwrap()
            .contains(&serde_json::Value::String("crypto".to_string())));

        // Check function capabilities
        let func = &parsed["functions"].as_array().unwrap()[0];
        assert!(func["required_capabilities"].as_array().unwrap()
            .contains(&serde_json::Value::String("crypto".to_string())));
    }

    #[test]
    fn test_capability_groups_basic() {
        let mut ir = KSLIR::new("test_contract", 1);
        
        // Add individual capabilities from sensitive group
        ir.add_capability("fs".to_string()).unwrap();
        ir.add_capability("crypto".to_string()).unwrap();
        ir.add_capability("auth".to_string()).unwrap();

        // Should be able to use sensitive group
        assert!(ir.validate_capabilities(&vec!["sensitive".to_string()]).is_ok());
    }

    #[test]
    fn test_capability_groups_partial() {
        let mut ir = KSLIR::new("test_contract", 1);
        
        // Only add some capabilities from sensitive group
        ir.add_capability("fs".to_string()).unwrap();
        ir.add_capability("crypto".to_string()).unwrap();
        // Missing "auth"

        // Should fail when using sensitive group
        assert!(ir.validate_capabilities(&vec!["sensitive".to_string()]).is_err());
    }

    #[test]
    fn test_capability_groups_multiple() {
        let mut ir = KSLIR::new("test_contract", 1);
        
        // Add capabilities from multiple groups
        ir.add_capability("fs".to_string()).unwrap();
        ir.add_capability("crypto".to_string()).unwrap();
        ir.add_capability("auth".to_string()).unwrap();
        ir.add_capability("http".to_string()).unwrap();
        ir.add_capability("tcp".to_string()).unwrap();
        ir.add_capability("udp".to_string()).unwrap();

        // Should be able to use both groups
        assert!(ir.validate_capabilities(&vec!["sensitive".to_string(), "network".to_string()]).is_ok());
    }

    #[test]
    fn test_chain_config_enforcement() {
        let mut ir = KSLIR::new("test_contract", 1);
        
        // Disable capability enforcement
        ir.capability_config.enforce_capabilities = false;

        // Should pass even without capabilities
        assert!(ir.validate_capabilities(&vec!["fs".to_string(), "network".to_string()]).is_ok());
    }

    #[test]
    fn test_chain_config_disabled_caps() {
        let mut ir = KSLIR::new("test_contract", 1);
        
        // Add capability but disable at chain level
        ir.add_capability("fs".to_string()).unwrap();
        ir.capability_config.disabled_capabilities.push("fs".to_string());

        // Should fail due to chain-level disable
        assert!(ir.validate_capabilities(&vec!["fs".to_string()]).is_err());
    }

    #[test]
    fn test_dynamic_requests_basic() {
        let mut ir = KSLIR::new("test_contract", 1);
        
        // Enable dynamic requests
        ir.capability_config.allow_dynamic_requests = true;

        // Request a capability
        assert!(ir.request_capability("network".to_string()).is_ok());
        assert!(ir.dynamic_capabilities.contains(&"network".to_string()));
    }

    #[test]
    fn test_dynamic_requests_disabled() {
        let mut ir = KSLIR::new("test_contract", 1);
        
        // Dynamic requests disabled by default
        assert!(ir.request_capability("network".to_string()).is_err());
    }

    #[test]
    fn test_dynamic_requests_chain_disabled() {
        let mut ir = KSLIR::new("test_contract", 1);
        
        // Enable dynamic requests but disable capability at chain level
        ir.capability_config.allow_dynamic_requests = true;
        ir.capability_config.disabled_capabilities.push("network".to_string());

        // Should fail due to chain-level disable
        assert!(ir.request_capability("network".to_string()).is_err());
    }

    #[test]
    fn test_abi_capability_config() {
        let mut ir = KSLIR::new("test_contract", 1);
        
        // Configure capabilities
        ir.capability_config.enforce_capabilities = true;
        ir.capability_config.allow_dynamic_requests = true;
        ir.capability_config.disabled_capabilities.push("fs".to_string());

        // Add some capabilities
        ir.add_capability("network".to_string()).unwrap();
        ir.request_capability("crypto".to_string()).unwrap();

        let abi = ir.generate_abi();
        
        // Check capability config in ABI
        let config = abi.get("capabilityConfig").unwrap().as_object().unwrap();
        assert_eq!(config.get("enforceCapabilities").unwrap().as_bool().unwrap(), true);
        assert_eq!(config.get("allowDynamicRequests").unwrap().as_bool().unwrap(), true);
        
        let disabled = config.get("disabledCapabilities").unwrap().as_array().unwrap();
        assert!(disabled.contains(&serde_json::Value::String("fs".to_string())));

        // Check groups in ABI
        let groups = config.get("groups").unwrap().as_array().unwrap();
        let sensitive_group = groups.iter()
            .find(|g| g.get("name").unwrap().as_str().unwrap() == "sensitive")
            .unwrap();
        let sensitive_caps = sensitive_group.get("capabilities").unwrap().as_array().unwrap();
        assert!(sensitive_caps.contains(&serde_json::Value::String("fs".to_string())));
        assert!(sensitive_caps.contains(&serde_json::Value::String("crypto".to_string())));
        assert!(sensitive_caps.contains(&serde_json::Value::String("auth".to_string())));

        // Check dynamic capabilities in ABI
        let dynamic_caps = abi.get("dynamicCapabilities").unwrap().as_array().unwrap();
        assert!(dynamic_caps.contains(&serde_json::Value::String("crypto".to_string())));
    }

    #[test]
    fn test_custom_capability_group() {
        let mut ir = KSLIR::new("test_contract", 1);
        
        // Add custom capability group
        ir.capability_config.capability_groups.insert(
            "custom".to_string(),
            CapabilityGroup {
                name: "custom".to_string(),
                capabilities: vec!["ai".to_string(), "gpu".to_string()],
                description: "Custom capability group".to_string(),
            }
        );

        // Add required capabilities
        ir.add_capability("ai".to_string()).unwrap();
        ir.add_capability("gpu".to_string()).unwrap();

        // Should be able to use custom group
        assert!(ir.validate_capabilities(&vec!["custom".to_string()]).is_ok());
    }
}