// ksl_ir.rs
// Intermediate Representation (IR) for KSL program auditing

use serde::{Serialize, Deserialize};
use std::fmt;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ir_creation() {
        let mut program = IRProgram::new("test.ksl");
        program.push(IRNode::Assign("x".to_string(), "42".to_string()));
        program.push(IRNode::Add("y".to_string(), "x".to_string(), "x".to_string()));
        assert_eq!(program.instructions.len(), 2);
    }

    #[test]
    fn test_ir_serialization() {
        let mut program = IRProgram::new("test.ksl");
        program.push(IRNode::Assert("x >= 0".to_string()));
        program.push(IRNode::Verify("y == z".to_string(), "Values must match".to_string()));
        
        let export = IRExport::new(program);
        let json = serde_json::to_string_pretty(&export).unwrap();
        
        let imported: IRExport = serde_json::from_str(&json).unwrap();
        assert_eq!(imported.program.instructions.len(), 2);
    }

    #[test]
    fn test_ir_display() {
        let node = IRNode::Add("x".to_string(), "y".to_string(), "z".to_string());
        assert_eq!(node.to_string(), "x = y + z");
        
        let node = IRNode::Assert("x >= 0".to_string());
        assert_eq!(node.to_string(), "assert x >= 0");
    }
} 