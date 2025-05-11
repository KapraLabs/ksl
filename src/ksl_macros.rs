// ksl_macros.rs
// Macro system for KSL to enable metaprogramming and code generation,
// supporting networking operations, async/await patterns, and procedural macros.

use crate::ksl_ast_transform::{AstTransformer, TransformConfig};
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_generics::{TypeParam, TraitBound};
use std::collections::HashMap;
use std::path::PathBuf;
use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::{parse_macro_input, ItemFn, Ident, FnArg, ReturnType, Type};
use proc_macro2::Span;

// Stub for ParseError that was imported from ksl_parser
#[derive(Debug)]
pub struct ParseError {
    pub message: String,
    pub position: SourcePosition,
}

// Stub for parse function that was imported from ksl_parser
pub fn parse(_source: &str) -> Result<Vec<AstNode>, ParseError> {
    // This is just a stub to fix the circular dependency
    // The real implementation is in ksl_parser.rs
    unimplemented!("This is a stub for the parser function. The real implementation is in ksl_parser.rs")
}

/// Represents a macro parameter (e.g., $msg: string).
#[derive(Debug, Clone)]
pub struct MacroParam {
    /// Parameter name (e.g., "msg")
    name: String,
    /// Parameter type (e.g., string, ident)
    param_type: ParamType,
    /// Whether the parameter is optional
    is_optional: bool,
}

/// Represents an attribute argument.
#[derive(Debug, Clone, PartialEq)]
pub enum AttributeArg {
    /// String literal argument (e.g., name = "value")
    String(String),
    /// Numeric argument (e.g., limit = 100)
    Number(u64),
    /// Identifier argument (e.g., flag = true)
    Ident(String),
    /// Key-value pair (e.g., config = { key: "value" })
    KeyValue(String, Box<AttributeArg>),
    /// Array of arguments (e.g., values = [1, 2, 3])
    Array(Vec<AttributeArg>),
    /// Tuple of arguments (e.g., point = (1, 2))
    Tuple(Vec<AttributeArg>),
}

/// Represents a code attribute (e.g., #[contract], #[test], #[shard])
#[derive(Debug, Clone, PartialEq)]
pub struct Attribute {
    /// Name of the attribute
    pub name: String,
    /// Arguments for the attribute
    pub args: Vec<AttributeArg>,
    /// Source position for error reporting
    pub position: SourcePosition,
}

impl Attribute {
    /// Creates a new attribute
    pub fn new(name: String, args: Vec<AttributeArg>, position: SourcePosition) -> Self {
        Attribute {
            name,
            args,
            position,
        }
    }
    
    /// Checks if an attribute is of a specific name
    pub fn is(&self, name: &str) -> bool {
        self.name == name
    }
    
    /// Gets an argument value by name
    pub fn get_arg(&self, name: &str) -> Option<&AttributeArg> {
        self.args.iter().find(|arg| {
            match arg {
                AttributeArg::KeyValue(key, _) => key == name,
                _ => false,
            }
        })
    }
}

impl MacroParam {
    /// Creates a new macro parameter.
    pub fn new(name: &str, param_type: ParamType, is_optional: bool) -> Self {
        MacroParam {
            name: name.to_string(),
            param_type,
            is_optional,
        }
    }
}

/// Token types for macro parameters
#[derive(Debug, Clone, PartialEq)]
pub enum TokenType {
    /// String literal
    String,
    /// Identifier
    Ident,
    /// Boolean value
    Bool,
    /// Integer number
    Int(IntType),
    /// Floating point number
    Float(FloatType),
    /// Character
    Char,
    /// Expression
    Expr,
    /// Type annotation
    Type,
}

/// Integer types
#[derive(Debug, Clone, PartialEq)]
pub enum IntType {
    U8, U16, U32, U64, U128,
    I8, I16, I32, I64, I128,
    USize, ISize,
}

/// Floating point types
#[derive(Debug, Clone, PartialEq)]
pub enum FloatType {
    F32, F64,
}

/// Types of macro parameters.
#[derive(Debug, Clone)]
pub enum ParamType {
    /// Token type
    Token(TokenType),
    /// Expression
    Expr,
    /// Network endpoint
    NetworkEndpoint,
    /// Network headers
    NetworkHeaders,
    /// Async task
    AsyncTask,
}

impl ParamType {
    /// Check if a node matches this parameter type
    pub fn matches_node(&self, node: &AstNode) -> bool {
        match (self, node) {
            (ParamType::Token(TokenType::String), AstNode::String(_)) => true,
            (ParamType::Token(TokenType::Ident), AstNode::Ident(_)) => true,
            (ParamType::Token(TokenType::Bool), AstNode::Bool(_)) => true,
            (ParamType::Token(TokenType::Int(_)), AstNode::Int(_, _)) => true,
            (ParamType::Token(TokenType::Float(_)), AstNode::Float(_, _)) => true,
            (ParamType::Token(TokenType::Char), AstNode::Char(_)) => true,
            (ParamType::Expr, _) => true, // Any node can be an expression
            (ParamType::NetworkEndpoint, AstNode::String(_)) => true,
            (ParamType::NetworkHeaders, _) => true, // Headers are checked separately
            (ParamType::AsyncTask, _) => true, // Async tasks are checked separately
            _ => false,
        }
    }
}

/// Documentation for a macro
#[derive(Debug, Clone)]
pub struct MacroDoc {
    /// Brief description of the macro
    summary: String,
    /// Detailed documentation
    details: Option<String>,
    /// Example usage
    examples: Vec<String>,
    /// Parameter descriptions
    param_docs: HashMap<String, String>,
    /// Return value description
    returns: Option<String>,
    /// Since version
    since: Option<String>,
    /// Deprecation notice
    deprecated: Option<String>,
}

impl MacroDoc {
    /// Creates a new macro documentation
    pub fn new(summary: &str) -> Self {
        MacroDoc {
            summary: summary.to_string(),
            details: None,
            examples: Vec::new(),
            param_docs: HashMap::new(),
            returns: None,
            since: None,
            deprecated: None,
        }
    }

    /// Add detailed documentation
    pub fn with_details(mut self, details: &str) -> Self {
        self.details = Some(details.to_string());
        self
    }

    /// Add an example
    pub fn with_example(mut self, example: &str) -> Self {
        self.examples.push(example.to_string());
        self
    }

    /// Add parameter documentation
    pub fn with_param(mut self, param: &str, description: &str) -> Self {
        self.param_docs.insert(param.to_string(), description.to_string());
        self
    }

    /// Add return value documentation
    pub fn with_returns(mut self, returns: &str) -> Self {
        self.returns = Some(returns.to_string());
        self
    }

    /// Add version information
    pub fn with_since(mut self, since: &str) -> Self {
        self.since = Some(since.to_string());
        self
    }

    /// Mark as deprecated
    pub fn with_deprecated(mut self, message: &str) -> Self {
        self.deprecated = Some(message.to_string());
        self
    }

    /// Format documentation as markdown
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        // Add deprecation warning if present
        if let Some(dep) = &self.deprecated {
            md.push_str(&format!("⚠️ **DEPRECATED**: {}\n\n", dep));
        }

        // Add summary
        md.push_str(&self.summary);
        md.push_str("\n\n");

        // Add detailed description if present
        if let Some(details) = &self.details {
            md.push_str(details);
            md.push_str("\n\n");
        }

        // Add parameters
        if !self.param_docs.is_empty() {
            md.push_str("### Parameters\n\n");
            for (param, desc) in &self.param_docs {
                md.push_str(&format!("- `{}`: {}\n", param, desc));
            }
            md.push_str("\n");
        }

        // Add return value if present
        if let Some(returns) = &self.returns {
            md.push_str("### Returns\n\n");
            md.push_str(returns);
            md.push_str("\n\n");
        }

        // Add examples
        if !self.examples.is_empty() {
            md.push_str("### Examples\n\n");
            for example in &self.examples {
                md.push_str("```ksl\n");
                md.push_str(example);
                md.push_str("\n```\n\n");
            }
        }

        // Add version info if present
        if let Some(since) = &self.since {
            md.push_str(&format!("*Since version {}*\n", since));
        }

        md
    }
}

/// Represents a macro definition.
#[derive(Debug, Clone)]
pub struct MacroDef {
    /// Macro name (e.g., "log")
    name: String,
    /// Parameters (e.g., $msg: string)
    params: Vec<MacroParam>,
    /// Body of the macro (what it expands to)
    body: Vec<AstNode>,
    /// Whether the macro is async
    is_async: bool,
    /// Whether the macro handles networking operations
    is_networking: bool,
    /// Documentation
    doc: Option<MacroDoc>,
}

impl MacroDef {
    /// Creates a new macro definition.
    pub fn new(name: &str, params: Vec<MacroParam>, body: Vec<AstNode>, is_async: bool, is_networking: bool) -> Self {
        MacroDef {
            name: name.to_string(),
            params,
            body,
            is_async,
            is_networking,
            doc: None,
        }
    }

    /// Creates a new macro definition with documentation
    pub fn new_documented(
        name: &str,
        params: Vec<MacroParam>,
        body: Vec<AstNode>,
        is_async: bool,
        is_networking: bool,
        doc: Option<MacroDoc>,
    ) -> Self {
        MacroDef {
            name: name.to_string(),
            params,
            body,
            is_async,
            is_networking,
            doc,
        }
    }
}

/// Represents a macro invocation (e.g., log!("Hello")).
#[derive(Debug, Clone)]
pub struct MacroCall {
    /// Macro name (e.g., "log")
    name: String,
    /// Arguments (e.g., "Hello")
    args: Vec<AstNode>,
    /// Whether the call is async
    is_async: bool,
    /// Whether the call involves networking
    is_networking: bool,
    /// Source position for error reporting
    position: SourcePosition,
}

impl MacroCall {
    /// Creates a new macro call.
    pub fn new(name: &str, args: Vec<AstNode>, is_async: bool, is_networking: bool) -> Self {
        MacroCall {
            name: name.to_string(),
            args,
            is_async,
            is_networking,
            position: SourcePosition::new(1, 1),
        }
    }
}

/// Metadata that can be attached to AST nodes
#[derive(Debug, Clone)]
pub struct NodeMetadata {
    /// Key-value metadata pairs
    pub values: HashMap<String, String>,
    /// Type-specific metadata (for contract, event, etc.)
    pub type_info: Option<TypeMetadata>,
    /// Source position
    pub position: SourcePosition,
}

/// Type-specific metadata
#[derive(Debug, Clone)]
pub enum TypeMetadata {
    /// Contract-specific metadata
    Contract(ContractMetadata),
    /// Event-specific metadata
    Event(EventMetadata),
    /// Test-specific metadata
    Test(TestMetadata),
    /// Procedural macro metadata
    Procedural(ProcMacro),
    /// Hot reloadable metadata
    HotReloadable(HotReloadableMetadata),
}

/// Contract-specific metadata
#[derive(Debug, Clone)]
pub struct ContractMetadata {
    /// Contract owner
    pub owner: String,
    /// Gas limit
    pub gas_limit: u64,
    /// Additional contract properties
    pub properties: HashMap<String, String>,
}

/// Hot reloadable function metadata
#[derive(Debug, Clone)]
pub struct HotReloadableMetadata {
    /// Whether the function can be hot reloaded
    pub reloadable: bool,
    /// Export name for FFI
    pub export_name: Option<String>,
    /// Additional attributes needed for reloading
    pub attributes: HashMap<String, String>,
}

/// Extend the AST to support macros (used by ksl_parser.rs).
#[derive(Debug, Clone)]
pub enum AstNode {
    /// Macro definition
    MacroDef(MacroDef),
    /// Macro invocation
    MacroCall(MacroCall),
    /// Async function declaration
    AsyncFnDecl { name: String, params: Vec<(String, Type)>, body: Vec<AstNode> },
    /// Await expression
    Await { expr: Box<AstNode> },
    /// Network operation
    Network { op_type: NetworkOpType, endpoint: String, headers: Option<HashMap<String, String>>, data: Option<Vec<u8>> },
    /// Existing node types...
    Let { name: String, ty: Type, value: Box<AstNode> },
    Call { name: String, args: Vec<AstNode> },
    Literal(String),
    /// Procedural macro attribute
    ProcMacro(ProcMacro),
    /// Array of AST nodes
    Array(Vec<AstNode>),
    /// Tuple of AST nodes
    Tuple(Vec<AstNode>),
    /// Type node
    Type(Type),
    /// Map literal
    Map(HashMap<String, AstNode>),
    
    /// JSON literal (for structured data)
    LiteralJson(String),
    
    /// Node with metadata
    WithMetadata {
        node: Box<AstNode>,
        metadata: NodeMetadata,
    },
    /// Identifier (variable names, function names, etc.)
    Ident(String),
    /// Boolean literal
    Bool(bool),
    /// Integer literal with type
    Int(String, IntType),
    /// Float literal with type
    Float(String, FloatType),
    /// Character literal
    Char(char),
    /// String literal (now more specific to actual strings)
    String(String),
    /// Attribute (e.g., #[no_mangle])
    Attribute {
        name: String,
        args: Vec<AstNode>,
    },
    /// Function declaration
    FnDecl {
        name: String,
        params: Vec<(String, Type)>,
        return_type: Option<Type>,
        body: Vec<AstNode>,
    },
    /// Pattern matching
    Match {
        expr: Box<AstNode>,
        arms: Vec<(AstNode, AstNode)>,
    },
    /// Pattern
    Pattern(String, Vec<AstNode>),
    /// Closure
    Closure {
        params: Vec<(String, Type)>,
        body: Vec<AstNode>,
    },
    /// Unit value
    Unit,
}

/// Types of network operations.
#[derive(Debug, Clone)]
pub enum NetworkOpType {
    /// HTTP GET request
    HttpGet,
    /// HTTP POST request
    HttpPost,
    /// TCP connection
    TcpConnect,
    /// TCP send
    TcpSend,
    /// TCP receive
    TcpReceive,
}

/// Represents a procedural macro attribute (e.g., #[shard], #[validator])
#[derive(Debug, Clone)]
pub struct ProcMacro {
    /// Name of the procedural macro (e.g., "shard", "validator")
    name: String,
    /// Arguments passed to the macro
    args: Vec<ProcMacroArg>,
    /// The AST node being decorated
    target: Box<AstNode>,
    /// Source position for error reporting
    position: SourcePosition,
    /// Documentation
    doc: Option<MacroDoc>,
}

/// Arguments for procedural macros
#[derive(Debug, Clone)]
pub enum ProcMacroArg {
    /// String literal argument
    String(String),
    /// Numeric argument
    Number(u64),
    /// Identifier argument
    Ident(String),
    /// Key-value pair
    KeyValue(String, Box<ProcMacroArg>),
    /// Array of arguments
    Array(Vec<ProcMacroArg>),
    /// Tuple of arguments
    Tuple(Vec<ProcMacroArg>),
}

/// Contract configuration for #[contract] macro
#[derive(Debug, Clone)]
pub struct ContractConfig {
    /// Contract owner address
    owner: String,
    /// Gas limit for contract execution
    gas_limit: u64,
    /// Contract metadata
    metadata: HashMap<String, String>,
}

impl ContractConfig {
    /// Creates a new contract configuration
    pub fn new(owner: String, gas_limit: u64) -> Self {
        ContractConfig {
            owner,
            gas_limit,
            metadata: HashMap::new(),
        }
    }

    /// Adds metadata to the contract configuration
    pub fn add_metadata(&mut self, key: &str, value: &str) {
        self.metadata.insert(key.to_string(), value.to_string());
    }
}

/// Configuration for zero-knowledge proofs
#[derive(Debug, Clone)]
pub struct ZkConfig {
    /// Circuit type (e.g., "groth16", "plonk")
    circuit_type: String,
    /// Public inputs
    public_inputs: Vec<String>,
    /// Private inputs
    private_inputs: Vec<String>,
}

/// Configuration for blockchain events
#[derive(Debug, Clone)]
pub struct EventConfig {
    /// Event name
    name: String,
    /// Event parameters
    params: Vec<(String, Type)>,
    /// Whether the event is indexed
    indexed: bool,
}

/// Configuration for test functions
#[derive(Debug, Clone)]
pub struct TestConfig {
    /// Test name
    name: String,
    /// Whether to ignore the test
    ignore: bool,
    /// Expected panic message if test should panic
    should_panic: Option<String>,
    /// Test timeout in milliseconds
    timeout_ms: Option<u64>,
}

impl ProcMacro {
    /// Expands the procedural macro into an AST
    pub fn expand(&self) -> Result<Vec<AstNode>, KslError> {
        match self.name.as_str() {
            "shard" => self.expand_shard_macro(),
            "validator" => self.expand_validator_macro(),
            "contract" => self.expand_contract_macro(),
            "zk" => self.expand_zk_macro(),
            "event" => self.expand_event_macro(),
            "test" => self.expand_test_macro(),
            "hot_reloadable" => self.expand_hot_reloadable_macro(),
            _ => Err(KslError::type_error(
                format!("Unknown procedural macro: {}", self.name),
                self.position,
            )),
        }
    }

    /// Expands the #[shard] macro
    fn expand_shard_macro(&self) -> Result<Vec<AstNode>, KslError> {
        // Extract shard size from arguments
        let size = self.args.iter()
            .find_map(|arg| {
                if let ProcMacroArg::KeyValue(key, value) = arg {
                    if key == "size" {
                        if let ProcMacroArg::Number(n) = value.as_ref() {
                            return Some(*n);
                        }
                    }
                }
                None
            })
            .ok_or_else(|| KslError::type_error(
                "Missing 'size' argument for #[shard] macro".to_string(),
                self.position,
            ))?;

        // Generate shard-specific code
        let mut expanded = vec![];
        
        // Add shard configuration
        expanded.push(AstNode::Let {
            name: "shard_size".to_string(),
            ty: Type::U64,
            value: Box::new(AstNode::Literal(size.to_string())),
        });

        // Add shard validation
        expanded.push(AstNode::Let {
            name: "validate_shard".to_string(),
            ty: Type::Bool,
            value: Box::new(AstNode::Call {
                name: "validate_shard_size".to_string(),
                args: vec![AstNode::Literal("shard_size".to_string())],
            }),
        });

        // Add the original target node
        expanded.push(*self.target.clone());

        Ok(expanded)
    }

    /// Expands the #[validator] macro
    fn expand_validator_macro(&self) -> Result<Vec<AstNode>, KslError> {
        // Extract validator stake from arguments
        let stake = self.args.iter()
            .find_map(|arg| {
                if let ProcMacroArg::KeyValue(key, value) = arg {
                    if key == "stake" {
                        if let ProcMacroArg::Number(n) = value.as_ref() {
                            return Some(*n);
                        }
                    }
                }
                None
            })
            .ok_or_else(|| KslError::type_error(
                "Missing 'stake' argument for #[validator] macro".to_string(),
                self.position,
            ))?;

        // Generate validator-specific code
        let mut expanded = vec![];
        
        // Add validator configuration
        expanded.push(AstNode::Let {
            name: "validator_stake".to_string(),
            ty: Type::U64,
            value: Box::new(AstNode::Literal(stake.to_string())),
        });

        // Add stake validation
        expanded.push(AstNode::Let {
            name: "validate_stake".to_string(),
            ty: Type::Bool,
            value: Box::new(AstNode::Call {
                name: "validate_minimum_stake".to_string(),
                args: vec![AstNode::Literal("validator_stake".to_string())],
            }),
        });

        // Add the original target node
        expanded.push(*self.target.clone());

        Ok(expanded)
    }

    /// Expands the #[contract] macro
    fn expand_contract_macro(&self) -> Result<Vec<AstNode>, KslError> {
        // Parse contract configuration
        let config = self.parse_contract_config()?;
        let mut expanded = vec![];
        
        // Create metadata map
        let mut metadata_map = HashMap::new();
        metadata_map.insert("owner".to_string(), AstNode::Literal(config.owner.clone()));
        metadata_map.insert("gas_limit".to_string(), AstNode::Literal(config.gas_limit.to_string()));
        
        // Add all custom metadata
        for (key, value) in &config.metadata {
            metadata_map.insert(key.clone(), AstNode::Literal(value.clone()));
        }

        // Add structured metadata as a map
        expanded.push(AstNode::Let {
            name: "contract_metadata".to_string(),
            ty: Type::Map(
                Box::new(Type::String),
                Box::new(Type::String)
            ),
            value: Box::new(AstNode::Map(metadata_map.clone())),
        });

        // Add contract configuration
        expanded.push(AstNode::Let {
            name: "contract_owner".to_string(),
            ty: Type::String,
            value: Box::new(AstNode::Literal(config.owner.clone())),
        });

        expanded.push(AstNode::Let {
            name: "contract_gas_limit".to_string(),
            ty: Type::U64,
            value: Box::new(AstNode::Literal(config.gas_limit.to_string())),
        });

        // Add owner validation
        expanded.push(AstNode::Let {
            name: "validate_owner".to_string(),
            ty: Type::Bool,
            value: Box::new(AstNode::Call {
                name: "check_contract_owner".to_string(),
                args: vec![
                    AstNode::Literal("contract_owner".to_string()),
                    AstNode::Literal("msg.sender".to_string()),
                ],
            }),
        });

        // Add gas validation
        expanded.push(AstNode::Let {
            name: "validate_gas".to_string(),
            ty: Type::Bool,
            value: Box::new(AstNode::Call {
                name: "check_contract_gas".to_string(),
                args: vec![
                    AstNode::Literal("contract_gas_limit".to_string()),
                    AstNode::Literal("msg.gas".to_string()),
                ],
            }),
        });

        // Create contract metadata structure
        let contract_metadata = ContractMetadata {
            owner: config.owner.clone(),
            gas_limit: config.gas_limit,
            properties: config.metadata.clone(),
        };

        // Create node metadata
        let node_metadata = NodeMetadata {
            values: metadata_map,
            type_info: Some(TypeMetadata::Contract(contract_metadata)),
            position: self.position,
        };

        // Wrap the target node with metadata
        let target_with_metadata = AstNode::WithMetadata {
            node: self.target.clone(),
            metadata: node_metadata,
        };

        // Add the metadata-wrapped target node
        expanded.push(target_with_metadata);

        Ok(expanded)
    }

    /// Expands the #[zk] macro for zero-knowledge proofs
    fn expand_zk_macro(&self) -> Result<Vec<AstNode>, KslError> {
        // Parse ZK configuration
        let config = self.parse_zk_config()?;
        let mut expanded = vec![];

        // Add ZK circuit configuration
        expanded.push(AstNode::Let {
            name: "zk_circuit_type".to_string(),
            ty: Type::String,
            value: Box::new(AstNode::Literal(config.circuit_type)),
        });

        // Add public inputs
        expanded.push(AstNode::Let {
            name: "zk_public_inputs".to_string(),
            ty: Type::Array(Box::new(Type::String)),
            value: Box::new(AstNode::Array(
                config.public_inputs.into_iter()
                    .map(|input| AstNode::Literal(input))
                    .collect()
            )),
        });

        // Add private inputs
        expanded.push(AstNode::Let {
            name: "zk_private_inputs".to_string(),
            ty: Type::Array(Box::new(Type::String)),
            value: Box::new(AstNode::Array(
                config.private_inputs.into_iter()
                    .map(|input| AstNode::Literal(input))
                    .collect()
            )),
        });

        // Add ZK verification setup
        expanded.push(AstNode::Call {
            name: "setup_zk_circuit".to_string(),
            args: vec![
                AstNode::Literal("zk_circuit_type".to_string()),
                AstNode::Literal("zk_public_inputs".to_string()),
                AstNode::Literal("zk_private_inputs".to_string()),
            ],
        });

        // Add the original target node
        expanded.push(*self.target.clone());

        Ok(expanded)
    }

    /// Expands the #[event] macro for blockchain events
    fn expand_event_macro(&self) -> Result<Vec<AstNode>, KslError> {
        // Parse event configuration
        let config = self.parse_event_config()?;
        let mut expanded = vec![];

        // Add event configuration
        expanded.push(AstNode::Let {
            name: "event_name".to_string(),
            ty: Type::String,
            value: Box::new(AstNode::Literal(config.name)),
        });

        // Add event parameters
        let params_array = config.params.into_iter()
            .map(|(name, ty)| AstNode::Tuple(vec![
                AstNode::Literal(name),
                AstNode::Type(ty),
            ]))
            .collect::<Vec<_>>();

        expanded.push(AstNode::Let {
            name: "event_params".to_string(),
            ty: Type::Array(Box::new(Type::Tuple(vec![Type::String, Type::Type]))),
            value: Box::new(AstNode::Array(params_array)),
        });

        // Add indexed flag
        expanded.push(AstNode::Let {
            name: "event_indexed".to_string(),
            ty: Type::Bool,
            value: Box::new(AstNode::Literal(config.indexed.to_string())),
        });

        // Register event in the blockchain
        expanded.push(AstNode::Call {
            name: "register_blockchain_event".to_string(),
            args: vec![
                AstNode::Literal("event_name".to_string()),
                AstNode::Literal("event_params".to_string()),
                AstNode::Literal("event_indexed".to_string()),
            ],
        });

        // Add the original target node
        expanded.push(*self.target.clone());

        Ok(expanded)
    }

    /// Expands the #[test] macro for unit tests
    fn expand_test_macro(&self) -> Result<Vec<AstNode>, KslError> {
        // Parse test configuration
        let config = self.parse_test_config()?;
        let mut expanded = vec![];

        // Add test configuration
        expanded.push(AstNode::Let {
            name: "test_name".to_string(),
            ty: Type::String,
            value: Box::new(AstNode::Literal(config.name)),
        });

        // Add ignore flag if present
        if config.ignore {
            expanded.push(AstNode::Let {
                name: "test_ignored".to_string(),
                ty: Type::Bool,
                value: Box::new(AstNode::Literal("true".to_string())),
            });
        }

        // Add panic expectation if present
        if let Some(panic_msg) = config.should_panic {
            expanded.push(AstNode::Let {
                name: "test_should_panic".to_string(),
                ty: Type::String,
                value: Box::new(AstNode::Literal(panic_msg)),
            });
        }

        // Add timeout if present
        if let Some(timeout) = config.timeout_ms {
            expanded.push(AstNode::Let {
                name: "test_timeout_ms".to_string(),
                ty: Type::U64,
                value: Box::new(AstNode::Literal(timeout.to_string())),
            });
        }

        // Wrap the target in test harness
        expanded.push(AstNode::Call {
            name: "run_test".to_string(),
            args: vec![
                AstNode::Literal("test_name".to_string()),
                Box::new(*self.target.clone()),
            ],
        });

        Ok(expanded)
    }

    /// Expands the #[hot_reloadable] macro with enhanced FFI support
    fn expand_hot_reloadable_macro(&self) -> Result<Vec<AstNode>, KslError> {
        // Extract function information
        let (fn_name, signature) = match self.target.as_ref() {
            AstNode::FnDecl { name, params, return_type, .. } => {
                let sig = FunctionSignature {
                    params: params.iter().map(|(_, ty)| ty.clone()).collect(),
                    return_type: return_type.clone(),
                    is_async: false,
                };
                (name.clone(), sig)
            }
            _ => return Err(KslError::type_error(
                "#[hot_reloadable] can only be applied to functions".to_string(),
                self.position,
            )),
        };

        // Generate export name
        let export_name = if let Some(name) = self.get_arg_value("name") {
            name
        } else {
            format!("ksl_hot_reload_{}", fn_name)
        };

        // Create hot reloadable function info
        let fn_info = HotReloadableFunction {
            original_name: fn_name.clone(),
            export_name: export_name.clone(),
            signature,
            position: self.position,
            attributes: self.args.iter()
                .filter_map(|arg| {
                    if let ProcMacroArg::KeyValue(k, v) = arg {
                        Some((k.clone(), v.to_string()))
                    } else {
                        None
                    }
                })
                .collect(),
        };

        // Create metadata
        let mut metadata = HashMap::new();
        metadata.insert("hot_reloadable".to_string(), "true".to_string());
        metadata.insert("export_name".to_string(), export_name.clone());

        let hot_reload_meta = HotReloadableMetadata {
            reloadable: true,
            export_name: Some(export_name),
            attributes: metadata.clone(),
        };

        let node_metadata = NodeMetadata {
            values: metadata,
            type_info: Some(TypeMetadata::HotReloadable(hot_reload_meta)),
            position: self.position,
        };

        // Generate FFI wrapper
        let mut expanded = vec![];

        // Add FFI attributes
        expanded.push(AstNode::Attribute {
            name: "no_mangle".to_string(),
            args: vec![],
        });

        expanded.push(AstNode::Attribute {
            name: "extern".to_string(),
            args: vec![AstNode::String("C".to_string())],
        });

        // Add visibility modifier
        expanded.push(AstNode::Attribute {
            name: "pub".to_string(),
            args: vec![],
        });

        // Wrap the original function with FFI safety
        if let AstNode::FnDecl { name, params, return_type, body } = self.target.as_ref() {
            // Create FFI-safe function
            let ffi_fn = AstNode::FnDecl {
                name: export_name,
                params: params.clone(),
                return_type: return_type.clone(),
                body: vec![
                    // Add panic handler
                    AstNode::Let {
                        name: "_panic_handler".to_string(),
                        ty: Type::Unit,
                        value: Box::new(AstNode::Call {
                            name: "std::panic::catch_unwind".to_string(),
                            args: vec![
                                AstNode::Closure {
                                    params: vec![],
                                    body: body.clone(),
                                },
                            ],
                        }),
                    },
                    // Convert result to FFI-safe value
                    AstNode::Match {
                        expr: Box::new(AstNode::Ident("_panic_handler".to_string())),
                        arms: vec![
                            // Success case
                            (
                                AstNode::Pattern("Ok".to_string(), vec![AstNode::Ident("result".to_string())]),
                                AstNode::Ident("result".to_string()),
                            ),
                            // Error case
                            (
                                AstNode::Pattern("Err".to_string(), vec![AstNode::Ident("_".to_string())]),
                                match return_type {
                                    Some(_) => AstNode::Call {
                                        name: "std::process::abort".to_string(),
                                        args: vec![],
                                    },
                                    None => AstNode::Unit,
                                },
                            ),
                        ],
                    },
                ],
            };

            // Add the FFI wrapper
            expanded.push(AstNode::WithMetadata {
                node: Box::new(ffi_fn),
                metadata: node_metadata,
            });
        }

        Ok(expanded)
    }

    /// Get argument value by name
    fn get_arg_value(&self, name: &str) -> Option<String> {
        for arg in &self.args {
            match arg {
                ProcMacroArg::KeyValue(key, value) => {
                    if key == name {
                        if let ProcMacroArg::String(s) = value.as_ref() {
                            return Some(s.clone());
                        }
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Get required argument or return error with helpful message
    fn require_arg(&self, name: &str, expected_type: &str) -> Result<String, KslError> {
        self.get_arg_value(name).ok_or_else(|| {
            let mut msg = format!("Missing required argument '{}' for #[{}] macro\n", name, self.name);
            msg.push_str("Expected arguments:\n");
            match self.name.as_str() {
                "contract" => {
                    msg.push_str("  owner: string - Contract owner address\n");
                    msg.push_str("  gas: number - Gas limit for execution\n");
                }
                "validator" => {
                    msg.push_str("  stake: number - Validator stake amount\n");
                }
                "hot_reloadable" => {
                    msg.push_str("  name: string (optional) - Export name for FFI\n");
                }
                _ => {}
            }
            KslError::type_error(msg, self.position)
        })
    }

    /// Parses contract configuration from macro arguments
    fn parse_contract_config(&self) -> Result<ContractConfig, KslError> {
        let mut owner = None;
        let mut gas_limit = None;
        let mut metadata = HashMap::new();

        for arg in &self.args {
            match arg {
                ProcMacroArg::KeyValue(key, value) => {
                    match key.as_str() {
                        "owner" => {
                            if let ProcMacroArg::String(s) = value.as_ref() {
                                owner = Some(s.clone());
                            } else {
                                return Err(KslError::type_error(
                                    "Contract owner must be a string".to_string(),
                                    self.position,
                                ));
                            }
                        }
                        "gas" => {
                            if let ProcMacroArg::Number(n) = value.as_ref() {
                                gas_limit = Some(*n);
                            } else {
                                return Err(KslError::type_error(
                                    "Contract gas limit must be a number".to_string(),
                                    self.position,
                                ));
                            }
                        }
                        _ => {
                            // Add to metadata
                            if let ProcMacroArg::String(s) = value.as_ref() {
                                metadata.insert(key.clone(), s.clone());
                            }
                        }
                    }
                }
                _ => {
                    return Err(KslError::type_error(
                        "Contract macro arguments must be key-value pairs".to_string(),
                        self.position,
                    ));
                }
            }
        }

        // Validate required fields
        let owner = owner.ok_or_else(|| KslError::type_error(
            "Missing 'owner' argument for #[contract] macro".to_string(),
            self.position,
        ))?;

        let gas_limit = gas_limit.ok_or_else(|| KslError::type_error(
            "Missing 'gas' argument for #[contract] macro".to_string(),
            self.position,
        ))?;

        let mut config = ContractConfig::new(owner, gas_limit);
        for (key, value) in metadata {
            config.add_metadata(&key, &value);
        }

        Ok(config)
    }

    /// Parses ZK configuration from macro arguments
    fn parse_zk_config(&self) -> Result<ZkConfig, KslError> {
        let mut circuit_type = String::from("groth16"); // default
        let mut public_inputs = Vec::new();
        let mut private_inputs = Vec::new();

        for arg in &self.args {
            match arg {
                ProcMacroArg::KeyValue(key, value) => {
                    match key.as_str() {
                        "circuit" => {
                            if let ProcMacroArg::String(s) = value.as_ref() {
                                circuit_type = s.clone();
                            }
                        }
                        "public" => {
                            if let ProcMacroArg::Array(inputs) = value.as_ref() {
                                for input in inputs {
                                    if let ProcMacroArg::String(s) = input {
                                        public_inputs.push(s.clone());
                                    }
                                }
                            }
                        }
                        "private" => {
                            if let ProcMacroArg::Array(inputs) = value.as_ref() {
                                for input in inputs {
                                    if let ProcMacroArg::String(s) = input {
                                        private_inputs.push(s.clone());
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        Ok(ZkConfig {
            circuit_type,
            public_inputs,
            private_inputs,
        })
    }

    /// Parses event configuration from macro arguments
    fn parse_event_config(&self) -> Result<EventConfig, KslError> {
        let mut name = String::new();
        let mut params = Vec::new();
        let mut indexed = false;

        for arg in &self.args {
            match arg {
                ProcMacroArg::KeyValue(key, value) => {
                    match key.as_str() {
                        "name" => {
                            if let ProcMacroArg::String(s) = value.as_ref() {
                                name = s.clone();
                            }
                        }
                        "params" => {
                            if let ProcMacroArg::Array(param_list) = value.as_ref() {
                                for param in param_list {
                                    if let ProcMacroArg::Tuple(param_tuple) = param {
                                        if param_tuple.len() == 2 {
                                            if let (ProcMacroArg::String(name), ProcMacroArg::Type(ty)) = 
                                                (&param_tuple[0], &param_tuple[1]) {
                                                params.push((name.clone(), ty.clone()));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        "indexed" => {
                            if let ProcMacroArg::Bool(b) = value.as_ref() {
                                indexed = *b;
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        if name.is_empty() {
            return Err(KslError::type_error(
                "Event name is required".to_string(),
                self.position,
            ));
        }

        Ok(EventConfig {
            name,
            params,
            indexed,
        })
    }

    /// Parses test configuration from macro arguments
    fn parse_test_config(&self) -> Result<TestConfig, KslError> {
        let mut name = String::new();
        let mut ignore = false;
        let mut should_panic = None;
        let mut timeout_ms = None;

        for arg in &self.args {
            match arg {
                ProcMacroArg::KeyValue(key, value) => {
                    match key.as_str() {
                        "name" => {
                            if let ProcMacroArg::String(s) = value.as_ref() {
                                name = s.clone();
                            }
                        }
                        "ignore" => {
                            if let ProcMacroArg::Bool(b) = value.as_ref() {
                                ignore = *b;
                            }
                        }
                        "should_panic" => {
                            if let ProcMacroArg::String(s) = value.as_ref() {
                                should_panic = Some(s.clone());
                            }
                        }
                        "timeout" => {
                            if let ProcMacroArg::Number(n) = value.as_ref() {
                                timeout_ms = Some(*n);
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        // Use function name if no explicit test name provided
        if name.is_empty() {
            if let AstNode::FnDecl { name: fn_name, .. } = self.target.as_ref() {
                name = fn_name.clone();
            }
        }

        Ok(TestConfig {
            name,
            ignore,
            should_panic,
            timeout_ms,
        })
    }
}

/// Configuration for macro expansion logging
#[derive(Debug, Clone)]
pub struct ExpansionLogConfig {
    /// Whether to enable expansion logging
    enabled: bool,
    /// Log level for expansion details
    log_level: ExpansionLogLevel,
    /// Whether to include source positions in logs
    include_positions: bool,
    /// Whether to log parameter substitutions
    log_substitutions: bool,
}

impl Default for ExpansionLogConfig {
    fn default() -> Self {
        ExpansionLogConfig {
            enabled: false,
            log_level: ExpansionLogLevel::Basic,
            include_positions: false,
            log_substitutions: false,
        }
    }
}

/// Log levels for macro expansion
#[derive(Debug, Clone, PartialEq)]
pub enum ExpansionLogLevel {
    /// Basic information about macro expansion
    Basic,
    /// Detailed information including parameter substitutions
    Detailed,
    /// Full debug information including AST transformations
    Debug,
}

/// Kinds of macros supported by the system
#[derive(Debug, Clone)]
pub enum MacroKind {
    /// Declarative macros (macro_rules! style)
    Declarative(MacroDef),
    /// Procedural macros (attribute style)
    Procedural(ProcMacro),
}

impl MacroKind {
    /// Get the name of the macro
    pub fn name(&self) -> &str {
        match self {
            MacroKind::Declarative(def) => &def.name,
            MacroKind::Procedural(proc) => &proc.name,
        }
    }

    /// Check if the macro is async
    pub fn is_async(&self) -> bool {
        match self {
            MacroKind::Declarative(def) => def.is_async,
            MacroKind::Procedural(_) => false, // Procedural macros are not async
        }
    }

    /// Check if the macro handles networking
    pub fn is_networking(&self) -> bool {
        match self {
            MacroKind::Declarative(def) => def.is_networking,
            MacroKind::Procedural(_) => false, // Procedural macros don't handle networking directly
        }
    }

    /// Expand the macro
    pub fn expand(&self, args: &[AstNode], position: SourcePosition) -> Result<Vec<AstNode>, KslError> {
        match self {
            MacroKind::Declarative(def) => {
                // Create a macro call for declarative expansion
                let macro_call = MacroCall::new(&def.name, args.to_vec(), def.is_async, def.is_networking);
                // Use existing expansion logic
                Ok(def.body.clone()) // This is simplified - actual expansion would be more complex
            }
            MacroKind::Procedural(proc) => {
                // Use existing procedural expansion
                proc.expand()
            }
        }
    }

    /// Get macro documentation if present
    pub fn documentation(&self) -> Option<&MacroDoc> {
        match self {
            MacroKind::Declarative(def) => def.doc.as_ref(),
            MacroKind::Procedural(proc) => proc.doc.as_ref(),
        }
    }
}

/// Configuration flags for conditional compilation
#[derive(Debug, Clone, PartialEq)]
pub enum CfgFlag {
    /// Test configuration
    Test,
    /// Debug build
    Debug,
    /// Target platform (e.g., "windows", "linux")
    Target(String),
    /// Feature flag
    Feature(String),
    /// Custom flag
    Custom(String),
    /// Combination of flags (all must be true)
    All(Vec<CfgFlag>),
    /// Any of the flags (one must be true)
    Any(Vec<CfgFlag>),
    /// Negation of a flag
    Not(Box<CfgFlag>),
}

impl CfgFlag {
    /// Parse a configuration flag from a string
    pub fn from_str(s: &str) -> Result<Self, KslError> {
        let s = s.trim();
        if s == "test" {
            Ok(CfgFlag::Test)
        } else if s == "debug" {
            Ok(CfgFlag::Debug)
        } else if s.starts_with("target = ") {
            Ok(CfgFlag::Target(s[9..].trim_matches('"').to_string()))
        } else if s.starts_with("feature = ") {
            Ok(CfgFlag::Feature(s[10..].trim_matches('"').to_string()))
        } else if s.starts_with("all(") && s.ends_with(")") {
            let inner = &s[4..s.len()-1];
            let flags = inner.split(',')
                .map(|f| CfgFlag::from_str(f.trim()))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(CfgFlag::All(flags))
        } else if s.starts_with("any(") && s.ends_with(")") {
            let inner = &s[4..s.len()-1];
            let flags = inner.split(',')
                .map(|f| CfgFlag::from_str(f.trim()))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(CfgFlag::Any(flags))
        } else if s.starts_with("not(") && s.ends_with(")") {
            let inner = &s[4..s.len()-1];
            Ok(CfgFlag::Not(Box::new(CfgFlag::from_str(inner)?)))
        } else {
            Ok(CfgFlag::Custom(s.to_string()))
        }
    }

    /// Evaluate if the flag is active given the current configuration
    pub fn is_active(&self, config: &CompileConfig) -> bool {
        match self {
            CfgFlag::Test => config.is_test,
            CfgFlag::Debug => config.is_debug,
            CfgFlag::Target(t) => config.target == *t,
            CfgFlag::Feature(f) => config.features.contains(f),
            CfgFlag::Custom(c) => config.custom_flags.contains(c),
            CfgFlag::All(flags) => flags.iter().all(|f| f.is_active(config)),
            CfgFlag::Any(flags) => flags.iter().any(|f| f.is_active(config)),
            CfgFlag::Not(flag) => !flag.is_active(config),
        }
    }
}

/// Compilation configuration
#[derive(Debug, Clone)]
pub struct CompileConfig {
    /// Whether we're in test mode
    pub is_test: bool,
    /// Whether we're in debug mode
    pub is_debug: bool,
    /// Target platform
    pub target: String,
    /// Enabled features
    pub features: HashSet<String>,
    /// Custom configuration flags
    pub custom_flags: HashSet<String>,
}

impl Default for CompileConfig {
    fn default() -> Self {
        CompileConfig {
            is_test: false,
            is_debug: true,
            target: std::env::consts::OS.to_string(),
            features: HashSet::new(),
            custom_flags: HashSet::new(),
        }
    }
}

impl CompileConfig {
    /// Create a new compilation configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable test mode
    pub fn with_test(mut self) -> Self {
        self.is_test = true;
        self
    }

    /// Set debug mode
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.is_debug = debug;
        self
    }

    /// Set target platform
    pub fn with_target(mut self, target: &str) -> Self {
        self.target = target.to_string();
        self
    }

    /// Enable a feature
    pub fn with_feature(mut self, feature: &str) -> Self {
        self.features.insert(feature.to_string());
        self
    }

    /// Add a custom flag
    pub fn with_custom_flag(mut self, flag: &str) -> Self {
        self.custom_flags.insert(flag.to_string());
        self
    }
}

/// Update ProcMacro to handle cfg attributes
impl ProcMacro {
    /// Check if this is a cfg attribute
    pub fn is_cfg(&self) -> bool {
        self.name == "cfg"
    }

    /// Parse cfg flag from arguments
    pub fn parse_cfg_flag(&self) -> Result<CfgFlag, KslError> {
        if !self.is_cfg() {
            return Err(KslError::type_error(
                "Not a cfg attribute".to_string(),
                self.position,
            ));
        }

        if self.args.len() != 1 {
            return Err(KslError::type_error(
                "cfg attribute requires exactly one argument".to_string(),
                self.position,
            ));
        }

        match &self.args[0] {
            ProcMacroArg::String(s) => CfgFlag::from_str(s),
            _ => Err(KslError::type_error(
                "cfg argument must be a string".to_string(),
                self.position,
            )),
        }
    }
}

/// Cache key for macro expansions
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct ExpansionCacheKey {
    /// Macro name
    macro_name: String,
    /// Arguments hash
    args_hash: u64,
    /// Configuration hash (for cfg attributes)
    config_hash: u64,
}

/// Cached macro expansion result
#[derive(Debug, Clone)]
struct CachedExpansion {
    /// Expanded AST
    nodes: Vec<AstNode>,
    /// When the expansion was cached
    timestamp: std::time::SystemTime,
    /// Source position for error tracking
    position: SourcePosition,
}

/// External macro plugin interface
pub trait MacroPlugin: Send + Sync {
    /// Plugin name
    fn name(&self) -> &str;
    /// Expand a macro
    fn expand(&self, args: &[AstNode], pos: SourcePosition) -> Result<Vec<AstNode>, KslError>;
}

/// Update MacroExpander with caching and plugins
impl MacroExpander {
    /// Expansion cache
    expansion_cache: HashMap<ExpansionCacheKey, CachedExpansion>,
    /// External macro plugins
    plugins: HashMap<String, Box<dyn MacroPlugin>>,
    /// Unique identifier counter for hygiene
    unique_id: std::sync::atomic::AtomicU64,

    /// Creates a new macro expander
    pub fn new() -> Self {
        MacroExpander {
            macros: HashMap::new(),
            ast_transformer: AstTransformer::new(TransformConfig {
                input_file: PathBuf::new(),
                output_file: None,
                rule: "inline".to_string(),
                plugin_name: None,
                max_unroll_iterations: 5,
                preserve_networking: true,
            }),
            expansion_log_config: ExpansionLogConfig::default(),
            compile_config: CompileConfig::default(),
            expansion_cache: HashMap::new(),
            plugins: HashMap::new(),
            unique_id: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Register an external macro plugin
    pub fn register_plugin(&mut self, plugin: Box<dyn MacroPlugin>) -> Result<(), KslError> {
        let name = plugin.name().to_string();
        if self.plugins.contains_key(&name) {
            return Err(KslError::type_error(
                format!("Plugin '{}' is already registered", name),
                SourcePosition::new(1, 1), // TODO: Better position
            ));
        }
        self.plugins.insert(name, plugin);
        Ok(())
    }

    /// Generate a unique identifier for hygiene
    fn generate_unique_id(&self) -> u64 {
        self.unique_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// Make an identifier hygienic by adding a unique prefix
    fn make_hygienic(&self, name: &str) -> String {
        format!("__ksl_{}__{}", self.generate_unique_id(), name)
    }

    /// Compute cache key for a macro expansion
    fn compute_cache_key(&self, macro_call: &MacroCall) -> ExpansionCacheKey {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        
        // Hash macro name
        macro_call.name.hash(&mut hasher);
        
        // Hash arguments
        for arg in &macro_call.args {
            format!("{:?}", arg).hash(&mut hasher);
        }
        let args_hash = hasher.finish();
        
        // Hash configuration
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        format!("{:?}", self.compile_config).hash(&mut hasher);
        let config_hash = hasher.finish();

        ExpansionCacheKey {
            macro_name: macro_call.name.clone(),
            args_hash,
            config_hash,
        }
    }

    /// Check expansion cache
    fn check_cache(&self, key: &ExpansionCacheKey) -> Option<Vec<AstNode>> {
        self.expansion_cache.get(key).map(|cached| {
            // Check if cache is still valid (e.g., not too old)
            if cached.timestamp.elapsed().unwrap() < std::time::Duration::from_secs(300) {
                Some(cached.nodes.clone())
            } else {
                None
            }
        }).flatten()
    }

    /// Update cache with expansion result
    fn update_cache(&mut self, key: ExpansionCacheKey, nodes: Vec<AstNode>, pos: SourcePosition) {
        self.expansion_cache.insert(key, CachedExpansion {
            nodes,
            timestamp: std::time::SystemTime::now(),
            position: pos,
        });
    }

    /// Expand a macro call with caching and hygiene
    pub fn expand(&mut self, macro_call: &MacroCall) -> Result<Vec<AstNode>, KslError> {
        // Check cache first
        let cache_key = self.compute_cache_key(macro_call);
        if let Some(cached) = self.check_cache(&cache_key) {
            return Ok(cached);
        }

        // Get source position from macro call
        let pos = macro_call.position.clone();

        // Try plugin expansion first
        let expanded = if let Some(plugin) = self.plugins.get(&macro_call.name) {
            plugin.expand(&macro_call.args, pos.clone())?
        } else {
            // Find built-in macro
            let macro_kind = self.macros.get(&macro_call.name)
            .ok_or_else(|| KslError::type_error(
                format!("Macro '{}' not found", macro_call.name),
                    pos.clone(),
            ))?;

            // Expand based on kind
            let mut expanded = match macro_kind {
                MacroKind::Declarative(def) => {
        // Validate argument count
                    let required_args = def.params.iter().filter(|p| !p.is_optional).count();
        if macro_call.args.len() < required_args {
            return Err(KslError::type_error(
                format!(
                    "Macro '{}' expects at least {} arguments, got {}",
                    macro_call.name, required_args, macro_call.args.len()
                ),
                            pos.clone(),
                        ));
                    }

                    // Build parameter substitution map with hygienic names
                    let mut param_map = HashMap::new();
                    for (param, arg) in def.params.iter().zip(macro_call.args.iter()) {
                        let hygienic_name = self.make_hygienic(&param.name);
                        param_map.insert(hygienic_name, (param.param_type.clone(), arg.clone()));
                    }

                    // Substitute parameters
                    self.substitute_with_map(&def.body, &param_map, pos.clone())?
                }
                MacroKind::Procedural(proc) => {
                    proc.expand()?
                }
            };

            // Apply transformations
            if macro_kind.is_async() {
                self.ast_transformer.transform_async(&mut expanded)?;
            }
            if macro_kind.is_networking() {
                self.ast_transformer.optimize_networking(&mut expanded)?;
            }

            expanded
        };

        // Update cache
        self.update_cache(cache_key, expanded.clone(), pos);

        // Log expansion
        self.log_expansion(macro_call, &expanded, None);

        Ok(expanded)
    }

    /// Updated substitution with source positions
    fn substitute_with_map(
        &self,
        nodes: &[AstNode],
        param_map: &HashMap<String, (ParamType, AstNode)>,
        pos: SourcePosition,
    ) -> Result<Vec<AstNode>, KslError> {
        let mut result = vec![];

        for node in nodes {
            let new_node = match node {
                AstNode::Let { name, ty, value } => {
                    if let Some((param_type, arg)) = param_map.get(name) {
                        if !param_type.matches_node(arg) {
                            return Err(KslError::type_error(
                                format!("Type mismatch for parameter '{}': expected {:?}, got {:?}",
                                    name, param_type, arg),
                                pos.clone(),
                            ));
                        }
                        arg.clone()
                    } else {
                        // Make variable name hygienic
                        let hygienic_name = self.make_hygienic(name);
                        AstNode::Let {
                            name: hygienic_name,
                            ty: ty.clone(),
                            value: Box::new(self.substitute_with_map(&[value.as_ref().clone()], param_map, pos.clone())?[0].clone()),
                        }
                    }
                }
                AstNode::Call { name, args } => {
                    if let Some((param_type, arg)) = param_map.get(name) {
                        match param_type {
                            ParamType::Token(TokenType::Ident) => {
                                if let Some(ident) = arg.as_ident() {
                                    AstNode::Call {
                                        name: ident,
                                        args: self.substitute_with_map(args, param_map, pos.clone())?,
                                    }
                                } else {
                                    return Err(KslError::type_error(
                                        format!("Expected identifier for parameter '{}', got {:?}", name, arg),
                                        pos.clone(),
                                    ));
                                }
                            }
                            _ => return Err(KslError::type_error(
                                format!("Invalid parameter type for function name: {:?}", param_type),
                                pos.clone(),
                            )),
                        }
                    } else {
                        AstNode::Call {
                            name: name.clone(),
                            args: self.substitute_with_map(args, param_map, pos.clone())?,
                        }
                    }
                }
                AstNode::Ident(name) => {
                    if let Some((param_type, arg)) = param_map.get(name) {
                        if let Some(ident) = arg.as_ident() {
                            AstNode::Ident(ident)
                        } else {
                            return Err(KslError::type_error(
                                format!("Expected identifier for parameter '{}', got {:?}", name, arg),
                                pos.clone(),
                            ));
                        }
                    } else {
                        node.clone()
                    }
                }
                AstNode::String(s) => {
                    if let Some((param_type, arg)) = param_map.get(s) {
                        if let Some(string) = arg.as_string() {
                            AstNode::String(string)
                    } else {
                            return Err(KslError::type_error(
                                format!("Expected string for parameter '{}', got {:?}", s, arg),
                                pos.clone(),
                            ));
                        }
                    } else {
                        node.clone()
                    }
                }
                _ => node.clone(),
            };
            result.push(new_node);
        }

        Ok(result)
    }
}

/// Enhanced macro expansion system with unified registration
pub struct MacroExpander {
    /// Store all macros in a single collection
    macros: HashMap<String, MacroKind>,
    /// AST transformer for post-expansion transformations
    ast_transformer: AstTransformer,
    /// Expansion log configuration
    expansion_log_config: ExpansionLogConfig,
}

impl MacroExpander {
    /// Register a macro of any kind
    pub fn register_macro(&mut self, kind: MacroKind) -> Result<(), KslError> {
        let name = kind.name().to_string();
        
        // Check for naming conflicts
        if self.macros.contains_key(&name) {
            return Err(KslError::type_error(
                format!("Macro '{}' is already registered", name),
                SourcePosition::new(1, 1),
            ));
        }

        // Log registration if enabled
        if self.expansion_log_config.enabled {
            println!("Registering {} macro: {}", 
                match kind {
                    MacroKind::Declarative(_) => "declarative",
                    MacroKind::Procedural(_) => "procedural",
                },
                name
            );
        }

        self.macros.insert(name, kind);
        Ok(())
    }

    /// Convenience method to register a declarative macro
    pub fn register_declarative(&mut self, macro_def: MacroDef) -> Result<(), KslError> {
        self.register_macro(MacroKind::Declarative(macro_def))
    }

    /// Convenience method to register a procedural macro
    pub fn register_procedural(&mut self, proc_macro: ProcMacro) -> Result<(), KslError> {
        self.register_macro(MacroKind::Procedural(proc_macro))
    }

    /// Get a registered macro by name
    pub fn get_macro(&self, name: &str) -> Option<&MacroKind> {
        self.macros.get(name)
    }

    /// Check if a macro name is registered
    pub fn is_macro_registered(&self, name: &str) -> bool {
        self.macros.contains_key(name)
    }

    /// Expand a macro call into an AST
    pub fn expand(&self, macro_call: &MacroCall) -> Result<Vec<AstNode>, KslError> {
        let pos = SourcePosition::new(1, 1);

        // Find the macro
        let macro_kind = self.macros.get(&macro_call.name)
            .ok_or_else(|| KslError::type_error(
                format!("Macro '{}' not found", macro_call.name),
                pos,
            ))?;

        // Expand based on kind
        let mut expanded_body = match macro_kind {
            MacroKind::Declarative(def) => {
        // Validate argument count
                let required_args = def.params.iter().filter(|p| !p.is_optional).count();
        if macro_call.args.len() < required_args {
            return Err(KslError::type_error(
                format!(
                    "Macro '{}' expects at least {} arguments, got {}",
                    macro_call.name, required_args, macro_call.args.len()
                ),
                pos,
            ));
        }

                // Build parameter substitution map
                let mut param_map = HashMap::new();
                for (param, arg) in def.params.iter().zip(macro_call.args.iter()) {
                    param_map.insert(param.name.clone(), (param.param_type.clone(), arg.clone()));
                }

                // Substitute parameters
                self.substitute_with_map(&def.body, &param_map)?
            }
            MacroKind::Procedural(proc) => {
                proc.expand()?
            }
        };

        // Apply transformations
        if macro_kind.is_async() {
            self.ast_transformer.transform_async(&mut expanded_body)?;
        }
        if macro_kind.is_networking() {
            self.ast_transformer.optimize_networking(&mut expanded_body)?;
        }

        // Log expansion
        self.log_expansion(macro_call, &expanded_body, None);

        Ok(expanded_body)
    }

    /// Log macro expansion details based on configuration
    fn log_expansion(&self, macro_call: &MacroCall, expanded_body: &[AstNode], param_map: Option<&HashMap<String, (ParamType, AstNode)>>) {
        if !self.expansion_log_config.enabled {
            return;
        }

        match self.expansion_log_config.log_level {
            ExpansionLogLevel::Basic => {
                println!("Expanding macro: {} → {:?}", macro_call.name, expanded_body);
            }
            ExpansionLogLevel::Detailed => {
                println!("=== Macro Expansion Details ===");
                println!("Macro name: {}", macro_call.name);
                println!("Arguments: {:?}", macro_call.args);
                if self.expansion_log_config.include_positions {
                    println!("Source position: {:?}", SourcePosition::new(1, 1));
                }
                println!("Expanded body: {:#?}", expanded_body);
            }
            ExpansionLogLevel::Debug => {
                println!("======= Macro Expansion Debug =======");
                println!("Macro name: {}", macro_call.name);
                println!("Is async: {}", macro_call.is_async);
                println!("Is networking: {}", macro_call.is_networking);
                println!("\nArguments:");
                for (i, arg) in macro_call.args.iter().enumerate() {
                    println!("  {}: {:?}", i, arg);
                }
                if let Some(param_map) = param_map {
                    if self.expansion_log_config.log_substitutions {
                        println!("\nParameter substitutions:");
                        for (name, (ty, value)) in param_map {
                            println!("  {} ({:?}) → {:?}", name, ty, value);
                        }
                    }
                }
                println!("\nExpanded body:");
                for (i, node) in expanded_body.iter().enumerate() {
                    println!("  {}: {:#?}", i, node);
                }
                println!("===================================");
            }
        }
    }

    /// Expand all macros in an AST node
    pub fn expand_node(&self, node: &AstNode) -> Result<Vec<AstNode>, KslError> {
        match node {
            AstNode::ProcMacro(proc_macro) => {
                // Expand procedural macro
                proc_macro.expand()
            }
            AstNode::MacroCall(macro_call) => {
                // Expand regular macro
                self.expand(macro_call)
            }
            AstNode::Let { name, ty, value } => {
                // Recursively expand the value
                let expanded_value = self.expand_node(value)?;
                Ok(vec![AstNode::Let {
                    name: name.clone(),
                    ty: ty.clone(),
                    value: Box::new(expanded_value[0].clone()),
                }])
            }
            AstNode::Call { name, args } => {
                // Recursively expand arguments
                let expanded_args = args.iter()
                    .map(|arg| self.expand_node(arg))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(vec![AstNode::Call {
                    name: name.clone(),
                    args: expanded_args.into_iter().flatten().collect(),
                }])
            }
            _ => Ok(vec![node.clone()]),
        }
    }

    /// Expand all macros in an AST
    pub fn expand_ast(&self, ast: &[AstNode]) -> Result<Vec<AstNode>, KslError> {
        let mut expanded = vec![];
        for node in ast {
            expanded.extend(self.expand_node(node)?);
        }
        Ok(expanded)
    }

    /// Get documentation for a registered macro
    pub fn get_macro_docs(&self, name: &str) -> Option<&MacroDoc> {
        self.macros.get(name).and_then(|m| m.documentation())
    }

    /// Generate documentation for all registered macros
    pub fn generate_all_docs(&self) -> String {
        let mut docs = String::from("# KSL Macro Reference\n\n");

        // Collect declarative macros
        docs.push_str("## Declarative Macros\n\n");
        for (name, kind) in self.macros.iter().filter(|(_, k)| matches!(k, MacroKind::Declarative(_))) {
            if let Some(doc) = kind.documentation() {
                docs.push_str(&format!("### {}\n\n", name));
                docs.push_str(&doc.to_markdown());
                docs.push_str("\n---\n\n");
            }
        }

        // Collect procedural macros
        docs.push_str("## Procedural Macros\n\n");
        for (name, kind) in self.macros.iter().filter(|(_, k)| matches!(k, MacroKind::Procedural(_))) {
            if let Some(doc) = kind.documentation() {
                docs.push_str(&format!("### {}\n\n", name));
                docs.push_str(&doc.to_markdown());
                docs.push_str("\n---\n\n");
            }
        }

        docs
    }
}

/// Integrate with the type checker (used by ksl_checker.rs).
pub struct MacroTypeChecker;

impl MacroTypeChecker {
    /// Checks a macro definition for type safety.
    pub fn check_macro_def(&self, macro_def: &MacroDef) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);

        // Validate parameter types
        for param in &macro_def.params {
            match param.param_type {
                ParamType::Token(TokenType::String | TokenType::NetworkEndpoint) => {
                    // Strings and network endpoints are fixed-size in KSL
                }
                ParamType::Token(TokenType::Ident) => {
                    // Identifiers are valid
                }
                ParamType::Expr | ParamType::AsyncTask => {
                    // Expressions and async tasks will be checked after expansion
                }
                ParamType::Token(TokenType::Type) => {
                    // Types will be checked after expansion
                }
                ParamType::Token(TokenType::NetworkHeaders) => {
                    // Network headers must be a map of strings
                }
            }
        }

        // Recursively check the macro body
        for node in &macro_def.body {
            self.check_node(node)?;
        }

        Ok(())
    }

    /// Checks an AST node for type safety.
    fn check_node(&self, node: &AstNode) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);

        match node {
            AstNode::MacroDef(_) => Err(KslError::type_error(
                "Nested macro definitions not supported".to_string(),
                pos,
            )),
            AstNode::MacroCall(_) => Ok(()), // Will be expanded before type checking
            AstNode::AsyncFnDecl { name: _, params: _, body } => {
                for node in body {
                    self.check_node(node)?;
                }
                Ok(())
            }
            AstNode::Await { expr } => {
                self.check_node(expr.as_ref())
            }
            AstNode::Network { op_type: _, endpoint: _, headers: _, data: _ } => {
                // Network operations are type-safe by construction
                Ok(())
            }
            AstNode::Let { name: _, ty: _, value } => {
                self.check_node(value.as_ref())
            }
            AstNode::Call { name: _, args } => {
                for arg in args {
                    self.check_node(arg)?;
                }
                Ok(())
            }
            AstNode::Literal(_) => Ok(()),
        }
    }
}

// Placeholder types (aligned with ksl_types.rs).
#[derive(Debug, Clone)]
pub enum Type {
    /// String type
    String,
    /// Network endpoint type
    NetworkEndpoint,
    /// Network headers type
    NetworkHeaders,
    /// Async task type
    AsyncTask,
    /// 64-bit unsigned integer type
    U64,
    /// Boolean type
    Bool,
    /// Array type
    Array(Box<Type>),
    /// Tuple type
    Tuple(Vec<Type>),
    /// Type type (for representing types as values)
    Type,
    /// Map type
    Map(Box<Type>, Box<Type>),
}

// Add helper methods for metadata access
impl AstNode {
    /// Get metadata if present
    pub fn metadata(&self) -> Option<&NodeMetadata> {
        match self {
            AstNode::WithMetadata { metadata, .. } => Some(metadata),
            _ => None,
        }
    }

    /// Get contract metadata if present
    pub fn contract_metadata(&self) -> Option<&ContractMetadata> {
        self.metadata().and_then(|m| {
            if let Some(TypeMetadata::Contract(cm)) = &m.type_info {
                Some(cm)
            } else {
                None
            }
        })
    }

    /// Get metadata value by key
    pub fn get_metadata_value(&self, key: &str) -> Option<&String> {
        self.metadata().and_then(|m| m.values.get(key))
    }
}

// Add helper methods for runtime metadata access
impl MacroExpander {
    /// Get metadata for a node
    pub fn get_node_metadata(&self, node: &AstNode) -> Option<&NodeMetadata> {
        node.metadata()
    }

    /// Get contract metadata for a node
    pub fn get_contract_metadata(&self, node: &AstNode) -> Option<&ContractMetadata> {
        node.contract_metadata()
    }

    /// Get all metadata values for a node
    pub fn get_metadata_values(&self, node: &AstNode) -> Option<&HashMap<String, String>> {
        node.metadata().map(|m| &m.values)
    }
}

/// Helper trait for converting between AST nodes
pub trait NodeConversion {
    /// Convert to identifier
    fn as_ident(&self) -> Option<String>;
    /// Convert to boolean
    fn as_bool(&self) -> Option<bool>;
    /// Convert to string
    fn as_string(&self) -> Option<String>;
    /// Convert to integer
    fn as_int(&self) -> Option<(String, IntType)>;
    /// Convert to float
    fn as_float(&self) -> Option<(String, FloatType)>;
    /// Convert to char
    fn as_char(&self) -> Option<char>;
}

impl NodeConversion for AstNode {
    fn as_ident(&self) -> Option<String> {
        match self {
            AstNode::Ident(s) => Some(s.clone()),
            AstNode::String(s) => Some(s.clone()),
            _ => None,
        }
    }

    fn as_bool(&self) -> Option<bool> {
        match self {
            AstNode::Bool(b) => Some(*b),
            AstNode::String(s) => s.parse().ok(),
            _ => None,
        }
    }

    fn as_string(&self) -> Option<String> {
        match self {
            AstNode::String(s) => Some(s.clone()),
            AstNode::Ident(s) => Some(s.clone()),
            AstNode::Bool(b) => Some(b.to_string()),
            AstNode::Int(n, _) => Some(n.clone()),
            AstNode::Float(n, _) => Some(n.clone()),
            AstNode::Char(c) => Some(c.to_string()),
            _ => None,
        }
    }

    fn as_int(&self) -> Option<(String, IntType)> {
        match self {
            AstNode::Int(n, t) => Some((n.clone(), t.clone())),
            AstNode::String(s) => {
                // Try to parse as integer and default to i32
                s.parse::<i32>().ok().map(|_| (s.clone(), IntType::I32))
            }
            _ => None,
        }
    }

    fn as_float(&self) -> Option<(String, FloatType)> {
        match self {
            AstNode::Float(n, t) => Some((n.clone(), t.clone())),
            AstNode::String(s) => {
                // Try to parse as float and default to f64
                s.parse::<f64>().ok().map(|_| (s.clone(), FloatType::F64))
            }
            _ => None,
        }
    }

    fn as_char(&self) -> Option<char> {
        match self {
            AstNode::Char(c) => Some(*c),
            AstNode::String(s) if s.len() == 1 => s.chars().next(),
            _ => None,
        }
    }
}

// Add tests for new node types and substitution
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_conversion() {
        // Test identifier conversion
        let ident = AstNode::Ident("test".to_string());
        assert_eq!(ident.as_ident(), Some("test".to_string()));
        assert_eq!(ident.as_string(), Some("test".to_string()));

        // Test boolean conversion
        let bool_node = AstNode::Bool(true);
        assert_eq!(bool_node.as_bool(), Some(true));
        assert_eq!(bool_node.as_string(), Some("true".to_string()));

        // Test number conversion
        let int_node = AstNode::Int("42".to_string(), IntType::I32);
        assert_eq!(int_node.as_int(), Some(("42".to_string(), IntType::I32)));
        assert_eq!(int_node.as_string(), Some("42".to_string()));
    }

    #[test]
    fn test_type_matching() {
        let ident_type = ParamType::Token(TokenType::Ident);
        let bool_type = ParamType::Token(TokenType::Bool);

        assert!(ident_type.matches_node(&AstNode::Ident("test".to_string())));
        assert!(bool_type.matches_node(&AstNode::Bool(true)));
        assert!(!ident_type.matches_node(&AstNode::Bool(false)));
    }
}

/// Add validation utilities
pub trait HotReloadableNode {
    /// Check if node is hot reloadable
    fn is_hot_reloadable(&self) -> bool;
    /// Get hot reloadable metadata if present
    fn hot_reload_metadata(&self) -> Option<&HotReloadableMetadata>;
}

impl HotReloadableNode for AstNode {
    fn is_hot_reloadable(&self) -> bool {
        match self {
            AstNode::WithMetadata { metadata, .. } => {
                metadata.values.get("hot_reloadable")
                    .map(|v| v == "true")
                    .unwrap_or(false)
            }
            _ => false,
        }
    }

    fn hot_reload_metadata(&self) -> Option<&HotReloadableMetadata> {
        match self {
            AstNode::WithMetadata { metadata, .. } => {
                if let Some(TypeMetadata::HotReloadable(meta)) = &metadata.type_info {
                    Some(meta)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// Configuration for hot reloadable functions
#[derive(Debug, Clone)]
pub struct HotReloadConfig {
    /// Module name for the .so/.dll
    pub module_name: String,
    /// Export prefix for FFI functions
    pub export_prefix: Option<String>,
    /// Whether to include debug symbols
    pub include_debug_info: bool,
    /// Additional linker flags
    pub linker_flags: Vec<String>,
}

impl Default for HotReloadConfig {
    fn default() -> Self {
        HotReloadConfig {
            module_name: "ksl_hot_reload".to_string(),
            export_prefix: None,
            include_debug_info: true,
            linker_flags: vec![],
        }
    }
}

/// Hot reloadable function information
#[derive(Debug, Clone)]
pub struct HotReloadableFunction {
    /// Original function name
    pub original_name: String,
    /// Exported FFI name
    pub export_name: String,
    /// Function signature
    pub signature: FunctionSignature,
    /// Source position
    pub position: SourcePosition,
    /// Additional attributes
    pub attributes: HashMap<String, String>,
}

/// Function signature information
#[derive(Debug, Clone)]
pub struct FunctionSignature {
    /// Parameter types
    pub params: Vec<Type>,
    /// Return type
    pub return_type: Option<Type>,
    /// Whether the function is async
    pub is_async: bool,
}

/// Helper trait for hot reloadable function management
pub trait HotReloadableFunctions {
    /// Get all hot reloadable functions
    fn get_hot_reloadable_functions(&self) -> Vec<HotReloadableFunction>;
    /// Check if a function is hot reloadable
    fn is_hot_reloadable_function(&self, name: &str) -> bool;
    /// Get hot reloadable function info
    fn get_hot_reloadable_function(&self, name: &str) -> Option<&HotReloadableFunction>;
}

impl HotReloadableFunctions for Vec<AstNode> {
    fn get_hot_reloadable_functions(&self) -> Vec<HotReloadableFunction> {
        self.iter()
            .filter_map(|node| {
                if let AstNode::WithMetadata { node, metadata } = node {
                    if let Some(TypeMetadata::HotReloadable(meta)) = &metadata.type_info {
                        if let AstNode::FnDecl { name, params, return_type, .. } = node.as_ref() {
                            Some(HotReloadableFunction {
                                original_name: name.clone(),
                                export_name: meta.export_name.clone().unwrap_or_else(|| name.clone()),
                                signature: FunctionSignature {
                                    params: params.iter().map(|(_, ty)| ty.clone()).collect(),
                                    return_type: return_type.clone(),
                                    is_async: false,
                                },
                                position: metadata.position,
                                attributes: meta.attributes.clone(),
                            })
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    fn is_hot_reloadable_function(&self, name: &str) -> bool {
        self.iter().any(|node| {
            if let AstNode::WithMetadata { node, metadata } = node {
                if let Some(TypeMetadata::HotReloadable(_)) = &metadata.type_info {
                    if let AstNode::FnDecl { name: fn_name, .. } = node.as_ref() {
                        return fn_name == name;
                    }
                }
            }
            false
        })
    }

    fn get_hot_reloadable_function(&self, name: &str) -> Option<&HotReloadableFunction> {
        self.iter()
            .filter_map(|node| {
                if let AstNode::WithMetadata { node, metadata } = node {
                    if let Some(TypeMetadata::HotReloadable(meta)) = &metadata.type_info {
                        if let AstNode::FnDecl { name: fn_name, .. } = node.as_ref() {
                            if fn_name == name {
                                Some(meta)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .next()
    }
}

/// Marks a function as hot reloadable, generating necessary FFI and metadata.
/// 
/// This macro:
/// 1. Adds #[no_mangle] attribute
/// 2. Generates FFI-safe exports
/// 3. Adds hot reload metadata
/// 
/// Example:
/// ```rust
/// #[hot_reloadable]
/// fn my_function(x: u32) -> u32 {
///     x * 2
/// }
/// ```
#[proc_macro_attribute]
pub fn hot_reloadable(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse the function
    let input_fn = parse_macro_input!(item as ItemFn);
    let fn_name = input_fn.sig.ident.clone();
    
    // Generate export name
    let export_name = if attr.is_empty() {
        format!("ksl_hot_reload_{}", fn_name)
    } else {
        parse_macro_input!(attr as syn::LitStr).value()
    };

    // Extract function signature info
    let params: Vec<_> = input_fn.sig.inputs.iter().collect();
    let return_type = match &input_fn.sig.output {
        ReturnType::Default => quote! { () },
        ReturnType::Type(_, ty) => quote! { #ty },
    };

    // Generate FFI-safe wrapper
    let ffi_wrapper = generate_ffi_wrapper(&fn_name, &export_name, &params, &return_type);

    // Add hot reload metadata
    let metadata = generate_hot_reload_metadata(&fn_name, &export_name);

    // Combine original function with generated code
    let expanded = quote! {
        #[no_mangle]
        #[doc(hidden)]
        #input_fn

        #ffi_wrapper

        #metadata
    };

    TokenStream::from(expanded)
}

/// Generates FFI-safe wrapper for the hot reloadable function
fn generate_ffi_wrapper(
    fn_name: &Ident,
    export_name: &str,
    params: &[&FnArg],
    return_type: &proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    let export_ident = Ident::new(export_name, Span::call_site());
    
    // Convert parameters to FFI-safe types
    let ffi_params: Vec<_> = params.iter().map(|arg| {
        match arg {
            FnArg::Typed(pat_type) => {
                let ty = &pat_type.ty;
                quote! { #ty }
            }
            _ => quote! { () },
        }
    }).collect();

    // Generate FFI wrapper function
    quote! {
        #[no_mangle]
        pub extern "C" fn #export_ident(
            #(#ffi_params),*
        ) -> #return_type {
            #fn_name(#(#ffi_params),*)
        }
    }
}

/// Generates hot reload metadata for the function
fn generate_hot_reload_metadata(
    fn_name: &Ident,
    export_name: &str,
) -> proc_macro2::TokenStream {
    quote! {
        #[doc(hidden)]
        #[allow(non_upper_case_globals)]
        static HOT_RELOAD_METADATA_#fn_name: HotReloadableMetadata = HotReloadableMetadata {
            reloadable: true,
            export_name: Some(#export_name.to_string()),
            attributes: {
                let mut map = std::collections::HashMap::new();
                map.insert("hot_reloadable".to_string(), "true".to_string());
                map.insert("export_name".to_string(), #export_name.to_string());
                map
            },
        };
    }
}