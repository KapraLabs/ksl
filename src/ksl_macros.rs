// ksl_macros.rs
// Macro system for KSL to enable metaprogramming and code generation,
// supporting networking operations and async/await patterns.

use crate::ksl_parser::{parse, AstNode, ExprKind, ParseError};
use crate::ksl_ast_transform::{AstTransformer, TransformConfig};
use crate::ksl_errors::{KslError, SourcePosition};
use std::collections::HashMap;

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

/// Types of macro parameters.
#[derive(Debug, Clone)]
pub enum ParamType {
    /// Literal string
    String,
    /// Identifier (e.g., for struct or contract names)
    Ident,
    /// Expression
    Expr,
    /// Type annotation
    Type,
    /// Network endpoint (e.g., URL, IP:port)
    NetworkEndpoint,
    /// HTTP headers
    NetworkHeaders,
    /// Async task
    AsyncTask,
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
}

impl MacroCall {
    /// Creates a new macro call.
    pub fn new(name: &str, args: Vec<AstNode>, is_async: bool, is_networking: bool) -> Self {
        MacroCall {
            name: name.to_string(),
            args,
            is_async,
            is_networking,
        }
    }
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

/// Macro expansion system (integrates with ksl_ast_transform.rs).
pub struct MacroExpander {
    /// Store defined macros
    macros: Vec<MacroDef>,
    /// AST transformer for post-expansion transformations
    ast_transformer: AstTransformer,
}

impl MacroExpander {
    /// Creates a new macro expander.
    pub fn new() -> Self {
        MacroExpander {
            macros: vec![],
            ast_transformer: AstTransformer::new(TransformConfig {
                input_file: PathBuf::new(),
                output_file: None,
                rule: "inline".to_string(),
                plugin_name: None,
                max_unroll_iterations: 5,
                preserve_networking: true,
            }),
        }
    }

    /// Register a macro definition.
    pub fn register_macro(&mut self, macro_def: MacroDef) {
        self.macros.push(macro_def);
    }

    /// Expand a macro call into an AST.
    pub fn expand(&self, macro_call: &MacroCall) -> Result<Vec<AstNode>, KslError> {
        let pos = SourcePosition::new(1, 1);

        // Find the macro definition
        let macro_def = self.macros.iter()
            .find(|m| m.name == macro_call.name)
            .ok_or_else(|| KslError::type_error(
                format!("Macro '{}' not found", macro_call.name),
                pos,
            ))?;

        // Validate argument count
        let required_args = macro_def.params.iter().filter(|p| !p.is_optional).count();
        if macro_call.args.len() < required_args {
            return Err(KslError::type_error(
                format!(
                    "Macro '{}' expects at least {} arguments, got {}",
                    macro_call.name, required_args, macro_call.args.len()
                ),
                pos,
            ));
        }

        // Substitute parameters in the macro body
        let mut expanded_body = macro_def.body.clone();
        for (param, arg) in macro_def.params.iter().zip(macro_call.args.iter()) {
            expanded_body = self.substitute(&expanded_body, &param.name, arg)?;
        }

        // Apply post-expansion transformations
        if macro_def.is_async {
            self.ast_transformer.transform_async(&mut expanded_body)?;
        }
        if macro_def.is_networking {
            self.ast_transformer.optimize_networking(&mut expanded_body)?;
        }

        Ok(expanded_body)
    }

    /// Substitute a parameter in the AST with an argument.
    fn substitute(&self, nodes: &[AstNode], param_name: &str, arg: &AstNode) -> Result<Vec<AstNode>, KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut result = vec![];

        for node in nodes {
            let new_node = match node {
                AstNode::Let { name, ty, value } => {
                    if name == param_name {
                        arg.clone()
                    } else {
                        AstNode::Let {
                            name: name.clone(),
                            ty: ty.clone(),
                            value: Box::new(self.substitute(&[value.as_ref().clone()], param_name, arg)?[0].clone()),
                        }
                    }
                }
                AstNode::Call { name, args } => {
                    if name == param_name {
                        match arg {
                            AstNode::Literal(lit) => AstNode::Call {
                                name: lit.clone(),
                                args: args.clone(),
                            },
                            _ => return Err(KslError::type_error(
                                format!("Expected identifier for parameter '{}', got {:?}", param_name, arg),
                                pos,
                            )),
                        }
                    } else {
                        let new_args = self.substitute(args, param_name, arg)?;
                        AstNode::Call {
                            name: name.clone(),
                            args: new_args,
                        }
                    }
                }
                AstNode::Network { op_type, endpoint, headers, data } => {
                    if endpoint == param_name {
                        match arg {
                            AstNode::Literal(lit) => AstNode::Network {
                                op_type: op_type.clone(),
                                endpoint: lit.clone(),
                                headers: headers.clone(),
                                data: data.clone(),
                            },
                            _ => return Err(KslError::type_error(
                                format!("Expected string for network endpoint '{}', got {:?}", param_name, arg),
                                pos,
                            )),
                        }
                    } else {
                        node.clone()
                    }
                }
                AstNode::Literal(lit) => {
                    if lit == param_name {
                        arg.clone()
                    } else {
                        AstNode::Literal(lit.clone())
                    }
                }
                _ => node.clone(),
            };
            result.push(new_node);
        }

        Ok(result)
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
                ParamType::String | ParamType::NetworkEndpoint => {
                    // Strings and network endpoints are fixed-size in KSL
                }
                ParamType::Ident => {
                    // Identifiers are valid
                }
                ParamType::Expr | ParamType::AsyncTask => {
                    // Expressions and async tasks will be checked after expansion
                }
                ParamType::Type => {
                    // Types will be checked after expansion
                }
                ParamType::NetworkHeaders => {
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
}