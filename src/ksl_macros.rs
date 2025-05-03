// ksl_macros.rs
// Macro system for KSL to enable metaprogramming and code generation

/// Represents a macro parameter (e.g., $msg: string).
#[derive(Debug, Clone)]
pub struct MacroParam {
    name: String,  // e.g., "msg"
    param_type: ParamType,  // e.g., string, ident
}

impl MacroParam {
    pub fn new(name: &str, param_type: ParamType) -> Self {
        MacroParam {
            name: name.to_string(),
            param_type,
        }
    }
}

/// Types of macro parameters.
#[derive(Debug, Clone)]
pub enum ParamType {
    String,  // Literal string
    Ident,   // Identifier (e.g., for struct or contract names)
    Expr,    // Expression
    Type,    // Type annotation
}

/// Represents a macro definition.
#[derive(Debug, Clone)]
pub struct MacroDef {
    name: String,              // Macro name (e.g., "log")
    params: Vec<MacroParam>,   // Parameters (e.g., $msg: string)
    body: Vec<AstNode>,        // Body of the macro (what it expands to)
}

impl MacroDef {
    pub fn new(name: &str, params: Vec<MacroParam>, body: Vec<AstNode>) -> Self {
        MacroDef {
            name: name.to_string(),
            params,
            body,
        }
    }
}

/// Represents a macro invocation (e.g., log!("Hello")).
#[derive(Debug, Clone)]
pub struct MacroCall {
    name: String,              // Macro name (e.g., "log")
    args: Vec<AstNode>,        // Arguments (e.g., "Hello")
}

impl MacroCall {
    pub fn new(name: &str, args: Vec<AstNode>) -> Self {
        MacroCall {
            name: name.to_string(),
            args,
        }
    }
}

/// Extend the AST to support macros (used by ksl_parser.rs).
#[derive(Debug, Clone)]
pub enum AstNode {
    MacroDef(MacroDef),        // Macro definition
    MacroCall(MacroCall),      // Macro invocation
    // Existing node types (simplified for this example)...
    Let { name: String, ty: Type, value: Box<AstNode> },
    Call { name: String, args: Vec<AstNode> },
    Literal(String),
    // Placeholder for other node types
}

/// Macro expansion system (integrates with ksl_ast_transform.rs).
pub struct MacroExpander {
    macros: Vec<MacroDef>,  // Store defined macros
}

impl MacroExpander {
    pub fn new() -> Self {
        MacroExpander { macros: vec![] }
    }

    /// Register a macro definition.
    pub fn register_macro(&mut self, macro_def: MacroDef) {
        self.macros.push(macro_def);
    }

    /// Expand a macro call into an AST.
    pub fn expand(&self, macro_call: &MacroCall) -> Result<Vec<AstNode>, String> {
        // Find the macro definition
        let macro_def = self.macros.iter()
            .find(|m| m.name == macro_call.name)
            .ok_or_else(|| format!("Macro '{}' not found", macro_call.name))?;

        // Validate argument count
        if macro_call.args.len() != macro_def.params.len() {
            return Err(format!(
                "Macro '{}' expects {} arguments, got {}",
                macro_call.name, macro_def.params.len(), macro_call.args.len()
            ));
        }

        // Substitute parameters in the macro body
        let mut expanded_body = macro_def.body.clone();
        for (param, arg) in macro_def.params.iter().zip(macro_call.args.iter()) {
            expanded_body = self.substitute(&expanded_body, &param.name, arg)?;
        }

        Ok(expanded_body)
    }

    /// Substitute a parameter in the AST with an argument.
    fn substitute(&self, nodes: &[AstNode], param_name: &str, arg: &AstNode) -> Result<Vec<AstNode>, String> {
        let mut result = vec![];
        for node in nodes {
            let new_node = match node {
                AstNode::Let { name, ty, value } => {
                    if name == param_name {
                        // Replace the variable with the argument
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
                        // Replace the function name if it matches the param (e.g., for identifiers)
                        match arg {
                            AstNode::Literal(lit) => AstNode::Call {
                                name: lit.clone(),
                                args: args.clone(),
                            },
                            _ => return Err(format!("Expected identifier for parameter '{}', got {:?}", param_name, arg)),
                        }
                    } else {
                        let new_args = self.substitute(args, param_name, arg)?;
                        AstNode::Call {
                            name: name.clone(),
                            args: new_args,
                        }
                    }
                }
                AstNode::Literal(lit) => {
                    if lit == param_name {
                        arg.clone()
                    } else {
                        AstNode::Literal(lit.clone())
                    }
                }
                _ => node.clone(), // Other nodes unchanged
            };
            result.push(new_node);
        }
        Ok(result)
    }
}

/// Integrate with the type checker (used by ksl_checker.rs).
pub struct MacroTypeChecker;

impl MacroTypeChecker {
    pub fn check_macro_def(&self, macro_def: &MacroDef) -> Result<(), String> {
        // Validate parameter types
        for param in &macro_def.params {
            match param.param_type {
                ParamType::String => {}, // Strings are fixed-size in KSL
                ParamType::Ident => {},  // Identifiers are valid
                ParamType::Expr => {},   // Expressions will be checked after expansion
                ParamType::Type => {},   // Types will be checked after expansion
            }
        }

        // Recursively check the macro body
        for node in &macro_def.body {
            self.check_node(node)?;
        }

        Ok(())
    }

    fn check_node(&self, node: &AstNode) -> Result<(), String> {
        match node {
            AstNode::MacroDef(_) => Err("Nested macro definitions not supported".to_string()),
            AstNode::MacroCall(_) => Ok(()), // Will be expanded before type checking
            AstNode::Let { name: _, ty, value } => {
                // Simplified type checking (placeholder)
                self.check_node(value.as_ref())?;
                Ok(())
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
    String,
    // Other types as needed
}