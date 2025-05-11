// ksl_parser.rs
// Parses KSL source code into an Abstract Syntax Tree (AST).

use std::str::Chars;
use std::iter::Peekable;
use std::collections::VecDeque;
use std::collections::HashMap;

// Re-export AstNode and related types from ksl_macros.rs
pub use crate::ksl_macros::AstNode;
pub use crate::ksl_macros::NetworkOpType;
pub use crate::ksl_macros::Attribute;
pub use crate::ksl_macros::AttributeArg;
pub use crate::ksl_errors::SourcePosition;
// Import plugin types from ksl_ast.rs
use crate::ksl_ast::{PluginOp, PluginHandler, Type as AstType};

// Define stubs for internal use only
mod internal {
    use super::{AstNode, ParseError, TypeAnnotation};
    
    pub struct MacroExpander;
    impl MacroExpander {
        pub fn validate_macro(
            _name: &str,
            _params: &[(String, TypeAnnotation)],
            _body: &[AstNode],
        ) -> Result<(), ParseError> {
            Ok(()) // Placeholder
    }
}

    pub struct AsyncValidator;
    impl AsyncValidator {
        pub fn validate_async_call(
            _name: &str,
            _args: &[AstNode],
        ) -> Result<(), ParseError> {
            Ok(()) // Placeholder
        }
    }
}

/// Token types for KSL source code.
#[derive(Debug, PartialEq, Clone)]
enum Token {
    Ident(String),
    Number(String),     // e.g., "42", "3.14"
    String(String),     // e.g., "data"
    Keyword(String),    // e.g., "let", "const", "fn", "if", "macro", "async"
    Symbol(String),     // e.g., "=", ":", "{", "}", "<", ">", "[", "]", "!"
    EOF,
}

/// Type annotations for variables and parameters.
#[derive(Debug, PartialEq, Clone)]
pub enum TypeAnnotation {
    Simple(String),            // e.g., "u32"
    Array { 
        element: Box<TypeAnnotation>, // e.g., "u8" in array<u8, 32>
        size: u32,             // e.g., 32 in array<u8, 32>
    },
    Result {
        success: Box<TypeAnnotation>,
        error: Box<TypeAnnotation>,
    },
}

/// Expression kinds within AST nodes.
#[derive(Debug, PartialEq, Clone)]
pub enum ExprKind {
    Ident(String),
    Number(String),
    String(String),
    BinaryOp {
        op: String,           // e.g., "+", ">", "=="
        left: Box<AstNode>,
        right: Box<AstNode>,
    },
    Call {
        name: String,
        args: Vec<AstNode>,
    },
    MacroCall {
        name: String,
        args: Vec<AstNode>,
    },
    AsyncCall {
        name: String,
        args: Vec<AstNode>,
    },
    ArrayAccess {
        array: Box<AstNode>,
        index: Box<AstNode>,
    },
}

/// Documentation comment type
#[derive(Debug, PartialEq, Clone)]
pub struct DocComment {
    pub text: String,
    pub position: usize,
}

/// Parser error type.
#[derive(Debug)]
pub struct ParseError {
    pub message: String,
    pub position: usize,
}

/// Match arm structure
#[derive(Debug, PartialEq, Clone)]
struct MatchArm {
    pattern: AstNode,
    body: Vec<AstNode>,
}

impl MatchArm {
    fn clone_with_body(&self, new_body: Vec<AstNode>) -> Self {
        MatchArm {
            pattern: self.pattern.clone(),
            body: new_body,
        }
    }
}

// Lexer struct
struct Lexer<'a> {
    input: Peekable<Chars<'a>>,
    position: usize,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str) -> Self {
        Lexer {
            input: input.chars().peekable(),
            position: 0,
        }
    }

    fn next_token(&mut self) -> Result<Token, ParseError> {
        self.skip_whitespace();
        let Some(&ch) = self.input.peek() else {
            return Ok(Token::EOF);
        };

        self.position += 1;
        match ch {
            'a'..='z' | 'A'..='Z' | '_' => self.read_identifier(),
            '0'..='9' => self.read_number(),
            '"' => self.read_string(),
            '=' | ':' | '+' | '>' | '{' | '}' | '(' | ')' | ',' | ';' | '<' | '>' | '[' | ']' | '!' => {
                self.input.next();
                Ok(Token::Symbol(ch.to_string()))
            }
            _ => Err(ParseError {
                message: format!("Unexpected character: {}", ch),
                position: self.position - 1,
            }),
        }
    }

    fn skip_whitespace(&mut self) {
        while let Some(&ch) = self.input.peek() {
            if ch.is_whitespace() {
                self.input.next();
                self.position += 1;
            } else {
                break;
            }
        }
    }

    fn read_identifier(&mut self) -> Result<Token, ParseError> {
        let mut ident = String::new();
        while let Some(&ch) = self.input.peek() {
            if ch.is_alphanumeric() || ch == '_' {
                ident.push(ch);
                self.input.next();
                self.position += 1;
            } else {
                break;
            }
        }
        Ok(match ident.as_str() {
            "let" | "const" | "var" | "fn" | "if" | "else" | "match" | "array" | "macro" | "async" => {
                Token::Keyword(ident)
            }
            _ => Token::Ident(ident),
        })
    }

    fn read_number(&mut self) -> Result<Token, ParseError> {
        let mut num = String::new();
        while let Some(&ch) = self.input.peek() {
            if ch.is_digit(10) || ch == '.' {
                num.push(ch);
                self.input.next();
                self.position += 1;
            } else {
                break;
            }
        }
        Ok(Token::Number(num))
    }

    fn read_string(&mut self) -> Result<Token, ParseError> {
        self.input.next(); // Consume opening quote
        self.position += 1;
        let mut string = String::new();
        while let Some(&ch) = self.input.peek() {
            if ch == '"' {
                self.input.next();
                self.position += 1;
                return Ok(Token::String(string));
            }
            string.push(ch);
            self.input.next();
            self.position += 1;
        }
        Err(ParseError {
            message: "Unterminated string literal".to_string(),
            position: self.position,
        })
    }
}

// Parser struct
struct Parser<'a> {
    lexer: Lexer<'a>,
    current: Token,
}

impl<'a> Parser<'a> {
    /// Creates a new parser for the given input.
    /// @param input The KSL source code to parse.
    /// @returns A `Result` containing the parser or a `ParseError`.
    /// @example
    /// ```ksl
    /// let parser = Parser::new("let x: u32 = 42;").unwrap();
    /// ```
    fn new(input: &'a str) -> Result<Self, ParseError> {
        let mut lexer = Lexer::new(input);
        let current = lexer.next_token()?;
        Ok(Parser { lexer, current })
    }

    fn advance(&mut self) -> Result<(), ParseError> {
        self.current = self.lexer.next_token()?;
        Ok(())
    }

    fn expect(&mut self, expected: Token) -> Result<(), ParseError> {
        if self.current == expected {
            self.advance()?;
            Ok(())
        } else {
            Err(ParseError {
                message: format!("Expected {:?}, got {:?}", expected, self.current),
                position: self.lexer.position,
            })
        }
    }

    /// Parses a KSL program into a vector of AST nodes.
    /// @returns A `Result` containing the AST nodes or a `ParseError`.
    /// @example
    /// ```ksl
    /// let ast = parse("let x: u32 = 42;").unwrap();
    /// ```
    pub fn parse_program(&mut self) -> Result<Vec<AstNode>, ParseError> {
        let mut nodes = Vec::new();
        while self.current != Token::EOF {
            nodes.push(self.parse_statement()?);
        }
        Ok(nodes)
    }

    fn parse_statement(&mut self) -> Result<AstNode, ParseError> {
        match &self.current {
            Token::Symbol(s) if s == "#" => {
                // Look ahead for block type
                let attrs = self.parse_attributes()?;
                match &self.current {
                    Token::Keyword(k) => match k.as_str() {
                        "shard" => self.parse_shard_block(),
                        "validator" => self.parse_validator_block(),
                        "contract" => self.parse_contract_block(),
                        _ => self.parse_fn_decl(), // Regular function with attributes
                    },
                    _ => Err(ParseError {
                        message: "Expected block type after attributes".to_string(),
                        position: self.lexer.position,
                    }),
                }
            }
            Token::Keyword(k) if k == "let" || k == "const" || k == "var" => self.parse_var_decl(),
            Token::Keyword(k) if k == "fn" => self.parse_fn_decl(),
            Token::Keyword(k) if k == "if" => self.parse_if(),
            Token::Keyword(k) if k == "match" => self.parse_match(),
            Token::Keyword(k) if k == "macro" => self.parse_macro_def(),
            Token::Keyword(k) if k == "verify" => self.parse_verify_block(),
            Token::Keyword(k) if k == "plugin" => self.parse_plugin_decl(),
            Token::Keyword(k) if k == "use" => self.parse_use_plugin(),
            Token::Keyword(k) if k == "request_capability" => self.parse_capability_request(),
            _ => self.parse_expr(),
        }
    }

    fn parse_var_decl(&mut self) -> Result<AstNode, ParseError> {
        let is_mutable = match &self.current {
            Token::Keyword(k) => {
                let mutable = k == "let" || k == "var";
                self.advance()?;
                mutable
            }
            _ => unreachable!(),
        };
        let name = match &self.current {
            Token::Ident(name) => {
                let name = name.clone();
                self.advance()?;
                name
            }
            _ => {
                return Err(ParseError {
                    message: "Expected identifier".to_string(),
                    position: self.lexer.position,
                })
            }
        };
        let type_annot = if self.match_symbol(":") {
            self.advance()?;
            Some(self.parse_type_annotation()?)
        } else {
            None
        };
        self.expect_symbol("=")?;
        let expr = self.parse_expr()?;
        self.expect_symbol(";")?;
        Ok(AstNode::VarDecl {
            is_mutable,
            name,
            type_annot,
            expr: Box::new(expr),
        })
    }

    fn parse_fn_decl(&mut self) -> Result<AstNode, ParseError> {
        let doc = self.parse_doc_comment()?;
        let attributes = self.parse_attributes()?;
        
        self.expect(Token::Keyword("fn".to_string()))?;
        let name = match &self.current {
            Token::Ident(name) => name.clone(),
            _ => return Err(ParseError {
                message: "Expected function name".to_string(),
                position: self.lexer.position,
            }),
        };
        self.advance()?;

        self.expect(Token::Symbol("(".to_string()))?;
        let params = self.parse_params()?;
        self.expect(Token::Symbol(")".to_string()))?;

        // Parse requires clause if present
        let required_capabilities = if self.current == Token::Keyword("requires".to_string()) {
            self.advance()?;
            self.expect(Token::Symbol("{".to_string()))?;
            let mut capabilities = Vec::new();
            while self.current != Token::Symbol("}".to_string()) {
                match &self.current {
                    Token::Ident(cap) => {
                        capabilities.push(cap.clone());
                        self.advance()?;
                        if self.current == Token::Symbol(",".to_string()) {
                            self.advance()?;
                        }
                    }
                    _ => return Err(ParseError {
                        message: "Expected capability name".to_string(),
                        position: self.lexer.position,
                    }),
                }
            }
            self.expect(Token::Symbol("}".to_string()))?;
            capabilities
        } else {
            Vec::new()
        };

        self.expect(Token::Symbol(":".to_string()))?;
        let return_type = self.parse_type_annotation()?;

        self.expect(Token::Symbol("{".to_string()))?;
        let mut body = Vec::new();
        while self.current != Token::Symbol("}".to_string()) {
            body.push(self.parse_statement()?);
        }
        self.expect(Token::Symbol("}".to_string()))?;

        Ok(AstNode::FnDecl {
            doc,
            name,
            params,
            return_type,
            required_capabilities,
            body,
            attributes,
        })
    }

    fn parse_doc_comment(&mut self) -> Result<Option<String>, ParseError> {
        let mut doc = None;
        while let Token::Symbol(s) = &self.current {
            if s == "///" {
                self.advance()?;
                if let Token::String(comment) = &self.current {
                    doc = Some(comment.clone());
                    self.advance()?;
                }
            } else {
                break;
            }
        }
        Ok(doc)
    }

    fn parse_attributes(&mut self) -> Result<Vec<Attribute>, ParseError> {
        let mut attributes = Vec::new();
        let start_pos = self.lexer.position;

        while let Token::Symbol(s) = &self.current {
            if s == "#" {
                self.advance()?;
                
                // Look for opening bracket
                if let Token::Symbol(s) = &self.current {
                    if s == "[" {
                        self.advance()?;
                        
                        // Parse attribute name
                        let name = match &self.current {
                            Token::Ident(name) => {
                                let name = name.clone();
                                self.advance()?;
                                name
                            }
                            _ => {
                                // Error recovery: Skip to next attribute or end
                                self.recover_to(&[
                                    Token::Symbol("]".to_string()),
                                    Token::Symbol("#".to_string())
                                ])?;
                                continue;
                            }
                        };

                        // Parse attribute arguments
                        let mut args = Vec::new();
                        if let Token::Symbol(s) = &self.current {
                            if s == "(" {
                                self.advance()?;
                                
                                while let Token::Symbol(s) = &self.current {
                                    if s == ")" {
                                        break;
                                    }
                                    
                                    if let Ok(arg) = self.parse_attribute_arg() {
                                        args.push(arg);
                                    } else {
                                        // Error recovery: Skip to end of argument
                                        self.recover_to(&[
                                            Token::Symbol(",".to_string()),
                                            Token::Symbol(")".to_string())
                                        ])?;
                                    }
                                    
                                    if let Token::Symbol(s) = &self.current {
                                        if s == "," {
                                            self.advance()?;
                                        } else {
                                            break;
                                        }
                                    } else {
                                        break;
                                    }
                                }
                                
                                self.expect(Token::Symbol(")".to_string()))?;
                            }
                        }

                        self.expect(Token::Symbol("]".to_string()))?;

                        attributes.push(Attribute {
                            name,
                            args,
                            position: SourcePosition::new(start_pos, self.lexer.position),
                        });
                    }
                }
            } else {
                break;
            }
        }

        Ok(attributes)
    }

    /// Parses an attribute argument
    fn parse_attribute_arg(&mut self) -> Result<AttributeArg, ParseError> {
        match &self.current {
            Token::String(s) => {
                let s = s.clone();
                self.advance()?;
                Ok(AttributeArg::String(s))
            }
            Token::Number(n) => {
                let n = n.parse().map_err(|_| ParseError {
                    message: "Invalid number in attribute".to_string(),
                    position: self.lexer.position,
                })?;
                self.advance()?;
                Ok(AttributeArg::Number(n))
            }
            Token::Ident(i) => {
                let i = i.clone();
                self.advance()?;
                if self.current == Token::Symbol("=".to_string()) {
                    self.advance()?;
                    let value = self.parse_attribute_arg()?;
                    Ok(AttributeArg::KeyValue(i, Box::new(value)))
                } else {
                    Ok(AttributeArg::Ident(i))
                }
            }
            _ => Err(ParseError {
                message: format!("Unexpected token in attribute: {:?}", self.current),
                position: self.lexer.position,
            }),
        }
    }

    /// Enhanced error recovery
    fn recover_to(&mut self, sync_tokens: &[Token]) -> Result<(), ParseError> {
        let mut errors = Vec::new();
        while !sync_tokens.contains(&self.current) && self.current != Token::EOF {
            errors.push(format!("Skipping unexpected token: {:?}", self.current));
            self.advance()?;
        }
        if !errors.is_empty() {
            Err(ParseError {
                message: errors.join("\n"),
                position: self.lexer.position,
            })
        } else {
            Ok(())
        }
    }

    fn parse_macro_def(&mut self) -> Result<AstNode, ParseError> {
        self.expect(Token::Keyword("macro".to_string()))?;
        let name = match &self.current {
            Token::Ident(name) => {
                let name = name.clone();
                self.advance()?;
                name
            }
            _ => {
                return Err(ParseError {
                    message: "Expected macro name".to_string(),
                    position: self.lexer.position,
                })
            }
        };
        self.expect(Token::Symbol("(".to_string()))?;
        let params = self.parse_params()?;
        self.expect(Token::Symbol(")".to_string()))?;
        self.expect(Token::Symbol("{".to_string()))?;
        let mut body = Vec::new();
        while self.current != Token::Symbol("}".to_string()) && self.current != Token::EOF {
            body.push(self.parse_statement()?);
        }
        self.expect(Token::Symbol("}".to_string()))?;
        // Validate macro with ksl_macros
        internal::MacroExpander::validate_macro(&name, &params, &body)?;
        Ok(AstNode::MacroDef {
            name,
            params,
            body,
        })
    }

    fn parse_params(&mut self) -> Result<Vec<(String, TypeAnnotation)>, ParseError> {
        let mut params = Vec::new();
        if self.current == Token::Symbol(")".to_string()) {
            return Ok(params);
        }
        loop {
            let name = match &self.current {
                Token::Ident(name) => {
                    let name = name.clone();
                    self.advance()?;
                    name
                }
                _ => {
                    return Err(ParseError {
                        message: "Expected parameter name".to_string(),
                        position: self.lexer.position,
                    })
                }
            };
            self.expect(Token::Symbol(":".to_string()))?;
            let type_ = self.parse_type_annotation()?;
            params.push((name, type_));
            if self.current == Token::Symbol(",".to_string()) {
                self.advance()?;
            } else {
                break;
            }
        }
        Ok(params)
    }

    fn parse_type_annotation(&mut self) -> Result<TypeAnnotation, ParseError> {
        match &self.current {
            Token::Keyword(k) if k == "array" => {
                self.advance()?;
                self.expect(Token::Symbol("<".to_string()))?;
                
                // Parse element type recursively
                let element = Box::new(self.parse_type_annotation()?);
                
                self.expect(Token::Symbol(",".to_string()))?;
                
                // Parse size
                let size = match &self.current {
                    Token::Number(n) => {
                        let n = n.parse::<u32>().map_err(|_| ParseError {
                            message: "Invalid array size".to_string(),
                            position: self.lexer.position,
                        })?;
                        self.advance()?;
                        n
                    }
                    _ => {
                        return Err(ParseError {
                            message: "Expected array size".to_string(),
                            position: self.lexer.position,
                        })
                    }
                };
                
                self.expect(Token::Symbol(">".to_string()))?;
                Ok(TypeAnnotation::Array { element, size })
            }
            Token::Ident(t) => {
                let t = t.clone();
                self.advance()?;
                Ok(TypeAnnotation::Simple(t))
            }
            _ => Err(ParseError {
                message: "Expected type annotation".to_string(),
                position: self.lexer.position,
            })
        }
    }

    fn parse_if(&mut self) -> Result<AstNode, ParseError> {
        self.expect(Token::Keyword("if".to_string()))?;
        let condition = self.parse_expr()?;
        self.expect(Token::Symbol("{".to_string()))?;
        let mut then_branch = Vec::new();
        while self.current != Token::Symbol("}".to_string()) && self.current != Token::EOF {
            then_branch.push(self.parse_statement()?);
        }
        self.expect(Token::Symbol("}".to_string()))?;
        let else_branch = if self.current == Token::Keyword("else".to_string()) {
            self.advance()?;
            self.expect(Token::Symbol("{".to_string()))?;
            let mut else_body = Vec::new();
            while self.current != Token::Symbol("}".to_string()) && self.current != Token::EOF {
                else_body.push(self.parse_statement()?);
            }
            self.expect(Token::Symbol("}".to_string()))?;
            Some(else_body)
        } else {
            None
        };
        Ok(AstNode::If {
            condition: Box::new(condition),
            then_branch,
            else_branch,
        })
    }

    fn parse_match(&mut self) -> Result<AstNode, ParseError> {
        self.expect(Token::Keyword("match".to_string()))?;
        let expr = self.parse_expr()?;
        self.expect(Token::Symbol("{".to_string()))?;
        let mut arms = Vec::new();
        while self.current != Token::Symbol("}".to_string()) && self.current != Token::EOF {
            let pattern = self.parse_expr()?;
            self.expect(Token::Symbol("=>".to_string()))?;
            let mut body = Vec::new();
            if self.current == Token::Symbol("{".to_string()) {
                self.advance()?;
                while self.current != Token::Symbol("}".to_string()) && self.current != Token::EOF {
                    body.push(self.parse_statement()?);
                }
                self.expect(Token::Symbol("}".to_string()))?;
            } else {
                body.push(self.parse_statement()?);
            }
            arms.push(MatchArm {
                pattern,
                body,
            });
            if self.current == Token::Symbol(",".to_string()) {
                self.advance()?;
            }
        }
        self.expect(Token::Symbol("}".to_string()))?;
        Ok(AstNode::Match {
            expr: Box::new(expr),
            arms,
        })
    }

    fn parse_expr(&mut self) -> Result<AstNode, ParseError> {
        self.parse_binary_op(0)
    }

    fn parse_binary_op(&mut self, precedence: u8) -> Result<AstNode, ParseError> {
        let mut left = self.parse_primary()?;
        while let Token::Symbol(op) = &self.current {
            let op_precedence = match op.as_str() {
                ">" | "==" => 1,
                "+" => 2,
                _ => 0,
            };
            if op_precedence < precedence {
                break;
            }
            let op = op.clone();
            self.advance()?;
            let right = self.parse_binary_op(op_precedence + 1)?;
            left = AstNode::Expr {
                kind: ExprKind::BinaryOp {
                    op,
                    left: Box::new(left),
                    right: Box::new(right),
                },
            };
        }
        Ok(left)
    }

    fn parse_primary(&mut self) -> Result<AstNode, ParseError> {
        if let Token::Keyword(k) = &self.current {
            if k == "async" {
                self.advance()?;
                return self.parse_async_call();
            }
        }
        match &self.current {
            Token::Ident(name) => {
                let name = name.clone();
                self.advance()?;
                if self.current == Token::Symbol("!".to_string()) {
                    // Parse macro call
                    self.advance()?;
                    self.expect(Token::Symbol("(".to_string()))?;
                    let mut args = Vec::new();
                    if self.current != Token::Symbol(")".to_string()) {
                        loop {
                            args.push(self.parse_expr()?);
                            if self.current == Token::Symbol(",".to_string()) {
                                self.advance()?;
                            } else {
                                break;
                            }
                        }
                    }
                    self.expect(Token::Symbol(")".to_string()))?;
                    Ok(AstNode::Expr {
                        kind: ExprKind::MacroCall { name, args },
                    })
                } else if self.current == Token::Symbol("(".to_string()) {
                    // Parse function call
                    self.advance()?;
                    let mut args = Vec::new();
                    if self.current != Token::Symbol(")".to_string()) {
                        loop {
                            args.push(self.parse_expr()?);
                            if self.current == Token::Symbol(",".to_string()) {
                                self.advance()?;
                            } else {
                                break;
                            }
                        }
                    }
                    self.expect(Token::Symbol(")".to_string()))?;
                    Ok(AstNode::Expr {
                        kind: ExprKind::Call { name, args },
                    })
                } else {
                    Ok(AstNode::Expr {
                        kind: ExprKind::Ident(name),
                    })
                }
            }
            Token::Number(num) => {
                let num = num.clone();
                self.advance()?;
                Ok(AstNode::Expr {
                    kind: ExprKind::Number(num),
                })
            }
            Token::String(s) => {
                let s = s.clone();
                self.advance()?;
                Ok(AstNode::Expr {
                    kind: ExprKind::String(s),
                })
            }
            _ => Err(ParseError {
                message: format!("Unexpected token: {:?}", self.current),
                position: self.lexer.position,
            }),
        }
    }

    fn parse_async_call(&mut self) -> Result<AstNode, ParseError> {
        let name = match &self.current {
            Token::Ident(name) => name.clone(),
            _ => return Err(ParseError {
                message: "Expected function name".to_string(),
                position: self.lexer.position,
            }),
        };
        self.advance()?;

        self.expect(Token::Symbol("(".to_string()))?;
        let mut args = Vec::new();
        while self.current != Token::Symbol(")".to_string()) {
            args.push(self.parse_expr()?);
            if self.current == Token::Symbol(",".to_string()) {
                self.advance()?;
            }
        }
        self.expect(Token::Symbol(")".to_string()))?;

        // Validate async call
        internal::AsyncValidator::validate_async_call(&name, &args)?;

        Ok(AstNode::Expr {
            kind: ExprKind::AsyncCall { name, args },
        })
    }

    /// Parses a shard block
    fn parse_shard_block(&mut self) -> Result<AstNode, ParseError> {
        let attributes = self.parse_attributes()?;
        self.expect(Token::Keyword("shard".to_string()))?;
        
        self.expect(Token::Symbol("(".to_string()))?;
        let mut params = Vec::new();
        if self.current != Token::Symbol(")".to_string()) {
            loop {
                let name = match &self.current {
                    Token::Ident(name) => {
                        let name = name.clone();
                        self.advance()?;
                        name
                    }
                    _ => return Err(ParseError {
                        message: "Expected parameter name".to_string(),
                        position: self.lexer.position,
                    }),
                };
                
                self.expect(Token::Symbol(":".to_string()))?;
                let type_annotation = self.parse_type_annotation()?;
                let ast_type = self.convert_type_annotation_to_ast_type(&type_annotation)?;
                
                params.push((name, ast_type));
                
                if self.current == Token::Symbol(",".to_string()) {
                    self.advance()?;
                } else {
                    break;
                }
            }
        }
        self.expect(Token::Symbol(")".to_string()))?;

        self.expect(Token::Symbol("{".to_string()))?;
        let mut body = Vec::new();
        while self.current != Token::Symbol("}".to_string()) && self.current != Token::EOF {
            body.push(self.parse_statement()?);
        }
        self.expect(Token::Symbol("}".to_string()))?;

        Ok(AstNode::ShardBlock {
            attributes,
            params,
            body,
        })
    }

    /// Parses a validator block
    fn parse_validator_block(&mut self) -> Result<AstNode, ParseError> {
        let attributes = self.parse_attributes()?;
        self.expect(Token::Keyword("validator".to_string()))?;
        
        self.expect(Token::Symbol("(".to_string()))?;
        let mut params = Vec::new();
        if self.current != Token::Symbol(")".to_string()) {
            loop {
                let name = match &self.current {
                    Token::Ident(name) => {
                        let name = name.clone();
                        self.advance()?;
                        name
                    }
                    _ => return Err(ParseError {
                        message: "Expected parameter name".to_string(),
                        position: self.lexer.position,
                    }),
                };
                
                self.expect(Token::Symbol(":".to_string()))?;
                let type_annotation = self.parse_type_annotation()?;
                let ast_type = self.convert_type_annotation_to_ast_type(&type_annotation)?;
                
                params.push((name, ast_type));
                
                if self.current == Token::Symbol(",".to_string()) {
                    self.advance()?;
                } else {
                    break;
                }
            }
        }
        self.expect(Token::Symbol(")".to_string()))?;

        self.expect(Token::Symbol("{".to_string()))?;
        let mut body = Vec::new();
        while self.current != Token::Symbol("}".to_string()) && self.current != Token::EOF {
            body.push(self.parse_statement()?);
        }
        self.expect(Token::Symbol("}".to_string()))?;

        Ok(AstNode::ValidatorBlock {
            attributes,
            params,
            body,
        })
    }

    /// Parses a contract block
    fn parse_contract_block(&mut self) -> Result<AstNode, ParseError> {
        let attributes = self.parse_attributes()?;
        self.expect(Token::Keyword("contract".to_string()))?;
        
        let name = match &self.current {
            Token::Ident(name) => {
                let name = name.clone();
                self.advance()?;
                name
            }
            _ => return Err(ParseError {
                message: "Expected contract name".to_string(),
                position: self.lexer.position,
            }),
        };

        self.expect(Token::Symbol("{".to_string()))?;
        
        // Parse state variables
        let mut state = Vec::new();
        while self.current == Token::Keyword("let".to_string()) {
            self.advance()?;
            let var_name = match &self.current {
                Token::Ident(name) => {
                    let name = name.clone();
                    self.advance()?;
                    name
                }
                _ => return Err(ParseError {
                    message: "Expected state variable name".to_string(),
                    position: self.lexer.position,
                }),
            };
            self.expect(Token::Symbol(":".to_string()))?;
            let type_annotation = self.parse_type_annotation()?;
            let ast_type = self.convert_type_annotation_to_ast_type(&type_annotation)?;
            self.expect(Token::Symbol(";".to_string()))?;
            state.push((var_name, ast_type));
        }

        // Parse methods
        let mut methods = Vec::new();
        while self.current != Token::Symbol("}".to_string()) && self.current != Token::EOF {
            methods.push(self.parse_fn_decl()?);
        }
        self.expect(Token::Symbol("}".to_string()))?;

        Ok(AstNode::ContractBlock {
            attributes,
            name,
            state,
            methods,
        })
    }

    /// Parses a verify block containing postconditions/assertions
    fn parse_verify_block(&mut self) -> Result<AstNode, ParseError> {
        self.expect(Token::Keyword("verify".to_string()))?;
        self.expect(Token::Symbol("{".to_string()))?;
        
        let mut conditions = Vec::new();
        while self.current != Token::Symbol("}".to_string()) && self.current != Token::EOF {
            let condition = self.parse_expr()?;
            conditions.push(condition);
            
            // Expect semicolon after each condition
            if self.current == Token::Symbol(";".to_string()) {
                self.advance()?;
            } else if self.current != Token::Symbol("}".to_string()) {
                return Err(ParseError {
                    message: "Expected semicolon after condition".to_string(),
                    position: self.lexer.position,
                });
            }
        }
        
        self.expect(Token::Symbol("}".to_string()))?;
        
        Ok(AstNode::VerifyBlock { conditions })
    }

    /// Parse a plugin declaration
    fn parse_plugin_decl(&mut self) -> Result<AstNode, ParseError> {
        self.expect(Token::Keyword("plugin".to_string()))?;
        
        // Parse plugin name
        let name = match &self.current {
            Token::Ident(name) => {
                let name = name.clone();
                self.advance()?;
                name
            }
            _ => return Err(ParseError {
                message: "Expected plugin name".to_string(),
                position: self.lexer.position,
            }),
        };
        
        // Parse namespace
        self.expect(Token::Symbol(":".to_string()))?;
        let namespace = match &self.current {
            Token::Ident(ns) => {
                let ns = ns.clone();
                self.advance()?;
                ns
            }
            _ => return Err(ParseError {
                message: "Expected plugin namespace".to_string(),
                position: self.lexer.position,
            }),
        };
        
        // Parse version
        self.expect(Token::Symbol("=".to_string()))?;
        let version = match &self.current {
            Token::String(ver) => {
                let ver = ver.clone();
                self.advance()?;
                ver
            }
            _ => return Err(ParseError {
                message: "Expected plugin version".to_string(),
                position: self.lexer.position,
            }),
        };
        
        // Parse operations
        self.expect(Token::Symbol("{".to_string()))?;
        let mut ops = Vec::new();
        while self.current != Token::Symbol("}".to_string()) {
            ops.push(self.parse_plugin_op()?);
            if self.current == Token::Symbol(",".to_string()) {
                self.advance()?;
            }
        }
        self.expect(Token::Symbol("}".to_string()))?;
        
        Ok(AstNode::PluginDecl {
            name,
            namespace,
            version,
            ops,
        })
    }
    
    /// Parse a plugin operation
    fn parse_plugin_op(&mut self) -> Result<PluginOp, ParseError> {
        // Parse operation name
        let name = match &self.current {
            Token::Ident(name) => {
                let name = name.clone();
                self.advance()?;
                name
            }
            _ => return Err(ParseError {
                message: "Expected operation name".to_string(),
                position: self.lexer.position,
            }),
        };
        
        // Parse signature
        self.expect(Token::Symbol("(".to_string()))?;
        let mut signature = Vec::new();
        if self.current != Token::Symbol(")".to_string()) {
            loop {
                let type_annotation = self.parse_type_annotation()?;
                // Convert TypeAnnotation to AstType
                let ast_type = self.convert_type_annotation_to_ast_type(&type_annotation)?;
                signature.push(ast_type);
                if self.current == Token::Symbol(",".to_string()) {
                    self.advance()?;
                } else {
                    break;
                }
            }
        }
        self.expect(Token::Symbol(")".to_string()))?;
        
        // Parse return type
        self.expect(Token::Symbol(":".to_string()))?;
        let return_type_annotation = self.parse_type_annotation()?;
        let return_type = self.convert_type_annotation_to_ast_type(&return_type_annotation)?;
        
        // Parse handler
        self.expect(Token::Symbol("=>".to_string()))?;
        let handler = self.parse_plugin_handler()?;
        
        Ok(PluginOp {
            name,
            signature,
            return_type,
            handler,
        })
    }
    
    /// Convert TypeAnnotation to AstType
    fn convert_type_annotation_to_ast_type(&self, type_annotation: &TypeAnnotation) -> Result<AstType, ParseError> {
        match type_annotation {
            TypeAnnotation::Simple(name) => {
                match name.as_str() {
                    // Integer types
                    "u8" | "u16" | "u32" | "u64" | "usize" |
                    "i8" | "i16" | "i32" | "i64" | "isize" | 
                    "int" => Ok(AstType::Int),
                    
                    // Float types
                    "f32" | "f64" | "float" => Ok(AstType::Float),
                    
                    // Boolean type
                    "bool" => Ok(AstType::Bool),
                    
                    // String types
                    "string" | "str" => Ok(AstType::Str),
                    
                    // Special types
                    "void" => Ok(AstType::Void),
                    
                    // Everything else is a custom type
                    _ => Ok(AstType::Custom(name.clone())),
                }
            },
            TypeAnnotation::Array { element, size } => {
                let elem_type = self.convert_type_annotation_to_ast_type(&*element)?;
                Ok(AstType::Array(Box::new(elem_type), *size as usize))
            },
            TypeAnnotation::Result { success, error } => {
                let success_type = self.convert_type_annotation_to_ast_type(&*success)?;
                let error_type = self.convert_type_annotation_to_ast_type(&*error)?;
                Ok(AstType::Result(Box::new(success_type), Box::new(error_type)))
            },
        }
    }
    
    /// Parse a plugin handler
    fn parse_plugin_handler(&mut self) -> Result<PluginHandler, ParseError> {
        let kind = match &self.current {
            Token::Ident(k) => {
                let k = k.clone();
                self.advance()?;
                k
            }
            _ => return Err(ParseError {
                message: "Expected handler kind".to_string(),
                position: self.lexer.position,
            }),
        };
        
        self.expect(Token::Symbol("(".to_string()))?;
        let name = match &self.current {
            Token::String(n) => {
                let n = n.clone();
                self.advance()?;
                n
            }
            _ => return Err(ParseError {
                message: "Expected handler name".to_string(),
                position: self.lexer.position,
            }),
        };
        self.expect(Token::Symbol(")".to_string()))?;
        
        Ok(PluginHandler {
            kind,
            name,
        })
    }
    
    /// Parse a plugin usage declaration
    fn parse_use_plugin(&mut self) -> Result<AstNode, ParseError> {
        self.expect(Token::Keyword("use".to_string()))?;
        self.expect(Token::Keyword("plugin".to_string()))?;
        
        // Parse plugin name
        let name = match &self.current {
            Token::String(name) => {
                let name = name.clone();
                self.advance()?;
                name
            }
            _ => return Err(ParseError {
                message: "Expected plugin name".to_string(),
                position: self.lexer.position,
            }),
        };
        
        // Parse namespace
        let namespace = match &self.current {
            Token::Ident(ns) => {
                let ns = ns.clone();
                self.advance()?;
                ns
            }
            _ => return Err(ParseError {
                message: "Expected plugin namespace".to_string(),
                position: self.lexer.position,
            }),
        };
        
        Ok(AstNode::UsePlugin {
            name,
            namespace,
        })
    }

    /// Parse a dynamic capability request
    fn parse_capability_request(&mut self) -> Result<AstNode, ParseError> {
        self.advance()?; // Skip 'request_capability'
        self.expect(Token::Symbol("(".to_string()))?;

        let capability = match &self.current {
            Token::String(cap) => {
                let cap = cap.clone();
                self.advance()?;
                cap
            }
            _ => return Err(ParseError {
                message: "Expected capability name as string".to_string(),
                position: self.lexer.position,
            }),
        };

        self.expect(Token::Symbol(")".to_string()))?;
        self.expect(Token::Symbol(";".to_string()))?;

        Ok(AstNode::RequestCapability { capability })
    }

    fn match_symbol(&self, symbol: &str) -> bool {
        if let Token::Symbol(s) = &self.current {
            s == symbol
        } else {
            false
        }
    }

    fn expect_symbol(&mut self, symbol: &str) -> Result<(), ParseError> {
        if self.match_symbol(symbol) {
            self.advance()?;
            Ok(())
        } else {
            Err(ParseError {
                message: format!("Expected symbol '{}', got {:?}", symbol, self.current),
                position: self.lexer.position,
            })
        }
    }
}

/// Public API to parse KSL source code into an AST.
/// @param input The KSL source code to parse.
/// @returns A `Result` containing a vector of AST nodes or a `ParseError`.
/// @example
/// ```ksl
/// let ast = parse("let x: u32 = 42;").unwrap();
/// ```
pub fn parse(input: &str) -> Result<Vec<AstNode>, ParseError> {
    let mut parser = Parser::new(input)?;
    parser.parse_program()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_var_decl() {
        let input = "let x: u32 = 42;";
        let ast = parse(input).unwrap();
        assert_eq!(
            ast[0],
            AstNode::VarDecl {
                is_mutable: true,
                name: "x".to_string(),
                type_annot: Some(TypeAnnotation::Simple("u32".to_string())),
                expr: Box::new(AstNode::Expr {
                    kind: ExprKind::Number("42".to_string())
                }),
            }
        );
    }

    #[test]
    fn parse_var_decl_array() {
        let input = "let msg: array<u8, 32> = \"data\";";
        let ast = parse(input).unwrap();
        assert_eq!(
            ast[0],
            AstNode::VarDecl {
                is_mutable: true,
                name: "msg".to_string(),
                type_annot: Some(TypeAnnotation::Array {
                    element: Box::new(TypeAnnotation::Simple("u8".to_string())),
                    size: 32,
                }),
                expr: Box::new(AstNode::Expr {
                    kind: ExprKind::String("data".to_string())
                }),
            }
        );
    }

    #[test]
    fn parse_fn_decl() {
        let input = "fn add(x: u32, y: u32): u32 { x + y; }";
        let ast = parse(input).unwrap();
        assert_eq!(
            ast[0],
            AstNode::FnDecl {
                doc: None,
                name: "add".to_string(),
                params: vec![
                    ("x".to_string(), TypeAnnotation::Simple("u32".to_string())),
                    ("y".to_string(), TypeAnnotation::Simple("u32".to_string()))
                ],
                return_type: TypeAnnotation::Simple("u32".to_string()),
                required_capabilities: Vec::new(),
                body: vec![AstNode::Expr {
                    kind: ExprKind::BinaryOp {
                        op: "+".to_string(),
                        left: Box::new(AstNode::Expr {
                            kind: ExprKind::Ident("x".to_string())
                        }),
                        right: Box::new(AstNode::Expr {
                            kind: ExprKind::Ident("y".to_string())
                        }),
                    }
                }],
                attributes: Vec::new(),
            }
        );
    }

    #[test]
    fn parse_fn_call() {
        let input = "sha3(\"data\");";
        let ast = parse(input).unwrap();
        assert_eq!(
            ast[0],
            AstNode::Expr {
                kind: ExprKind::Call {
                    name: "sha3".to_string(),
                    args: vec![AstNode::Expr {
                        kind: ExprKind::String("data".to_string())
                    }],
                }
            }
        );
    }

    #[test]
    fn parse_if() {
        let input = "if x > 0 { y = 1; } else { y = 2; }";
        let ast = parse(input).unwrap();
        assert_eq!(
            ast[0],
            AstNode::If {
                condition: Box::new(AstNode::Expr {
                    kind: ExprKind::BinaryOp {
                        op: ">".to_string(),
                        left: Box::new(AstNode::Expr {
                            kind: ExprKind::Ident("x".to_string())
                        }),
                        right: Box::new(AstNode::Expr {
                            kind: ExprKind::Number("0".to_string())
                        }),
                    }
                }),
                then_branch: vec![AstNode::VarDecl {
                    is_mutable: true,
                    name: "y".to_string(),
                    type_annot: None,
                    expr: Box::new(AstNode::Expr {
                        kind: ExprKind::Number("1".to_string())
                    }),
                }],
                else_branch: Some(vec![AstNode::VarDecl {
                    is_mutable: true,
                    name: "y".to_string(),
                    type_annot: None,
                    expr: Box::new(AstNode::Expr {
                        kind: ExprKind::Number("2".to_string())
                    }),
                }]),
            }
        );
    }

    #[test]
    fn parse_macro_def() {
        let input = "macro log($msg: string) { print($msg); }";
        let ast = parse(input).unwrap();
        assert_eq!(
            ast[0],
            AstNode::MacroDef {
                name: "log".to_string(),
                params: vec![
                    ("msg".to_string(), TypeAnnotation::Simple("string".to_string()))
                ],
                body: vec![AstNode::Expr {
                    kind: ExprKind::Call {
                        name: "print".to_string(),
                        args: vec![AstNode::Expr {
                            kind: ExprKind::Ident("msg".to_string())
                        }],
                    }
                }],
            }
        );
    }

    #[test]
    fn parse_macro_call() {
        let input = "log!(\"Hello\");";
        let ast = parse(input).unwrap();
        assert_eq!(
            ast[0],
            AstNode::Expr {
                kind: ExprKind::MacroCall {
                    name: "log".to_string(),
                    args: vec![AstNode::Expr {
                        kind: ExprKind::String("Hello".to_string())
                    }],
                }
            }
        );
    }

    #[test]
    fn parse_async_fn() {
        let input = r#"
        /// Async function documentation
        #[async]
        fn fetch_data(url: string): string {
            let response = http.get(url);
            response
        }
        "#;
        let mut parser = Parser::new(input).unwrap();
        let ast = parser.parse_program().unwrap();
        assert_eq!(ast.len(), 1);
        if let AstNode::FnDecl { doc, name, params, return_type, body, attributes } = &ast[0] {
            assert_eq!(doc.as_deref(), Some("Async function documentation"));
            assert_eq!(name, "fetch_data");
            assert_eq!(params.len(), 1);
            assert_eq!(params[0].0, "url");
            assert_eq!(attributes.len(), 1);
            assert_eq!(attributes[0].name, "async");
            assert_eq!(body.len(), 2);
        } else {
            panic!("Expected FnDecl");
        }
    }

    #[test]
    fn parse_networking_calls() {
        let input = r#"
        fn send_data(url: string, data: string): string {
            let response = http.post(url, data);
            response
        }
        "#;
        let mut parser = Parser::new(input).unwrap();
        let ast = parser.parse_program().unwrap();
        assert_eq!(ast.len(), 1);
        if let AstNode::FnDecl { body, .. } = &ast[0] {
            assert_eq!(body.len(), 2);
            if let AstNode::Expr { kind: ExprKind::AsyncCall { name, args } } = &body[0] {
                assert_eq!(name, "http.post");
                assert_eq!(args.len(), 2);
            } else {
                panic!("Expected AsyncCall");
            }
        } else {
            panic!("Expected FnDecl");
        }
    }

    #[test]
    fn parse_match_arm() {
        let input = r#"
        match x {
            1 => {
                let y = http.get("url");
                y
            }
            2 => {
                let z = http.post("url", "data");
                z
            }
        }
        "#;
        let mut parser = Parser::new(input).unwrap();
        let ast = parser.parse_program().unwrap();
        assert_eq!(ast.len(), 1);
        if let AstNode::Match { arms, .. } = &ast[0] {
            assert_eq!(arms.len(), 2);
            let arm1 = &arms[0];
            assert_eq!(arm1.body.len(), 2);
            if let AstNode::Expr { kind: ExprKind::AsyncCall { name, .. } } = &arm1.body[0] {
                assert_eq!(name, "http.get");
            } else {
                panic!("Expected AsyncCall");
            }
            let arm2 = &arms[1];
            assert_eq!(arm2.body.len(), 2);
            if let AstNode::Expr { kind: ExprKind::AsyncCall { name, .. } } = &arm2.body[0] {
                assert_eq!(name, "http.post");
            } else {
                panic!("Expected AsyncCall");
            }
        } else {
            panic!("Expected Match");
        }
    }

    #[test]
    fn test_parse_shard_block() {
        let input = r#"
            #[shard(size = 32)]
            shard(account: array<u8, 32>) {
                let hash = sha3(account);
                return hash % 32;
            }
        "#;
        let mut parser = Parser::new(input);
        let result = parser.parse_program();
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_validator_block() {
        let input = r#"
            #[validator(stake = 1000000)]
            validator(block: array<u8, 1024>, signature: array<u8, 2420>) {
                verify_dilithium(block, signature)
            }
        "#;
        let mut parser = Parser::new(input);
        let result = parser.parse_program();
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_contract_block() {
        let input = r#"
            #[contract(version = "1.0")]
            contract Token {
                let total_supply: u64;
                let balances: map<address, u64>;

                fn transfer(to: address, amount: u64) -> bool {
                    if balances[msg.sender] >= amount {
                        balances[msg.sender] -= amount;
                        balances[to] += amount;
                        return true;
                    }
                    return false;
                }
            }
        "#;
        let mut parser = Parser::new(input);
        let result = parser.parse_program();
        assert!(result.is_ok());
    }

    #[test]
    fn test_error_recovery() {
        let input = r#"
            #[shard(size = )] // Missing value
            shard(account: array<u8, 32>) {
                let hash = sha3(account);
                return hash % 32;
            }
        "#;
        let mut parser = Parser::new(input);
        let result = parser.parse_program();
        assert!(result.is_ok()); // Should recover and continue parsing
    }

    #[test]
    fn test_parse_verify_block() {
        let input = r#"
            verify {
                x >= 0;
                y == z;
            }
        "#;
        let ast = parse(input).unwrap();
        assert_eq!(ast.len(), 1);
        
        if let AstNode::VerifyBlock { conditions } = &ast[0] {
            assert_eq!(conditions.len(), 2);
            
            // Check first condition: x >= 0
            if let AstNode::Expr { kind: ExprKind::BinaryOp { op, left, right } } = &conditions[0] {
                assert_eq!(op, ">=");
                if let AstNode::Expr { kind: ExprKind::Ident(name) } = &**left {
                    assert_eq!(name, "x");
                } else {
                    panic!("Expected identifier 'x'");
                }
                if let AstNode::Expr { kind: ExprKind::Number(num) } = &**right {
                    assert_eq!(num, "0");
                } else {
                    panic!("Expected number '0'");
                }
            } else {
                panic!("Expected binary operation");
            }
            
            // Check second condition: y == z
            if let AstNode::Expr { kind: ExprKind::BinaryOp { op, left, right } } = &conditions[1] {
                assert_eq!(op, "==");
                if let AstNode::Expr { kind: ExprKind::Ident(name) } = &**left {
                    assert_eq!(name, "y");
                } else {
                    panic!("Expected identifier 'y'");
                }
                if let AstNode::Expr { kind: ExprKind::Ident(name) } = &**right {
                    assert_eq!(name, "z");
                } else {
                    panic!("Expected identifier 'z'");
                }
            } else {
                panic!("Expected binary operation");
            }
        } else {
            panic!("Expected VerifyBlock");
        }
    }

    #[test]
    fn test_parse_plugin_decl() {
        let input = r#"
            plugin ksl_ai: ai = "1.0.0" {
                infer(model: String, input: Array<u8>): Float => native("infer_handler"),
                train(model: String, data: Array<u8>): Bool => wasm("train.wasm")
            }
        "#;
        let ast = parse(input).unwrap();
        assert!(matches!(ast[0], AstNode::PluginDecl { .. }));
    }
    
    #[test]
    fn test_parse_use_plugin() {
        let input = r#"use plugin "ksl_ai" ai"#;
        let ast = parse(input).unwrap();
        assert!(matches!(ast[0], AstNode::UsePlugin { .. }));
    }

    #[test]
    fn test_parse_fn_with_capabilities() {
        let input = r#"
            fn send_data() requires { network, crypto } : void {
                let result = ai::infer("model", input);
                send_packet("192.168.0.1", result);
            }
        "#;
        let ast = parse(input).unwrap();
        if let AstNode::FnDecl { required_capabilities, .. } = &ast[0] {
            assert_eq!(required_capabilities, &vec!["network".to_string(), "crypto".to_string()]);
        } else {
            panic!("Expected FnDecl");
        }
    }

    #[test]
    fn test_parse_capability_request_basic() {
        let input = r#"
            fn test_dynamic() : void {
                request_capability("network");
            }
        "#;
        let ast = parse(input).unwrap();
        if let AstNode::FnDecl { body, .. } = &ast[0] {
            if let AstNode::RequestCapability { capability } = &body[0] {
                assert_eq!(capability, "network");
            } else {
                panic!("Expected RequestCapability");
            }
        } else {
            panic!("Expected FnDecl");
        }
    }

    #[test]
    fn test_parse_capability_request_multiple() {
        let input = r#"
            fn test_multiple() : void {
                request_capability("network");
                request_capability("crypto");
            }
        "#;
        let ast = parse(input).unwrap();
        if let AstNode::FnDecl { body, .. } = &ast[0] {
            if let AstNode::RequestCapability { capability } = &body[0] {
                assert_eq!(capability, "network");
            } else {
                panic!("Expected RequestCapability");
            }
            if let AstNode::RequestCapability { capability } = &body[1] {
                assert_eq!(capability, "crypto");
            } else {
                panic!("Expected RequestCapability");
            }
        } else {
            panic!("Expected FnDecl");
        }
    }

    #[test]
    fn test_parse_capability_request_with_requires() {
        let input = r#"
            fn test_mixed() requires { fs } : void {
                request_capability("network");
            }
        "#;
        let ast = parse(input).unwrap();
        if let AstNode::FnDecl { required_capabilities, body, .. } = &ast[0] {
            assert_eq!(required_capabilities, &vec!["fs".to_string()]);
            if let AstNode::RequestCapability { capability } = &body[0] {
                assert_eq!(capability, "network");
            } else {
                panic!("Expected RequestCapability");
            }
        } else {
            panic!("Expected FnDecl");
        }
    }

    #[test]
    fn test_parse_capability_request_invalid() {
        // Missing string literal
        let input = r#"
            fn test_invalid() : void {
                request_capability(network);
            }
        "#;
        assert!(parse(input).is_err());

        // Missing semicolon
        let input = r#"
            fn test_invalid() : void {
                request_capability("network")
            }
        "#;
        assert!(parse(input).is_err());

        // Missing parentheses
        let input = r#"
            fn test_invalid() : void {
                request_capability "network";
            }
        "#;
        assert!(parse(input).is_err());
    }

    #[test]
    fn test_parse_capability_request_in_group() {
        let input = r#"
            fn test_group() requires { sensitive } : void {
                request_capability("network");
                let x = 42;
                request_capability("ai");
            }
        "#;
        let ast = parse(input).unwrap();
        if let AstNode::FnDecl { required_capabilities, body, .. } = &ast[0] {
            assert_eq!(required_capabilities, &vec!["sensitive".to_string()]);
            if let AstNode::RequestCapability { capability } = &body[0] {
                assert_eq!(capability, "network");
            } else {
                panic!("Expected RequestCapability");
            }
            if let AstNode::RequestCapability { capability } = &body[2] {
                assert_eq!(capability, "ai");
            } else {
                panic!("Expected RequestCapability");
            }
        } else {
            panic!("Expected FnDecl");
        }
    }
}
