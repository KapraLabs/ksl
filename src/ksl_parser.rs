// ksl_parser.rs
// Parses KSL source code into an Abstract Syntax Tree (AST).

use std::str::Chars;
use std::iter::Peekable;
use std::collections::VecDeque;

// Assume ksl_macros.rs provides MacroExpander
mod ksl_macros {
    use super::{ParseError, TypeAnnotation, AstNode};
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
}

// Assume ksl_async.rs provides AsyncValidator
mod ksl_async {
    use super::{ParseError, AstNode};
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

/// AST node types representing KSL program structure.
#[derive(Debug, PartialEq)]
enum AstNode {
    VarDecl {
        is_mutable: bool,               // true for let/var, false for const
        name: String,
        type_annot: Option<TypeAnnotation>, // e.g., "u32", "array<u8, 32>"
        expr: Box<AstNode>,
    },
    FnDecl {
        doc: Option<String>,
        name: String,
        params: Vec<(String, TypeAnnotation)>, // (name, type)
        return_type: TypeAnnotation,
        body: Vec<AstNode>,
        attributes: Vec<Attribute>,
    },
    If {
        condition: Box<AstNode>,
        then_branch: Vec<AstNode>,
        else_branch: Option<Vec<AstNode>>,
    },
    Match {
        expr: Box<AstNode>,
        arms: Vec<MatchArm>, // (pattern, body)
    },
    MacroDef {
        name: String,
        params: Vec<(String, TypeAnnotation)>, // (name, type)
        body: Vec<AstNode>,
    },
    Expr {
        kind: ExprKind,
    },
    ArrayLiteral {
        elements: Vec<AstNode>,
        element_type: TypeAnnotation,
    },
    ArrayAccess {
        array: Box<AstNode>,
        index: Box<AstNode>,
    },
    ShardBlock {
        attributes: Vec<Attribute>,
        params: Vec<(String, TypeAnnotation)>,
        body: Vec<AstNode>,
    },
    ValidatorBlock {
        attributes: Vec<Attribute>,
        params: Vec<(String, TypeAnnotation)>,
        body: Vec<AstNode>,
    },
    ContractBlock {
        attributes: Vec<Attribute>,
        name: String,
        state: Vec<(String, TypeAnnotation)>,
        methods: Vec<AstNode>,
    },
    VerifyBlock {
        conditions: Vec<AstNode>,
    },
}

/// Type annotations for variables and parameters.
#[derive(Debug, PartialEq, Clone)]
enum TypeAnnotation {
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
#[derive(Debug, PartialEq)]
enum ExprKind {
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

/// Parser error type.
#[derive(Debug)]
pub struct ParseError {
    pub message: String,
    pub position: usize,
}

/// Enhanced attribute system for KSL
#[derive(Debug, Clone, PartialEq)]
pub struct Attribute {
    /// Attribute name (e.g., "shard", "validator", "contract")
    pub name: String,
    /// Attribute arguments
    pub args: Vec<AttributeArg>,
    /// Source position for error reporting
    pub position: SourcePosition,
}

/// Attribute argument types
#[derive(Debug, Clone, PartialEq)]
pub enum AttributeArg {
    /// String argument (e.g., name = "main")
    String(String),
    /// Number argument (e.g., size = 32)
    Number(u64),
    /// Identifier argument (e.g., type = u32)
    Ident(String),
    /// Key-value pair (e.g., config = { size = 32 })
    KeyValue(String, Box<AttributeArg>),
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
            'a'..='z' | 'A'.. Literatura='Z' | '_' => self.read_identifier(),
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
            Token::Symbol("#".to_string()) => {
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
        let type_annot = if self.current == Token::Symbol(":".to_string()) {
            self.advance()?;
            Some(self.parse_type_annotation()?)
        } else {
            None
        };
        self.expect(Token::Symbol("=".to_string()))?;
        let expr = self.parse_expr()?;
        self.expect(Token::Symbol(";".to_string()))?;
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

        while self.current == Token::Symbol("#".to_string()) {
            self.advance()?;
            self.expect(Token::Symbol("[".to_string()))?;

            // Parse attribute name
            let name = match &self.current {
                Token::Ident(name) => {
                    let name = name.clone();
                    self.advance()?;
                    name
                }
                _ => {
                    // Error recovery: Skip to next attribute or end
                    self.recover_to(&[Token::Symbol("]".to_string()), Token::Symbol("#".to_string())])?;
                    continue;
                }
            };

            // Parse attribute arguments
            let mut args = Vec::new();
            if self.current == Token::Symbol("(".to_string()) {
                self.advance()?;
                while self.current != Token::Symbol(")".to_string()) {
                    if let Ok(arg) = self.parse_attribute_arg() {
                        args.push(arg);
                    } else {
                        // Error recovery: Skip to end of argument
                        self.recover_to(&[Token::Symbol(",".to_string()), Token::Symbol(")".to_string())])?;
                    }
                    
                    if self.current == Token::Symbol(",".to_string()) {
                        self.advance()?;
                    } else {
                        break;
                    }
                }
                self.expect(Token::Symbol(")".to_string()))?;
            }

            self.expect(Token::Symbol("]".to_string()))?;

            attributes.push(Attribute {
                name,
                args,
                position: SourcePosition::new(start_pos, self.lexer.position),
            });
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
        ksl_macros::MacroExpander::validate_macro(&name, &params, &body)?;
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
        ksl_async::AsyncValidator::validate_async_call(&name, &args)?;

        Ok(AstNode::Expr {
            kind: ExprKind::AsyncCall { name, args },
        })
    }

    /// Parses a shard block
    fn parse_shard_block(&mut self) -> Result<AstNode, ParseError> {
        let attributes = self.parse_attributes()?;
        self.expect(Token::Keyword("shard".to_string()))?;
        
        self.expect(Token::Symbol("(".to_string()))?;
        let params = self.parse_params()?;
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
        let params = self.parse_params()?;
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
            let var_type = self.parse_type_annotation()?;
            self.expect(Token::Symbol(";".to_string()))?;
            state.push((var_name, var_type));
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
}
