// ksl_parser.rs
// Parses KSL source code into an Abstract Syntax Tree (AST).

use std::str::Chars;
use std::iter::Peekable;

// Token types for KSL source code
#[derive(Debug, PartialEq, Clone)]
enum Token {
    Ident(String),
    Number(String), // e.g., "42", "3.14"
    String(String), // e.g., "data"
    Keyword(String), // e.g., "let", "const", "fn", "if"
    Symbol(String), // e.g., "=", ":", "{", "}", "<", ">", "[", "]"
    EOF,
}

// AST node types
#[derive(Debug, PartialEq)]
enum AstNode {
    VarDecl {
        is_mutable: bool, // true for let/var, false for const
        name: String,
        type_annot: Option<TypeAnnotation>, // e.g., "u32", "array<u8, 32>"
        expr: Box<AstNode>,
    },
    FnDecl {
        name: String,
        params: Vec<(String, TypeAnnotation)>, // (name, type)
        return_type: TypeAnnotation,
        body: Vec<AstNode>,
    },
    If {
        condition: Box<AstNode>,
        then_branch: Vec<AstNode>,
        else_branch: Option<Vec<AstNode>>,
    },
    Match {
        expr: Box<AstNode>,
        arms: Vec<(AstNode, Vec<AstNode>)>, // (pattern, body)
    },
    Expr {
        kind: ExprKind,
    },
}

#[derive(Debug, PartialEq, Clone)]
enum TypeAnnotation {
    Simple(String), // e.g., "u32"
    Array { element: String, size: u32 }, // e.g., "array<u8, 32>"
}

#[derive(Debug, PartialEq)]
enum ExprKind {
    Ident(String),
    Number(String),
    String(String),
    BinaryOp {
        op: String, // e.g., "+", ">", "=="
        left: Box<AstNode>,
        right: Box<AstNode>,
    },
    Call {
        name: String,
        args: Vec<AstNode>,
    },
}

// Parser error type
#[derive(Debug)]
pub struct ParseError {
    pub message: String,
    pub position: usize,
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
            '=' | ':' | '+' | '>' | '{' | '}' | '(' | ')' | ',' | ';' | '<' | '>' | '[' | ']' => {
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
            "let" | "const" | "var" | "fn" | "if" | "else" | "match" | "array" => Token::Keyword(ident),
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

    fn parse_program(&mut self) -> Result<Vec<AstNode>, ParseError> {
        let mut nodes = Vec::new();
        while self.current != Token::EOF {
            nodes.push(self.parse_statement()?);
        }
        Ok(nodes)
    }

    fn parse_statement(&mut self) -> Result<AstNode, ParseError> {
        match &self.current {
            Token::Keyword(k) if k == "let" || k == "const" || k == "var" => self.parse_var_decl(),
            Token::Keyword(k) if k == "fn" => self.parse_fn_decl(),
            Token::Keyword(k) if k == "if" => self.parse_if(),
            Token::Keyword(k) if k == "match" => self.parse_match(),
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
        self.expect(Token::Keyword("fn".to_string()))?;
        let name = match &self.current {
            Token::Ident(name) => {
                let name = name.clone();
                self.advance()?;
                name
            }
            _ => {
                return Err(ParseError {
                    message: "Expected function name".to_string(),
                    position: self.lexer.position,
                })
            }
        };
        self.expect(Token::Symbol("(".to_string()))?;
        let params = self.parse_params()?;
        self.expect(Token::Symbol(")".to_string()))?;
        let return_type = if self.current == Token::Symbol(":".to_string()) {
            self.advance()?;
            self.parse_type_annotation()?
        } else {
            TypeAnnotation::Simple("void".to_string())
        };
        self.expect(Token::Symbol("{".to_string()))?;
        let mut body = Vec::new();
        while self.current != Token::Symbol("}".to_string()) && self.current != Token::EOF {
            body.push(self.parse_statement()?);
        }
        self.expect(Token::Symbol("}".to_string()))?;
        Ok(AstNode::FnDecl {
            name,
            params,
            return_type,
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
                let element = match &self.current {
                    Token::Ident(t) => {
                        let t = t.clone();
                        self.advance()?;
                        t
                    }
                    _ => {
                        return Err(ParseError {
                            message: "Expected element type".to_string(),
                            position: self.lexer.position,
                        })
                    }
                };
                self.expect(Token::Symbol(",".to_string()))?;
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
            }),
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
            arms.push((pattern, body));
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
        match &self.current {
            Token::Ident(name) => {
                let name = name.clone();
                self.advance()?;
                if self.current == Token::Symbol("(".to_string()) {
                    // Parse function call
                    self.advance()?;
                    [self.current.as_str()];
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
}

// Public API to parse KSL source code
pub fn parse(input: &str) -> Result<Vec<AstNode>, ParseError> {
    let mut parser = Parser::new(input)?;
    parser.parse_program()
}

// Example usage in tests
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
                    element: "u8".to_string(),
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
}