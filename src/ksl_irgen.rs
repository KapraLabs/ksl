// ksl_irgen.rs
// Generates IR from AST for program analysis and auditing

use crate::ksl_ast::{AstNode, Expr, BinaryOperator, Literal};
use crate::ksl_ir::{IRNode, IRProgram, IRExport};
use crate::ksl_errors::KslError;
use std::collections::HashMap;

/// IR generator state
pub struct IRGenerator {
    /// Current program being generated
    program: IRProgram,
    /// Variable name counter for temporaries
    temp_counter: usize,
    /// Label counter for control flow
    label_counter: usize,
    /// Variable scope mapping
    variables: HashMap<String, String>,
}

impl IRGenerator {
    /// Creates a new IR generator
    pub fn new(source_file: &str) -> Self {
        IRGenerator {
            program: IRProgram::new(source_file),
            temp_counter: 0,
            label_counter: 0,
            variables: HashMap::new(),
        }
    }

    /// Generates a new temporary variable name
    fn new_temp(&mut self) -> String {
        let temp = format!("t{}", self.temp_counter);
        self.temp_counter += 1;
        temp
    }

    /// Generates a new label name
    fn new_label(&mut self) -> String {
        let label = format!("L{}", self.label_counter);
        self.label_counter += 1;
        label
    }

    /// Generates IR for an AST node
    fn generate_node(&mut self, node: &AstNode) -> Result<String, KslError> {
        match node {
            AstNode::Expression(expr) => self.generate_expr(expr),
            AstNode::Statement(stmt) => self.generate_stmt(stmt),
            AstNode::Function(func) => self.generate_function(func),
            AstNode::VerifyBlock { conditions } => {
                for condition in conditions {
                    let cond_temp = match condition {
                        AstNode::Expression(e) => self.generate_expr(e),
                        _ => Err(KslError::type_error(
                            format!("Expected Expression node in verify block, found {:?}", condition),
                            SourcePosition::new(1, 1),
                            "E203".to_string()
                        ))
                    }?;
                    self.program.push(IRNode::Assert(cond_temp));
                }
                Ok("void".to_string())
            },
            AstNode::If { condition, then_branch, else_branch } => {
                let cond_temp = match condition.as_ref() {
                    AstNode::Expression(e) => self.generate_expr(e),
                    _ => Err(KslError::type_error(
                        format!("Expected Expression node in if condition, found {:?}", condition),
                        SourcePosition::new(1, 1),
                        "E203".to_string()
                    ))
                }?;
                let then_label = self.new_label();
                let else_label = self.new_label();
                let end_label = self.new_label();

                self.program.push(IRNode::Branch(
                    cond_temp,
                    then_label.clone(),
                    else_label.clone(),
                ));

                // Then branch
                self.program.push(IRNode::Label(then_label.clone()));
                self.generate_node(then_branch)?;
                self.program.push(IRNode::Jump(end_label.clone()));

                // Else branch
                self.program.push(IRNode::Label(else_label));
                if let Some(else_branch) = else_branch {
                    self.generate_node(else_branch)?;
                }

                // End
                self.program.push(IRNode::Label(end_label));
                Ok("void".to_string())
            },
            AstNode::Return { value } => {
                if let Some(expr) = value {
                    let temp = match expr.as_ref() {
                        AstNode::Expression(e) => self.generate_expr(e),
                        _ => Err(KslError::type_error(
                            "Expected Expression node in return value".to_string(),
                            SourcePosition::new(1, 1),
                            "E204".to_string()
                        ))
                    }?;
                    self.program.push(IRNode::Return(Some(temp)));
                } else {
                    self.program.push(IRNode::Return(None));
                }
                Ok("void".to_string())
            },
            _ => Err(KslError::type_error(
                format!("Unsupported AST node: {:?}", node),
                SourcePosition::new(1, 1),
                "E303".to_string()
            )),
        }
    }

    /// Generate IR for an expression
    fn generate_expr(&mut self, expr: &Expr) -> Result<String, KslError> {
        match expr {
            Expr::Literal(lit) => {
                let temp = self.new_temp();
                match lit {
                    Literal::Int(n) => {
                        self.program.push(IRNode::Assign(
                            temp.clone(),
                            n.to_string(),
                        ));
                    }
                    Literal::Float(f) => {
                        self.program.push(IRNode::Assign(
                            temp.clone(),
                            f.to_string(),
                        ));
                    }
                    Literal::Bool(b) => {
                        self.program.push(IRNode::Assign(
                            temp.clone(),
                            b.to_string(),
                        ));
                    }
                    Literal::Str(s) => {
                        self.program.push(IRNode::Assign(
                            temp.clone(),
                            format!("\"{}\"", s),
                        ));
                    }
                    _ => {
                        return Err(KslError::type_error(
                            format!("Unsupported literal: {:?}", lit),
                            SourcePosition::new(1, 1),
                            "E302".to_string()
                        ));
                    }
                }
                Ok(temp)
            },
            Expr::Identifier(name) => {
                let temp = self.new_temp();
                let var = self.variables.get(name).cloned().unwrap_or_else(|| name.clone());
                self.program.push(IRNode::Assign(temp.clone(), var));
                Ok(temp)
            },
            Expr::BinaryOp { left, op, right } => {
                let left_temp = self.generate_expr(left)?;
                let right_temp = self.generate_expr(right)?;
                let result_temp = self.new_temp();

                match op {
                    BinaryOperator::Add => {
                        self.program.push(IRNode::Add(
                            result_temp.clone(),
                            left_temp,
                            right_temp,
                        ));
                    }
                    BinaryOperator::Sub => {
                        self.program.push(IRNode::Sub(
                            result_temp.clone(),
                            left_temp,
                            right_temp,
                        ));
                    }
                    BinaryOperator::Mul => {
                        self.program.push(IRNode::Mul(
                            result_temp.clone(),
                            left_temp,
                            right_temp,
                        ));
                    }
                    _ => {
                        return Err(KslError::type_error(
                            format!("Unsupported binary operator: {:?}", op),
                            SourcePosition::new(1, 1),
                            "E301".to_string()
                        ));
                    }
                }
                Ok(result_temp)
            },
            _ => Err(KslError::type_error(
                format!("Unsupported expression: {:?}", expr),
                SourcePosition::new(1, 1),
                "E304".to_string()
            )),
        }
    }

    /// Generate IR for a statement
    fn generate_stmt(&mut self, stmt: &Stmt) -> Result<String, KslError> {
        match stmt {
            Stmt::Let { name, typ, value } => {
                let value_temp = self.generate_expr(value)?;
                self.variables.insert(name.clone(), value_temp.clone());
                Ok("void".to_string())
            },
            Stmt::Return(expr) => {
                let temp = self.generate_expr(expr)?;
                self.program.push(IRNode::Return(Some(temp)));
                Ok("void".to_string())
            },
            _ => Err(KslError::type_error(
                format!("Unsupported statement: {:?}", stmt),
                SourcePosition::new(1, 1),
                "E303".to_string()
            )),
        }
    }

    /// Generate IR for a function
    fn generate_function(&mut self, func: &Function) -> Result<String, KslError> {
        // Create function entry
        self.program.push(IRNode::Comment(format!("Function: {}", func.name.clone())));
        
        // Add parameters
        for (idx, (name, _)) in func.params.iter().enumerate() {
            let param_temp = format!("param{}", idx);
            self.variables.insert(name.clone(), param_temp);
        }
        
        // Generate body
        for stmt in &func.body {
            self.generate_stmt(stmt)?;
        }
        
        // If no explicit return, add void return
        if func.body.iter().all(|stmt| !matches!(stmt, Stmt::Return(_))) {
            self.program.push(IRNode::Return(None));
        }
        
        // End function
        self.program.push(IRNode::Comment(format!("End function: {}", func.name.clone())));
        
        Ok("void".to_string())
    }

    /// Generates IR for a list of AST nodes
    pub fn generate(&mut self, ast: &[AstNode]) -> Result<(), KslError> {
        for node in ast {
            self.generate_node(node)?;
        }
        Ok(())
    }

    /// Gets the generated IR program
    pub fn get_program(self) -> IRProgram {
        self.program
    }
}

/// Public API to generate IR from AST
pub fn generate_ir(ast: &[AstNode], source_file: &str) -> Result<IRProgram, KslError> {
    let mut generator = IRGenerator::new(source_file);
    generator.generate(ast)?;
    Ok(generator.get_program())
}

/// Public API to generate and export IR to JSON
pub fn generate_and_export_ir(ast: &[AstNode], source_file: &str, output_path: &str) -> Result<(), KslError> {
    let program = generate_ir(ast, source_file)?;
    let export = IRExport::new(program);
    export.export_json(output_path).map_err(|e| {
        KslError::type_error(
            format!("Failed to export IR: {}", e),
            SourcePosition::new(1, 1),
            "E304".to_string()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ksl_ast::Type;

    #[test]
    fn test_generate_binary_op() {
        let ast = vec![
            AstNode::BinaryOp {
                left: Box::new(AstNode::Literal(Literal::Int(1))),
                op: BinaryOperator::Add,
                right: Box::new(AstNode::Literal(Literal::Int(2))),
            },
        ];

        let program = generate_ir(&ast, "test.ksl").unwrap();
        assert!(program.instructions.len() > 0);
    }

    #[test]
    fn test_generate_verify_block() {
        let ast = vec![
            AstNode::VerifyBlock {
                conditions: vec![
                    AstNode::BinaryOp {
                        left: Box::new(AstNode::Identifier("x".to_string())),
                        op: BinaryOperator::GreaterEqual,
                        right: Box::new(AstNode::Literal(Literal::Int(0))),
                    },
                ],
            },
        ];

        let program = generate_ir(&ast, "test.ksl").unwrap();
        assert!(program.instructions.len() > 0);
    }

    #[test]
    fn test_ir_export() {
        let ast = vec![
            AstNode::BinaryOp {
                left: Box::new(AstNode::Literal(Literal::Int(1))),
                op: BinaryOperator::Add,
                right: Box::new(AstNode::Literal(Literal::Int(2))),
            },
        ];

        generate_and_export_ir(&ast, "test.ksl", "test.ir.json").unwrap();
        let imported = IRExport::import_json("test.ir.json").unwrap();
        assert!(imported.program.instructions.len() > 0);
    }
} 