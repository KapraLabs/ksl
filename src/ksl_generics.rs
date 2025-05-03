// ksl_generics.rs
// Support for generic types and functions in KSL

/// Represents a generic type parameter (e.g., T, U).
#[derive(Debug, Clone)]
pub struct TypeParam {
    name: String,
    // Add constraints if needed (e.g., T must be fixed-size)
}

impl TypeParam {
    pub fn new(name: &str) -> Self {
        TypeParam {
            name: name.to_string(),
        }
    }
}

/// Represents a generic type or function definition.
#[derive(Debug, Clone)]
pub struct GenericDef {
    params: Vec<TypeParam>, // List of type parameters (e.g., T, U)
    concrete_types: Vec<Type>, // Concrete types after monomorphization
}

impl GenericDef {
    pub fn new(params: Vec<TypeParam>) -> Self {
        GenericDef {
            params,
            concrete_types: vec![],
        }
    }

    /// Monomorphize the generic definition by substituting type parameters
    /// with concrete types (e.g., T -> u32).
    pub fn monomorphize(&mut self, substitutions: Vec<Type>) -> Result<(), String> {
        if substitutions.len() != self.params.len() {
            return Err(format!(
                "Expected {} type arguments, got {}",
                self.params.len(),
                substitutions.len()
            ));
        }
        self.concrete_types = substitutions;
        Ok(())
    }
}

/// Extend the AST to support generics (used by ksl_parser.rs).
#[derive(Debug, Clone)]
pub enum AstNode {
    // Existing node types...
    GenericFunction {
        name: String,
        type_params: GenericDef,
        args: Vec<(String, Type)>,
        return_type: Type,
        body: Vec<AstNode>,
    },
    GenericStruct {
        name: String,
        type_params: GenericDef,
        fields: Vec<(String, Type)>,
    },
    // Other node types...
}

/// Integrate with the type checker (used by ksl_checker.rs).
pub struct GenericTypeChecker;

impl GenericTypeChecker {
    /// Validate a generic function or struct, ensuring type parameters are used correctly.
    pub fn check_generic_node(&self, node: &AstNode) -> Result<(), String> {
        match node {
            AstNode::GenericFunction {
                type_params,
                args,
                return_type,
                body,
                ..
            } => {
                // Ensure all type parameters are used and substituted correctly
                for param in &type_params.params {
                    // Check if param is used in args or return_type
                    // (Placeholder for deeper type checking logic)
                }
                // Recursively check the body
                for node in body {
                    self.check_generic_node(node)?;
                }
                Ok(())
            }
            AstNode::GenericStruct {
                type_params,
                fields,
                ..
            } => {
                // Ensure all fields use valid types (fixed-size, no dynamic types)
                for (_, field_type) in fields {
                    if !self.is_fixed_size(field_type) {
                        return Err(format!("Field type {:?} must be fixed-size", field_type));
                    }
                }
                Ok(())
            }
            _ => Ok(()), // Other node types handled elsewhere
        }
    }

    /// Check if a type is fixed-size (enforce KSL's constraints).
    fn is_fixed_size(&self, ty: &Type) -> bool {
        match ty {
            Type::U8 | Type::U16 | Type::U32 | Type::U64 | Type::Bool => true,
            Type::Array(inner, size) => *size > 0 && self.is_fixed_size(inner),
            Type::Generic(param) => false, // Must be monomorphized before this check
            _ => false, // Disallow dynamic types
        }
    }
}

/// Integrate with the compiler (used by ksl_compiler.rs).
pub struct GenericCompiler;

impl GenericCompiler {
    /// Compile a generic node by monomorphizing it.
    pub fn compile_generic_node(&self, node: &AstNode, generics: &mut GenericDef) -> Result<Bytecode, String> {
        match node {
            AstNode::GenericFunction {
                args,
                return_type,
                body,
                ..
            } => {
                // Monomorphize: Substitute type parameters with concrete types
                let substitutions = generics.concrete_types.clone();
                if substitutions.is_empty() {
                    return Err("Generic function must be monomorphized".to_string());
                }

                // Compile the function body with substituted types
                let mut bytecode = Bytecode::new();
                for node in body {
                    let node_bytecode = self.compile_generic_node(node, generics)?;
                    bytecode.extend(node_bytecode);
                }
                Ok(bytecode)
            }
            AstNode::GenericStruct { fields, .. } => {
                // Compile the struct definition (layout fields in memory)
                let mut bytecode = Bytecode::new();
                for (_, field_type) in fields {
                    let concrete_type = self.substitute_type(field_type, &generics.concrete_types)?;
                    bytecode.push_field(concrete_type);
                }
                Ok(bytecode)
            }
            _ => Ok(Bytecode::new()), // Other node types handled elsewhere
        }
    }

    /// Substitute a generic type with a concrete type.
    fn substitute_type(&self, ty: &Type, substitutions: &[Type]) -> Result<Type, String> {
        match ty {
            Type::Generic(param) => {
                // Find the corresponding substitution (simplified)
                Ok(substitutions[0].clone()) // Placeholder for proper lookup
            }
            Type::Array(inner, size) => {
                let new_inner = self.substitute_type(inner, substitutions)?;
                Ok(Type::Array(Box::new(new_inner), *size))
            }
            _ => Ok(ty.clone()),
        }
    }
}

// Placeholder types (to be aligned with ksl_types.rs and ksl_bytecode.rs).
#[derive(Debug, Clone)]
pub enum Type {
    U8,
    U16,
    U32,
    U64,
    Bool,
    Array(Box<Type>, usize),
    Generic(String), // Placeholder for a type parameter (e.g., T)
}

#[derive(Debug, Clone)]
pub struct Bytecode {
    instructions: Vec<u8>, // Simplified representation
}

impl Bytecode {
    pub fn new() -> Self {
        Bytecode {
            instructions: vec![],
        }
    }

    pub fn extend(&mut self, other: Bytecode) {
        self.instructions.extend(other.instructions);
    }

    pub fn push_field(&mut self, ty: Type) {
        // Placeholder for field layout in bytecode
        self.instructions.push(0); // Dummy instruction
    }
}