// ksl_value.rs
// Defines the Value type for representing runtime values in KSL.

use crate::ksl_types::{Type, TypeError};
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_kapra_zkp::ZkProofType;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    U8(u8),
    U32(u32),
    U64(u64),
    Bool(bool),
    String(String),
    Array(Vec<Value>),
    Tuple(Vec<Value>),
    ZkProof(Vec<u8>),
    Signature(Vec<u8>),
    Void,
}

impl Value {
    pub fn get_type(&self) -> Type {
        match self {
            Value::U8(_) => Type::U8,
            Value::U32(_) => Type::U32,
            Value::U64(_) => Type::U64,
            Value::Bool(_) => Type::Bool,
            Value::String(_) => Type::String,
            Value::Array(_) => Type::Array(Box::new(Type::U8), 0), // Simplified
            Value::Tuple(_) => Type::Tuple(vec![]), // Simplified
            Value::ZkProof(_) => Type::ZkProof(ZkProofType::Generic),
            Value::Signature(_) => Type::Signature(crate::ksl_types::SignatureType::Ed25519),
            Value::Void => Type::Void,
        }
    }

    pub fn try_convert(&self, target_type: &Type) -> Result<Value, KslError> {
        // Simplified conversion logic
        if self.get_type() == *target_type {
            Ok(self.clone())
        } else {
            Err(KslError::type_error("Type conversion error".into(), SourcePosition::new(1, 1), "E016"))
        }
    }
} 