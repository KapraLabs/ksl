use crate::ksl_ast::{AstNode, Function, Type};
use crate::ksl_errors::{KslError, SourcePosition};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// Contract ABI representation
#[derive(Debug, Serialize, Deserialize)]
pub struct ContractABI {
    pub name: String,
    pub methods: Vec<MethodABI>,
    pub version: ContractVersion,
}

/// Method ABI representation
#[derive(Debug, Serialize, Deserialize)]
pub struct MethodABI {
    pub name: String,
    pub params: Vec<TypeABI>,
    pub return_type: Option<TypeABI>,
    pub is_public: bool,
}

/// Type ABI representation
#[derive(Debug, Serialize, Deserialize)]
pub struct TypeABI {
    pub name: String,
    pub is_array: bool,
    pub array_size: Option<usize>,
}

/// Contract version information
#[derive(Debug, Serialize, Deserialize)]
pub struct ContractVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub checksum: [u8; 32],
}

/// ABI generator for KSL contracts
pub struct ABIGenerator {
    contracts: HashMap<String, ContractABI>,
}

impl ABIGenerator {
    /// Creates a new ABI generator
    pub fn new() -> Self {
        ABIGenerator {
            contracts: HashMap::new(),
        }
    }

    /// Generates ABI for a contract from AST
    pub fn generate_contract_abi(&mut self, ast: &[AstNode], contract_name: &str) -> Result<ContractABI, KslError> {
        let mut methods = Vec::new();
        
        for node in ast {
            if let AstNode::Function(func) = node {
                if func.is_public {
                    methods.push(self.generate_method_abi(func)?);
                }
            }
        }

        let contract = ContractABI {
            name: contract_name.to_string(),
            methods,
            version: ContractVersion {
                major: 1,
                minor: 0,
                patch: 0,
                checksum: [0; 32], // TODO: Implement checksum generation
            },
        };

        self.contracts.insert(contract_name.to_string(), contract.clone());
        Ok(contract)
    }

    /// Generates ABI for a method
    fn generate_method_abi(&self, func: &Function) -> Result<MethodABI, KslError> {
        let params = func.params.iter()
            .map(|param| self.type_to_abi_type(&param.ty))
            .collect::<Result<Vec<_>, _>>()?;

        let return_type = func.return_type.as_ref()
            .map(|ty| self.type_to_abi_type(ty))
            .transpose()?;

        Ok(MethodABI {
            name: func.name.clone(),
            params,
            return_type,
            is_public: func.is_public,
        })
    }

    /// Converts KSL type to ABI type
    fn type_to_abi_type(&self, ty: &Type) -> Result<TypeABI, KslError> {
        match ty {
            Type::Array(elem_ty, size) => {
                let elem_abi = self.type_to_abi_type(elem_ty)?;
                Ok(TypeABI {
                    name: elem_abi.name,
                    is_array: true,
                    array_size: *size,
                })
            }
            Type::Primitive(name) => Ok(TypeABI {
                name: name.clone(),
                is_array: false,
                array_size: None,
            }),
            _ => Err(KslError::type_error(
                format!("Unsupported type for ABI: {:?}", ty),
                SourcePosition::new(1, 1),
            )),
        }
    }

    /// Writes ABI to file
    pub fn write_abi(&self, contract_name: &str, path: &PathBuf) -> Result<(), KslError> {
        let contract = self.contracts.get(contract_name).ok_or_else(|| {
            KslError::type_error(
                format!("Contract not found: {}", contract_name),
                SourcePosition::new(1, 1),
            )
        })?;

        let json = serde_json::to_string_pretty(contract).map_err(|e| {
            KslError::type_error(
                format!("Failed to serialize ABI: {}", e),
                SourcePosition::new(1, 1),
            )
        })?;

        fs::write(path, json).map_err(|e| {
            KslError::type_error(
                format!("Failed to write ABI file: {}", e),
                SourcePosition::new(1, 1),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ksl_ast::{Function, Parameter, Type};

    #[test]
    fn test_generate_contract_abi() {
        let mut generator = ABIGenerator::new();
        
        let func = Function {
            name: "transfer".to_string(),
            params: vec![
                Parameter {
                    name: "to".to_string(),
                    ty: Type::Primitive("address".to_string()),
                },
                Parameter {
                    name: "amount".to_string(),
                    ty: Type::Primitive("u64".to_string()),
                },
            ],
            return_type: Some(Type::Primitive("bool".to_string())),
            is_public: true,
            body: vec![],
        };

        let ast = vec![AstNode::Function(func)];
        let abi = generator.generate_contract_abi(&ast, "MyToken").unwrap();

        assert_eq!(abi.name, "MyToken");
        assert_eq!(abi.methods.len(), 1);
        assert_eq!(abi.methods[0].name, "transfer");
        assert_eq!(abi.methods[0].params.len(), 2);
        assert_eq!(abi.methods[0].params[0].name, "address");
        assert_eq!(abi.methods[0].params[1].name, "u64");
        assert_eq!(abi.methods[0].return_type.as_ref().unwrap().name, "bool");
    }
} 