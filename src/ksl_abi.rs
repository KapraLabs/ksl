use crate::ksl_ast::{AstNode, Function};
use crate::ksl_types::Type;
use crate::ksl_errors::{KslError, SourcePosition};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use crate::ksl_ir::KSLIR;
use serde_json::{Value, Map};
use std::fs::File;
use std::io::Write;
use std::path::Path;

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

/// ABI export format for KSL contracts
#[derive(Debug, Clone)]
pub struct KSLABI {
    pub contract_name: String,
    pub version: u32,
    pub bytecode_hash: String,
    pub functions: Vec<FunctionABI>,
    pub events: Vec<EventABI>,
    pub errors: Vec<ErrorABI>,
    pub structs: Vec<StructABI>,
    pub enums: Vec<EnumABI>,
}

/// Function ABI representation
#[derive(Debug, Clone)]
pub struct FunctionABI {
    pub name: String,
    pub inputs: Vec<ParamABI>,
    pub outputs: Vec<ParamABI>,
    pub state_mutability: StateMutability,
    pub gas_estimate: u64,
    pub doc: Option<String>,
}

/// Event ABI representation
#[derive(Debug, Clone)]
pub struct EventABI {
    pub name: String,
    pub inputs: Vec<ParamABI>,
    pub anonymous: bool,
    pub doc: Option<String>,
}

/// Error ABI representation
#[derive(Debug, Clone)]
pub struct ErrorABI {
    pub name: String,
    pub inputs: Vec<ParamABI>,
    pub doc: Option<String>,
}

/// Struct ABI representation
#[derive(Debug, Clone)]
pub struct StructABI {
    pub name: String,
    pub fields: Vec<ParamABI>,
    pub doc: Option<String>,
}

/// Enum ABI representation
#[derive(Debug, Clone)]
pub struct EnumABI {
    pub name: String,
    pub variants: Vec<String>,
    pub doc: Option<String>,
}

/// Parameter ABI representation
#[derive(Debug, Clone)]
pub struct ParamABI {
    pub name: String,
    pub type_: String,
    pub indexed: bool,
    pub doc: Option<String>,
}

/// State mutability for functions
#[derive(Debug, Clone, PartialEq)]
pub enum StateMutability {
    Pure,
    View,
    NonPayable,
    Payable,
}

impl KSLABI {
    /// Creates a new ABI from an IR
    pub fn from_ir(ir: &KSLIR) -> Self {
        let mut abi = Self {
            contract_name: ir.contract_name.clone(),
            version: ir.version,
            bytecode_hash: hex::encode(ir.bytecode_hash.0),
            functions: Vec::new(),
            events: Vec::new(),
            errors: Vec::new(),
            structs: Vec::new(),
            enums: Vec::new(),
        };

        // Convert functions
        for func in &ir.entrypoints {
            let mut inputs = Vec::new();
            for arg in &func.args {
                inputs.push(ParamABI {
                    name: arg.name.clone(),
                    type_: arg.name.clone(),
                    indexed: false,
                    doc: None,
                });
            }

            let mut outputs = Vec::new();
            if let Some(ret) = &func.return_type {
                outputs.push(ParamABI {
                    name: "return".to_string(),
                    type_: ret.name.clone(),
                    indexed: false,
                    doc: None,
                });
            }

            let state_mutability = if func.modifiers.contains(&crate::ksl_ir::FunctionModifier::Pure) {
                StateMutability::Pure
            } else if func.modifiers.contains(&crate::ksl_ir::FunctionModifier::View) {
                StateMutability::View
            } else if func.modifiers.contains(&crate::ksl_ir::FunctionModifier::Payable) {
                StateMutability::Payable
            } else {
                StateMutability::NonPayable
            };

            abi.functions.push(FunctionABI {
                name: func.name.clone(),
                inputs,
                outputs,
                state_mutability,
                gas_estimate: func.gas_estimate,
                doc: func.doc.clone(),
            });
        }

        abi
    }

    /// Converts the ABI to a JSON value
    pub fn to_json(&self) -> Value {
        let mut map = Map::new();
        
        map.insert("name".to_string(), Value::String(self.contract_name.clone()));
        map.insert("version".to_string(), Value::Number(serde_json::Number::from(self.version)));
        map.insert("bytecodeHash".to_string(), Value::String(self.bytecode_hash.clone()));

        // Convert functions
        let functions: Vec<Value> = self.functions.iter().map(|f| {
            let mut func = Map::new();
            func.insert("name".to_string(), Value::String(f.name.clone()));
            func.insert("inputs".to_string(), Value::Array(
                f.inputs.iter().map(|input| {
                    let mut param = Map::new();
                    param.insert("name".to_string(), Value::String(input.name.clone()));
                    param.insert("type".to_string(), Value::String(input.type_.clone()));
                    param.insert("indexed".to_string(), Value::Bool(input.indexed));
                    if let Some(doc) = &input.doc {
                        param.insert("doc".to_string(), Value::String(doc.clone()));
                    }
                    Value::Object(param)
                }).collect()
            ));
            func.insert("outputs".to_string(), Value::Array(
                f.outputs.iter().map(|output| {
                    let mut param = Map::new();
                    param.insert("name".to_string(), Value::String(output.name.clone()));
                    param.insert("type".to_string(), Value::String(output.type_.clone()));
                    param.insert("indexed".to_string(), Value::Bool(output.indexed));
                    if let Some(doc) = &output.doc {
                        param.insert("doc".to_string(), Value::String(doc.clone()));
                    }
                    Value::Object(param)
                }).collect()
            ));
            func.insert("stateMutability".to_string(), Value::String(
                match f.state_mutability {
                    StateMutability::Pure => "pure",
                    StateMutability::View => "view",
                    StateMutability::NonPayable => "nonpayable",
                    StateMutability::Payable => "payable",
                }.to_string()
            ));
            func.insert("gasEstimate".to_string(), Value::Number(serde_json::Number::from(f.gas_estimate)));
            if let Some(doc) = &f.doc {
                func.insert("doc".to_string(), Value::String(doc.clone()));
            }
            Value::Object(func)
        }).collect();
        map.insert("functions".to_string(), Value::Array(functions));

        // Convert events
        let events: Vec<Value> = self.events.iter().map(|e| {
            let mut event = Map::new();
            event.insert("name".to_string(), Value::String(e.name.clone()));
            event.insert("inputs".to_string(), Value::Array(
                e.inputs.iter().map(|input| {
                    let mut param = Map::new();
                    param.insert("name".to_string(), Value::String(input.name.clone()));
                    param.insert("type".to_string(), Value::String(input.type_.clone()));
                    param.insert("indexed".to_string(), Value::Bool(input.indexed));
                    if let Some(doc) = &input.doc {
                        param.insert("doc".to_string(), Value::String(doc.clone()));
                    }
                    Value::Object(param)
                }).collect()
            ));
            event.insert("anonymous".to_string(), Value::Bool(e.anonymous));
            if let Some(doc) = &e.doc {
                event.insert("doc".to_string(), Value::String(doc.clone()));
            }
            Value::Object(event)
        }).collect();
        map.insert("events".to_string(), Value::Array(events));

        // Convert errors
        let errors: Vec<Value> = self.errors.iter().map(|e| {
            let mut error = Map::new();
            error.insert("name".to_string(), Value::String(e.name.clone()));
            error.insert("inputs".to_string(), Value::Array(
                e.inputs.iter().map(|input| {
                    let mut param = Map::new();
                    param.insert("name".to_string(), Value::String(input.name.clone()));
                    param.insert("type".to_string(), Value::String(input.type_.clone()));
                    param.insert("indexed".to_string(), Value::Bool(input.indexed));
                    if let Some(doc) = &input.doc {
                        param.insert("doc".to_string(), Value::String(doc.clone()));
                    }
                    Value::Object(param)
                }).collect()
            ));
            if let Some(doc) = &e.doc {
                error.insert("doc".to_string(), Value::String(doc.clone()));
            }
            Value::Object(error)
        }).collect();
        map.insert("errors".to_string(), Value::Array(errors));

        // Convert structs
        let structs: Vec<Value> = self.structs.iter().map(|s| {
            let mut struct_ = Map::new();
            struct_.insert("name".to_string(), Value::String(s.name.clone()));
            struct_.insert("fields".to_string(), Value::Array(
                s.fields.iter().map(|field| {
                    let mut param = Map::new();
                    param.insert("name".to_string(), Value::String(field.name.clone()));
                    param.insert("type".to_string(), Value::String(field.type_.clone()));
                    param.insert("indexed".to_string(), Value::Bool(field.indexed));
                    if let Some(doc) = &field.doc {
                        param.insert("doc".to_string(), Value::String(doc.clone()));
                    }
                    Value::Object(param)
                }).collect()
            ));
            if let Some(doc) = &s.doc {
                struct_.insert("doc".to_string(), Value::String(doc.clone()));
            }
            Value::Object(struct_)
        }).collect();
        map.insert("structs".to_string(), Value::Array(structs));

        // Convert enums
        let enums: Vec<Value> = self.enums.iter().map(|e| {
            let mut enum_ = Map::new();
            enum_.insert("name".to_string(), Value::String(e.name.clone()));
            enum_.insert("variants".to_string(), Value::Array(
                e.variants.iter().map(|v| Value::String(v.clone())).collect()
            ));
            if let Some(doc) = &e.doc {
                enum_.insert("doc".to_string(), Value::String(doc.clone()));
            }
            Value::Object(enum_)
        }).collect();
        map.insert("enums".to_string(), Value::Array(enums));

        Value::Object(map)
    }

    /// Exports the ABI to a JSON file
    pub fn export_to_file(&self, path: &Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(&self.to_json())?;
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
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