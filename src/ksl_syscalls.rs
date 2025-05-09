use crate::kapra_vm::{KapraVM, RuntimeError, FixedArray, ContractMetadata};
use crate::ksl_kapra_crypto::FixedArray;
use crate::ksl_bytecode::{KapraInstruction, KapraOpCode, Operand};
use crate::ksl_types::Type;
use crate::ksl_types::TransactionContext;
use crate::ksl_types::TxAction;
use crate::ksl_bytecode::KapraBytecode;
use crate::ksl_value::Value;
use std::collections::HashMap;

/// Syscall for delegating authentication
/// @param delegatee The address to delegate authority to
/// @returns `Ok(())` if delegation succeeds, or `Err` with a `RuntimeError`
pub fn auth_delegate(vm: &mut KapraVM, delegatee: FixedArray<32>) -> Result<(), RuntimeError> {
    // Create AUTH instruction
    let instr = KapraInstruction::new(
        KapraOpCode::Auth,
        vec![Operand::Immediate(delegatee.0.to_vec())],
        Some(Type::Array(Box::new(Type::U8), 32)),
    );
    
    // Execute the instruction
    vm.execute_instruction(&instr, false)
}

/// Syscall for setting a gas sponsor
/// @param sponsor The address that will pay for gas
/// @param limit The maximum amount of gas the sponsor will cover
/// @returns `Ok(())` if sponsor is set successfully, or `Err` with a `RuntimeError`
pub fn set_sponsor(vm: &mut KapraVM, sponsor: FixedArray<32>, limit: u64) -> Result<(), RuntimeError> {
    let sender = vm.current_sender.ok_or_else(|| RuntimeError {
        message: "No current sender set".to_string(),
        pc: vm.pc,
    })?;

    let account = vm.get_smart_account_mut(&sender).ok_or_else(|| RuntimeError {
        message: format!("No smart account found for sender {:?}", sender),
        pc: vm.pc,
    })?;

    account.set_sponsor(sponsor, limit);
    Ok(())
}

/// Syscall for removing a gas sponsor
/// @returns `Ok(())` if sponsor is removed successfully, or `Err` with a `RuntimeError`
pub fn remove_sponsor(vm: &mut KapraVM) -> Result<(), RuntimeError> {
    let sender = vm.current_sender.ok_or_else(|| RuntimeError {
        message: "No current sender set".to_string(),
        pc: vm.pc,
    })?;

    let account = vm.get_smart_account_mut(&sender).ok_or_else(|| RuntimeError {
        message: format!("No smart account found for sender {:?}", sender),
        pc: vm.pc,
    })?;

    account.remove_sponsor();
    Ok(())
}

/// Executes a batch of actions atomically
pub fn batch_execute(
    vm: &mut KapraVM,
    actions: Vec<TxAction>,
    sponsor: Option<FixedArray<32>>,
    postconditions: Option<KapraBytecode>,
) -> Result<(), RuntimeError> {
    let current_sender = vm.tx_context.sender;
    
    // Set postconditions if provided
    if let Some(postcode) = postconditions {
        vm.set_postconditions(postcode);
    }

    let context = TransactionContext {
        sender: current_sender,
        actions,
        sponsor,
        gas_limit: 0, // Will be set per action
        tx_id: 0, // Will be auto-incremented
    };

    vm.run_transaction(context)
}

/// Deploys a new contract
pub fn deploy_contract(
    vm: &mut KapraVM,
    bytecode: KapraBytecode,
    changelog: String,
) -> Result<FixedArray<32>, RuntimeError> {
    let sender = vm.current_sender.ok_or_else(|| RuntimeError {
        message: "No current sender set".to_string(),
        pc: vm.pc,
    })?;

    vm.deploy_contract(bytecode, sender, changelog)
}

/// Upgrades an existing contract
pub fn upgrade_contract(
    vm: &mut KapraVM,
    contract_id: FixedArray<32>,
    new_bytecode: KapraBytecode,
    new_version: u32,
    changelog: String,
) -> Result<(), RuntimeError> {
    vm.upgrade_contract(contract_id, new_bytecode, new_version, changelog)
}

/// Gets contract metadata
pub fn get_contract_metadata(
    vm: &KapraVM,
    contract_id: FixedArray<32>,
) -> Result<ContractMetadata, RuntimeError> {
    vm.get_contract_metadata(contract_id)
}

/// Marks a contract as deprecated
pub fn deprecate_contract(
    vm: &mut KapraVM,
    contract_id: FixedArray<32>,
) -> Result<(), RuntimeError> {
    vm.deprecate_contract(contract_id)
}

/// Adds an upgrade guardian
pub fn add_upgrade_guardian(
    vm: &mut KapraVM,
    contract_id: FixedArray<32>,
    guardian: FixedArray<32>,
) -> Result<(), RuntimeError> {
    vm.add_upgrade_guardian(contract_id, guardian)
}

/// Removes an upgrade guardian
pub fn remove_upgrade_guardian(
    vm: &mut KapraVM,
    contract_id: FixedArray<32>,
    guardian: FixedArray<32>,
) -> Result<(), RuntimeError> {
    vm.remove_upgrade_guardian(contract_id, guardian)
}

/// Dispatch a plugin syscall with capability checking
pub fn dispatch_plugin_syscall(vm: &KapraVM, namespace: &str, fn_name: &str, args: Vec<Value>) -> Result<Value, RuntimeError> {
    // Check capabilities based on namespace
    let required_capability = match namespace {
        "ksl_ai" => "ai",
        "ksl_iot" => "iot",
        "ksl_game" => "game",
        "ksl_finance" => "finance",
        _ => return Err(RuntimeError::new(format!("Unknown plugin namespace: {}", namespace))),
    };

    // Verify capability is available
    if !vm.has_capability(required_capability) {
        return Err(RuntimeError::new(format!(
            "Missing required capability: {}. Add 'requires {{ {} }}' to function declaration.",
            required_capability, required_capability
        )));
    }

    // Dispatch to appropriate handler
    match (namespace, fn_name) {
        // AI Plugin
        ("ksl_ai", "infer") => ai::infer(args),
        ("ksl_ai", "train") => ai::train(args),
        ("ksl_ai", "quantize") => ai::quantize(args),
        ("ksl_ai", "get_model_info") => ai::get_model_info(args),

        // IoT Plugin
        ("ksl_iot", "read_sensor") => iot::read_sensor(args),
        ("ksl_iot", "ping") => iot::ping(args),
        ("ksl_iot", "set_actuator") => iot::set_actuator(args),
        ("ksl_iot", "get_device_status") => iot::get_device_status(args),

        // Game Plugin
        ("ksl_game", "spawn_entity") => game::spawn_entity(args),
        ("ksl_game", "move_entity") => game::move_entity(args),
        ("ksl_game", "apply_force") => game::apply_force(args),
        ("ksl_game", "get_entity_state") => game::get_entity_state(args),

        // Finance Plugin
        ("ksl_finance", "price_feed") => finance::price_feed(args),
        ("ksl_finance", "risk_eval") => finance::risk_eval(args),
        ("ksl_finance", "option_price") => finance::option_price(args),
        ("ksl_finance", "get_market_data") => finance::get_market_data(args),

        _ => Err(RuntimeError::new(format!("Plugin syscall {}.{} not found", namespace, fn_name))),
    }
}

/// AI plugin syscalls
mod ai {
    use super::*;

    pub fn infer(args: Vec<Value>) -> Result<Value, RuntimeError> {
        if args.len() != 2 {
            return Err(RuntimeError::new("ai::infer requires 2 arguments".to_string()));
        }

        let model = match &args[0] {
            Value::String(s) => s,
            _ => return Err(RuntimeError::new("First argument must be a string".to_string())),
        };

        let input = match &args[1] {
            Value::Array(a) => a,
            _ => return Err(RuntimeError::new("Second argument must be an array".to_string())),
        };

        // TODO: Implement actual inference
        // For now, return a dummy value
        Ok(Value::Float(0.93))
    }

    pub fn train(args: Vec<Value>) -> Result<Value, RuntimeError> {
        if args.len() != 2 {
            return Err(RuntimeError::new("ai::train requires 2 arguments".to_string()));
        }

        let model = match &args[0] {
            Value::String(s) => s,
            _ => return Err(RuntimeError::new("First argument must be a string".to_string())),
        };

        let data = match &args[1] {
            Value::Array(a) => a,
            _ => return Err(RuntimeError::new("Second argument must be an array".to_string())),
        };

        // TODO: Implement actual training
        Ok(Value::Bool(true))
    }

    pub fn quantize(args: Vec<Value>) -> Result<Value, RuntimeError> {
        if args.len() != 2 {
            return Err(RuntimeError::new("ai::quantize requires 2 arguments".to_string()));
        }

        let model = match &args[0] {
            Value::String(s) => s,
            _ => return Err(RuntimeError::new("First argument must be a string".to_string())),
        };

        let bits = match &args[1] {
            Value::U8(b) => b,
            _ => return Err(RuntimeError::new("Second argument must be a u8".to_string())),
        };

        // TODO: Implement actual quantization
        Ok(Value::Bool(true))
    }

    pub fn get_model_info(args: Vec<Value>) -> Result<Value, RuntimeError> {
        if args.len() != 1 {
            return Err(RuntimeError::new("ai::get_model_info requires 1 argument".to_string()));
        }

        let model = match &args[0] {
            Value::String(s) => s,
            _ => return Err(RuntimeError::new("First argument must be a string".to_string())),
        };

        // TODO: Implement actual model info retrieval
        let mut info = HashMap::new();
        info.insert("name".to_string(), Value::String(model.clone()));
        info.insert("type".to_string(), Value::String("resnet".to_string()));
        info.insert("size".to_string(), Value::String("10MB".to_string()));
        
        Ok(Value::Map(info))
    }
}

/// IoT plugin syscalls
mod iot {
    use super::*;

    pub fn read_sensor(args: Vec<Value>) -> Result<Value, RuntimeError> {
        if args.len() != 2 {
            return Err(RuntimeError::new("iot::read_sensor requires 2 arguments".to_string()));
        }

        let device_id = match &args[0] {
            Value::String(s) => s,
            _ => return Err(RuntimeError::new("First argument must be a string".to_string())),
        };

        let sensor_type = match &args[1] {
            Value::String(s) => s,
            _ => return Err(RuntimeError::new("Second argument must be a string".to_string())),
        };

        // TODO: Implement actual sensor reading
        Ok(Value::Float(25.5))
    }

    pub fn ping(args: Vec<Value>) -> Result<Value, RuntimeError> {
        if args.len() != 1 {
            return Err(RuntimeError::new("iot::ping requires 1 argument".to_string()));
        }

        let device_id = match &args[0] {
            Value::String(s) => s,
            _ => return Err(RuntimeError::new("First argument must be a string".to_string())),
        };

        // TODO: Implement actual device ping
        Ok(Value::Bool(true))
    }

    pub fn set_actuator(args: Vec<Value>) -> Result<Value, RuntimeError> {
        if args.len() != 3 {
            return Err(RuntimeError::new("iot::set_actuator requires 3 arguments".to_string()));
        }

        let device_id = match &args[0] {
            Value::String(s) => s,
            _ => return Err(RuntimeError::new("First argument must be a string".to_string())),
        };

        let actuator_type = match &args[1] {
            Value::String(s) => s,
            _ => return Err(RuntimeError::new("Second argument must be a string".to_string())),
        };

        let value = match &args[2] {
            Value::Float(f) => f,
            _ => return Err(RuntimeError::new("Third argument must be a float".to_string())),
        };

        // TODO: Implement actual actuator control
        Ok(Value::Bool(true))
    }

    pub fn get_device_status(args: Vec<Value>) -> Result<Value, RuntimeError> {
        if args.len() != 1 {
            return Err(RuntimeError::new("iot::get_device_status requires 1 argument".to_string()));
        }

        let device_id = match &args[0] {
            Value::String(s) => s,
            _ => return Err(RuntimeError::new("First argument must be a string".to_string())),
        };

        // TODO: Implement actual status retrieval
        let mut status = HashMap::new();
        status.insert("id".to_string(), Value::String(device_id.clone()));
        status.insert("status".to_string(), Value::String("online".to_string()));
        status.insert("battery".to_string(), Value::String("85%".to_string()));

        Ok(Value::Map(status))
    }
}

/// Game plugin syscalls
mod game {
    use super::*;

    pub fn spawn_entity(args: Vec<Value>) -> Result<Value, RuntimeError> {
        if args.len() != 2 {
            return Err(RuntimeError::new("game::spawn_entity requires 2 arguments".to_string()));
        }

        let entity_type = match &args[0] {
            Value::String(s) => s,
            _ => return Err(RuntimeError::new("First argument must be a string".to_string())),
        };

        let properties = match &args[1] {
            Value::Map(m) => m,
            _ => return Err(RuntimeError::new("Second argument must be a map".to_string())),
        };

        // TODO: Implement actual entity spawning
        Ok(Value::String("entity_123".to_string()))
    }

    pub fn move_entity(args: Vec<Value>) -> Result<Value, RuntimeError> {
        if args.len() != 2 {
            return Err(RuntimeError::new("game::move_entity requires 2 arguments".to_string()));
        }

        let entity_id = match &args[0] {
            Value::String(s) => s,
            _ => return Err(RuntimeError::new("First argument must be a string".to_string())),
        };

        let position = match &args[1] {
            Value::Array(a) => a,
            _ => return Err(RuntimeError::new("Second argument must be an array".to_string())),
        };

        if position.len() != 3 {
            return Err(RuntimeError::new("Position must be an array of 3 floats".to_string()));
        }

        // TODO: Implement actual entity movement
        Ok(Value::Bool(true))
    }

    pub fn apply_force(args: Vec<Value>) -> Result<Value, RuntimeError> {
        if args.len() != 2 {
            return Err(RuntimeError::new("game::apply_force requires 2 arguments".to_string()));
        }

        let entity_id = match &args[0] {
            Value::String(s) => s,
            _ => return Err(RuntimeError::new("First argument must be a string".to_string())),
        };

        let force = match &args[1] {
            Value::Array(a) => a,
            _ => return Err(RuntimeError::new("Second argument must be an array".to_string())),
        };

        if force.len() != 3 {
            return Err(RuntimeError::new("Force must be an array of 3 floats".to_string()));
        }

        // TODO: Implement actual force application
        Ok(Value::Bool(true))
    }

    pub fn get_entity_state(args: Vec<Value>) -> Result<Value, RuntimeError> {
        if args.len() != 1 {
            return Err(RuntimeError::new("game::get_entity_state requires 1 argument".to_string()));
        }

        let entity_id = match &args[0] {
            Value::String(s) => s,
            _ => return Err(RuntimeError::new("First argument must be a string".to_string())),
        };

        // TODO: Implement actual state retrieval
        let mut state = HashMap::new();
        state.insert("id".to_string(), Value::String(entity_id.clone()));
        state.insert("position".to_string(), Value::String("[0,0,0]".to_string()));
        state.insert("health".to_string(), Value::String("100".to_string()));

        Ok(Value::Map(state))
    }
}

/// Finance plugin syscalls
mod finance {
    use super::*;

    pub fn price_feed(args: Vec<Value>) -> Result<Value, RuntimeError> {
        if args.len() != 2 {
            return Err(RuntimeError::new("finance::price_feed requires 2 arguments".to_string()));
        }

        let asset_pair = match &args[0] {
            Value::String(s) => s,
            _ => return Err(RuntimeError::new("First argument must be a string".to_string())),
        };

        let source = match &args[1] {
            Value::String(s) => s,
            _ => return Err(RuntimeError::new("Second argument must be a string".to_string())),
        };

        // TODO: Implement actual price feed
        Ok(Value::Float(1850.75))
    }

    pub fn risk_eval(args: Vec<Value>) -> Result<Value, RuntimeError> {
        if args.len() != 1 {
            return Err(RuntimeError::new("finance::risk_eval requires 1 argument".to_string()));
        }

        let portfolio = match &args[0] {
            Value::Map(m) => m,
            _ => return Err(RuntimeError::new("First argument must be a map".to_string())),
        };

        // TODO: Implement actual risk evaluation
        let mut metrics = HashMap::new();
        metrics.insert("var".to_string(), Value::Float(12500.0));
        metrics.insert("sharpe".to_string(), Value::Float(1.8));
        metrics.insert("beta".to_string(), Value::Float(1.1));

        Ok(Value::Map(metrics))
    }

    pub fn option_price(args: Vec<Value>) -> Result<Value, RuntimeError> {
        if args.len() != 5 {
            return Err(RuntimeError::new("finance::option_price requires 5 arguments".to_string()));
        }

        let option_type = match &args[0] {
            Value::String(s) => s,
            _ => return Err(RuntimeError::new("First argument must be a string".to_string())),
        };

        let strike = match &args[1] {
            Value::Float(f) => f,
            _ => return Err(RuntimeError::new("Second argument must be a float".to_string())),
        };

        let spot = match &args[2] {
            Value::Float(f) => f,
            _ => return Err(RuntimeError::new("Third argument must be a float".to_string())),
        };

        let vol = match &args[3] {
            Value::Float(f) => f,
            _ => return Err(RuntimeError::new("Fourth argument must be a float".to_string())),
        };

        let time = match &args[4] {
            Value::Float(f) => f,
            _ => return Err(RuntimeError::new("Fifth argument must be a float".to_string())),
        };

        // TODO: Implement actual option pricing
        Ok(Value::Float(125.50))
    }

    pub fn get_market_data(args: Vec<Value>) -> Result<Value, RuntimeError> {
        if args.len() != 3 {
            return Err(RuntimeError::new("finance::get_market_data requires 3 arguments".to_string()));
        }

        let asset = match &args[0] {
            Value::String(s) => s,
            _ => return Err(RuntimeError::new("First argument must be a string".to_string())),
        };

        let metric = match &args[1] {
            Value::String(s) => s,
            _ => return Err(RuntimeError::new("Second argument must be a string".to_string())),
        };

        let timestamp = match &args[2] {
            Value::U64(t) => t,
            _ => return Err(RuntimeError::new("Third argument must be a u64".to_string())),
        };

        // TODO: Implement actual market data retrieval
        let data = vec![
            Value::Tuple(vec![Value::U64(*timestamp), Value::Float(100.0)]),
            Value::Tuple(vec![Value::U64(*timestamp + 3600), Value::Float(101.2)]),
            Value::Tuple(vec![Value::U64(*timestamp + 7200), Value::Float(99.8)]),
        ];

        Ok(Value::Array(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockVM {
        capabilities: Vec<String>,
    }

    impl MockVM {
        fn new(capabilities: Vec<String>) -> Self {
            Self { capabilities }
        }

        fn has_capability(&self, cap: &str) -> bool {
            self.capabilities.contains(&cap.to_string())
        }
    }

    #[test]
    fn test_ai_plugin() {
        let vm = MockVM::new(vec!["ai".to_string()]);
        
        // Test infer
        let args = vec![
            Value::String("resnet18".to_string()),
            Value::Array(vec![Value::U8(1), Value::U8(2), Value::U8(3)]),
        ];
        let result = dispatch_plugin_syscall(&vm, "ksl_ai", "infer", args);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), Value::Float(_)));

        // Test train
        let args = vec![
            Value::String("resnet18".to_string()),
            Value::Array(vec![Value::Tuple(vec![Value::U64(1), Value::Float(0.95)])]),
        ];
        let result = dispatch_plugin_syscall(&vm, "ksl_ai", "train", args);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), Value::Bool(true)));
    }

    #[test]
    fn test_iot_plugin() {
        let vm = MockVM::new(vec!["iot".to_string()]);
        
        // Test read_sensor
        let args = vec![
            Value::String("device1".to_string()),
            Value::String("temperature".to_string()),
        ];
        let result = dispatch_plugin_syscall(&vm, "ksl_iot", "read_sensor", args);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), Value::Float(_)));

        // Test ping
        let args = vec![Value::String("device1".to_string())];
        let result = dispatch_plugin_syscall(&vm, "ksl_iot", "ping", args);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), Value::Bool(true)));
    }

    #[test]
    fn test_game_plugin() {
        let vm = MockVM::new(vec!["game".to_string()]);
        
        // Test spawn_entity
        let mut properties = HashMap::new();
        properties.insert("health".to_string(), Value::String("100".to_string()));
        let args = vec![
            Value::String("player".to_string()),
            Value::Map(properties),
        ];
        let result = dispatch_plugin_syscall(&vm, "ksl_game", "spawn_entity", args);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), Value::String(_)));

        // Test move_entity
        let args = vec![
            Value::String("entity_123".to_string()),
            Value::Array(vec![Value::Float(1.0), Value::Float(2.0), Value::Float(3.0)]),
        ];
        let result = dispatch_plugin_syscall(&vm, "ksl_game", "move_entity", args);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), Value::Bool(true)));
    }

    #[test]
    fn test_finance_plugin() {
        let vm = MockVM::new(vec!["finance".to_string()]);
        
        // Test price_feed
        let args = vec![
            Value::String("ETH/USD".to_string()),
            Value::String("chainlink".to_string()),
        ];
        let result = dispatch_plugin_syscall(&vm, "ksl_finance", "price_feed", args);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), Value::Float(_)));

        // Test risk_eval
        let mut portfolio = HashMap::new();
        portfolio.insert("ETH".to_string(), Value::Float(10.0));
        portfolio.insert("BTC".to_string(), Value::Float(1.0));
        let args = vec![Value::Map(portfolio)];
        let result = dispatch_plugin_syscall(&vm, "ksl_finance", "risk_eval", args);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), Value::Map(_)));
    }

    #[test]
    fn test_missing_capability() {
        let vm = MockVM::new(vec!["ai".to_string()]);
        
        // Try to use IoT plugin without capability
        let args = vec![Value::String("device1".to_string())];
        let result = dispatch_plugin_syscall(&vm, "ksl_iot", "ping", args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Missing required capability: iot"));
    }
} 