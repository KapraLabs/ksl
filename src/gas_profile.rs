// gas_profile.rs
// Defines gas costs for KapraVM operations.

use crate::ksl_bytecode::KapraOpCode;

/// Returns the gas cost for a given opcode.
/// @param opcode The opcode to get gas cost for.
/// @returns The gas cost in units.
pub fn gas_cost(opcode: &KapraOpCode) -> u64 {
    match opcode {
        // Core operations - low cost
        KapraOpCode::Mov => 2,
        KapraOpCode::Add => 3,
        KapraOpCode::Sub => 3,
        KapraOpCode::Mul => 5,
        KapraOpCode::Halt => 0,
        KapraOpCode::Fail => 0,
        KapraOpCode::Assert => 2,

        // Control flow - medium cost
        KapraOpCode::Jump => 8,
        KapraOpCode::Call => 10,
        KapraOpCode::Return => 5,

        // Crypto operations - high cost
        KapraOpCode::Sha3 => 50,
        KapraOpCode::Sha3_512 => 100,
        KapraOpCode::Kaprekar => 30,
        KapraOpCode::BlsVerify => 200,
        KapraOpCode::DilithiumVerify => 300,
        KapraOpCode::MerkleVerify => 150,

        // Async operations - medium cost
        KapraOpCode::AsyncCall => 20,

        // Networking operations - high cost
        KapraOpCode::TcpConnect => 100,
        KapraOpCode::UdpSend => 80,
        KapraOpCode::HttpPost => 120,
        KapraOpCode::HttpGet => 100,

        // I/O operations - low cost
        KapraOpCode::Print => 5,
        KapraOpCode::DeviceSensor => 10,

        // Math operations - medium cost
        KapraOpCode::Sin => 15,
        KapraOpCode::Cos => 15,
        KapraOpCode::Sqrt => 20,
        KapraOpCode::MatrixMul => 50,
        KapraOpCode::TensorReduce => 40,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gas_costs() {
        // Test core operations
        assert_eq!(gas_cost(&KapraOpCode::Mov), 2);
        assert_eq!(gas_cost(&KapraOpCode::Add), 3);
        assert_eq!(gas_cost(&KapraOpCode::Sub), 3);
        assert_eq!(gas_cost(&KapraOpCode::Mul), 5);

        // Test crypto operations
        assert_eq!(gas_cost(&KapraOpCode::Sha3), 50);
        assert_eq!(gas_cost(&KapraOpCode::Sha3_512), 100);
        assert_eq!(gas_cost(&KapraOpCode::BlsVerify), 200);

        // Test networking operations
        assert_eq!(gas_cost(&KapraOpCode::TcpConnect), 100);
        assert_eq!(gas_cost(&KapraOpCode::HttpPost), 120);
    }
} 