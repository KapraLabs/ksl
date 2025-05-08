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