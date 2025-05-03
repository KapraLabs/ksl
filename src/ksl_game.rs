// ksl_game.rs
// Gaming-specific primitives for Kapra Chain and standalone gaming applications

/// Represents KSL bytecode (aligned with ksl_bytecode.rs).
#[derive(Debug, Clone)]
pub struct Bytecode {
    instructions: Vec<u8>,
    constants: Vec<Constant>,
}

impl Bytecode {
    pub fn new(instructions: Vec<u8>, constants: Vec<Constant>) -> Self {
        Bytecode {
            instructions,
            constants,
        }
    }

    pub fn extend(&mut self, other: Bytecode) {
        self.instructions.extend(other.instructions);
        self.constants.extend(other.constants);
    }
}

/// Represents a constant in the bytecode.
#[derive(Debug, Clone)]
pub enum Constant {
    U32(u32),
    ArrayU32(usize, Vec<u32>), // e.g., array<u32, 4>
    ArrayU8(usize, Vec<u8>),   // e.g., array<u8, 32>
}

/// Represents an AST node (aligned with ksl_parser.rs).
#[derive(Debug, Clone)]
pub enum AstNode {
    PhysicsBlock {
        params: Vec<(String, Type)>, // Parameters (e.g., obj1, obj2)
        return_type: Type,           // Return type (bool)
        body: Vec<AstNode>,          // Body of the physics block
    },
    RenderBlock {
        params: Vec<(String, Type)>, // Parameters (e.g., sprite)
        return_type: Type,           // Return type (bool)
        body: Vec<AstNode>,          // Body of the render block
    },
    MultiplayerBlock {
        params: Vec<(String, Type)>, // Parameters (e.g., peer_id, state)
        return_type: Type,           // Return type (bool)
        body: Vec<AstNode>,          // Body of the multiplayer block
    },
    Call {
        name: String,
        args: Vec<AstNode>,
    },
    LiteralU32(u32),
    LiteralArrayU32(usize, Vec<u32>),
    LiteralArrayU8(usize, Vec<u8>),
}

/// Represents a type (aligned with ksl_types.rs).
#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    Bool,
    U32,
    ArrayU32(usize), // e.g., array<u32, 4>
    ArrayU8(usize),  // e.g., array<u8, 32>
}

/// Game runtime for Kapra Chain.
#[derive(Debug, Clone)]
pub struct GameRuntime {
    is_embedded: bool,
}

impl GameRuntime {
    pub fn new(is_embedded: bool) -> Self {
        GameRuntime { is_embedded }
    }

    /// Check if two objects collide (simplified AABB collision detection).
    pub fn collides(&self, obj1: &Vec<u32>, obj2: &Vec<u32>) -> bool {
        // obj1 and obj2 are [x, y, width, height]
        let (x1, y1, w1, h1) = (obj1[0], obj1[1], obj1[2], obj1[3]);
        let (x2, y2, w2, h2) = (obj2[0], obj2[1], obj2[2], obj2[3]);
        x1 < x2 + w2 && x1 + w1 > x2 && y1 < y2 + h2 && y1 + h1 > y2
    }

    /// Draw a sprite (simplified 2D rendering).
    pub fn draw_sprite(&self, sprite: &Vec<u32>) -> bool {
        // sprite is [x, y, sprite_id]
        if self.is_embedded {
            // Simplified rendering for embedded devices (e.g., no GPU)
            sprite[2] != 0 // sprite_id must be non-zero
        } else {
            // In reality, this would interact with a graphics API
            true
        }
    }

    /// Send game state to a peer (simplified networking).
    pub fn send_state(&self, peer_id: u32, state: &Vec<u8>) -> bool {
        // Simulated networking (in reality, this would use net.udp_send from ksl_stdlib_net.rs)
        peer_id != u32::MAX && state.len() == 32
    }
}

/// Kapra VM with game support (aligned with kapra_vm.rs).
#[derive(Debug)]
pub struct KapraVM {
    stack: Vec<u64>,
    game_runtime: GameRuntime,
    async_tasks: Vec<AsyncTask>,
}

impl KapraVM {
    pub fn new(is_embedded: bool) -> Self {
        KapraVM {
            stack: vec![],
            game_runtime: GameRuntime::new(is_embedded),
            async_tasks: vec![],
        }
    }

    pub fn execute(&mut self, bytecode: &Bytecode) -> Result<bool, String> {
        let mut ip = 0;
        while ip < bytecode.instructions.len() {
            let instr = bytecode.instructions[ip];
            ip += 1;

            match instr {
                OPCODE_COLLIDES => {
                    if self.stack.len() < 2 {
                        return Err("Not enough values on stack for COLLIDES".to_string());
                    }
                    let obj2_idx = self.stack.pop().unwrap() as usize;
                    let obj1_idx = self.stack.pop().unwrap() as usize;
                    let obj1 = match &bytecode.constants[obj1_idx] {
                        Constant::ArrayU32(_, data) => data,
                        _ => return Err("Invalid type for COLLIDES first object".to_string()),
                    };
                    let obj2 = match &bytecode.constants[obj2_idx] {
                        Constant::ArrayU32(_, data) => data,
                        _ => return Err("Invalid type for COLLIDES second object".to_string()),
                    };
                    let collides = self.game_runtime.collides(obj1, obj2);
                    self.stack.push(collides as u64);
                }
                OPCODE_DRAW_SPRITE => {
                    if self.stack.len() < 1 {
                        return Err("Not enough values on stack for DRAW_SPRITE".to_string());
                    }
                    let sprite_idx = self.stack.pop().unwrap() as usize;
                    let sprite = match &bytecode.constants[sprite_idx] {
                        Constant::ArrayU32(_, data) => data,
                        _ => return Err("Invalid type for DRAW_SPRITE sprite".to_string()),
                    };
                    let success = self.game_runtime.draw_sprite(sprite);
                    self.stack.push(success as u64);
                }
                OPCODE_SEND_STATE => {
                    if self.stack.len() < 2 {
                        return Err("Not enough values on stack for SEND_STATE".to_string());
                    }
                    let state_idx = self.stack.pop().unwrap() as usize;
                    let peer_id = self.stack.pop().unwrap() as u32;
                    let state = match &bytecode.constants[state_idx] {
                        Constant::ArrayU8(_, data) => data,
                        _ => return Err("Invalid type for SEND_STATE state".to_string()),
                    };
                    let success = self.game_runtime.send_state(peer_id, state);
                    self.async_tasks.push(AsyncTask::SendState(peer_id, state.clone()));
                    self.stack.push(success as u64);
                }
                OPCODE_PUSH => {
                    if ip >= bytecode.instructions.len() {
                        return Err("Incomplete PUSH instruction".to_string());
                    }
                    let value = bytecode.instructions[ip] as u64;
                    ip += 1;
                    self.stack.push(value);
                }
                OPCODE_FAIL => {
                    return Err("Game operation failed".to_string());
                }
                _ => return Err(format!("Unsupported opcode: {}", instr)),
            }
        }

        if self.stack.len() != 1 {
            return Err("Game block must return exactly one boolean value".to_string());
        }
        Ok(self.stack[0] != 0)
    }
}

/// Represents an async task (aligned with ksl_async.rs).
#[derive(Debug, Clone)]
pub enum AsyncTask {
    SendState(u32, Vec<u8>),
}

/// Game compiler for Kapra Chain.
pub struct GameCompiler {
    is_embedded: bool,
}

impl GameCompiler {
    pub fn new(is_embedded: bool) -> Self {
        GameCompiler { is_embedded }
    }

    /// Compile a game block into bytecode.
    pub fn compile(&self, node: &AstNode) -> Result<Bytecode, String> {
        match node {
            AstNode::PhysicsBlock { params, return_type, body } => {
                // Validate parameters and return type
                if params.len() != 2 {
                    return Err("Physics block must have exactly 2 parameters: obj1, obj2".to_string());
                }
                if params[0].0 != "obj1" || !matches!(params[0].1, Type::ArrayU32(4)) {
                    return Err("First parameter must be 'obj1: array<u32, 4]'".to_string());
                }
                if params[1].0 != "obj2" || !matches!(params[1].1, Type::ArrayU32(4)) {
                    return Err("Second parameter must be 'obj2: array<u32, 4]'".to_string());
                }
                if !matches!(return_type, Type::Bool) {
                    return Err("Physics block must return bool".to_string());
                }

                let mut bytecode = Bytecode::new(vec![], vec![]);

                // Compile the body
                for stmt in body {
                    let stmt_bytecode = self.compile_stmt(stmt)?;
                    bytecode.extend(stmt_bytecode);
                }

                Ok(bytecode)
            }
            AstNode::RenderBlock { params, return_type, body } => {
                // Validate parameters and return type
                if params.len() != 1 {
                    return Err("Render block must have exactly 1 parameter: sprite".to_string());
                }
                if params[0].0 != "sprite" || !matches!(params[0].1, Type::ArrayU32(3)) {
                    return Err("Parameter must be 'sprite: array<u32, 3]'".to_string());
                }
                if !matches!(return_type, Type::Bool) {
                    return Err("Render block must return bool".to_string());
                }

                let mut bytecode = Bytecode::new(vec![], vec![]);

                // Compile the body
                for stmt in body {
                    let stmt_bytecode = self.compile_stmt(stmt)?;
                    bytecode.extend(stmt_bytecode);
                }

                Ok(bytecode)
            }
            AstNode::MultiplayerBlock { params, return_type, body } => {
                // Validate parameters and return type
                if params.len() != 2 {
                    return Err("Multiplayer block must have exactly 2 parameters: peer_id, state".to_string());
                }
                if params[0].0 != "peer_id" || !matches!(params[0].1, Type::U32) {
                    return Err("First parameter must be 'peer_id: u32'".to_string());
                }
                if params[1].0 != "state" || !matches!(params[1].1, Type::ArrayU8(32)) {
                    return Err("Second parameter must be 'state: array<u8, 32]'".to_string());
                }
                if !matches!(return_type, Type::Bool) {
                    return Err("Multiplayer block must return bool".to_string());
                }

                let mut bytecode = Bytecode::new(vec![], vec![]);

                // Compile the body
                for stmt in body {
                    let stmt_bytecode = self.compile_stmt(stmt)?;
                    bytecode.extend(stmt_bytecode);
                }

                Ok(bytecode)
            }
            _ => Err("Only game blocks can be compiled at the top level".to_string()),
        }
    }

    fn compile_stmt(&self, stmt: &AstNode) -> Result<Bytecode, String> {
        match stmt {
            AstNode::Call { name, args } => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                for arg in args {
                    let arg_bytecode = self.compile_expr(arg)?;
                    bytecode.extend(arg_bytecode);
                }
                match name.as_str() {
                    "collides" => {
                        bytecode.instructions.push(OPCODE_COLLIDES);
                    }
                    "draw_sprite" => {
                        bytecode.instructions.push(OPCODE_DRAW_SPRITE);
                    }
                    "send_state" => {
                        bytecode.instructions.push(OPCODE_SEND_STATE);
                    }
                    _ => return Err(format!("Unsupported function in game block: {}", name)),
                }
                Ok(bytecode)
            }
            _ => Err("Unsupported statement in game block".to_string()),
        }
    }

    fn compile_expr(&self, expr: &AstNode) -> Result<Bytecode, String> {
        match expr {
            AstNode::LiteralU32(val) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::U32(*val));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::LiteralArrayU32(size, data) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::ArrayU32(*size, data.clone()));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::LiteralArrayU8(size, data) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::ArrayU8(*size, data.clone()));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::Call { name, args } => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                for arg in args {
                    let arg_bytecode = self.compile_expr(arg)?;
                    bytecode.extend(arg_bytecode);
                }
                if name == "collides" {
                    bytecode.instructions.push(OPCODE_COLLIDES);
                } else if name == "draw_sprite" {
                    bytecode.instructions.push(OPCODE_DRAW_SPRITE);
                } else if name == "send_state" {
                    bytecode.instructions.push(OPCODE_SEND_STATE);
                } else {
                    return Err(format!("Unsupported expression in game block: {}", name));
                }
                Ok(bytecode)
            }
            _ => Err("Unsupported expression in game block".to_string()),
        }
    }
}

const OPCODE_COLLIDES: u8 = 0x01;
const OPCODE_DRAW_SPRITE: u8 = 0x02;
const OPCODE_SEND_STATE: u8 = 0x03;
const OPCODE_PUSH: u8 = 0x04;
const OPCODE_FAIL: u8 = 0x05;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_physics_block_compilation() {
        let physics_node = AstNode::PhysicsBlock {
            params: vec![
                ("obj1".to_string(), Type::ArrayU32(4)),
                ("obj2".to_string(), Type::ArrayU32(4)),
            ],
            return_type: Type::Bool,
            body: vec![
                AstNode::Call {
                    name: "collides".to_string(),
                    args: vec![
                        AstNode::LiteralArrayU32(4, vec![0, 0, 10, 10]), // [x, y, width, height]
                        AstNode::LiteralArrayU32(4, vec![5, 5, 10, 10]),
                    ],
                },
            ],
        };

        let compiler = GameCompiler::new(false);
        let bytecode = compiler.compile(&physics_node).unwrap();
        assert!(!bytecode.instructions.is_empty());
        assert!(bytecode.instructions.contains(&OPCODE_COLLIDES));
    }

    #[test]
    fn test_render_block_compilation() {
        let render_node = AstNode::RenderBlock {
            params: vec![("sprite".to_string(), Type::ArrayU32(3))],
            return_type: Type::Bool,
            body: vec![
                AstNode::Call {
                    name: "draw_sprite".to_string(),
                    args: vec![AstNode::LiteralArrayU32(3, vec![10, 20, 1])], // [x, y, sprite_id]
                },
            ],
        };

        let compiler = GameCompiler::new(false);
        let bytecode = compiler.compile(&render_node).unwrap();
        assert!(!bytecode.instructions.is_empty());
        assert!(bytecode.instructions.contains(&OPCODE_DRAW_SPRITE));
    }

    #[test]
    fn test_multiplayer_block_compilation() {
        let multiplayer_node = AstNode::MultiplayerBlock {
            params: vec![
                ("peer_id".to_string(), Type::U32),
                ("state".to_string(), Type::ArrayU8(32)),
            ],
            return_type: Type::Bool,
            body: vec![
                AstNode::Call {
                    name: "send_state".to_string(),
                    args: vec![
                        AstNode::LiteralU32(1),
                        AstNode::LiteralArrayU8(32, vec![1; 32]),
                    ],
                },
            ],
        };

        let compiler = GameCompiler::new(false);
        let bytecode = compiler.compile(&multiplayer_node).unwrap();
        assert!(!bytecode.instructions.is_empty());
        assert!(bytecode.instructions.contains(&OPCODE_SEND_STATE));
    }

    #[test]
    fn test_physics_execution() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::ArrayU32(4, vec![0, 0, 10, 10]), // obj1: [x, y, width, height]
            Constant::ArrayU32(4, vec![5, 5, 10, 10]), // obj2: overlapping
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,           // Push obj1
            OPCODE_PUSH, 1,           // Push obj2
            OPCODE_COLLIDES,          // Check collision
        ]);

        let mut vm = KapraVM::new(false);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should collide
    }

    #[test]
    fn test_render_execution() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::ArrayU32(3, vec![10, 20, 1]), // sprite: [x, y, sprite_id]
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,           // Push sprite
            OPCODE_DRAW_SPRITE,       // Draw sprite
        ]);

        let mut vm = KapraVM::new(false);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_multiplayer_execution() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::ArrayU8(32, vec![1; 32]), // state
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 1,           // Push peer_id
            OPCODE_PUSH, 0,           // Push state
            OPCODE_SEND_STATE,        // Send state
        ]);

        let mut vm = KapraVM::new(false);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(vm.async_tasks.len(), 1);
    }

    #[test]
    fn test_invalid_physics_params() {
        let physics_node = AstNode::PhysicsBlock {
            params: vec![("obj1".to_string(), Type::ArrayU32(4))],
            return_type: Type::Bool,
            body: vec![],
        };

        let compiler = GameCompiler::new(false);
        let result = compiler.compile(&physics_node);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must have exactly 2 parameters"));
    }
}