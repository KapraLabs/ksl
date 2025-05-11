// ksl_stdlib_net.rs
// Implements networking functions for KSL standard library, providing TCP/UDP and HTTP
// client functions with async support.

use crate::ksl_types::{Type, TypeError};
use crate::ksl_bytecode::{KapraOpCode, Operand, KapraInstruction};
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_async::AsyncRuntime;
use crate::ksl_docgen::{DocGen, DocItem, DocParam, DocReturn};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::net::{TcpStream, UdpSocket};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use std::arch::x86_64::*;
use std::arch::asm;
use std::collections::HashMap;
use std::net::{SocketAddr, IpAddr};
use std::time::Duration;
use std::sync::atomic::{AtomicU64, Ordering};

/// Networking standard library function signature
/// @struct NetStdLibFunction
/// @field name Function name
/// @field params Function parameters
/// @field return_type Function return type
/// @field opcode Function opcode
/// @field is_async Whether the function is async
#[derive(Debug, PartialEq, Clone)]
pub struct NetStdLibFunction {
    pub name: &'static str,
    pub params: Vec<Type>,
    pub return_type: Type,
    pub opcode: Option<KapraOpCode>,
    pub is_async: bool,
}

/// Networking standard library registry
/// @struct NetStdLib
/// @field functions Registered networking functions
/// @field runtime Async runtime for network operations
/// @field rdma_context Optional RDMA context
/// @field p2p_manager Optional P2P manager
pub struct NetStdLib {
    functions: Vec<NetStdLibFunction>,
    runtime: Arc<AsyncRuntime>,
    rdma_context: Option<Arc<Mutex<RDMAContext>>>,
    p2p_manager: Arc<Mutex<P2PManager>>,
}

/// RDMA configuration
#[derive(Debug, Clone)]
pub struct RDMAConfig {
    /// Whether to enable RDMA
    pub enable_rdma: bool,
    /// RDMA device name
    pub device_name: String,
    /// Queue pair size
    pub qp_size: usize,
    /// Memory region size
    pub mr_size: usize,
    /// Zero-copy threshold
    pub zero_copy_threshold: usize,
}

/// RDMA context for zero-copy operations
pub struct RDMAContext {
    /// RDMA device
    device: Arc<Mutex<RDMADevice>>,
    /// Memory regions
    memory_regions: HashMap<u64, MemoryRegion>,
    /// Queue pairs
    queue_pairs: HashMap<u64, QueuePair>,
    /// Metrics
    metrics: RDMAMetrics,
}

/// RDMA device
struct RDMADevice {
    /// Device name
    name: String,
    /// Device capabilities
    capabilities: RDMACapabilities,
    /// Active connections
    connections: HashMap<u64, RDMAConnection>,
}

/// RDMA capabilities
#[derive(Debug, Clone)]
struct RDMACapabilities {
    /// Maximum message size
    max_msg_size: usize,
    /// Maximum queue depth
    max_qp_depth: usize,
    /// Supported operations
    supported_ops: Vec<RDMAOp>,
}

/// RDMA operation types
#[derive(Debug, Clone, PartialEq)]
enum RDMAOp {
    Send,
    Receive,
    Read,
    Write,
    Atomic,
}

/// Memory region for RDMA operations
struct MemoryRegion {
    /// Memory region ID
    id: u64,
    /// Memory address
    addr: *mut u8,
    /// Memory size
    size: usize,
    /// Access flags
    access_flags: u32,
}

/// Queue pair for RDMA operations
struct QueuePair {
    /// Queue pair ID
    id: u64,
    /// Send queue
    send_queue: Vec<RDMAWorkRequest>,
    /// Receive queue
    recv_queue: Vec<RDMAWorkRequest>,
    /// Completion queue
    comp_queue: Vec<RDMACompletion>,
}

/// RDMA work request
struct RDMAWorkRequest {
    /// Operation type
    op_type: RDMAOp,
    /// Memory region ID
    mr_id: u64,
    /// Remote address
    remote_addr: u64,
    /// Remote key
    remote_key: u32,
    /// Local offset
    local_offset: u64,
    /// Length
    length: usize,
}

/// RDMA completion
struct RDMACompletion {
    /// Work request ID
    wr_id: u64,
    /// Status
    status: u32,
    /// Operation type
    op_type: RDMAOp,
}

/// RDMA metrics
#[derive(Debug, Default)]
struct RDMAMetrics {
    /// Total bytes transferred
    total_bytes: AtomicU64,
    /// Total operations
    total_ops: AtomicU64,
    /// Average latency
    avg_latency_us: AtomicU64,
}

/// P2P connection manager
pub struct P2PManager {
    /// Local address
    local_addr: SocketAddr,
    /// Peer connections
    peers: HashMap<u64, PeerConnection>,
    /// NAT traversal state
    nat_state: NATState,
    /// Connection metrics
    metrics: P2PMetrics,
}

/// Peer connection
struct PeerConnection {
    /// Peer ID
    id: u64,
    /// Connection state
    state: ConnectionState,
    /// Local address
    local_addr: SocketAddr,
    /// Remote address
    remote_addr: SocketAddr,
    /// RDMA context
    rdma: Option<RDMAContext>,
}

/// Connection state
#[derive(Debug, Clone, PartialEq)]
enum ConnectionState {
    Connecting,
    Connected,
    Disconnected,
}

/// NAT traversal state
#[derive(Debug, Clone)]
struct NATState {
    /// NAT type
    nat_type: NATType,
    /// STUN server
    stun_server: SocketAddr,
    /// TURN server
    turn_server: Option<SocketAddr>,
    /// ICE candidates
    ice_candidates: Vec<IceCandidate>,
}

/// NAT type
#[derive(Debug, Clone, PartialEq)]
enum NATType {
    Open,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
}

/// ICE candidate
#[derive(Debug, Clone)]
struct IceCandidate {
    /// Candidate type
    candidate_type: CandidateType,
    /// Protocol
    protocol: Protocol,
    /// Priority
    priority: u32,
    /// Address
    address: SocketAddr,
}

/// Candidate type
#[derive(Debug, Clone, PartialEq)]
enum CandidateType {
    Host,
    ServerReflexive,
    PeerReflexive,
    Relayed,
}

/// Protocol
#[derive(Debug, Clone, PartialEq)]
enum Protocol {
    UDP,
    TCP,
}

/// P2P metrics
#[derive(Debug, Default)]
struct P2PMetrics {
    /// Total connections
    total_connections: AtomicU64,
    /// Active connections
    active_connections: AtomicU64,
    /// Total bytes sent
    total_bytes_sent: AtomicU64,
    /// Total bytes received
    total_bytes_received: AtomicU64,
}

impl NetStdLib {
    /// Creates a new networking standard library instance with RDMA support
    pub fn new_with_rdma(runtime: Arc<AsyncRuntime>, rdma_config: Option<RDMAConfig>) -> Self {
        let mut functions = vec![
            // tcp.connect(host: string, port: u32) -> result<u32, error>
            NetStdLibFunction {
                name: "tcp.connect",
                params: vec![Type::String, Type::U32],
                return_type: Type::Result {
                    ok: Box::new(Type::U32),
                    err: Box::new(Type::Error),
                },
                opcode: Some(KapraOpCode::TcpConnect),
                is_async: true,
            },
            // udp.send(host: string, port: u32, data: array<u8, 1024>) -> result<u32, error>
            NetStdLibFunction {
                name: "udp.send",
                params: vec![Type::String, Type::U32, Type::Array(Box::new(Type::U8), 1024)],
                return_type: Type::Result {
                    ok: Box::new(Type::U32),
                    err: Box::new(Type::Error),
                },
                opcode: Some(KapraOpCode::UdpSend),
                is_async: true,
            },
            // http.get(url: string) -> result<string, error>
            NetStdLibFunction {
                name: "http.get",
                params: vec![Type::String],
                return_type: Type::Result {
                    ok: Box::new(Type::String),
                    err: Box::new(Type::Error),
                },
                opcode: Some(KapraOpCode::HttpGet),
                is_async: true,
            },
            // http.post(url: string, data: string) -> result<string, error>
            NetStdLibFunction {
                name: "http.post",
                params: vec![Type::String, Type::String],
                return_type: Type::Result {
                    ok: Box::new(Type::String),
                    err: Box::new(Type::Error),
                },
                opcode: Some(KapraOpCode::HttpPost),
                is_async: true,
            },
            // rdma.connect(host: string, port: u32) -> result<u64, error>
            NetStdLibFunction {
                name: "rdma.connect",
                params: vec![Type::String, Type::U32],
                return_type: Type::Result {
                    ok: Box::new(Type::U64),
                    err: Box::new(Type::Error),
                },
                opcode: Some(KapraOpCode::RDMAConnect),
                is_async: true,
            },
            // rdma.send(conn_id: u64, data: array<u8, 1024>) -> result<u32, error>
            NetStdLibFunction {
                name: "rdma.send",
                params: vec![Type::U64, Type::Array(Box::new(Type::U8), 1024)],
                return_type: Type::Result {
                    ok: Box::new(Type::U32),
                    err: Box::new(Type::Error),
                },
                opcode: Some(KapraOpCode::RDMASend),
                is_async: true,
            },
            // p2p.connect(peer_id: u64) -> result<bool, error>
            NetStdLibFunction {
                name: "p2p.connect",
                params: vec![Type::U64],
                return_type: Type::Result {
                    ok: Box::new(Type::Bool),
                    err: Box::new(Type::Error),
                },
                opcode: Some(KapraOpCode::P2PConnect),
                is_async: true,
            },
        ];

        NetStdLib {
            functions,
            runtime,
            rdma_context: rdma_config.map(|config| Arc::new(Mutex::new(RDMAContext::new(config)))),
            p2p_manager: Arc::new(Mutex::new(P2PManager::new())),
        }
    }

    /// Get function by name
    /// 
    /// # Arguments
    /// * `name` - The name of the function to get
    /// 
    /// # Returns
    /// The function if found, None otherwise
    pub fn get_function(&self, name: &str) -> Option<&NetStdLibFunction> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Validate function call (used by type checker)
    /// 
    /// # Arguments
    /// * `name` - The name of the function to validate
    /// * `arg_types` - The types of the arguments
    /// * `position` - The source position for error reporting
    /// 
    /// # Returns
    /// The return type of the function if valid, an error otherwise
    pub fn validate_call(
        &self,
        name: &str,
        arg_types: &[Type],
        position: SourcePosition,
    ) -> Result<Type, KslError> {
        let func = self.get_function(name).ok_or_else(|| KslError::type_error(
            format!("Undefined networking function: {}", name),
            position,
        ))?;
        if arg_types.len() != func.params.len() {
            return Err(KslError::type_error(
                format!(
                    "Expected {} arguments, got {}",
                    func.params.len(),
                    arg_types.len()
                ),
                position,
            ));
        }
        for (expected, actual) in func.params.iter().zip(arg_types) {
            if expected != actual {
                return Err(KslError::type_error(
                    format!("Argument type mismatch: expected {:?}, got {:?}", expected, actual),
                    position,
                ));
            }
        }
        Ok(func.return_type.clone())
    }

    /// Generate bytecode for function call (used by compiler)
    /// 
    /// # Arguments
    /// * `name` - The name of the function to generate bytecode for
    /// * `arg_regs` - The registers containing the arguments
    /// * `dst_reg` - The register to store the result in
    /// 
    /// # Returns
    /// The bytecode instructions for the function call
    pub fn emit_call(
        &self,
        name: &str,
        arg_regs: &[u8],
        dst_reg: u8,
    ) -> Result<Vec<KapraInstruction>, KslError> {
        let func = self.get_function(name).ok_or_else(|| KslError::type_error(
            format!("Undefined networking function: {}", name),
            SourcePosition::new(1, 1),
        ))?;
        if arg_regs.len() != func.params.len() {
            return Err(KslError::type_error(
                format!(
                    "Expected {} arguments, got {}",
                    func.params.len(),
                    arg_regs.len()
                ),
                SourcePosition::new(1, 1),
            ));
        }

        match func.opcode {
            Some(opcode) => {
                let mut operands = vec![Operand::Register(dst_reg)];
                operands.extend(arg_regs.iter().map(|&r| Operand::Register(r)));
                Ok(vec![KapraInstruction::new(
                    opcode,
                    operands,
                    Some(func.return_type.clone()),
                )])
            }
            None => Err(KslError::type_error(
                format!("No implementation for {}", name),
                SourcePosition::new(1, 1),
            )),
        }
    }

    /// Executes a networking function with RDMA support
    /// @param name Function name
    /// @param args Function arguments
    /// @returns Function result
    pub async fn execute(&self, name: &str, args: Vec<Value>) -> Result<Value, KslError> {
        let pos = SourcePosition::new(1, 1);
        match name {
            "tcp.connect" => {
                if args.len() != 2 {
                    return Err(KslError::type_error(
                        format!("tcp.connect expects 2 arguments, got {}", args.len()),
                        pos,
                    ));
                }
                let host = match &args[0] {
                    Value::String(s) => s,
                    _ => return Err(KslError::type_error("tcp.connect: host must be a string".to_string(), pos)),
                };
                let port = match &args[1] {
                    Value::U32(p) => *p,
                    _ => return Err(KslError::type_error("tcp.connect: port must be a u32".to_string(), pos)),
                };
                let address = format!("{}:{}", host, port);
                let stream = TcpStream::connect(&address)
                    .await
                    .map_err(|e| KslError::type_error(
                        format!("tcp.connect failed: {}", e),
                        pos,
                    ))?;
                Ok(Value::U32(stream.local_addr().unwrap().port() as u32))
            }
            "udp.send" => {
                if args.len() != 3 {
                    return Err(KslError::type_error(
                        format!("udp.send expects 3 arguments, got {}", args.len()),
                        pos,
                    ));
                }
                let host = match &args[0] {
                    Value::String(s) => s,
                    _ => return Err(KslError::type_error("udp.send: host must be a string".to_string(), pos)),
                };
                let port = match &args[1] {
                    Value::U32(p) => *p,
                    _ => return Err(KslError::type_error("udp.send: port must be a u32".to_string(), pos)),
                };
                let data = match &args[2] {
                    Value::Array(data, size) if *size <= 1024 => {
                        data.iter().map(|v| match v {
                            Value::U32(n) if *n <= 255 => Ok(*n as u8),
                            _ => Err(KslError::type_error("udp.send: data must be an array of u8".to_string(), pos)),
                        }).collect::<Result<Vec<u8>, KslError>>()?
                    }
                    _ => return Err(KslError::type_error("udp.send: data must be an array<u8, 1024>".to_string(), pos)),
                };
                let socket = UdpSocket::bind("0.0.0.0:0")
                    .await
                    .map_err(|e| KslError::type_error(
                        format!("udp.send failed to bind: {}", e),
                        pos,
                    ))?;
                let address = format!("{}:{}", host, port);
                let bytes_sent = socket.send_to(&data, &address)
                    .await
                    .map_err(|e| KslError::type_error(
                        format!("udp.send failed: {}", e),
                        pos,
                    ))?;
                Ok(Value::U32(bytes_sent as u32))
            }
            "http.get" => {
                if args.len() != 1 {
                    return Err(KslError::type_error(
                        format!("http.get expects 1 argument, got {}", args.len()),
                        pos,
                    ));
                }
                let url = match &args[0] {
                    Value::String(s) => s,
                    _ => return Err(KslError::type_error("http.get: url must be a string".to_string(), pos)),
                };
                let response = self.runtime.http_get(url)
                    .await
                    .map_err(|e| KslError::type_error(
                        format!("http.get failed: {}", e),
                        pos,
                    ))?;
                Ok(Value::String(response))
            }
            "http.post" => {
                if args.len() != 2 {
                    return Err(KslError::type_error(
                        format!("http.post expects 2 arguments, got {}", args.len()),
                        pos,
                    ));
                }
                let url = match &args[0] {
                    Value::String(s) => s,
                    _ => return Err(KslError::type_error("http.post: url must be a string".to_string(), pos)),
                };
                let data = match &args[1] {
                    Value::String(s) => s,
                    _ => return Err(KslError::type_error("http.post: data must be a string".to_string(), pos)),
                };
                let response = self.runtime.http_post(url, data)
                    .await
                    .map_err(|e| KslError::type_error(
                        format!("http.post failed: {}", e),
                        pos,
                    ))?;
                Ok(Value::String(response))
            }
            "rdma.connect" => {
                if args.len() != 2 {
                    return Err(KslError::type_error(
                        format!("rdma.connect expects 2 arguments, got {}", args.len()),
                        pos,
                    ));
                }
                let host = match &args[0] {
                    Value::String(s) => s,
                    _ => return Err(KslError::type_error("rdma.connect: host must be a string".to_string(), pos)),
                };
                let port = match &args[1] {
                    Value::U32(p) => *p,
                    _ => return Err(KslError::type_error("rdma.connect: port must be a u32".to_string(), pos)),
                };

                if let Some(rdma) = &self.rdma_context {
                    let mut rdma = rdma.lock().await;
                    let conn_id = rdma.connect(host, port).await.map_err(|e| KslError::type_error(
                        format!("rdma.connect failed: {}", e),
                        pos,
                    ))?;
                    Ok(Value::U64(conn_id))
                } else {
                    Err(KslError::type_error("RDMA not available".to_string(), pos))
                }
            }
            "rdma.send" => {
                if args.len() != 2 {
                    return Err(KslError::type_error(
                        format!("rdma.send expects 2 arguments, got {}", args.len()),
                        pos,
                    ));
                }
                let conn_id = match &args[0] {
                    Value::U64(id) => *id,
                    _ => return Err(KslError::type_error("rdma.send: conn_id must be a u64".to_string(), pos)),
                };
                let data = match &args[1] {
                    Value::Array(data, size) if *size <= 1024 => {
                        data.iter().map(|v| match v {
                            Value::U32(n) if *n <= 255 => Ok(*n as u8),
                            _ => Err(KslError::type_error("rdma.send: data must be an array of u8".to_string(), pos)),
                        }).collect::<Result<Vec<u8>, KslError>>()?
                    }
                    _ => return Err(KslError::type_error("rdma.send: data must be an array<u8, 1024>".to_string(), pos)),
                };

                if let Some(rdma) = &self.rdma_context {
                    let mut rdma = rdma.lock().await;
                    let bytes_sent = rdma.send(conn_id, &data).await.map_err(|e| KslError::type_error(
                        format!("rdma.send failed: {}", e),
                        pos,
                    ))?;
                    Ok(Value::U32(bytes_sent as u32))
                } else {
                    Err(KslError::type_error("RDMA not available".to_string(), pos))
                }
            }
            "p2p.connect" => {
                if args.len() != 1 {
                    return Err(KslError::type_error(
                        format!("p2p.connect expects 1 argument, got {}", args.len()),
                        pos,
                    ));
                }
                let peer_id = match &args[0] {
                    Value::U64(id) => *id,
                    _ => return Err(KslError::type_error("p2p.connect: peer_id must be a u64".to_string(), pos)),
                };

                let mut p2p = self.p2p_manager.lock().await;
                let success = p2p.connect(peer_id).await.map_err(|e| KslError::type_error(
                    format!("p2p.connect failed: {}", e),
                    pos,
                ))?;
                Ok(Value::Bool(success))
            }
            _ => Err(KslError::type_error(
                format!("Undefined networking function: {}", name),
                pos,
            )),
        }
    }

    /// Generates documentation for networking functions
    /// @returns Documentation items
    pub fn generate_docs(&self) -> Vec<DocItem> {
        self.functions.iter().map(|func| {
            DocItem::Function {
                name: func.name.to_string(),
                params: func.params.iter().map(|typ| {
                    DocParam {
                        name: "".to_string(), // Parameter names not available
                        typ: format_type(typ),
                    }
                }).collect(),
                returns: DocReturn {
                    typ: format_type(&func.return_type),
                },
                description: match func.name {
                    "tcp.connect" => "Establishes a TCP connection to the specified host and port".to_string(),
                    "udp.send" => "Sends UDP data to the specified host and port".to_string(),
                    "http.get" => "Performs an HTTP GET request to the specified URL".to_string(),
                    "http.post" => "Performs an HTTP POST request to the specified URL with the given data".to_string(),
                    _ => "".to_string(),
                },
            }
        }).collect()
    }
}

impl RDMAContext {
    /// Creates a new RDMA context
    pub fn new(config: RDMAConfig) -> Self {
        RDMAContext {
            device: Arc::new(Mutex::new(RDMADevice::new(config))),
            memory_regions: HashMap::new(),
            queue_pairs: HashMap::new(),
            metrics: RDMAMetrics::default(),
        }
    }

    /// Connects to a remote RDMA endpoint
    pub async fn connect(&mut self, host: &str, port: u32) -> Result<u64, String> {
        let port_u32: u32 = port.try_into().unwrap();
        let mut device = self.device.lock().await;
        let conn_id = device.create_connection(host, port_u32).await?;
        Ok(conn_id)
    }

    /// Sends data using RDMA
    pub async fn send(&mut self, conn_id: u64, data: &[u8]) -> Result<usize, String> {
        let mut device = self.device.lock().await;
        let bytes_sent = device.send(conn_id, data).await?;
        self.metrics.total_bytes.fetch_add(bytes_sent as u64, Ordering::Relaxed);
        self.metrics.total_ops.fetch_add(1, Ordering::Relaxed);
        Ok(bytes_sent)
    }
}

impl P2PManager {
    /// Creates a new P2P manager
    pub fn new() -> Self {
        P2PManager {
            local_addr: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
            peers: HashMap::new(),
            nat_state: NATState::new(),
            metrics: P2PMetrics::default(),
        }
    }

    /// Connects to a peer with NAT traversal
    pub async fn connect(&mut self, peer_id: u64) -> Result<bool, String> {
        // Discover NAT type
        let nat_type = self.discover_nat_type().await?;
        self.nat_state.nat_type = nat_type;

        // Gather ICE candidates
        let candidates = self.gather_ice_candidates().await?;
        self.nat_state.ice_candidates = candidates;

        // Establish connection
        let peer = PeerConnection::new(peer_id);
        self.peers.insert(peer_id, peer);

        // Update metrics
        self.metrics.total_connections.fetch_add(1, Ordering::Relaxed);
        self.metrics.active_connections.fetch_add(1, Ordering::Relaxed);

        Ok(true)
    }

    /// Discovers NAT type using STUN
    async fn discover_nat_type(&self) -> Result<NATType, String> {
        // Implement STUN-based NAT discovery
        Ok(NATType::Open)
    }

    /// Gathers ICE candidates
    async fn gather_ice_candidates(&self) -> Result<Vec<IceCandidate>, String> {
        // Implement ICE candidate gathering
        Ok(vec![])
    }
}

// Assume ksl_types.rs, ksl_bytecode.rs, ksl_errors.rs, and ksl_async.rs are in the same crate
mod ksl_types {
    pub use super::{Type, TypeError};
}

mod ksl_bytecode {
    pub use super::{KapraOpCode, Operand, KapraInstruction};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

mod ksl_async {
    pub use super::AsyncRuntime;
}

mod ksl_docgen {
    pub use super::{DocGen, DocItem, DocParam, DocReturn};
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;
    use std::sync::Arc;

    #[test]
    fn test_get_function() {
        let runtime = Arc::new(AsyncRuntime::new());
        let stdlib = NetStdLib::new_with_rdma(runtime, None);
        
        // Test tcp.connect
        let func = stdlib.get_function("tcp.connect").unwrap();
        assert_eq!(func.name, "tcp.connect");
        assert_eq!(func.params, vec![Type::String, Type::U32]);
        assert_eq!(func.return_type, Type::Result {
            ok: Box::new(Type::U32),
            err: Box::new(Type::Error),
        });
        assert_eq!(func.opcode, Some(KapraOpCode::TcpConnect));
        assert!(func.is_async);

        // Test http.get
        let func = stdlib.get_function("http.get").unwrap();
        assert_eq!(func.name, "http.get");
        assert_eq!(func.params, vec![Type::String]);
        assert_eq!(func.return_type, Type::Result {
            ok: Box::new(Type::String),
            err: Box::new(Type::Error),
        });
        assert_eq!(func.opcode, Some(KapraOpCode::HttpGet));
        assert!(func.is_async);
    }

    #[tokio::test]
    async fn test_http_operations() {
        let runtime = Arc::new(AsyncRuntime::new());
        let stdlib = NetStdLib::new_with_rdma(runtime, None);
        
        // Test http.get
        let response = stdlib.execute("http.get", vec![Value::String("https://httpbin.org/get".to_string())]).await;
        assert!(response.is_ok());
        let body = response.unwrap();
        assert!(matches!(body, Value::String(s) if s.contains("httpbin.org")));
        
        // Test http.post
        let response = stdlib.execute("http.post", vec![
            Value::String("https://httpbin.org/post".to_string()),
            Value::String("test data".to_string()),
        ]).await;
        assert!(response.is_ok());
        let body = response.unwrap();
        assert!(matches!(body, Value::String(s) if s.contains("test data")));
    }

    #[tokio::test]
    async fn test_tcp_connect() {
        let runtime = Arc::new(AsyncRuntime::new());
        let stdlib = NetStdLib::new_with_rdma(runtime, None);
        
        // Test successful connection
        let response = stdlib.execute("tcp.connect", vec![
            Value::String("localhost".to_string()),
            Value::U32(80),
        ]).await;
        assert!(response.is_ok());
        let port = response.unwrap();
        assert!(matches!(port, Value::U32(_)));
    }

    #[tokio::test]
    async fn test_udp_send() {
        let runtime = Arc::new(AsyncRuntime::new());
        let stdlib = NetStdLib::new_with_rdma(runtime, None);
        
        // Test successful send
        let data = vec![Value::U32(1), Value::U32(2), Value::U32(3)];
        let response = stdlib.execute("udp.send", vec![
            Value::String("localhost".to_string()),
            Value::U32(12345),
            Value::Array(data, 3),
        ]).await;
        assert!(response.is_ok());
        let bytes_sent = response.unwrap();
        assert!(matches!(bytes_sent, Value::U32(3)));
    }
}
