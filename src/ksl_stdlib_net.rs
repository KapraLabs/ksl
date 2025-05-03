// ksl_stdlib_net.rs
// Adds networking support to the KSL standard library, providing TCP/UDP and HTTP
// client functions with async support.

use crate::ksl_stdlib::{StdLibFunctionTrait, StdLib};
use crate::ksl_async::{AsyncRuntime};
use crate::ksl_docgen::generate_docgen;
use crate::ksl_errors::{KslError, SourcePosition};
use std::net::{TcpStream, UdpSocket};
use reqwest::blocking::Client;
use std::sync::{Arc, Mutex};
use std::path::PathBuf;

// Networking standard library functions
pub struct NetStdLib;

impl NetStdLib {
    pub fn new() -> Self {
        NetStdLib
    }

    // Register networking functions in the standard library
    pub fn register(&self, stdlib: &mut StdLib, runtime: &AsyncRuntime) -> Result<(), KslError> {
        stdlib.register_function("net.tcp_connect", Arc::new(TcpConnect));
        stdlib.register_function("net.udp_send", Arc::new(UdpSend));
        stdlib.register_function("http.post", Arc::new(HttpPost { runtime: runtime.clone() }));

        // Generate documentation for networking functions
        self.generate_docs()?;
        Ok(())
    }

    // Generate documentation for networking functions
    fn generate_docs(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("net_stdlib_temp.ksl");
        let mut file = File::create(&temp_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to create temp file {}: {}", temp_file.display(), e),
                pos,
            ))?;
        writeln!(
            file,
            "/// Connects to a TCP server\n#[async]\nfn net.tcp_connect(host: string, port: u32): u32 {{}}\n/// Sends a UDP packet\nfn net.udp_send(host: string, port: u32, data: array<u8, 1024>): u32 {{}}\n/// Performs an HTTP POST request\n#[async]\nfn http.post(url: string, data: string): string {{}}"
        ).map_err(|e| KslError::type_error(
            format!("Failed to write temp file {}: {}", temp_file.display(), e),
            pos,
        ))?;

        generate_docgen("net_stdlib", "markdown", temp_dir.clone())?;
        fs::remove_file(&temp_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to clean up temp file {}: {}", temp_file.display(), e),
                pos,
            ))?;
        Ok(())
    }
}

// TCP connect function
struct TcpConnect;

impl StdLibFunctionTrait for TcpConnect {
    fn call(&self, args: Vec<Value>) -> Result<Value, KslError> {
        let pos = SourcePosition::new(1, 1);
        if args.len() != 2 {
            return Err(KslError::type_error(
                format!("net.tcp_connect expects 2 arguments, got {}", args.len()),
                pos,
            ));
        }

        let host = match &args[0] {
            Value::String(s) => s,
            _ => return Err(KslError::type_error("net.tcp_connect: host must be a string".to_string(), pos)),
        };
        let port = match &args[1] {
            Value::U32(p) => *p,
            _ => return Err(KslError::type_error("net.tcp_connect: port must be a u32".to_string(), pos)),
        };

        let address = format!("{}:{}", host, port);
        let stream = TcpStream::connect(&address)
            .map_err(|e| KslError::type_error(
                format!("net.tcp_connect failed: {}", e),
                pos,
            ))?;

        // Simplified: Return a handle (simulated as a u32)
        Ok(Value::U32(stream.local_addr().unwrap().port() as u32))
    }
}

// UDP send function
struct UdpSend;

impl StdLibFunctionTrait for UdpSend {
    fn call(&self, args: Vec<Value>) -> Result<Value, KslError> {
        let pos = SourcePosition::new(1, 1);
        if args.len() != 3 {
            return Err(KslError::type_error(
                format!("net.udp_send expects 3 arguments, got {}", args.len()),
                pos,
            ));
        }

        let host = match &args[0] {
            Value::String(s) => s,
            _ => return Err(KslError::type_error("net.udp_send: host must be a string".to_string(), pos)),
        };
        let port = match &args[1] {
            Value::U32(p) => *p,
            _ => return Err(KslError::type_error("net.udp_send: port must be a u32".to_string(), pos)),
        };
        let data = match &args[2] {
            Value::Array(data, size) if *size <= 1024 => {
                data.iter().map(|v| match v {
                    Value::U32(n) if *n <= 255 => Ok(*n as u8),
                    _ => Err(KslError::type_error("net.udp_send: data must be an array of u8".to_string(), pos)),
                }).collect::<Result<Vec<u8>, KslError>>()?
            }
            _ => return Err(KslError::type_error("net.udp_send: data must be an array<u8, 1024>".to_string(), pos)),
        };

        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| KslError::type_error(
                format!("net.udp_send failed to bind: {}", e),
                pos,
            ))?;
        let address = format!("{}:{}", host, port);
        socket.send_to(&data, &address)
            .map_err(|e| KslError::type_error(
                format!("net.udp_send failed: {}", e),
                pos,
            ))?;

        Ok(Value::U32(data.len() as u32))
    }
}

// HTTP POST function (async)
struct HttpPost {
    runtime: AsyncRuntime,
}

impl StdLibFunctionTrait for HttpPost {
    fn call(&self, args: Vec<Value>) -> Result<Value, KslError> {
        let pos = SourcePosition::new(1, 1);
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

        let client = Client::new();
        let response = client.post(url)
            .body(data.to_string())
            .send()
            .map_err(|e| KslError::type_error(
                format!("http.post failed: {}", e),
                pos,
            ))?
            .text()
            .map_err(|e| KslError::type_error(
                format!("http.post failed to read response: {}", e),
                pos,
            ))?;

        Ok(Value::String(response))
    }
}

// Assume ksl_stdlib.rs, ksl_async.rs, ksl_docgen.rs, and ksl_errors.rs are in the same crate
mod ksl_stdlib {
    pub use super::{StdLibFunctionTrait, StdLib, Value};
}

mod ksl_async {
    pub use super::AsyncRuntime;
}

mod ksl_docgen {
    pub use super::generate_docgen;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, UdpSocket};
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    #[test]
    fn test_tcp_connect() {
        // Start a TCP server for testing
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"Connected").unwrap();
        });

        // Test TCP connect
        let func = TcpConnect;
        let args = vec![
            Value::String("127.0.0.1".to_string()),
            Value::U32(port as u32),
        ];
        let result = func.call(args).unwrap();
        assert!(matches!(result, Value::U32(_)));
    }

    #[test]
    fn test_udp_send() {
        // Start a UDP server for testing
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        thread::spawn(move || {
            let mut buf = [0; 1024];
            let (amt, _) = socket.recv_from(&mut buf).unwrap();
            assert_eq!(amt, 5);
            assert_eq!(&buf[..amt], &[1, 2, 3, 4, 5]);
        });

        // Test UDP send
        let func = UdpSend;
        let args = vec![
            Value::String("127.0.0.1".to_string()),
            Value::U32(port as u32),
            Value::Array(vec![
                Value::U32(1),
                Value::U32(2),
                Value::U32(3),
                Value::U32(4),
                Value::U32(5),
            ], 1024),
        ];
        let result = func.call(args).unwrap();
        assert_eq!(result, Value::U32(5));
    }

    #[test]
    fn test_generate_docs() {
        let temp_dir = TempDir::new().unwrap();
        let net_lib = NetStdLib::new();
        let runtime = AsyncRuntime::new();
        let mut stdlib = StdLib::new();
        net_lib.register(&mut stdlib, &runtime).unwrap();

        let doc_file = temp_dir.path().join("net_stdlib.md");
        assert!(doc_file.exists());
        let content = fs::read_to_string(&doc_file).unwrap();
        assert!(content.contains("## Function `net.tcp_connect`"));
        assert!(content.contains("## Function `net.udp_send`"));
        assert!(content.contains("## Function `http.post`"));
    }
}
