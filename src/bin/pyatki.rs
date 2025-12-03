use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::error::Error;
use std::sync::Arc;
use std::env;
use dotenv::dotenv;
use noski::encryption::{EncryptionLayer, PassthroughEncryption};
use noski::chacha20_encryption::ChaCha20Encryption;
use noski::obfuscated_encryption::ObfuscatedEncryption;
use noski::encrypted_stream::{EncryptedReader, EncryptedWriter, copy_encrypted_to_plain, copy_plain_to_encrypted};

const SOCKS_VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const RSV: u8 = 0x00;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv().ok();

    let local_addr = env::var("PYATKI_LOCAL_ADDR").unwrap_or_else(|_| "127.0.0.1:1081".to_string());
    let remote_addr = env::var("NOSKI_REMOTE_ADDR").expect("NOSKI_REMOTE_ADDR must be set in .env");
    
    let listener = TcpListener::bind(&local_addr).await?;
    println!("[*] Pyatki SOCKS5 Client listening on {}", local_addr);
    println!("[*] Forwarding to Noski Server at {}", remote_addr);

    let encryption_type = env::var("ENCRYPTION_TYPE").unwrap_or_else(|_| "chacha20".to_string());
    let encryption: Box<dyn EncryptionLayer> = match encryption_type.to_lowercase().as_str() {
        "passthrough" | "none" | "disabled" => {
            println!("[!] ENCRYPTION DISABLED - Using passthrough mode");
            Box::new(PassthroughEncryption::new())
        }
        "chacha20" | "chacha20-poly1305" | "encrypted" => {
            match ChaCha20Encryption::from_env() {
                Ok(enc) => {
                    println!("[*] Loaded encryption key from ENCRYPTION_KEY");
                    Box::new(enc)
                }
                Err(_) => {
                    eprintln!("[!] ENCRYPTION_KEY not found. Cannot start in encrypted mode.");
                    return Err("Missing ENCRYPTION_KEY".into());
                }
            }
        }
        "obfuscated" | "dpi" | "tls" => {
            match ObfuscatedEncryption::from_env() {
                Ok(enc) => {
                    println!("[*] Loaded encryption key from ENCRYPTION_KEY");
                    println!("[*] Using obfuscated mode - DPI evasion enabled");
                    Box::new(enc)
                }
                Err(_) => {
                    eprintln!("[!] ENCRYPTION_KEY not found. Cannot start in obfuscated mode.");
                    return Err("Missing ENCRYPTION_KEY".into());
                }
            }
        }
        _ => {
            eprintln!("[!] Invalid ENCRYPTION_TYPE: '{}'", encryption_type);
            return Err("Invalid ENCRYPTION_TYPE".into());
        }
    };
    
    let encryption = Arc::new(encryption);
    let remote_addr_str = remote_addr.clone();

    loop {
        let (stream, addr) = listener.accept().await?;
        println!("[+] Accepted local connection from {}", addr);

        let encryption = Arc::clone(&encryption);
        let remote_addr = remote_addr_str.clone();
        
        tokio::spawn(async move {
            if let Err(e) = handle_local_client(stream, remote_addr, encryption).await {
                eprintln!("[!] Error handling client {}: {}", addr, e);
            }
        });
    }
}

async fn handle_local_client(mut client_stream: TcpStream, remote_addr: String, encryption: Arc<Box<dyn EncryptionLayer>>) -> Result<(), Box<dyn Error>> {
    // 1. Handshake with Local Client
    let mut header = [0u8; 2];
    client_stream.read_exact(&mut header).await?;

    if header[0] != SOCKS_VERSION {
        return Err("Invalid SOCKS version".into());
    }

    let nmethods = header[1];
    let mut methods = vec![0u8; nmethods as usize];
    client_stream.read_exact(&mut methods).await?;

    // We only support NO AUTH for local clients for simplicity
    if !methods.contains(&NO_AUTH) {
        client_stream.write_all(&[SOCKS_VERSION, 0xFF]).await?;
        return Err("Client does not support No Authentication".into());
    }
    client_stream.write_all(&[SOCKS_VERSION, NO_AUTH]).await?;

    // 2. Read Request from Local Client
    let mut request_header = [0u8; 4];
    client_stream.read_exact(&mut request_header).await?;

    let ver = request_header[0];
    let cmd = request_header[1];
    let atyp = request_header[3];

    if ver != SOCKS_VERSION {
        return Err("Invalid SOCKS version in request".into());
    }

    if cmd != CMD_CONNECT {
        return Err(format!("Unsupported command: {}", cmd).into());
    }

    // Read target address from local client
    let (target_addr_bytes, _target_port) = read_addr_bytes(&mut client_stream, atyp).await?;

    // 3. Connect to Remote Noski Server
    let mut remote_stream = TcpStream::connect(&remote_addr).await?;
    
    // 4. Handshake with Remote Noski Server
    // Send Init
    remote_stream.write_all(&[SOCKS_VERSION, 1, NO_AUTH]).await?;
    
    // Read Init Reply
    let mut remote_header = [0u8; 2];
    remote_stream.read_exact(&mut remote_header).await?;
    if remote_header[0] != SOCKS_VERSION || remote_header[1] != NO_AUTH {
        // Try Auth? For now assume Noski is configured with NO_AUTH or we need to implement auth
        // The user didn't specify auth requirements for pyatki -> noski, but noski supports it.
        // Let's assume NO_AUTH for now as per the prompt "work as local socks server".
        return Err("Remote server refused NO_AUTH".into());
    }

    // 5. Send Request Header to Remote (Plaintext)
    // We forward the same ATYP
    remote_stream.write_all(&[SOCKS_VERSION, CMD_CONNECT, RSV, atyp]).await?;

    // 6. Setup Encryption
    let (remote_read, remote_write) = remote_stream.into_split();
    let mut encrypted_writer = EncryptedWriter::new(remote_write, Arc::clone(&encryption));
    let mut encrypted_reader = EncryptedReader::new(remote_read, Arc::clone(&encryption));

    // 7. Send Encrypted Target Address
    encrypted_writer.write_encrypted(&target_addr_bytes).await?;

    // 8. Read Encrypted Reply from Remote
    let mut reply_buf = [0u8; 1024];
    let n = encrypted_reader.read_encrypted(&mut reply_buf).await?;
    if n == 0 {
        return Err("Remote server closed connection during handshake".into());
    }
    let reply_bytes = &reply_buf[..n];
    
    // 9. Forward Reply to Local Client (Plaintext)
    client_stream.write_all(&reply_bytes).await?;

    // Check if reply indicates success (REP = 0x00)
    if reply_bytes.len() < 2 || reply_bytes[1] != 0x00 {
        return Err("Remote server returned error".into());
    }

    // 10. Relay Loop
    let (mut client_read, mut client_write) = client_stream.into_split();

    let client_to_remote = copy_plain_to_encrypted(&mut client_read, &mut encrypted_writer);
    let remote_to_client = copy_encrypted_to_plain(&mut encrypted_reader, &mut client_write);

    tokio::select! {
        _ = client_to_remote => {},
        _ = remote_to_client => {},
    }

    Ok(())
}

async fn read_addr_bytes(stream: &mut TcpStream, atyp: u8) -> Result<(Vec<u8>, u16), Box<dyn Error>> {
    let mut buf = Vec::new();
    let port;

    match atyp {
        ATYP_IPV4 => {
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).await?;
            buf.extend_from_slice(&bytes);
        },
        ATYP_DOMAIN => {
            let mut len_byte = [0u8; 1];
            stream.read_exact(&mut len_byte).await?;
            buf.push(len_byte[0]);
            let mut domain_bytes = vec![0u8; len_byte[0] as usize];
            stream.read_exact(&mut domain_bytes).await?;
            buf.extend_from_slice(&domain_bytes);
        },
        ATYP_IPV6 => {
            let mut bytes = [0u8; 16];
            stream.read_exact(&mut bytes).await?;
            buf.extend_from_slice(&bytes);
        },
        _ => return Err("Unknown address type".into()),
    }

    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    buf.extend_from_slice(&port_bytes);
    port = u16::from_be_bytes(port_bytes);

    Ok((buf, port))
}

// Helper to read a packet from EncryptedReader since it doesn't expose it directly in the trait?
// Wait, `EncryptedReader` struct has `read_encrypted` which reads into a buffer.
// But we don't know the size of the reply beforehand.
// Noski `write_encrypted` writes: [Len: u16][Data].
// `read_encrypted` reads [Len], then reads [Data] into provided buffer.
// If provided buffer is too small, it errors?
// Let's check `encrypted_stream.rs`.
// I need to add `read_packet` to `EncryptedReader` or implement it here.
// But `EncryptedReader` fields are private?
// I'll check `encrypted_stream.rs` content.
