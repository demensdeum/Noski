use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::error::Error;
use std::sync::Arc;
use std::io;
use tokio::sync::Mutex;
use std::env;
use dotenv::dotenv;
use noski::encryption::EncryptionLayer;
use noski::chacha20_encryption::ChaCha20Encryption;
use noski::obfuscated_encryption::ObfuscatedEncryption;
use noski::encrypted_stream::{EncryptedReader, EncryptedWriter, DeliveryControl};

const SOCKS_VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const USERNAME_PASSWORD_AUTH: u8 = 0x02;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const RSV: u8 = 0x00;

const AUTH_VERSION: u8 = 0x01;
const AUTH_SUCCESS: u8 = 0x00;
const AUTH_FAILURE: u8 = 0x01;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv().ok();

    let local_addr = env::var("PYATKI_LOCAL_ADDR").unwrap_or_else(|_| "127.0.0.1:1081".to_string());
    let remote_addr = env::var("NOSKI_REMOTE_ADDR").expect("NOSKI_REMOTE_ADDR must be set in .env");
    
    let socks_user = env::var("SOCKS_USER").ok();
    let socks_password = env::var("SOCKS_PASSWORD").ok();
    let require_auth = socks_user.is_some() && socks_password.is_some();
    
    if require_auth {
        println!("[*] SOCKS5 authentication enabled");
    } else {
        println!("[*] SOCKS5 authentication disabled");
    }
    
    let listener = TcpListener::bind(&local_addr).await?;
    println!("[*] Pyatki SOCKS5 Client listening on {}", local_addr);
    println!("[*] Forwarding to Noski Server at {}", remote_addr);

    let encryption_type = env::var("ENCRYPTION_TYPE").unwrap_or_else(|_| "chacha20".to_string());
    let encryption: Box<dyn EncryptionLayer> = match encryption_type.to_lowercase().as_str() {
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
        let socks_user_for_task = socks_user.clone();
        let socks_password_for_task = socks_password.clone();
        
        tokio::spawn(async move {
            if let Err(e) = handle_local_client(
                stream,
                remote_addr,
                encryption,
                socks_user_for_task,
                socks_password_for_task,
            ).await {
                eprintln!("[!] Error handling client {}: {}", addr, e);
            }
        });
    }
}

async fn handle_local_client(
    mut client_stream: TcpStream, 
    remote_addr: String, 
    encryption: Arc<Box<dyn EncryptionLayer>>,
    socks_user: Option<String>,
    socks_password: Option<String>
) -> Result<(), Box<dyn Error>> {
    // 1. Handshake with Local Client
    let mut header = [0u8; 2];
    client_stream.read_exact(&mut header).await?;

    if header[0] != SOCKS_VERSION {
        return Err("Invalid SOCKS version".into());
    }

    let nmethods = header[1];
    let mut methods = vec![0u8; nmethods as usize];
    client_stream.read_exact(&mut methods).await?;

    // Determine which authentication method to use
    let selected_method = if socks_user.is_some() && socks_password.is_some() {
        // If credentials are configured, prefer username/password auth
        if methods.contains(&USERNAME_PASSWORD_AUTH) {
            USERNAME_PASSWORD_AUTH
        } else if methods.contains(&NO_AUTH) {
            NO_AUTH
        } else {
            client_stream.write_all(&[SOCKS_VERSION, 0xFF]).await?;
            return Err("Client does not support any supported authentication method".into());
        }
    } else {
        // No credentials configured, use NO_AUTH if available
        if methods.contains(&NO_AUTH) {
            NO_AUTH
        } else {
            client_stream.write_all(&[SOCKS_VERSION, 0xFF]).await?;
            return Err("Client does not support No Authentication".into());
        }
    };
    
    client_stream.write_all(&[SOCKS_VERSION, selected_method]).await?;
    
    // If username/password authentication is selected, perform it
    if selected_method == USERNAME_PASSWORD_AUTH {
        let mut auth_header = [0u8; 2];
        client_stream.read_exact(&mut auth_header).await?;
        
        if auth_header[0] != AUTH_VERSION {
            return Err("Invalid authentication subnegotiation version".into());
        }
        
        let username_len = auth_header[1] as usize;
        let mut username_bytes = vec![0u8; username_len];
        client_stream.read_exact(&mut username_bytes).await?;
        
        let mut password_len_byte = [0u8; 1];
        client_stream.read_exact(&mut password_len_byte).await?;
        let password_len = password_len_byte[0] as usize;
        let mut password_bytes = vec![0u8; password_len];
        client_stream.read_exact(&mut password_bytes).await?;
        
        let username = String::from_utf8_lossy(&username_bytes);
        let password = String::from_utf8_lossy(&password_bytes);
        
        // Verify credentials
        if let (Some(ref expected_user), Some(ref expected_password)) = (&socks_user, &socks_password) {
            if username.as_ref() == expected_user.as_str() && password.as_ref() == expected_password.as_str() {
                client_stream.write_all(&[AUTH_VERSION, AUTH_SUCCESS]).await?;
                println!("[+] SOCKS5 authentication successful for user: {}", username);
            } else {
                client_stream.write_all(&[AUTH_VERSION, AUTH_FAILURE]).await?;
                eprintln!("[!] SOCKS5 authentication failed for user: {}", username);
                return Err("Authentication failed".into());
            }
        } else {
            client_stream.write_all(&[AUTH_VERSION, AUTH_FAILURE]).await?;
            return Err("Server authentication configuration error".into());
        }
    }

    // 2. Read Request from Local Client
    let mut request_header = [0u8; 4];
    client_stream.read_exact(&mut request_header).await?;

    let ver = request_header[0];
    let cmd = request_header[1];
    let atyp = request_header[3];

    if ver != SOCKS_VERSION {
        return Err("Invalid SOCKS version in request".into());
    }

    match cmd {
        CMD_CONNECT => {
            // Read target address from local client
            let (target_addr_bytes, _target_port) = read_addr_bytes_plain(&mut client_stream, atyp).await?;

            // 3. Connect to Remote Noski Server
            let remote_stream = TcpStream::connect(&remote_addr).await?;
            let control = Arc::new(DeliveryControl::new());
            
            let max_message_size = std::env::var("MESSAGE_SIZE")
                .unwrap_or_default()
                .parse::<usize>()
                .unwrap_or(1024 * 1024);

            let signature = std::env::var("MESSAGE_HEADER_SIGN").ok()
                .filter(|s| !s.is_empty())
                .map(|s| s.into_bytes());

            let (read_half, write_half) = remote_stream.into_split();
            let mut r = EncryptedReader::new(read_half, Arc::clone(&encryption), max_message_size, signature.clone(), Arc::clone(&control));
            let mut w = EncryptedWriter::new(write_half, Arc::clone(&encryption), signature, Arc::clone(&control));

            // Perform handshake over the encrypted stream
            remote_socks5_handshake_encrypted(&mut r, &mut w, &socks_user, &socks_password).await?;
            
            // 5. Send Request Header and Target Address
            w.write_encrypted(&[SOCKS_VERSION, CMD_CONNECT, RSV, atyp]).await?;
            w.write_encrypted(&target_addr_bytes).await?;

            // 8. Read Reply from Remote
            let mut reply_buf = [0u8; 1024];
            let (n, _seq) = r.read_encrypted(&mut reply_buf).await?;
            if n == 0 {
                return Err("Remote server closed connection during handshake".into());
            }
            let reply_bytes = reply_buf[..n].to_vec();

            // 9. Forward Reply to Local Client (Plaintext)
            client_stream.write_all(&reply_bytes).await?;

            // Check if reply indicates success (REP = 0x00)
            if reply_bytes.len() < 2 || reply_bytes[1] != 0x00 {
                return Err("Remote server returned error".into());
            }

            // 10. Relay Loop
            let (client_read, client_write) = client_stream.into_split();
            let shared_writer = Arc::new(tokio::sync::Mutex::new(w));

            let remote_to_client = relay_loop_encrypted_to_plain(r, client_write, Arc::clone(&shared_writer));
            let client_to_remote = relay_loop_plain_to_encrypted(client_read, Arc::clone(&shared_writer));
            tokio::spawn(heartbeat_loop(Arc::clone(&shared_writer)));

            tokio::select! {
                res = remote_to_client => {
                    if let Err(e) = res {
                        eprintln!("[!] Remote to client error: {}", e);
                    }
                },
                res = client_to_remote => {
                    if let Err(e) = res {
                        eprintln!("[!] Client to remote error: {}", e);
                    }
                },
            }

            Ok(())
        }
        CMD_UDP_ASSOCIATE => {
            handle_udp_associate(client_stream, atyp, remote_addr, socks_user, socks_password, encryption).await
        }
        _ => {
            send_reply_plain(&mut client_stream, 0x07, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), 0)).await?;
            Err(format!("Unsupported command: {}", cmd).into())
        }
    }
}

async fn remote_socks5_handshake_encrypted<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
    reader: &mut EncryptedReader<R>,
    writer: &mut EncryptedWriter<W>,
    socks_user: &Option<String>,
    socks_password: &Option<String>,
) -> Result<(), Box<dyn Error>> {
    // Send Init (advertise supported methods)
    if socks_user.is_some() && socks_password.is_some() {
        writer
            .write_encrypted(&[SOCKS_VERSION, 2, NO_AUTH, USERNAME_PASSWORD_AUTH])
            .await?;
    } else {
        writer.write_encrypted(&[SOCKS_VERSION, 1, NO_AUTH]).await?;
    }

    // Read Init Reply
    let mut remote_header = [0u8; 2];
    reader.read_encrypted(&mut remote_header).await?;
    if remote_header[0] != SOCKS_VERSION {
        return Err("Remote server invalid SOCKS version".into());
    }

    match remote_header[1] {
        NO_AUTH => Ok(()),
        USERNAME_PASSWORD_AUTH => {
            let (user, pass) = match (socks_user, socks_password) {
                (Some(u), Some(p)) => (u, p),
                _ => return Err("Remote server requires auth but SOCKS_USER/SOCKS_PASSWORD are not set".into()),
            };

            let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
            auth_req.push(AUTH_VERSION);
            auth_req.push(user.len() as u8);
            auth_req.extend_from_slice(user.as_bytes());
            auth_req.push(pass.len() as u8);
            auth_req.extend_from_slice(pass.as_bytes());
            writer.write_encrypted(&auth_req).await?;

            let mut auth_resp = [0u8; 2];
            reader.read_encrypted(&mut auth_resp).await?;
            if auth_resp[0] != AUTH_VERSION || auth_resp[1] != AUTH_SUCCESS {
                return Err("Remote server authentication failed".into());
            }
            Ok(())
        }
        0xFF => Err("Remote server rejected all authentication methods".into()),
        other => Err(format!("Remote server selected unsupported auth method: {}", other).into()),
    }
}

// Deprecated: passthrough mode removed

async fn handle_udp_associate(
    mut client_stream: TcpStream,
    atyp: u8,
    remote_addr: String,
    socks_user: Option<String>,
    socks_password: Option<String>,
    encryption: Arc<Box<dyn EncryptionLayer>>,
) -> Result<(), Box<dyn Error>> {
    // Read and ignore the client-provided address/port for UDP associate
    let (client_addr_bytes, _client_port) = read_addr_bytes_plain(&mut client_stream, atyp).await?;

    // Connect TCP control channel to remote server
    let remote_stream = TcpStream::connect(&remote_addr).await?;
    let control = Arc::new(DeliveryControl::new());
    
    let max_message_size = std::env::var("MESSAGE_SIZE")
        .unwrap_or_default()
        .parse::<usize>()
        .unwrap_or(1024 * 1024);

    let signature = std::env::var("MESSAGE_HEADER_SIGN").ok()
        .filter(|s| !s.is_empty())
        .map(|s| s.into_bytes());

    let (read_half, write_half) = remote_stream.into_split();
    let mut reader = EncryptedReader::new(read_half, Arc::clone(&encryption), max_message_size, signature.clone(), Arc::clone(&control));
    let mut writer = EncryptedWriter::new(write_half, Arc::clone(&encryption), signature, Arc::clone(&control));

    // Perform handshake over the encrypted stream
    remote_socks5_handshake_encrypted(&mut reader, &mut writer, &socks_user, &socks_password).await?;

    // Send UDP ASSOCIATE to remote
    writer.write_encrypted(&[SOCKS_VERSION, CMD_UDP_ASSOCIATE, RSV, atyp]).await?;
    writer.write_encrypted(&client_addr_bytes).await?;

    let (rep, remote_udp_relay) = read_socks5_reply_encrypted(&mut reader).await?;
    if rep != 0x00 {
        send_reply_plain(&mut client_stream, rep, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), 0)).await?;
        return Err("Remote server rejected UDP associate".into());
    }

    // Tell local client where to send UDP packets (local gateway)
    let local_ip = client_stream.local_addr()?.ip();
    let udp_socket = UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?;
    let local_udp_addr = udp_socket.local_addr()?;
    let local_udp_addr = SocketAddr::new(local_ip, local_udp_addr.port());

    send_reply_plain(&mut client_stream, 0x00, local_udp_addr).await?;

    let udp_socket = Arc::new(udp_socket);
    let mut buf = [0u8; 65535];
    let mut tcp_buf = [0u8; 1];
    let mut known_client_udp: Option<SocketAddr> = None;

    let shared_writer = Arc::new(Mutex::new(writer));
    tokio::spawn(heartbeat_loop(Arc::clone(&shared_writer)));

    let mut control_buf = [0u8; 1024];
    loop {
        tokio::select! {
            res = reader.read_encrypted(&mut control_buf) => {
                // If TCP control channel closes or has error
                if let Err(e) = res {
                    eprintln!("[!] UDP control channel error: {}", e);
                }
                break;
            }
            res = client_stream.read(&mut tcp_buf) => {
                if res.unwrap_or(0) == 0 {
                    break;
                }
            }
            res = udp_socket.recv_from(&mut buf) => {
                match res {
                    Ok((size, src_addr)) => {
                        let data = &buf[..size];

                        if known_client_udp.is_none() {
                            known_client_udp = Some(src_addr);
                        }

                        // Local client -> remote relay
                        if Some(src_addr) == known_client_udp {
                            let _ = udp_socket.send_to(data, remote_udp_relay).await;
                        } else if src_addr == remote_udp_relay {
                            // Remote relay -> local client
                            if let Some(client_udp) = known_client_udp {
                                let _ = udp_socket.send_to(data, client_udp).await;
                            }
                        }
                    }
                    Err(e) => eprintln!("[!] UDP Recv Error: {}", e),
                }
            }
        }
    }

    Ok(())
}

async fn read_socks5_reply_encrypted<R: tokio::io::AsyncRead + Unpin>(reader: &mut EncryptedReader<R>) -> Result<(u8, SocketAddr), Box<dyn Error>> {
    let mut header = [0u8; 4];
    reader.read_encrypted(&mut header).await?;
    if header[0] != SOCKS_VERSION {
        return Err("Invalid SOCKS version in reply".into());
    }
    let rep = header[1];
    let atyp = header[3];

    let ip = match atyp {
        ATYP_IPV4 => {
            let mut bytes = [0u8; 4];
            reader.read_encrypted(&mut bytes).await?;
            IpAddr::V4(Ipv4Addr::from(bytes))
        }
        ATYP_IPV6 => {
            let mut bytes = [0u8; 16];
            reader.read_encrypted(&mut bytes).await?;
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        ATYP_DOMAIN => {
            let mut len_byte = [0u8; 1];
            reader.read_encrypted(&mut len_byte).await?;
            let len = len_byte[0] as usize;
            let mut domain_bytes = vec![0u8; len];
            reader.read_encrypted(&mut domain_bytes).await?;
            let domain = String::from_utf8(domain_bytes)?;
            let _ = domain;
            IpAddr::V4(Ipv4Addr::new(0,0,0,0))
        }
        _ => return Err("Unknown ATYP in reply".into()),
    };

    let mut port_bytes = [0u8; 2];
    reader.read_encrypted(&mut port_bytes).await?;
    let port = u16::from_be_bytes(port_bytes);

    Ok((rep, SocketAddr::new(ip, port)))
}

async fn send_reply_plain(stream: &mut TcpStream, rep: u8, bind_addr: SocketAddr) -> Result<(), Box<dyn Error>> {
    let mut response = vec![SOCKS_VERSION, rep, RSV];

    match bind_addr.ip() {
        IpAddr::V4(ip) => {
            response.push(ATYP_IPV4);
            response.extend_from_slice(&ip.octets());
        },
        IpAddr::V6(ip) => {
            response.push(ATYP_IPV6);
            response.extend_from_slice(&ip.octets());
        }
    }

    response.extend_from_slice(&bind_addr.port().to_be_bytes());
    stream.write_all(&response).await?;
    Ok(())
}

async fn read_addr_bytes_plain(stream: &mut TcpStream, atyp: u8) -> Result<(Vec<u8>, u16), Box<dyn Error>> {
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

async fn relay_loop_encrypted_to_plain(
    mut reader: noski::encrypted_stream::EncryptedReader<tokio::net::tcp::OwnedReadHalf>,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    shared_writer: Arc<tokio::sync::Mutex<noski::encrypted_stream::EncryptedWriter<tokio::net::tcp::OwnedWriteHalf>>>,
) -> io::Result<()> {
    let mut buf = vec![0u8; 8192];
    loop {
        let (n, seq) = reader.read_encrypted(&mut buf).await?;
        if n == 0 && seq == 0 { break; }

        if seq & 0x80000000 != 0 {
            // Heartbeat PING
            let mut w = shared_writer.lock().await;
            w.send_pong(seq & 0x7FFFFFFF).await?;
            continue;
        }

        if n > 0 {
            writer.write_all(&buf[..n]).await?;
            if seq != 0 {
                let mut w = shared_writer.lock().await;
                w.send_ack(seq).await?;
            }
        }
    }
    Ok(())
}

async fn relay_loop_plain_to_encrypted(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    shared_writer: Arc<tokio::sync::Mutex<noski::encrypted_stream::EncryptedWriter<tokio::net::tcp::OwnedWriteHalf>>>,
) -> io::Result<()> {
    let mut buf = vec![0u8; 8192];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 { break; }

        let mut w = shared_writer.lock().await;
        w.write_encrypted(&buf[..n]).await?;
    }
    Ok(())
}

async fn heartbeat_loop(
    shared_writer: Arc<tokio::sync::Mutex<noski::encrypted_stream::EncryptedWriter<tokio::net::tcp::OwnedWriteHalf>>>,
) -> io::Result<()> {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        let mut w = shared_writer.lock().await;
        w.send_ping().await?;
    }
}
