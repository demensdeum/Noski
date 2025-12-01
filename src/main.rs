use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::error::Error;
use std::sync::Arc;
use std::env;
use dotenv::dotenv;

const SOCKS_VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const AUTH_USER_PASS: u8 = 0x02;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const RSV: u8 = 0x00;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv().ok();

    let addr = "127.0.0.1:1080";
    let listener = TcpListener::bind(addr).await?;

    // Check auth status for logging
    if env::var("SOCKS_USER").is_ok() && env::var("SOCKS_PASSWORD").is_ok() {
        println!("[*] SOCKS5 Proxy listening on {} (Auth Enabled)", addr);
    } else {
        println!("[*] SOCKS5 Proxy listening on {} (OPEN PROXY - No Auth)", addr);
    }

    loop {
        let (stream, addr) = listener.accept().await?;
        println!("[+] Accepted connection from {}", addr);

        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, addr).await {
                eprintln!("[!] Error handling client {}: {}", addr, e);
            }
        });
    }
}

async fn handle_client(mut stream: TcpStream, client_addr: SocketAddr) -> Result<(), Box<dyn Error>> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;

    if header[0] != SOCKS_VERSION {
        return Err("Invalid SOCKS version".into());
    }

    let nmethods = header[1];
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;

    // Determine authentication mode based on environment variables
    let has_user = env::var("SOCKS_USER").is_ok();
    let has_pass = env::var("SOCKS_PASSWORD").is_ok();

    if has_user && has_pass {
        // Auth Mode
        if !methods.contains(&AUTH_USER_PASS) {
            stream.write_all(&[SOCKS_VERSION, 0xFF]).await?;
            return Err("Client does not support Username/Password authentication".into());
        }
        stream.write_all(&[SOCKS_VERSION, AUTH_USER_PASS]).await?;
        authenticate(&mut stream).await?;
    } else {
        // No Auth Mode
        if !methods.contains(&NO_AUTH) {
            stream.write_all(&[SOCKS_VERSION, 0xFF]).await?;
            return Err("Client does not support No Authentication".into());
        }
        stream.write_all(&[SOCKS_VERSION, NO_AUTH]).await?;
    }

    let mut request_header = [0u8; 4];
    stream.read_exact(&mut request_header).await?;

    let ver = request_header[0];
    let cmd = request_header[1];
    let atyp = request_header[3];

    if ver != SOCKS_VERSION {
        return Err("Invalid SOCKS version in request".into());
    }

    match cmd {
        CMD_CONNECT => handle_tcp(stream, atyp).await,
        CMD_UDP_ASSOCIATE => handle_udp(stream, atyp, client_addr).await,
        _ => {
            send_reply(&mut stream, 0x07, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), 0)).await?;
            Err(format!("Unsupported command: {}", cmd).into())
        }
    }
}

async fn authenticate(stream: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    let mut auth_header = [0u8; 2];
    stream.read_exact(&mut auth_header).await?;

    let ver = auth_header[0];
    let ulen = auth_header[1];

    if ver != 0x01 {
        return Err("Unsupported auth protocol version".into());
    }

    let mut username_bytes = vec![0u8; ulen as usize];
    stream.read_exact(&mut username_bytes).await?;
    let username = String::from_utf8_lossy(&username_bytes);

    let mut plen_byte = [0u8; 1];
    stream.read_exact(&mut plen_byte).await?;
    let plen = plen_byte[0];

    let mut password_bytes = vec![0u8; plen as usize];
    stream.read_exact(&mut password_bytes).await?;
    let password = String::from_utf8_lossy(&password_bytes);

    println!("[*] Auth attempt: {} / ...", username);

    let valid_user = env::var("SOCKS_USER").unwrap_or_else(|_| "".to_string());
    let valid_pass = env::var("SOCKS_PASSWORD").unwrap_or_else(|_| "".to_string());

    if username == valid_user && password == valid_pass {
        stream.write_all(&[0x01, 0x00]).await?;
        Ok(())
    } else {
        stream.write_all(&[0x01, 0x01]).await?;
        Err("Authentication failed".into())
    }
}

async fn handle_tcp(mut client_stream: TcpStream, atyp: u8) -> Result<(), Box<dyn Error>> {
    let target_addr = read_addr_port(&mut client_stream, atyp).await?;

    println!("[*] TCP Request to {}", target_addr);

    match TcpStream::connect(&target_addr).await {
        Ok(mut target_stream) => {
            let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
            send_reply(&mut client_stream, 0x00, bind_addr).await?;

            let (mut client_read, mut client_write) = client_stream.split();
            let (mut target_read, mut target_write) = target_stream.split();

            let client_to_target = tokio::io::copy(&mut client_read, &mut target_write);
            let target_to_client = tokio::io::copy(&mut target_read, &mut client_write);

            tokio::select! {
                _ = client_to_target => {},
                _ = target_to_client => {},
            }
        }
        Err(e) => {
            eprintln!("[!] Failed to connect to target: {}", e);
            let empty_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
            send_reply(&mut client_stream, 0x01, empty_addr).await?;
        }
    }

    Ok(())
}

async fn handle_udp(mut client_stream: TcpStream, atyp: u8, client_addr: SocketAddr) -> Result<(), Box<dyn Error>> {
    let _ = read_addr_port(&mut client_stream, atyp).await?;

    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let relay_addr = udp_socket.local_addr()?;

    println!("[*] UDP Associate: Allocated {} for client {}", relay_addr, client_addr);

    send_reply(&mut client_stream, 0x00, relay_addr).await?;

    let udp_socket = Arc::new(udp_socket);
    let mut buf = [0u8; 65535];
    let mut tcp_buf = [0u8; 1];
    let mut known_client_udp: Option<SocketAddr> = None;

    loop {
        tokio::select! {
            res = client_stream.read(&mut tcp_buf) => {
                if res.unwrap_or(0) == 0 {
                    println!("[*] TCP Control channel closed. Stopping UDP.");
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

                        if Some(src_addr) == known_client_udp {
                            if let Some((target_addr, payload)) = unwrap_udp_header(data) {
                                let _ = udp_socket.send_to(payload, target_addr).await;
                            }
                        } else {
                            if let Some(client_udp) = known_client_udp {
                                let packet = wrap_udp_header(src_addr, data);
                                let _ = udp_socket.send_to(&packet, client_udp).await;
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

async fn read_addr_port(stream: &mut TcpStream, atyp: u8) -> Result<String, Box<dyn Error>> {
    let host: String;

    match atyp {
        ATYP_IPV4 => {
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).await?;
            host = Ipv4Addr::from(bytes).to_string();
        },
        ATYP_DOMAIN => {
            let mut len_byte = [0u8; 1];
            stream.read_exact(&mut len_byte).await?;
            let len = len_byte[0] as usize;
            let mut domain_bytes = vec![0u8; len];
            stream.read_exact(&mut domain_bytes).await?;
            host = String::from_utf8(domain_bytes)?;
        },
        ATYP_IPV6 => {
            let mut bytes = [0u8; 16];
            stream.read_exact(&mut bytes).await?;
            host = Ipv6Addr::from(bytes).to_string();
        },
        _ => return Err("Unknown address type".into()),
    }

    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    let port = u16::from_be_bytes(port_bytes);

    Ok(format!("{}:{}", host, port))
}

async fn send_reply(stream: &mut TcpStream, rep: u8, bind_addr: SocketAddr) -> Result<(), Box<dyn Error>> {
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

fn unwrap_udp_header(data: &[u8]) -> Option<(String, &[u8])> {
    if data.len() < 4 || data[0] != 0 || data[1] != 0 || data[2] != 0 {
        return None;
    }

    let atyp = data[3];
    let mut offset = 4;

    let host: String;

    match atyp {
        ATYP_IPV4 => {
            if data.len() < offset + 4 { return None; }
            let bytes: [u8; 4] = data[offset..offset+4].try_into().ok()?;
            host = Ipv4Addr::from(bytes).to_string();
            offset += 4;
        },
        ATYP_DOMAIN => {
            if data.len() < offset + 1 { return None; }
            let len = data[offset] as usize;
            offset += 1;
            if data.len() < offset + len { return None; }
            host = String::from_utf8(data[offset..offset+len].to_vec()).ok()?;
            offset += len;
        },
        ATYP_IPV6 => {
            if data.len() < offset + 16 { return None; }
            let bytes: [u8; 16] = data[offset..offset+16].try_into().ok()?;
            host = Ipv6Addr::from(bytes).to_string();
            offset += 16;
        },
        _ => return None,
    }

    if data.len() < offset + 2 { return None; }
    let port_bytes: [u8; 2] = data[offset..offset+2].try_into().ok()?;
    let port = u16::from_be_bytes(port_bytes);
    offset += 2;

    Some((format!("{}:{}", host, port), &data[offset..]))
}

fn wrap_udp_header(src_addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut header = vec![0x00, 0x00, 0x00];

    match src_addr.ip() {
        IpAddr::V4(ip) => {
            header.push(ATYP_IPV4);
            header.extend_from_slice(&ip.octets());
        },
        IpAddr::V6(ip) => {
            header.push(ATYP_IPV6);
            header.extend_from_slice(&ip.octets());
        }
    }

    header.extend_from_slice(&src_addr.port().to_be_bytes());
    header.extend_from_slice(payload);
    header
}
