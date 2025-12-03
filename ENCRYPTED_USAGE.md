# Encrypted SOCKS5 Proxy - Usage Guide

## Overview

The Noski SOCKS5 proxy now features **ChaCha20-Poly1305 encryption** for all traffic between the client and the proxy server. This provides:

- **Confidentiality**: All data is encrypted
- **Integrity**: Authentication tags prevent tampering
- **Modern cryptography**: ChaCha20-Poly1305 is fast and secure

## Important: Client-Proxy Encryption

**Traffic Flow:**
```
[Client] <--ENCRYPTED--> [Proxy] <--PLAIN--> [Target Server]
```

- Traffic between **client and proxy** is **encrypted** with ChaCha20-Poly1305
- Traffic between **proxy and target** is **plain** (unless the target uses HTTPS/TLS)

## Setup

### 1. First Run - Generate Encryption Key

Run the proxy for the first time:

```bash
cargo run --release
```

You'll see output like:

```
[*] Generated new encryption key: a1b2c3d4e5f6...
[!] Save this key to .env as: ENCRYPTION_KEY=a1b2c3d4e5f6...
[!] Clients must use the same key to connect!
[*] SOCKS5 Proxy listening on 127.0.0.1:1080 (OPEN PROXY - No Auth)
[*] Encryption Layer: chacha20-poly1305
```

### 2. Save the Encryption Key

Copy the generated key and add it to your `.env` file:

```bash
ENCRYPTION_KEY=a1b2c3d4e5f6...
SOCKS_USER=myuser
SOCKS_PASSWORD=mypassword
```

### 3. Restart the Proxy

```bash
cargo run --release
```

Now you'll see:

```
[*] Loaded encryption key from ENCRYPTION_KEY environment variable
[*] SOCKS5 Proxy listening on 127.0.0.1:1080 (Auth Enabled)
[*] Encryption Layer: chacha20-poly1305
```

## Client Implementation

Clients must implement the same encryption protocol to connect. Here's how the protocol works:

### Message Format

All messages between client and proxy are encrypted and framed:

```
[4 bytes: length] [encrypted data]
```

- **Length**: 32-bit big-endian integer (size of encrypted data)
- **Encrypted data**: ChaCha20-Poly1305 ciphertext with prepended nonce

### Encrypted Data Format

```
[12 bytes: nonce] [ciphertext + 16 bytes auth tag]
```

### Example Client Pseudocode

```python
import socket
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

key = bytes.fromhex("YOUR_ENCRYPTION_KEY_HERE")
cipher = ChaCha20Poly1305(key)

def send_encrypted(sock, data):
    nonce = os.urandom(12)
    ciphertext = cipher.encrypt(nonce, data, None)
    encrypted = nonce + ciphertext
    length = len(encrypted).to_bytes(4, 'big')
    sock.sendall(length + encrypted)

def recv_encrypted(sock):
    length_bytes = sock.recv(4)
    length = int.from_bytes(length_bytes, 'big')
    encrypted = sock.recv(length)
    nonce = encrypted[:12]
    ciphertext = encrypted[12:]
    return cipher.decrypt(nonce, ciphertext, None)

sock = socket.socket()
sock.connect(('127.0.0.1', 1080))

send_encrypted(sock, b'\x05\x01\x00')
response = recv_encrypted(sock)
```

## Security Considerations

### What's Protected

✅ SOCKS5 handshake is encrypted  
✅ Authentication credentials are encrypted  
✅ Target addresses/domains are encrypted  
✅ All data between client and proxy is encrypted  

### What's NOT Protected

❌ Traffic between proxy and target server (unless target uses HTTPS/TLS)  
❌ DNS queries (if proxy resolves domains)  
❌ Metadata (connection timing, packet sizes)  

### Recommendations

1. **Use HTTPS**: For end-to-end encryption, access HTTPS websites
2. **Secure the key**: Store `ENCRYPTION_KEY` securely
3. **Rotate keys**: Periodically generate new keys
4. **Use authentication**: Always set `SOCKS_USER` and `SOCKS_PASSWORD`
5. **Network security**: Run proxy on trusted networks only

## Key Management

### Generate a New Key

```bash
# The proxy will generate one automatically if ENCRYPTION_KEY is not set
cargo run --release
```

Or generate manually:

```bash
# Using OpenSSL
openssl rand -hex 32

# Using Python
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### Distribute Keys to Clients

**Secure methods:**
- In-person transfer
- Encrypted messaging (Signal, etc.)
- Secure key management system

**NEVER:**
- Send via plain email
- Post in public channels
- Commit to version control

## Troubleshooting

### "Decryption failed" errors

- Client and server have different encryption keys
- Check that `ENCRYPTION_KEY` matches on both sides

### Connection drops immediately

- Client not implementing encryption protocol
- Verify client is sending encrypted messages

### "Data too short for nonce" errors

- Client sending malformed encrypted messages
- Check message framing (4-byte length prefix)

## Performance

ChaCha20-Poly1305 is designed for high performance:

- **Fast**: Optimized for modern CPUs
- **Low overhead**: ~16 bytes per message (nonce + auth tag)
- **Stream-friendly**: Efficient for continuous data transfer

Typical overhead: < 5% for large transfers

## Protocol Specification

### Full SOCKS5 Handshake (Encrypted)

1. **Client → Proxy**: Encrypted SOCKS5 greeting
   ```
   [length][encrypted: 0x05 0x01 0x00]
   ```

2. **Proxy → Client**: Encrypted method selection
   ```
   [length][encrypted: 0x05 0x00]
   ```

3. **Client → Proxy**: Encrypted connection request
   ```
   [length][encrypted: 0x05 0x01 0x00 0x01 <IP> <PORT>]
   ```

4. **Proxy → Client**: Encrypted reply
   ```
   [length][encrypted: 0x05 0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00]
   ```

5. **Data transfer**: All subsequent data is encrypted

## Example: Complete Connection

```
Client                          Proxy                    Target
  |                               |                         |
  |--[ENC: SOCKS5 greeting]------>|                         |
  |<-[ENC: Method selection]------|                         |
  |--[ENC: Connect request]------>|                         |
  |                               |----[TCP connect]------->|
  |<-[ENC: Success reply]---------|                         |
  |--[ENC: HTTP GET /]----------->|----[HTTP GET /]-------->|
  |<-[ENC: HTTP response]---------|<---[HTTP response]------|
  |                               |                         |
```

## Migration from Unencrypted

If you have existing clients using the old unencrypted proxy:

1. Keep old proxy running on port 1080
2. Start encrypted proxy on port 1081
3. Migrate clients one by one
4. Shut down old proxy when all clients migrated

## License

Same as main project (see LICENSE file)
