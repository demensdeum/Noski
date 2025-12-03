# Quick Start Guide

## Option 1: Standard SOCKS5 (No Encryption) - Use with curl, browsers, etc.

### Setup

Add to `.env`:
```
ENCRYPTION_TYPE=passthrough
```

Or run directly:
```bash
ENCRYPTION_TYPE=passthrough cargo run --release
```

### Output
```
[!] ENCRYPTION DISABLED - Using passthrough mode
[!] This mode is compatible with standard SOCKS5 clients
[!] WARNING: All traffic between client and proxy is UNENCRYPTED!
[*] SOCKS5 Proxy listening on 127.0.0.1:1080 (OPEN PROXY - No Auth)
[*] Encryption Layer: passthrough
```

### Usage with curl

```bash
curl -x socks5://127.0.0.1:1080 https://www.google.com
```

With authentication (add to `.env`):
```
ENCRYPTION_TYPE=passthrough
SOCKS_USER=myuser
SOCKS_PASSWORD=mypass
```

Then:
```bash
curl -x socks5://myuser:mypass@127.0.0.1:1080 https://www.google.com
```

### Usage with browsers

**Firefox:**
1. Settings → Network Settings → Manual proxy configuration
2. SOCKS Host: `127.0.0.1`
3. Port: `1080`
4. Select: SOCKS v5

**Chrome/Edge:**
```bash
chrome.exe --proxy-server="socks5://127.0.0.1:1080"
```

---

## Option 2: Encrypted Mode (ChaCha20-Poly1305) - Requires custom client

### Setup

**First run** (generates key):
```bash
cargo run --release
```

Output:
```
[*] Generated new encryption key: a1b2c3d4e5f6789...
[!] Save this key to .env as: ENCRYPTION_KEY=a1b2c3d4e5f6789...
[!] Clients must use the same key to connect!
[*] Encryption Layer: chacha20-poly1305
```

**Save the key** to `.env`:
```
ENCRYPTION_KEY=a1b2c3d4e5f6789...
```

**Subsequent runs**:
```bash
cargo run --release
```

Output:
```
[*] Loaded encryption key from ENCRYPTION_KEY environment variable
[*] Encryption Layer: chacha20-poly1305
```

### Usage

Requires custom client implementation. See [ENCRYPTED_USAGE.md](ENCRYPTED_USAGE.md) for details.

---

## Comparison

| Feature | Passthrough Mode | Encrypted Mode |
|---------|------------------|----------------|
| **Client compatibility** | ✅ Standard SOCKS5 clients | ❌ Custom client required |
| **Encryption** | ❌ None | ✅ ChaCha20-Poly1305 |
| **Setup difficulty** | ✅ Easy | ⚠️ Moderate |
| **Use with curl** | ✅ Yes | ❌ No |
| **Use with browsers** | ✅ Yes | ❌ No |
| **Security** | ⚠️ Unencrypted | ✅ Encrypted |
| **Best for** | Testing, local dev | Production, privacy |

---

## Configuration Options

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `ENCRYPTION_TYPE` | Encryption mode: `passthrough`, `chacha20` | `passthrough` |
| `ENCRYPTION_KEY` | 256-bit encryption key (64 hex chars) | `a1b2c3d4...` |
| `SOCKS_USER` | Username for authentication | `myuser` |
| `SOCKS_PASSWORD` | Password for authentication | `mypass` |

### Example `.env` files

**Passthrough with auth:**
```
ENCRYPTION_TYPE=passthrough
SOCKS_USER=admin
SOCKS_PASSWORD=secret123
```

**Encrypted with auth:**
```
ENCRYPTION_TYPE=chacha20
ENCRYPTION_KEY=a1b2c3d4e5f6789abcdef...
SOCKS_USER=admin
SOCKS_PASSWORD=secret123
```

**Passthrough without auth (not recommended):**
```
ENCRYPTION_TYPE=passthrough
```

---

## Testing

### Test passthrough mode with curl

```bash
# Start proxy in passthrough mode
ENCRYPTION_TYPE=passthrough cargo run --release

# In another terminal
curl -v -x socks5://127.0.0.1:1080 https://www.google.com
```

### Test encrypted mode

See [ENCRYPTED_USAGE.md](ENCRYPTED_USAGE.md) for client implementation examples.

---

## Troubleshooting

### "Connection refused"
- Proxy not running
- Check if port 1080 is available

### "Authentication failed"
- Wrong username/password
- Check `SOCKS_USER` and `SOCKS_PASSWORD` in `.env`

### curl doesn't work
- Make sure `ENCRYPTION_TYPE=passthrough` is set
- Encrypted mode requires custom client

### "Decryption failed"
- Wrong encryption key
- Client and server keys must match
- Or you're using standard client with encrypted mode

---

## Recommendations

**For development/testing:**
```bash
ENCRYPTION_TYPE=passthrough cargo run --release
```

**For production:**
```bash
# Set in .env:
ENCRYPTION_TYPE=chacha20
ENCRYPTION_KEY=<your-key>
SOCKS_USER=<username>
SOCKS_PASSWORD=<password>

cargo run --release
```
