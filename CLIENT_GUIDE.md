# Pyatki - SOCKS5 Client for Noski

**Pyatki** ("Heels") is the companion client for **Noski** ("Socks"). It acts as a local SOCKS5 server that transparently handles encryption/decryption when communicating with a remote Noski server.

## Architecture

```
[App (Browser/Curl)] --(Plain SOCKS5)--> [Pyatki Client] --(Encrypted)--> [Noski Server] --(Plain)--> [Target]
```

This allows you to use **any standard SOCKS5 application** with the encrypted Noski proxy.

## Build

```bash
cargo build --release --bin pyatki
```

The binary will be at `target/release/pyatki`.

## Configuration

Pyatki is configured via environment variables or a `.env` file.

| Variable | Description | Default |
|----------|-------------|---------|
| `PYATKI_LOCAL_ADDR` | Local address to listen on | `127.0.0.1:1081` |
| `NOSKI_REMOTE_ADDR` | Address of the remote Noski server | **Required** |
| `ENCRYPTION_TYPE` | Encryption mode (`chacha20`, `obfuscated`) | `chacha20` |
| `ENCRYPTION_KEY` | Shared encryption key | **Required** (if encrypted) |

## Usage Examples

### 1. Basic Encrypted Mode (ChaCha20)

**Scenario:** You have a Noski server running at `203.0.113.1:1080` with key `a1b2...`.

Run Pyatki locally:

```bash
# Set environment variables
export NOSKI_REMOTE_ADDR=203.0.113.1:1080
export ENCRYPTION_KEY=a1b2c3d4... 
export ENCRYPTION_TYPE=chacha20

# Run client
cargo run --release --bin pyatki
```

**Connect your apps:**
Configure your browser or app to use SOCKS5 proxy at `127.0.0.1:1081`.

### 2. DPI Evasion Mode (Obfuscated)

**Scenario:** You need to bypass DPI, server is running in `obfuscated` mode.

```bash
export NOSKI_REMOTE_ADDR=203.0.113.1:443
export ENCRYPTION_KEY=a1b2c3d4...
export ENCRYPTION_TYPE=obfuscated

cargo run --release --bin pyatki
```

### 3. Using a `.env` file

Create a `.env` file in the directory where you run pyatki:

```env
PYATKI_LOCAL_ADDR=127.0.0.1:1081
NOSKI_REMOTE_ADDR=myserver.com:1080
ENCRYPTION_TYPE=obfuscated
ENCRYPTION_KEY=a1b2c3d4e5f6...
```

Then just run:
```bash
cargo run --release --bin pyatki
```

## Troubleshooting

### "Remote server refused NO_AUTH"
Pyatki currently attempts to connect to Noski using "No Authentication". Ensure your Noski server allows no auth, or update Pyatki to support authentication (planned feature).

### "Connection refused"
- Check `NOSKI_REMOTE_ADDR` is correct.
- Check if Noski server is running and accessible.
- Check firewall settings.

### "Decryption failed"
- Ensure `ENCRYPTION_KEY` matches exactly on both sides.
- Ensure `ENCRYPTION_TYPE` matches.
