# Quick Start Guide

Noski is an encrypted SOCKS5 proxy server. To use it with standard applications (like browsers or curl), you must run the **Noski server** on your remote machine and the **Pyatki client** on your local machine.

*Note: Unencrypted "passthrough" mode has been removed for security. All traffic must be encrypted.*

## Step 1: Run the Noski Server (Remote)

The server receives encrypted traffic, decrypts it, and forwards it to the internet.

1.  **Generate a configuration:**
    Run the server once to generate a secure encryption key:
    ```bash
    cargo run --release
    ```

    Output:
    ```
    [*] Generated new encryption key: a1b2c3d4e5f6789...
    [!] Save this key to .env as: ENCRYPTION_KEY=a1b2c3d4e5f6789...
    ```

2.  **Save the key and configure `.env`**:
    Create a `.env` file on the server:
    ```ini
    ENCRYPTION_KEY=a1b2c3d4e5f6789...
    SOCKS_USER=myuser
    SOCKS_PASSWORD=mypassword
    RETRANSMISSION_COUNT=10
    ```

3.  **Start the server:**
    ```bash
    cargo run --release
    ```
    *The server is now listening on port 1080.*

---

## Step 2: Run the Pyatki Client (Local)

Pyatki acts as a translator. It accepts standard SOCKS5 traffic from your local apps, encrypts it, and sends it to the Noski server.

1.  **Configure `.env` on your local machine**:
    Create a `.env` file where you run Pyatki. You MUST use the exact same `ENCRYPTION_KEY` as the server.
    ```ini
    # Remote Noski server IP and Port
    NOSKI_REMOTE_ADDR=1.2.3.4:1080
    
    # Local port for Pyatki to listen on
    PYATKI_LOCAL_ADDR=127.0.0.1:1081
    
    # Matching credentials and key
    ENCRYPTION_KEY=a1b2c3d4e5f6789...
    
    # Optional delivery control
    RETRANSMISSION_COUNT=10
    ```

2.  **Start the Pyatki client:**
    ```bash
    cargo run --release --bin pyatki
    ```
    *Pyatki is now listening locally on `127.0.0.1:1081`.*

---

## Step 3: Connect Your Applications

Now that Pyatki is running locally, you can point any SOCKS5-compatible application to it!

### Usage with curl

```bash
curl -x socks5://127.0.0.1:1081 https://api.ipify.org
```

### Usage with browsers

**Firefox:**
1. Settings → Network Settings → Manual proxy configuration
2. SOCKS Host: `127.0.0.1`
3. Port: `1081`
4. Select: SOCKS v5

**Chrome/Edge:**
```bash
chrome.exe --proxy-server="socks5://127.0.0.1:1081"
```

## Troubleshooting

### "Connection refused"
- Check that Pyatki is running locally.
- Confirm Pyatki can reach your remote Noski server IP/Port.

### "Decryption failed"
- Your `ENCRYPTION_KEY` does not match between the server and the client.

### "Authentication failed"
- Ensure `SOCKS_USER` and `SOCKS_PASSWORD` match on both sides, or that you aren't trying to auth against a server that doesn't have them configured.

### Connection drops / High latency
- Pyatki actively monitors the TCP stream and retransmits lost packets. Check your terminal output and `noski_errors.log` to see if your network is dropping significant amounts of packets. You can increase `RETRANSMISSION_COUNT` in `.env` to handle severely degraded connections.

