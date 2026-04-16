# Noski - SOCKS5 Proxy Server in Rust

![Logo](logo.jpg "Logo")

Noski is a lightweight, asynchronous SOCKS5 proxy server implementation
written in Rust. It is built using the tokio runtime for
high-performance non-blocking I/O.

## Features

-   **🔒 ChaCha20-Poly1305 Encryption**: All traffic between client and proxy is encrypted
    using modern authenticated encryption (see [ENCRYPTED_USAGE.md](ENCRYPTED_USAGE.md) for setup).
-   **🕵️ DPI Evasion Mode**: Obfuscated encryption that makes traffic look like HTTPS/TLS
    to bypass Deep Packet Inspection (see [DPI_EVASION.md](DPI_EVASION.md) for details).
-   **Protocol Support**: Full implementation of the SOCKS5 protocol
    (RFC 1928).
-   **Reliable Delivery**: Automatic sequence verification and retransmisson of dropped packets via adjustable `RETRANSMISSION_COUNT`.
-   **Silent Drop Prevention**: `PING`/`PONG` heartbeat mechanisms preserve long-lived connections.
-   **TCP Support**: Handles `CONNECT` commands for standard TCP
    tunneling.
-   **UDP Support**: Handles `UDP ASSOCIATE` for UDP relaying.
-   **Authentication**: Supports Username/Password authentication (RFC
    1929).
-   **Configuration**: Simple environment-based configuration via
    `.env`.


## Prerequisites

-   **Rust & Cargo**: You need a working Rust installation.\
    Install Rust via `rustup`: <https://rustup.rs/>

## Installation

1.  **Clone the repository:**

    ``` sh
    git clone https://github.com/yourusername/noski.git
    cd noski
    ```

2.  **Build the project:**

    ``` sh
    cargo build --release
    ```

    The binary will be located at `target/release/noski`.

## Configuration

Noski uses a `.env` file to manage configuration.

1.  Create a file named `.env` in the root directory.

2.  Add your configuration:

        ENCRYPTION_KEY=<generated-key-from-first-run>
        SOCKS_USER=myuser
        SOCKS_PASSWORD=mypassword
        RETRANSMISSION_COUNT=10


### Encryption Setup

On first run without `ENCRYPTION_KEY`, the proxy will generate and display a new encryption key:

```
[*] Generated new encryption key: a1b2c3d4e5f6...
[!] Save this key to .env as: ENCRYPTION_KEY=a1b2c3d4e5f6...
```

**Important**: Save this key to your `.env` file and share it securely with clients.

See [ENCRYPTED_USAGE.md](ENCRYPTED_USAGE.md) for detailed encryption setup and client implementation.

**Valid ENCRYPTION_TYPE values:**
- `chacha20` / `chacha20-poly1305` / `encrypted` - ChaCha20-Poly1305 encryption (default)
- `obfuscated` / `dpi` / `tls` - Obfuscated encryption with DPI evasion (see [DPI_EVASION.md](DPI_EVASION.md))

*(Note: Unencrypted "passthrough" mode is explicitly removed to ensure security by default.)*

## Client Application (Pyatki)

**Pyatki** is the official client for Noski. It runs locally and provides a standard SOCKS5 interface for your applications while handling encryption to the remote Noski server.

See [CLIENT_GUIDE.md](CLIENT_GUIDE.md) for build and usage instructions.

```bash
# Quick build
cargo build --release --bin pyatki
```

## No Authentication (Not Recommended)

If you omit the SOCKS_USER and SOCKS_PASSWORD variables, the server will default to No Authentication mode.

⚠️ **Warning**: In this mode, anyone who can access the server port can use the proxy. Always use authentication in production!
        
## Usage

### Running the Server

Run directly using Cargo:

``` sh
cargo run --release
```

Or run the compiled binary:

``` sh
./target/release/noski
```

The server will start listening on `127.0.0.1:1080`.

### Testing with cURL

On PowerShell use `curl.exe` to avoid alias conflicts.

**Bash / Command Prompt:**

``` sh
curl -v -x socks5://myuser:mypassword@127.0.0.1:1080 https://www.google.com
```

**PowerShell:**

``` powershell
curl.exe -v -x socks5://myuser:mypassword@127.0.0.1:1080 https://www.google.com
```

### DNS Resolution

To prevent DNS leaks, let the proxy resolve the hostname by passing a
domain name instead of a resolved IP.\
Use `socks5h://` scheme where supported (e.g. in cURL/other clients that
implement it), otherwise ensure remote DNS resolution in your client
settings.

## Pyatki Client

**Pyatki** is the official local client for Noski. It runs on your local machine, acts as a standard SOCKS5 server, and tunnels all traffic through an encrypted connection to your remote Noski server.

### Why use Pyatki?
- **Encryption**: Encrypts traffic from your local machine to the proxy, protecting you from ISP surveillance and DPI.
- **Compatibility**: Works with any app that supports standard SOCKS5 (browsers, Telegram, etc.) without them needing to know about the encryption.

### Setup

1.  **Configure `.env`**:
    Add the following to your `.env` file (or set as environment variables):

    ```ini
    # Address of your remote Noski server
    NOSKI_REMOTE_ADDR=1.2.3.4:1080
    
    # Local address for Pyatki to listen on
    PYATKI_LOCAL_ADDR=127.0.0.1:1081
    
    # Must match the server's key and type
    ENCRYPTION_KEY=<your-shared-key>
    ENCRYPTION_TYPE=chacha20
    ```

2.  **Run Pyatki**:

    ```sh
    cargo run --release --bin pyatki
    ```

3.  **Connect your apps**:
    Configure your browser or application to use the **local** proxy:
    - **Host**: `127.0.0.1`
    - **Port**: `1081` (or whatever you set in `PYATKI_LOCAL_ADDR`)
    - **Type**: SOCKS5

    Now all traffic from that app will be encrypted by Pyatki and sent to Noski.

## Project Structure

    Noski/
    ├── Cargo.toml                      # Rust dependencies and package info
    ├── .env                            # Environment variables for credentials
    ├── ENCRYPTION.md                   # Encryption layer documentation
    └── src/
        ├── lib.rs                      # Shared library (encryption modules)
        ├── main.rs                     # Noski Server entry point
        ├── bin/
        │   └── pyatki.rs               # Pyatki Client entry point
        ├── encryption.rs               # Encryption layer abstraction
        └── xor_encryption_example.rs   # Example encryption implementation

## License

This project is open source. Feel free to modify and distribute.

------------------------------------------------------------------------
