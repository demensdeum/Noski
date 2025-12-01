# Noski - SOCKS5 Proxy Server in Rust

![Logo](logo.png "Logo")

Noski is a lightweight, asynchronous SOCKS5 proxy server implementation
written in Rust. It is built using the tokio runtime for
high-performance non-blocking I/O.

## Features

-   **Protocol Support**: Full implementation of the SOCKS5 protocol
    (RFC 1928).
-   **TCP Support**: Handles `CONNECT` commands for standard TCP
    tunneling.
-   **UDP Support**: Handles `UDP ASSOCIATE` for UDP relaying.
-   **Authentication**: Supports Username/Password authentication (RFC
    1929).
-   **IPv4 & IPv6**: Robust handling of both address types.
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

Noski uses a `.env` file to manage authentication credentials.

1.  Create a file named `.env` in the root directory.

2.  Add your desired username and password:

        SOCKS_USER=myuser
        SOCKS_PASSWORD=mypassword

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

## Project Structure

    Noski/
    ├── Cargo.toml      # Rust dependencies and package info
    ├── .env            # Environment variables for credentials
    └── src/
        └── main.rs     # Main entry point and server logic

## License

This project is open source. Feel free to modify and distribute.

------------------------------------------------------------------------
