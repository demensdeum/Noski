# Noski Encryption Layer Architecture

## Overview

The Noski SOCKS5 proxy now includes an abstraction layer for traffic encryption. This allows you to plug in different encryption implementations without modifying the core proxy logic.

## Architecture

### Core Components

2. **`EncryptedReader<R>`** (`src/encrypted_stream.rs`)
   - Wrapper for `AsyncRead` that handles decryption and framing
   - Features: Signature verification, Max message size enforcement, Plaintext detection

3. **`EncryptedWriter<W>`** (`src/encrypted_stream.rs`)
   - Wrapper for `AsyncWrite` that handles encryption and framing
   - Features: Signature insertion, Correct length prefixing

4. **`EncryptionLayer` Trait** (`src/encryption.rs`)
   - Abstract interface for all encryption implementations (ChaCha20, Obfuscated, Passthrough)

## Message Framing

All communication between client and proxy follows this framing protocol:

```
[Optional: Signature (N bytes)] [Length (4 bytes)] [Encrypted Data (Var)]
```

- **Signature**: Optional fixed byte sequence used for additional obfuscation and packet identification.
- **Length**: 32-bit big-endian integer representing the size of the following encrypted data.
- **Encrypted Data**: Contains the nonce, ciphertext, and authentication tag.

## Security Hardening

### 🚫 Message Size Limits
The proxy enforces a maximum message size (default 1MB) to prevent memory exhaustion (OOM) attacks from malicious clients. This is configurable via the `MESSAGE_SIZE` environment variable.

### 🛡️ Plaintext Detection
`EncryptedReader` can detect standard SOCKS5 plaintext greetings (starting with `0x05`) on an encrypted port. This provides clear error messages for configuration mismatches:
`"Message too large: ... Potential plaintext SOCKS5 protocol detected on encrypted port."`

### 🔑 Nonce Management
Nonces are managed automatically via an internal counter to ensure each message uses a unique nonce, preventing replay and cryptographic attacks within a session.

## Usage

### Using the Default (No Encryption)

The proxy uses `PassthroughEncryption` by default:

```rust
// In main.rs (already configured)
let encryption: Box<dyn EncryptionLayer> = Box::new(PassthroughEncryption::new());
```

### Implementing Custom Encryption

To add your own encryption (e.g., AES-GCM, ChaCha20-Poly1305):

1. **Create a new module** (e.g., `src/aes_encryption.rs`):

```rust
use crate::encryption::EncryptionLayer;
use std::error::Error;

pub struct AesGcmEncryption {
    cipher: /* your cipher instance */,
}

impl AesGcmEncryption {
    pub fn new(key: &[u8]) -> Self {
        // Initialize your cipher
        todo!()
    }
}

impl EncryptionLayer for AesGcmEncryption {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        // Implement encryption
        todo!()
    }
    
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        // Implement decryption
        todo!()
    }
    
    fn name(&self) -> &str {
        "aes-gcm"
    }
}
```

2. **Register the module** in `src/main.rs`:

```rust
mod aes_encryption;
use aes_encryption::AesGcmEncryption;
```

3. **Use your encryption** in `main()`:

```rust
let encryption: Box<dyn EncryptionLayer> = Box::new(AesGcmEncryption::new(key));
```

### Example: XOR Encryption

See `src/xor_encryption_example.rs` for a complete example implementation (demonstration only, not secure!).

## Configuration

You can configure the encryption layer via environment variables:

```bash
ENCRYPTION_TYPE=chacha20      # "passthrough", "chacha20", "obfuscated"
ENCRYPTION_KEY="..."         # 256-bit key (64 hex chars)
MESSAGE_SIZE=1048576         # Max message size in bytes
MESSAGE_HEADER_SIGN="magic"  # Optional fixed signature
ERRORS_COUNT_LOG=100         # Error logging limit
```

## Design Principles

1. **Abstraction**: The `EncryptionLayer` trait allows any encryption algorithm to be plugged in
2. **Zero-cost for passthrough**: Default mode has no performance overhead
3. **Thread-safe**: All implementations must be `Send + Sync`
4. **Error handling**: Proper error propagation with `Result` types
5. **Testability**: Each implementation should include unit tests

## Future Enhancements

- [ ] Stream-based encryption/decryption (avoid buffering entire messages)
- [ ] TLS/SSL integration
- [ ] Key rotation support
- [ ] Per-connection encryption keys
- [ ] Encryption negotiation protocol
- [ ] Performance benchmarks

## Security Considerations

⚠️ **Important**: 
- The `PassthroughEncryption` provides NO security
- The XOR example is for demonstration only - DO NOT use in production
- For production use, implement proper authenticated encryption (AES-GCM, ChaCha20-Poly1305)
- Consider using TLS instead of custom encryption
- Ensure proper key management and rotation

## Testing

Run the encryption layer tests:

```bash
cargo test encryption
```

Run all tests including examples:

```bash
cargo test
```

## Performance

The encryption layer is designed to have minimal overhead:

- **Passthrough**: Zero overhead (data is copied but not transformed)
- **Custom encryption**: Overhead depends on the algorithm chosen
- **Future**: Stream-based processing will reduce memory overhead

## Contributing

When adding a new encryption implementation:

1. Implement the `EncryptionLayer` trait
2. Add comprehensive unit tests
3. Document the security properties
4. Update this README
5. Consider adding benchmarks
