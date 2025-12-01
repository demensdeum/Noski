# Noski Encryption Layer Architecture

## Overview

The Noski SOCKS5 proxy now includes an abstraction layer for traffic encryption. This allows you to plug in different encryption implementations without modifying the core proxy logic.

## Architecture

### Core Components

1. **`EncryptionLayer` Trait** (`src/encryption.rs`)
   - Abstract interface for all encryption implementations
   - Methods:
     - `encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>>`
     - `decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>>`
     - `name(&self) -> &str`

2. **`PassthroughEncryption`** (`src/encryption.rs`)
   - Default implementation with no encryption
   - Simply passes data through unchanged
   - Zero performance overhead

3. **`EncryptedStream<S>`** (`src/encryption.rs`)
   - Wrapper for AsyncRead/AsyncWrite streams
   - Applies encryption/decryption transparently
   - Currently supports passthrough mode

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
# Future: Add encryption configuration
ENCRYPTION_TYPE=passthrough  # or "aes-gcm", "chacha20", etc.
ENCRYPTION_KEY=your-base64-encoded-key
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
