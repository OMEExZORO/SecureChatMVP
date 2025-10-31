# Secure Chat MVP

A secure end-to-end encrypted chat application demonstrating cryptographic best practices with C++20 backend and React TypeScript frontend.

## Features

- **End-to-End Encryption**: AES-256-GCM with Web Crypto API (default)
- **Key Derivation**: PBKDF2-HMAC-SHA256 (200k iterations, random salt per chat)
- **Integrity Verification**: SHA-256 hash verification with PASS/FAIL UI indicator
- **Replay Protection**: Monotonic counter + timestamp window (±5 minutes)
- **Educational Ciphers**: XOR and Caesar cipher implementations for demonstration
- **Real-time Communication**: WebSocket relay server (server never decrypts)
- **OOP Design**: Strategy pattern, interfaces, RAII, const-correctness

## Architecture

```
┌─────────────┐                  ┌─────────────┐
│   Client A  │                  │   Client B  │
│  (Browser)  │                  │  (Browser)  │
└──────┬──────┘                  └──────┬──────┘
       │                                │
       │  Encrypted Messages            │
       │  (AES-256-GCM)                │
       │                                │
       └────────┬───────────────┬───────┘
                │               │
         ┌──────▼───────────────▼──────┐
         │   Drogon WebSocket Server   │
         │   (Relay Only - No Decrypt) │
         │   - Replay Protection       │
         │   - Counter Validation      │
         │   - Timestamp Verification  │
         └─────────────────────────────┘
```

## Tech Stack

### Backend (C++20)
- **Framework**: Drogon (WebSocket + HTTP)
- **Build**: CMake 3.10+
- **Crypto**: OpenSSL (SHA-256)
- **JSON**: nlohmann/json (via jsoncpp)

### Frontend (React + TypeScript)
- **Build Tool**: Vite
- **Crypto**: Web Crypto API (AES-256-GCM, PBKDF2, SHA-256)
- **WebSocket**: Native WebSocket API
- **Styling**: Tailwind CSS

## Quick Start

### Prerequisites

On Replit, all dependencies are automatically installed. For local development:
- C++20 compiler (GCC 13+ or Clang 14+)
- CMake 3.10+
- Node.js 20+
- OpenSSL

### Installation

1. **Install Frontend Dependencies**
```bash
cd client
npm install
```

2. **Build Backend**
```bash
cd server
mkdir build
cd build
cmake ..
make
```

### Running the Application

**Option 1: Using Workflows (Replit)**

The project is configured with workflows that will automatically start both services.

**Option 2: Manual Start**

Terminal 1 - Start Backend:
```bash
cd server/build
./SecureChatServer
```

Terminal 2 - Start Frontend:
```bash
cd client
npm run dev
```

The frontend will be available at `http://localhost:5000`

### Testing the Application

1. **Open two browser windows/tabs** at `http://localhost:5000`

2. **Window 1**:
   - Enter User ID: `alice`
   - Click "Connect"
   - Enter Recipient ID: `bob`
   - Click "Setup Encryption Key"
   - Enter passphrase: `secret123`
   - Click "Setup"

3. **Window 2**:
   - Enter User ID: `bob`
   - Click "Connect"
   - Enter Recipient ID: `alice`
   - Click "Setup Encryption Key"
   - Enter passphrase: `secret123`
   - Click "Setup"

4. **Exchange Messages**:
   - Type messages in either window
   - Observe PASS/FAIL verification badges
   - Check counter increments
   - Server logs show relay only (no decryption)

5. **Test Replay Protection**:
   - Open browser DevTools → Network → WS
   - Copy a sent message JSON
   - Manually send it again
   - Server rejects with "Counter not monotonic"

## Security Model

### Encryption Flow

**Sender**:
```
Plaintext → AES-256-GCM encrypt → SHA-256(plaintext) → 
{ciphertext, iv, authTag, sha256, counter, timestamp, AAD}
```

**Receiver**:
```
Verify counter/timestamp → Decrypt → Recompute SHA-256 → 
Compare hashes → PASS/FAIL
```

### Key Derivation

```typescript
Passphrase + Random Salt (16 bytes) → 
PBKDF2-HMAC-SHA256 (200k iterations) → 
256-bit AES-GCM Key
```

### AAD (Additional Authenticated Data)

```json
{
  "senderId": "alice",
  "recipientId": "bob", 
  "counter": 42
}
```

### Replay Protection

1. **Monotonic Counter**: Strictly increasing per (sender → recipient) pair
2. **Timestamp Window**: ±5 minutes from server time
3. **Server Enforcement**: Rejects duplicates and old counters

### Message Envelope

```json
{
  "type": "MSG",
  "senderId": "alice",
  "recipientId": "bob",
  "counter": 1,
  "timestamp": 1698765432,
  "iv": "base64...",
  "ciphertext": "base64...",
  "authTag": "base64...",
  "sha256_plaintext": "hex...",
  "aad": {"senderId": "alice", "recipientId": "bob", "counter": 1},
  "cipher": "AES-256-GCM"
}
```

## OOP Design Patterns

### Strategy Pattern
```cpp
IEncryptionStrategy (interface)
├── AesGcmCipher (production)
├── XorCipher (educational)
└── CaesarCipher (educational)
```

### Composition
```cpp
CryptoContext {
  IEncryptionStrategy* strategy;
  IHasher* hasher;
  KeyDeriver* deriver;
}
```

### RAII
- Secure buffer management with automatic zeroization
- Connection lifecycle management
- Mutex lock guards

## API Endpoints

### WebSocket: `ws://localhost:8080/ws`

**HELLO (Client → Server)**
```json
{"type": "HELLO", "userId": "alice"}
```

**HELLO_ACK (Server → Client)**
```json
{"type": "HELLO_ACK", "userId": "alice", "message": "Connected successfully"}
```

**MSG (Client → Server → Client)**
```json
{
  "type": "MSG",
  "senderId": "alice",
  "recipientId": "bob",
  ...envelope fields...
}
```

**REJECT (Server → Client)**
```json
{"type": "REJECT", "reason": "Counter not monotonic"}
```

### HTTP: `GET /healthz`

```json
{"status": "healthy", "service": "secure-chat-server"}
```

## Encryption Strategy Selector

The UI includes a dropdown to select encryption modes:

- **AES-256-GCM** (Default): Production-ready AEAD cipher
- **XOR** (Educational): Simple XOR cipher for demonstration only
- **Caesar** (Educational): Classic Caesar cipher for learning

⚠️ **Security Note**: XOR and Caesar ciphers are for educational purposes ONLY. Always use AES-256-GCM for production.

## Project Structure

```
secure-chat/
├── server/                 # C++ Backend
│   ├── include/
│   │   ├── IEncryptionStrategy.hpp
│   │   ├── IHasher.hpp
│   │   ├── XorCipher.hpp
│   │   ├── CaesarCipher.hpp
│   │   ├── Sha256Hasher.hpp
│   │   ├── ReplayGuard.hpp
│   │   └── ConnRegistry.hpp
│   ├── src/
│   │   ├── main.cpp
│   │   ├── XorCipher.cpp
│   │   ├── CaesarCipher.cpp
│   │   ├── Sha256Hasher.cpp
│   │   ├── ReplayGuard.cpp
│   │   └── ConnRegistry.cpp
│   ├── CMakeLists.txt
│   └── .env.example
├── client/                 # React Frontend
│   ├── src/
│   │   ├── lib/
│   │   │   ├── crypto.ts
│   │   │   └── websocket.ts
│   │   ├── App.tsx
│   │   ├── main.tsx
│   │   └── index.css
│   ├── package.json
│   └── vite.config.ts
├── docs/
│   ├── crypto-design.md
│   └── threat-model.md
└── README.md
```

## Acceptance Criteria

✅ Messages encrypted at client, arrive encrypted at server, decrypted only at recipient  
✅ AES-GCM default path with all unit tests passing  
✅ XOR/Caesar strategies exist and selectable for demonstration  
✅ Hash verification PASS/FAIL visible in UI  
✅ Replay attempts (duplicate/lower counter or stale timestamp) rejected by server  
✅ Code exhibits OOP principles (interfaces, inheritance, composition, RAII)  
✅ Clear build/run instructions  
✅ Works on Replit and local Linux/macOS

## Security Notes

⚠️ **This is an MVP for educational purposes**. Production deployments should include:

- User authentication (JWT/OAuth)
- TLS/SSL for WebSocket transport
- Persistent key storage with proper key management
- Forward secrecy (X25519 key exchange)
- Message persistence with encrypted storage
- Rate limiting and DDoS protection
- Comprehensive audit logging
- Security testing and code review

**Remember**: XOR and Caesar ciphers are for learning ONLY. Always use AES-GCM (or better) in production.

## License

MIT License - Educational Project

## Authors

Built as a secure cryptography demonstration project.
