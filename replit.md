# Secure Chat MVP

## Project Overview
A secure end-to-end encrypted chat application demonstrating cryptographic best practices. Built with C++20 Drogon backend (WebSocket relay) and React TypeScript frontend (Web Crypto API encryption).

## Recent Changes
- 2025-01-31: Initial project setup
  - C++ backend with Drogon WebSocket relay server
  - React TypeScript frontend with Web Crypto API
  - AES-256-GCM encryption, PBKDF2 key derivation
  - Replay protection (counter + timestamp)
  - SHA-256 integrity verification with PASS/FAIL UI
  - Educational cipher implementations (XOR, Caesar)

## Project Architecture

### Backend (C++20)
- **Framework**: Drogon (WebSocket + HTTP server)
- **Relay-only**: Server never decrypts messages
- **Replay Protection**: ReplayGuard validates counters and timestamps
- **Connection Registry**: Maps userIds to WebSocket connections
- **OOP Design**: Strategy pattern for ciphers, IHasher interface

### Frontend (React + TypeScript)
- **Build**: Vite
- **Crypto**: Web Crypto API (AES-256-GCM, PBKDF2-HMAC-SHA256, SHA-256)
- **Real-time**: WebSocket client with auto-reconnect
- **UI**: Passphrase modal, message list, verification badges

## Key Security Features
- End-to-end encryption (AES-256-GCM by default)
- PBKDF2-HMAC-SHA256 key derivation (200k iterations, random salt)
- SHA-256 integrity verification (PASS/FAIL indicator)
- Replay protection (monotonic counter + ±5min timestamp window)
- AAD binding (senderId, recipientId, counter)

## Educational Components
- XOR cipher (demonstration only)
- Caesar cipher (demonstration only)
- Strategy pattern for cipher selection

## Build Instructions

### Backend
```bash
cd server/build
cmake ..
make
./SecureChatServer
```

### Frontend
```bash
cd client
npm install
npm run dev
```

## Testing Demo
1. Open two browser tabs at localhost:5000
2. Tab 1: Login as "alice", set recipient "bob", enter passphrase
3. Tab 2: Login as "bob", set recipient "alice", same passphrase
4. Exchange messages and observe PASS/FAIL verification

## Documentation
- `README.md`: Complete setup and usage guide
- `docs/crypto-design.md`: Cryptographic design decisions
- `docs/threat-model.md`: Security analysis and threat assessment

## Dependencies
- Backend: Drogon, OpenSSL, jsoncpp, c-ares, zlib, sqlite3, brotli
- Frontend: React, TypeScript, Vite, Tailwind CSS
