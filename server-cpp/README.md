# Secure Chat C++ Server

## Overview
This is a **C++ WebSocket server** implementation for the Secure Chat application using **Windows Sockets (Winsock2)**.

## OOP Principles Demonstrated

### 1. **Encapsulation**
- `ReplayGuard` class encapsulates replay protection logic with private data members and public interface
- `ConnectionRegistry` hides internal user-socket mappings
- `WebSocketFrame` encapsulates WebSocket protocol details

### 2. **Abstraction**
- `WebSocketFrame` provides simple encode/decode methods hiding protocol complexity
- `ReplayGuard` provides abstract validation interface without exposing implementation

### 3. **Composition**
- `SecureChatServer` composes `ReplayGuard` and `ConnectionRegistry` objects
- Server uses "has-a" relationships with helper classes

### 4. **Single Responsibility Principle**
- Each class has one clear purpose:
  - `ReplayGuard`: Replay attack prevention
  - `ConnectionRegistry`: Connection management
  - `WebSocketFrame`: Protocol encoding/decoding
  - `SecureChatServer`: Server orchestration

## Prerequisites

### Windows (MinGW or Visual Studio)
- **C++ Compiler**: g++ (MinGW) or MSVC
- **CMake**: Version 3.10 or higher
- **Windows SDK**: For Winsock2

## Compilation Instructions

### Option 1: Using g++ directly (MinGW)
```cmd
cd server-cpp
g++ -std=c++17 -I./include src/main.cpp -o SecureChatServer.exe -lws2_32
```

### Option 2: Using CMake
```cmd
cd server-cpp
mkdir build
cd build
cmake ..
cmake --build .
```

The executable will be in `build/bin/SecureChatServer.exe`

## Running the Server

```cmd
cd server-cpp
SecureChatServer.exe
```

Or from build directory:
```cmd
cd server-cpp/build/bin
SecureChatServer.exe
```

The server will start on port **8080**.

## Features

- ✅ **Zero-Knowledge Architecture**: Server never decrypts messages
- ✅ **Replay Protection**: Validates message counters and timestamps
- ✅ **Admin Monitoring**: Separate admin connections can view encrypted traffic
- ✅ **WebSocket Protocol**: Full WebSocket handshake and framing
- ✅ **Connection Management**: Tracks users and admin clients
- ✅ **Error Handling**: Proper rejection messages for invalid requests

## Architecture

```
SecureChatServer (Main class)
├── ReplayGuard (Replay attack prevention)
├── ConnectionRegistry (User/Socket management)
└── WebSocketFrame (Protocol handling)
```

## Protocol

### Client Messages
- `HELLO`: Register user connection
- `MSG`: Send encrypted message
- `ADMIN_CONNECT`: Register as admin

### Server Responses
- `HELLO_ACK`: Confirm registration
- `REJECT`: Message validation failed
- `ERROR`: Parse or protocol error
- `ADMIN_MSG`: Forwarded encrypted message (admin only)

## Port Configuration

Default port: **8080**

To change, modify line in `main.cpp`:
```cpp
securechat::SecureChatServer server(8080);  // Change to desired port
```

## Troubleshooting

### "Bind failed" error
- Port 8080 is already in use
- Stop Node.js server first: `taskkill /F /IM node.exe`
- Or change server port

### Linker errors about ws2_32
- Make sure to link against Winsock: `-lws2_32`
- Or ensure CMake is linking correctly

### WebSocket connection refused
- Check firewall settings
- Verify server is running
- Ensure correct port number

## OOP Concepts Checklist

- [x] **Classes and Objects**: Multiple classes with clear responsibilities
- [x] **Encapsulation**: Private members with public interfaces
- [x] **Abstraction**: Hidden implementation details
- [x] **Composition**: Server uses helper classes
- [x] **const Correctness**: Const methods where appropriate
- [x] **RAII**: Proper resource management in destructors
- [x] **Modern C++**: Using C++17 features

## License
MIT License
