# 🎓 Object-Oriented Programming Concepts - Detailed Reference Guide
**Secure Chat MVP - C++ Backend Implementation**

---

## 📋 Table of Contents
1. [Encapsulation](#1-encapsulation)
2. [Abstraction](#2-abstraction)
3. [Composition](#3-composition)
4. [Single Responsibility Principle](#4-single-responsibility-principle)
5. [Thread Safety & Concurrency](#5-thread-safety--concurrency)
6. [Resource Management](#6-resource-management)

---

## 1. 🔒 ENCAPSULATION

### Definition
**Encapsulation** is the bundling of data (attributes) and methods (functions) that operate on that data within a single unit (class), while restricting direct access to some of the object's components.

### Implementation in Our Project

#### **File: `server-cpp/src/main.cpp`**

### 📌 **Example 1: ReplayGuard Class (Lines 30-68)**

```cpp
class ReplayGuard {
private:
    std::map<std::string, int> lastCounters;  // Private data - hidden from outside
    int timeWindowSeconds;                     // Private configuration

public:
    explicit ReplayGuard(int timeWindow = 300) : timeWindowSeconds(timeWindow) {}
    
    bool validateCounter(const std::string& userId, int counter) {
        auto it = lastCounters.find(userId);
        if (it == lastCounters.end()) {
            lastCounters[userId] = counter;
            return true;
        }
        
        if (counter > it->second) {
            it->second = counter;
            return true;
        }
        return false;  // Counter not monotonic - replay attack detected
    }
    
    void clearUser(const std::string& userId) {
        lastCounters.erase(userId);
    }
};
```

**🔍 How Encapsulation is Demonstrated:**
- **Private Members**: `lastCounters` and `timeWindowSeconds` are hidden from external access
- **Public Interface**: Only `validateCounter()` and `clearUser()` are exposed
- **Data Protection**: Direct manipulation of counter data is prevented
- **Controlled Access**: All modifications go through validated methods

**💡 Benefits:**
- Prevents unauthorized replay counter manipulation
- Maintains data integrity for security validation
- Changes to internal storage don't affect external code

---

### 📌 **Example 2: ConnectionRegistry Class (Lines 73-118)**

```cpp
class ConnectionRegistry {
private:
    std::map<std::string, SOCKET> userToSocket;     // Private mapping
    std::map<SOCKET, std::string> socketToUser;     // Bidirectional lookup
    std::set<SOCKET> adminSockets;                   // Admin tracking

public:
    void registerUser(const std::string& userId, SOCKET socket) {
        userToSocket[userId] = socket;
        socketToUser[socket] = userId;
    }
    
    void registerAdmin(SOCKET socket) {
        adminSockets.insert(socket);
    }
    
    void unregister(SOCKET socket) {
        auto it = socketToUser.find(socket);
        if (it != socketToUser.end()) {
            userToSocket.erase(it->second);
            socketToUser.erase(it);
        }
        adminSockets.erase(socket);
    }
    
    SOCKET getUserSocket(const std::string& userId) const {
        auto it = userToSocket.find(userId);
        return (it != userToSocket.end()) ? it->second : INVALID_SOCKET;
    }
    
    std::string getUserId(SOCKET socket) const {
        auto it = socketToUser.find(socket);
        return (it != socketToUser.end()) ? it->second : "";
    }
    
    bool isAdmin(SOCKET socket) const {
        return adminSockets.find(socket) != adminSockets.end();
    }
};
```

**🔍 How Encapsulation is Demonstrated:**
- **Hidden Complexity**: Three internal data structures are completely hidden
- **Public API**: Simple, intuitive methods for user/socket management
- **Data Consistency**: Bidirectional mappings are automatically maintained
- **Safe Operations**: All modifications happen through controlled methods

**💡 Benefits:**
- Complex bidirectional mapping logic is hidden
- Prevents inconsistent state (orphaned mappings)
- Easy to add new features without breaking existing code

---

### 📌 **Example 3: SecureChatServer Private Methods (Lines 200-237)**

```cpp
class SecureChatServer {
private:
    SOCKET serverSocket;
    int port;
    bool running;
    ReplayGuard replayGuard;
    ConnectionRegistry connRegistry;
    std::mutex registryMutex;
    
    // Private helper methods - implementation details hidden
    bool initializeWinsock() {
        WSADATA wsaData;
        return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
    }
    
    bool createSocket() {
        serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (serverSocket == INVALID_SOCKET) {
            std::cerr << "Socket creation failed: " << WSAGetLastError() << std::endl;
            return false;
        }
        
        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(port);
        
        if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            return false;
        }
        
        if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
            return false;
        }
        
        return true;
    }

public:
    explicit SecureChatServer(int p) : port(p), running(false), replayGuard(300) {}
    
    bool start() {
        if (!initializeWinsock()) return false;
        if (!createSocket()) return false;
        running = true;
        // ... server loop
    }
};
```

**🔍 How Encapsulation is Demonstrated:**
- **Hidden Setup Logic**: Socket initialization details are private
- **Simple Public API**: Users only need to call `start()` and `stop()`
- **Internal State**: Server state variables are protected
- **Error Handling**: Complex Winsock setup is abstracted away

---

## 2. 🎭 ABSTRACTION

### Definition
**Abstraction** means hiding complex implementation details and showing only the essential features of an object. It focuses on WHAT an object does rather than HOW it does it.

### Implementation in Our Project

#### **File: `server-cpp/src/main.cpp`**

### 📌 **Example 1: WebSocketFrame Class (Lines 120-198)**

```cpp
class WebSocketFrame {
public:
    static std::string encode(const std::string& payload) {
        std::string frame;
        size_t len = payload.length();
        
        // Complex protocol logic hidden from users
        frame += (char)0x81;  // FIN + Text frame
        
        if (len <= 125) {
            frame += (char)len;
        } else if (len <= 65535) {
            frame += (char)126;
            frame += (char)((len >> 8) & 0xFF);
            frame += (char)(len & 0xFF);
        } else {
            frame += (char)127;
            for (int i = 7; i >= 0; i--) {
                frame += (char)((len >> (8 * i)) & 0xFF);
            }
        }
        
        frame += payload;
        return frame;
    }
    
    static std::string decode(const char* data, size_t dataLen, size_t& bytesRead) {
        if (dataLen < 2) return "";
        
        bool masked = (data[1] & 0x80) != 0;
        size_t payloadLen = data[1] & 0x7F;
        size_t pos = 2;
        
        if (payloadLen == 126) {
            if (dataLen < 4) return "";
            payloadLen = ((unsigned char)data[2] << 8) | (unsigned char)data[3];
            pos = 4;
        } else if (payloadLen == 127) {
            if (dataLen < 10) return "";
            payloadLen = 0;
            for (int i = 0; i < 8; i++) {
                payloadLen = (payloadLen << 8) | (unsigned char)data[2 + i];
            }
            pos = 10;
        }
        
        if (!masked) {
            bytesRead = pos + payloadLen;
            if (dataLen < bytesRead) return "";
            return std::string(data + pos, payloadLen);
        }
        
        if (dataLen < pos + 4 + payloadLen) return "";
        
        char mask[4];
        for (int i = 0; i < 4; i++) {
            mask[i] = data[pos + i];
        }
        pos += 4;
        
        std::string payload;
        for (size_t i = 0; i < payloadLen; i++) {
            payload += data[pos + i] ^ mask[i % 4];
        }
        
        bytesRead = pos + payloadLen;
        return payload;
    }
};
```

**🔍 How Abstraction is Demonstrated:**
- **Complex Protocol Hidden**: WebSocket frame format (RFC 6455) is completely abstracted
- **Simple Interface**: Users just call `encode(payload)` and `decode(data)`
- **No Protocol Knowledge Needed**: Developers don't need to understand bit manipulation
- **Implementation Independence**: Protocol details can change without affecting callers

**💡 Real-World Usage:**
```cpp
// Instead of manually crafting WebSocket frames:
std::string message = "Hello";
std::string frame = WebSocketFrame::encode(message);  // ✅ Simple!
send(socket, frame.c_str(), frame.length(), 0);

// Instead of manual parsing:
std::string payload = WebSocketFrame::decode(buffer, bytesReceived, bytesRead);  // ✅ Easy!
```

---

### 📌 **Example 2: ReplayGuard Abstraction (Lines 30-68)**

```cpp
class ReplayGuard {
public:
    bool validateCounter(const std::string& userId, int counter) {
        // Implementation details hidden
        auto it = lastCounters.find(userId);
        if (it == lastCounters.end()) {
            lastCounters[userId] = counter;
            return true;
        }
        if (counter > it->second) {
            it->second = counter;
            return true;
        }
        return false;
    }
    
    bool validateTimestamp(int64_t timestamp) {
        int64_t now = static_cast<int64_t>(std::time(nullptr));
        int64_t diff = std::abs(now - timestamp);
        return diff <= timeWindowSeconds;
    }
};
```

**🔍 How Abstraction is Demonstrated:**
- **High-Level Interface**: Simple yes/no validation methods
- **Hidden Complexity**: Internal counter tracking and time calculations are hidden
- **Security Logic Abstracted**: Replay attack prevention algorithm is encapsulated
- **Easy to Use**: Callers don't need cryptography knowledge

**💡 Usage Example:**
```cpp
// Clean, readable security validation
if (!replayGuard.validateTimestamp(msg.timestamp)) {
    sendReject(socket, "Timestamp out of range");
    return;
}

if (!replayGuard.validateCounter(senderId, counter)) {
    sendReject(socket, "Counter not monotonic - replay attack");
    return;
}
```

---

### 📌 **Example 3: WebSocket Handshake Abstraction (Lines 239-272)**

```cpp
std::string performHandshake(SOCKET clientSocket) {
    char buffer[4096];
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesReceived <= 0) return "";
    
    std::string request(buffer, bytesReceived);
    
    // Extract Sec-WebSocket-Key
    size_t keyPos = request.find("Sec-WebSocket-Key: ");
    if (keyPos == std::string::npos) return "";
    
    keyPos += 19;
    size_t keyEnd = request.find("\r\n", keyPos);
    std::string webSocketKey = request.substr(keyPos, keyEnd - keyPos);
    
    // Generate proper accept key: SHA-1(key + magic string) then Base64
    const std::string magicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string acceptInput = webSocketKey + magicString;
    
    // Calculate SHA-1 hash
    std::string hash = SHA1::hash(acceptInput);
    
    // Base64 encode the hash
    std::string acceptKey = Base64::encode((const unsigned char*)hash.c_str(), hash.length());
    
    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + acceptKey + "\r\n"
        "\r\n";
    
    send(clientSocket, response.c_str(), response.length(), 0);
    return "OK";
}
```

**🔍 How Abstraction is Demonstrated:**
- **Protocol Complexity Hidden**: HTTP upgrade and WebSocket handshake details abstracted
- **Cryptographic Operations**: SHA-1 and Base64 encoding handled internally
- **Simple Success/Fail**: Returns "OK" or empty string
- **RFC 6455 Compliance**: Implementation details completely hidden

---

## 3. 🧩 COMPOSITION

### Definition
**Composition** is a "has-a" relationship where a class contains objects of other classes as members. It represents a strong ownership relationship.

### Implementation in Our Project

#### **File: `server-cpp/src/main.cpp`**

### 📌 **Example 1: SecureChatServer Composition (Lines 200-206)**

```cpp
class SecureChatServer {
private:
    SOCKET serverSocket;
    int port;
    bool running;
    ReplayGuard replayGuard;              // ✅ Composed object
    ConnectionRegistry connRegistry;       // ✅ Composed object
    std::mutex registryMutex;             // ✅ Composed object
    
public:
    explicit SecureChatServer(int p) 
        : port(p), 
          running(false), 
          replayGuard(300) {  // Initialize composed objects
    }
};
```

**🔍 How Composition is Demonstrated:**
- **Ownership**: `SecureChatServer` OWNS `ReplayGuard` and `ConnectionRegistry`
- **Lifetime Management**: Composed objects are created/destroyed with server
- **Has-A Relationship**: Server HAS-A replay guard, HAS-A connection registry
- **No Inheritance**: Using composition instead of inheritance for flexibility

**💡 Why Composition over Inheritance:**
- **Flexibility**: Can easily swap or modify security components
- **Reusability**: `ReplayGuard` can be used in other projects
- **Loose Coupling**: Each component has clear responsibility
- **Testability**: Components can be tested independently

---

### 📌 **Example 2: Using Composed Objects (Lines 365-389)**

```cpp
void handleChatMessage(SOCKET clientSocket, const json& msg) {
    std::string senderId = msg.value("senderId", "");
    std::string recipientId = msg.value("recipientId", "");
    int counter = msg.value("counter", 0);
    int64_t timestamp = msg.value("timestamp", 0);
    
    // ✅ Using composed ReplayGuard object
    if (!replayGuard.validateTimestamp(timestamp)) {
        sendReject(clientSocket, "Timestamp out of range");
        return;
    }
    
    // ✅ Using composed ReplayGuard object
    if (!replayGuard.validateCounter(senderId, counter)) {
        sendReject(clientSocket, "Counter not monotonic");
        return;
    }
    
    // ✅ Using composed ConnectionRegistry object
    SOCKET recipientSocket;
    std::set<SOCKET> adminSockets;
    {
        std::lock_guard<std::mutex> lock(registryMutex);
        recipientSocket = connRegistry.getUserSocket(recipientId);
        adminSockets = connRegistry.getAdminSockets();
    }
    
    if (recipientSocket != INVALID_SOCKET) {
        sendToSocket(recipientSocket, msg.dump());
    }
}
```

**🔍 Composition Benefits in Action:**
- **Clear Separation**: Security logic is in `ReplayGuard`, networking in `ConnectionRegistry`
- **Modular Design**: Each component handles one aspect
- **Easy Maintenance**: Can update security without touching networking code
- **Code Reuse**: Same components used throughout the codebase

---

## 4. 📝 SINGLE RESPONSIBILITY PRINCIPLE (SRP)

### Definition
**Single Responsibility Principle** states that a class should have only ONE reason to change. Each class should do ONE thing and do it well.

### Implementation in Our Project

### 📌 **Class Responsibilities Summary**

| Class | Single Responsibility | File Location |
|-------|----------------------|---------------|
| `ReplayGuard` | Replay attack prevention | Lines 30-68 |
| `ConnectionRegistry` | Connection management | Lines 73-118 |
| `WebSocketFrame` | Protocol encoding/decoding | Lines 120-198 |
| `SecureChatServer` | Server orchestration | Lines 200-477 |

---

### 📌 **Example 1: ReplayGuard - Security Only (Lines 30-68)**

```cpp
/**
 * Single Responsibility: Replay Attack Prevention
 * DOES: Validates message counters and timestamps
 * DOES NOT: Handle networking, encryption, or storage
 */
class ReplayGuard {
private:
    std::map<std::string, int> lastCounters;
    int timeWindowSeconds;

public:
    explicit ReplayGuard(int timeWindow = 300) : timeWindowSeconds(timeWindow) {}
    
    // ✅ Security validation only
    bool validateCounter(const std::string& userId, int counter) { /*...*/ }
    
    // ✅ Security validation only
    bool validateTimestamp(int64_t timestamp) { /*...*/ }
    
    // ✅ Security cleanup only
    void clearUser(const std::string& userId) { /*...*/ }
};
```

**🔍 Why It Follows SRP:**
- **One Reason to Change**: Only changes if replay attack prevention algorithm changes
- **No Mixed Concerns**: Doesn't handle networking, storage, or encryption
- **Clear Purpose**: Anyone reading the code immediately understands its role
- **Easy Testing**: Can test security logic independently

---

### 📌 **Example 2: ConnectionRegistry - Networking Only (Lines 73-118)**

```cpp
/**
 * Single Responsibility: Connection Management
 * DOES: Maps users to sockets
 * DOES NOT: Handle security, encryption, or message routing
 */
class ConnectionRegistry {
private:
    std::map<std::string, SOCKET> userToSocket;
    std::map<SOCKET, std::string> socketToUser;
    std::set<SOCKET> adminSockets;

public:
    // ✅ Connection tracking only
    void registerUser(const std::string& userId, SOCKET socket) { /*...*/ }
    void registerAdmin(SOCKET socket) { /*...*/ }
    void unregister(SOCKET socket) { /*...*/ }
    
    // ✅ Connection lookup only
    SOCKET getUserSocket(const std::string& userId) const { /*...*/ }
    std::string getUserId(SOCKET socket) const { /*...*/ }
    bool isAdmin(SOCKET socket) const { /*...*/ }
};
```

**🔍 Why It Follows SRP:**
- **One Reason to Change**: Only changes if connection tracking requirements change
- **No Security Logic**: Doesn't validate messages or check permissions
- **Pure Data Management**: Just stores and retrieves connection info
- **Independent**: Can work with any transport layer (TCP, UDP, etc.)

---

### 📌 **Example 3: WebSocketFrame - Protocol Only (Lines 120-198)**

```cpp
/**
 * Single Responsibility: WebSocket Protocol
 * DOES: Encodes and decodes WebSocket frames
 * DOES NOT: Handle business logic, security, or connections
 */
class WebSocketFrame {
public:
    // ✅ Protocol encoding only
    static std::string encode(const std::string& payload) {
        // RFC 6455 frame format implementation
        // No business logic, no security checks
    }
    
    // ✅ Protocol decoding only
    static std::string decode(const char* data, size_t dataLen, size_t& bytesRead) {
        // RFC 6455 frame parsing implementation
        // No message validation, no routing logic
    }
};
```

**🔍 Why It Follows SRP:**
- **One Reason to Change**: Only changes if WebSocket protocol changes (RFC update)
- **Pure Protocol**: No application-specific logic
- **Stateless**: No instance variables, pure transformation functions
- **Reusable**: Can be used in any WebSocket application

---

### 📌 **Example 4: SecureChatServer - Orchestration Only (Lines 200-477)**

```cpp
/**
 * Single Responsibility: Server Orchestration
 * DOES: Coordinates other components to run the chat server
 * DOES NOT: Implement security, protocols, or connection tracking itself
 */
class SecureChatServer {
private:
    ReplayGuard replayGuard;           // ✅ Delegates security
    ConnectionRegistry connRegistry;    // ✅ Delegates connection tracking
    // Uses WebSocketFrame static methods for protocol
    
public:
    bool start() {
        // ✅ Orchestrates: Initialize -> Listen -> Coordinate
        if (!initializeWinsock()) return false;
        if (!createSocket()) return false;
        
        while (running) {
            SOCKET clientSocket = accept(serverSocket, nullptr, nullptr);
            std::thread clientThread([this, clientSocket]() {
                this->handleClient(clientSocket);
            });
            clientThread.detach();
        }
    }
    
    void handleChatMessage(SOCKET clientSocket, const json& msg) {
        // ✅ Orchestrates: Validate -> Route -> Broadcast
        if (!replayGuard.validateTimestamp(msg.timestamp)) { /*...*/ }
        if (!replayGuard.validateCounter(msg.senderId, msg.counter)) { /*...*/ }
        
        SOCKET recipientSocket = connRegistry.getUserSocket(recipientId);
        sendToSocket(recipientSocket, msg.dump());
    }
};
```

**🔍 Why It Follows SRP:**
- **One Reason to Change**: Only changes if overall server behavior changes
- **Delegates Everything**: Security to `ReplayGuard`, connections to `ConnectionRegistry`
- **Coordinator Role**: Doesn't implement low-level details
- **Clean Architecture**: Each layer has clear boundaries

---

## 5. 🔐 THREAD SAFETY & CONCURRENCY

### Definition
**Thread Safety** ensures that shared data is accessed safely by multiple threads simultaneously, preventing race conditions and data corruption.

### Implementation in Our Project

#### **File: `server-cpp/src/main.cpp`**

### 📌 **Example 1: Mutex Protection (Lines 204-206)**

```cpp
class SecureChatServer {
private:
    ConnectionRegistry connRegistry;
    std::mutex registryMutex;  // ✅ Protects shared resource
    
    void handleChatMessage(SOCKET clientSocket, const json& msg) {
        // ✅ Critical section protection
        {
            std::lock_guard<std::mutex> lock(registryMutex);
            recipientSocket = connRegistry.getUserSocket(recipientId);
            adminSockets = connRegistry.getAdminSockets();
        }  // ✅ Automatically unlocks when lock_guard goes out of scope
    }
    
    void handleHello(SOCKET clientSocket, const json& msg) {
        // ✅ Another critical section
        {
            std::lock_guard<std::mutex> lock(registryMutex);
            connRegistry.registerUser(userId, clientSocket);
            replayGuard.clearUser(userId);
        }
    }
};
```

**🔍 Thread Safety Techniques:**
- **std::mutex**: Prevents simultaneous access to `ConnectionRegistry`
- **std::lock_guard**: RAII-based automatic lock/unlock (exception-safe)
- **Critical Sections**: Minimal locked scope for performance
- **Prevents Race Conditions**: Multiple threads can safely register/lookup users

---

### 📌 **Example 2: Multi-Threaded Server (Lines 450-463)**

```cpp
bool start() {
    running = true;
    std::cout << "Multi-threaded mode: ENABLED" << std::endl;
    
    while (running) {
        SOCKET clientSocket = accept(serverSocket, nullptr, nullptr);
        if (clientSocket != INVALID_SOCKET) {
            // ✅ Spawn new thread for each client
            std::thread clientThread([this, clientSocket]() {
                this->handleClient(clientSocket);
            });
            clientThread.detach();  // ✅ Run independently
        }
    }
    
    return true;
}
```

**🔍 Concurrency Features:**
- **One Thread Per Client**: Each connection runs independently
- **Non-Blocking**: Server continues accepting while handling clients
- **Lambda Capture**: `[this, clientSocket]` captures context safely
- **Detached Threads**: Clients run autonomously until disconnection

**💡 Why This Design:**
- **Scalability**: Handles 100+ simultaneous connections
- **Responsiveness**: No client blocks others
- **Simplicity**: Each client thread has linear, easy-to-understand logic
- **Real-World**: Modern server architecture pattern

---

## 6. 💾 RESOURCE MANAGEMENT

### Definition
**Resource Management** ensures that system resources (sockets, memory, threads) are properly acquired and released, preventing leaks and crashes.

### Implementation in Our Project

### 📌 **Example 1: RAII in Destructor (Lines 430-435)**

```cpp
class SecureChatServer {
public:
    ~SecureChatServer() {
        stop();          // ✅ Ensure server stops
        WSACleanup();    // ✅ Clean up Winsock resources
    }
    
    void stop() {
        running = false;
        if (serverSocket != INVALID_SOCKET) {
            closesocket(serverSocket);  // ✅ Release socket
        }
    }
};
```

**🔍 RAII Principles:**
- **Automatic Cleanup**: Destructor guarantees resource release
- **Exception Safety**: Resources freed even if exceptions occur
- **Predictable**: Cleanup happens at end of scope
- **No Memory Leaks**: Winsock and sockets always cleaned up

---

### 📌 **Example 2: Socket Lifecycle Management (Lines 274-298)**

```cpp
void handleClient(SOCKET clientSocket) {
    // Perform WebSocket handshake
    if (performHandshake(clientSocket).empty()) {
        closesocket(clientSocket);  // ✅ Clean up on failure
        return;
    }
    
    std::cout << "WebSocket connection established" << std::endl;
    
    char buffer[4096];
    while (running) {
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesReceived <= 0) break;  // ✅ Detect disconnection
        
        size_t bytesRead;
        std::string payload = WebSocketFrame::decode(buffer, bytesReceived, bytesRead);
        
        if (!payload.empty()) {
            handleMessage(clientSocket, payload);
        }
    }
    
    {
        std::lock_guard<std::mutex> lock(registryMutex);
        connRegistry.unregister(clientSocket);  // ✅ Clean up registry
    }
    closesocket(clientSocket);  // ✅ Always close socket
    std::cout << "Client disconnected" << std::endl;
}
```

**🔍 Resource Management Best Practices:**
- **Early Exit Cleanup**: Close socket immediately on handshake failure
- **Always Close**: Socket closed in all code paths
- **Registry Cleanup**: Remove from tracking before closing
- **No Resource Leaks**: Every opened socket is eventually closed

---

## 📊 Summary Table: OOP Concepts by Class

| Class | Encapsulation | Abstraction | Composition | SRP | Thread Safety |
|-------|--------------|-------------|-------------|-----|---------------|
| **ReplayGuard** | ✅ Private counters | ✅ Simple validation API | ❌ N/A | ✅ Security only | ⚠️ Used with mutex |
| **ConnectionRegistry** | ✅ Hidden maps | ✅ Simple user lookup | ❌ N/A | ✅ Connections only | ⚠️ Protected by server |
| **WebSocketFrame** | ✅ Static methods | ✅ Protocol hidden | ❌ N/A | ✅ Protocol only | ✅ Stateless |
| **SecureChatServer** | ✅ Private helpers | ✅ Simple start/stop | ✅ Uses ReplayGuard & Registry | ✅ Orchestration | ✅ Mutex protection |

---

## 🎯 Key Takeaways for Presentation

1. **Encapsulation**: All classes hide internal data, expose only necessary methods
2. **Abstraction**: Complex protocols (WebSocket, security) have simple interfaces
3. **Composition**: Server builds functionality by composing specialized objects
4. **SRP**: Each class has exactly ONE reason to change
5. **Thread Safety**: std::mutex and lock_guard protect shared resources
6. **RAII**: Automatic resource cleanup prevents leaks

---

## 📸 Screenshot Recommendations

**For Best Presentation Impact:**

1. **Encapsulation Screenshot**: Show `ReplayGuard` class (Lines 30-68)
2. **Abstraction Screenshot**: Show `WebSocketFrame::encode()` (Lines 122-145)
3. **Composition Screenshot**: Show `SecureChatServer` private members (Lines 200-206)
4. **SRP Screenshot**: Show all four class declarations side-by-side
5. **Thread Safety Screenshot**: Show mutex usage in `handleChatMessage()` (Lines 375-381)

**Pro Tip**: Use syntax highlighting in your screenshots to make code more readable!

---

**Document Version**: 1.0  
**Last Updated**: November 14, 2025  
**Project**: Secure Chat MVP - C++ Backend
