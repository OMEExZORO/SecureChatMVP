# OOP CONCEPTS - TECHNICAL DOCUMENTATION

---

## 1. ENCAPSULATION

### Definition
Bundling data and methods within a class while restricting direct access to internal components.

### Example 1: ReplayGuard Class

**File: server-cpp/src/main.cpp (Lines 30-68)**

```cpp
class ReplayGuard {
private:
    std::map<std::string, int> lastCounters;
    int timeWindowSeconds;

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
        return false;
    }
    
    void clearUser(const std::string& userId) {
        lastCounters.erase(userId);
    }
    
    bool validateTimestamp(int64_t timestamp) {
        int64_t now = static_cast<int64_t>(std::time(nullptr));
        int64_t diff = std::abs(now - timestamp);
        return diff <= timeWindowSeconds;
    }
};
```

**What it demonstrates:**
Private data members (lastCounters, timeWindowSeconds) are hidden. Public methods provide controlled access. Direct manipulation of counter data is prevented.

### Example 2: ConnectionRegistry Class

**File: server-cpp/src/main.cpp (Lines 73-118)**

```cpp
class ConnectionRegistry {
private:
    std::map<std::string, SOCKET> userToSocket;
    std::map<SOCKET, std::string> socketToUser;
    std::set<SOCKET> adminSockets;

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
    
    const std::set<SOCKET>& getAdminSockets() const {
        return adminSockets;
    }
};
```

**What it demonstrates:**
Three internal data structures (bidirectional mappings) are completely hidden. Public API provides simple methods. Bidirectional consistency is automatically maintained.

### Example 3: SecureChatServer Private Methods

**File: server-cpp/src/main.cpp (Lines 200-237)**

```cpp
class SecureChatServer {
private:
    SOCKET serverSocket;
    int port;
    bool running;
    ReplayGuard replayGuard;
    ConnectionRegistry connRegistry;
    std::mutex registryMutex;
    
    bool initializeWinsock() {
        WSADATA wsaData;
        return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
    }
    
    bool createSocket() {
        serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (serverSocket == INVALID_SOCKET) {
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
    }
};
```

**What it demonstrates:**
Complex socket initialization details are private. Public API provides simple start/stop methods. Internal state is protected from external modification.

---

## 2. ABSTRACTION

### Definition
Hiding complex implementation details and exposing only essential features.

### Example 1: WebSocketFrame Class

**File: server-cpp/src/main.cpp (Lines 120-198)**

```cpp
class WebSocketFrame {
public:
    static std::string encode(const std::string& payload) {
        std::string frame;
        size_t len = payload.length();
        
        frame += (char)0x81;
        
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

**What it demonstrates:**
WebSocket protocol (RFC 6455) complexity is completely hidden. Simple encode/decode interface. Users don't need to understand bit manipulation or framing logic.

**Usage:**
```cpp
std::string message = "Hello";
std::string frame = WebSocketFrame::encode(message);
send(socket, frame.c_str(), frame.length(), 0);

std::string payload = WebSocketFrame::decode(buffer, bytesReceived, bytesRead);
```

### Example 2: ReplayGuard Validation

**File: server-cpp/src/main.cpp (Lines 44-68)**

```cpp
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
    return false;
}

bool validateTimestamp(int64_t timestamp) {
    int64_t now = static_cast<int64_t>(std::time(nullptr));
    int64_t diff = std::abs(now - timestamp);
    return diff <= timeWindowSeconds;
}
```

**What it demonstrates:**
Complex replay attack prevention algorithm is abstracted. Simple boolean return (valid/invalid). Internal counter tracking and time calculations are hidden.

**Usage:**
```cpp
if (!replayGuard.validateTimestamp(msg.timestamp)) {
    sendReject(socket, "Timestamp out of range");
    return;
}

if (!replayGuard.validateCounter(senderId, counter)) {
    sendReject(socket, "Counter not monotonic");
    return;
}
```

### Example 3: WebSocket Handshake

**File: server-cpp/src/main.cpp (Lines 239-272)**

```cpp
std::string performHandshake(SOCKET clientSocket) {
    char buffer[4096];
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesReceived <= 0) return "";
    
    std::string request(buffer, bytesReceived);
    
    size_t keyPos = request.find("Sec-WebSocket-Key: ");
    if (keyPos == std::string::npos) return "";
    
    keyPos += 19;
    size_t keyEnd = request.find("\r\n", keyPos);
    std::string webSocketKey = request.substr(keyPos, keyEnd - keyPos);
    
    const std::string magicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string acceptInput = webSocketKey + magicString;
    
    std::string hash = SHA1::hash(acceptInput);
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

**What it demonstrates:**
HTTP upgrade and WebSocket handshake complexity is hidden. SHA-1 and Base64 encoding handled internally. Simple success/fail return.

---

## 3. COMPOSITION

### Definition
"Has-a" relationship where a class contains objects of other classes as members.

### Example: SecureChatServer Composition

**File: server-cpp/src/main.cpp (Lines 200-206)**

```cpp
class SecureChatServer {
private:
    SOCKET serverSocket;
    int port;
    bool running;
    ReplayGuard replayGuard;
    ConnectionRegistry connRegistry;
    std::mutex registryMutex;
    
public:
    explicit SecureChatServer(int p) 
        : port(p), 
          running(false), 
          replayGuard(300) {
    }
};
```

**What it demonstrates:**
SecureChatServer OWNS ReplayGuard and ConnectionRegistry. Composed objects are created/destroyed with server. Has-A relationship instead of inheritance.

### Usage of Composed Objects

**File: server-cpp/src/main.cpp (Lines 365-389)**

```cpp
void handleChatMessage(SOCKET clientSocket, const json& msg) {
    std::string senderId = msg.value("senderId", "");
    std::string recipientId = msg.value("recipientId", "");
    int counter = msg.value("counter", 0);
    int64_t timestamp = msg.value("timestamp", 0);
    
    if (!replayGuard.validateTimestamp(timestamp)) {
        sendReject(clientSocket, "Timestamp out of range");
        return;
    }
    
    if (!replayGuard.validateCounter(senderId, counter)) {
        sendReject(clientSocket, "Counter not monotonic");
        return;
    }
    
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

**What it demonstrates:**
Server delegates security to ReplayGuard and connection management to ConnectionRegistry. Clear separation of concerns. Each component handles one aspect.

---

## 4. SINGLE RESPONSIBILITY PRINCIPLE

### Definition
Each class should have only ONE reason to change. One clear purpose.

### Class Responsibilities

**ReplayGuard: Security Only**
```cpp
class ReplayGuard {
public:
    bool validateCounter(const std::string& userId, int counter);
    bool validateTimestamp(int64_t timestamp);
    void clearUser(const std::string& userId);
};
```
Does: Validates message counters and timestamps
Does NOT: Handle networking, encryption, or storage

**ConnectionRegistry: Networking Only**
```cpp
class ConnectionRegistry {
public:
    void registerUser(const std::string& userId, SOCKET socket);
    void registerAdmin(SOCKET socket);
    void unregister(SOCKET socket);
    SOCKET getUserSocket(const std::string& userId) const;
    std::string getUserId(SOCKET socket) const;
    bool isAdmin(SOCKET socket) const;
};
```
Does: Maps users to sockets
Does NOT: Handle security, encryption, or message routing

**WebSocketFrame: Protocol Only**
```cpp
class WebSocketFrame {
public:
    static std::string encode(const std::string& payload);
    static std::string decode(const char* data, size_t dataLen, size_t& bytesRead);
};
```
Does: Encodes and decodes WebSocket frames
Does NOT: Handle business logic, security, or connections

**SecureChatServer: Orchestration Only**
```cpp
class SecureChatServer {
public:
    bool start();
    void stop();
};
```
Does: Coordinates other components to run the server
Does NOT: Implement security, protocols, or connection tracking itself

### Why This Matters

Each class has exactly ONE reason to change:
- ReplayGuard changes only if replay attack algorithm changes
- ConnectionRegistry changes only if connection tracking needs change
- WebSocketFrame changes only if WebSocket protocol changes
- SecureChatServer changes only if overall server behavior changes

---

## 5. THREAD SAFETY & CONCURRENCY

### Definition
Ensuring shared data is accessed safely by multiple threads simultaneously.

### Example 1: Mutex Protection

**File: server-cpp/src/main.cpp (Lines 204-206, 375-381)**

```cpp
class SecureChatServer {
private:
    ConnectionRegistry connRegistry;
    std::mutex registryMutex;
    
    void handleChatMessage(SOCKET clientSocket, const json& msg) {
        SOCKET recipientSocket;
        std::set<SOCKET> adminSockets;
        {
            std::lock_guard<std::mutex> lock(registryMutex);
            recipientSocket = connRegistry.getUserSocket(recipientId);
            adminSockets = connRegistry.getAdminSockets();
        }
    }
    
    void handleHello(SOCKET clientSocket, const json& msg) {
        {
            std::lock_guard<std::mutex> lock(registryMutex);
            connRegistry.registerUser(userId, clientSocket);
            replayGuard.clearUser(userId);
        }
    }
};
```

**What it demonstrates:**
std::mutex prevents simultaneous access to ConnectionRegistry. std::lock_guard provides automatic lock/unlock (RAII). Critical sections have minimal locked scope for performance.

### Example 2: Multi-Threaded Server

**File: server-cpp/src/main.cpp (Lines 450-463)**

```cpp
bool start() {
    running = true;
    
    while (running) {
        SOCKET clientSocket = accept(serverSocket, nullptr, nullptr);
        if (clientSocket != INVALID_SOCKET) {
            std::thread clientThread([this, clientSocket]() {
                this->handleClient(clientSocket);
            });
            clientThread.detach();
        }
    }
    
    return true;
}
```

**What it demonstrates:**
One thread spawned per client connection. Each connection runs independently. Non-blocking server continues accepting while handling clients. Lambda capture safely passes context.

---

## 6. RESOURCE MANAGEMENT

### Definition
Ensuring system resources (sockets, memory, threads) are properly acquired and released.

### Example 1: RAII in Destructor

**File: server-cpp/src/main.cpp (Lines 430-435)**

```cpp
class SecureChatServer {
public:
    ~SecureChatServer() {
        stop();
        WSACleanup();
    }
    
    void stop() {
        running = false;
        if (serverSocket != INVALID_SOCKET) {
            closesocket(serverSocket);
        }
    }
};
```

**What it demonstrates:**
Destructor guarantees resource cleanup. Sockets and Winsock cleaned up automatically. Exception-safe (cleanup happens even if exceptions occur).

### Example 2: Socket Lifecycle Management

**File: server-cpp/src/main.cpp (Lines 274-298)**

```cpp
void handleClient(SOCKET clientSocket) {
    if (performHandshake(clientSocket).empty()) {
        closesocket(clientSocket);
        return;
    }
    
    char buffer[4096];
    while (running) {
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesReceived <= 0) break;
        
        size_t bytesRead;
        std::string payload = WebSocketFrame::decode(buffer, bytesReceived, bytesRead);
        
        if (!payload.empty()) {
            handleMessage(clientSocket, payload);
        }
    }
    
    {
        std::lock_guard<std::mutex> lock(registryMutex);
        connRegistry.unregister(clientSocket);
    }
    closesocket(clientSocket);
}
```

**What it demonstrates:**
Socket closed on handshake failure. Socket closed after client loop exits. Registry cleaned up before closing socket. Every opened socket is eventually closed.

---

## SUMMARY TABLE

| Class | Encapsulation | Abstraction | Composition | SRP | Thread Safety |
|-------|--------------|-------------|-------------|-----|---------------|
| ReplayGuard | Private counters | Simple validation API | N/A | Security only | Used with mutex |
| ConnectionRegistry | Hidden maps | Simple user lookup | N/A | Connections only | Protected by server |
| WebSocketFrame | Static methods | Protocol hidden | N/A | Protocol only | Stateless |
| SecureChatServer | Private helpers | Simple start/stop | Uses ReplayGuard & Registry | Orchestration | Mutex protection |

---

## KEY CONCEPTS BY FILE

**server-cpp/src/main.cpp:**
- Lines 30-68: ReplayGuard (Encapsulation, SRP)
- Lines 73-118: ConnectionRegistry (Encapsulation, SRP)
- Lines 120-198: WebSocketFrame (Abstraction, SRP)
- Lines 200-477: SecureChatServer (Composition, Thread Safety, RAII)

**All concepts demonstrated in single file with clear examples and practical implementation.**
