/**
 * @file main.cpp
 * @brief Entry point for Secure Chat C++ WebSocket Server
 * @details Demonstrates OOP principles: Encapsulation, Inheritance, Polymorphism, Abstraction
 * 
 * This server implements a zero-knowledge message relay for secure chat.
 * It uses Windows Sockets (Winsock2) for network communication.
 */

#include <iostream>
#include <memory>
#include <string>
#include <map>
#include <set>
#include <sstream>
#include <ctime>
#include <thread>
#include <mutex>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include "../include/json.hpp"
#include "../include/sha1.hpp"
#include "../include/base64.hpp"

#pragma comment(lib, "Ws2_32.lib")

using json = nlohmann::json;

namespace securechat {

/**
 * @class ReplayGuard
 * @brief Protects against replay attacks by tracking message counters
 * Demonstrates: Encapsulation (private data members with public interface)
 */
class ReplayGuard {
private:
    std::map<std::string, int> lastCounters;  // userId -> last valid counter
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
        return false;  // Counter not monotonic
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

/**
 * @class ConnectionRegistry
 * @brief Manages WebSocket connections and user mappings
 * Demonstrates: Encapsulation, Association (manages relationships between users and sockets)
 */
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

/**
 * @class WebSocketFrame
 * @brief Handles WebSocket protocol frame encoding/decoding
 * Demonstrates: Encapsulation (hides protocol complexity)
 */
class WebSocketFrame {
public:
    static std::string encode(const std::string& payload) {
        std::string frame;
        size_t len = payload.length();
        
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

/**
 * @class SecureChatServer
 * @brief Main WebSocket server implementing zero-knowledge message relay
 * Demonstrates: Composition (uses ReplayGuard and ConnectionRegistry)
 */
class SecureChatServer {
private:
    SOCKET serverSocket;
    int port;
    bool running;
    ReplayGuard replayGuard;
    ConnectionRegistry connRegistry;
    std::mutex registryMutex;  // Thread safety for connection registry
    
    // Helper methods (Encapsulation)
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
            std::cerr << "Bind failed: " << WSAGetLastError() << std::endl;
            return false;
        }
        
        if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
            std::cerr << "Listen failed: " << WSAGetLastError() << std::endl;
            return false;
        }
        
        return true;
    }
    
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
    
    void handleClient(SOCKET clientSocket) {
        // Perform WebSocket handshake
        if (performHandshake(clientSocket).empty()) {
            closesocket(clientSocket);
            return;
        }
        
        std::cout << "WebSocket connection established (Socket: " << clientSocket << ")" << std::endl;
        
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
        std::cout << "Client disconnected (Socket: " << clientSocket << ")" << std::endl;
    }
    
    void handleMessage(SOCKET clientSocket, const std::string& payload) {
        try {
            json msg = json::parse(payload);
            std::string type = msg.value("type", "");
            
            if (type == "HELLO") {
                handleHello(clientSocket, msg);
            } else if (type == "ADMIN_CONNECT") {
                handleAdminConnect(clientSocket);
            } else if (type == "MSG") {
                handleChatMessage(clientSocket, msg);
            } else {
                sendError(clientSocket, "Unknown message type");
            }
        } catch (const std::exception& e) {
            sendError(clientSocket, std::string("Parse error: ") + e.what());
        }
    }
    
    void handleHello(SOCKET clientSocket, const json& msg) {
        std::string userId = msg.value("userId", "");
        if (userId.empty()) {
            sendError(clientSocket, "userId required");
            return;
        }
        
        {
            std::lock_guard<std::mutex> lock(registryMutex);
            connRegistry.registerUser(userId, clientSocket);
            replayGuard.clearUser(userId);  // Clear replay guard on reconnect
        }
        
        json response;
        response["type"] = "HELLO_ACK";
        response["userId"] = userId;
        response["message"] = "Connected successfully";
        
        sendToSocket(clientSocket, response.dump());
        std::cout << "User registered: " << userId << " (Socket: " << clientSocket << ")" << std::endl;
    }
    
    void handleAdminConnect(SOCKET clientSocket) {
        {
            std::lock_guard<std::mutex> lock(registryMutex);
            connRegistry.registerAdmin(clientSocket);
        }
        
        json response;
        response["type"] = "ADMIN_CONNECTED";
        response["message"] = "Admin connection established";
        
        sendToSocket(clientSocket, response.dump());
        std::cout << "Admin connected (Socket: " << clientSocket << ")" << std::endl;
    }
    
    void handleChatMessage(SOCKET clientSocket, const json& msg) {
        std::string senderId = msg.value("senderId", "");
        std::string recipientId = msg.value("recipientId", "");
        int counter = msg.value("counter", 0);
        int64_t timestamp = msg.value("timestamp", 0);
        
        // Validate timestamp
        if (!replayGuard.validateTimestamp(timestamp)) {
            sendReject(clientSocket, "Timestamp out of range");
            return;
        }
        
        // Validate counter
        if (!replayGuard.validateCounter(senderId, counter)) {
            sendReject(clientSocket, "Counter not monotonic");
            return;
        }
        
        // Forward to recipient
        SOCKET recipientSocket;
        std::set<SOCKET> adminSockets;
        {
            std::lock_guard<std::mutex> lock(registryMutex);
            recipientSocket = connRegistry.getUserSocket(recipientId);
            adminSockets = connRegistry.getAdminSockets();
        }
        
        if (recipientSocket != INVALID_SOCKET) {
            sendToSocket(recipientSocket, msg.dump());
            std::cout << "Message relayed: " << senderId << " -> " << recipientId 
                      << " (counter: " << counter << ")" << std::endl;
        } else {
            sendReject(clientSocket, "Recipient not online");
            return;
        }
        
        // Broadcast to admin clients
        json adminMsg = msg;
        adminMsg["type"] = "ADMIN_MSG";
        std::string adminPayload = adminMsg.dump();
        
        for (SOCKET adminSocket : adminSockets) {
            sendToSocket(adminSocket, adminPayload);
        }
        std::cout << "Broadcasted to " << adminSockets.size() << " admin clients" << std::endl;
    }
    
    void sendToSocket(SOCKET socket, const std::string& message) {
        std::string frame = WebSocketFrame::encode(message);
        send(socket, frame.c_str(), frame.length(), 0);
    }
    
    void sendError(SOCKET socket, const std::string& errorMsg) {
        json error;
        error["type"] = "ERROR";
        error["message"] = errorMsg;
        sendToSocket(socket, error.dump());
    }
    
    void sendReject(SOCKET socket, const std::string& reason) {
        json reject;
        reject["type"] = "REJECT";
        reject["reason"] = reason;
        sendToSocket(socket, reject.dump());
    }

public:
    explicit SecureChatServer(int p) : port(p), running(false), replayGuard(300) {}
    
    ~SecureChatServer() {
        stop();
        WSACleanup();
    }
    
    bool start() {
        if (!initializeWinsock()) {
            std::cerr << "Failed to initialize Winsock" << std::endl;
            return false;
        }
        
        if (!createSocket()) {
            return false;
        }
        
        running = true;
        std::cout << "=== Secure Chat Server ===" << std::endl;
        std::cout << "Server listening on 0.0.0.0:" << port << std::endl;
        std::cout << "WebSocket endpoint: ws://localhost:" << port << "/ws" << std::endl;
        std::cout << "Multi-threaded mode: ENABLED" << std::endl;
        
        while (running) {
            SOCKET clientSocket = accept(serverSocket, nullptr, nullptr);
            if (clientSocket != INVALID_SOCKET) {
                // Spawn a new thread for each client connection
                std::thread clientThread([this, clientSocket]() {
                    this->handleClient(clientSocket);
                });
                clientThread.detach();  // Detach thread to handle multiple clients concurrently
            }
        }
        
        return true;
    }
    
    void stop() {
        running = false;
        if (serverSocket != INVALID_SOCKET) {
            closesocket(serverSocket);
        }
    }
};

} // namespace securechat

int main() {
    securechat::SecureChatServer server(8080);
    server.start();
    return 0;
}
