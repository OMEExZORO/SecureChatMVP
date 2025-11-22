#ifndef WEBSOCKET_SERVER_HPP
#define WEBSOCKET_SERVER_HPP

#include <string>
#include <map>
#include <memory>
#include <functional>
#include <WinSock2.h>
#include <WS2tcpip.h>

namespace securechat {

// Forward declarations
class WebSocketConnection;
class MessageHandler;

/**
 * @brief WebSocket Server class using Windows Sockets
 * Demonstrates OOP principles: Encapsulation, Abstraction
 */
class WebSocketServer {
private:
    SOCKET serverSocket;
    int port;
    bool running;
    std::map<SOCKET, std::shared_ptr<WebSocketConnection>> connections;
    std::shared_ptr<MessageHandler> messageHandler;

    // Private helper methods (Encapsulation)
    bool initializeWinsock();
    bool createServerSocket();
    void acceptConnections();
    void handleClientData(SOCKET clientSocket);
    std::string performWebSocketHandshake(const std::string& request);
    std::string generateAcceptKey(const std::string& webSocketKey);

public:
    // Constructor & Destructor
    explicit WebSocketServer(int port);
    virtual ~WebSocketServer();

    // Delete copy constructor and assignment (Best practice)
    WebSocketServer(const WebSocketServer&) = delete;
    WebSocketServer& operator=(const WebSocketServer&) = delete;

    // Public interface
    bool start();
    void stop();
    void setMessageHandler(std::shared_ptr<MessageHandler> handler);
    void broadcast(const std::string& message, SOCKET excludeSocket = INVALID_SOCKET);
    void sendToSocket(SOCKET socket, const std::string& message);
    
    // Getter
    bool isRunning() const { return running; }
};

/**
 * @brief Represents a WebSocket connection (Encapsulation)
 */
class WebSocketConnection {
private:
    SOCKET socket;
    std::string userId;
    bool isHandshakeComplete;

public:
    explicit WebSocketConnection(SOCKET sock);
    ~WebSocketConnection();

    SOCKET getSocket() const { return socket; }
    void setUserId(const std::string& id) { userId = id; }
    std::string getUserId() const { return userId; }
    void setHandshakeComplete(bool complete) { isHandshakeComplete = complete; }
    bool handshakeComplete() const { return isHandshakeComplete; }

    bool send(const std::string& message);
    std::string receive();
};

} // namespace securechat

#endif // WEBSOCKET_SERVER_HPP
