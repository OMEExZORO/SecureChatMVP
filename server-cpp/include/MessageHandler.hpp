#ifndef MESSAGE_HANDLER_HPP
#define MESSAGE_HANDLER_HPP

#include <string>
#include <memory>
#include <map>
#include <set>
#include "json.hpp"

using json = nlohmann::json;

namespace securechat {

/**
 * @brief Abstract base class for message handling (Abstraction, Polymorphism)
 * Demonstrates OOP principle: Abstract base class with virtual methods
 */
class MessageHandler {
public:
    virtual ~MessageHandler() = default;
    virtual void handleMessage(SOCKET clientSocket, const std::string& message) = 0;
    virtual void onClientConnected(SOCKET clientSocket) = 0;
    virtual void onClientDisconnected(SOCKET clientSocket) = 0;
};

/**
 * @brief Concrete implementation of MessageHandler for secure chat
 * Demonstrates OOP: Inheritance, Polymorphism
 */
class SecureChatMessageHandler : public MessageHandler {
private:
    // User registry: socket -> userId
    std::map<SOCKET, std::string> socketToUser;
    std::map<std::string, SOCKET> userToSocket;
    
    // Admin clients
    std::set<SOCKET> adminClients;
    
    // Replay protection: userId -> last counter
    std::map<std::string, int> replayGuard;

    // Helper methods (Encapsulation)
    void handleHello(SOCKET clientSocket, const json& message);
    void handleMessage(SOCKET clientSocket, const json& message);
    void handleAdminConnect(SOCKET clientSocket);
    bool validateTimestamp(int64_t timestamp);
    bool validateCounter(const std::string& userId, int counter);

public:
    SecureChatMessageHandler() = default;
    virtual ~SecureChatMessageHandler() = default;

    // Override base class methods (Polymorphism)
    void handleMessage(SOCKET clientSocket, const std::string& message) override;
    void onClientConnected(SOCKET clientSocket) override;
    void onClientDisconnected(SOCKET clientSocket) override;

    // Additional methods
    void sendToUser(const std::string& userId, const std::string& message);
    void broadcastToAdmins(const std::string& message);
};

} // namespace securechat

#endif // MESSAGE_HANDLER_HPP
