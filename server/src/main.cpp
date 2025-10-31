#include <drogon/drogon.h>
#include <drogon/WebSocketController.h>
#include <json/json.h>
#include <iostream>
#include <memory>
#include "../include/ReplayGuard.hpp"
#include "../include/ConnRegistry.hpp"

using namespace drogon;
using namespace securechat;

std::shared_ptr<ReplayGuard> replayGuard;
std::shared_ptr<ConnRegistry> connRegistry;

class ChatWebSocketController : public drogon::WebSocketController<ChatWebSocketController> {
public:
    void handleNewMessage(const WebSocketConnectionPtr& wsConnPtr,
                         std::string&& message,
                         const WebSocketMessageType& type) override {
        
        Json::Value root;
        Json::CharReaderBuilder builder;
        std::string errs;
        std::istringstream stream(message);
        
        if (!Json::parseFromStream(builder, stream, &root, &errs)) {
            Json::Value error;
            error["type"] = "ERROR";
            error["message"] = "Invalid JSON";
            wsConnPtr->send(error.toStyledString());
            return;
        }
        
        std::string msgType = root.get("type", "").asString();
        
        if (msgType == "HELLO") {
            handleHello(wsConnPtr, root);
        } else if (msgType == "MSG") {
            handleMessage(wsConnPtr, root);
        } else if (msgType == "KEY_SHARE") {
            handleKeyShare(wsConnPtr, root);
        } else {
            Json::Value error;
            error["type"] = "ERROR";
            error["message"] = "Unknown message type";
            wsConnPtr->send(error.toStyledString());
        }
    }
    
    void handleNewConnection(const HttpRequestPtr& req,
                           const WebSocketConnectionPtr& wsConnPtr) override {
        std::cout << "New WebSocket connection established" << std::endl;
    }
    
    void handleConnectionClosed(const WebSocketConnectionPtr& wsConnPtr) override {
        std::string userId = connRegistry->getUserIdByConnection(wsConnPtr);
        if (!userId.empty()) {
            connRegistry->unregisterConnection(userId);
            std::cout << "User " << userId << " disconnected" << std::endl;
        }
    }
    
    WS_PATH_LIST_BEGIN
    WS_PATH_ADD("/ws");
    WS_PATH_LIST_END
    
private:
    void handleHello(const WebSocketConnectionPtr& wsConnPtr, const Json::Value& msg) {
        std::string userId = msg.get("userId", "").asString();
        
        if (userId.empty()) {
            Json::Value error;
            error["type"] = "ERROR";
            error["message"] = "userId required in HELLO message";
            wsConnPtr->send(error.toStyledString());
            return;
        }
        
        connRegistry->registerConnection(userId, wsConnPtr);
        
        Json::Value response;
        response["type"] = "HELLO_ACK";
        response["userId"] = userId;
        response["message"] = "Connected successfully";
        
        wsConnPtr->send(response.toStyledString());
        
        std::cout << "User " << userId << " registered" << std::endl;
    }
    
    void handleKeyShare(const WebSocketConnectionPtr& wsConnPtr, const Json::Value& msg) {
        std::string senderId = msg.get("senderId", "").asString();
        std::string recipientId = msg.get("recipientId", "").asString();
        
        if (senderId.empty() || recipientId.empty()) {
            sendReject(wsConnPtr, "senderId and recipientId are required for KEY_SHARE");
            return;
        }
        
        auto recipientConn = connRegistry->getConnection(recipientId);
        if (!recipientConn) {
            sendReject(wsConnPtr, "Recipient not online");
            return;
        }
        
        recipientConn->send(msg.toStyledString());
        
        std::cout << "KEY_SHARE relayed from " << senderId 
                  << " to " << recipientId << std::endl;
    }
    
    void handleMessage(const WebSocketConnectionPtr& wsConnPtr, const Json::Value& msg) {
        std::string senderId = msg.get("senderId", "").asString();
        std::string recipientId = msg.get("recipientId", "").asString();
        int counter = msg.get("counter", 0).asInt();
        long timestamp = msg.get("timestamp", 0).asInt64();
        
        if (senderId.empty() || recipientId.empty()) {
            sendReject(wsConnPtr, "senderId and recipientId are required");
            return;
        }
        
        if (!replayGuard->validateMessage(senderId, recipientId, counter, timestamp)) {
            sendReject(wsConnPtr, replayGuard->getRejectReason());
            return;
        }
        
        auto recipientConn = connRegistry->getConnection(recipientId);
        if (!recipientConn) {
            sendReject(wsConnPtr, "Recipient not online");
            return;
        }
        
        recipientConn->send(msg.toStyledString());
        
        std::cout << "Message relayed from " << senderId 
                  << " to " << recipientId 
                  << " (counter: " << counter << ")" << std::endl;
    }
    
    void sendReject(const WebSocketConnectionPtr& wsConnPtr, const std::string& reason) {
        Json::Value reject;
        reject["type"] = "REJECT";
        reject["reason"] = reason;
        wsConnPtr->send(reject.toStyledString());
        
        std::cout << "Message rejected: " << reason << std::endl;
    }
};

int main() {
    replayGuard = std::make_shared<ReplayGuard>(300);
    connRegistry = std::make_shared<ConnRegistry>();
    
    std::cout << "=== Secure Chat Server ===" << std::endl;
    std::cout << "Starting Drogon WebSocket server..." << std::endl;
    
    app().addListener("0.0.0.0", 8080);
    
    app().registerHandler("/healthz",
        [](const HttpRequestPtr& req,
           std::function<void(const HttpResponsePtr&)>&& callback) {
            Json::Value response;
            response["status"] = "healthy";
            response["service"] = "secure-chat-server";
            
            auto resp = HttpResponse::newHttpJsonResponse(response);
            callback(resp);
        },
        {Get});
    
    std::cout << "Server listening on 0.0.0.0:8080" << std::endl;
    std::cout << "WebSocket endpoint: ws://localhost:8080/ws" << std::endl;
    std::cout << "Health check: http://localhost:8080/healthz" << std::endl;
    
    app().run();
    
    return 0;
}
