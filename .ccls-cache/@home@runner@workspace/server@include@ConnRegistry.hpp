#pragma once
#include <string>
#include <map>
#include <mutex>
#include <drogon/WebSocketConnection.h>

namespace securechat {

class ConnRegistry {
public:
    void registerConnection(const std::string& userId, 
                          const drogon::WebSocketConnectionPtr& conn);
    
    void unregisterConnection(const std::string& userId);
    
    drogon::WebSocketConnectionPtr getConnection(const std::string& userId);
    
    bool isUserOnline(const std::string& userId);
    
    std::string getUserIdByConnection(const drogon::WebSocketConnectionPtr& conn);
    
private:
    std::map<std::string, drogon::WebSocketConnectionPtr> userConnections_;
    std::map<drogon::WebSocketConnectionPtr, std::string> connectionUsers_;
    std::mutex mutex_;
};

}
