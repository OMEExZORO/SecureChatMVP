#include "../include/ConnRegistry.hpp"

namespace securechat {

void ConnRegistry::registerConnection(const std::string& userId, 
                                     const drogon::WebSocketConnectionPtr& conn) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto oldConn = userConnections_.find(userId);
    if (oldConn != userConnections_.end()) {
        connectionUsers_.erase(oldConn->second);
    }
    
    userConnections_[userId] = conn;
    connectionUsers_[conn] = userId;
}

void ConnRegistry::unregisterConnection(const std::string& userId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = userConnections_.find(userId);
    if (it != userConnections_.end()) {
        connectionUsers_.erase(it->second);
        userConnections_.erase(it);
    }
}

drogon::WebSocketConnectionPtr ConnRegistry::getConnection(const std::string& userId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = userConnections_.find(userId);
    if (it != userConnections_.end()) {
        return it->second;
    }
    
    return nullptr;
}

bool ConnRegistry::isUserOnline(const std::string& userId) {
    std::lock_guard<std::mutex> lock(mutex_);
    return userConnections_.find(userId) != userConnections_.end();
}

std::string ConnRegistry::getUserIdByConnection(const drogon::WebSocketConnectionPtr& conn) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = connectionUsers_.find(conn);
    if (it != connectionUsers_.end()) {
        return it->second;
    }
    
    return "";
}

}
