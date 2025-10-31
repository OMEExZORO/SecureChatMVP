#pragma once
#include <string>
#include <map>
#include <utility>
#include <mutex>

namespace securechat {

class ReplayGuard {
public:
    ReplayGuard(int maxAgeSeconds = 300);
    
    bool validateMessage(const std::string& senderId, 
                        const std::string& recipientId,
                        int counter,
                        long timestamp);
    
    std::string getRejectReason() const { return lastRejectReason_; }
    
private:
    using ConversationKey = std::pair<std::string, std::string>;
    
    struct ConversationState {
        int lastCounter = -1;
        long lastTimestamp = 0;
    };
    
    std::map<ConversationKey, ConversationState> conversations_;
    std::mutex mutex_;
    int maxAgeSeconds_;
    std::string lastRejectReason_;
    
    long getCurrentTimestamp() const;
};

}
