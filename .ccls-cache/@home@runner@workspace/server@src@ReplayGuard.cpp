#include "../include/ReplayGuard.hpp"
#include <chrono>
#include <sstream>

namespace securechat {

ReplayGuard::ReplayGuard(int maxAgeSeconds) 
    : maxAgeSeconds_(maxAgeSeconds) {
}

long ReplayGuard::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::seconds>(duration).count();
}

bool ReplayGuard::validateMessage(const std::string& senderId, 
                                  const std::string& recipientId,
                                  int counter,
                                  long timestamp) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    long currentTime = getCurrentTimestamp();
    long timeDiff = currentTime - timestamp;
    
    if (timeDiff > maxAgeSeconds_ || timeDiff < -maxAgeSeconds_) {
        std::ostringstream oss;
        oss << "Timestamp outside allowed window (±" << maxAgeSeconds_ 
            << "s). Diff: " << timeDiff << "s";
        lastRejectReason_ = oss.str();
        return false;
    }
    
    ConversationKey key = std::make_pair(senderId, recipientId);
    auto it = conversations_.find(key);
    
    if (it != conversations_.end()) {
        if (counter <= it->second.lastCounter) {
            std::ostringstream oss;
            oss << "Counter not monotonic. Received: " << counter 
                << ", Last: " << it->second.lastCounter;
            lastRejectReason_ = oss.str();
            return false;
        }
        
        it->second.lastCounter = counter;
        it->second.lastTimestamp = timestamp;
    } else {
        ConversationState state;
        state.lastCounter = counter;
        state.lastTimestamp = timestamp;
        conversations_[key] = state;
    }
    
    lastRejectReason_ = "";
    return true;
}

}
