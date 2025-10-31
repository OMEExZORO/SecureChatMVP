#pragma once
#include <string>
#include <vector>
#include <memory>

namespace securechat {

class IEncryptionStrategy {
public:
    virtual ~IEncryptionStrategy() = default;
    
    virtual std::string encrypt(const std::string& plaintext, const std::string& key) = 0;
    virtual std::string decrypt(const std::string& ciphertext, const std::string& key) = 0;
    virtual std::string getName() const = 0;
};

}
