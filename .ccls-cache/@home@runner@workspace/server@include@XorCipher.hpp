#pragma once
#include "IEncryptionStrategy.hpp"

namespace securechat {

class XorCipher : public IEncryptionStrategy {
public:
    std::string encrypt(const std::string& plaintext, const std::string& key) override;
    std::string decrypt(const std::string& ciphertext, const std::string& key) override;
    std::string getName() const override { return "XOR"; }
    
private:
    std::string xorOperation(const std::string& data, const std::string& key);
};

}
