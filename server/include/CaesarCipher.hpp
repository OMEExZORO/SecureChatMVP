#pragma once
#include "IEncryptionStrategy.hpp"

namespace securechat {

class CaesarCipher : public IEncryptionStrategy {
public:
    explicit CaesarCipher(int shift = 3) : shift_(shift) {}
    
    std::string encrypt(const std::string& plaintext, const std::string& key) override;
    std::string decrypt(const std::string& ciphertext, const std::string& key) override;
    std::string getName() const override { return "Caesar"; }
    
private:
    int shift_;
    char shiftChar(char c, int shift);
};

}
