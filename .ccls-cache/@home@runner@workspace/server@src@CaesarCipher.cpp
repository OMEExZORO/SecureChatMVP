#include "../include/CaesarCipher.hpp"

namespace securechat {

char CaesarCipher::shiftChar(char c, int shift) {
    if (c >= 'a' && c <= 'z') {
        return 'a' + (c - 'a' + shift + 26) % 26;
    } else if (c >= 'A' && c <= 'Z') {
        return 'A' + (c - 'A' + shift + 26) % 26;
    }
    return c;
}

std::string CaesarCipher::encrypt(const std::string& plaintext, const std::string& key) {
    int actualShift = shift_;
    if (!key.empty()) {
        actualShift = (shift_ + static_cast<int>(key[0])) % 26;
    }
    
    std::string result;
    result.reserve(plaintext.size());
    
    for (char c : plaintext) {
        result += shiftChar(c, actualShift);
    }
    
    return result;
}

std::string CaesarCipher::decrypt(const std::string& ciphertext, const std::string& key) {
    int actualShift = shift_;
    if (!key.empty()) {
        actualShift = (shift_ + static_cast<int>(key[0])) % 26;
    }
    
    std::string result;
    result.reserve(ciphertext.size());
    
    for (char c : ciphertext) {
        result += shiftChar(c, -actualShift);
    }
    
    return result;
}

}
