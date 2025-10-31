#include "../include/XorCipher.hpp"
#include <sstream>
#include <iomanip>

namespace securechat {

std::string XorCipher::xorOperation(const std::string& data, const std::string& key) {
    if (key.empty()) {
        return data;
    }
    
    std::string result;
    result.reserve(data.size());
    
    for (size_t i = 0; i < data.size(); ++i) {
        result += data[i] ^ key[i % key.size()];
    }
    
    return result;
}

std::string XorCipher::encrypt(const std::string& plaintext, const std::string& key) {
    std::string xored = xorOperation(plaintext, key);
    
    std::ostringstream hex;
    for (unsigned char c : xored) {
        hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    
    return hex.str();
}

std::string XorCipher::decrypt(const std::string& ciphertext, const std::string& key) {
    std::string bytes;
    for (size_t i = 0; i < ciphertext.length(); i += 2) {
        std::string byteString = ciphertext.substr(i, 2);
        char byte = static_cast<char>(std::stoi(byteString, nullptr, 16));
        bytes += byte;
    }
    
    return xorOperation(bytes, key);
}

}
