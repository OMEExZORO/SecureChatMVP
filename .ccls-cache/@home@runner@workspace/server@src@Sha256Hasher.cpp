#include "../include/Sha256Hasher.hpp"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>

namespace securechat {

std::string Sha256Hasher::hash(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
    
    std::ostringstream hexStream;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        hexStream << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(hash[i]);
    }
    
    return hexStream.str();
}

}
