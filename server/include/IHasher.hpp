#pragma once
#include <string>

namespace securechat {

class IHasher {
public:
    virtual ~IHasher() = default;
    
    virtual std::string hash(const std::string& data) = 0;
    virtual std::string getName() const = 0;
};

}
