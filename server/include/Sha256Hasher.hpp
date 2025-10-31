#pragma once
#include "IHasher.hpp"

namespace securechat {

class Sha256Hasher : public IHasher {
public:
    std::string hash(const std::string& data) override;
    std::string getName() const override { return "SHA-256"; }
};

}
