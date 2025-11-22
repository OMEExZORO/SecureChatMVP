#ifndef SHA1_HPP
#define SHA1_HPP

#include <string>
#include <cstring>
#include <cstdint>

namespace securechat {

/**
 * @class SHA1
 * @brief Simple SHA-1 implementation for WebSocket handshake
 */
class SHA1 {
private:
    uint32_t digest[5];
    std::string buffer;
    uint64_t transforms;

    static uint32_t rol(uint32_t value, size_t bits) {
        return (value << bits) | (value >> (32 - bits));
    }

    static uint32_t blk(uint32_t block[16], size_t i) {
        return rol(block[(i+13)&15] ^ block[(i+8)&15] ^ block[(i+2)&15] ^ block[i], 1);
    }

    static void R0(uint32_t block[16], uint32_t v, uint32_t &w, uint32_t x, uint32_t y, uint32_t &z, size_t i) {
        z += ((w&(x^y))^y) + block[i] + 0x5a827999 + rol(v, 5);
        w = rol(w, 30);
    }

    static void R1(uint32_t block[16], uint32_t v, uint32_t &w, uint32_t x, uint32_t y, uint32_t &z, size_t i) {
        block[i] = blk(block, i);
        z += ((w&(x^y))^y) + block[i] + 0x5a827999 + rol(v, 5);
        w = rol(w, 30);
    }

    static void R2(uint32_t block[16], uint32_t v, uint32_t &w, uint32_t x, uint32_t y, uint32_t &z, size_t i) {
        block[i] = blk(block, i);
        z += (w^x^y) + block[i] + 0x6ed9eba1 + rol(v, 5);
        w = rol(w, 30);
    }

    static void R3(uint32_t block[16], uint32_t v, uint32_t &w, uint32_t x, uint32_t y, uint32_t &z, size_t i) {
        block[i] = blk(block, i);
        z += (((w|x)&y)|(w&x)) + block[i] + 0x8f1bbcdc + rol(v, 5);
        w = rol(w, 30);
    }

    static void R4(uint32_t block[16], uint32_t v, uint32_t &w, uint32_t x, uint32_t y, uint32_t &z, size_t i) {
        block[i] = blk(block, i);
        z += (w^x^y) + block[i] + 0xca62c1d6 + rol(v, 5);
        w = rol(w, 30);
    }

    void transform(uint32_t block[16]) {
        uint32_t a = digest[0];
        uint32_t b = digest[1];
        uint32_t c = digest[2];
        uint32_t d = digest[3];
        uint32_t e = digest[4];

        R0(block, a, b, c, d, e, 0);
        R0(block, e, a, b, c, d, 1);
        R0(block, d, e, a, b, c, 2);
        R0(block, c, d, e, a, b, 3);
        R0(block, b, c, d, e, a, 4);
        R0(block, a, b, c, d, e, 5);
        R0(block, e, a, b, c, d, 6);
        R0(block, d, e, a, b, c, 7);
        R0(block, c, d, e, a, b, 8);
        R0(block, b, c, d, e, a, 9);
        R0(block, a, b, c, d, e, 10);
        R0(block, e, a, b, c, d, 11);
        R0(block, d, e, a, b, c, 12);
        R0(block, c, d, e, a, b, 13);
        R0(block, b, c, d, e, a, 14);
        R0(block, a, b, c, d, e, 15);
        R1(block, e, a, b, c, d, 0);
        R1(block, d, e, a, b, c, 1);
        R1(block, c, d, e, a, b, 2);
        R1(block, b, c, d, e, a, 3);
        R2(block, a, b, c, d, e, 4);
        R2(block, e, a, b, c, d, 5);
        R2(block, d, e, a, b, c, 6);
        R2(block, c, d, e, a, b, 7);
        R2(block, b, c, d, e, a, 8);
        R2(block, a, b, c, d, e, 9);
        R2(block, e, a, b, c, d, 10);
        R2(block, d, e, a, b, c, 11);
        R2(block, c, d, e, a, b, 12);
        R2(block, b, c, d, e, a, 13);
        R2(block, a, b, c, d, e, 14);
        R2(block, e, a, b, c, d, 15);
        R2(block, d, e, a, b, c, 0);
        R2(block, c, d, e, a, b, 1);
        R2(block, b, c, d, e, a, 2);
        R2(block, a, b, c, d, e, 3);
        R2(block, e, a, b, c, d, 4);
        R2(block, d, e, a, b, c, 5);
        R2(block, c, d, e, a, b, 6);
        R2(block, b, c, d, e, a, 7);
        R3(block, a, b, c, d, e, 8);
        R3(block, e, a, b, c, d, 9);
        R3(block, d, e, a, b, c, 10);
        R3(block, c, d, e, a, b, 11);
        R3(block, b, c, d, e, a, 12);
        R3(block, a, b, c, d, e, 13);
        R3(block, e, a, b, c, d, 14);
        R3(block, d, e, a, b, c, 15);
        R3(block, c, d, e, a, b, 0);
        R3(block, b, c, d, e, a, 1);
        R3(block, a, b, c, d, e, 2);
        R3(block, e, a, b, c, d, 3);
        R3(block, d, e, a, b, c, 4);
        R3(block, c, d, e, a, b, 5);
        R3(block, b, c, d, e, a, 6);
        R3(block, a, b, c, d, e, 7);
        R3(block, e, a, b, c, d, 8);
        R3(block, d, e, a, b, c, 9);
        R3(block, c, d, e, a, b, 10);
        R3(block, b, c, d, e, a, 11);
        R4(block, a, b, c, d, e, 12);
        R4(block, e, a, b, c, d, 13);
        R4(block, d, e, a, b, c, 14);
        R4(block, c, d, e, a, b, 15);
        R4(block, b, c, d, e, a, 0);
        R4(block, a, b, c, d, e, 1);
        R4(block, e, a, b, c, d, 2);
        R4(block, d, e, a, b, c, 3);
        R4(block, c, d, e, a, b, 4);
        R4(block, b, c, d, e, a, 5);
        R4(block, a, b, c, d, e, 6);
        R4(block, e, a, b, c, d, 7);
        R4(block, d, e, a, b, c, 8);
        R4(block, c, d, e, a, b, 9);
        R4(block, b, c, d, e, a, 10);
        R4(block, a, b, c, d, e, 11);
        R4(block, e, a, b, c, d, 12);
        R4(block, d, e, a, b, c, 13);
        R4(block, c, d, e, a, b, 14);
        R4(block, b, c, d, e, a, 15);

        digest[0] += a;
        digest[1] += b;
        digest[2] += c;
        digest[3] += d;
        digest[4] += e;
    }

public:
    SHA1() {
        reset();
    }

    void reset() {
        digest[0] = 0x67452301;
        digest[1] = 0xefcdab89;
        digest[2] = 0x98badcfe;
        digest[3] = 0x10325476;
        digest[4] = 0xc3d2e1f0;
        buffer.clear();
        transforms = 0;
    }

    void update(const std::string &s) {
        std::istringstream is(s);
        update(is);
    }

    void update(std::istream &is) {
        while (true) {
            char sbuf[64];
            is.read(sbuf, 64 - buffer.size());
            buffer.append(sbuf, is.gcount());
            if (buffer.size() != 64) {
                return;
            }
            uint32_t block[16];
            for (size_t i = 0; i < 16; i++) {
                block[i] = (buffer[4*i+3] & 0xff)
                         | (buffer[4*i+2] & 0xff)<<8
                         | (buffer[4*i+1] & 0xff)<<16
                         | (buffer[4*i+0] & 0xff)<<24;
            }
            transform(block);
            buffer.clear();
            transforms++;
        }
    }

    std::string final() {
        unsigned char hash[20];
        size_t total_bits = (transforms*64 + buffer.size()) * 8;
        buffer += (char)0x80;
        size_t orig_size = buffer.size();
        while (buffer.size() < 64) {
            buffer += (char)0x00;
        }
        
        if (orig_size > 56) {
            uint32_t block[16];
            for (size_t i = 0; i < 16; i++) {
                block[i] = (buffer[4*i+3] & 0xff)
                         | (buffer[4*i+2] & 0xff)<<8
                         | (buffer[4*i+1] & 0xff)<<16
                         | (buffer[4*i+0] & 0xff)<<24;
            }
            transform(block);
            buffer.clear();
            while (buffer.size() < 64) {
                buffer += (char)0x00;
            }
        }
        
        buffer[63] = total_bits & 0xff;
        buffer[62] = (total_bits>>8) & 0xff;
        buffer[61] = (total_bits>>16) & 0xff;
        buffer[60] = (total_bits>>24) & 0xff;
        buffer[59] = (total_bits>>32) & 0xff;
        buffer[58] = (total_bits>>40) & 0xff;
        buffer[57] = (total_bits>>48) & 0xff;
        buffer[56] = (total_bits>>56) & 0xff;
        
        uint32_t block[16];
        for (size_t i = 0; i < 16; i++) {
            block[i] = (buffer[4*i+3] & 0xff)
                     | (buffer[4*i+2] & 0xff)<<8
                     | (buffer[4*i+1] & 0xff)<<16
                     | (buffer[4*i+0] & 0xff)<<24;
        }
        transform(block);
        
        for (size_t i = 0; i < 20; i++) {
            hash[i] = (digest[i>>2] >> (((3-(i & 0x03)) * 8))) & 0xff;
        }
        
        return std::string((char*)hash, 20);
    }

    static std::string hash(const std::string &s) {
        SHA1 sha1;
        sha1.update(s);
        return sha1.final();
    }
};

} // namespace securechat

#endif // SHA1_HPP
