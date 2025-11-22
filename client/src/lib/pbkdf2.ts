/**
 * Custom PBKDF2 Implementation
 * Password-Based Key Derivation Function 2
 * Based on RFC 2898
 * No external libraries or APIs used
 */

import { SHA256 } from './sha256';

/**
 * HMAC-SHA256 implementation
 */
class HMAC_SHA256 {
  /**
   * Compute HMAC-SHA256
   */
  static compute(key: Uint8Array, message: Uint8Array): Uint8Array {
    const blockSize = 64; // SHA-256 block size in bytes
    
    // If key is longer than block size, hash it
    let processedKey: Uint8Array;
    if (key.length > blockSize) {
      const sha = new SHA256();
      processedKey = sha.hash(key);
    } else {
      processedKey = key;
    }

    // Pad key to block size
    const paddedKey = new Uint8Array(blockSize);
    paddedKey.set(processedKey);

    // Create inner and outer padded keys
    const ipad = new Uint8Array(blockSize);
    const opad = new Uint8Array(blockSize);
    
    for (let i = 0; i < blockSize; i++) {
      ipad[i] = paddedKey[i] ^ 0x36;
      opad[i] = paddedKey[i] ^ 0x5c;
    }

    // Inner hash: H(K XOR ipad, message)
    const innerMessage = new Uint8Array(blockSize + message.length);
    innerMessage.set(ipad);
    innerMessage.set(message, blockSize);
    
    const sha1 = new SHA256();
    const innerHash = sha1.hash(innerMessage);

    // Outer hash: H(K XOR opad, innerHash)
    const outerMessage = new Uint8Array(blockSize + innerHash.length);
    outerMessage.set(opad);
    outerMessage.set(innerHash, blockSize);
    
    const sha2 = new SHA256();
    return sha2.hash(outerMessage);
  }
}

/**
 * PBKDF2 implementation
 */
export class PBKDF2 {
  /**
   * Derive key using PBKDF2-HMAC-SHA256
   * @param password - Password string
   * @param salt - Salt bytes
   * @param iterations - Number of iterations
   * @param keyLength - Desired key length in bytes
   */
  static derive(
    password: string,
    salt: Uint8Array,
    iterations: number,
    keyLength: number
  ): Uint8Array {
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);

    const hLen = 32; // SHA-256 output length
    const l = Math.ceil(keyLength / hLen);
    const r = keyLength - (l - 1) * hLen;

    const derivedKey = new Uint8Array(keyLength);
    let offset = 0;

    for (let i = 1; i <= l; i++) {
      const block = this.computeBlock(passwordBytes, salt, iterations, i);
      const copyLength = (i === l && r !== 0) ? r : hLen;
      derivedKey.set(block.slice(0, copyLength), offset);
      offset += copyLength;
    }

    return derivedKey;
  }

  /**
   * Compute a single PBKDF2 block
   */
  private static computeBlock(
    password: Uint8Array,
    salt: Uint8Array,
    iterations: number,
    blockNumber: number
  ): Uint8Array {
    // Concatenate salt and block number (big-endian)
    const saltBlock = new Uint8Array(salt.length + 4);
    saltBlock.set(salt);
    saltBlock[salt.length] = (blockNumber >>> 24) & 0xff;
    saltBlock[salt.length + 1] = (blockNumber >>> 16) & 0xff;
    saltBlock[salt.length + 2] = (blockNumber >>> 8) & 0xff;
    saltBlock[salt.length + 3] = blockNumber & 0xff;

    // U1 = HMAC(password, salt || blockNumber)
    let u = HMAC_SHA256.compute(password, saltBlock);
    const result = new Uint8Array(u);

    // U2 through Uc = HMAC(password, U(i-1))
    for (let i = 1; i < iterations; i++) {
      u = HMAC_SHA256.compute(password, u);
      
      // XOR with result
      for (let j = 0; j < result.length; j++) {
        result[j] ^= u[j];
      }
    }

    return result;
  }
}

/**
 * Export HMAC for standalone use
 */
export function computeHMAC(key: Uint8Array, data: Uint8Array): Uint8Array {
  return HMAC_SHA256.compute(key, data);
}
