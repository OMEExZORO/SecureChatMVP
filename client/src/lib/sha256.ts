/**
 * Custom SHA-256 Implementation
 * Based on FIPS 180-4 specification
 * No external libraries or APIs used
 */

/**
 * SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
 */
const K: number[] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

/**
 * SHA-256 class
 */
export class SHA256 {
  private h: number[] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];

  /**
   * Right rotate operation
   */
  private rotr(n: number, x: number): number {
    return (x >>> n) | (x << (32 - n));
  }

  /**
   * Process a single 512-bit block
   */
  private processBlock(block: Uint8Array): void {
    const w: number[] = new Array(64);

    // Prepare message schedule
    for (let t = 0; t < 16; t++) {
      w[t] = (block[t * 4] << 24) | (block[t * 4 + 1] << 16) | 
             (block[t * 4 + 2] << 8) | block[t * 4 + 3];
    }

    for (let t = 16; t < 64; t++) {
      const s0 = this.rotr(7, w[t - 15]) ^ this.rotr(18, w[t - 15]) ^ (w[t - 15] >>> 3);
      const s1 = this.rotr(17, w[t - 2]) ^ this.rotr(19, w[t - 2]) ^ (w[t - 2] >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }

    // Initialize working variables
    let a = this.h[0];
    let b = this.h[1];
    let c = this.h[2];
    let d = this.h[3];
    let e = this.h[4];
    let f = this.h[5];
    let g = this.h[6];
    let h = this.h[7];

    // Main compression loop
    for (let t = 0; t < 64; t++) {
      const S1 = this.rotr(6, e) ^ this.rotr(11, e) ^ this.rotr(25, e);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[t] + w[t]) >>> 0;
      const S0 = this.rotr(2, a) ^ this.rotr(13, a) ^ this.rotr(22, a);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    // Update hash values
    this.h[0] = (this.h[0] + a) >>> 0;
    this.h[1] = (this.h[1] + b) >>> 0;
    this.h[2] = (this.h[2] + c) >>> 0;
    this.h[3] = (this.h[3] + d) >>> 0;
    this.h[4] = (this.h[4] + e) >>> 0;
    this.h[5] = (this.h[5] + f) >>> 0;
    this.h[6] = (this.h[6] + g) >>> 0;
    this.h[7] = (this.h[7] + h) >>> 0;
  }

  /**
   * Hash a message
   */
  hash(message: Uint8Array): Uint8Array {
    const messageLength = message.length;
    const bitLength = messageLength * 8;

    // Calculate padding
    const paddingLength = (messageLength % 64 < 56) 
      ? 56 - (messageLength % 64) 
      : 120 - (messageLength % 64);

    // Create padded message
    const paddedLength = messageLength + paddingLength + 8;
    const padded = new Uint8Array(paddedLength);
    padded.set(message);
    padded[messageLength] = 0x80; // Append '1' bit

    // Append message length as 64-bit big-endian
    for (let i = 0; i < 8; i++) {
      padded[paddedLength - 1 - i] = (bitLength >>> (i * 8)) & 0xff;
    }

    // Process blocks
    for (let i = 0; i < paddedLength; i += 64) {
      this.processBlock(padded.slice(i, i + 64));
    }

    // Generate final hash
    const hash = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      hash[i * 4] = (this.h[i] >>> 24) & 0xff;
      hash[i * 4 + 1] = (this.h[i] >>> 16) & 0xff;
      hash[i * 4 + 2] = (this.h[i] >>> 8) & 0xff;
      hash[i * 4 + 3] = this.h[i] & 0xff;
    }

    return hash;
  }

  /**
   * Hash a string and return hex
   */
  static hashString(message: string): string {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const sha = new SHA256();
    const hash = sha.hash(data);
    return Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Hash bytes and return hex
   */
  static hashBytes(data: Uint8Array): string {
    const sha = new SHA256();
    const hash = sha.hash(data);
    return Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
  }
}
