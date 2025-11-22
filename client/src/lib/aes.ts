/**
 * Custom AES-256 Implementation (Educational Purpose)
 * Implements AES encryption from scratch for educational demonstration
 * 
 * Based on FIPS 197 specification
 */

// AES S-Box (Substitution Box) - used in SubBytes step
const SBOX: number[] = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

// Inverse S-Box - used in InvSubBytes step for decryption
const INV_SBOX: number[] = [
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
];

// Rcon - Round constants used in key expansion
const RCON: number[] = [
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
];

/**
 * AES-256 class implementing encryption and decryption
 */
export class AES256 {
  private key: Uint8Array;
  private roundKeys: Uint8Array[] = [];
  private readonly Nr = 14; // Number of rounds for AES-256

  constructor(key: Uint8Array) {
    if (key.length !== 32) {
      throw new Error('AES-256 requires a 32-byte (256-bit) key');
    }
    this.key = key;
    this.expandKey();
  }

  /**
   * Galois Field (2^8) multiplication - used in MixColumns
   */
  private gmul(a: number, b: number): number {
    let p = 0;
    for (let i = 0; i < 8; i++) {
      if (b & 1) p ^= a;
      const hiBitSet = a & 0x80;
      a = (a << 1) & 0xff;
      if (hiBitSet) a ^= 0x1b; // XOR with irreducible polynomial
      b >>= 1;
    }
    return p;
  }

  /**
   * Key expansion - generates round keys from cipher key
   */
  private expandKey(): void {
    const Nk = 8; // Number of 32-bit words in key (256 bits / 32 = 8)
    const w: number[][] = [];

    // Copy key into first Nk words
    for (let i = 0; i < Nk; i++) {
      w[i] = [
        this.key[4 * i],
        this.key[4 * i + 1],
        this.key[4 * i + 2],
        this.key[4 * i + 3]
      ];
    }

    // Expand key
    for (let i = Nk; i < 4 * (this.Nr + 1); i++) {
      let temp = [...w[i - 1]];
      
      if (i % Nk === 0) {
        // RotWord
        temp = [temp[1], temp[2], temp[3], temp[0]];
        // SubWord
        temp = temp.map(b => SBOX[b]);
        // XOR with Rcon
        temp[0] ^= RCON[Math.floor(i / Nk)];
      } else if (i % Nk === 4) {
        // SubWord only (for AES-256)
        temp = temp.map(b => SBOX[b]);
      }
      
      w[i] = w[i - Nk].map((b, j) => b ^ temp[j]);
    }

    // Convert words to round keys
    for (let round = 0; round <= this.Nr; round++) {
      const roundKey = new Uint8Array(16);
      for (let i = 0; i < 4; i++) {
        for (let j = 0; j < 4; j++) {
          roundKey[i * 4 + j] = w[round * 4 + i][j];
        }
      }
      this.roundKeys.push(roundKey);
    }
  }

  /**
   * SubBytes transformation - substitute bytes using S-box
   */
  private subBytes(state: number[][]): void {
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 4; j++) {
        state[i][j] = SBOX[state[i][j]];
      }
    }
  }

  /**
   * Inverse SubBytes - substitute bytes using inverse S-box
   */
  private invSubBytes(state: number[][]): void {
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 4; j++) {
        state[i][j] = INV_SBOX[state[i][j]];
      }
    }
  }

  /**
   * ShiftRows transformation - circular shift rows
   */
  private shiftRows(state: number[][]): void {
    // Row 0: no shift
    // Row 1: shift left by 1
    const temp1 = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp1;

    // Row 2: shift left by 2
    let temp2 = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp2;
    temp2 = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp2;

    // Row 3: shift left by 3 (or right by 1)
    const temp3 = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp3;
  }

  /**
   * Inverse ShiftRows - circular shift rows in opposite direction
   */
  private invShiftRows(state: number[][]): void {
    // Row 1: shift right by 1
    const temp1 = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp1;

    // Row 2: shift right by 2
    let temp2 = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp2;
    temp2 = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp2;

    // Row 3: shift right by 3 (or left by 1)
    const temp3 = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp3;
  }

  /**
   * MixColumns transformation - matrix multiplication in GF(2^8)
   */
  private mixColumns(state: number[][]): void {
    for (let i = 0; i < 4; i++) {
      const s0 = state[0][i];
      const s1 = state[1][i];
      const s2 = state[2][i];
      const s3 = state[3][i];

      state[0][i] = this.gmul(0x02, s0) ^ this.gmul(0x03, s1) ^ s2 ^ s3;
      state[1][i] = s0 ^ this.gmul(0x02, s1) ^ this.gmul(0x03, s2) ^ s3;
      state[2][i] = s0 ^ s1 ^ this.gmul(0x02, s2) ^ this.gmul(0x03, s3);
      state[3][i] = this.gmul(0x03, s0) ^ s1 ^ s2 ^ this.gmul(0x02, s3);
    }
  }

  /**
   * Inverse MixColumns - inverse matrix multiplication in GF(2^8)
   */
  private invMixColumns(state: number[][]): void {
    for (let i = 0; i < 4; i++) {
      const s0 = state[0][i];
      const s1 = state[1][i];
      const s2 = state[2][i];
      const s3 = state[3][i];

      state[0][i] = this.gmul(0x0e, s0) ^ this.gmul(0x0b, s1) ^ this.gmul(0x0d, s2) ^ this.gmul(0x09, s3);
      state[1][i] = this.gmul(0x09, s0) ^ this.gmul(0x0e, s1) ^ this.gmul(0x0b, s2) ^ this.gmul(0x0d, s3);
      state[2][i] = this.gmul(0x0d, s0) ^ this.gmul(0x09, s1) ^ this.gmul(0x0e, s2) ^ this.gmul(0x0b, s3);
      state[3][i] = this.gmul(0x0b, s0) ^ this.gmul(0x0d, s1) ^ this.gmul(0x09, s2) ^ this.gmul(0x0e, s3);
    }
  }

  /**
   * AddRoundKey - XOR state with round key
   */
  private addRoundKey(state: number[][], round: number): void {
    const roundKey = this.roundKeys[round];
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 4; j++) {
        state[i][j] ^= roundKey[i * 4 + j];
      }
    }
  }

  /**
   * Convert block (Uint8Array) to state matrix
   */
  private toState(block: Uint8Array): number[][] {
    const state: number[][] = [[], [], [], []];
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 4; j++) {
        state[i][j] = block[i * 4 + j];
      }
    }
    return state;
  }

  /**
   * Convert state matrix to block (Uint8Array)
   */
  private fromState(state: number[][]): Uint8Array {
    const block = new Uint8Array(16);
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 4; j++) {
        block[i * 4 + j] = state[i][j];
      }
    }
    return block;
  }

  /**
   * Encrypt a single 16-byte block
   */
  encryptBlock(block: Uint8Array): Uint8Array {
    if (block.length !== 16) {
      throw new Error('Block must be 16 bytes');
    }

    const state = this.toState(block);

    // Initial round
    this.addRoundKey(state, 0);

    // Main rounds (1 to Nr-1)
    for (let round = 1; round < this.Nr; round++) {
      this.subBytes(state);
      this.shiftRows(state);
      this.mixColumns(state);
      this.addRoundKey(state, round);
    }

    // Final round (no MixColumns)
    this.subBytes(state);
    this.shiftRows(state);
    this.addRoundKey(state, this.Nr);

    return this.fromState(state);
  }

  /**
   * Decrypt a single 16-byte block
   */
  decryptBlock(block: Uint8Array): Uint8Array {
    if (block.length !== 16) {
      throw new Error('Block must be 16 bytes');
    }

    const state = this.toState(block);

    // Initial round
    this.addRoundKey(state, this.Nr);

    // Main rounds (Nr-1 to 1)
    for (let round = this.Nr - 1; round > 0; round--) {
      this.invShiftRows(state);
      this.invSubBytes(state);
      this.addRoundKey(state, round);
      this.invMixColumns(state);
    }

    // Final round (no InvMixColumns)
    this.invShiftRows(state);
    this.invSubBytes(state);
    this.addRoundKey(state, 0);

    return this.fromState(state);
  }

  /**
   * Encrypt data in CBC mode (Cipher Block Chaining)
   */
  encryptCBC(plaintext: Uint8Array, iv: Uint8Array): Uint8Array {
    if (iv.length !== 16) {
      throw new Error('IV must be 16 bytes');
    }

    // Apply PKCS7 padding
    const paddedLength = Math.ceil(plaintext.length / 16) * 16;
    const padded = new Uint8Array(paddedLength);
    padded.set(plaintext);
    const paddingValue = paddedLength - plaintext.length;
    for (let i = plaintext.length; i < paddedLength; i++) {
      padded[i] = paddingValue;
    }

    const ciphertext = new Uint8Array(paddedLength);
    let previousBlock = iv;

    // Encrypt each block
    for (let i = 0; i < paddedLength; i += 16) {
      const block = padded.slice(i, i + 16);
      
      // XOR with previous ciphertext block (or IV for first block)
      const xored = new Uint8Array(16);
      for (let j = 0; j < 16; j++) {
        xored[j] = block[j] ^ previousBlock[j];
      }

      // Encrypt block
      const encrypted = this.encryptBlock(xored);
      ciphertext.set(encrypted, i);
      previousBlock = encrypted;
    }

    return ciphertext;
  }

  /**
   * Decrypt data in CBC mode
   */
  decryptCBC(ciphertext: Uint8Array, iv: Uint8Array): Uint8Array {
    if (iv.length !== 16) {
      throw new Error('IV must be 16 bytes');
    }

    if (ciphertext.length % 16 !== 0) {
      throw new Error('Ciphertext length must be multiple of 16');
    }

    const plaintext = new Uint8Array(ciphertext.length);
    let previousBlock = iv;

    // Decrypt each block
    for (let i = 0; i < ciphertext.length; i += 16) {
      const block = ciphertext.slice(i, i + 16);
      
      // Decrypt block
      const decrypted = this.decryptBlock(block);
      
      // XOR with previous ciphertext block (or IV for first block)
      for (let j = 0; j < 16; j++) {
        plaintext[i + j] = decrypted[j] ^ previousBlock[j];
      }

      previousBlock = block;
    }

    // Remove PKCS7 padding
    const paddingValue = plaintext[plaintext.length - 1];
    if (paddingValue > 0 && paddingValue <= 16) {
      return plaintext.slice(0, plaintext.length - paddingValue);
    }

    return plaintext;
  }
}


