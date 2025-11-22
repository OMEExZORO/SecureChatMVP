// Custom cryptographic implementations for secure chat
// Educational implementations of encryption algorithms
// NO external APIs used (except hardware RNG for true randomness)

import { AES256 } from './aes';
import { SHA256 } from './sha256';
import { PBKDF2, computeHMAC as computeHMACInternal } from './pbkdf2';
import { generateRandomBytes as generateRandom } from './random';

const PBKDF2_ITERATIONS = 200000;
const SALT_LENGTH = 16;
const IV_LENGTH = 16; // Changed to 16 for AES-CBC

export type CipherType = 'XOR' | 'CAESAR' | 'AES-256-CBC';

export interface EncryptedData {
  iv: string; // base64
  ciphertext: string; // base64
  authTag: string; // base64
  sha256: string; // hex
}

export interface CipherInfo {
  name: CipherType;
  displayName: string;
  securityLevel: 'low' | 'medium' | 'high';
  description: string;
  color: string;
}

export const AVAILABLE_CIPHERS: CipherInfo[] = [
  {
    name: 'XOR',
    displayName: 'XOR Cipher',
    securityLevel: 'low',
    description: 'Simple XOR operation. Educational only - easily breakable.',
    color: 'red'
  },
  {
    name: 'CAESAR',
    displayName: 'Caesar Cipher',
    securityLevel: 'low',
    description: 'Classical substitution cipher. Very weak - only 26 possible keys.',
    color: 'orange'
  },
  {
    name: 'AES-256-CBC',
    displayName: 'AES-256-CBC (Custom)',
    securityLevel: 'high',
    description: 'Custom AES-256 implementation with S-Box, MixColumns, ShiftRows. Educational demonstration.',
    color: 'green'
  }
];

/**
 * Generate a random salt for key derivation
 */
export async function generateSalt(): Promise<Uint8Array> {
  return generateRandom(SALT_LENGTH);
}

/**
 * Custom SHA-256 implementation
 */
async function computeSHA256Custom(data: string): Promise<string> {
  return SHA256.hashString(data);
}

/**
 * HMAC-SHA256 for authentication (custom implementation)
 */
async function computeHMAC(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  return computeHMACInternal(key, data).slice(0, 16); // 16 bytes for tag
}

/**
 * Derive an AES-256 key from a passphrase (returns raw bytes)
 * Uses custom PBKDF2 implementation
 */
export async function deriveKeyBytes(
  passphrase: string,
  salt: Uint8Array
): Promise<Uint8Array> {
  return PBKDF2.derive(passphrase, salt, PBKDF2_ITERATIONS, 32);
}

/**
 * Create canonical AAD (Additional Authenticated Data)
 * Format: {"counter":N,"recipientId":"R","senderId":"S"}
 * Keys MUST be alphabetically sorted
 */
export function createCanonicalAAD(aad: {
  senderId: string;
  recipientId: string;
  counter: number;
}): string {
  const canonical = {
    counter: aad.counter,
    recipientId: aad.recipientId,
    senderId: aad.senderId,
  };
  return JSON.stringify(canonical);
}

/**
 * Encrypt plaintext using custom AES-256-CBC
 */
export async function encryptMessage(
  plaintext: string,
  key: Uint8Array,
  aadString: string
): Promise<EncryptedData> {
  const encoder = new TextEncoder();
  const plaintextBuffer = encoder.encode(plaintext);
  const iv = generateRandom(IV_LENGTH);

  // Create AES cipher
  const aes = new AES256(key);

  // Encrypt with AES-CBC
  const ciphertext = aes.encryptCBC(plaintextBuffer, iv);

  // Compute SHA-256 of plaintext for integrity
  const sha256 = await computeSHA256Custom(plaintext);

  // For CBC mode, create HMAC as authentication tag
  const authTag = await computeHMAC(key, new Uint8Array([...ciphertext, ...encoder.encode(aadString)]));

  return {
    iv: arrayBufferToBase64(iv),
    ciphertext: arrayBufferToBase64(ciphertext),
    authTag: arrayBufferToBase64(authTag),
    sha256,
  };
}

/**
 * Decrypt ciphertext using custom AES-256-CBC
 */
export async function decryptMessage(
  iv: string,
  ciphertext: string,
  authTag: string,
  key: Uint8Array,
  aadString: string
): Promise<string> {
  const ivBuffer = new Uint8Array(base64ToArrayBuffer(iv));
  const ciphertextBuffer = new Uint8Array(base64ToArrayBuffer(ciphertext));
  const receivedAuthTag = authTag;
  const encoder = new TextEncoder();

  // Verify HMAC authentication tag
  const computedAuthTag = await computeHMAC(key, new Uint8Array([...ciphertextBuffer, ...encoder.encode(aadString)]));
  const computedAuthTagBase64 = arrayBufferToBase64(computedAuthTag);

  if (computedAuthTagBase64 !== receivedAuthTag) {
    throw new Error('Authentication failed - message may have been tampered with');
  }

  try {
    // Create AES cipher
    const aes = new AES256(key);

    // Decrypt with AES-CBC
    const decryptedBuffer = aes.decryptCBC(ciphertextBuffer, ivBuffer);

    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
  } catch (error) {
    throw new Error('Decryption failed - invalid key or corrupted data');
  }
}

/**
 * Verify SHA-256 hash of decrypted plaintext
 */
export async function verifyHash(plaintext: string, expectedHash: string): Promise<boolean> {
  const actualHash = await computeSHA256Custom(plaintext);
  return actualHash === expectedHash.toLowerCase();
}

// Helper functions for base64 encoding/decoding
function arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Export salt conversion helpers
export function saltToBase64(salt: Uint8Array): string {
  return arrayBufferToBase64(salt);
}

export function base64ToSalt(base64: string): Uint8Array {
  return new Uint8Array(base64ToArrayBuffer(base64));
}

// ============================================================================
// EDUCATIONAL CIPHERS (XOR and Caesar)
// ============================================================================

/**
 * XOR Cipher - Simple bitwise XOR operation
 * Security: LOW - Pattern analysis can easily break it
 */
export async function encryptXOR(plaintext: string, key: string): Promise<EncryptedData> {
  const encoder = new TextEncoder();
  const plaintextBytes = encoder.encode(plaintext);
  const keyBytes = encoder.encode(key);
  
  // XOR operation
  const cipherBytes = new Uint8Array(plaintextBytes.length);
  for (let i = 0; i < plaintextBytes.length; i++) {
    cipherBytes[i] = plaintextBytes[i] ^ keyBytes[i % keyBytes.length];
  }
  
  const sha256 = await computeSHA256Custom(plaintext);
  
  return {
    iv: '', // XOR doesn't use IV
    ciphertext: arrayBufferToBase64(cipherBytes),
    authTag: '', // XOR doesn't have authentication
    sha256
  };
}

export async function decryptXOR(ciphertext: string, key: string): Promise<string> {
  const cipherBytes = new Uint8Array(base64ToArrayBuffer(ciphertext));
  const keyBytes = new TextEncoder().encode(key);
  
  // XOR operation (same as encryption)
  const plaintextBytes = new Uint8Array(cipherBytes.length);
  for (let i = 0; i < cipherBytes.length; i++) {
    plaintextBytes[i] = cipherBytes[i] ^ keyBytes[i % keyBytes.length];
  }
  
  const decoder = new TextDecoder();
  return decoder.decode(plaintextBytes);
}

/**
 * Caesar Cipher - Classical substitution cipher
 * Security: VERY LOW - Only 26 possible keys, trivial to brute force
 */
export async function encryptCaesar(plaintext: string, key: string): Promise<EncryptedData> {
  // Derive shift value from key
  let shift = 0;
  for (let i = 0; i < key.length; i++) {
    shift += key.charCodeAt(i);
  }
  shift = shift % 26;
  
  let ciphertext = '';
  for (let i = 0; i < plaintext.length; i++) {
    const char = plaintext[i];
    if (char >= 'a' && char <= 'z') {
      ciphertext += String.fromCharCode(((char.charCodeAt(0) - 97 + shift) % 26) + 97);
    } else if (char >= 'A' && char <= 'Z') {
      ciphertext += String.fromCharCode(((char.charCodeAt(0) - 65 + shift) % 26) + 65);
    } else {
      ciphertext += char; // Non-alphabetic characters unchanged
    }
  }
  
  const sha256 = await computeSHA256Custom(plaintext);
  
  return {
    iv: shift.toString(), // Store shift in IV field
    ciphertext: btoa(ciphertext), // base64 encode
    authTag: '', // Caesar doesn't have authentication
    sha256
  };
}

export async function decryptCaesar(ciphertext: string, iv: string): Promise<string> {
  const shift = parseInt(iv) || 0;
  const decoded = atob(ciphertext);
  
  let plaintext = '';
  for (let i = 0; i < decoded.length; i++) {
    const char = decoded[i];
    if (char >= 'a' && char <= 'z') {
      plaintext += String.fromCharCode(((char.charCodeAt(0) - 97 - shift + 26) % 26) + 97);
    } else if (char >= 'A' && char <= 'Z') {
      plaintext += String.fromCharCode(((char.charCodeAt(0) - 65 - shift + 26) % 26) + 65);
    } else {
      plaintext += char;
    }
  }
  
  return plaintext;
}

// ============================================================================
// UNIFIED ENCRYPTION/DECRYPTION INTERFACE
// ============================================================================

export async function encryptWithCipher(
  plaintext: string,
  key: CryptoKey | Uint8Array | string,
  cipher: CipherType,
  aadString?: string
): Promise<EncryptedData> {
  switch (cipher) {
    case 'XOR':
      return encryptXOR(plaintext, key as string);
    case 'CAESAR':
      return encryptCaesar(plaintext, key as string);
    case 'AES-256-CBC':
      if (typeof key === 'string' || !aadString) {
        throw new Error('AES-256-CBC requires Uint8Array key and AAD');
      }
      return encryptMessage(plaintext, key as Uint8Array, aadString);
    default:
      throw new Error(`Unknown cipher: ${cipher}`);
  }
}

export async function decryptWithCipher(
  encrypted: EncryptedData,
  key: CryptoKey | Uint8Array | string,
  cipher: CipherType,
  aadString?: string
): Promise<string> {
  switch (cipher) {
    case 'XOR':
      return decryptXOR(encrypted.ciphertext, key as string);
    case 'CAESAR':
      return decryptCaesar(encrypted.ciphertext, encrypted.iv);
    case 'AES-256-CBC':
      if (typeof key === 'string' || !aadString) {
        throw new Error('AES-256-CBC requires Uint8Array key and AAD');
      }
      return decryptMessage(encrypted.iv, encrypted.ciphertext, encrypted.authTag, key as Uint8Array, aadString);
    default:
      throw new Error(`Unknown cipher: ${cipher}`);
  }
}
