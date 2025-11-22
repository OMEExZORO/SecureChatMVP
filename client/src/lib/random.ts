/**
 * Custom Random Number Generator
 * Uses browser's crypto.getRandomValues for true randomness
 * This is the ONLY acceptable use of browser API for cryptographic randomness
 * (Generating truly random numbers without hardware is impossible)
 */

/**
 * Generate cryptographically secure random bytes
 * Note: This uses crypto.getRandomValues which accesses hardware RNG
 * This is acceptable as generating true randomness requires hardware
 */
export function generateRandomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  
  // Use browser's hardware random number generator
  // This is the ONLY Web Crypto API call we keep because:
  // 1. True randomness requires hardware (CPU instruction RDRAND, etc.)
  // 2. Software PRNGs are not cryptographically secure for key generation
  // 3. This is a primitive operation, not a complex algorithm
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    // Fallback for non-browser environments (NOT cryptographically secure!)
    console.warn('crypto.getRandomValues not available, using Math.random() fallback');
    for (let i = 0; i < length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  
  return bytes;
}

/**
 * Generate a random integer between min and max (inclusive)
 */
export function randomInt(min: number, max: number): number {
  const range = max - min + 1;
  const bytes = generateRandomBytes(4);
  const value = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
  return min + (value >>> 0) % range;
}

/**
 * Generate a random string of specified length
 */
export function randomString(length: number, charset: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'): string {
  const bytes = generateRandomBytes(length);
  let result = '';
  
  for (let i = 0; i < length; i++) {
    result += charset[bytes[i] % charset.length];
  }
  
  return result;
}
