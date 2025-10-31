export interface EncryptionResult {
  ciphertext: string;
  iv: string;
  authTag: string;
  sha256: string;
}

export type EncryptionStrategy = 'AES-GCM' | 'XOR' | 'Caesar';

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
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

function arrayBufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function deriveKey(
  passphrase: string,
  salt: string
): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: base64ToArrayBuffer(salt),
      iterations: 200000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export function generateSalt(): string {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  return arrayBufferToBase64(saltBytes.buffer);
}

export async function sha256Hash(text: string): Promise<string> {
  const enc = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', enc.encode(text));
  return arrayBufferToHex(hashBuffer);
}

export async function encryptAESGCM(
  plaintext: string,
  key: CryptoKey,
  aad: { senderId: string; recipientId: string; counter: number }
): Promise<EncryptionResult> {
  const enc = new TextEncoder();
  const plaintextBytes = enc.encode(plaintext);
  
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  const aadString = JSON.stringify(aad);
  const aadBytes = enc.encode(aadString);
  
  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      additionalData: aadBytes,
    },
    key,
    plaintextBytes
  );
  
  const encryptedBytes = new Uint8Array(encrypted);
  const tagLength = 16;
  const ciphertext = encryptedBytes.slice(0, encryptedBytes.length - tagLength);
  const authTag = encryptedBytes.slice(encryptedBytes.length - tagLength);
  
  const hash = await sha256Hash(plaintext);
  
  return {
    ciphertext: arrayBufferToBase64(ciphertext.buffer),
    iv: arrayBufferToBase64(iv.buffer),
    authTag: arrayBufferToBase64(authTag.buffer),
    sha256: hash,
  };
}

export async function decryptAESGCM(
  ciphertext: string,
  authTag: string,
  iv: string,
  key: CryptoKey,
  aad: { senderId: string; recipientId: string; counter: number }
): Promise<string> {
  const ciphertextBytes = new Uint8Array(base64ToArrayBuffer(ciphertext));
  const authTagBytes = new Uint8Array(base64ToArrayBuffer(authTag));
  const ivBytes = new Uint8Array(base64ToArrayBuffer(iv));
  
  const combined = new Uint8Array(ciphertextBytes.length + authTagBytes.length);
  combined.set(ciphertextBytes);
  combined.set(authTagBytes, ciphertextBytes.length);
  
  const enc = new TextEncoder();
  const aadString = JSON.stringify(aad);
  const aadBytes = enc.encode(aadString);
  
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: ivBytes,
      additionalData: aadBytes,
    },
    key,
    combined
  );
  
  const dec = new TextDecoder();
  return dec.decode(decrypted);
}

export function encryptXOR(plaintext: string, key: string): string {
  if (!key) return plaintext;
  
  let result = '';
  for (let i = 0; i < plaintext.length; i++) {
    const charCode = plaintext.charCodeAt(i) ^ key.charCodeAt(i % key.length);
    result += charCode.toString(16).padStart(2, '0');
  }
  return result;
}

export function decryptXOR(ciphertext: string, key: string): string {
  if (!key) return ciphertext;
  
  let result = '';
  for (let i = 0; i < ciphertext.length; i += 2) {
    const hexByte = ciphertext.substr(i, 2);
    const charCode = parseInt(hexByte, 16) ^ key.charCodeAt((i / 2) % key.length);
    result += String.fromCharCode(charCode);
  }
  return result;
}

export function encryptCaesar(plaintext: string, key: string, shift: number = 3): string {
  const actualShift = key ? (shift + key.charCodeAt(0)) % 26 : shift;
  
  return plaintext
    .split('')
    .map(char => {
      if (char >= 'a' && char <= 'z') {
        return String.fromCharCode(((char.charCodeAt(0) - 97 + actualShift) % 26) + 97);
      } else if (char >= 'A' && char <= 'Z') {
        return String.fromCharCode(((char.charCodeAt(0) - 65 + actualShift) % 26) + 65);
      }
      return char;
    })
    .join('');
}

export function decryptCaesar(ciphertext: string, key: string, shift: number = 3): string {
  const actualShift = key ? (shift + key.charCodeAt(0)) % 26 : shift;
  
  return ciphertext
    .split('')
    .map(char => {
      if (char >= 'a' && char <= 'z') {
        return String.fromCharCode(((char.charCodeAt(0) - 97 - actualShift + 26) % 26) + 97);
      } else if (char >= 'A' && char <= 'Z') {
        return String.fromCharCode(((char.charCodeAt(0) - 65 - actualShift + 26) % 26) + 65);
      }
      return char;
    })
    .join('');
}
