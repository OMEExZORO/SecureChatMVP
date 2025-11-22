export interface Message {
  senderId: string;
  recipientId: string;
  counter: number;
  timestamp: number;
  cipher: string;
  iv: string;
  aad: string;
  ciphertext: string;
  authTag: string;
  sha256_plaintext: string;
  plaintext?: string;
  verified?: boolean;
}

export interface WSMessage {
  type: 'HELLO' | 'HELLO_ACK' | 'MSG' | 'REJECT' | 'ERROR' | 'DEFERRED';
  userId?: string;
  message?: string;
  reason?: string;
  senderId?: string;
  recipientId?: string;
  counter?: number;
  timestamp?: number;
  cipher?: string;
  iv?: string;
  aad?: string;
  ciphertext?: string;
  authTag?: string;
  sha256_plaintext?: string;
}

export interface Conversation {
  userId: string;
  counter: number;
  encryptionKey?: CryptoKey | Uint8Array | string; // Uint8Array for AES, string for XOR/Caesar
  salt?: Uint8Array;
  selectedCipher?: string;
}
