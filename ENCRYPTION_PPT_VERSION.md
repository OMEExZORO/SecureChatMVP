# ENCRYPTION METHODS - TECHNICAL DOCUMENTATION

---

## 1. XOR CIPHER

### Algorithm Description
XOR (Exclusive OR) is a bitwise operation that combines plaintext with a key. Each byte of plaintext is XORed with corresponding key byte.

### Mathematical Formula
```
Encryption: Ciphertext = Plaintext XOR Key
Decryption: Plaintext = Ciphertext XOR Key
```

### Implementation Code

**File: client/src/lib/crypto.ts (Lines 241-266)**

```typescript
export async function encryptXOR(plaintext: string, key: string): Promise<EncryptedData> {
  const encoder = new TextEncoder();
  const plaintextBytes = encoder.encode(plaintext);
  const keyBytes = encoder.encode(key);
  
  const cipherBytes = new Uint8Array(plaintextBytes.length);
  for (let i = 0; i < plaintextBytes.length; i++) {
    cipherBytes[i] = plaintextBytes[i] ^ keyBytes[i % keyBytes.length];
  }
  
  const sha256 = await computeSHA256(plaintext);
  
  return {
    iv: '',
    ciphertext: arrayBufferToBase64(cipherBytes),
    authTag: '',
    sha256
  };
}

export async function decryptXOR(ciphertext: string, key: string): Promise<string> {
  const cipherBytes = new Uint8Array(base64ToArrayBuffer(ciphertext));
  const keyBytes = new TextEncoder().encode(key);
  
  const plaintextBytes = new Uint8Array(cipherBytes.length);
  for (let i = 0; i < cipherBytes.length; i++) {
    plaintextBytes[i] = cipherBytes[i] ^ keyBytes[i % keyBytes.length];
  }
  
  const decoder = new TextDecoder();
  return decoder.decode(plaintextBytes);
}
```

### How It Works

**Step 1: Convert to bytes**
```
Plaintext: "HI" → [72, 73]
Key: "MY" → [77, 89]
```

**Step 2: XOR operation**
```
72 XOR 77 = 5
73 XOR 89 = 16
Ciphertext: [5, 16]
```

**Step 3: Decryption (same XOR)**
```
5 XOR 77 = 72 → 'H'
16 XOR 89 = 73 → 'I'
```

### Security Level
LOW - Vulnerable to frequency analysis and known-plaintext attacks

### Vulnerabilities
1. Pattern leakage in repeated characters
2. Known-plaintext attack reveals the key
3. No authentication or integrity checking
4. Key reuse allows message XOR without knowing key

---

## 2. CAESAR CIPHER

### Algorithm Description
Caesar Cipher shifts each letter by a fixed number of positions in the alphabet. Named after Julius Caesar (50 BC).

### Mathematical Formula
```
Encryption: C = (P + K) mod 26
Decryption: P = (C - K) mod 26

Where:
P = Plaintext letter position (A=0, B=1, ..., Z=25)
K = Shift key (0-25)
C = Ciphertext letter position
```

### Implementation Code

**File: client/src/lib/crypto.ts (Lines 268-319)**

```typescript
export async function encryptCaesar(plaintext: string, key: string): Promise<EncryptedData> {
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
      ciphertext += char;
    }
  }
  
  const sha256 = await computeSHA256(plaintext);
  
  return {
    iv: shift.toString(),
    ciphertext: btoa(ciphertext),
    authTag: '',
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
```

### How It Works

**Example: Shift = 3**
```
Plaintext:  A B C D ... X Y Z
Ciphertext: D E F G ... A B C

"ATTACK" with shift 3:
A → D
T → W
T → W
A → D
C → F
K → N
Result: "DWWDFN"
```

### Security Level
VERY LOW - Only 26 possible keys, trivial to brute force

### Vulnerabilities
1. Brute force takes less than 1 second (26 keys)
2. Frequency analysis reveals shift immediately
3. Pattern recognition (common words visible)
4. Any password converts to single number 0-25

---

## 3. AES-256-GCM

### Algorithm Description
AES-256-GCM (Advanced Encryption Standard with 256-bit key in Galois/Counter Mode) is military-grade encryption providing confidentiality, integrity, and authenticity.

### Components
```
AES: Block cipher encrypting 128-bit blocks
256: Key size in bits (2^256 possible keys)
GCM: Galois/Counter Mode for authenticated encryption
AEAD: Authenticated Encryption with Associated Data
```

### Key Derivation (PBKDF2)

**File: client/src/lib/crypto.ts (Lines 60-82)**

```typescript
export async function deriveKey(
  passphrase: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const passphraseKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations: 200000,
      hash: 'SHA-256',
    },
    passphraseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}
```

**What it does:**
Converts user password into cryptographic key using PBKDF2 with 200,000 iterations and random salt. Prevents rainbow table attacks and makes brute force extremely slow.

### Encryption Function

**File: client/src/lib/crypto.ts (Lines 107-130)**

```typescript
export async function encryptMessage(
  plaintext: string,
  key: CryptoKey,
  aadString: string
): Promise<EncryptedData> {
  const encoder = new TextEncoder();
  const plaintextBuffer = encoder.encode(plaintext);
  const aadBuffer = encoder.encode(aadString);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      additionalData: aadBuffer,
      tagLength: 128,
    },
    key,
    plaintextBuffer
  );

  const encrypted = new Uint8Array(encryptedBuffer);
  const ciphertext = encrypted.slice(0, -16);
  const authTag = encrypted.slice(-16);

  const sha256 = await computeSHA256(plaintext);

  return {
    iv: arrayBufferToBase64(iv),
    ciphertext: arrayBufferToBase64(ciphertext),
    authTag: arrayBufferToBase64(authTag),
    sha256,
  };
}
```

**What it does:**
1. Generates random 12-byte IV (Initialization Vector)
2. Encrypts plaintext using AES-256-GCM with key and IV
3. Authenticates Additional Associated Data (AAD) - metadata like sender, recipient, counter
4. Produces ciphertext and 16-byte authentication tag
5. Computes SHA-256 hash of plaintext for extra verification

### Decryption Function

**File: client/src/lib/crypto.ts (Lines 132-156)**

```typescript
export async function decryptMessage(
  iv: string,
  ciphertext: string,
  authTag: string,
  key: CryptoKey,
  aadString: string
): Promise<string> {
  const ivBuffer = base64ToArrayBuffer(iv);
  const ciphertextBuffer = base64ToArrayBuffer(ciphertext);
  const authTagBuffer = base64ToArrayBuffer(authTag);
  const aadBuffer = new TextEncoder().encode(aadString);

  const combined = new Uint8Array(ciphertextBuffer.byteLength + authTagBuffer.byteLength);
  combined.set(new Uint8Array(ciphertextBuffer), 0);
  combined.set(new Uint8Array(authTagBuffer), ciphertextBuffer.byteLength);

  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ivBuffer,
        additionalData: aadBuffer,
        tagLength: 128,
      },
      key,
      combined
    );

    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
  } catch (error) {
    throw new Error('Decryption failed - invalid key or tampered data');
  }
}
```

**What it does:**
1. Combines ciphertext and authentication tag
2. Verifies authentication tag using key, IV, ciphertext, and AAD
3. If tag is invalid (tampered or wrong key), throws error immediately
4. If valid, decrypts ciphertext using AES-256-GCM
5. Returns plaintext

### Additional Authenticated Data (AAD)

**File: client/src/lib/crypto.ts (Lines 96-106)**

```typescript
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
```

**What it does:**
Creates authenticated metadata (not encrypted, but integrity-protected). Keys alphabetically sorted for canonical format. Prevents replay attacks and message manipulation.

### Complete Message Flow

**File: client/src/ChatApp.tsx (Lines 177-219)**

```typescript
const handleSendMessage = async () => {
  const newCounter = conversation.counter + 1;

  const aad = createCanonicalAAD({
    senderId: userId,
    recipientId: recipientId,
    counter: newCounter,
  });

  const encrypted = await encryptMessage(
    inputMessage,
    conversation.encryptionKey,
    aad
  );

  const message: WSMessage = {
    type: 'MSG',
    senderId: userId,
    recipientId: recipientId,
    counter: newCounter,
    timestamp: Math.floor(Date.now() / 1000),
    cipher: 'AES-256-GCM',
    iv: encrypted.iv,
    aad,
    ciphertext: encrypted.ciphertext,
    authTag: encrypted.authTag,
    sha256_plaintext: encrypted.sha256,
  };

  wsClient.send(message);
  
  setConversation(prev => prev ? { ...prev, counter: newCounter } : null);
};
```

**What it does:**
1. Increments message counter (prevents replay attacks)
2. Creates AAD with sender, recipient, counter
3. Encrypts message with AES-256-GCM
4. Creates complete message with metadata
5. Sends via WebSocket to server
6. Updates local counter

### Security Level
MILITARY-GRADE - NSA approved for TOP SECRET information

### Security Properties

**Confidentiality:**
Ciphertext reveals nothing about plaintext. Even identical messages produce different ciphertexts due to random IV.

**Integrity:**
Any modification to ciphertext is detected. Authentication tag verification fails if even one bit is changed.

**Authenticity:**
Only holders of the key can create valid ciphertexts. Prevents attacker from injecting fake messages.

**Replay Attack Protection:**
Counter in AAD ensures each message is unique. Server validates counter is monotonically increasing.

**Non-Malleability:**
Attacker cannot modify ciphertext to alter plaintext. Unlike XOR where bit flipping works.

### PBKDF2 Parameters

```
Algorithm: HMAC-SHA256
Iterations: 200,000
Salt: 16 random bytes
Output: 256-bit AES key

Purpose:
- Makes brute force extremely slow (100ms per attempt)
- Salt prevents rainbow table attacks
- Same password produces different keys for different users
```

### Why GCM Mode?

```
Provides:
- Encryption (confidentiality)
- Authentication (integrity + authenticity)
- Single pass operation (efficient)
- Parallelizable (fast with modern CPUs)
- AEAD standard (industry best practice)

Prevents:
- Padding oracle attacks (no padding needed)
- Bit flipping attacks (authenticated)
- Message forgery (authentication tag)
```

---

## COMPARISON TABLE

### Security Comparison

| Feature | XOR | Caesar | AES-256-GCM |
|---------|-----|--------|-------------|
| Key Space | 2^n bits | 26 keys | 2^256 keys |
| Brute Force Time | Hours | Milliseconds | > Age of universe |
| Known-Plaintext Attack | Fails immediately | Fails immediately | Secure |
| Pattern Leakage | Severe | Severe | None |
| Frequency Analysis | Vulnerable | Vulnerable | Immune |
| Authentication | None | None | Built-in GCM tag |
| Integrity Protection | None | None | Tamper detection |
| Replay Protection | None | None | With AAD + counter |

### Performance Comparison

| Metric | XOR | Caesar | AES-256-GCM |
|--------|-----|--------|-------------|
| Encryption Speed | ~1 GB/s | ~500 MB/s | ~200 MB/s |
| Key Setup Time | Instant | Instant | ~100ms (PBKDF2) |
| CPU Usage | Very Low | Very Low | Low (HW accelerated) |
| Code Complexity | 10 lines | 20 lines | Web Crypto API |

### Attack Resistance

| Attack Type | XOR | Caesar | AES-256-GCM |
|------------|-----|--------|-------------|
| Brute Force | Depends on key length | 26 keys = trivial | 2^256 keys = infeasible |
| Frequency Analysis | Vulnerable | Vulnerable | Immune |
| Known-Plaintext | Breaks immediately | Breaks immediately | Secure |
| Bit Flipping | Undetected | Detected as gibberish | Detected by AuthTag |
| Replay Attack | No protection | No protection | Counter validation |

---

## USE CASE RECOMMENDATIONS

### Production Applications
Use AES-256-GCM for:
- Chat applications
- Financial transactions
- Medical records
- Password managers
- Any sensitive data

### Educational/Historical
Use XOR/Caesar for:
- Learning cryptography concepts
- Historical demonstrations
- CTF challenges
- Puzzle design

### Never Use XOR/Caesar For:
- Real security applications
- Password storage
- Personal information
- Financial data
- "Just testing" (always use proper crypto)

---

## IMPLEMENTATION FILES

```
client/src/lib/crypto.ts
├── Lines 60-82:    PBKDF2 key derivation
├── Lines 96-106:   AAD creation
├── Lines 107-130:  AES-256-GCM encryption
├── Lines 132-156:  AES-256-GCM decryption
├── Lines 241-266:  XOR cipher
└── Lines 268-319:  Caesar cipher

client/src/ChatApp.tsx
└── Lines 177-219:  Message sending flow

server-cpp/src/main.cpp
└── Lines 365-402:  Zero-knowledge message relay
```

---

## KEY TAKEAWAYS

**XOR Cipher:**
Simple bitwise operation. Fast but insecure. Vulnerable to pattern analysis and known-plaintext attacks. Educational only.

**Caesar Cipher:**
Classical substitution with alphabet shift. Only 26 possible keys. Broken by brute force in milliseconds. Historical significance only.

**AES-256-GCM:**
Military-grade authenticated encryption. 2^256 key space. Provides confidentiality, integrity, and authenticity. Industry standard for secure communications. NSA approved for TOP SECRET data.

**Production Recommendation:**
Always use AES-256-GCM with PBKDF2 key derivation for any real-world security application.
