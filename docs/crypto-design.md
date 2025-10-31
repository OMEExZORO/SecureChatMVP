# Cryptographic Design

## Overview

This document describes the cryptographic design decisions for the Secure Chat MVP, including cipher selection, key derivation, integrity verification, and replay protection mechanisms.

## Design Goals

1. **End-to-End Encryption**: Server never sees plaintext
2. **Authenticated Encryption**: Prevent tampering and forgery
3. **Replay Protection**: Prevent message replay attacks
4. **Integrity Verification**: Detect any modifications to messages
5. **Educational Value**: Demonstrate secure vs insecure ciphers

## Cipher Selection

### Production Cipher: AES-256-GCM

**Why AES-256-GCM?**

- **AEAD**: Authenticated Encryption with Associated Data
- **Industry Standard**: NIST-approved, widely vetted
- **Performance**: Hardware acceleration available (AES-NI)
- **Built-in Authentication**: No need for separate MAC
- **Nonce Misuse Resistance**: Better than CBC, CTR modes
- **Web Crypto Support**: Native browser implementation

**Parameters**:
- Key size: 256 bits
- IV/Nonce size: 96 bits (12 bytes) - recommended for GCM
- Tag size: 128 bits (16 bytes)
- Block size: 128 bits

**Algorithm Flow**:
```
Key (256-bit) + IV (96-bit) + AAD + Plaintext → AES-GCM Encrypt →
Ciphertext || Auth Tag (128-bit)
```

**Security Properties**:
- **Confidentiality**: AES-256 provides ~2^256 brute-force resistance
- **Authenticity**: GCM tag ensures message hasn't been tampered
- **Integrity**: Any bit flip in ciphertext/AAD causes decryption failure
- **AAD Protection**: senderId, recipientId, counter authenticated but not encrypted

### Educational Ciphers

#### XOR Cipher

**Purpose**: Demonstrate inadequate security

**Weaknesses**:
- ❌ No security against known-plaintext attacks
- ❌ Trivial to break with frequency analysis
- ❌ Key reuse reveals XOR of plaintexts
- ❌ No authentication
- ❌ Vulnerable to bit-flipping attacks

**Implementation**:
```
C[i] = P[i] XOR K[i mod len(K)]
```

**Use Case**: Educational only - shows why simple XOR is insufficient

#### Caesar Cipher

**Purpose**: Demonstrate classical cipher weaknesses

**Weaknesses**:
- ❌ Only 26 possible keys (trivial brute force)
- ❌ Vulnerable to frequency analysis
- ❌ Known-plaintext attack reveals shift
- ❌ No authentication
- ❌ Pattern preservation (same letter → same ciphertext)

**Implementation**:
```
C[i] = (P[i] + shift) mod 26
```

**Use Case**: Historical educational example - never use in production

## Key Derivation

### PBKDF2-HMAC-SHA256

**Why PBKDF2?**

- **Standardized**: NIST SP 800-132, RFC 8018
- **Web Crypto Support**: Native browser implementation
- **Widely Deployed**: Proven security record
- **Tuneable**: Iteration count increases with hardware improvements

**Parameters**:
```typescript
{
  algorithm: 'PBKDF2',
  hash: 'SHA-256',
  iterations: 200000,    // OWASP recommended minimum (2023)
  saltLength: 16 bytes,  // 128 bits
  keyLength: 32 bytes    // 256 bits for AES-256
}
```

**Process**:
```
Passphrase + Salt (random 128-bit) →
PBKDF2-HMAC-SHA256 (200k iterations) →
256-bit Derived Key
```

**Security Considerations**:

- **Salt**: Random per conversation, prevents rainbow tables
- **Iterations**: 200k iterations ~100ms on modern hardware (OWASP 2023)
- **Future-Proofing**: Iterations can be increased as hardware improves
- **Memory**: PBKDF2 is not memory-hard (Argon2id would be better for passwords)

**Why Not Argon2id?**

While Argon2id is superior for password hashing (memory-hard), we chose PBKDF2 because:
- Native Web Crypto API support (no additional libraries)
- Sufficient for key derivation from passphrases
- Cross-platform compatibility
- MVP scope limitation

## Integrity Verification

### SHA-256 Hash

**Purpose**: Independent integrity verification (assignment requirement)

**Why SHA-256 when GCM provides authentication?**

1. **Educational**: Demonstrates hash-based integrity
2. **Defense in Depth**: Independent verification mechanism
3. **Assignment Requirement**: Explicit hash verification with PASS/FAIL
4. **Debugging**: Helps identify encryption vs integrity issues

**Process**:
```
Sender:
  1. Compute SHA-256(plaintext) → hash_expected
  2. Encrypt plaintext with AES-GCM → ciphertext
  3. Send {ciphertext, hash_expected, ...}

Receiver:
  1. Decrypt ciphertext → plaintext_recovered
  2. Compute SHA-256(plaintext_recovered) → hash_computed
  3. Compare: hash_computed === hash_expected → PASS/FAIL
```

**Security Properties**:
- **Collision Resistance**: ~2^128 operations to find collision
- **Preimage Resistance**: ~2^256 operations to find preimage
- **Avalanche Effect**: Single bit change → ~50% output bits flip
- **Deterministic**: Same input always produces same hash

## Additional Authenticated Data (AAD)

### Purpose

Bind metadata to ciphertext without encrypting it.

### AAD Components

```json
{
  "senderId": "alice",
  "recipientId": "bob",
  "counter": 42
}
```

**Why Include in AAD?**

1. **Sender/Recipient Binding**: Prevents message substitution attacks
2. **Counter Protection**: Prevents counter manipulation
3. **Metadata Integrity**: Server can see metadata but can't modify it
4. **Context Binding**: Message only valid in specific conversation context

**Security Impact**:

Without AAD, an attacker could:
- ❌ Swap messages between different conversations
- ❌ Manipulate counters while keeping ciphertext valid
- ❌ Redirect messages to wrong recipients

With AAD, GCM ensures:
- ✅ Ciphertext is bound to exact sender/recipient/counter
- ✅ Any AAD modification causes decryption failure
- ✅ Server can enforce replay protection without decryption

## Replay Protection

### Multi-Layer Defense

#### Layer 1: Monotonic Counter

**Per-Conversation Counter**:
- Scope: (senderId, recipientId) tuple
- Start: 0 (or 1)
- Increment: +1 for each message
- Validation: counter > lastSeenCounter

**Storage**:
```cpp
map<pair<string, string>, int> lastCounters;
```

**Security**:
- ✅ Prevents duplicate message injection
- ✅ Detects out-of-order delivery
- ✅ Client and server both enforce
- ⚠️ Resets on server restart (in-memory for MVP)

#### Layer 2: Timestamp Window

**Timestamp Validation**:
```
|currentTime - messageTimestamp| ≤ 5 minutes (300 seconds)
```

**Why ±5 minutes?**

- Allows for clock skew between clients
- Prevents very old messages from being replayed
- Short enough to limit replay window
- Long enough for network delays

**Security**:
- ✅ Limits replay attack window to 10 minutes max
- ✅ Prevents ancient message replay
- ✅ Combined with counter, very strong protection

### Combined Protection

**Attack Scenarios**:

1. **Replay Same Message**:
   - Counter: ❌ Rejected (not > lastCounter)
   - Timestamp: ✅ Might pass if within window
   - **Result**: ❌ Blocked by counter

2. **Replay Old Message**:
   - Counter: ❌ Rejected (lower than current)
   - Timestamp: ❌ Rejected (outside window)
   - **Result**: ❌ Blocked by both

3. **Message Reordering**:
   - Counter: ❌ Rejected (out of sequence)
   - Timestamp: ✅ Might pass
   - **Result**: ❌ Blocked by counter

## IV/Nonce Management

### AES-GCM IV Generation

**Requirements**:
- **Uniqueness**: Never reuse same IV with same key
- **Randomness**: Unpredictable to attackers
- **Size**: 96 bits (12 bytes) recommended for GCM

**Implementation**:
```typescript
const iv = crypto.getRandomValues(new Uint8Array(12));
```

**Security**:
- ✅ Cryptographically secure random number generator
- ✅ 2^96 possible IVs (collision probability negligible)
- ✅ New random IV for every message

**Critical Warning**:
⚠️ **Never reuse IV with same key** - catastrophic security failure in GCM

## Tag Handling (Web Crypto Quirk)

### The Issue

Web Crypto API returns:
```
AES-GCM encrypt output = ciphertext || authTag (last 16 bytes)
```

### Solution

**On Encrypt**:
```typescript
const encrypted = await crypto.subtle.encrypt(...);
const fullOutput = new Uint8Array(encrypted);
const ciphertext = fullOutput.slice(0, -16);
const authTag = fullOutput.slice(-16);
```

**On Decrypt**:
```typescript
const combined = new Uint8Array([...ciphertext, ...authTag]);
const decrypted = await crypto.subtle.decrypt(..., combined);
```

### Wire Format

We separate them in the message envelope for clarity:
```json
{
  "ciphertext": "base64...",  // without tag
  "authTag": "base64..."      // separate field
}
```

## Security Assumptions

### In Scope

✅ Passive attacker observing encrypted traffic  
✅ Active attacker modifying/replaying messages  
✅ Server compromise (end-to-end property)  
✅ Network-level attacks (MITM can't decrypt)  

### Out of Scope (MVP Limitations)

⚠️ Forward secrecy (no key rotation)  
⚠️ User authentication (HELLO handshake is insecure)  
⚠️ Transport security (should use TLS in production)  
⚠️ Denial of Service  
⚠️ Side-channel attacks (timing, cache)  
⚠️ Client compromise (malware, XSS)  
⚠️ Quantum resistance  

## Threat Mitigation Summary

| Threat | Mitigation |
|--------|-----------|
| Eavesdropping | AES-256-GCM encryption |
| Message Tampering | GCM authentication + SHA-256 |
| Replay Attacks | Counter + timestamp |
| Substitution | AAD binding (sender/recipient/counter) |
| Server Reading Messages | E2E encryption |
| Man-in-the-Middle | AAD prevents message redirection |
| Brute Force | PBKDF2 200k iterations |
| Rainbow Tables | Random salt per conversation |

## Future Improvements

For production deployment, consider:

1. **Key Exchange**: X25519 Diffie-Hellman for automatic key agreement
2. **Forward Secrecy**: Ratcheting mechanism (Double Ratchet Algorithm)
3. **Perfect Forward Secrecy**: Ephemeral keys rotated frequently
4. **TLS Transport**: Encrypt WebSocket connection
5. **Persistent Storage**: Secure key storage (Web Crypto API non-extractable keys)
6. **Argon2id**: For password hashing (memory-hard KDF)
7. **Post-Quantum**: Lattice-based or hash-based signatures

## References

- [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) - GCM Specification
- [RFC 5116](https://tools.ietf.org/html/rfc5116) - AEAD Interface
- [RFC 8018](https://tools.ietf.org/html/rfc8018) - PBKDF2 Specification
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Web Crypto API](https://www.w3.org/TR/WebCryptoAPI/)
