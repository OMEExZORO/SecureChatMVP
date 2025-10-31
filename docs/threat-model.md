# Threat Model

## Document Purpose

This threat model identifies security assets, potential adversaries, attack vectors, and mitigations for the Secure Chat MVP. It follows a structured approach to understand what we're protecting, from whom, and how.

## Assets

### Critical Assets

1. **Message Content (Plaintext)**
   - Description: The actual text of user conversations
   - Sensitivity: HIGH
   - Storage: Client memory only (encrypted in transit)
   - Lifetime: Session-based, cleared on page refresh

2. **Encryption Keys**
   - Description: AES-256 symmetric keys derived from passphrases
   - Sensitivity: CRITICAL
   - Storage: Client memory only (CryptoKey object, non-extractable)
   - Lifetime: Per-conversation session

3. **Passphrases**
   - Description: Shared secret used for key derivation
   - Sensitivity: CRITICAL
   - Storage: Never persisted (input field only)
   - Lifetime: Cleared immediately after key derivation

### Moderate Assets

4. **User IDs**
   - Description: Participant identifiers
   - Sensitivity: MEDIUM
   - Storage: Server connection registry (in-memory)
   - Lifetime: Active connection duration

5. **Message Metadata**
   - Description: Counter, timestamp, sender/recipient IDs
   - Sensitivity: LOW-MEDIUM
   - Storage: Server relay memory, client messages array
   - Lifetime: Session-based

6. **Salts**
   - Description: Random values for PBKDF2
   - Sensitivity: LOW (public is acceptable)
   - Storage: Client memory per conversation
   - Lifetime: Per-conversation session

## Threat Actors

### 1. Passive Network Attacker

**Capabilities**:
- ✅ Observe all network traffic
- ✅ Collect encrypted messages
- ❌ Cannot modify traffic
- ❌ Cannot compromise endpoints

**Goals**:
- Read message contents
- Identify communication patterns
- Collect long-term data for future attacks

**Threat Level**: MEDIUM

### 2. Active Network Attacker (MITM)

**Capabilities**:
- ✅ Observe traffic
- ✅ Modify messages in transit
- ✅ Inject/delete/replay messages
- ✅ Impersonate server
- ❌ Cannot compromise endpoints

**Goals**:
- Inject false messages
- Replay old messages
- Substitute message recipients
- Disrupt service

**Threat Level**: HIGH

### 3. Compromised Server

**Capabilities**:
- ✅ Full access to server code/memory
- ✅ Observe all encrypted traffic
- ✅ Manipulate server logic
- ✅ Deny service
- ❌ Cannot decrypt messages (E2E property)
- ❌ Cannot compromise clients

**Goals**:
- Read message contents (fails due to E2E)
- Collect metadata
- Disrupt communication
- Perform targeted DoS

**Threat Level**: MEDIUM (mitigated by E2E design)

### 4. Malicious User

**Capabilities**:
- ✅ Registered user access
- ✅ Send messages to any user
- ✅ Attempt replay attacks
- ✅ Spam/flood the system
- ❌ Cannot read others' conversations

**Goals**:
- Disrupt other users
- Test replay protection
- Resource exhaustion
- Message flooding

**Threat Level**: LOW-MEDIUM

### 5. Client-Side Attacker

**Capabilities**:
- ✅ XSS vulnerabilities (if present)
- ✅ Malware on client device
- ✅ Access to browser memory/storage
- ✅ Keylogging

**Goals**:
- Steal encryption keys
- Read message plaintext
- Impersonate user
- Exfiltrate data

**Threat Level**: HIGH (out of scope for MVP)

## Attack Vectors

### 1. Message Eavesdropping

**Scenario**: Passive attacker captures encrypted messages

**Attack Path**:
```
Attacker → Network Tap → Encrypted Message → Attempt Decryption
```

**Mitigations**:
- ✅ AES-256-GCM encryption (2^256 brute-force resistance)
- ✅ End-to-end encryption (server doesn't have keys)
- ✅ PBKDF2 200k iterations (slow password cracking)
- ⚠️ Missing: Transport-layer encryption (TLS)

**Residual Risk**: LOW (cryptography is sound)

### 2. Replay Attacks

**Scenario**: Attacker captures message and resends it

**Attack Path**:
```
Capture {MSG, counter: 5, timestamp: T1}
→ Wait some time
→ Resend identical message
→ Victim receives duplicate
```

**Mitigations**:
- ✅ Monotonic counter enforcement (server rejects counter ≤ last)
- ✅ Timestamp window validation (±5 minutes)
- ✅ Client-side counter tracking
- ✅ Both server AND client validate

**Test**:
```javascript
// DevTools console
ws.send(previouslyCapturedMessage); // Should fail
```

**Residual Risk**: VERY LOW (strong mitigation)

### 3. Message Tampering

**Scenario**: MITM modifies encrypted message

**Attack Path**:
```
Intercept {ciphertext, authTag, ...}
→ Modify ciphertext
→ Forward to recipient
→ GCM decryption fails
```

**Mitigations**:
- ✅ GCM authentication tag (any modification → decryption failure)
- ✅ SHA-256 integrity check (independent verification)
- ✅ AAD binds metadata to ciphertext

**Residual Risk**: VERY LOW (cryptographic guarantee)

### 4. Message Substitution

**Scenario**: Attacker swaps message from conversation A into conversation B

**Attack Path**:
```
Capture MSG(alice → bob, "Hello")
→ Replay to charlie
→ Attempt to impersonate alice
```

**Mitigations**:
- ✅ AAD includes senderId and recipientId
- ✅ GCM binds ciphertext to exact sender/recipient
- ✅ Wrong AAD → decryption failure

**Residual Risk**: VERY LOW (AAD prevents this)

### 5. User Impersonation

**Scenario**: Attacker pretends to be another user

**Attack Path**:
```
HELLO {userId: "alice"}  // No authentication!
→ Server accepts
→ Attacker receives messages for alice
```

**Mitigations**:
- ❌ No user authentication in MVP
- ⚠️ HELLO handshake is insecure
- ⚠️ Anyone can claim any userId

**Residual Risk**: HIGH (MVP limitation - would need JWT/OAuth)

### 6. Denial of Service

**Scenario**: Attacker floods server with messages

**Attack Path**:
```
while(true) {
  ws.send(SPAM_MESSAGE);
}
```

**Mitigations**:
- ❌ No rate limiting
- ❌ No connection throttling
- ❌ No resource quotas

**Residual Risk**: HIGH (out of scope for MVP)

### 7. Server Reads Messages

**Scenario**: Compromised server tries to decrypt messages

**Attack Path**:
```
Server captures {ciphertext, iv, authTag}
→ Attempts decryption
→ No key available
→ FAIL
```

**Mitigations**:
- ✅ End-to-end encryption
- ✅ Keys derived client-side only
- ✅ Keys never sent to server
- ✅ Server acts as relay only

**Residual Risk**: NONE (core E2E property)

### 8. Cryptographic Downgrade

**Scenario**: Attacker forces use of weak cipher

**Attack Path**:
```
Client selects "AES-GCM"
→ Attacker modifies to "XOR"
→ Weak encryption
```

**Mitigations**:
- ⚠️ Cipher selection is client-side only
- ⚠️ No negotiation protocol
- ✅ Default is AES-GCM
- ⚠️ XOR/Caesar clearly marked as educational

**Residual Risk**: MEDIUM (user education required)

### 9. Key Derivation Weaknesses

**Scenario**: Weak passphrase allows brute-force

**Attack Path**:
```
Capture salt + ciphertext
→ Brute-force passphrases
→ Test decryption
```

**Mitigations**:
- ✅ PBKDF2 200k iterations (slow brute-force)
- ✅ Random salt (prevents rainbow tables)
- ⚠️ No passphrase complexity requirements
- ⚠️ User can choose weak passphrase ("123")

**Residual Risk**: MEDIUM (depends on user passphrase choice)

### 10. Forward Secrecy Absence

**Scenario**: Future key compromise reveals past messages

**Attack Path**:
```
Capture all encrypted messages
→ Wait months/years
→ Compromise passphrase
→ Decrypt all historical messages
```

**Mitigations**:
- ❌ No forward secrecy
- ❌ No key rotation
- ❌ Single long-term key per conversation

**Residual Risk**: HIGH (out of scope for MVP)

## Out of Scope Threats

The following are explicitly **out of scope** for this MVP:

### 1. Side-Channel Attacks
- Timing attacks on crypto operations
- Cache-timing attacks
- Power analysis
- **Justification**: Educational MVP, not deployed to hostile environments

### 2. Quantum Computing
- Future quantum attacks on AES-256
- Shor's algorithm on key exchange
- **Justification**: Not relevant for current threat landscape

### 3. Physical Security
- Server physical access
- Client device theft
- Evil maid attacks
- **Justification**: Physical security is environmental, not application-level

### 4. Social Engineering
- Phishing for passphrases
- Shoulder surfing
- Coercion
- **Justification**: Human factors outside technical scope

### 5. Browser/Client Vulnerabilities
- XSS in client application
- Malicious browser extensions
- Compromised npm packages
- **Justification**: Assumes trusted client environment

### 6. Compliance/Legal
- GDPR data residency
- Lawful intercept requirements
- Data retention policies
- **Justification**: Educational demo, not production service

## Security Boundaries

### Trust Boundaries

```
┌─────────────────────────────────────────┐
│  Trusted Zone: Client Browser           │
│  - Encryption/Decryption                │
│  - Key Derivation                       │
│  - Plaintext Access                     │
└─────────────────────────────────────────┘
              │
              │ Encrypted Messages Only
              │
┌─────────────▼─────────────────────────────┐
│  Untrusted Zone: Server                   │
│  - Relays encrypted messages              │
│  - Never sees plaintext                   │
│  - Enforces replay protection             │
└───────────────────────────────────────────┘
              │
              │ Encrypted Messages Only
              │
┌─────────────▼─────────────────────────────┐
│  Untrusted Zone: Network                  │
│  - Observes encrypted traffic             │
│  - Cannot decrypt                         │
│  - Cannot meaningfully tamper             │
└───────────────────────────────────────────┘
```

### What Crosses Boundaries

**Client → Server**:
- ✅ Encrypted ciphertext
- ✅ Metadata (userId, counter, timestamp)
- ✅ Authentication tags (GCM tag, SHA-256 hash)
- ❌ Plaintext messages (NEVER)
- ❌ Encryption keys (NEVER)
- ❌ Passphrases (NEVER)

## Risk Assessment Matrix

| Threat | Likelihood | Impact | Risk Level | Mitigation Status |
|--------|-----------|--------|------------|-------------------|
| Eavesdropping | HIGH | HIGH | MEDIUM | ✅ Mitigated (AES-256-GCM) |
| Replay Attack | MEDIUM | MEDIUM | LOW | ✅ Mitigated (counter+timestamp) |
| Message Tampering | MEDIUM | HIGH | LOW | ✅ Mitigated (GCM+SHA-256) |
| Message Substitution | LOW | HIGH | LOW | ✅ Mitigated (AAD binding) |
| User Impersonation | HIGH | HIGH | **HIGH** | ❌ Not Mitigated (MVP) |
| DoS/Flooding | MEDIUM | MEDIUM | **MEDIUM** | ❌ Not Mitigated (MVP) |
| Server Compromise | LOW | HIGH | LOW | ✅ Mitigated (E2E design) |
| Weak Passphrase | MEDIUM | HIGH | **MEDIUM** | ⚠️ Partial (PBKDF2, no requirements) |
| Forward Secrecy | LOW | HIGH | **MEDIUM** | ❌ Not Mitigated (MVP) |
| XSS/Client Compromise | LOW | CRITICAL | **MEDIUM** | ❌ Out of Scope |

## Recommended Mitigations for Production

### High Priority

1. **Add TLS/SSL**: Encrypt WebSocket transport
2. **User Authentication**: JWT or OAuth for HELLO handshake
3. **Rate Limiting**: Prevent message flooding
4. **Passphrase Requirements**: Enforce minimum complexity
5. **Key Rotation**: Implement periodic key refresh

### Medium Priority

6. **Forward Secrecy**: X25519 key exchange + ratcheting
7. **Connection Throttling**: Limit connections per IP
8. **Audit Logging**: Log security events (failed auth, replay attempts)
9. **CSP Headers**: Content Security Policy for XSS protection
10. **Non-extractable Keys**: Use Web Crypto API `extractable: false`

### Low Priority (Future)

11. **Persistent Storage**: Encrypted IndexedDB for message history
12. **Group Chat**: Extend to multi-party encryption
13. **File Attachments**: Chunked encrypted file transfer
14. **Read Receipts**: With encryption
15. **Typing Indicators**: Without leaking timing info

## Security Testing Recommendations

### Unit Tests

```cpp
// C++ Backend
TEST(ReplayGuard, RejectsDuplicateCounter)
TEST(ReplayGuard, RejectsStaleTimestamp)
TEST(ReplayGuard, AcceptsMonotonicCounter)
```

```typescript
// Frontend
test('encrypts and decrypts correctly')
test('detects hash mismatch')
test('rejects replayed messages')
```

### Integration Tests

1. **E2E Encryption Test**:
   - Verify server never sees plaintext
   - Capture traffic, confirm ciphertext is random

2. **Replay Protection Test**:
   - Manually replay message
   - Confirm rejection with correct error

3. **Tampering Test**:
   - Modify ciphertext byte
   - Confirm decryption failure

### Penetration Testing

For production deployment:

1. **Network Analysis**: Wireshark capture → verify encryption
2. **Replay Fuzzing**: Automated replay attempts
3. **Server Compromise Simulation**: Verify E2E property holds
4. **XSS Testing**: Check for injection vulnerabilities
5. **DoS Testing**: Load testing and rate limit validation

## Compliance Considerations

### Data Protection

⚠️ **This MVP does not comply with:**
- GDPR (no data retention controls, no right to erasure)
- HIPAA (healthcare data requires additional safeguards)
- SOC 2 (no comprehensive audit logging)
- PCI DSS (if payment data involved)

### Lawful Intercept

⚠️ E2E encryption prevents lawful intercept. Production deployment must consider:
- Local regulations (some jurisdictions ban E2E)
- Enterprise requirements (some want server-side decryption)
- Backup/recovery (no key escrow = data loss if passphrase forgotten)

## Conclusion

This Secure Chat MVP provides **strong cryptographic protection** against:
- ✅ Eavesdropping
- ✅ Message tampering
- ✅ Replay attacks
- ✅ Server compromise

However, it has **known limitations** suitable for an educational project:
- ⚠️ No user authentication (anyone can claim any userId)
- ⚠️ No transport encryption (should use TLS)
- ⚠️ No forward secrecy (key compromise = all messages compromised)
- ⚠️ No DoS protection

**For production use**, implement the recommended mitigations above and conduct thorough security testing.

## References

- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
- [STRIDE Threat Model](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [Attack Trees](https://www.schneier.com/academic/archives/1999/12/attack_trees.html)
