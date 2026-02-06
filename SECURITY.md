# Security Analysis: Secure UAV Command and Control System

## Overview

This document provides a comprehensive security analysis of the UAV Command and Control (C2) protocol, focusing on how the system ensures **Freshness** and **Forward Secrecy**, along with defenses against common attacks.

---

## 1. Freshness Guarantees

Freshness ensures that messages are current and not replayed from previous sessions. Our protocol implements a **dual-layer freshness mechanism** using both timestamps and nonces.

### 1.1 Timestamp-Based Freshness

**Implementation**: Every protocol message includes a timestamp (`TS`).

**Phase 1A - Drone Request**:
```
Message = ⟨TSi, RNi, IDDi, Ci, SignKRDi(TSi ∥ RNi ∥ IDDi ∥ Ci)⟩
```

**MCC Validation** (mcc.py, lines 121-124):
```python
if abs(time.time() - ts_d) > 60:
    print(f"[!] SECURITY ALERT: Stale Timestamp from {drone_id}. Possible Replay.")
    conn.close()
    return
```

**Security Properties**:
- ✅ **Time Window**: Messages older than 60 seconds are rejected
- ✅ **Prevents Long-Term Replay**: Attackers cannot replay old captured messages
- ✅ **Signed Timestamps**: Timestamps are included in digital signatures, preventing modification

**Limitations**:
- ⚠️ Requires loose clock synchronization between MCC and drones
- ⚠️ Vulnerable to replay within the 60-second window (mitigated by nonces)

### 1.2 Nonce-Based Freshness

**Implementation**: Each drone generates a unique random nonce (`RN`) for every authentication attempt.

**Nonce Generation** (drone.py, line 69):
```python
rn_d = secrets.randbelow(2**256)  # 256-bit random nonce
```

**MCC Nonce Cache** (mcc.py, lines 129-135):
```python
if (drone_id, rn_d) in self.seen_nonces:
    print(f"[!] SECURITY ALERT: Replay Attack Detected! Nonce {rn_d} already used by {drone_id}.")
    conn.close()
    return

self.seen_nonces.add((drone_id, rn_d))
```

**Security Properties**:
- ✅ **Unique Per Session**: Each authentication uses a fresh 256-bit nonce
- ✅ **Prevents Short-Term Replay**: Even within the 60-second window, duplicate nonces are detected
- ✅ **Cryptographically Secure**: Uses `secrets.randbelow()` for unpredictable nonces
- ✅ **Per-Drone Tracking**: Nonces are tracked per drone ID to prevent cross-drone replay

**Nonce Space Analysis**:
- Nonce size: 256 bits
- Collision probability: ~2^-128 (negligible for practical purposes)
- Storage: Grows linearly with authentication attempts (acceptable for lab environment)

### 1.3 Combined Freshness Mechanism

The protocol uses **both** timestamps and nonces together:

1. **Timestamp** provides coarse-grained freshness (60-second window)
2. **Nonce** provides fine-grained uniqueness (prevents replay within window)
3. **Digital Signature** binds both to the message content

**Attack Scenario - Replay Attack**:
```
Attacker captures: ⟨TS=1000, RN=12345, ID=Drone_A, C, Sig⟩
Attacker replays at TS=1010 (within 60-second window)

MCC checks:
1. Timestamp: ✅ Within 60 seconds (passes)
2. Nonce: ❌ (Drone_A, 12345) already in seen_nonces (REJECTED)
```

**Result**: Attack detected and connection terminated.

---

## 2. Forward Secrecy

Forward secrecy ensures that compromise of long-term keys does not compromise past session keys. Our protocol achieves forward secrecy through **ephemeral key material** and **session-specific derivation**.

### 2.1 Ephemeral Shared Secret

**Phase 1A - Drone Generates Ephemeral Secret** (drone.py, line 68):
```python
k_dm = secrets.randbelow(2**256)  # Fresh 256-bit secret per session
```

**Key Properties**:
- ✅ **Session-Specific**: New `K_Dm` generated for every authentication
- ✅ **Never Reused**: Each session has a unique shared secret
- ✅ **Securely Transmitted**: Encrypted with MCC's public key (ElGamal)

**Encryption** (drone.py, lines 73-74):
```python
c1, c2 = cu.elgamal_encrypt(k_dm, p, g, mcc_pub_key)
```

**Decryption** (mcc.py, line 145):
```python
k_dm = cu.elgamal_decrypt(c1, c2, self.priv_key, self.p)
```

### 2.2 Session Key Derivation

**Phase 2 - Derive Session Key** (crypto_utils.py, lines 253-262):
```python
def derive_session_key(k_dm, ts_d, ts_mcc, rn_d, rn_mcc):
    def to_b(x): return str(x).encode()
    
    blob = to_b(k_dm) + to_b(ts_d) + to_b(ts_mcc) + to_b(rn_d) + to_b(rn_mcc)
    sk = hashlib.sha256(blob).digest()
    return sk
```

**Formula**:
```
SK = SHA256(K_Dm ∥ TS_D ∥ TS_MCC ∥ RN_D ∥ RN_MCC)
```

**Security Properties**:
- ✅ **Unique Per Session**: Different timestamps and nonces ensure unique SK
- ✅ **Mutual Contribution**: Both drone and MCC contribute randomness (RN_D, RN_MCC)
- ✅ **One-Way Derivation**: Cannot reverse SHA-256 to recover K_Dm
- ✅ **Binds Session Context**: Includes timestamps to bind to specific session

### 2.3 Forward Secrecy Analysis

**Scenario 1: Long-Term Private Key Compromise**

Assume attacker obtains MCC's private key `x_MCC` at time T:

**Past Sessions (T < T₀)**:
- Attacker has: `x_MCC`, captured ciphertext `(c1, c2)`
- Attacker can decrypt: `K_Dm = c2 · (c1^x_MCC)^-1 mod p` ✅
- Attacker can derive: `SK = SHA256(K_Dm ∥ TS_D ∥ TS_MCC ∥ RN_D ∥ RN_MCC)` ✅

**Verdict**: ❌ **No Perfect Forward Secrecy**

> [!WARNING]
> **Limitation**: This protocol does NOT provide perfect forward secrecy because the ephemeral secret `K_Dm` is encrypted with the long-term public key. If the long-term private key is compromised, past sessions can be decrypted.

**Why This Design?**

The assignment specifies using ElGamal encryption for `K_Dm` transmission. True perfect forward secrecy would require:
- Ephemeral Diffie-Hellman key exchange (both parties generate ephemeral keys)
- Or: Ephemeral ElGamal keys (generate new ElGamal key pair per session)

However, the protocol DOES provide:

### 2.4 Session Isolation

**Property**: Compromise of one session key does not compromise other sessions.

**Scenario 2: Single Session Key Compromise**

Assume attacker obtains `SK_1` for Drone_A's session:

**Other Sessions**:
- Drone_B's session: Uses different `K_Dm_B`, `RN_B`, `TS_B` → Different `SK_B` ✅
- Drone_A's next session: Uses different `K_Dm_A'`, `RN_A'`, `TS_A'` → Different `SK_A'` ✅

**Verdict**: ✅ **Session Isolation Maintained**

### 2.5 Group Key Forward Secrecy

**Phase 3 - Group Key Derivation** (mcc.py, lines 194-198):
```python
hasher = hashlib.sha256()
for did in sorted(self.fleet.keys()):
    hasher.update(self.fleet[did]['sk'])
hasher.update(str(self.priv_key).encode())
gk = hasher.digest()
```

**Formula**:
```
GK = SHA256(SK_D1 ∥ SK_D2 ∥ ... ∥ SK_Dn ∥ KR_MCC)
```

**Security Properties**:
- ✅ **Depends on All Session Keys**: Compromise of one SK doesn't reveal GK
- ✅ **MCC Contribution**: Includes MCC's private key for additional entropy
- ✅ **Deterministic**: Same fleet produces same GK (important for synchronization)

**Forward Secrecy**:
- If `KR_MCC` is compromised AND all `SK_i` are known → GK can be recomputed
- However, `SK_i` are session-specific, so future GK values remain secure

---

## 3. Attack Resistance

### 3.1 Replay Attack

**Attack**: Attacker captures and retransmits a valid authentication message.

**Defense**:
1. **Timestamp Check**: Rejects messages older than 60 seconds
2. **Nonce Cache**: Detects duplicate (drone_id, nonce) pairs
3. **Signature Verification**: Ensures message integrity

**Demonstration** (attacks.py):
```python
# Send same packet twice
self.send_current_packet()  # First attempt: SUCCESS
self.send_current_packet()  # Second attempt: REJECTED (replay detected)
```

**Result**: ✅ **Replay attacks are detected and blocked**

### 3.2 Man-in-the-Middle (MitM)

**Attack**: Attacker intercepts and modifies messages.

**Defense**:
1. **Digital Signatures**: All messages signed with ElGamal
2. **Mutual Authentication**: Both parties verify each other's signatures
3. **Parameter Integrity**: Phase 0 parameters are signed by MCC

**Attack Scenario**:
```
Attacker modifies Phase 0: p' = 23 (weak prime)
Drone receives: ⟨p'=23, g=2, SL=2048, TS, ID_MCC, Sig⟩
```

**Drone Validation** (drone.py, lines 62-68):
```python
# Check if prime bit length matches claimed SL
p_bit_length = p.bit_length()
if abs(p_bit_length - params['sl']) > 10:
    print(f"[!] SECURITY ALERT: Parameter mismatch! Prime is {p_bit_length}-bit but SL claims {params['sl']}-bit")
    return

if params['sl'] < 2048:
    print(f"[!] SECURITY ALERT: Security level {params['sl']} below minimum requirement (2048)")
    return
```

**Result**: ✅ **Parameter tampering is detected**

### 3.3 Unauthorized Access

**Attack**: Unknown drone attempts to connect without valid credentials.

**Defense**:
1. **Public Key Authentication**: Drone must have valid ElGamal key pair
2. **Signature Verification**: MCC verifies drone's signature
3. **HMAC Confirmation**: Final session key verification

**Attack Scenario**:
```
Attacker (no valid key pair) sends random signature
MCC verifies: elgamal_verify(msg, r, s, pub_key, p, g)
```

**Result**: ✅ **Invalid signatures are rejected**

### 3.4 Eavesdropping

**Attack**: Passive attacker captures all network traffic.

**Defense**:
1. **ElGamal Encryption**: `K_Dm` encrypted in Phase 1
2. **Session Key Derivation**: SK derived from encrypted secret
3. **AES-256 Encryption**: All commands encrypted with GK

**What Attacker Sees**:
- Phase 0: Public parameters (p, g, SL) - OK, these are public
- Phase 1: Ciphertext (c1, c2) - Cannot decrypt without private key
- Phase 2: HMAC - Cannot forge without SK
- Phase 3: Encrypted commands - Cannot decrypt without GK

**Result**: ✅ **Confidentiality maintained against passive eavesdropping**

---

## 4. Security Limitations

### 4.1 No Perfect Forward Secrecy

**Issue**: Compromise of MCC's long-term private key allows decryption of past sessions.

**Reason**: `K_Dm` is encrypted with long-term public key, not ephemeral keys.

**Mitigation**: 
- Regularly rotate MCC key pairs
- Use hardware security modules (HSM) to protect private keys
- Implement ephemeral Diffie-Hellman for perfect forward secrecy

### 4.2 Clock Synchronization Requirement

**Issue**: Timestamp validation requires synchronized clocks.

**Impact**: 
- Drones with incorrect clocks may be rejected
- Attackers can exploit clock skew for limited replay window

**Mitigation**:
- Use NTP for clock synchronization
- Implement adaptive time windows based on observed clock drift

### 4.3 Nonce Cache Growth

**Issue**: Nonce cache grows indefinitely in current implementation.

**Impact**: Memory usage increases over time.

**Mitigation** (for production):
```python
# Implement cache expiration
if (drone_id, rn_d) in self.seen_nonces:
    if time.time() - self.nonce_timestamps[(drone_id, rn_d)] < 300:
        # Reject: Nonce used within last 5 minutes
        return
    else:
        # Allow: Nonce expired, remove from cache
        self.seen_nonces.remove((drone_id, rn_d))
```

### 4.4 Denial of Service (DoS)

**Issue**: Attacker can flood MCC with connection requests.

**Impact**: Legitimate drones may be unable to connect.

**Current Defense**: None (out of scope for this assignment)

**Mitigation** (for production):
- Rate limiting per IP address
- Connection quotas
- Challenge-response puzzles (proof-of-work)

---

## 5. Cryptographic Strength

### 5.1 ElGamal Security

**Parameters**:
- Prime size: 2048 bits
- Generator: 2 (primitive root)
- Private key: Random in [1, p-2]

**Security Level**: ~112 bits (equivalent to RSA-2048)

**Attacks**:
- **Discrete Logarithm**: Best known attack requires ~2^112 operations
- **Chosen Ciphertext**: ElGamal is malleable, but signatures prevent tampering

### 5.2 Hash Functions

**SHA-256**:
- Output size: 256 bits
- Security level: 128 bits (birthday paradox)
- Collision resistance: No known practical attacks

**HMAC-SHA256**:
- Security: Depends on SHA-256 and key secrecy
- Prevents length extension attacks

### 5.3 Symmetric Encryption

**AES-256-CBC**:
- Key size: 256 bits
- Security level: ~256 bits
- IV: Random 16 bytes per encryption

---

## 6. Compliance Summary

| Security Property | Status | Implementation |
|------------------|--------|----------------|
| Confidentiality | ✅ | ElGamal + AES-256 encryption |
| Integrity | ✅ | Digital signatures + HMAC |
| Authentication | ✅ | Mutual ElGamal signature verification |
| Freshness | ✅ | Timestamp + nonce mechanism |
| Replay Protection | ✅ | Nonce cache + timestamp window |
| Session Isolation | ✅ | Unique session keys per connection |
| Forward Secrecy | ⚠️ | Limited (no perfect forward secrecy) |
| Non-Repudiation | ✅ | Digital signatures |

---

## 7. Recommendations

### For Production Deployment

1. **Implement Perfect Forward Secrecy**:
   - Use ephemeral Diffie-Hellman key exchange
   - Generate new ElGamal key pairs per session

2. **Add Certificate Authority**:
   - Implement PKI for public key distribution
   - Prevent MitM attacks on initial key exchange

3. **Enhance DoS Protection**:
   - Rate limiting
   - Connection quotas
   - IP-based blacklisting

4. **Implement Nonce Cache Expiration**:
   - Time-based cache cleanup
   - Bounded memory usage

5. **Add Logging and Auditing**:
   - Security event logging
   - Intrusion detection system integration

6. **Use Hardware Security Modules**:
   - Protect long-term private keys
   - Secure key generation

---

## 8. Conclusion

The Secure UAV Command and Control System implements a robust authentication and encryption protocol with strong defenses against common attacks:

**Strengths**:
- ✅ Strong freshness guarantees (dual-layer: timestamp + nonce)
- ✅ Effective replay attack prevention
- ✅ Mutual authentication with digital signatures
- ✅ Session isolation and unique session keys
- ✅ Secure group key distribution

**Limitations**:
- ⚠️ No perfect forward secrecy (by design, per assignment requirements)
- ⚠️ Requires clock synchronization
- ⚠️ Limited DoS protection

For the scope of this academic assignment, the protocol successfully demonstrates manual cryptographic implementation and secure protocol design principles.
