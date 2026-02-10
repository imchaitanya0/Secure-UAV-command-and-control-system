# Security Analysis

## Threat Model

### Assets
- **MCC Private Key**: Compromise enables impersonation of Mission Control
- **Session Keys (K_Dm)**: Per-drone secrets for key distribution
- **Group Key (GK)**: Shared secret for broadcast command encryption
- **Drone Authorization**: Only IDs 1-20 should access the system

### Adversary Capabilities
- **Network Access**: Can intercept, replay, and inject packets
- **Computational Power**: Cannot break 2048-bit ElGamal in polynomial time
- **No Physical Access**: Cannot extract keys from memory/storage

## Security Guarantees

### Confidentiality
- **ElGamal Encryption (2048-bit)**: Session keys encrypted under MCC public key with semantic security
- **AES-256-GCM**: Broadcast commands encrypted with group key; provides authenticated encryption
- **Forward Secrecy**: Group key refreshed before each broadcast; past traffic remains secure if GK leaked
- **Backward Secrecy**: New drones receive fresh GK; cannot decrypt historical broadcasts

### Authentication
- **Mutual Authentication**: Both MCC and drones verify identity via ElGamal signatures
- **Message Authentication**: All Phase 1B/2/3 messages protected by HMAC-SHA256
- **Identity Binding**: Public keys signed with corresponding private keys

### Integrity
- **Digital Signatures**: ElGamal signatures on Phase 0/1A prevent parameter/packet tampering
- **HMAC Verification**: All encrypted payloads include MAC; modified messages rejected
- **AES-GCM**: Provides both encryption and authentication (AEAD)
- **Emergency Shutdown**: Drones detect HMAC failure and immediately disconnect (fail-secure design)

### Freshness
- **Timestamps**: All authentication messages include Unix timestamp; 30-second validity window
- **Nonces**: Random 256-bit nonces prevent replay attacks within same time window
- **Nonce Tracking**: MCC maintains `seen_nonces` set; duplicate (drone_id, nonce) pairs rejected

### Authorization
- **Drone ID Validation**: Only integer IDs 1-20 allowed; checked before cryptographic validation
- **Early Rejection**: Unauthorized IDs fail immediately (opcode 60); no resource consumption

## Attack Resistance

### Replay Attacks
**Mitigation**: 
- MCC tracks all `(drone_id, nonce)` pairs in `seen_nonces` set
- Duplicate authentication attempts rejected even with valid signatures
- Timestamp freshness provides additional replay window limitation

**Demonstration**: `attacks.py` → Build packet → Send twice → Second attempt fails

### Man-in-the-Middle (MitM)
**Mitigation**:
- Phase 0 parameters signed by MCC; drone verifies signature before proceeding
- Parameter tampering detected (e.g., weak prime substitution)
- Drone enforces minimum 2048-bit security level; rejects weak parameters
- Public key exchange signed; attacker cannot substitute keys

**Demonstration**: `attacks.py` → MitM test → Send weak parameters → Drone rejects

### Broadcast Tampering
**Mitigation**:
- All broadcast commands protected by HMAC-SHA256
- Drone verifies HMAC before decrypting/executing command
- **Fail-Secure Response**: On HMAC verification failure:
  - Drone logs critical security alert
  - Drone initiates emergency shutdown
  - Drone disconnects from MCC immediately
  - No tampered command execution
- Prevents attacker from injecting malicious commands even with network control

**Demonstration**: `attacks.py` → Broadcast MitM Attack → Proxy tampers with broadcast → Drone detects and shuts down

### Unauthorized Access
**Mitigation**:
- **ID-Based**: Drones with IDs outside 1-20 rejected before crypto checks (fast rejection)
- **Crypto-Based**: Wrong private key → signature verification fails → rejected
- **Stolen Public Key**: Attacker without corresponding private key cannot sign valid packets

**Demonstration**: 
- `python drone.py 999` → MCC rejects (opcode 60)
- `attacks.py` → Use random key → Signature fails

### Key Compromise Scenarios

| Compromised Key | Impact | Mitigation |
|----------------|--------|------------|
| **MCC Private Key** | Attacker can impersonate MCC, authenticate rogue drones | Detected by timestamp anomalies; requires secure key storage |
| **Drone Private Key** | Attacker can impersonate specific drone | Per-drone compromise limited; does not affect other drones |
| **Session Key (K_Dm)** | Attacker can decrypt GK for one drone | Other drones unaffected; GK rotated regularly |
| **Group Key (GK)** | Attacker can decrypt *one* broadcast | GK refreshed before each broadcast; forward secrecy limits damage |

### Connection Hijacking
**Mitigation**:
- Socket-level integrity: Each drone has unique session key
- Liveness Detection: `list` and `broadcast` commands probe sockets; dead connections auto-removed
- No Stale Drones: Disconnected drones immediately removed from fleet; cannot receive broadcasts

## Implementation Security

### Manual Cryptography
**Risk**: Custom crypto implementations may have subtle bugs
**Mitigation**:
- ElGamal follows standard textbook algorithms (Schneier, Applied Cryptography)
- Modular exponentiation uses proven square-and-multiply algorithm
- HMAC/AES delegated to battle-tested `cryptography` library (FIPS 140-2 validated)

### Side-Channel Resistance
**Timing Attacks**:
- **Modular Exponentiation**: Constant-time square-and-multiply (no secret-dependent branches)
- **HMAC Verification**: Uses `hmac.compare_digest()` to prevent timing leaks

**Limitation**: Python's arbitrary-precision integers may leak timing information; production systems should use constant-time libraries

### Randomness
- All secrets generated with `secrets` module (cryptographically secure PRNG)
- Nonces: 256-bit random values from `secrets.randbelow(2**256)`
- Session Keys: 256-bit random integers
- ElGamal ephemeral values: Random exponents in `[1, p-2]`

## Known Limitations

### Denial of Service (DoS)
- **Computational DoS**: Attacker can send invalid packets forcing expensive signature verification
- **Connection Exhaustion**: No rate limiting on new connections
- **Mitigation Strategy**: Authorization check before crypto (fast rejection); production would add rate limiting

### Key Distribution
- MCC public key distributed out-of-band (manual copy-paste)
- Production systems should use PKI with certificate validation

### Session Management
- Sessions persist until drone disconnects; no timeout mechanism
- Compromised session key valid indefinitely within session
- Production should implement session timeouts and periodic re-authentication

### Scalability
- `seen_nonces` set grows unbounded; memory exhaustion risk over time
- Production should implement sliding-window nonce tracking with expiration

### Perfect Forward Secrecy (PFS)
- ElGamal uses static MCC keypair; PFS not achieved for session key exchange
- Production should use ephemeral Diffie-Hellman for session establishment

## Security Best Practices Followed

✅ **Defense in Depth**: Multiple layers (authorization, crypto, MAC, timestamps)  
✅ **Principle of Least Privilege**: Drones only receive commands, cannot issue them  
✅ **Fail Securely**: Invalid packets rejected; no fallback to weak crypto  
✅ **Secure Defaults**: 2048-bit prime enforced; weak parameters rejected  
✅ **Input Validation**: All received fields validated before processing  
✅ **Constant-Time Comparisons**: HMAC verification uses timing-safe compare  
✅ **Cryptographic Agility**: Easy to upgrade primitives (parameter swapping)  

## Compliance

This implementation demonstrates academic understanding of:
- Public-key cryptography (ElGamal)
- Symmetric encryption (AES-GCM)
- Message authentication (HMAC)
- Secure protocol design
- Attack detection and mitigation

**Note**: This is a demonstration system for educational purposes. Production deployment would require additional hardening:
- Certificate-based key distribution
- Hardware security modules (HSMs) for private keys
- Rate limiting and DoS protection
- Comprehensive logging and intrusion detection
- Regular security audits and penetration testing
