# Secure UAV Command and Control System

A cryptographically secure UAV fleet management system implementing manual ElGamal encryption, digital signatures, and authenticated key distribution with comprehensive attack demonstrations.

## Features

- **Manual Cryptography**: Custom implementation of modular arithmetic, ElGamal encryption/signing, and HMAC/AES
- **Secure Authentication**: Multi-phase mutual authentication with timestamp and nonce validation
- **Group Key Management**: Dynamic group key distribution with forward/backward secrecy
- **Authorization Policy**: Drone ID validation (only IDs 1-20 allowed)
- **Concurrent Operations**: Thread-safe MCC server handling multiple drones simultaneously
- **Attack Detection**: Replay attack prevention, timestamp freshness checks, signature verification
- **Fail-Secure Design**: Emergency shutdown on integrity violations (HMAC failures)

## Architecture

### Components

1. **MCC (Mission Control Center)** - `mcc.py`
   - Concurrent server handling drone authentication and commands
   - ElGamal keypair generation and parameter distribution
   - Group key management and broadcast capabilities
   - Real-time fleet monitoring with connection status detection

2. **Drone Client** - `drone.py`
   - Multi-phase authentication protocol
   - Secure command reception via HMAC-authenticated AES
   - Parameter validation and signature verification
   - Graceful handling of authorization failures

3. **Crypto Utilities** - `crypto_utils.py`
   - Manual modular exponentiation (square-and-multiply)
   - ElGamal encryption/decryption and signing/verification
   - HMAC-SHA256 and AES-256-GCM wrappers
   - RFC 3526 safe prime parameters (2048-bit)
   - Performance benchmarking utilities

4. **Attack Demonstrations** - `attacks.py`
   - Replay attack simulation
   - MitM parameter tampering
   - Unauthorized access (ID-based and crypto-based)
   - Interactive packet manipulation tool

## Installation

```bash
pip install -r requirements.txt
```

**Dependencies**: `cryptography` (for AES-GCM only; all ElGamal/modular math is manual)

## Usage

### Start MCC Server

```bash
python mcc.py
```

Copy the displayed public key for use in `attacks.py` if testing attacks.

### Connect Drones

```bash
python drone.py <drone_id> <port>
65432 -> original mcc
65434 -> attacker
```

Example: `python drone.py 5 port` (IDs must be integers 1-20)

### MCC Commands

- `list` - Show all drones with live connection status (auto-removes disconnected)
- `broadcast <message>` - Send encrypted command to all active drones (group key updated before each broadcast)
- `shutdown` - Stop the MCC server

### Run Attack Demonstrations

```bash
python attacks.py
```

Follow the interactive menu to:
1. Configure target MCC public key
2. Build custom authentication packets
3. Test replay attacks (send same packet twice)
4. Simulate MitM parameter downgrade
5. Test unauthorized access scenarios

## Security Protocol

### Phase 0: Parameter Distribution
- MCC sends signed parameters (p, g, SL, timestamp, identity)
- Drone verifies signature, timestamp freshness, and parameter validity
- Enforces 2048-bit minimum security level

### Phase 1A: Authentication Request
- Drone generates ephemeral session key K_Dm
- Encrypts K_Dm with MCC public key
- Signs packet with drone's private key
- Includes timestamp and nonce for replay prevention

### Phase 1B: Authentication Response
- MCC validates drone ID authorization (1-20 only)
- Checks timestamp freshness (30-second window)
- Verifies signature and prevents nonce replay
- Decrypts and echoes K_Dm back encrypted
- Drone confirms successful mutual authentication

### Phase 2: Group Key Distribution
- MCC generates fresh group key before each broadcast
- Encrypts group key with each drone's session key
- HMAC authentication prevents tampering

### Phase 3: Broadcast Commands
- Commands encrypted with AES-256-GCM using group key
- HMAC verification ensures message integrity
- Disconnected drones immediately removed from fleet

## Performance Logs

- 512-bit Modular Exponentiation: 0.001341 seconds
- 1024-bit Modular Exponentiation: 0.007145 seconds
- 2048-bit Modular Exponentiation: 0.042458 seconds
- 3072-bit Modular Exponentiation: 0.130984 seconds

### Manual Modular Exponentiation
- 2048-bit prime operations: TBD ms/operation
- Comparison vs. Python built-in `pow()`: TBD

### ElGamal Operations
- Key generation: TBD ms
- Encryption: TBD ms
- Decryption: TBD ms
- Signing: TBD ms
- Verification: TBD ms

### End-to-End Authentication
- Phase 0-1B completion: TBD ms
- Group key distribution per drone: TBD ms
- Broadcast to N drones: TBD ms

*(Run `crypto_utils.benchmark_all()` to generate performance data)*

## Project Structure

```
.
├── mcc.py              # Mission Control Center server
├── drone.py            # UAV client implementation
├── crypto_utils.py     # Manual cryptography primitives
├── attacks.py          # Security testing & attack demonstrations
├── requirements.txt    # Python dependencies
├── README.md           # This file
└── SECURITY.md         # Security analysis and threat model
```

## Testing

1. **Normal Operation**: Start MCC → Connect 2-3 drones → Test `list` and `broadcast` commands
2. **Authorization**: Try drone IDs outside 1-20 range (should be rejected)
3. **Replay Attack**: Run `attacks.py` → Send same packet twice (second fails)
4. **MitM Detection**: Run weak parameter attack (drone rejects <2048-bit)
5. **Connection Handling**: Kill drone process → Run `list` (auto-removed)