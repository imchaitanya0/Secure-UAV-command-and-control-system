# Secure UAV Command and Control System

## Overview

This project implements a secure, distributed UAV Command-and-Control (C2) system with manual ElGamal cryptography, mutual authentication, session management, and group key aggregation for fleet-wide secure broadcasting.

## System Components

- **MCC (Mission Control Center)**: Central server that manages multiple drones
- **Drone Clients**: UAV agents that authenticate and receive encrypted commands
- **Crypto Utilities**: Manual implementation of ElGamal and modular arithmetic
- **Attack Tools**: Demonstration of security vulnerabilities and defenses

## Features

### Manual Cryptographic Implementation
- **Modular Exponentiation**: Square-and-multiply algorithm for efficient computation
- **Extended Euclidean Algorithm**: Iterative implementation for 2048-bit numbers
- **ElGamal Encryption/Decryption**: Full manual implementation
- **ElGamal Digital Signatures**: Manual signing and verification
- **No High-Level Crypto Libraries**: Only uses primitives (AES-CBC, SHA-256, HMAC)

### Security Features
- **Mutual Authentication**: Both MCC and drones verify each other's identities
- **Replay Attack Protection**: Timestamp freshness checking + nonce caching
- **Session Key Derivation**: Unique session keys per drone
- **Group Key Aggregation**: Fleet-wide secure broadcasting
- **Digital Signatures**: All protocol messages are signed and verified

### Protocol Phases
1. **Phase 0**: Parameter initialization (p, g, SL)
2. **Phase 1**: Mutual authentication with ElGamal encryption and signatures
3. **Phase 2**: Session key establishment with HMAC confirmation
4. **Phase 3**: Group key distribution for broadcast commands

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup

```bash
# Clone or navigate to the project directory
cd Secure-UAV-command-and-control-system

# Install dependencies
pip install -r requirements.txt
```

### Dependencies
```
cryptography==46.0.4  # Used ONLY for AES-CBC primitive
```

## Usage

### 1. Start the MCC Server

```bash
python3 mcc.py
```

The MCC will:
- Generate 2048-bit ElGamal parameters
- Display its public key (copy this for attack demonstrations)
- Listen on port 65432
- Provide a CLI interface for commands

### 2. Connect Drones

In separate terminals, launch drone clients:

```bash
# Launch with custom ID
python3 drone.py Drone_Alpha

# Launch with random ID
python3 drone.py
```

Each drone will:
- Connect to MCC at 127.0.0.1:65432
- Perform mutual authentication
- Establish a session key
- Wait for commands

### 3. MCC Commands

Once drones are connected, use the MCC CLI:

```
MCC> list
Active Drones: 2
 - Drone_Alpha [ACTIVE]
 - Drone_Beta [ACTIVE]

MCC> broadcast MISSION_START
[*] Broadcasting: 'MISSION_START' to 2 drones.
[+] Broadcast Complete.

MCC> shutdown
[*] Shutting down MCC...
```

### 4. Attack Demonstrations

Run the attack tool to test security features:

```bash
python3 attacks.py
```

Available attack scenarios:
1. **Set MCC Public Key**: Configure target for attacks
2. **Build/Craft Packet**: Create custom authentication packets
3. **Send Packet**: Test replay attacks, timestamp validation
4. **MitM Test**: Demonstrate parameter tampering detection
5. **Unauthorized Access**: Test unknown drone ID rejection

## Performance Benchmarks

### Modular Exponentiation (2048-bit)

Performance measurements for manual modular exponentiation with 2048-bit primes:

| Metric | Time (ms) |
|--------|-----------|
| Average | 40.59 |
| Minimum | 36.97 |
| Maximum | 51.87 |

**Test Configuration**:
- Prime: RFC 3526 MODP Group 14 (2048-bit)
- Generator: 2
- Iterations: 10
- Algorithm: Square-and-multiply

**Performance Notes**:
- Using RFC 3526 standardized prime for consistency and security
- Iterative Extended GCD avoids Python recursion depth limits
- All arithmetic operations use Python's built-in arbitrary precision integers

### Key Generation Performance

| Operation | Average Time |
|-----------|--------------|
| ElGamal Key Generation | ~41 ms |
| ElGamal Encryption | ~82 ms (2 exponentiations) |
| ElGamal Decryption | ~41 ms (1 exponentiation + inverse) |
| ElGamal Signing | ~50-100 ms (varies with k selection) |
| ElGamal Verification | ~82 ms (2 exponentiations) |

## Project Structure

```
Secure-UAV-command-and-control-system/
├── crypto_utils.py      # Manual cryptographic primitives
├── mcc.py              # Mission Control Center server
├── drone.py            # Drone client implementation
├── attacks.py          # Security testing and attack demonstrations
├── requirements.txt    # Python dependencies
├── README.md          # This file
└── SECURITY.md        # Security analysis and protocol explanation
```

## File Descriptions

### crypto_utils.py
Contains all manual cryptographic implementations:
- `manual_mod_exp()`: Modular exponentiation
- `extended_gcd()`: Extended Euclidean algorithm
- `manual_mod_inverse()`: Modular inverse calculation
- `elgamal_keygen()`: ElGamal key pair generation
- `elgamal_encrypt()`: ElGamal encryption
- `elgamal_decrypt()`: ElGamal decryption
- `elgamal_sign()`: ElGamal digital signature
- `elgamal_verify()`: Signature verification
- `derive_session_key()`: Session key derivation
- `aes_encrypt()` / `aes_decrypt()`: AES-256-CBC wrappers
- `compute_hmac()`: HMAC-SHA256 wrapper
- `benchmark_mod_exp()`: Performance benchmarking

### mcc.py
Mission Control Center server implementation:
- Multi-threaded drone handling
- Thread-safe fleet registry
- CLI interface for operator commands
- Phase 0-3 protocol implementation
- Replay attack detection
- Group key aggregation and distribution

### drone.py
Drone client implementation:
- Automatic connection to MCC
- Parameter validation (security level checking)
- Mutual authentication protocol
- Session key derivation
- Command reception and decryption

### attacks.py
Security testing tool:
- Replay attack demonstration
- Timestamp freshness testing
- Wrong public key testing
- MitM parameter tampering
- Unauthorized drone access attempts

## Protocol Opcodes

| Opcode | Name | Description |
|--------|------|-------------|
| 10 | PARAM_INIT | Phase 0: Crypto parameters and MCC signature |
| 20 | AUTH_REQ | Phase 1A: Drone authentication packet |
| 30 | AUTH_RES | Phase 1B: MCC proof of decryption |
| 40 | SK_CONFIRM | Phase 2: Session key verification (HMAC) |
| 50 | SUCCESS | Handshake complete |
| 60 | ERR_MISMATCH | Key or HMAC verification failed |
| 70 | GROUP_KEY | Phase 3: Distribution of group key |
| 80 | GROUP_CMD | Secure broadcast (encrypted via GK) |
| 90 | SHUTDOWN | Close all drone connections |

## Security Considerations

See [SECURITY.md](SECURITY.md) for detailed security analysis including:
- Freshness guarantees (timestamp + nonce mechanism)
- Forward secrecy properties
- Replay attack prevention
- Man-in-the-Middle attack resistance

## Testing

### Basic Functionality Test

1. Start MCC: `python3 mcc.py`
2. Connect 2-3 drones in separate terminals
3. Use `list` command to verify connections
4. Use `broadcast` to send commands
5. Verify drones receive and decrypt commands

### Security Testing

1. Run `python3 attacks.py`
2. Copy MCC public key from MCC terminal
3. Test replay attack by sending same packet twice
4. Test timestamp validation with old timestamps
5. Test parameter tampering with weak primes

### Expected Behavior

**Successful Authentication**:
- Drone connects and completes all 3 phases
- MCC shows "[+] Drone X Authenticated Successfully"
- Drone shows "[+] Session Established"

**Replay Attack Detected**:
- MCC shows "[!] SECURITY ALERT: Replay Attack Detected!"
- Connection immediately closed

**Stale Timestamp**:
- MCC shows "[!] SECURITY ALERT: Stale Timestamp"
- Connection immediately closed

## Troubleshooting

### Connection Refused
- Ensure MCC is running before starting drones
- Check that port 65432 is not in use
- Verify firewall settings

### Signature Verification Failed
- Ensure parameters (p, g) match between MCC and drone
- Check that public keys are correctly exchanged
- Verify message format matches signature computation

### HMAC Mismatch
- Ensure session key derivation uses same parameters
- Check timestamp synchronization
- Verify nonce values match

## Implementation Notes

### Why RFC 3526 MODP Group 14?
Instead of generating a random 2048-bit prime (which takes several minutes), we use the standardized RFC 3526 MODP Group 14 prime. This is:
- Cryptographically secure (widely vetted)
- Faster (no prime generation delay)
- Consistent across runs
- Industry standard for Diffie-Hellman

### Iterative vs Recursive Extended GCD
Python has a default recursion limit of ~1000. With 2048-bit numbers, recursive Extended GCD causes stack overflow. Our iterative implementation handles arbitrary-sized integers.

### Thread Safety
The MCC uses a threading lock (`self.lock`) to protect the fleet registry from race conditions when multiple drones connect simultaneously.

## License

This is an academic project for the System and Network Security course (CS8.403) at IIIT Hyderabad.

## Authors

Lab Assignment 2 - Secure UAV Command and Control System

## References

- RFC 3526: More Modular Exponential (MODP) Diffie-Hellman groups
- ElGamal Encryption and Signature Schemes
- NIST FIPS 180-4: Secure Hash Standard (SHA-256)
- NIST FIPS 198-1: The Keyed-Hash Message Authentication Code (HMAC)
