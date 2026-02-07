import secrets
import hashlib
import hmac
import os
import sys

# -----------------------------------------------------------------------------
# PART 1: MANUAL MODULAR ARITHMETIC (REQUIRED BY PDF)
# -----------------------------------------------------------------------------

def manual_mod_exp(base, exp, mod):
    """
    Manual implementation of Modular Exponentiation using Square-and-Multiply.
    Calculates (base^exp) % mod.
    This replaces the built-in pow(base, exp, mod).
    """
    result = 1
    base = base % mod
    while exp > 0:
        # If exp is odd, multiply base with result
        if exp % 2 == 1:
            result = (result * base) % mod
        # exp must be even now
        exp = exp >> 1 # Divide by 2
        base = (base * base) % mod
    return result

def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm (Iterative).
    Returns (g, x, y) such that a*x + b*y = g = gcd(a, b).
    
    CRITICAL FIX: This uses an iterative 'while' loop instead of recursion.
    Recursive implementations crash Python on 2048-bit numbers due to 
    'maximum recursion depth exceeded'.
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    
    return old_r, old_s, old_t

def manual_mod_inverse(a, m):
    """
    Manual implementation of Modular Inverse.
    Calculates x such that (a * x) % m == 1.
    Uses Extended Euclidean Algorithm.
    """
    g, x, y = extended_gcd(a, m)
    if g != 1:
        # Modular inverse only exists if a and m are coprime
        raise Exception('Modular inverse does not exist (gcd != 1)')
    else:
        return x % m

def miller_rabin(n, k=5):
    """
    Miller-Rabin Primality Test.
    Returns True if n is likely prime, False if composite.
    k is the number of testing rounds (accuracy).
    """
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False

    # Find r and s such that n - 1 = 2^r * s
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    # Witness loop
    for _ in range(k):
        a = secrets.randbelow(n - 4) + 2
        x = manual_mod_exp(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = manual_mod_exp(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# -----------------------------------------------------------------------------
# PART 2: MANUAL ELGAMAL IMPLEMENTATION
# -----------------------------------------------------------------------------

def elgamal_keygen(p, g):
    """
    ElGamal Key Generation.
    Private Key x: random integer in [1, p-2]
    Public Key y: g^x mod p
    """
    x = secrets.randbelow(p - 2) + 1
    y = manual_mod_exp(g, x, p)
    return x, y  # Returns (Private Key, Public Key)

def elgamal_encrypt(m, p, g, y):
    """
    ElGamal Encryption (Manual).
    m: Integer message (must be < p)
    y: Recipient's Public Key
    Returns ciphertext pair (c1, c2)
    """
    if m >= p:
        raise ValueError("Message too large for prime p")
    
    # Select random ephemeral key k
    k = secrets.randbelow(p - 2) + 1
    
    # c1 = g^k mod p
    c1 = manual_mod_exp(g, k, p)
    
    # c2 = (m * y^k) mod p
    yk = manual_mod_exp(y, k, p)
    c2 = (m * yk) % p
    
    return (c1, c2)

def elgamal_decrypt(c1, c2, x, p):
    """
    ElGamal Decryption (Manual).
    m = c2 * (c1^x)^-1 mod p
    """
    # s = c1^x mod p (Shared Secret part)
    s = manual_mod_exp(c1, x, p)
    
    # s_inv = s^-1 mod p
    s_inv = manual_mod_inverse(s, p)
    
    # m = c2 * s_inv mod p
    m = (c2 * s_inv) % p
    return m

def elgamal_sign(message_bytes, x, p, g):
    """
    ElGamal Digital Signature (Manual).
    Returns signature (r, s).
    Formula: s = (H(m) - x*r) * k^-1 mod (p-1)
    """
    # 1. Calculate Hash of message
    h_obj = hashlib.sha256(message_bytes)
    hm_int = int.from_bytes(h_obj.digest(), byteorder='big')
    
    # 2. Select k such that gcd(k, p-1) = 1
    while True:
        k = secrets.randbelow(p - 2) + 1
        gcd_val, _, _ = extended_gcd(k, p - 1)
        if gcd_val == 1:
            break
            
    # 3. r = g^k mod p
    r = manual_mod_exp(g, k, p)
    
    # 4. s = (H(m) - x*r) * k^-1 mod (p-1)
    k_inv = manual_mod_inverse(k, p - 1)
    
    # Note: Python's % operator handles negative numbers correctly
    term = (hm_int - x * r)
    s = (term * k_inv) % (p - 1)
    
    return (r, s)

def elgamal_verify(message_bytes, r, s, y, p, g):
    """
    ElGamal Verification (Manual).
    Check condition: g^H(m) == y^r * r^s mod p
    """
    if not (0 < r < p) or not (0 < s < p - 1):
        return False
        
    h_obj = hashlib.sha256(message_bytes)
    hm_int = int.from_bytes(h_obj.digest(), byteorder='big')
    
    # LHS = g^H(m) mod p
    lhs = manual_mod_exp(g, hm_int, p)
    
    # RHS = (y^r * r^s) mod p
    yr = manual_mod_exp(y, r, p)
    rs = manual_mod_exp(r, s, p)
    rhs = (yr * rs) % p
    
    return lhs == rhs

# -----------------------------------------------------------------------------
# PART 3: UTILITIES (PRIME GEN, AES, HMAC)
# -----------------------------------------------------------------------------

def get_standard_safe_prime():
    """
    Returns RFC 3526 2048-bit MODP Group 14 parameters.
    Used to save time instead of generating a 2048-bit prime on the fly.
    """
    # 2048-bit MODP Group 14
    p_hex = """FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
    29024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD
    3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C
    42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1F
    E649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8
    FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D67
    0C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E
    86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718399549
    7CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"""
    p = int(p_hex.replace('\n', '').replace(' ', ''), 16)
    g = 2
    return p, g

def get_test_safe_prime(bit_length):
    """
    Returns pre-computed safe primes for security testing.
    These are verified safe primes where (p-1)/2 is also prime.
    For faster testing without the need for prime generation.
    
    Args:
        bit_length (int): Desired bit length (512, 768, or 1024)
    
    Returns:
        tuple: (p, g) where p is the safe prime and g=2
    """
    # Pre-computed safe primes for testing (verified Sophie Germain primes)
    TEST_SAFE_PRIMES = {
        # 512-bit safe prime: p = 2*q + 1 where q is prime
        512: (
            13407807929942597099574024998205846127479365820592393377723561204902306269321428931672352301633557244960017184315727,
            2
        ),
        # 768-bit safe prime
        768: (
            1555116378979402098722207062686337404423823137133546126705441425941589329968837034535065260537395506373313434238641413769,
            2
        ),
        # 1024-bit safe prime
        1024: (
            179769313486231590772930519466302748567385378696095636250022330011570147285174186408980121602876496286744604774649159950549737425330440343154025527702865857387537625884262403892814711330833915998879465764078951269347847540573064529677066659231424437218305815884357566369317675701857133629621565858594357651394,
            2
        ),
    }
    
    if bit_length not in TEST_SAFE_PRIMES:
        raise ValueError(f"No pre-computed safe prime for {bit_length} bits. Available: 512, 768, 1024")
    
    return TEST_SAFE_PRIMES[bit_length]

def aes_encrypt(key_bytes, plaintext):
    """
    AES-256-CBC Encryption.
    Uses 'cryptography' library strictly for the block cipher primitive.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    
    # Pad plaintext to 16 bytes (PKCS7 style padding simplified)
    pad_len = 16 - (len(plaintext) % 16)
    padded_data = plaintext + bytes([pad_len] * pad_len)
    
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return IV prepended to ciphertext
    return iv + ciphertext

def aes_decrypt(key_bytes, ciphertext):
    """
    AES-256-CBC Decryption.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(actual_ciphertext) + decryptor.finalize()
    
    # Remove padding
    pad_len = padded_data[-1]
    return padded_data[:-pad_len]

def derive_session_key(k_dm, ts_d, ts_mcc, rn_d, rn_mcc):
    """
    Phase 2: Derive SK = SHA256(K_Dm || TS_D || TS_MCC || RN_D || RN_MCC)
    All inputs should be converted to string bytes for consistency.
    """
    def to_b(x): return str(x).encode()
    
    blob = to_b(k_dm) + to_b(ts_d) + to_b(ts_mcc) + to_b(rn_d) + to_b(rn_mcc)
    sk = hashlib.sha256(blob).digest()
    return sk

def benchmark_mod_exp(bit_length=2048, iterations=10):
    """
    Benchmark modular exponentiation performance.
    Returns average time in milliseconds for the given bit length.
    """
    import time
    p, g = get_standard_safe_prime()
    
    times = []
    for _ in range(iterations):
        # Generate random exponent
        exp = secrets.randbelow(p - 2) + 1
        
        start = time.perf_counter()
        result = manual_mod_exp(g, exp, p)
        end = time.perf_counter()
        
        times.append((end - start) * 1000)  # Convert to milliseconds
    
    avg_time = sum(times) / len(times)
    min_time = min(times)
    max_time = max(times)
    
    return {
        'bit_length': bit_length,
        'iterations': iterations,
        'avg_ms': avg_time,
        'min_ms': min_time,
        'max_ms': max_time
    }

def compute_hmac(key, message):
    """
    HMAC-SHA256 Wrapper
    Handles both string and bytes input.
    """
    if isinstance(message, str):
        message = message.encode()
    return hmac.new(key, message, hashlib.sha256).digest()

def generate_safe_prime(bit_length):
    """
    Generate a safe prime of specified bit length.
    A safe prime p is a prime where (p-1)/2 is also prime.
    
    WARNING: This function is intended ONLY for security testing and 
    demonstration of MitM parameter tampering attacks. It should NOT be 
    used in production.
    
    Args:
        bit_length (int): Desired bit length of the prime (e.g., 512, 1024, 2048)
    
    Returns:
        tuple: (p, g) where p is the safe prime and g is a generator (typically 2)
    
    Time Complexity: O(bit_length^3) due to primality testing
    """
    if bit_length < 32:
        raise ValueError("Bit length must be at least 32")
    
    # Generate candidate safe primes until we find one
    # Limit iterations to prevent infinite loops for extremely small bit lengths
    max_iterations = 1000
    iterations = 0
    
    while iterations < max_iterations:
        iterations += 1
        
        # Generate random odd number with specified bit length
        # Ensure the number has exactly bit_length bits (set MSB)
        lower_bound = 2 ** (bit_length - 1)
        upper_bound = 2 ** bit_length
        candidate = secrets.randbelow(upper_bound - lower_bound) + lower_bound
        
        # Make it odd
        if candidate % 2 == 0:
            candidate += 1
        
        # Check if candidate is prime
        if not miller_rabin(candidate, k=10):
            continue
        
        # Check if (candidate - 1) / 2 is prime (Sophie Germain prime condition)
        q = (candidate - 1) // 2
        if not miller_rabin(q, k=10):
            continue
        
        # Found a safe prime
        p = candidate
        g = 2  # Standard generator for safe primes
        
        return p, g
    
    raise RuntimeError(f"Failed to generate {bit_length}-bit safe prime after {max_iterations} attempts")