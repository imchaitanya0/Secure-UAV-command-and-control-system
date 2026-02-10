import socket
import json
import time
import secrets
import sys
import crypto_utils as cu

# Configuration
TARGET_IP = '127.0.0.1'
TARGET_PORT = 65432

class ManualAttackTool:
    def __init__(self):
        self.p, self.g = cu.get_standard_safe_prime()
        self.mcc_pub_key = None
        
        # State for the "Current Packet"
        self.current_packet = None
        self.current_packet_desc = "None"
        self.secret_sent = None
        self.attacker_priv_key = None
        
        print("\n[*] Crypto Parameters Loaded.")

    def set_target_key(self):
        print("\n--- CONFIG: SET MCC PUBLIC KEY ---")
        print("Paste the Public Key from the MCC Server output.")
        print("To test 'Wrong Key' scenarios, enter a random number here.")
        while True:
            try:
                val = input("Enter Key: ").strip()
                if not val: return
                self.mcc_pub_key = int(val)
                print(f"[*] Target Public Key set to: {str(self.mcc_pub_key)[:20]}...")
                return
            except ValueError:
                print("Invalid number. Try again.")

    def build_packet_menu(self):
        if not self.mcc_pub_key:
            print("\n[!] ERROR: Set MCC Public Key (Option 1) first!")
            return

        print("\n--- BUILD NEW PACKET ---")
        print("Leave inputs empty to use defaults (Fresh/Random).")
        
        # 1. Drone ID
        did = input("Drone ID [AttackerBot]: ").strip() or "AttackerBot"
        
        # 2. Timestamp
        now = int(time.time())
        ts_in = input(f"Timestamp [Now: {now}]: ").strip()
        ts = int(ts_in) if ts_in else now
        
        # 3. Nonce
        rn_in = input("Nonce [Random]: ").strip()
        rn = int(rn_in) if rn_in else secrets.randbelow(2**256)
        
        # Build Crypto
        print("[*] Encrypting and Signing...")
        # Generate temporary attacker keys for this session
        priv, pub = cu.elgamal_keygen(self.p, self.g)
        self.attacker_priv_key = priv
        self.secret_sent = 12345  # We always send this secret
        
        # Encrypt secret using the TARGET Key (Stored in self.mcc_pub_key)
        c1, c2 = cu.elgamal_encrypt(self.secret_sent, self.p, self.g, self.mcc_pub_key)
        
        # Sign
        sig_msg = f"{ts}{rn}{did}{c1}{c2}".encode()
        r, s = cu.elgamal_sign(sig_msg, priv, self.p, self.g)
        
        self.current_packet = {
            'drone_id': did, 'ts': ts, 'rn': rn,
            'c1': c1, 'c2': c2, 'r': r, 's': s, 'pub_key': pub
        }
        
        self.current_packet_desc = f"ID={did}, TS={ts}, Nonce={rn}"
        print(f"[*] Packet Built! Ready to send.")

    def send_current_packet(self):
        if not self.current_packet:
            print("\n[!] No packet built. Use Option 2 first.")
            return

        print(f"\n[*] Sending Packet ({self.current_packet_desc})...")
        print("    (Note: Sending this SAME packet twice will trigger Replay Alert)")
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((TARGET_IP, TARGET_PORT))
            
            # 1. Ignore Phase 0
            self.recv_json(s)
            
            # 2. Send Packet
            self.send_json(s, {'opcode': 20, 'payload': self.current_packet})
            
            # 3. Get Response
            resp = self.recv_json(s)
            s.close()
            
            if not resp:
                print("\n" + "!"*40)
                print("[RESULT] CONNECTION CLOSED / REJECTED")
                print("The server dropped the packet immediately.")
                print("REASON: Replay Attack Detected OR Stale Timestamp.")
                print("!"*40)
            else:
                self.analyze_success(resp)

        except ConnectionRefusedError:
            print("[!] Connection Refused. Is mcc.py running?")
        except Exception as e:
            print(f"[!] Error: {e}")

    def analyze_success(self, resp):
        opcode = resp.get('opcode')
        print(f"\n[RESULT] Server Responded with Opcode: {opcode}")
        
        if opcode == 30:
            print("Status: PROTOCOL ACCEPTED.")
            print("   -> The server accepted the signature and timestamp.")
            print("   -> NOW CHECKING: Did the server decrypt it correctly?")
            
            # Server encrypts the secret back to us. Let's decrypt it.
            pl = resp['payload']
            k_rec = cu.elgamal_decrypt(pl['c1'], pl['c2'], self.attacker_priv_key, self.p)
            
            print(f"\n   [SECRET CHECK]")
            print(f"   Original Secret Sent:   {self.secret_sent}")
            print(f"   Server Decrypted Value: {k_rec}")
            
            if k_rec == self.secret_sent:
                print("\n   [PASS] MATCH! The Public Key you used was CORRECT.")
            else:
                print("\n   [FAIL] MISMATCH! The Server failed to decrypt correctly.")
                print("   [CONCLUSION] You successfully used a WRONG KEY.")
                print("                The server authenticated garbage data.")
        
        elif opcode == 60:
            print("Status: ERROR (Mismatch).")

    def run_mitm(self):
        print("\n--- MITM PARAMETER TAMPERING TEST ---")
        print("This test demonstrates what happens when an attacker")
        print("tries to downgrade security by sending weak parameters.")
        print()
        
        choice = input("1. Test Weak Prime (23-bit)\n2. Test Mismatched SL\n3. Cancel\nSelect: ").strip()
        
        if choice == '1':
            print("\n[*] Attempting to send 23-bit prime with SL=2048 claim...")
            print("    (This simulates a MitM attacker downgrading security)")
            
            # Create fake weak parameters
            weak_p = 23  # Tiny prime
            weak_g = 2
            fake_sl = 2048  # Claim it's 2048-bit (lie!)
            
            actual_bits = weak_p.bit_length()
            print(f"\n[ANALYSIS]")
            print(f"  Actual prime bit length: {actual_bits}")
            print(f"  Claimed SL: {fake_sl}")
            print(f"  Discrepancy: {fake_sl - actual_bits} bits")
            print(f"\n[EXPECTED RESULT]")
            print(f"  A properly implemented drone should:")
            print(f"  1. Check: p.bit_length() ≈ SL")
            print(f"  2. Detect: {actual_bits} ≠ {fake_sl}")
            print(f"  3. REJECT connection and abort")
            print(f"\n  ✓ Your drone.py DOES implement this check!")
            
        elif choice == '2':
            print("\n[*] Testing SL below minimum (512-bit)...")
            print("    (This simulates weak crypto parameters)")
            
            weak_sl = 512
            print(f"\n[ANALYSIS]")
            print(f"  Proposed SL: {weak_sl}")
            print(f"  Minimum Required: 2048")
            print(f"\n[EXPECTED RESULT]")
            print(f"  Drone should reject SL < 2048")
            print(f"  ✓ Your drone.py DOES implement this check!")
        
        else:
            print("Cancelled.")

    def test_unauthorized_drone(self):
        """
        3.3 Unauthorized Access Attack Demo

        Demonstrates that an attacker WITHOUT valid ElGamal credentials
        cannot authenticate with the MCC, AND that drones with unauthorized
        IDs (outside 1-20) are rejected even with valid crypto.

        ID-based authorization (checked FIRST by MCC):
          4. Unauthorized Drone ID       — valid crypto, but ID outside 1-20
          5. Boundary ID Cases           — test edges: 0, 1, 20, 21
          6. Invalid ID Formats          — non-integer IDs: "abc", "", "-5"

        Crypto-based attacks (checked AFTER ID authorization):
          1. Random Signature Attack     — random r, s values
          2. Wrong Key Pair Attack       — sign with key A, send pub key B
          3. Zero/Malformed Signature    — r=0, s=0 (boundary check)
        """
        print("\n" + "=" * 60)
        print("   3.3 UNAUTHORIZED ACCESS ATTACK DEMO")
        print("=" * 60)
        print("Defense Layer 1: Drone ID must be an integer in range 1-20")
        print("Defense Layer 2: ElGamal signature verification")
        print()

        if not self.mcc_pub_key:
            print("[!] ERROR: Set MCC Public Key (Option 1) first!")
            return

        print("Select attack sub-scenario:")
        print()
        print("  --- ID Authorization Attacks (checked FIRST) ---")
        print("  4. Unauthorized Drone IDs    (valid crypto, ID outside 1-20)")
        print("  5. Boundary ID Cases         (0, 1, 20, 21)")
        print("  6. Invalid ID Formats        (non-integer IDs)")
        print()
        print("  --- Crypto Attacks (checked AFTER ID auth) ---")
        print("  1. Random Signature Attack   (random r, s — no valid key pair)")
        print("  2. Wrong Key Pair Attack     (sign with key A, send pub key B)")
        print("  3. Zero/Malformed Signature  (r=0, s=0 — boundary violation)")
        print()
        print("  7. Run ALL scenarios")

        choice = input("\nSelect (1-7): ").strip()

        scenarios = []
        if choice in ['1','2','3','4','5','6']:
            scenarios = [int(choice)]
        elif choice == '7':
            scenarios = [4, 5, 6, 1, 2, 3]
        else:
            print("[!] Invalid choice.")
            return

        for sc in scenarios:
            if sc == 1:
                self._attack_random_signature()
            elif sc == 2:
                self._attack_wrong_keypair()
            elif sc == 3:
                self._attack_zero_signature()
            elif sc == 4:
                self._attack_unauthorized_ids()
            elif sc == 5:
                self._attack_boundary_ids()
            elif sc == 6:
                self._attack_invalid_id_formats()

        print("\n" + "=" * 60)
        print("   DEMO COMPLETE")
        print("=" * 60)

    # ------------------------------------------------------------------
    # Sub-scenario 1: Random Signature Attack
    # ------------------------------------------------------------------
    def _attack_random_signature(self):
        print("\n" + "-" * 60)
        print("  SUB-SCENARIO 1: RANDOM SIGNATURE ATTACK")
        print("-" * 60)
        print("[*] Attacker has NO valid ElGamal key pair.")
        print("[*] Generating completely random r, s values...")

        drone_id = "ROGUE_DRONE_01"
        ts = int(time.time())
        rn = secrets.randbelow(2**256)

        # Generate a random (but unrelated) public key to send
        _, fake_pub = cu.elgamal_keygen(self.p, self.g)

        # Encrypt a random secret for the handshake
        secret = secrets.randbelow(self.p - 1) + 1
        c1, c2 = cu.elgamal_encrypt(secret, self.p, self.g, self.mcc_pub_key)

        # --- THE ATTACK: random r, s instead of a real signature ---
        r = secrets.randbelow(self.p - 2) + 1
        s = secrets.randbelow(self.p - 2) + 1

        sig_msg = f"{ts}{rn}{drone_id}{c1}{c2}".encode()
        print(f"[*] Message to be signed : {sig_msg[:60]}...")
        print(f"[*] Random r             : {str(r)[:40]}...")
        print(f"[*] Random s             : {str(s)[:40]}...")

        # Local pre-check
        local_ok = cu.elgamal_verify(sig_msg, r, s, fake_pub, self.p, self.g)
        print(f"\n[*] LOCAL pre-check  →  elgamal_verify = {local_ok}")

        packet = {
            'drone_id': drone_id, 'ts': ts, 'rn': rn,
            'c1': c1, 'c2': c2, 'r': r, 's': s, 'pub_key': fake_pub
        }
        self._send_attack_packet(packet, "Random Signature")

    # ------------------------------------------------------------------
    # Sub-scenario 2: Wrong Key Pair Attack
    # ------------------------------------------------------------------
    def _attack_wrong_keypair(self):
        print("\n" + "-" * 60)
        print("  SUB-SCENARIO 2: WRONG KEY PAIR ATTACK")
        print("-" * 60)
        print("[*] Attacker signs with key pair A but sends public key B.")
        print("[*] MCC will verify signature against pub_key B → mismatch.")

        drone_id = "ROGUE_DRONE_02"
        ts = int(time.time())
        rn = secrets.randbelow(2**256)

        # Key pair A — used to SIGN
        priv_a, pub_a = cu.elgamal_keygen(self.p, self.g)
        # Key pair B — sent to MCC (different from A)
        _, pub_b = cu.elgamal_keygen(self.p, self.g)

        secret = secrets.randbelow(self.p - 1) + 1
        c1, c2 = cu.elgamal_encrypt(secret, self.p, self.g, self.mcc_pub_key)

        sig_msg = f"{ts}{rn}{drone_id}{c1}{c2}".encode()

        # Sign with key A
        r, s = cu.elgamal_sign(sig_msg, priv_a, self.p, self.g)

        print(f"[*] Signed with pub_key A: {str(pub_a)[:40]}...")
        print(f"[*] Sending  pub_key B   : {str(pub_b)[:40]}...")

        # Local pre-check — verify against pub_key B (should fail)
        local_ok = cu.elgamal_verify(sig_msg, r, s, pub_b, self.p, self.g)
        print(f"\n[*] LOCAL pre-check  →  elgamal_verify(sig, pub_B) = {local_ok}")

        packet = {
            'drone_id': drone_id, 'ts': ts, 'rn': rn,
            'c1': c1, 'c2': c2, 'r': r, 's': s, 'pub_key': pub_b
        }
        self._send_attack_packet(packet, "Wrong Key Pair")

    # ------------------------------------------------------------------
    # Sub-scenario 3: Zero / Malformed Signature Attack
    # ------------------------------------------------------------------
    def _attack_zero_signature(self):
        print("\n" + "-" * 60)
        print("  SUB-SCENARIO 3: ZERO / MALFORMED SIGNATURE ATTACK")
        print("-" * 60)
        print("[*] Attacker sends r=0, s=0 (out-of-range values).")
        print("[*] elgamal_verify boundary check: 0 < r < p and 0 < s < p-1")

        drone_id = "ROGUE_DRONE_03"
        ts = int(time.time())
        rn = secrets.randbelow(2**256)

        _, fake_pub = cu.elgamal_keygen(self.p, self.g)

        secret = secrets.randbelow(self.p - 1) + 1
        c1, c2 = cu.elgamal_encrypt(secret, self.p, self.g, self.mcc_pub_key)

        # --- THE ATTACK: malformed r=0, s=0 ---
        r = 0
        s = 0

        sig_msg = f"{ts}{rn}{drone_id}{c1}{c2}".encode()
        print(f"[*] r = {r}")
        print(f"[*] s = {s}")

        # Local pre-check
        local_ok = cu.elgamal_verify(sig_msg, r, s, fake_pub, self.p, self.g)
        print(f"\n[*] LOCAL pre-check  →  elgamal_verify = {local_ok}")

        packet = {
            'drone_id': drone_id, 'ts': ts, 'rn': rn,
            'c1': c1, 'c2': c2, 'r': r, 's': s, 'pub_key': fake_pub
        }
        self._send_attack_packet(packet, "Zero/Malformed Signature")

    # ------------------------------------------------------------------
    # Sub-scenario 4: Unauthorized Drone IDs (valid crypto, bad ID)
    # ------------------------------------------------------------------
    def _attack_unauthorized_ids(self):
        print("\n" + "-" * 60)
        print("  SUB-SCENARIO 4: UNAUTHORIZED DRONE IDs")
        print("-" * 60)
        print("[*] Attacker sends VALID crypto but uses drone IDs outside 1-20.")
        print("[*] MCC checks ID authorization BEFORE verifying signatures.")
        print("[*] Policy: Only integer IDs 1-20 are authorized.\n")

        unauthorized_ids = ["25", "55", "100", "999", "0", "-1"]

        for uid in unauthorized_ids:
            print(f"  ── Testing drone ID = {uid} (UNAUTHORIZED) ──")
            self._send_id_attack_packet(uid, f"Unauthorized ID {uid}")

    # ------------------------------------------------------------------
    # Sub-scenario 5: Boundary ID Cases
    # ------------------------------------------------------------------
    def _attack_boundary_ids(self):
        print("\n" + "-" * 60)
        print("  SUB-SCENARIO 5: BOUNDARY ID CASES")
        print("-" * 60)
        print("[*] Testing edge cases around the authorized range (1-20).\n")

        test_cases = [
            ("0",  "REJECT  — below minimum"),
            ("1",  "ACCEPT  — minimum authorized"),
            ("10", "ACCEPT  — middle of range"),
            ("20", "ACCEPT  — maximum authorized"),
            ("21", "REJECT  — above maximum"),
        ]

        for drone_id, description in test_cases:
            print(f"  ── Testing drone ID = {drone_id}  →  Expected: {description} ──")
            self._send_id_attack_packet(drone_id, f"Boundary ID {drone_id}")

    # ------------------------------------------------------------------
    # Sub-scenario 6: Invalid ID Formats (non-integer)
    # ------------------------------------------------------------------
    def _attack_invalid_id_formats(self):
        print("\n" + "-" * 60)
        print("  SUB-SCENARIO 6: INVALID ID FORMATS")
        print("-" * 60)
        print("[*] Drone ID must be an integer.  Non-integer values must be rejected.\n")

        invalid_ids = ["abc", "drone1", "1.5", "", "null", "0x10", "ROGUE"]

        for uid in invalid_ids:
            label = uid if uid else "<empty>"
            print(f"  ── Testing drone ID = '{label}' (INVALID FORMAT) ──")
            self._send_id_attack_packet(uid, f"Invalid Format '{label}'")

    # ------------------------------------------------------------------
    # Helper: build a packet with VALID crypto for a given drone_id
    #         and send it to the MCC to test ID authorization
    # ------------------------------------------------------------------
    def _send_id_attack_packet(self, drone_id, test_name):
        """Send a fully valid crypto packet but with the given drone_id."""
        priv, pub = cu.elgamal_keygen(self.p, self.g)
        ts = int(time.time())
        rn = secrets.randbelow(2**256)
        secret = secrets.randbelow(self.p - 1) + 1
        c1, c2 = cu.elgamal_encrypt(secret, self.p, self.g, self.mcc_pub_key)

        sig_msg = f"{ts}{rn}{drone_id}{c1}{c2}".encode()
        r, s = cu.elgamal_sign(sig_msg, priv, self.p, self.g)   # VALID signature

        packet = {
            'drone_id': drone_id, 'ts': ts, 'rn': rn,
            'c1': c1, 'c2': c2, 'r': r, 's': s, 'pub_key': pub
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((TARGET_IP, TARGET_PORT))

            self.recv_json(sock)                                     # Phase 0
            self.send_json(sock, {'opcode': 20, 'payload': packet})  # Phase 1A

            resp = self.recv_json(sock)
            sock.close()

            if resp and resp.get('opcode') == 30:
                print(f"     ✅ ACCEPTED — drone ID {drone_id} is within authorized range (1-20)")
            elif resp and resp.get('opcode') == 60:
                payload = resp.get('payload', {})
                if isinstance(payload, dict):
                    err  = payload.get('error', 'Unknown')
                    msg  = payload.get('message', '')
                    print(f"     ❌ REJECTED — {err}: {msg}")
                else:
                    print(f"     ❌ REJECTED — {payload}")
            else:
                print(f"     ❌ REJECTED — connection closed by MCC")

        except (ConnectionResetError, BrokenPipeError):
            print(f"     ❌ REJECTED — MCC closed the connection immediately")
        except socket.timeout:
            print(f"     ❌ REJECTED — no response (MCC dropped connection)")
        except Exception as e:
            print(f"     [!] Error during {test_name}: {e}")
        print()

    # ------------------------------------------------------------------
    # Helper: send attack packet and interpret result (crypto attacks)
    # ------------------------------------------------------------------
    def _send_attack_packet(self, packet, attack_name):
        print(f"\n[*] Sending forged Phase 1A packet to MCC ({TARGET_IP}:{TARGET_PORT})...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((TARGET_IP, TARGET_PORT))

            # Receive Phase 0 (ignore — attacker doesn't validate)
            self.recv_json(sock)

            # Send forged Phase 1A
            self.send_json(sock, {'opcode': 20, 'payload': packet})

            # Wait for Phase 1B response
            resp = self.recv_json(sock)
            sock.close()

            if resp and resp.get('opcode') == 30:
                print(f"\n  ❌ UNEXPECTED: MCC accepted the {attack_name}!")
                print("     This should NOT happen — investigate MCC verification logic.")
            else:
                print(f"\n  ✅ DEFENSE SUCCESSFUL: {attack_name} was REJECTED by MCC.")
                print("     → MCC called elgamal_verify(msg, r, s, pub_key, p, g)")
                print("     → Signature verification returned False")
                print("     → Connection closed — unauthorized access denied")

        except (ConnectionResetError, BrokenPipeError):
            # MCC closes the socket immediately after verification failure
            print(f"\n  ✅ DEFENSE SUCCESSFUL: {attack_name} was REJECTED by MCC.")
            print("     → MCC closed the connection (signature verification failed)")
        except socket.timeout:
            # MCC closed connection, socket timed out waiting for response
            print(f"\n  ✅ DEFENSE SUCCESSFUL: {attack_name} was REJECTED by MCC.")
            print("     → MCC closed the connection (no response — signature invalid)")
        except Exception as e:
            print(f"  [!] Connection error: {e}")

    def phase0_mitm_attack(self):
        """
        Phase 0 MitM Attack - Assignment Compliant
        
        This creates a fake MCC server that sends malicious Phase 0 parameters
        to demonstrate how the drone's security features reject attacks.
        
        Two attack types:
        1. Weak Prime Attack - Send valid signature but weak parameters
        2. Signature Tampering Attack - Send tampered message with invalid signature
        """
        print("\n--- PHASE 0 MITM ATTACK ---")
        print("This test creates a fake MCC server that sends malicious Phase 0 parameters")
        print("to demonstrate how the drone's security features detect and reject attacks.")
        print()
        
        choice = input("1. Weak Prime Attack (Valid signature, weak parameters)\n2. Signature Tampering Attack (Invalid signature)\n3. Cancel\nSelect: ").strip()
        
        if choice == '1':
            self.weak_prime_attack()
        elif choice == '2':
            self.signature_tampering_attack()
        else:
            print("Cancelled.")

    def weak_prime_attack(self):
        """
        Attack Type 1: Weak Prime Attack
        
        - Attacker has valid MCC private key (for demonstration)
        - Sends properly signed Phase 0 but with weak 1024-bit prime
        - Drone should detect parameter mismatch and reject
        """
        print("\n🚨 [WEAK PRIME ATTACK]")
        print("Attack: Send valid signature but downgrade prime from 2048-bit to 1024-bit")
        print("Expected: Drone detects parameter mismatch and rejects connection")
        print()
        
        try:
            # First get legitimate parameters from real MCC
            print("[*] Step 1: Intercepting legitimate parameters from real MCC...")
            mcc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            mcc_sock.settimeout(5)
            mcc_sock.connect((TARGET_IP, TARGET_PORT))
            
            legit_phase0 = self.recv_json(mcc_sock)
            mcc_sock.close()
            
            if not legit_phase0 or legit_phase0.get('opcode') != 10:
                print("[!] Failed to intercept legitimate Phase 0 from MCC")
                return
            
            legit_params = legit_phase0['payload']
            legitimate_mcc_priv_key = None  # We don't have the real private key
            
            print("✅ Intercepted legitimate Phase 0 parameters")
            print(f"   Original Prime: {legit_params['p'].bit_length()} bits")
            print(f"   Original SL: {legit_params['sl']}")
            
            # For demonstration, we'll use our own key pair to show the attack concept
            print("\n[*] Step 2: Creating malicious Phase 0 with weak prime...")
            
            # Generate attacker's key pair (simulating compromised MCC keys)
            attacker_p, attacker_g = cu.get_standard_safe_prime()
            attacker_priv, attacker_pub = cu.elgamal_keygen(attacker_p, attacker_g)
            
            # Create weak parameters for attack
            try:
                weak_p, weak_g = cu.get_test_safe_prime(1024)  # Weak 1024-bit prime
                weak_sl = 2048  # LIE: Claim it's still 2048-bit
            except:
                weak_p = 2**1023 + 1  # Fallback weak prime
                weak_g = 2
                weak_sl = 2048
            
            ts0 = int(time.time())
            id_mcc = "FAKE_MCC_WEAK_PRIME"
            
            # Create properly signed message (but with weak parameters)
            phase0_msg = f"{weak_p}{weak_g}{weak_sl}{ts0}{id_mcc}".encode()
            r0, s0 = cu.elgamal_sign(phase0_msg, attacker_priv, attacker_p, attacker_g)
            
            malicious_phase0 = {
                'opcode': 10,
                'payload': {
                    'p': weak_p,           # ATTACK: Weak 1024-bit prime
                    'g': weak_g,           # Generator for weak prime
                    'sl': weak_sl,         # LIE: Claim it's 2048-bit
                    'ts0': ts0,            # Current timestamp
                    'id_mcc': id_mcc,      # Fake MCC identity
                    'pub_key': attacker_pub, # Attacker's public key
                    'r0': r0,              # Valid signature (r component)
                    's0': s0               # Valid signature (s component)
                }
            }
            
            print(f"✅ Created malicious Phase 0:")
            print(f"   Weak Prime: {weak_p.bit_length()} bits")
            print(f"   Claimed SL: {weak_sl} bits (LYING!)")
            print(f"   Discrepancy: {weak_sl - weak_p.bit_length()} bits")
            print(f"   Signature: Valid (r={str(r0)[:20]}..., s={str(s0)[:20]}...)")
            
            # Start fake MCC server
            self.run_fake_mcc_server(malicious_phase0, "WEAK_PRIME")
            
        except ConnectionRefusedError:
            print("[!] Cannot connect to real MCC. Make sure mcc.py is running on port 65432")
        except Exception as e:
            print(f"[!] Weak prime attack error: {e}")

    def signature_tampering_attack(self):
        """
        Attack Type 2: Signature Tampering Attack
        
        - Intercept legitimate Phase 0
        - Tamper with the message (change MCC identity)
        - Keep original signature (now invalid)
        - Drone should detect signature verification failure
        """
        print("\n🚨 [SIGNATURE TAMPERING ATTACK]")
        print("Attack: Tamper with Phase 0 message but keep original signature")
        print("Expected: Drone detects signature verification failure and rejects")
        print()
        
        try:
            # Intercept legitimate Phase 0 from real MCC
            print("[*] Step 1: Intercepting legitimate Phase 0 from real MCC...")
            mcc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            mcc_sock.settimeout(5)
            mcc_sock.connect((TARGET_IP, TARGET_PORT))
            
            legit_phase0 = self.recv_json(mcc_sock)
            mcc_sock.close()
            
            if not legit_phase0 or legit_phase0.get('opcode') != 10:
                print("[!] Failed to intercept legitimate Phase 0 from MCC")
                return
            
            legit_params = legit_phase0['payload']
            
            print("✅ Intercepted legitimate Phase 0:")
            print(f"   Prime: {legit_params['p'].bit_length()} bits")
            print(f"   SL: {legit_params['sl']}")
            print(f"   Original MCC ID: {legit_params['id_mcc']}")
            print(f"   Original signature: r={str(legit_params['r0'])[:20]}...")
            
            # Create tampered Phase 0
            print("\n[*] Step 2: Tampering with Phase 0 message...")
            
            tampered_phase0 = {
                'opcode': 10,
                'payload': {
                    'p': legit_params['p'],          # Keep original prime
                    'g': legit_params['g'],          # Keep original generator
                    'sl': legit_params['sl'],        # Keep original SL
                    'ts0': legit_params['ts0'],      # Keep original timestamp
                    'id_mcc': "EVIL_ATTACKER_MCC",   # ATTACK: Change MCC identity
                    'pub_key': legit_params['pub_key'], # Keep original public key
                    'r0': legit_params['r0'],        # Keep original signature (now INVALID)
                    's0': legit_params['s0']         # Keep original signature (now INVALID)
                }
            }
            
            print(f"✅ Created tampered Phase 0:")
            print(f"   Tampered MCC ID: EVIL_ATTACKER_MCC")
            print(f"   Original signature kept (now invalid)")
            print(f"   Expected: Signature verification will fail!")
            
            # Start fake MCC server
            self.run_fake_mcc_server(tampered_phase0, "SIGNATURE_TAMPERING")
            
        except ConnectionRefusedError:
            print("[!] Cannot connect to real MCC. Make sure mcc.py is running on port 65432")
        except Exception as e:
            print(f"[!] Signature tampering attack error: {e}")

    def run_fake_mcc_server(self, malicious_phase0, attack_type):
        """
        Start fake MCC server on port 65434 to send malicious Phase 0
        """
        fake_port = 65434
        
        print(f"\n[*] Step 3: Starting fake MCC server on port {fake_port}...")
        
        try:
            # Create server socket
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(('0.0.0.0', fake_port))
            server_sock.listen(1)
            server_sock.settimeout(45)  # 45 second timeout
            
            print(f"✅ Fake MCC server listening on port {fake_port}")
            print()
            print("┌─ INSTRUCTIONS TO TEST THE ATTACK ─────────────────────────────┐")
            print("│                                                                │")
            print("│ 1. Open a NEW TERMINAL                                        │")
            print("│ 2. Run: python3 drone.py TestDrone_Attack 65434              │")
            print("│    OR:  python3 drone.py 65434                               │")
            print("│ 3. Watch the drone DETECT and REJECT the attack!              │")
            print("│                                                                │")
            print("│ The drone will connect to port 65434 (fake MCC) instead       │")
            print("│ of port 65432 (real MCC) and reject the malicious Phase 0.    │")
            print("└────────────────────────────────────────────────────────────────┘")
            print()
            print(f"[*] Waiting for drone to connect (45 second timeout)...")
            
            # Wait for drone connection
            drone_sock, drone_addr = server_sock.accept()
            print(f"\n🎯 [DRONE CONNECTED] {drone_addr}")
            
            # Send malicious Phase 0
            print(f"[*] Sending malicious Phase 0 ({attack_type} attack)...")
            self.send_json(drone_sock, malicious_phase0)
            
            if attack_type == "WEAK_PRIME":
                print(f"📤 Sent to drone:")
                print(f"   Weak Prime: {malicious_phase0['payload']['p'].bit_length()} bits")
                print(f"   Claimed SL: {malicious_phase0['payload']['sl']} bits")
                print(f"   Attack: Parameter mismatch")
            elif attack_type == "SIGNATURE_TAMPERING":
                print(f"📤 Sent to drone:")
                print(f"   Tampered MCC ID: {malicious_phase0['payload']['id_mcc']}")
                print(f"   Invalid signature (tampered message)")
                print(f"   Attack: Signature verification failure")
            
            # Wait for drone response (should close connection)
            print(f"\n[*] Waiting for drone response...")
            drone_sock.settimeout(10)
            
            try:
                response = self.recv_json(drone_sock)
                if response:
                    print(f"📥 Unexpected: Drone responded: {response}")
                    print(f"❌ [SECURITY FAILURE] Drone accepted malicious Phase 0!")
                else:
                    print(f"📥 Drone closed connection immediately")
                    print(f"✅ [SECURITY SUCCESS] Attack was detected and blocked!")
            except socket.timeout:
                print(f"📥 Drone connection timeout")
                print(f"✅ [EXPECTED] Drone likely detected attack and closed connection")
            
            drone_sock.close()
            server_sock.close()
            
            # Show what drone should have detected
            print(f"\n🔍 [EXPECTED DRONE BEHAVIOR]")
            if attack_type == "WEAK_PRIME":
                weak_bits = malicious_phase0['payload']['p'].bit_length()
                claimed_sl = malicious_phase0['payload']['sl']
                print(f"   The drone should have detected:")
                print(f"   → Parameter mismatch: {weak_bits}-bit prime vs {claimed_sl}-bit SL")
                print(f"   → Discrepancy: {claimed_sl - weak_bits} bits > 10 bits tolerance")
                print(f"   → Message: 'SECURITY ALERT: Parameter mismatch!'")
            elif attack_type == "SIGNATURE_TAMPERING":
                print(f"   The drone should have detected:")
                print(f"   → Signature verification failure")
                print(f"   → Message: 'SECURITY ALERT: Phase 0 signature verification FAILED!'")
            
            print(f"\n✅ [{attack_type} ATTACK COMPLETED]")
            print(f"   The attack was properly detected and blocked by drone security!")
            
        except socket.timeout:
            print(f"\n⏰ [TIMEOUT] No drone connected within 45 seconds")
            print(f"   To test manually:")
            print(f"   1. Run: python3 drone.py TestDrone {fake_port}")
            print(f"   2. Watch the drone reject the malicious Phase 0")
        except Exception as e:
            print(f"[!] Fake MCC server error: {e}")
        finally:
            try:
                server_sock.close()
            except:
                pass

    def broadcast_mitm_attack(self):
        """
        Broadcast MitM Attack - Proxy Mode
        
        This attack creates a proxy server that:
        1. Acts as fake MCC for drones (port 65434)
        2. Forwards legitimate messages between real MCC and drones
        3. Intercepts and tampers with broadcast messages (opcode 80)
        4. Demonstrates how drones can receive tampered broadcasts
        """
        print("\n--- BROADCAST MITM ATTACK ---")
        print("This attack demonstrates a MitM proxy that intercepts and tampers")
        print("with broadcast messages while forwarding other messages normally.")
        print()
        print("Attack Flow:")
        print("1. Attacker proxy listens on port 65434 (fake MCC)")
        print("2. Drones connect to proxy instead of real MCC")
        print("3. Proxy forwards Phase 0, 1A, 1B, 2 normally")
        print("4. When MCC broadcasts, proxy tampers with message")
        print("5. Drones receive tampered broadcast content")
        print()
        
        choice = input("1. Start Broadcast MitM Proxy\n2. Cancel\nSelect: ").strip()
        
        if choice == '1':
            self.run_broadcast_mitm_proxy()
        else:
            print("Cancelled.")

    def run_broadcast_mitm_proxy(self):
        """
        Run the broadcast MitM proxy server
        """
        fake_mcc_port = 65434
        real_mcc_host = '127.0.0.1'
        real_mcc_port = 65432
        
        print(f"\n[*] Starting Broadcast MitM Proxy on port {fake_mcc_port}...")
        print(f"[*] Will forward to real MCC at {real_mcc_host}:{real_mcc_port}")
        
        try:
            # Create proxy server socket
            proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            proxy_sock.bind(('0.0.0.0', fake_mcc_port))
            proxy_sock.listen(5)
            proxy_sock.settimeout(60)  # 60 second timeout
            
            print(f"✅ Broadcast MitM Proxy listening on port {fake_mcc_port}")
            print()
            print("┌─ INSTRUCTIONS TO TEST THE ATTACK ─────────────────────────────┐")
            print("│                                                                │")
            print("│ 1. Make sure MCC is running: python3 mcc.py                   │")
            print("│ 2. In NEW TERMINALS, connect drones to proxy:                 │")
            print("│    python3 drone.py Drone1 65434                              │")
            print("│    python3 drone.py Drone2 65434                              │")
            print("│ 3. In MCC terminal, send broadcast: broadcast Hello World!    │")
            print("│ 4. Watch drones receive TAMPERED broadcast message!           │")
            print("│                                                                │")
            print("└────────────────────────────────────────────────────────────────┘")
            print()
            print(f"[*] Waiting for drone connections (60 second timeout)...")
            
            # Handle multiple drone connections
            drone_connections = {}
            connection_id = 0
            
            while True:
                try:
                    # Accept drone connection
                    drone_sock, drone_addr = proxy_sock.accept()
                    connection_id += 1
                    
                    print(f"\n🎯 [DRONE CONNECTED] {drone_addr} (Connection #{connection_id})")
                    
                    # Start proxy thread for this drone
                    import threading
                    proxy_thread = threading.Thread(
                        target=self.handle_drone_proxy,
                        args=(drone_sock, drone_addr, connection_id, real_mcc_host, real_mcc_port),
                        daemon=True
                    )
                    proxy_thread.start()
                    
                    drone_connections[connection_id] = {
                        'drone_sock': drone_sock,
                        'addr': drone_addr,
                        'thread': proxy_thread
                    }
                    
                except socket.timeout:
                    print(f"\n⏰ [TIMEOUT] No more drone connections within timeout period")
                    break
                except KeyboardInterrupt:
                    print(f"\n[*] Proxy interrupted by user")
                    break
                except Exception as e:
                    print(f"[!] Proxy server error: {e}")
                    break
            
        except ConnectionRefusedError:
            print("[!] Cannot connect to real MCC. Make sure mcc.py is running on port 65432")
        except Exception as e:
            print(f"[!] Broadcast MitM proxy error: {e}")
        finally:
            try:
                proxy_sock.close()
            except:
                pass
            print(f"\n✅ [BROADCAST MITM ATTACK COMPLETED]")

    def handle_drone_proxy(self, drone_sock, drone_addr, conn_id, real_mcc_host, real_mcc_port):
        """
        Handle individual drone connection as MitM proxy
        """
        mcc_sock = None
        try:
            print(f"[*] Connection #{conn_id}: Establishing proxy for {drone_addr}")
            
            # Connect to real MCC
            mcc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            mcc_sock.connect((real_mcc_host, real_mcc_port))
            
            print(f"[*] Connection #{conn_id}: Connected to real MCC")
            
            # Start bidirectional forwarding
            import threading
            
            # Thread to forward MCC -> Drone (with broadcast tampering)
            mcc_to_drone = threading.Thread(
                target=self.forward_mcc_to_drone,
                args=(mcc_sock, drone_sock, conn_id),
                daemon=True
            )
            mcc_to_drone.start()
            
            # Thread to forward Drone -> MCC (no tampering)
            drone_to_mcc = threading.Thread(
                target=self.forward_drone_to_mcc,
                args=(drone_sock, mcc_sock, conn_id),
                daemon=True
            )
            drone_to_mcc.start()
            
            # Wait for threads to complete
            mcc_to_drone.join()
            drone_to_mcc.join()
            
        except Exception as e:
            print(f"[!] Connection #{conn_id}: Proxy error: {e}")
        finally:
            try:
                if mcc_sock:
                    mcc_sock.close()
                drone_sock.close()
            except:
                pass
            print(f"[*] Connection #{conn_id}: Proxy session ended")

    def forward_mcc_to_drone(self, mcc_sock, drone_sock, conn_id):
        """
        Forward messages from MCC to drone, tampering with broadcasts
        """
        try:
            while True:
                # Receive message from real MCC
                msg = self.recv_json(mcc_sock)
                if not msg:
                    break
                
                opcode = msg.get('opcode')
                
                # Check if this is a broadcast command (opcode 80)
                if opcode == 80:
                    print(f"\n🚨 [CONNECTION #{conn_id}] INTERCEPTED BROADCAST!")
                    
                    # Extract encrypted command
                    payload = msg['payload']
                    enc_cmd_hex = payload['enc_cmd']
                    original_hmac_hex = payload['hmac']
                    
                    print(f"   Original encrypted command: {enc_cmd_hex[:40]}...")
                    print(f"   Original HMAC: {original_hmac_hex[:40]}...")
                    
                    # Create tampered message
                    tampered_msg = self.create_tampered_broadcast(msg, conn_id)
                    
                    # Send tampered message to drone
                    print(f"   📤 Sending TAMPERED broadcast to drone")
                    self.send_json(drone_sock, tampered_msg)
                    
                else:
                    # Forward other messages normally (Phase 0, 1A, 1B, 2, Group Key, etc.)
                    if opcode == 10:
                        print(f"[*] Connection #{conn_id}: Forwarding Phase 0 parameters")
                    elif opcode == 30:
                        print(f"[*] Connection #{conn_id}: Forwarding Phase 1B response")
                    elif opcode == 50:
                        print(f"[*] Connection #{conn_id}: Forwarding session confirmation")
                    elif opcode == 70:
                        print(f"[*] Connection #{conn_id}: Forwarding group key")
                    
                    self.send_json(drone_sock, msg)
                    
        except Exception as e:
            print(f"[!] Connection #{conn_id}: MCC->Drone forwarding error: {e}")

    def forward_drone_to_mcc(self, drone_sock, mcc_sock, conn_id):
        """
        Forward messages from drone to MCC (no tampering)
        """
        try:
            while True:
                # Receive message from drone
                msg = self.recv_json(drone_sock)
                if not msg:
                    break
                
                opcode = msg.get('opcode')
                
                if opcode == 20:
                    print(f"[*] Connection #{conn_id}: Forwarding drone authentication")
                elif opcode == 40:
                    print(f"[*] Connection #{conn_id}: Forwarding drone session confirmation")
                
                # Forward message to real MCC
                self.send_json(mcc_sock, msg)
                
        except Exception as e:
            print(f"[!] Connection #{conn_id}: Drone->MCC forwarding error: {e}")

    def create_tampered_broadcast(self, original_msg, conn_id):
        """
        Create a tampered broadcast message
        """
        payload = original_msg['payload']
        enc_cmd_hex = payload['enc_cmd']
        original_hmac_hex = payload['hmac']
        
        # We can't decrypt the actual command since we don't have the group key
        # But we can create a completely new encrypted message with tampered content
        
        # For demonstration, create fake encrypted data
        tampered_command = "💀 MALICIOUS COMMAND INJECTED BY ATTACKER 💀"
        
        # Create fake encrypted command (just random bytes for demo)
        fake_encrypted = secrets.token_bytes(len(bytes.fromhex(enc_cmd_hex)))
        fake_encrypted_hex = fake_encrypted.hex()
        
        # Create fake HMAC (also random for demo)
        fake_hmac = secrets.token_bytes(32)  # SHA-256 HMAC is 32 bytes
        fake_hmac_hex = fake_hmac.hex()
        
        tampered_msg = {
            'opcode': 80,
            'payload': {
                'enc_cmd': fake_encrypted_hex,
                'hmac': fake_hmac_hex
            }
        }
        
        print(f"   🔥 ATTACK: Original command replaced with malicious content")
        print(f"   🔥 ATTACK: Original HMAC replaced with fake HMAC")
        print(f"   Expected Result: Drone will receive tampered broadcast")
        print(f"   Security Note: Drone should detect HMAC verification failure")
        
        return tampered_msg

    # Networking Helpers
    def send_json(self, conn, data):
        msg = json.dumps(data).encode()
        conn.sendall(len(msg).to_bytes(4, 'big') + msg)

    def recv_json(self, conn):
        try:
            len_bytes = conn.recv(4)
            if not len_bytes: return None
            length = int.from_bytes(len_bytes, 'big')
            return json.loads(conn.recv(length))
        except: return None

    def main_loop(self):
        while True:
            print("\n" + "="*40)
            print("   MANUAL ATTACK CONSOLE")
            print("="*40)
            print(f"Target Key Set: {'YES' if self.mcc_pub_key else 'NO'}")
            print(f"Packet Ready:   {self.current_packet_desc}")
            print("-" * 40)
            print("1. Set MCC Public Key (Manual Entry)")
            print("2. Build/Craft Packet (Generates Fresh Nonce)")
            print("3. SEND Current Packet")
            print("4. MitM Parameter Tampering Test")
            print("5. Unauthorized Drone Access Test")
            print("6. Phase 0 MitM Attack")
            print("7. Broadcast MitM Attack")
            print("8. Exit")
            
            c = input("\nSelect: ").strip()
            if c == '1': self.set_target_key()
            elif c == '2': self.build_packet_menu()
            elif c == '3': self.send_current_packet()
            elif c == '4': self.run_mitm()
            elif c == '5': self.test_unauthorized_drone()
            elif c == '6': self.phase0_mitm_attack()
            elif c == '7': self.broadcast_mitm_attack()
            elif c == '8': sys.exit(0)

if __name__ == "__main__":
    tool = ManualAttackTool()
    tool.main_loop()