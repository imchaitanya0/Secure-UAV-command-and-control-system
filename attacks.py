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
        print("\n--- MITM PARAMETER TEST ---")
        val = input("Enter Weak Prime (e.g. 23): ").strip()
        if not val: val = "23"
        
        bits = len(bin(int(val))) - 2
        print(f"Bit length: {bits}")
        if bits < 2048:
            print("[SUCCESS] Drone would REJECT this (Security Level Mismatch).")
        else:
            print("[FAIL] Drone would ACCEPT this.")

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
            print("4. MitM Test")
            print("5. Exit")
            
            c = input("\nSelect: ").strip()
            if c == '1': self.set_target_key()
            elif c == '2': self.build_packet_menu()
            elif c == '3': self.send_current_packet()
            elif c == '4': self.run_mitm()
            elif c == '5': sys.exit(0)

if __name__ == "__main__":
    tool = ManualAttackTool()
    tool.main_loop()