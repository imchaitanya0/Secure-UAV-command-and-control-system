import socket
import json
import time
import secrets
import sys
import hmac
import crypto_utils as cu

MCC_IP = '127.0.0.1'
MCC_PORT = 65432

class DroneClient:
    def __init__(self, drone_id):
        self.drone_id = drone_id
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sk = None # Session Key
        self.gk = None # Group Key
        self.running = True

    def connect(self):
        try:
            self.sock.connect((MCC_IP, MCC_PORT))
            print(f"[*] Connected to MCC at {MCC_IP}:{MCC_PORT}")
            self.protocol_handshake()
            self.listen_for_commands()
        except Exception as e:
            print(f"[!] Connection Error: {e}")
        finally:
            self.sock.close()

    def send_json(self, data):
        msg = json.dumps(data).encode()
        self.sock.sendall(len(msg).to_bytes(4, 'big') + msg)

    def recv_json(self):
        try:
            len_bytes = self.sock.recv(4)
            if not len_bytes: return None
            length = int.from_bytes(len_bytes, 'big')
            data = b''
            while len(data) < length:
                chunk = self.sock.recv(min(length - len(data), 4096))
                if not chunk: break
                data += chunk
            return json.loads(data)
        except: return None

    def protocol_handshake(self):
        # --- PHASE 0: RECEIVE PARAMETERS ---
        print("[*] Waiting for Phase 0 Parameters...")
        msg = self.recv_json()
        if not msg: 
            print("[!] Failed Phase 0")
            return
        
        params = msg['payload']
        p = params['p']
        g = params['g']
        mcc_pub_key = params.get('pub_key') # Automatically fetch MCC Key

        print(f"[*] Parameters Received. MCC Public Key found: {mcc_pub_key is not None}")

        # Generate Own Keys
        priv_key, pub_key = cu.elgamal_keygen(p, g)
        
        # --- PHASE 1A: AUTH REQUEST ---
        print("[*] Starting Phase 1A (Auth Request)...")
        k_dm = secrets.randbelow(2**256)
        rn_d = secrets.randbelow(2**256)
        ts_d = int(time.time())
        
        # Encrypt K_Dm using MCC's Public Key
        c1, c2 = cu.elgamal_encrypt(k_dm, p, g, mcc_pub_key)
        
        # Sign the packet
        sig_msg = f"{ts_d}{rn_d}{self.drone_id}{c1}{c2}".encode()
        r, s = cu.elgamal_sign(sig_msg, priv_key, p, g)
        
        payload = {
            'drone_id': self.drone_id, 
            'ts': ts_d, 
            'rn': rn_d,
            'c1': c1, 'c2': c2, 
            'r': r, 's': s, 
            'pub_key': pub_key # Sending my PubKey to MCC
        }
        self.send_json({'opcode': 20, 'payload': payload})
        print("[*] Phase 1A Sent.")

        # --- PHASE 1B: RECEIVE RESPONSE ---
        msg = self.recv_json()
        if not msg: return
        
        resp = msg['payload']
        ts_mcc, rn_mcc = resp['ts'], resp['rn']
        c1_mcc, c2_mcc = resp['c1'], resp['c2']
        r_mcc, s_mcc = resp['r'], resp['s']
        
        # Verify MCC Signature
        sig_msg_mcc = f"{ts_mcc}{rn_mcc}{params['id_mcc']}{c1_mcc}{c2_mcc}".encode()
        if not cu.elgamal_verify(sig_msg_mcc, r_mcc, s_mcc, mcc_pub_key, p, g):
            print("[!] MCC Signature Verification Failed!")
            return
            
        # Decrypt to verify K_Dm match
        k_dec = cu.elgamal_decrypt(c1_mcc, c2_mcc, priv_key, p)
        if k_dec != k_dm:
            print("[!] Key Mismatch! Proof of Decryption failed.")
            return
        
        print("[*] Phase 1B Verified. Mutual Auth Success.")
        
        # --- PHASE 2: SESSION KEY ---
        self.sk = cu.derive_session_key(k_dm, ts_d, ts_mcc, rn_d, rn_mcc)
        
        ts_final = int(time.time())
        my_hmac = cu.compute_hmac(self.sk, f"{self.drone_id}{ts_final}")
        
        # Send Confirmation (Opcode 40)
        self.send_json({
            'opcode': 40, 
            'payload': {'ts_final': ts_final, 'hmac': my_hmac.hex()}
        })
        
        # Wait for Opcode 50 (Success)
        msg = self.recv_json()
        if msg and msg['opcode'] == 50:
            print("[+] Session Established. Waiting for commands...")
        else:
            print("[!] Handshake Failed at final step.")
            self.running = False

    def listen_for_commands(self):
        while self.running:
            msg = self.recv_json()
            if not msg: break
            
            opcode = msg['opcode']
            
            if opcode == 70: # Group Key Received
                enc_gk = bytes.fromhex(msg['payload']['enc_gk'])
                self.gk = cu.aes_decrypt(self.sk, enc_gk)
                print(f"[*] Group Key Received and Decrypted.")
                
            elif opcode == 80: # Encrypted Command
                if not self.gk:
                    print("[!] No Group Key available to decrypt command.")
                    continue
                    
                payload = msg['payload']
                enc_cmd = bytes.fromhex(payload['enc_cmd'])
                # (Optional) Verify HMAC of command here for extra security
                
                cmd = cu.aes_decrypt(self.gk, enc_cmd).decode()
                print(f"[CMD] EXECUTING: {cmd}")

if __name__ == "__main__":
    # Generate random ID if not provided
    did = sys.argv[1] if len(sys.argv) > 1 else f"Drone_{secrets.randbelow(999)}"
    client = DroneClient(did)
    client.connect()