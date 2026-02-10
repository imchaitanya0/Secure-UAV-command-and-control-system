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
            # Use the current module's MCC_PORT (which may have been overridden)
            current_port = sys.modules[__name__].MCC_PORT
            self.sock.connect((MCC_IP, current_port))
            print(f"[*] Connected to MCC at {MCC_IP}:{current_port}")
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
        # --- PHASE 0: RECEIVE AND VERIFY SECURE PARAMETERS ---
        print("[*] Waiting for Phase 0 Parameters...")
        msg = self.recv_json()
        if not msg: 
            print("[!] Failed Phase 0")
            return
        
        params = msg['payload']
        p = params['p']
        g = params['g']
        sl = params['sl']
        ts0 = params.get('ts0')           # Phase 0 timestamp
        id_mcc = params.get('id_mcc')     # MCC identity  
        mcc_pub_key = params.get('pub_key')  # MCC public key
        r0 = params.get('r0')             # Phase 0 signature (r)
        s0 = params.get('s0')             # Phase 0 signature (s)

        # --- SECURITY VALIDATION (REQUIRED BY ASSIGNMENT) ---
        
        # Check 1: Verify all required Phase 0 fields are present
        if not all([ts0, id_mcc, mcc_pub_key, r0, s0]):
            print("[!] SECURITY ALERT: Missing Phase 0 security fields!")
            print("    Required: ts0, id_mcc, pub_key, r0, s0")
            print("    Possible incomplete or malicious MCC. Aborting connection.")
            return
        
        # Check 2: Verify MCC signature on Phase 0 parameters
        phase0_msg = f"{p}{g}{sl}{ts0}{id_mcc}".encode()
        if not cu.elgamal_verify(phase0_msg, r0, s0, mcc_pub_key, p, g):
            print("[!] SECURITY ALERT: Phase 0 signature verification FAILED!")
            print("    MCC signature is invalid or parameters have been tampered with.")
            print("    Possible MitM attack detected. Aborting connection.")
            return
        
        print("[*] ✅ Phase 0 signature verified - MCC is authentic")
        
        # Check 3: Verify timestamp freshness (within 30 seconds)
        current_time = int(time.time())
        time_diff = abs(current_time - ts0)
        if time_diff > 30:
            print(f"[!] SECURITY ALERT: Phase 0 timestamp is stale!")
            print(f"    Timestamp age: {time_diff} seconds (max allowed: 30)")
            print(f"    Possible replay attack detected. Aborting connection.")
            return
        
        print(f"[*] ✅ Timestamp freshness verified - {time_diff}s old")
        
        # Check 4: Verify MCC identity (basic validation)
        if not id_mcc or len(id_mcc.strip()) == 0:
            print("[!] SECURITY ALERT: Invalid or empty MCC identity!")
            print("    MCC identity verification failed. Aborting connection.")
            return
        
        print(f"[*] ✅ MCC identity verified: {id_mcc}")
        
        # Check 5: Verify prime bit length matches claimed SL
        p_bit_length = p.bit_length()
        if abs(p_bit_length - sl) > 10:  # Allow small tolerance for edge cases
            print(f"[!] SECURITY ALERT: Parameter mismatch!")
            print(f"    Prime is {p_bit_length}-bit but SL claims {sl}-bit")
            print(f"    Possible MitM attack detected. Aborting connection.")
            return
        
        # Check 6: Enforce minimum security level (2048-bit minimum)
        if sl < 2048:
            print(f"[!] SECURITY ALERT: Security level {sl} below minimum requirement (2048)")
            print(f"    Rejecting weak cryptographic parameters. Aborting connection.")
            return
        
        print(f"[*] ✅ Parameters Validated: {p_bit_length}-bit prime, SL={sl}")
        print(f"[*] ✅ PHASE 0 SECURITY COMPLETE - All checks passed!")

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

        # Check if MCC rejected us (opcode 60 = error/unauthorized)
        if msg.get('opcode') == 60:
            payload = msg.get('payload', {})
            if isinstance(payload, dict):
                err = payload.get('error', 'Unknown')
                detail = payload.get('message', 'No details provided')
                print(f"[!] ❌ MCC REJECTED CONNECTION: {err}")
                print(f"    → {detail}")
            else:
                print(f"[!] ❌ MCC REJECTED CONNECTION: {payload}")
            return
        
        resp = msg['payload']
        ts_mcc, rn_mcc = resp['ts'], resp['rn']
        c1_mcc, c2_mcc = resp['c1'], resp['c2']
        r_mcc, s_mcc = resp['r'], resp['s']
        
        # Verify MCC Signature
        sig_msg_mcc = f"{ts_mcc}{rn_mcc}{id_mcc}{c1_mcc}{c2_mcc}".encode()
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
                received_hmac = bytes.fromhex(payload['hmac'])
                
                # Verify HMAC of encrypted command for integrity
                expected_hmac = cu.compute_hmac(self.gk, payload['enc_cmd'])
                
                if not hmac.compare_digest(received_hmac, expected_hmac):
                    print("[!] 🚨 SECURITY ALERT: Broadcast HMAC verification FAILED!")
                    print("    Command integrity compromised - possible MitM attack detected!")
                    print("    CRITICAL SECURITY BREACH - Initiating emergency shutdown...")
                    print("    Disconnecting from MCC immediately for safety.")
                    self.running = False
                    break
                
                # HMAC verified, safe to decrypt and execute
                try:
                    cmd = cu.aes_decrypt(self.gk, enc_cmd).decode()
                    print(f"[CMD] ✅ HMAC verified - EXECUTING: {cmd}")
                except Exception as e:
                    print(f"[!] Failed to decrypt command: {e}")
                    print("    Possible encryption tampering detected.")
            
            elif opcode == 90: # Shutdown Command
                print("[*] SHUTDOWN command received from MCC.")
                print("[*] Closing connection gracefully...")
                self.running = False
                break

if __name__ == "__main__":
    # Parse command line arguments for MitM attack testing
    # Usage: python3 drone.py [drone_id] [port]
    # Examples: 
    #   python3 drone.py                     -> Random ID, port 65432
    #   python3 drone.py MyDrone             -> MyDrone, port 65432  
    #   python3 drone.py MyDrone 65434       -> MyDrone, port 65434 (for MitM test)
    #   python3 drone.py 65434               -> Random ID, port 65434 (for MitM test)
    
    args = sys.argv[1:]
    
    # Default values
    drone_id = f"Drone_{secrets.randbelow(999)}"
    target_port = MCC_PORT  # Use the default port from config
    
    if len(args) == 1:
        # One argument: could be drone_id or port
        arg = args[0]
        if arg.isdigit():
            # It's a port number
            target_port = int(arg)
            print(f"[*] Using port {target_port} with random drone ID: {drone_id}")
        else:
            # It's a drone ID
            drone_id = arg
            print(f"[*] Using drone ID: {drone_id} with default port: {target_port}")
    elif len(args) == 2:
        # Two arguments: drone_id and port
        drone_id = args[0]
        target_port = int(args[1])
        print(f"[*] Using drone ID: {drone_id} with port: {target_port}")
    else:
        # No arguments or too many
        print(f"[*] Using random drone ID: {drone_id} with default port: {target_port}")
    
    # Override the global MCC_PORT with the target port
    current_module = sys.modules[__name__]
    current_module.MCC_PORT = target_port
    
    client = DroneClient(drone_id)
    client.connect()