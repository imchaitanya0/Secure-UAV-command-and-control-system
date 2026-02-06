import socket
import threading
import json
import time
import secrets
import sys
import hashlib
import hmac
import crypto_utils as cu

# Configuration
HOST = '0.0.0.0'
PORT = 65432
SL = 2048

class MCCServer:
    def __init__(self):
        print(f"[*] Initializing MCC... Generating {SL}-bit parameters.")
        # Load parameters (Phase 0 logic)
        self.p, self.g = cu.get_standard_safe_prime()
        self.priv_key, self.pub_key = cu.elgamal_keygen(self.p, self.g)
        self.mcc_id = "MCC_MAIN_HQ"
        
        # Security State
        self.fleet = {}
        self.seen_nonces = set() # Stores (drone_id, rn) to prevent Replay Attacks
        self.lock = threading.Lock()
        self.running = True

        print(f"[*] MCC Ready.")
        print("-" * 60)
        print("COPY THIS PUBLIC KEY FOR ATTACKS.PY:")
        print(self.pub_key)
        print("-" * 60)

    def start(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Allow immediate restart of the server
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_sock.bind((HOST, PORT))
            server_sock.listen(5)
            print(f"[*] Listening on {HOST}:{PORT}")
        except Exception as e:
            print(f"[!] Critical Error binding port: {e}")
            return

        threading.Thread(target=self.cli_interface, daemon=True).start()

        while self.running:
            try:
                client_sock, addr = server_sock.accept()
                threading.Thread(target=self.handle_drone, args=(client_sock, addr), daemon=True).start()
            except OSError:
                break
            except Exception as e:
                print(f"[!] Accept Error: {e}")

    def cli_interface(self):
        time.sleep(1)
        print("\n--- MCC COMMAND CONSOLE ---")
        print("Commands: list, broadcast <msg>, shutdown")
        
        while self.running:
            try:
                cmd_raw = input("MCC> ").strip()
            except EOFError:
                break
            except Exception:
                continue
                
            parts = cmd_raw.split(' ', 1)
            cmd = parts[0].lower()

            if cmd == 'list':
                with self.lock:
                    # Check connection status for all drones
                    active_count = 0
                    dead_drones = []
                    
                    for did, data in self.fleet.items():
                        try:
                            # Test if socket is still alive
                            data['socket'].getpeername()
                            data['status'] = 'ACTIVE'
                            active_count += 1
                        except:
                            data['status'] = 'DISCONNECTED'
                            dead_drones.append(did)
                    
                    print(f"\nTotal Drones: {len(self.fleet)} (Active: {active_count}, Disconnected: {len(dead_drones)})")
                    for did, data in self.fleet.items():
                        status_marker = "✓" if data['status'] == 'ACTIVE' else "✗"
                        print(f" {status_marker} {did} [{data['status']}]")
                    
                    # Optionally auto-remove disconnected drones
                    if dead_drones:
                        print(f"\n[!] Found {len(dead_drones)} disconnected drone(s).")
                        # Uncomment next lines to auto-remove:
                        # for did in dead_drones:
                        #     del self.fleet[did]
                        # print(f"[*] Removed disconnected drones.")
            
            elif cmd == 'broadcast':
                if len(parts) < 2:
                    print("Usage: broadcast <message>")
                    continue
                self.perform_broadcast(parts[1])
                
            elif cmd == 'shutdown':
                print("[*] Shutting down MCC...")
                # Send shutdown notification to all drones
                with self.lock:
                    shutdown_msg = {'opcode': 90, 'payload': 'SHUTDOWN'}
                    for did, drone_data in list(self.fleet.items()):
                        try:
                            self.send_json(drone_data['socket'], shutdown_msg)
                            print(f"[*] Sent shutdown notification to {did}")
                        except Exception as e:
                            print(f"[!] Failed to notify {did}: {e}")
                    print("[*] All drones notified. Shutting down...")
                self.running = False
                sys.exit(0)

    def handle_drone(self, conn, addr):
        drone_id = "Unknown"
        try:
            # --- PHASE 0 ---
            ts0 = int(time.time())
            params = {
                'p': self.p, 'g': self.g, 'sl': SL,
                'ts': ts0, 'id_mcc': self.mcc_id,
                'pub_key': self.pub_key 
            }
            self.send_json(conn, {'opcode': 10, 'payload': params})

            # --- PHASE 1A ---
            data = self.recv_json(conn)
            if not data or data['opcode'] != 20:
                conn.close()
                return

            payload = data['payload']
            drone_id = payload['drone_id']
            ts_d = payload['ts']
            rn_d = payload['rn']
            c1, c2 = payload['c1'], payload['c2'] 
            sig_r, sig_s = payload['r'], payload['s']
            drone_pub_key = payload['pub_key']

            # --- SECURITY CHECKS (Freshness & Replay) ---
            # 1. Check Timestamp Window (e.g., 60 seconds)
            if abs(time.time() - ts_d) > 60:
                print(f"[!] SECURITY ALERT: Stale Timestamp from {drone_id}. Possible Replay.")
                conn.close()
                return

            # 2. Check Nonce Cache
            # Note: In a production system, we would clean up old nonces. 
            # For this lab, the set grows indefinitely which is fine for demonstration.
            if (drone_id, rn_d) in self.seen_nonces:
                print(f"[!] SECURITY ALERT: Replay Attack Detected! Nonce {rn_d} already used by {drone_id}.")
                conn.close()
                return
            
            # Add to cache
            self.seen_nonces.add((drone_id, rn_d))
            
            # --- AUTH LOGIC ---
            sig_msg = f"{ts_d}{rn_d}{drone_id}{c1}{c2}".encode()
            
            if not cu.elgamal_verify(sig_msg, sig_r, sig_s, drone_pub_key, self.p, self.g):
                print(f"[!] Signature Verification Failed for {drone_id}")
                conn.close()
                return
            
            k_dm = cu.elgamal_decrypt(c1, c2, self.priv_key, self.p)

            # --- PHASE 1B ---
            ts_mcc = int(time.time())
            rn_mcc = secrets.randbelow(2**256)
            c_mcc_1, c_mcc_2 = cu.elgamal_encrypt(k_dm, self.p, self.g, drone_pub_key)
            
            resp_sig_msg = f"{ts_mcc}{rn_mcc}{self.mcc_id}{c_mcc_1}{c_mcc_2}".encode()
            r_mcc, s_mcc = cu.elgamal_sign(resp_sig_msg, self.priv_key, self.p, self.g)
            
            resp_payload = {
                'ts': ts_mcc, 'rn': rn_mcc, 'id_mcc': self.mcc_id,
                'c1': c_mcc_1, 'c2': c_mcc_2, 'r': r_mcc, 's': s_mcc
            }
            self.send_json(conn, {'opcode': 30, 'payload': resp_payload})

            # --- PHASE 2 ---
            sk = cu.derive_session_key(k_dm, ts_d, ts_mcc, rn_d, rn_mcc)
            data = self.recv_json(conn)
            if not data or data['opcode'] != 40:
                conn.close()
                return
            
            hmac_received = bytes.fromhex(data['payload']['hmac'])
            ts_final = data['payload']['ts_final']
            
            expected_hmac = cu.compute_hmac(sk, f"{drone_id}{ts_final}")
            
            if hmac.compare_digest(hmac_received, expected_hmac):
                self.send_json(conn, {'opcode': 50, 'payload': 'CONFIRM'})
                with self.lock:
                    self.fleet[drone_id] = {'socket': conn, 'sk': sk, 'status': 'ACTIVE'}
                print(f"[+] Drone {drone_id} Authenticated Successfully.")
            else:
                self.send_json(conn, {'opcode': 60, 'payload': 'MISMATCH'})
                print(f"[!] Drone {drone_id} HMAC Mismatch.")
                conn.close()

        except Exception as e:
            print(f"[!] Error handling {drone_id}: {e}")
            conn.close()

    def perform_broadcast(self, cmd_text):
        # with self.lock:
        #     if not self.fleet:
        #         print("[!] No active drones.")
        #         return
        with self.lock:
        # Remove dead connections
            dead_drones = []
            for did, drone_data in self.fleet.items():
                try:
                    # Test if socket is still alive
                    drone_data['socket'].getpeername()
                except:
                    dead_drones.append(did)
            
            for did in dead_drones:
                del self.fleet[did]
                print(f"[*] Removed disconnected drone: {did}")

                
            print(f"[*] Broadcasting: '{cmd_text}' to {len(self.fleet)} drones.")
            # Compute Group Key: GK = H(SK_D1 || SK_D2 || ... || SK_Dn || KR_MCC)
            hasher = hashlib.sha256()
            for did in sorted(self.fleet.keys()):
                hasher.update(self.fleet[did]['sk'])
            # Use consistent byte encoding for private key
            priv_key_bytes = self.priv_key.to_bytes((self.priv_key.bit_length() + 7) // 8, byteorder='big')
            hasher.update(priv_key_bytes)
            gk = hasher.digest()
            
            enc_cmd = cu.aes_encrypt(gk, cmd_text.encode())
            cmd_hmac = cu.compute_hmac(gk, enc_cmd.hex())
            cmd_msg = {'opcode': 80, 'payload': {'enc_cmd': enc_cmd.hex(), 'hmac': cmd_hmac.hex()}}
            
            for did, drone_data in self.fleet.items():
                try:
                    enc_gk = cu.aes_encrypt(drone_data['sk'], gk)
                    self.send_json(drone_data['socket'], {'opcode': 70, 'payload': {'enc_gk': enc_gk.hex()}})
                    self.send_json(drone_data['socket'], cmd_msg)
                except Exception as e:
                    print(f"Failed to send to {did}")
            print("[+] Broadcast Complete.")

    def send_json(self, conn, data):
        msg = json.dumps(data).encode()
        conn.sendall(len(msg).to_bytes(4, 'big') + msg)

    def recv_json(self, conn):
        try:
            len_bytes = conn.recv(4)
            if not len_bytes: return None
            length = int.from_bytes(len_bytes, 'big')
            data = b''
            while len(data) < length:
                chunk = conn.recv(min(length - len(data), 4096))
                if not chunk: break
                data += chunk
            return json.loads(data)
        except: return None

if __name__ == "__main__":
    server = MCCServer()
    server.start()