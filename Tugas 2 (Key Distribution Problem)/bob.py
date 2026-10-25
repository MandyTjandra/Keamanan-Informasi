# bob.py - Node Bob
import socket
import json
import threading
import random
import sys
from aes import aes_encrypt, aes_decrypt

SESSION_KEY = None
MASTER_KB = None
RUNNING = True
PENDING_REKEY = {}

def handle_socket_messages(conn):
    global SESSION_KEY, RUNNING, MASTER_KB, PENDING_REKEY
    buffer = ""

    while RUNNING:
        try:
            data = conn.recv(4096).decode('utf-8')
            if not data:
                print("\n[-] Koneksi ditutup oleh Alice.")
                RUNNING = False
                break
            
            buffer += data
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if not line.strip():
                    continue
                
                packet = json.loads(line)
                pkt_type = packet.get("type")

                # Langkah 3 (Rekeying dari Alice)
                if pkt_type == "rekey_step3":
                    ticket_b_hex = packet["ticket_b"]
                    ticket_json = json.loads(aes_decrypt(ticket_b_hex, MASTER_KB))
                    new_ks = ticket_json["ks"]

                    n2 = random.randint(100000, 999999)
                    PENDING_REKEY = {"new_ks": new_ks, "expected_fn2": n2 - 1}
                    challenge_hex = aes_encrypt(str(n2), new_ks)
                    
                    conn.sendall((json.dumps({"type": "rekey_step4", "challenge": challenge_hex}) + "\n").encode('utf-8'))

                # Langkah 5 (Respon Rekeying dari Alice)
                elif pkt_type == "rekey_step5":
                    rec_fn2 = int(aes_decrypt(packet["response"], PENDING_REKEY["new_ks"]))
                    if rec_fn2 == PENDING_REKEY["expected_fn2"]:
                        SESSION_KEY = PENDING_REKEY["new_ks"]
                        conn.sendall((json.dumps({"type": "rekey_success"}) + "\n").encode('utf-8'))
                        print(f"\n\n[+] [REKEY SUKSES] Session Key diperbarui via KDC: '{SESSION_KEY}'")
                    print("Bob > ", end="", flush=True)

                # Pergantian manual
                elif pkt_type == "set_session_key":
                    SESSION_KEY = packet["new_key"]
                    print(f"\n\n[+] [MANUAL KEY] Kunci sesi diubah menjadi: '{SESSION_KEY}'")
                    print("Bob > ", end="", flush=True)

                # Pesan chat biasa
                elif pkt_type == "chat":
                    ct_hex = packet["ciphertext_hex"]
                    pt = aes_decrypt(ct_hex, SESSION_KEY)
                    print(f"\n[Alice (Hex)]: {ct_hex}")
                    print(f"[Alice (Teks)]: {pt}")
                    print("Bob > ", end="", flush=True)

        except Exception as e:
            if RUNNING:
                print(f"\n[-] Error receive: {e}")
            break

def run_bob():
    global SESSION_KEY, MASTER_KB, RUNNING
    print("=" * 50)
    print("                   NODE: BOB                      ")
    print("=" * 50)

    port = int(input("Port Bob [Default 9002]: ").strip() or 9002)
    MASTER_KB = input("Master Key Bob (Kb) [Default: MasterBobKey1234]: ").strip() or "MasterBobKey1234"

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(1)
    print(f"\n[+] Bob standby di port {port}. Menunggu koneksi Alice...")

    conn, addr = server.accept()
    print(f"[+] Alice terhubung dari {addr[0]}:{addr[1]}")

    line = ""
    while "\n" not in line:
        line += conn.recv(4096).decode('utf-8')
    data_step3 = json.loads(line.strip())

    print("\n[LANGKAH 3 DITERIMA] Membaca Ticket B...")
    ticket_b_hex = data_step3["ticket_b"]
    ticket_json = json.loads(aes_decrypt(ticket_b_hex, MASTER_KB))
    SESSION_KEY = ticket_json["ks"]
    print(f"[+] Handshake Sukses! Partner: {ticket_json['id_a']}, Ks: '{SESSION_KEY}'")

    n2 = random.randint(100000, 999999)
    challenge_hex = aes_encrypt(str(n2), SESSION_KEY)
    conn.sendall((json.dumps({"type": "step4", "challenge": challenge_hex}) + "\n").encode('utf-8'))

    line5 = ""
    while "\n" not in line5:
        line5 += conn.recv(4096).decode('utf-8')
    data_step5 = json.loads(line5.strip())
    rec_fn2 = int(aes_decrypt(data_step5["response"], SESSION_KEY))

    if rec_fn2 == n2 - 1:
        conn.sendall((json.dumps({"type": "auth_ok"}) + "\n").encode('utf-8'))
        print("[+] MUTUAL AUTHENTICATION SUKSES DENGAN ALICE!")
    else:
        print("[-] Autentikasi Gagal! Nonce tidak valid.")
        conn.close()
        return

    print("\n" + "=" * 50)
    print("     SECURE AES-128 BIDIRECTIONAL CHAT DIMULAI     ")
    print(" Perintah: /setkey <kunci>, /exit")
    print("=" * 50)

    t_recv = threading.Thread(target=handle_socket_messages, args=(conn,), daemon=True)
    t_recv.start()

    while RUNNING:
        try:
            msg = input("Bob > ")
            if not msg.strip():
                continue
            if msg.strip() == "/exit":
                RUNNING = False
                conn.close()
                break

            if msg.startswith("/setkey "):
                new_key = msg.split(" ", 1)[1].strip()
                SESSION_KEY = new_key
                conn.sendall((json.dumps({"type": "set_session_key", "new_key": new_key}) + "\n").encode('utf-8'))
                print(f"[+] Kunci sesi diubah manual ke: '{SESSION_KEY}'")
                continue

            ct_hex = aes_encrypt(msg, SESSION_KEY)
            packet = {"type": "chat", "ciphertext_hex": ct_hex}
            conn.sendall((json.dumps(packet) + "\n").encode('utf-8'))
            print(f" -> Terkirim (Hex AES): {ct_hex}")
        except (KeyboardInterrupt, EOFError):
            RUNNING = False
            break

    server.close()

if __name__ == "__main__":
    run_bob()