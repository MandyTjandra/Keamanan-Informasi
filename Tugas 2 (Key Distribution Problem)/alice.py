# alice.py - Node Alice
import socket
import json
import threading
import random
import sys
from aes import aes_encrypt, aes_decrypt

SESSION_KEY = None
MASTER_KA = None
KDC_HOST = None
KDC_PORT = None
RUNNING = True
TEMP_KS = None

def request_kdc_ticket():
    s_kdc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_kdc.connect((KDC_HOST, KDC_PORT))

    nonce1 = random.randint(100000, 999999)
    req = {"step": 1, "id_a": "Alice", "id_b": "Bob", "nonce1": nonce1}
    s_kdc.sendall((json.dumps(req) + "\n").encode('utf-8'))

    raw = s_kdc.recv(4096).decode('utf-8')
    s_kdc.close()

    resp = json.loads(raw.strip())
    dec = aes_decrypt(resp["encrypted_payload"], MASTER_KA)
    payload = json.loads(dec)

    if payload["nonce1"] != nonce1:
        raise ValueError("Nonce1 tidak cocok! Replay attack terdeteksi.")

    return payload["ks"], payload["ticket_b"]

def handle_socket_messages(conn):
    global SESSION_KEY, TEMP_KS, RUNNING
    buffer = ""

    while RUNNING:
        try:
            data = conn.recv(4096).decode('utf-8')
            if not data:
                print("\n[-] Koneksi ditutup oleh Bob.")
                RUNNING = False
                break

            buffer += data
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if not line.strip():
                    continue

                packet = json.loads(line)
                pkt_type = packet.get("type")

                # Langkah 4 Rekeying: Terima Challenge N2 dari Bob
                if pkt_type == "rekey_step4":
                    challenge_hex = packet["challenge"]
                    n2 = int(aes_decrypt(challenge_hex, TEMP_KS))
                    resp_hex = aes_encrypt(str(n2 - 1), TEMP_KS)
                    conn.sendall((json.dumps({"type": "rekey_step5", "response": resp_hex}) + "\n").encode('utf-8'))

                # Akhir Rekeying: Konfirmasi Bob
                elif pkt_type == "rekey_success":
                    SESSION_KEY = TEMP_KS
                    print(f"\n\n[+] [REKEY SUKSES] Kunci sesi aktif sekarang: '{SESSION_KEY}'")
                    print("Alice > ", end="", flush=True)

                elif pkt_type == "set_session_key":
                    SESSION_KEY = packet["new_key"]
                    print(f"\n\n[+] [MANUAL KEY] Kunci sesi diubah menjadi: '{SESSION_KEY}'")
                    print("Alice > ", end="", flush=True)

                elif pkt_type == "chat":
                    ct_hex = packet["ciphertext_hex"]
                    pt = aes_decrypt(ct_hex, SESSION_KEY)
                    print(f"\n[Bob (Hex)]: {ct_hex}")
                    print(f"[Bob (Teks)]: {pt}")
                    print("Alice > ", end="", flush=True)

        except Exception as e:
            if RUNNING:
                print(f"\n[-] Error receive: {e}")
            break

def run_alice():
    global SESSION_KEY, TEMP_KS, MASTER_KA, KDC_HOST, KDC_PORT, RUNNING
    print("=" * 50)
    print("                  NODE: ALICE                     ")
    print("=" * 50)

    KDC_HOST = input("IP KDC [Default 172.20.0.10]: ").strip() or "172.20.0.10"
    KDC_PORT = int(input("Port KDC [Default 8000]: ").strip() or 8000)
    bob_host = input("IP Bob [Default 172.20.0.30]: ").strip() or "172.20.0.30"
    bob_port = int(input("Port Bob [Default 9002]: ").strip() or 9002)
    MASTER_KA = input("Master Key Alice (Ka) [Default: MasterAliceKey12]: ").strip() or "MasterAliceKey12"

    print("\n[*] Menghubungi KDC...")
    SESSION_KEY, ticket_b = request_kdc_ticket()
    print(f"[+] Handshake KDC Berhasil! Ks didapatkan: '{SESSION_KEY}'")

    print(f"[*] Menghubungi Bob di {bob_host}:{bob_port}...")
    bob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob_sock.connect((bob_host, bob_port))

    # Langkah 3
    bob_sock.sendall((json.dumps({"type": "step3", "ticket_b": ticket_b}) + "\n").encode('utf-8'))

    # Langkah 4
    step4_raw = bob_sock.recv(4096).decode('utf-8').strip()
    n2 = int(aes_decrypt(json.loads(step4_raw)["challenge"], SESSION_KEY))

    # Langkah 5
    resp_hex = aes_encrypt(str(n2 - 1), SESSION_KEY)
    bob_sock.sendall((json.dumps({"type": "step5", "response": resp_hex}) + "\n").encode('utf-8'))

    ack = json.loads(bob_sock.recv(4096).decode('utf-8').strip())
    if ack.get("type") == "auth_ok":
        print("[+] MUTUAL AUTHENTICATION SUKSES DENGAN BOB!")
    else:
        print("[-] Autentikasi ditolak.")
        bob_sock.close()
        return

    print("\n" + "=" * 50)
    print("     SECURE AES-128 BIDIRECTIONAL CHAT DIMULAI     ")
    print(" Perintah: /rekey, /setkey <kunci>, /exit")
    print("=" * 50)

    t_recv = threading.Thread(target=handle_socket_messages, args=(bob_sock,), daemon=True)
    t_recv.start()

    while RUNNING:
        try:
            msg = input("Alice > ")
            if not msg.strip():
                continue
            if msg.strip() == "/exit":
                RUNNING = False
                bob_sock.close()
                break

            # Rekey otomatis via KDC tanpa race condition
            if msg.strip() == "/rekey":
                print("\n[*] [REKEY] Menghubungi KDC untuk Session Key baru...")
                TEMP_KS, new_ticket_b = request_kdc_ticket()
                print(f"[+] KDC memberikan Ks baru: '{TEMP_KS}'")
                print("[*] Mengirimkan Ticket B baru ke Bob...")
                bob_sock.sendall((json.dumps({"type": "rekey_step3", "ticket_b": new_ticket_b}) + "\n").encode('utf-8'))
                continue

            # Ganti manual
            if msg.startswith("/setkey "):
                new_key = msg.split(" ", 1)[1].strip()
                SESSION_KEY = new_key
                bob_sock.sendall((json.dumps({"type": "set_session_key", "new_key": new_key}) + "\n").encode('utf-8'))
                print(f"[+] Kunci sesi diubah manual ke: '{SESSION_KEY}'")
                continue

            ct_hex = aes_encrypt(msg, SESSION_KEY)
            packet = {"type": "chat", "ciphertext_hex": ct_hex}
            bob_sock.sendall((json.dumps(packet) + "\n").encode('utf-8'))
            print(f" -> Terkirim (Hex AES): {ct_hex}")
        except (KeyboardInterrupt, EOFError):
            RUNNING = False
            break

    print("\n[+] Selesai.")

if __name__ == "__main__":
    run_alice()