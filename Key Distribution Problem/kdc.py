# kdc.py - Key Distribution Center
import socket
import json
import random
import string
from aes import aes_encrypt

def generate_session_key(length=16):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def run_kdc():
    print("=" * 50)
    print("        KDC SERVER (Key Distribution Center)      ")
    print("=" * 50)

    port = int(input("Port KDC [Default 8000]: ").strip() or 8000)
    ka = input("Master Key Alice (Ka) [Default: MasterAliceKey12]: ").strip() or "MasterAliceKey12"
    kb = input("Master Key Bob   (Kb) [Default: MasterBobKey1234]: ").strip() or "MasterBobKey1234"

    db_keys = {"Alice": ka, "Bob": kb}

    # Bind 0.0.0.0 agar container ki_kdc dapat diakses dari IP 172.20.0.20 (Alice)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    print(f"\n[+] KDC aktif mendengarkan di port {port}")
    print(f"[+] Master Key Ka: '{ka}', Kb: '{kb}'")
    print("[*] Menunggu permohonan sesi dari Alice...\n")

    while True:
        conn, addr = server.accept()
        raw = conn.recv(4096).decode('utf-8')
        if not raw:
            conn.close()
            continue

        try:
            req = json.loads(raw.strip())
            if req.get("step") == 1:
                id_a = req["id_a"]
                id_b = req["id_b"]
                nonce1 = req["nonce1"]
                print(f"[LANGKAH 1 DITERIMA dari {addr[0]}]")
                print(f" -> Permintaan: {id_a} ingin berbicara dengan {id_b}")
                print(f" -> Nonce1: {nonce1}")

                if id_a not in db_keys or id_b not in db_keys:
                    print("[-] Entitas tidak terdaftar.")
                    conn.close()
                    continue

                # 1. Bangkitkan Session Key Ks baru (16 karakter ASCII)
                ks = generate_session_key()
                print(f"[+] Ks baru di-generate: '{ks}'")

                # 2. Buat Ticket B = E(Kb, [Ks || ID_A])
                ticket_payload = json.dumps({"ks": ks, "id_a": id_a})
                ticket_b_hex = aes_encrypt(ticket_payload, db_keys[id_b])

                # 3. Buat Payload Alice = E(Ka, [Ks || ID_B || Nonce1 || Ticket_B])
                alice_payload = json.dumps({
                    "ks": ks,
                    "id_b": id_b,
                    "nonce1": nonce1,
                    "ticket_b": ticket_b_hex
                })
                alice_resp_hex = aes_encrypt(alice_payload, db_keys[id_a])

                # Kirim balasan Langkah 2 ke Alice
                resp = {"step": 2, "encrypted_payload": alice_resp_hex}
                conn.sendall((json.dumps(resp) + "\n").encode('utf-8'))
                print(f"[LANGKAH 2 TERKIRIM] Berhasil mengirimkan Ks dan Ticket ke {id_a}.\n")
        except Exception as e:
            print(f"[-] Error KDC: {e}")
        finally:
            conn.close()

if __name__ == "__main__":
    run_kdc()