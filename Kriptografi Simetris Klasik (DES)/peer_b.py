import socket
import threading
from des_manual import des_encrypt, des_decrypt

SHARED_KEY = "KUNCI8BY"  # Wajib sama dengan Peer A

def receive_messages(sock):
    while True:
        try:
            data = sock.recv(2048)
            if not data:
                break
            print(f"\n[Raw Ciphertext Diterima (Hex)]: {data.hex()}")
            decrypted = des_decrypt(data, SHARED_KEY)
            print(f"[Pesan Didekripsi]: {decrypted}")
            print("Kirim pesan: ", end="", flush=True)
        except Exception:
            break

def main():
    host = "127.0.0.1"
    port = 65432

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    print(f"[+] Terhubung ke Peer A di {host}:{port}")

    threading.Thread(target=receive_messages, args=(client,), daemon=True).start()

    while True:
        msg = input("Kirim pesan: ")
        if msg.lower() == 'exit':
            break
        cipher_bytes = des_encrypt(msg, SHARED_KEY)
        print(f"[Transmisi Ciphertext (Hex)]: {cipher_bytes.hex()}")
        client.sendall(cipher_bytes)

    client.close()

if __name__ == "__main__":
    main()