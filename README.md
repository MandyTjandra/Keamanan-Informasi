# Keamanan Informasi: Implementasi Kriptografi Simetris & Protokol Distribusi Kunci

Selamat datang di repositori **Keamanan Informasi**. Repositori ini berisi kumpulan implementasi mandiri (*from-scratch / pure Python*) dari konsep fundamental hingga tingkat lanjut dalam bidang Kriptografi dan Keamanan Informasi, tanpa mengandalkan pustaka kriptografi pihak ketiga (*zero third-party crypto dependencies*).

Repositori ini memuat implementasi algoritma simetris klasik **Data Encryption Standard (DES)** dan penyelesaian masalah pertukaran kunci rahasia (*Key Distribution Problem*) menggunakan arsitektur tersentralisasi **Key Distribution Center (KDC)** berprotokol **Needham-Schroeder** dengan enkripsi **AES-128**.

---

## 📚 Daftar Isi Repositori

1. [Modul & Topik Pembelajaran](#-modul--topik-pembelajaran)
   - [1. Kriptografi Simetris Klasik (DES)](#1-kriptografi-simetris-klasik-des)
   - [2. Key Distribution Problem (KDC & Needham-Schroeder)](#2-key-distribution-problem-kdc--needham-schroeder)
2. [Tabel Komparasi Algoritma & Sistem](#-tabel-komparasi-algoritma--sistem)
3. [Struktur Direktori Repositori](#-struktur-direktori-repositori)
4. [Prasyarat & Persiapan Lingkungan](#-prasyarat--persiapan-lingkungan)
5. [Panduan Memulai Cepat (Quick Start)](#-panduan-memulai-cepat-quick-start)
   - [Menjalankan P2P Chat DES](#menjalankan-p2p-chat-des)
   - [Menjalankan Simulasi KDC & Alice-Bob](#menjalankan-simulasi-kdc--alice-bob)
6. [Tujuan Edukasi & Keamanan](#-tujuan-edukasi--keamanan)

---

## 🧩 Modul & Topik Pembelajaran

### 1. [Kriptografi Simetris Klasik (DES)](./Kriptografi%20Simetris%20Klasik%20(DES)/)
Implementasi murni algoritma **Data Encryption Standard (DES)** 64-bit yang dipadukan dengan obrolan dua arah (*peer-to-peer secure chat*) berbasis socket TCP.
- **Konsep Kunci**:
  - Jaringan Feistel 16 putaran (*16 Feistel rounds*).
  - Pembangkitan 16 subkunci 48-bit dari kunci 64-bit melalui *Permuted Choice* (PC-1 & PC-2) dan *circular left shift*.
  - 8 S-Box standar NIST/FIPS 46-3 dan permutasi P-Box.
  - Padding PKCS#7 untuk kelipatan 8 byte.
  - Komunikasi soket real-time non-blocking menggunakan multi-threading.
- **Dokumentasi Lengkap**: Baca panduan teknis dan alur di [README Kriptografi Simetris Klasik (DES)](./Kriptografi%20Simetris%20Klasik%20(DES)/README.md).

---

### 2. [Key Distribution Problem (KDC & Needham-Schroeder)](./Key%20Distribution%20Problem/)
Simulasi penyelesaian masalah distribusi kunci simetris (*Key Distribution Problem*) berskala $N$ pengguna menggunakan entitas tepercaya **Key Distribution Center (KDC)** dan protokol klasik **Needham-Schroeder**, diperkuat dengan implementasi manual algoritma modern **AES-128**.
- **Konsep Kunci**:
  - Arsitektur *Trusted Third Party* (TTP) KDC untuk mereduksi kompleksitas $N(N-1)/2$ pasangan kunci menjadi $N$ kunci master.
  - Handshake 5 tahap Needham-Schroeder dengan proteksi *anti-replay attack* via Nonce numerik ($Nonce_1$ dan $Nonce_2 \to Nonce_2 - 1$).
  - Otentikasi timbal-balik (*Mutual Authentication*) antara inisiator (Alice) dan responder (Bob).
  - Implementasi murni **AES-128** (*State Matrix*, `SubBytes`, `ShiftRows`, `MixColumns` dengan operasi Galois Field $GF(2^8)$, `AddRoundKey`, dan `KeyExpansion`).
  - Fitur interaktif: *Real-time chat*, *Dynamic Rekeying* otomatis via KDC (`/rekey`), dan penggantian kunci manual (`/setkey`).
  - Dukungan isolasi jaringan virtual menggunakan **Docker Compose** (subnet `172.20.0.0/16`).
- **Dokumentasi Lengkap**: Baca panduan teknis, alur paket, dan setup kontainer di [README Key Distribution Problem](./Key%20Distribution%20Problem/README.md).

---

## ⚖️ Tabel Komparasi Algoritma & Sistem

| Parameter | Kriptografi Simetris Klasik (DES) | Key Distribution Problem (KDC) |
|---|---|---|
| **Algoritma Utama** | Data Encryption Standard (DES) | Advanced Encryption Standard (AES-128) |
| **Ukuran Blok** | 64 bit (8 byte) | 128 bit (16 byte) |
| **Ukuran Kunci** | 64 bit (56 bit efektif) | 128 bit (16 karakter ASCII) |
| **Arsitektur Cipher** | Feistel Network (16 ronde) | Substitution-Permutation Network / SPN (10 ronde) |
| **Distribusi Kunci** | Kunci manual/prakonfigurasi (*Pre-Shared Key*) | Dinamis via KDC (*Session Key* $K_S$ & Tiket) |
| **Otentikasi & Anti-Replay** | Tidak ada (hanya kerahasiaan) | Ada (Otentikasi dua arah dengan Nonce) |
| **Topologi Jaringan** | Peer-to-Peer (1 Server : 1 Client) | Client-Server / KDC Tersentralisasi + P2P Chat |
| **Pembaruan Kunci** | Statis per sesi | Dinamis (*on-the-fly rekeying* tanpa putus koneksi) |
| **Kesiapan Lingkungan** | Localhost (Soket Python murni) | Localhost atau Docker Compose (`ki_net` terisolasi) |

---

## 📂 Struktur Direktori Repositori

```text
Keamanan-Informasi/
├── README.md                                  # Dokumentasi utama repositori
│
├── Kriptografi Simetris Klasik (DES)/         # Modul DES & P2P Chat
│   ├── README.md                              # Dokumentasi teknis mendalam modul DES
│   ├── des_manual.py                          # Algoritma DES murni (Feistel, S-Box, Subkeys)
│   ├── peer_a.py                              # Node Peer A (Server TCP port 65432)
│   └── peer_b.py                              # Node Peer B (Client TCP)
│
└── Key Distribution Problem/                  # Modul KDC, Needham-Schroeder & AES-128
    ├── README.md                              # Dokumentasi teknis mendalam protokol KDC
    ├── aes.py                                 # Algoritma AES-128 murni (SPN, Galois Field, S-Box)
    ├── kdc.py                                 # Server Key Distribution Center
    ├── alice.py                               # Node Alice (Inisiator & Client KDC/Bob)
    ├── bob.py                                 # Node Bob (Responder & Penerima Tiket)
    ├── Dockerfile                             # Definisi Docker container Python 3.11-slim
    └── docker-compose.yml                     # Orkestrasi 3 node dalam bridge network 172.20.0.0/16
```

---

## 🛠️ Prasyarat & Persiapan Lingkungan

1. **Python**: Versi 3.8 ke atas terpasang pada sistem operasi.
2. **Tanpa Pustaka Tambahan**: Seluruh kriptografi dibangun *from scratch*, sehingga Anda tidak perlu menjalankan `pip install` untuk modul kriptografi eksternal.
3. **Docker & Docker Compose (Opsional)**: Diperlukan jika ingin menguji simulasi KDC multi-container dalam jaringan subnet virtual.

---

## ⚡ Panduan Memulai Cepat (Quick Start)

### Menjalankan P2P Chat DES

1. Masuk ke direktori DES:
   ```powershell
   cd "Kriptografi Simetris Klasik (DES)"
   ```
2. Jalankan Peer A di terminal 1:
   ```powershell
   python peer_a.py
   ```
3. Jalankan Peer B di terminal 2:
   ```powershell
   python peer_b.py
   ```
4. Kirim pesan bolak-balik dan amati transmisi ciphertext dalam format heksadesimal.

---

### Menjalankan Simulasi KDC & Alice-Bob

#### Menggunakan Docker Compose (Skenario Jaringan Virtual):
1. Masuk ke direktori KDC:
   ```powershell
   cd "Key Distribution Problem"
   ```
2. Nyalakan seluruh container:
   ```powershell
   docker compose up -d --build
   ```
3. Buka 3 terminal berbeda untuk masing-masing peran:
   - **Terminal 1 (KDC)**: `docker exec -it ki_kdc python kdc.py` (tekan Enter untuk nilai default)
   - **Terminal 2 (Bob)**: `docker exec -it ki_bob python bob.py` (tekan Enter untuk nilai default)
   - **Terminal 3 (Alice)**: `docker exec -it ki_alice python alice.py` (tekan Enter untuk nilai default)
4. Sesi chat aman dimulai! Coba gunakan perintah `/rekey` pada Alice untuk mengamati peremajaan kunci sesi secara *real-time*.

*(Untuk panduan eksekusi lokal tanpa Docker, silakan baca [README Key Distribution Problem](./Key%20Distribution%20Problem/README.md)).*

---

## 🎓 Tujuan Edukasi & Keamanan

Semua kode dalam repositori ini dibuat untuk keperluan **edukasi, riset akademis, dan pemahaman mendalam** mengenai:
- Bagaimana algoritma blok cipher bekerja pada tingkat permutasi bit dan matematika medan berhingga (*finite field*).
- Alasan mengapa algoritma klasik (seperti DES) ditinggalkan demi algoritma modern (seperti AES).
- Bagaimana protokol pertukaran kunci formal dirancang untuk mengatasi kerentanan *eavesdropping* dan *replay attacks*.
