# Arsip Tugas Sebelumnya — Komunikasi DES 2 Arah (Windows ↔ Linux)

> **Dokumen arsip.** Isi berkas ini adalah dokumentasi tugas **sebelum** Tugas 2 AES/KDC. Entry point tugas yang sedang dikumpulkan ada di [README.md](README.md); laporan lengkapnya di [LAPORAN.md](LAPORAN.md). Berkas DES tidak dihapus agar riwayat pengerjaan tetap terlihat.

Simulasi komunikasi dua arah antara dua node (Sender dan Receiver) di **dua sistem operasi berbeda** dengan **alamat IP berbeda**. Seluruh proses enkripsi memakai **algoritma DES (Data Encryption Standard) yang diimplementasikan manual dari nol**, tanpa library kriptografi eksternal.

---

## 1. Daftar Isi

- [Tujuan](#2-tujuan)
- [Metode](#3-metode)
- [Library yang Digunakan](#4-library-yang-digunakan)
- [Struktur Berkas](#5-struktur-berkas)
- [Cara Pengerjaan](#6-cara-pengerjaan)
- [Panduan Pengujian — Windows](#7-panduan-pengujian--windows)
- [Panduan Pengujian — Linux](#8-panduan-pengujian--linux)
- [Pengujian Lintas OS (Syarat Utama)](#9-pengujian-lintas-os-syarat-utama)
- [Hasil Pengujian](#10-hasil-pengujian)
- [Catatan Keamanan](#11-catatan-keamanan)

---

## 2. Tujuan

1. Membuktikan implementasi manual DES menghasilkan ciphertext sesuai vektor uji standar.
2. Membangun komunikasi TCP dua arah yang pesannya terenkripsi di kedua sisi.
3. Memenuhi syarat utama: **dapat diuji pada dua OS berbeda dengan IP berbeda**.

---

## 3. Metode

### 3.1 DES Manual (`cipher_manual.py`)

DES diimplementasikan dari nol mengikuti spesifikasi klasik:

| Komponen | Keterangan |
|---|---|
| Feistel 16 putaran | Blok 64-bit (8 byte), L/R dipertukarkan tiap putaran |
| Initial / Final Permutation | Tabel IP dan FP (IP⁻¹) |
| Expansion Permutation | E-tabel, 32 bit → 48 bit |
| Key Scheduling | PC-1, rotasi kiri 28 bit sesuai `SHIFT_SCHEDULE`, PC-2 → 16 subkey 48 bit |
| S-Box | 8 S-Box 6×4 |
| Permutation P | 32 bit |
| Padding | PKCS#7, pesan selalu dilengkapi hingga kelipatan 8 byte |

Kunci dinormalkan ke tepat 8 byte: kurang dari 8 ditambah nol, lebih dari 8 dipotong.

**Vektor uji standar yang dipakai** (membuktikan kebenaran implementasi):

```text
key=133457799BBCDFF1 pt=0123456789ABCDEF -> 85E813540F0AB405
key=0E329232EA6D0D73 pt=8787878787878787 -> 0000000000000000
```

### 3.2 Manajemen Kunci (PSK)

Kunci bersama (**Pre-Shared Key**) berupa 8 byte `KunciDES`, sudah disepakati kedua node sebelum transmisi dan **tidak pernah dikirim melalui jaringan**. Nilai PSK ada di dalam kode (bawaan `KunciDES`) dan bisa dioverride per sesi dengan `--key` atau variabel lingkungan `DES_PSK`.

### 3.3 Framing TCP (`transport.py`)

`recv(4096)` tidak menghormati batas pesan. Dua pesan yang tiba berdekatan bisa menyatu dalam satu `recv()`, dan ciphertext DES yang terpotong menghasilkan plaintext rusak. Karena itu setiap pesan dibungkus **frame 4 byte panjang (big-endian) + payload**.

Karena ECB bersifat deterministik, tiap payload yang diterima juga **diverifikasi ulang** dengan cara mengenkripsinya kembali. Jika hasilnya tidak identik dengan ciphertext masuk, berarti PSK berbeda atau data rusak — program menolak dan memberi pesan yang jelas, bukan menampilkan plaintext sampah.

### 3.4 Arsitektur Node

| Node | Peran | Berkas |
|---|---|---|
| Node A | Receiver (server TCP) | `receiver_node-v3.py` |
| Node B | Sender (client TCP) | `sender_node-v3.py` |

Keduanya berjalan mode interaktif (ketik pesan) maupun mode otomatis (`--send/--reply --count`), cocok untuk pengujian berulang.

---

## 4. Library yang Digunakan

Seluruh program hanya memakai **Python standard library** — tanpa `pip install` apa pun, sehingga langsung jalan di Windows maupun Linux.

| Modul | Dipakai untuk |
|---|---|
| `socket` | Koneksi TCP (server & client) |
| `threading` | Menerima pesan sambil tetap bisa mengirim (dua arah) |
| `struct` | Encoding panjang frame 4 byte (`!I`) |
| `subprocess` | Menjalankan node dari `test_des.py` dan `uji_lintas_mesin.py` |
| `datetime`, `time` | Stempel waktu bukti uji dan pengukuran durasi |
| `argparse` | Opsi CLI (mode otomatis, kunci, log, timeout, selftest) |
| `shutil`, `os`, `sys`, `re`, `socket` | Utilitas umum |

**Persyaratan:** Python 3.8 atau lebih baru. Tidak ada dependensi pihak ketiga. `requirements.txt` berisi komentar saja sebagai penanda bahwa memang tidak ada paket yang perlu dipasang.

---

## 5. Struktur Berkas

```text
Tugas 2 Keamanan Informasi/
├── cipher_manual.py        # Implementasi DES manual (Feistel 16 putaran, PKCS#7)
├── transport.py            # Framing TCP + verifikasi PSK + pencatat bukti uji
├── receiver_node-v3.py     # Node A — server TCP
├── sender_node-v3.py       # Node B — client TCP
├── test_des.py             # 17 uji otomatis (unittest)
├── uji_lintas_mesin.py     # Otomatisasi uji lintas mesin via SSH
├── requirements.txt        # Penanda nol dependensi
├── .github/workflows/test.yml  # CI: uji lintas OS (Ubuntu + Windows)
├── PANDUAN_PENGUJIAN.md    # Panduan pengujian lengkap & matriks uji
├── HASIL_PENGUJIAN.md      # Tabel hasil pengujian + angka terukur
└── bukti/                  # Log & keluaran uji sebagai bukti
```

---

## 6. Cara Pengerjaan

1. **Implementasi DES manual** — menulis tabel IP/FP/E/P/PC1/PC2/S-Box, key scheduling, dan fungsi Feistel di `cipher_manual.py`.
2. **Uji vektor standar** — mencocokkan output DES dengan dua vektor uji resmi (dijalankan otomatis lewat `--selftest`).
3. **Node jaringan** — membangun sender (client) dan receiver (server) yang saling mengirim pesan terenkripsi dua arah.
4. **Menambah framing** — menemukan bug penyatuan/ pemotongan pesan pada `recv()`, lalu menambahkan frame 4 byte di `transport.py`.
5. **Mode otomatis & bukti uji** — menambah `--send/--reply/--count/--expect/--log/--timeout/--selftest` supaya pengujian bisa berjalan otomatis dan meninggalkan bukti log.
6. **Verifikasi PSK** — mendeteksi kunci berbeda lewat enkripsi-ulang (ECB deterministik).
7. **Otomatisasi lintas mesin** — membangun `uji_lintas_mesin.py` (SSH) dan menjalankan pengujian lintas OS nyata.
8. **Dokumentasi** — menyusun panduan, tabel hasil, dan README ini.

---

## 7. Panduan Pengujian — Windows

Buka **Command Prompt** atau **PowerShell** di folder ini.

### 7.1 Uji cepat (tanpa jaringan)

```cmd
python sender_node-v3.py --selftest
python -m unittest test_des -v
```

Keluaran yang diharapkan: `[SELFTEST] LULUS` dan `Ran 17 tests ... OK`.

Uji yang sama juga berjalan otomatis di GitHub Actions (Ubuntu + Windows) setiap ada push — lihat badge di bagian atas README.

### 7.2 Sebagai Receiver (Node A) — mode interaktif

```cmd
python receiver_node-v3.py 0.0.0.0 65432
```

### 7.3 Sebagai Sender (Node B) — mode interaktif

```cmd
python sender_node-v3.py <IP_RECEIVER> 65432
```

Ketik pesan lalu Enter; teks akan terenkripsi DES sebelum dikirim. Ketik `exit` untuk berhenti.

### 7.4 Mode otomatis (untuk pengujian berulang)

```cmd
python sender_node-v3.py 192.168.207.128 65432 --send "PING dari Windows" --count 3 --expect "OK dari Linux" --log sender.log
```

### 7.5 Firewall (bila Windows menjadi receiver)

```cmd
netsh advfirewall firewall add rule name="DES TCP 65432" dir=in action=allow protocol=TCP localport=65432
```

Jalankan dengan **Administrator**.

---

## 8. Panduan Pengujian — Linux

Buka terminal di mesin Linux (fisik, VM, atau WSL).

### 8.1 Uji cepat

```bash
python3 receiver_node-v3.py --selftest
python3 -m unittest test_des -v
```

### 8.2 Sebagai Receiver (Node A) — mode interaktif

```bash
python3 receiver_node-v3.py 0.0.0.0 65432
```

`0.0.0.0` membuat receiver mendengarkan di semua antarmuka, termasuk NAT VM.

### 8.3 Sebagai Sender (Node B) — mode interaktif

```bash
python3 sender_node-v3.py <IP_RECEIVER> 65432
```

### 8.4 Mode otomatis

```bash
python3 receiver_node-v3.py 0.0.0.0 65432 --reply "OK dari Linux" --count 3 --expect "PING" --log receiver.log
```

### 8.5 Cek IP & firewall

```bash
ip a                       # catat IP, mis. 192.168.207.128
sudo ufw allow 65432/tcp   # bila ufw aktif
```

---

## 9. Pengujian Lintas OS (Syarat Utama)

### Skenario A — Windows Host ↔ VM Linux (NAT VMware)

```text
Windows 11 (sender) 192.168.207.1  --NAT-->  VM Linux (receiver) 192.168.207.128
```

1. Di VM Linux: `python3 receiver_node-v3.py 0.0.0.0 65432 --reply "OK dari Linux" --expect "PING dari Windows" --count 1 --log receiver.log`
2. Di Windows: `python sender_node-v3.py <IP_VM> 65432 --send "PING dari Windows" --expect "OK dari Linux" --count 1 --log sender.log`

Bukti IP berbeda muncul di log: `PEER=<ip>:<port>` di sisi receiver.

### Skenario B — WSL2 Ubuntu ↔ Windows (sudah dijalankan)

Receiver di Ubuntu WSL2, sender di Windows, atau kebalikannya. Lihat tabel hasil.

### Skenario C — Dua perangkat fisik di Wi-Fi yang sama

Pakai IP masing-masing (`192.168.1.x`).

### Otomatisasi via SSH

```bash
python uji_lintas_mesin.py --host <IP_VM> --user <user> --count 3
python uji_lintas_mesin.py --lokal     # uji tanpa SSH
python uji_lintas_mesin.py --dry-run   # cetak rencana perintah
```

Skrip menyalin berkas ke VM, menjalankan receiver di sana, menjalankan sender lokal, lalu mengumpulkan log dan exit code kedua sisi ke `bukti/lintas_mesin/<waktu>/`.

> **Catatan Windows:** bila port bawaan `65432` menghasilkan `WinError 10013` (port dipesan sistem), gunakan port lain seperti `55555`.

---

## 10. Hasil Pengujian

Tabel lengkap, angka terukur, dan bukti ada di [`HASIL_PENGUJIAN.md`](HASIL_PENGUJIAN.md).

| Uji | Hasil |
|---|---|
| Vektor DES standar (2 vektor) | Lulus |
| Unit test otomatis (17 uji) | Lulus |
| Loopback 3 pesan | Lulus, exit 0/0 |
| Bind antarmuka non-loopback + UTF-8 | Lulus |
| 50 pesan cepat | Lulus, 50 RX / 50 TX, 0 padding bocor |
| Kasus negatif (4 skenario) | Exit code sesuai harapan |
| 200 pesan, ukur waktu | Lulus, 0,344 s |
| Mode interaktif (demo) | Lulus |
| Windows sender → Ubuntu receiver | Lulus, 3/3 pesan, exit 0/0 |
| Ubuntu sender → Windows receiver | Lulus, 3/3 pesan, exit 0/0 |
| Otomatisasi `--lokal` & uji negatif | Lulus (exit 0 / 1 sesuai harapan) |
| Uji ke VM VMware | Diblokir: sshd VM tidak aktif |

**Angka terukur:** 1,72 ms/pertukaran (loopback), 5,4 ms (50 pesan), 0,344 s untuk 200 pertukaran, overhead framing 4 byte/pesan.

---

## 11. Catatan Keamanan

Penting untuk laporan: ini adalah **tugas pemahaman algoritma**, bukan sistem enkripsi siap pakai.

- **DES 56-bit sudah tidak aman** — rentan terhadap brute force.
- **Mode ECB** bersifat deterministik: blok plaintext yang sama menghasilkan ciphertext sama, sehingga pola data bisa ditebak.
- **PSK hardcoded** di dalam kode.
- **Tidak ada autentikasi pihak** maupun IV — rentan MITM dan penggantian pesan.

Saran pengembangan: mode **CBC dengan IV acak per sesi**, kunci dari file/env tanpa nilai bawaan, dan **HMAC** untuk integritas. Pemeriksaan `dekripsi_terverifikasi` saat ini mendeteksi PSK salah, **bukan** pengganti MAC.

---

## Lisensi

Tugas mata kuliah Keamanan Informasi — untuk tujuan pembelajaran.
