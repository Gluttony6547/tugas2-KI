# Tugas 2 Keamanan Informasi — AES Manual + KDC

| Identitas | |
|---|---|
| **Nama** | Naufal Dariskarim |
| **NRP** | 5025231027 |
| **Mata kuliah** | Keamanan Informasi |
| **Tugas** | Tugas 2 — Key Distribution Scenario + AES |

> **Ini entry point Tugas 2.** Implementasi yang sedang dinilai adalah **AES-128 manual + KDC** untuk Alice dan Bob. Laporan lengkap, analisis 12 ketentuan, panduan tiga mesin, Wireshark, dan hasil uji ada di **[LAPORAN.md](LAPORAN.md)**.
>
> Folder ini juga menyimpan tugas **DES** sebelumnya. Berkas DES **tidak dihapus** dan diberi label arsip di bagian [Tugas sebelumnya (DES)](#tugas-sebelumnya-des--arsip).

---

## Ringkasan

Tiga proses terpisah, masing-masing memakai alamat IP sendiri:

| Entitas | Berkas | Peran | IP default | Port default |
|---|---|---|---|---|
| **KDC** | `kdc.py` | Memegang `K_A`/`K_B`, menerbitkan `K_S` dan tiket | `127.0.0.2` | 5000 |
| **Alice** | `node.py --peran alice` | Meminta sesi ke KDC, mengirim tiket ke Bob, memulai percakapan | `127.0.0.3` (IP sumber) | ephemeral |
| **Bob** | `node.py --peran bob` | Menerima tiket, mengirim tantangan nonce, menerima pesan | `127.0.0.4` | 5002 |

Setelah lima langkah Needham–Schroeder, Alice dan Bob memakai `K_S` yang sama untuk komunikasi AES dua arah. AES-128 diimplementasikan dari nol di `aes_manual.py`; tidak ada library kriptografi, OpenSSL, atau pycryptodome. KDC juga memakai AES manual untuk tiket dan balasan.

```text
Alice  --- (1) ID_A, ID_B, N1 ---------------->  KDC
Alice  <-- (2) E_KA[K_S, ID_A, ID_B, N1, tiket]  KDC
Alice  --- (3) tiket E_KB[K_S, ID_A, ID_B, waktu] -->  Bob
Alice  <-- (4) E_KS[N2] ------------------------  Bob
Alice  --- (5) E_KS[N2-1] --------------------->  Bob
Alice  <========== E_KS[pesan] dua arah ========>  Bob
```

Penjelasan notasi dan isi tiap langkah: [LAPORAN.md bagian 3](LAPORAN.md#3-skenario-distribusi-kunci-lima-langkah).

---

## Mulai cepat (satu mesin, tiga IP loopback)

Prasyarat: Python 3.8+, hanya standard library (tidak perlu `pip install`). Konfigurasi default sudah memakai tiga alamat loopback berbeda, jadi tidak perlu mengedit JSON untuk uji lokal.

Buka tiga terminal di folder ini:

```bash
# Terminal 1 — KDC (mendengarkan di 127.0.0.2:5000)
python kdc.py --bind 127.0.0.2

# Terminal 2 — Bob (mendengarkan di 127.0.0.4:5002)
python node.py --peran bob --bind 127.0.0.4

# Terminal 3 — Alice (IP sumber 127.0.0.3)
python node.py --peran alice
```

Setelah Alice selesai handshake, ketik pesan di konsol Alice atau Bob:

```text
Halo Bob, ini pesan pertama
/status
/kunci
Pesan setelah kunci berganti
/keluar
```

`/status` menampilkan IP lokal dan peer yang benar-benar dipakai socket, misalnya `lokal: 127.0.0.3:...` dan `bob @ 127.0.0.4:5002`.

`/kunci` meminta kunci sesi baru ke KDC tanpa restart. Kunci lama ditahan sampai peer mengonfirmasi, agar balasan yang masih di jaringan tidak hilang.

Untuk mengubah port/kunci:

```bash
python kdc.py --bind 127.0.0.2 --port 6000 --kunci-alice "KunciAliceKI2026" --kunci-bob "KunciBobKI2026XX"
python node.py --peran bob --bind 127.0.0.4 --kdc-port 6000 --port 6002
python node.py --peran alice --kdc-port 6000 --lawan-port 6002 --bind 127.0.0.3
```

---

## Menjalankan di tiga mesin (tiga IP LAN)

Isi `konfigurasi.json` di tiap mesin:

- `kdc.host` = IP mesin KDC, `kdc.port` = 5000.
- `bob.host` = IP mesin Bob, `bob.port` = 5002.
- `alice.host` = IP mesin Alice; dipakai sebagai **IP sumber** koneksi keluar (bukan listener).
- Kunci master harus sama dengan yang dipegang KDC.

Urutan start: **KDC → Bob → Alice**. Beri `--bind` eksplisit di KDC dan Bob agar keduanya benar-benar mendengarkan di IP mesinnya.

```bash
# Mesin KDC
python kdc.py --konfigurasi konfigurasi.json --bind 192.168.1.10

# Mesin Bob
python node.py --peran bob --konfigurasi konfigurasi.json --bind 192.168.1.12

# Mesin Alice
python node.py --peran alice --konfigurasi konfigurasi.json --bind 192.168.1.11
```

Contoh lengkap konfigurasi, alternatif flag CLI, firewall, dan catatan IP ada di [LAPORAN.md bagian 6](LAPORAN.md#6-panduan-menjalankan-tiga-mesin).

---

## Perintah konsol

| Perintah | Fungsi |
|---|---|
| teks biasa atau `/kirim <teks>` | Kirim pesan AES ke peer |
| `/status` | Tampilkan peran, IP lokal, peer, sesi KDC, `K_A`/`K_B`, `K_S`, TX/RX |
| `/kunci` | Rotasi kunci sesi lewat KDC, tanpa restart |
| `/bantu` | Daftar perintah |
| `/keluar` | Tutup koneksi dan program |

Mode otomatis untuk pengujian: `--kirim`, `--balas`, `--jumlah`, `--harap-balasan`, `--rotasi-setelah`, `--batas`, `--tanpa-konsol`.

---

## Struktur repository

### Tugas 2 — AES + KDC (yang sedang dinilai)

| Berkas | Isi |
|---|---|
| [`aes_manual.py`](aes_manual.py) | AES-128 manual: key expansion, SubBytes, ShiftRows, MixColumns, CBC, PKCS#7 |
| [`kdc.py`](kdc.py) | KDC langkah 1–2, registry sesi, konsol `/sesi` dan `/kunci` |
| [`node.py`](node.py) | CLI, `Node.__init__`, dan `main`; kelas `Node` menggabungkan dua mixin di bawah |
| [`protokol.py`](protokol.py) | Handshake langkah 1–5, pesan dua arah, transport, rotasi kunci |
| [`konsol.py`](konsol.py) | Tampilan, `/status`, `/kunci`, `/bantu`, `/keluar`, mode otomatis |
| [`sesi.py`](sesi.py) | Keadaan sesi (`K_S`, lawan, peer, TX/RX) yang dipakai bersama |
| [`jaringan.py`](jaringan.py) | Framing TCP 4 byte, JSON, log frame TX/RX |
| [`konfigurasi.py`](konfigurasi.py) | Pembaca `konfigurasi.json` |
| [`konfigurasi.json`](konfigurasi.json) | IP, port, dan kunci master |
| [`test_aes.py`](test_aes.py) | 20 unit test, termasuk vektor FIPS-197 dan NIST CBC |
| [`uji_end_to_end.py`](uji_end_to_end.py) | Harness tiga proses dengan tiga IP berbeda: dasar, rotasi kunci, negatif |
| [`LAPORAN.md`](LAPORAN.md) | Laporan lengkap Tugas 2 |
| [`.github/workflows/test.yml`](.github/workflows/test.yml) | CI Windows + Ubuntu untuk unit test dan E2E |

### Tugas sebelumnya (DES) — arsip

Berkas berikut adalah **tugas DES**, bukan bagian AES/KDC. Jangan dijalankan untuk demo Tugas 2, tetapi jangan dihapus agar riwayat pengerjaan tetap terlihat.

- Dokumentasi lama: [`README_DES_SEBELUMNYA.md`](README_DES_SEBELUMNYA.md), [`PANDUAN_PENGUJIAN.md`](PANDUAN_PENGUJIAN.md), [`HASIL_PENGUJIAN.md`](HASIL_PENGUJIAN.md)
- Kode DES: [`cipher_manual.py`](cipher_manual.py), [`transport.py`](transport.py), [`sender_node-v3.py`](sender_node-v3.py), [`receiver_node-v3.py`](receiver_node-v3.py), [`test_des.py`](test_des.py), [`uji_lintas_mesin.py`](uji_lintas_mesin.py)
- Bukti DES: file lama di [`bukti/`](bukti/), sebelum folder `bukti/e2e/` yang berisi bukti AES/KDC.

---

## Pengujian

```bash
# 20 unit test AES/KDC
python -m unittest test_aes -v

# Tiga proses: KDC di 127.0.0.2, Alice dari 127.0.0.3, Bob di 127.0.0.4
python uji_end_to_end.py
```

Hasil terakhir (27 Oktober 2026, 23.49 WIB), dijalankan setelah pemisahan modul:

- **20 unit test lulus**, termasuk FIPS-197 C.1 dan NIST SP 800-38A CBC. Bukti: [`bukti/unit_aes_out.txt`](bukti/unit_aes_out.txt).
- **3 skenario E2E lulus** dengan tiga IP berbeda: percakapan dua arah, rotasi kunci di tengah percakapan, dan kunci master salah. Ringkasan: [`bukti/e2e_hasil.txt`](bukti/e2e_hasil.txt); detail: [`bukti/e2e/20261027-234923/`](bukti/e2e/20261027-234923/).
- **Capture pcap nyata** dari handshake + percakapan: [`bukti/pcap/handshake_chat.pcap`](bukti/pcap/handshake_chat.pcap). Analisis dan payload hex: [`bukti/pcap/analisis.txt`](bukti/pcap/analisis.txt).
- **Konsol interaktif** diuji ulang setelah kode dipecah menjadi modul: pesan biasa, `/status`, `/kunci`, pesan setelah rotasi, dan `/keluar` (exit 0). Bukti: [`bukti/konsol_interaktif.txt`](bukti/konsol_interaktif.txt).

Angka dan skenario lengkap di [LAPORAN.md bagian 8](LAPORAN.md#8-hasil-pengujian).

---

## Batasan

- Tiga IP sudah **dijalankan nyata** di mesin ini memakai `127.0.0.2`, `127.0.0.3`, dan `127.0.0.4`, tetapi masih **satu host**, bukan tiga perangkat fisik. Capture pcap juga berasal dari interface loopback, bukan Wi-Fi/Ethernet.
- Kunci master dapat diubah lewat config/CLI, tetapi memerlukan restart; hanya kunci sesi yang bisa dirotasi live lewat `/kunci`.
- Plaintext menerima UTF-8 (ASCII adalah subset), sedangkan kunci dipaksa 16 karakter ASCII.
- Tidak ada MAC/timestamp/replay protection; ini implementasi edukatif, bukan sistem produksi.
- `alice.host` dipakai sebagai IP sumber koneksi Alice; Alice tidak membuka listener, jadi tidak ada `alice.port`.

Daftar lengkap ada di [LAPORAN.md bagian 9](LAPORAN.md#9-batasan-dan-hal-yang-belum-dikerjakan).

---

## Dokumentasi

- Laporan lengkap dan jawaban 12 ketentuan: **[LAPORAN.md](LAPORAN.md)**
- Panduan tiga mesin: [LAPORAN.md bagian 6](LAPORAN.md#6-panduan-menjalankan-tiga-mesin)
- Wireshark dan pcap: [LAPORAN.md bagian 7](LAPORAN.md#7-wireshark)
- Skrip demo dan tanya-jawab: [LAPORAN.md bagian 10](LAPORAN.md#10-skrip-demo) dan [bagian 11](LAPORAN.md#11-tanya-jawab-examiner)

Tugas ini dibuat untuk mata kuliah Keamanan Informasi. Implementasi bersifat edukatif dan tidak dimaksudkan untuk melindungi data nyata tanpa audit keamanan.
