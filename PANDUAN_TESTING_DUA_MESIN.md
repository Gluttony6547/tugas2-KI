# Panduan Testing Dua Terminal — Desktop Utama + VM Linux Mint

Panduan ini menjalankan **Tugas 2 (KDC + AES manual)** dengan dua terminal berbeda alamat IP:
**desktop utama** dan **Linux Mint di virtual machine**, sesuai ketentuan "IP harus berbeda
(bisa 1 main desktop, 1 virtual machine)". Kedua sisi saling kirim dan menerima pesan
sebagai sender maupun receiver.

| Entitas | Dijalankan di | Terminal | Program |
|---|---|---|---|
| **KDC** | Desktop (terminal 1) | Terminal A | `kdc.py` |
| **Alice** | Desktop (terminal 2) | Terminal B | `node.py --peran alice` |
| **Bob** | VM Linux Mint (terminal tunggal) | Terminal C | `node.py --peran bob` |

Pemetaan ketentuan tiga alamat: KDC mendengarkan di IP desktop, Alice memakai IP desktop
sebagai IP sumber, dan Bob mendengarkan di IP VM — ketiganya tampil terpisah di `/status`
dan di Wireshark.

---

## 1. Persiapan

### 1.1 Ringkasan update terbaru (dari hasil testing)

- Seluruh implementasi kini diuji: 20/20 unit test, 3 skenario E2E, uji konsol interaktif — semua lulus.
- Repo hanya berisi berkas AES/KDC + dokumen yang relevan; bukti DES lama dihapus dari `bukti/`.
- Kunci sesi bisa dirotasi live lewat `/kunci` tanpa restart (bukan hardcode).

### 1.2 Cari alamat IP kedua sisi

**Windows (desktop):** buka Command Prompt:

```bat
ipconfig
```

Catat **IPv4 Address** adapter yang aktif (mis. `192.168.1.10`).

**Linux Mint (VM):** buka terminal (Ctrl+Alt+T):

```bash
ip a
```

Catat **inet** adapter yang aktif (mis. `10.0.2.15` untuk NAT, atau `192.168.1.15` untuk bridged).

> **Catatan VM:** gunakan mode jaringan **bridged** supaya VM mendapat IP di subnet yang sama
> dengan desktop dan saling terjangkau. Mode **NAT** juga bisa, asal dua arah `ping` berhasil
> sebelum mulai; kalau desktop tidak bisa menjangkau IP NAT VM, ganti VM ke bridged.

### 1.3 Isi `konfigurasi.json`

Arahkan tiga entitas ke alamat yang benar. Anggap desktop `192.168.1.10`, VM `10.0.2.15`:

```json
{
  "kdc": {
    "host": "192.168.1.10",
    "port": 5000,
    "kunci_master": {
      "alice": "KunciAliceKI2026",
      "bob": "KunciBobKI2026XX"
    }
  },
  "alice": {
    "id": "alice",
    "host": "192.168.1.10",
    "kunci_master": "KunciAliceKI2026"
  },
  "bob": {
    "id": "bob",
    "host": "10.0.2.15",
    "port": 5002,
    "kunci_master": "KunciBobKI2026XX"
  },
  "jaringan": { "timeout": 15.0 }
}
```

Kedua mesin memakai file yang **identik**. Yang perlu disesuaikan hanya:
- `kdc.host` dan `alice.host` = IP desktop;
- `bob.host` = IP VM;
- nilai `kunci_master` tetap sama persis di KDC dan node masing-masing (boleh diganti, asal 16 karakter ASCII dan cocok antar sisi).

### 1.4 Izinkan firewall

Di desktop (PowerShell sebagai Administrator):

```powershell
netsh advfirewall firewall add rule name="KDC AES" dir=in action=allow protocol=TCP localport=5000
```

Di Linux Mint (VM):

```bash
sudo ufw allow 5002/tcp
```

Sesuaikan bila `ufw` tidak aktif (biasanya default Mint membiarkan inbound dari jaringan lokal).

---

## 2. Menjalankan Program

Urutan wajib: **KDC → Bob → Alice**. Alice yang memicu handshake, jadi siapkan Bob dulu.

### Terminal A — KDC di desktop

```bash
python kdc.py --bind 192.168.1.10
```

KDC mencetak `[MENDENGAR] 192.168.1.10:5000` dan daftar kunci master.

### Terminal C — Bob di VM Linux Mint

```bash
python3 node.py --peran bob --bind 10.0.2.15
```

Bob mencetak `[SIAP] bob mendengarkan di 10.0.2.15:5002`.

### Terminal B — Alice di desktop

```bash
python node.py --peran alice
```

Alice membuka koneksi ke KDC (LANGKAH 1), menerima K_S + tiket (LANGKAH 2), mengirim tiket
ke Bob (LANGKAH 3), membalas tantangan N2 (LANGKAH 4), dan menutup handshake (LANGKAH 5).
Kini kedua sisi siap komunikasi AES.

---

## 3. Pengujian Manual Langkah demi Langkah

Lakukan urutan kasus uji berikut di terminal B (Alice) dan C (Bob).

### 3.1 Pesan dua arah (sender + receiver)

Alice ketik:

```
Halo Bob, ini Alice
```

Bob ketik balasan:

```
Halo Alice, pesan diterima
```

Verifikasi:
- Tiap sisi menampilkan **Ciphertext AES (HEX)** lalu **Plaintext** hasil dekripsi.
- Ciphertext yang tampil di pengirim dan penerima **identik**.
- Jalankan `/status` di kedua sisi; penghitung `TX`/`RX` naik berpasangan.

### 3.2 Rotasi kunci sesi tanpa restart

Dari Alice:

```
/kunci
```

Keduanya mencetak "[KUNCI] kunci baru aktif di kedua sisi". Lanjutkan percakapan:

```
Pesan SETELAH kunci berganti
```

Verifikasi pesan tetap terkirim; nilai `K_S` berubah di `/status` kedua sisi.

### 3.3 Case negatif (kunci master salah)

Hentikan semua program (Ctrl+C, atau `/keluar` di Alice dan Bob). Lalu jalankan Alice
dengan kunci yang berbeda dari KDC:

```bash
python node.py --peran alice --kunci KunciSalahBanget
```

Keluaran yang diharapkan (exit code 3):

```
[ERROR] Handshake gagal: gagal membuka balasan KDC dengan kunci master
```

Ini membuktikan kunci master yang salah ditolak pada langkah 2.

### 3.4 Kasus uji pelengkap

- Kirim pesan **panjang** (mis. 200 karakter): ciphertext tumbuh mengikuti blok 16 byte; penerima tetap mendapat teks utuh.
- Kirim karakter non-ASCII (mis. emoji): tetap terkirim karena plaintext diproses sebagai UTF-8; kunci tetap wajib 16 karakter ASCII.
- Kirim pesan dari sisi Bob tanpa intervensi Alice: bukti Bob berperan sebagai sender juga.

---

## 4. Wireshark

Siapkan **sebelum** mengirim pesan agar capture tidak terpecah:

1. Buka Wireshark di desktop **dan** pilih interface yang aktif (Wi-Fi/Ethernet, bukan loopback).
2. Set capture filter (di bar atas):

```
tcp port 5000 or tcp port 5002
```

3. Mulai capture; jalankan pengujian di bagian 3.
4. Untuk memeriksa isi payload, klik satu paket TCP yang membawa data lalu salin `tcp.payload`:
   seluruh datanya ciphertext AES (HEX) berukuran kelipatan 16 byte; tidak ada plaintext yang terkirim polos.
5. Simpan file capture (`File > Save As`) sebagai bukti demo.

Pada Wireshark akan terlihat tiga kombinasi alamat berbeda:
desktop:5xxx → desktop:5000 (LANGKAH 1–2, Alice↔KDC),
desktop:5xxx → 10.0.2.15:5002 (LANGKAH 3–5 + pesan, Alice↔Bob).

---

## 5. Checklist Pengumpulan

- [ ] Unit test: `python -m unittest test_aes -v` → 20/20 oke di kedua mesin.
- [ ] Handshake 5 langkah tercatat di output KDC, Alice, dan Bob.
- [ ] Pesan dua arah Alice→Bob dan Bob→Alice lulus.
- [ ] Rotasi `/kunci` mengganti `K_S` sesi tanpa restart program.
- [ ] Case negatif kunci master salah ditolak dengan exit code 3.
- [ ] Wireshark menangkap pertukaran data ketiga alamat; filter capture `tcp port 5000 or tcp port 5002`.
- [ ] Simpan bukti demo: file `.pcap` dan output terminal di `bukti/`, bila perlu lampiran.

Jika semua kotak tercentang, demo siap. Skrip urutan demo lengkap dan tanya-jawab examiner ada di `LAPORAN.md` bagian 10–11.
