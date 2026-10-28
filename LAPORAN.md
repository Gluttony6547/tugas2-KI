# LAPORAN Tugas 2 — Keamanan Informasi

## Implementasi AES Manual dan Key Distribution Center (KDC) untuk Alice–Bob

| Identitas | |
|---|---|
| **Nama** | Naufal Dariskarim |
| **NRP** | 5025231027 |
| **Mata kuliah** | Keamanan Informasi |
| **Tugas** | Tugas 2 — Key Distribution Scenario + AES |
| **Repository** | <https://github.com/Gluttony6547/tugas2-KI> |
| **Tanggal pengujian terakhir** | 27 Oktober 2026, 23.49 WIB |

> Dokumen ini ditulis berdasarkan source yang benar-benar ada di folder ini. Nama fungsi, flag CLI, dan angka hasil uji diambil dari kode dan dari folder `bukti/`, bukan dari perkiraan. Jika ada perbedaan antara laporan dan source, source adalah acuan; bagian [Batasan](#9-batasan-dan-hal-yang-belum-dikerjakan) mencatat hal-hal yang belum dikerjakan.

---

## Daftar isi

1. [Ringkasan](#ringkasan)
2. [Jawaban atas 12 ketentuan tugas](#1-jawaban-atas-12-ketentuan-tugas)
3. [Arsitektur tiga entitas](#2-arsitektur-tiga-entitas)
4. [Skenario distribusi kunci lima langkah](#3-skenario-distribusi-kunci-lima-langkah)
5. [Implementasi AES manual](#4-implementasi-aes-manual)
6. [KDC manual dan manajemen kunci](#5-kdc-manual-dan-manajemen-kunci)
7. [Panduan menjalankan tiga mesin](#6-panduan-menjalankan-tiga-mesin)
8. [Wireshark](#7-wireshark)
9. [Hasil pengujian](#8-hasil-pengujian)
10. [Batasan](#9-batasan-dan-hal-yang-belum-dikerjakan)
11. [Skrip demo](#10-skrip-demo)
12. [Tanya-jawab examiner](#11-tanya-jawab-examiner)
13. [Peta berkas dan fungsi](#12-peta-berkas-dan-fungsi)
14. [Status pengumpulan](#13-status-pengumpulan)

---

## Ringkasan

Program ini menjalankan tiga proses terpisah:

- **KDC** (`kdc.py`) yang memegang kunci master Alice dan Bob, menerbitkan kunci sesi, dan membuat tiket.
- **Alice** (`node.py --peran alice`) yang meminta sesi ke KDC, meneruskan tiket ke Bob, dan menyelesaikan tantangan nonce.
- **Bob** (`node.py --peran bob`) yang menerima tiket, memverifikasi bahwa tiket memang untuk dirinya, lalu mengirim tantangan nonce.

Setelah lima langkah skenario selesai, Alice dan Bob memakai kunci sesi `K_S` yang sama untuk mengirim dan menerima pesan AES dua arah. AES-128 diimplementasikan sendiri di `aes_manual.py`; tidak ada `cryptography`, `pycryptodome`, OpenSSL, atau pemanggilan cipher dari library lain. KDC juga memakai implementasi AES yang sama untuk tiket dan balasan.

Verifikasi yang sudah dijalankan:

- **20 unit test** lulus, termasuk vektor FIPS-197 dan NIST SP 800-38A CBC.
- **3 skenario end-to-end** lulus dengan **tiga alamat IP berbeda**: KDC `127.0.0.2`, Alice `127.0.0.3`, Bob `127.0.0.4`.
- **Capture pcap nyata** dari handshake dan percakapan, berisi 9 segmen data dengan Source/Destination ketiga IP tersebut.
- Bukti tersimpan di [`bukti/unit_aes_out.txt`](bukti/unit_aes_out.txt), [`bukti/e2e_hasil.txt`](bukti/e2e_hasil.txt), [`bukti/e2e/20261027-234923/`](bukti/e2e/20261027-234923/), dan [`bukti/pcap/`](bukti/pcap/).

Yang **belum** dilakukan: menjalankan tiga perangkat fisik. Tiga IP sudah dibuktikan dengan tiga proses nyata di satu host memakai alamat loopback berbeda. Capture juga berasal dari interface loopback, bukan Wi-Fi/Ethernet. Ini disebut lagi di bagian batasan.

---

## 1. Jawaban atas 12 ketentuan tugas

### Ketentuan 1 — Kelompok (individu atau maksimal 2 orang)

Laporan ini memakai identitas tunggal **Naufal Dariskarim (5025231027)**. Tidak ada logika kelompok di dalam program: jumlah Alice dan Bob tidak berhubungan dengan jumlah anggota. Jika tugas dikumpulkan sebagai kelompok dua orang, identitas anggota kedua harus ditambahkan di README/laporan dan commit harus dilakukan oleh kedua akun; hal itu tidak bisa dibuktikan dari kode. Implementasi saat ini tidak membatasi jumlah anggota, tetapi juga tidak menyediakan fitur khusus kelompok.

**Kode/berkas:** identitas ada di [README.md](README.md) dan laporan ini; tidak ada kode kelompok.

### Ketentuan 2 — Arsitektur dan key distribution: KDC, Alice, Bob pada tiga IP berbeda

Ada tiga proses dengan peran yang jelas. KDC memegang `K_A` dan `K_B`, Alice hanya memuat kunci master miliknya, dan Bob hanya memuat kunci master miliknya. Alice menghubungi KDC untuk langkah 1–2, lalu menghubungi Bob untuk langkah 3–5. Setelah langkah 5 berhasil, keduanya memakai `K_S` untuk pesan AES. Tidak ada alamat IP yang di-hardcode di kode; alamat tujuan KDC/Bob, IP sumber Alice, dan port dibaca dari `konfigurasi.json` dan bisa ditimpa lewat flag CLI. Bind default `0.0.0.0` (wildcard) ditulis di argparse dan dapat diganti dengan `--bind`. Di `kdc.py` masih ada konstanta `DEFAULT_PORT = 5000` yang tidak dipakai oleh argparse; nilai yang benar-benar dipakai tetap berasal dari konfigurasi atau `--port`.

Alamat tiga entitas diatur di bagian `kdc.host`, `kdc.port`, `bob.host`, `bob.port`, dan `alice.host`. `kdc.host` dan `bob.host` menjadi target koneksi; `alice.host` dipakai sebagai **IP sumber** koneksi keluar Alice. Tidak ada `alice.port`, karena Alice tidak membuka listener; field itu sudah dihapus agar konfigurasi tidak berpura-pura mengatur sesuatu. Detail dan contoh konfigurasi ada di [bagian 6](#6-panduan-menjalankan-tiga-mesin).

Bukti eksekusi: harness menjalankan KDC dengan `--bind 127.0.0.2`, Bob dengan `--bind 127.0.0.4`, dan Alice dengan IP sumber `127.0.0.3`. `/status` Alice mencetak `lokal: 127.0.0.3:<port>` dan peer `127.0.0.4:<port>`; log KDC/Bob mencatat `PEER=127.0.0.3:<port>`. Capture [`bukti/pcap/handshake_chat.pcap`](bukti/pcap/handshake_chat.pcap) menunjukkan pasangan IP yang sama di kolom Source/Destination.

**Kode:** [`KDC.layani_permintaan`](kdc.py) untuk langkah 1–2; [`Node.minta_sesi`](protokol.py), [`Node.jalankan_alice`](protokol.py), [`Node.layani_bob`](protokol.py), dan [`Node.terima_loop`](protokol.py) untuk langkah 3–5 dan percakapan. Konfigurasi dibaca oleh [`konfigurasi.muat`](konfigurasi.py) lalu dipakai di [`Node.__init__`](node.py).

### Ketentuan 3 — Komunikasi dua arah; Alice dan Bob sama-sama sender dan receiver

Arsitekturnya client–server untuk pembentukan koneksi: Alice adalah inisiator yang menghubungi Bob, dan Bob adalah listener TCP. Setelah handshake selesai, pembagian peran itu tidak lagi membatasi arah pesan. Kedua proses menjalankan thread penerima dan konsol pengirim; `Node.kirim_data` dipakai oleh kedua peran, sedangkan `Node.terima_loop` menerima pesan dari kedua arah. Karena itu Alice bisa mengirim lalu Bob membalas, dan sebaliknya, pada koneksi TCP yang sama.

Mode otomatis membuktikan dua arah tanpa manusia: `--kirim` pada Alice dan `--balas` pada Bob. Mode interaktif membuktikan hal yang sama lewat perintah yang diketik.

**Kode:** [`Node.kirim_data`](protokol.py), [`Node.terima_loop`](protokol.py), [`Node.tangani_pesan`](protokol.py), [`Node.konsol`](konsol.py), [`Node.mode_otomatis_alice`](konsol.py), [`Node.mode_otomatis_bob`](konsol.py).

### Ketentuan 4 — AES dan KDC manual; key/plaintext ASCII; ciphertext hex; key dapat diubah

AES-128 ditulis dari nol di `aes_manual.py` dengan kelas `ManualAES`: key expansion, SubBytes, ShiftRows, MixColumns, AddRoundKey, invers untuk dekripsi, CBC, dan padding PKCS#7. KDC juga manual: `KDC.layani_permintaan` memakai `ManualAES.enkripsi` untuk tiket dan balasan, bukan library kriptografi.

Kunci wajib 16 karakter ASCII dan divalidasi di `ManualAES.__init__`; kunci sesi dibuat acak 16 karakter ASCII oleh `buat_kunci_sesi`. Plaintext pesan adalah teks yang diubah menjadi byte UTF-8; ASCII adalah bagian dari UTF-8, sehingga semua input ASCII yang diminta tugas bekerja. Program saat ini **tidak menolak** karakter non-ASCII; ini dicatat sebagai batasan, bukan diklaim sebagai pembatasan yang tidak ada. Ciphertext selalu ditampilkan dan dikirim sebagai hex (`.hex()`), bukan base64 atau byte mentah.

Kunci master tidak di-hardcode di kode; nilainya ada di `konfigurasi.json` dan dapat ditimpa dengan `--kunci`, `--kunci-alice`, dan `--kunci-bob`. Kunci sesi dapat diganti saat program berjalan lewat `/kunci` (lihat ketentuan 5 dan 12), tanpa restart.

**Kode:** [`ManualAES`](aes_manual.py), [`ManualAES._perluas_kunci`](aes_manual.py), [`ManualAES.enkripsi`](aes_manual.py), [`ManualAES.dekripsi`](aes_manual.py), [`KDC.layani_permintaan`](kdc.py), [`buat_kunci_sesi`](kdc.py), [`Node.kirim_data`](protokol.py).

### Ketentuan 5 — Program interaktif; key bisa diubah tanpa menjalankan ulang

Setelah sesi terbentuk, konsol menerima pesan biasa atau perintah:

| Perintah | Fungsi |
|---|---|
| `/kirim <teks>` | Mengirim pesan terenkripsi; teks biasa tanpa slash juga dikirim |
| `/status` | Menampilkan peran, IP lokal, peer, sesi KDC, `K_A`/`K_B`, `K_S`, waktu mulai, TX/RX |
| `/kunci` | Meminta `K_S` baru ke KDC, mengirim tiket baru ke peer, dan menunggu konfirmasi |
| `/bantu` | Daftar perintah |
| `/keluar` | Menutup koneksi dan program |

`/kunci` mengubah kunci sesi tanpa restart. Kunci lama tetap dipakai sampai peer mengonfirmasi, sehingga balasan yang masih dalam perjalanan tidak langsung gagal didekripsi. Perubahan kunci **master** (`K_A`/`K_B`) masih memerlukan restart atau flag baru; yang bisa diubah live adalah kunci sesi. Ini penting untuk dijelaskan dengan tepat saat demo.

**Kode:** [`Node.konsol`](konsol.py), [`Node.status`](konsol.py), [`Node.rotasi_kunci`](protokol.py), [`Node.tangani_kontrol`](protokol.py), [`Node.buka_payload`](protokol.py).

### Ketentuan 6 — Wireshark

Program mengirim JSON di atas TCP. Metadata seperti `tipe`, `id_a`, `id_b`, dan `n1` terlihat di Wireshark; isi rahasia ada di field `data`/`tiket` sebagai hex hasil AES-CBC. Capture filter yang dipakai untuk konfigurasi default adalah `tcp port 5000 or tcp port 5002`. Field yang harus ditunjuk saat demo dijelaskan di [bagian 7](#7-wireshark).

Capture Wireshark **sudah dibuat** dengan `tshark`/Npcap pada interface loopback dan disimpan di [`bukti/pcap/handshake_chat.pcap`](bukti/pcap/handshake_chat.pcap). File berisi 32 paket, 9 segmen data, dan memperlihatkan tiga IP berbeda. Rincian, filter, dan payload hex ada di [bagian 7](#7-wireshark).

**Kode:** envelope JSON dibuat oleh [`kirim_json`](jaringan.py) dan [`terima_json`](jaringan.py); hex dihasilkan di [`Node.kirim_data`](protokol.py), [`KDC.layani_permintaan`](kdc.py), dan [`Node.jalankan_alice`](protokol.py).

### Ketentuan 7 — Persiapan dan pemahaman kode

Program sudah dijalankan end-to-end secara otomatis dan manual, termasuk tiga proses dengan tiga IP berbeda dan capture pcap. Pemeriksaan otomatis ada di `test_aes.py` (20 test) dan `uji_end_to_end.py` (tiga proses nyata). Untuk pemahaman, laporan ini memetakan setiap bagian ke file dan fungsi, menyediakan skrip demo, dan menyediakan tanya-jawab. Yang belum ada adalah rekaman video atau transkrip demo pada tiga perangkat fisik; itu harus dilakukan saat persiapan demo.

**Kode/berkas:** [`test_aes.py`](test_aes.py), [`uji_end_to_end.py`](uji_end_to_end.py), [skrip demo](#10-skrip-demo), [tanya-jawab](#11-tanya-jawab-examiner).

### Ketentuan 8 — Pendaftaran kelompok di spreadsheet

Pendaftaran kelompok adalah tindakan administratif di luar repository. Laporan ini tidak bisa membuktikan bahwa kelompok sudah terdaftar di spreadsheet, karena tidak ada data pendaftaran di repo. Yang bisa dipastikan: repo berisi identitas Naufal Dariskarim (5025231027), dan jika kelompok berisi dua orang, anggota kedua harus ditambahkan sebelum pengumpulan. Tindakan yang masih diperlukan: cek spreadsheet dan isi baris kelompok jika belum.

**Kode/berkas:** tidak ada kode untuk ketentuan ini; status ada di [bagian 13](#13-status-pengumpulan).

### Ketentuan 9 — Pengumpulan melalui Google Form; authorship dan riwayat commit

Repository yang dipakai adalah <https://github.com/Gluttony6547/tugas2-KI>. Pengumpulan dilakukan dengan mengirim link repo melalui Google Form. Authorship harus mencerminkan anggota sebenarnya; jika kelompok, commit tidak boleh hanya berasal dari satu akun. Folder ini sudah memiliki riwayat commit dari pengerjaan DES sebelumnya, lalu penambahan AES/KDC pada working tree. Pada pass dokumentasi ini **belum dilakukan commit/push**, sehingga sebelum submit perubahan harus di-commit dengan akun yang benar. Jangan mengarang commit atau menambahkan akun yang tidak terlibat.

**Kode/berkas:** README, LAPORAN, dan source di folder ini; riwayat Git ada di repo.

### Ketentuan 10 — Demo dan penilaian individual

Demo dapat mengikuti [skrip demo](#10-skrip-demo): tiga terminal, Wireshark, lima langkah handshake, pesan dua arah, `/status`, `/kunci`, dan `/keluar`. Penilaian pemahaman dilakukan individual; karena itu laporan ini menyertakan [tanya-jawab](#11-tanya-jawab-examiner) dan setiap bagian diberi nama fungsi yang bisa ditunjukkan. Penjadwalan ulang bukan kewenangan program/repo; tidak ada tanggal demo yang bisa dijanjikan di sini.

**Kode/berkas:** seluruh source; skrip demo dan Q&A ada di laporan ini.

### Ketentuan 11 — Plagiarisme

Implementasi AES dan KDC ditulis di repository ini. Tidak ada import library kriptografi untuk block cipher: `aes_manual.py` hanya memakai operasi byte, list, dan `os.urandom` untuk IV. KDC memakai `secrets` untuk kunci sesi, sedangkan node memakai `secrets` untuk nonce; JSON dipakai untuk serialisasi dan socket untuk transport. Tidak ada cipher dari library. Kebenaran AES diuji terhadap vektor publik FIPS-197 dan NIST SP 800-38A, sehingga implementasi bisa diperiksa, bukan hanya diklaim. Referensi standar tersebut dicantumkan sebagai acuan algoritma, bukan kode yang disalin.

**Kode/berkas:** [`aes_manual.py`](aes_manual.py), [`test_aes.py`](test_aes.py) (vektor), [`kdc.py`](kdc.py).

### Ketentuan 12 — Fitur tambahan

Fitur tambahan utama adalah **rotasi kunci sesi tanpa restart**:

1. Salah satu node menjalankan `/kunci`.
2. Node meminta sesi baru ke KDC lewat `Node.minta_sesi`; KDC menerbitkan `K_S` baru dan tiket baru.
3. Node mengirim tiket baru ke peer dalam pesan kontrol yang dienkripsi dengan `K_S` lama.
4. Peer membuka tiket dengan kunci master-nya, beralih ke `K_S` baru, dan mengirim konfirmasi dengan kunci baru.
5. Inisiator baru beralih setelah konfirmasi diterima. Selama masa peralihan, `Node.buka_payload` mencoba kunci aktif lalu kunci baru, sehingga pesan lama yang masih memakai kunci lama tidak hilang.

Fitur pendukung: registry sesi KDC (`/sesi`), log bukti per kejadian (`Catatan.tulis`), mode otomatis `--rotasi-setelah`, dan harness tiga proses yang memeriksa ciphertext benar-benar dapat didekripsi menjadi teks yang dikirim. Ini yang bisa dijelaskan sebagai nilai tambah, bukan sekadar tampilan.

**Kode:** [`Node.rotasi_kunci`](protokol.py), [`Node.tangani_kontrol`](protokol.py), [`Node.buka_payload`](protokol.py), [`KDC.tampilkan_sesi`](kdc.py), [`uji_end_to_end.py`](uji_end_to_end.py).

---

## 2. Arsitektur tiga entitas

### 2.1 Diagram

```text
+-------------------------------+        TCP 5000 (target)       +-------------------------------+
| Alice                         |<------------------------------>| KDC                           |
| 127.0.0.3 (IP sumber)         |  (1) ID_A || ID_B || N1         | 127.0.0.2:5000                |
| python node.py --peran alice  |  (2) E_KA[K_S || ID_A || ID_B   | python kdc.py --bind 127.0.0.2|
| --bind 127.0.0.3              |       || N1 || tiket]]          | K_A, K_B, registry sesi       |
+---------------+---------------+                                +-------------------------------+
                |
                |  TCP 5002 (target)
                |  (3) tiket = E_KB[K_S || ID_A || ID_B || waktu]
                |  (4) E_KS[N2]
                |  (5) E_KS[N2-1]
                |  lalu E_KS[pesan] dua arah
                v
+-------------------------------+
| Bob                           |
| 127.0.0.4:5002 (listener)     |
| python node.py --peran bob    |
+-------------------------------+
```

Alamat di atas adalah konfigurasi default untuk uji tiga IP di satu host. Untuk demo tiga mesin, ganti dengan IP LAN masing-masing (contoh di [bagian 6](#6-panduan-menjalankan-tiga-mesin)); bentuk alur dan port tetap sama.

### 2.2 Peran masing-masing proses

| Entitas | Berkas | IP default | Peran jaringan | Kunci yang dipegang |
|---|---|---|---|---|
| KDC | `kdc.py` | `127.0.0.2` | Server TCP, port 5000 | `K_A`, `K_B` |
| Alice | `node.py --peran alice` | `127.0.0.3` | Klien KDC, inisiator koneksi ke Bob; bind sebagai IP sumber | `K_A` |
| Bob | `node.py --peran bob` | `127.0.0.4` | Server TCP, port 5002 | `K_B` |

KDC memuat kedua kunci master di `KDC.__init__`. Setiap node memuat kunci master miliknya sendiri di `Node.__init__`. Tiket untuk Bob dienkripsi dengan `K_B`, sehingga Alice tidak bisa membuka tiket itu; balasan KDC untuk Alice dienkripsi dengan `K_A`, sehingga Bob tidak bisa membuka `K_S` dari balasan tersebut.

### 2.3 Arti `alice.host` setelah perbaikan konfigurasi

Sebelum pass ini, `alice.host` dan `alice.port` hanya metadata: Alice tidak pernah memakainya, sehingga konfigurasi tampak mengatur sesuatu yang sebenarnya tidak terjadi. Sekarang:

- `alice.host` **dipakai** di `Node.__init__` sebagai `self.bind` default untuk peran Alice, lalu diteruskan ke `socket.create_connection(..., source_address=(alice.host, 0))` di `Node.sumber_koneksi`. Jadi IP sumber Alice benar-benar dipilih, bukan diserahkan ke OS.
- `alice.port` **dihapus** dari `konfigurasi.json` karena Alice tidak membuka listener dan port itu tidak pernah dipakai untuk apa pun. Angka acak pada `/status` adalah ephemeral port yang diberikan OS untuk koneksi keluar, bukan nilai konfigurasi.
- `--bind` menimpa `alice.host` bila diberikan. Untuk Bob, `--bind` menentukan alamat listener; `bob.host` tetap menjadi alamat tujuan yang dipakai Alice.
- KDC membuka listener memakai `--bind` (default `0.0.0.0`) dan `--port`/`kdc.port`.

Pada demo tiga mesin, isi `alice.host` dengan IP mesin Alice dan jalankan `--bind` dengan IP yang sama. Pada uji lokal, nilai default `127.0.0.3` sudah cukup. `Node.status` membaca `getsockname()` dari koneksi yang benar-benar terbentuk, sehingga angka yang ditampilkan adalah bukti, bukan nilai konfigurasi yang diulang.

---

## 3. Skenario distribusi kunci lima langkah

### 3.1 Notasi

| Notasi | Arti |
|---|---|
| `ID_A`, `ID_B` | Identitas Alice dan Bob; di konfigurasi default `alice` dan `bob` |
| `K_A`, `K_B` | Kunci master 16 karakter ASCII milik Alice dan Bob; hanya KDC yang memegang keduanya |
| `K_S` | Kunci sesi 16 karakter ASCII yang dibuat KDC untuk satu sesi |
| `N1` | Nonce 32-bit dari Alice, dibuat `secrets.randbits(32)` |
| `N2` | Nonce 32-bit dari Bob, dibuat `secrets.randbits(32)` |
| `E_KA[X]` | AES-CBC atas JSON `X` dengan kunci `K_A`; IV acak disertakan di depan ciphertext |
| `E_KB[X]` | AES-CBC dengan kunci `K_B` |
| `E_KS[X]` | AES-CBC dengan kunci sesi `K_S` |
| `tiket` | `E_KB[K_S, ID_A, ID_B, waktu]`, dibuat KDC untuk Bob |

Semua `E_*` adalah AES-128-CBC dari `ManualAES.enkripsi`: IV 16 byte acak + ciphertext berpadding PKCS#7, lalu dikirim sebagai hex. "||" berarti field-field tersebut digabung dalam satu objek JSON, bukan konkatenasi byte mentah; JSON dipakai agar field dapat diperiksa dan mudah dibaca di Wireshark.

Catatan akurasi: konsol mencetak label singkat `E_KB[K_S, ID_A]`, mengikuti notasi PPT. Isi JSON tiket yang sebenarnya adalah `{ks, id_a, id_b, waktu}`, jadi `ID_B` dan `waktu` juga ikut terenkripsi. `ID_B` dipakai Bob untuk memastikan tiket memang untuk dirinya; `waktu` dicatat tetapi belum divalidasi umurnya.

### 3.2 Diagram urutan pesan

```text
Alice                                      KDC                                      Bob
  |                                         |                                        |
  | (1) ID_A, ID_B, N1  ------------------->|                                        |
  |     (JSON polos)                        |                                        |
  |                                         | buat K_S, sesi S-xxx, tiket E_KB       |
  |<-- (2) E_KA[K_S, ID_A, ID_B, N1, tiket] |                                        |
  |                                         |                                        |
  | (3) tiket E_KB[K_S, ID_A, ID_B, waktu]  ----------------------------------------->|
  |                                         |                          buka tiket    |
  |<--------------------------------------------------------- (4) E_KS[N2] -----------|
  |                                                                                  |
  | (5) E_KS[N2 - 1]  -------------------------------------------------------------->|
  |                                                                                  |
  |<============================== E_KS[pesan] dua arah =============================>|
  |                                                                                  |
```

### 3.3 Rincian tiap langkah

| Langkah | Arah | Isi yang dikirim | Enkripsi | Fungsi |
|---|---|---|---|---|
| 1 | Alice → KDC | `{"tipe":"permintaan_kdc","id_a":...,"id_b":...,"n1":...}` | Tidak ada; ID dan N1 memang terlihat, sesuai skenario | `Node.minta_sesi` |
| 2 | KDC → Alice | `{"tipe":"balasan_kdc","sesi_id":"S-xxx","data":hex}`; `data` berisi `{ks,id_a,id_b,n1,tiket}` | `E_KA` | `KDC.layani_permintaan`; `Node.minta_sesi` |
| 3 | Alice → Bob | `{"tipe":"tiket","dari":"alice","tiket":hex}` | Tiket di dalamnya `E_KB` | `Node.jalankan_alice`; `Node.layani_bob` |
| 4 | Bob → Alice | `{"tipe":"tantangan","data":hex(E_KS[str(N2)])}` | `E_KS` | `Node.layani_bob`; `Node.jalankan_alice` |
| 5 | Alice → Bob | `{"tipe":"konfirmasi","data":hex(E_KS[str(N2-1)])}` | `E_KS` | `Node.jalankan_alice`; `Node.layani_bob` |
| Data | Dua arah | `{"tipe":"pesan","dari":...,"data":hex(E_KS[JSON teks])}` | `E_KS` | `Node.kirim_data`; `Node.tangani_pesan` |

### 3.4 Pemeriksaan yang dilakukan

- KDC menolak `tipe` yang salah, ID yang tidak terdaftar, `ID_A == ID_B`, dan `N1` yang bukan bilangan bulat. Implementasinya di `KDC.layani_permintaan`.
- Alice memeriksa `N1` pada balasan KDC, `ID_A`, `ID_B`, dan memvalidasi bahwa `K_S` adalah 16 karakter ASCII. Implementasinya di `Node.minta_sesi`.
- Bob membuka tiket dengan `K_B` dan memeriksa `id_b == id_diri` sebelum menerima. Implementasinya di `Node.layani_bob`.
- Bob membuat `N2` baru, mengirim `E_KS[N2]`, lalu memeriksa bahwa langkah 5 berisi `N2 - 1`. Ini membuktikan Alice benar-benar memegang `K_S` yang sama dan bukan hanya meneruskan tiket.
- Alice memeriksa tipe pesan langkah 4 (`tantangan`) dan mendekripsi `N2` dengan `K_S` sebelum mengirim langkah 5.

### 3.5 Setelah langkah 5

`Sesi.pasang` menyimpan cipher, `K_S`, ID sesi, lawan, dan peer. Setelah itu `Node.kirim_data` mengenkripsi setiap pesan dengan `E_KS`, dan `Node.terima_loop` mendekripsi pesan masuk dengan kunci aktif. Tidak ada lagi tiket atau kunci master yang dikirim pada percakapan biasa.

---

## 4. Implementasi AES manual

### 4.1 Mengapa manual

Tugas meminta implementasi AES dan KDC secara manual. Karena itu block cipher-nya tidak memanggil library apa pun:

- `aes_manual.py` hanya memakai operasi list/byte, `os.urandom` untuk IV, dan konstanta AES.
- `kdc.py` memakai `ManualAES` untuk tiket dan balasan; `secrets` hanya untuk nonce/kunci sesi, bukan cipher.
- Tidak ada `cryptography`, `pycryptodome`, `Crypto`, OpenSSL, atau `openssl` di source.

`os.urandom` dan `secrets` adalah sumber acak, bukan implementasi AES. Memakai keduanya tidak mengurangi syarat "AES manual".

### 4.2 Key expansion

`ManualAES._perluas_kunci` mengubah 16 byte kunci menjadi 44 word (11 kunci putaran × 4 kolom):

- Empat word pertama adalah kunci asli.
- Untuk setiap word berikutnya, ambil word sebelumnya.
- Setiap kelipatan 4: RotWord (geser byte), SubWord (S-box), lalu XOR dengan `RCON[i//4 - 1]`.
- Word baru = word 4 posisi sebelumnya XOR word sementara.

Hasilnya dipakai sebagai `kunci_putaran[0]` sampai `kunci_putaran[10]`. AES-128 memakai 10 putaran, jadi ada 11 kunci putaran.

### 4.3 SubBytes

`ManualAES._sub_bytes` mengganti setiap byte state dengan nilai dari tabel `SBOX` 256 entri. Untuk dekripsi, `INV_SBOX` dibuat sekali saat modul dimuat:

```python
INV_SBOX = [0] * 256
for _i, _nilai in enumerate(SBOX):
    INV_SBOX[_nilai] = _i
```

Dengan begitu tidak ada tabel kedua yang bisa salah ketik.

### 4.4 ShiftRows dan state

State disimpan sebagai 16 byte dengan urutan kolom-mayor: indeks `baris + 4 * kolom`. `_shift_rows` menggeser baris 1 ke kiri 1, baris 2 ke kiri 2, dan baris 3 ke kiri 3. `_inv_shift_rows` melakukan kebalikannya untuk dekripsi. Representasi ini yang membuat indeks tetap konsisten dengan `MixColumns` dan `AddRoundKey`.

### 4.5 MixColumns

`_mix_columns` mengolah setiap kolom empat byte dengan matriks AES:

```text
[2 3 1 1]
[1 2 3 1]
[1 1 2 3]
[3 1 1 2]
```

Perkalian dilakukan oleh `_kali(a, b)` di GF(2^8) dengan polinomial `0x11B`. Untuk dekripsi, `_inv_mix_columns` memakai koefisien `14, 11, 13, 9`. Implementasi sengaja memakai perkalian generik agar mudah diaudit, bukan tabel perkalian yang besar.

### 4.6 Putaran enkripsi dan dekripsi

`enkripsi_blok` melakukan:

1. `AddRoundKey` dengan kunci putaran 0.
2. Untuk putaran 1–9: SubBytes, ShiftRows, MixColumns, AddRoundKey.
3. Putaran terakhir: SubBytes, ShiftRows, AddRoundKey (tanpa MixColumns).

`dekripsi_blok` menjalankan urutan invers dengan kunci putaran dari 10 ke 0. `enkripsi_blok`/`dekripsi_blok` adalah primitif blok tunggal yang dipakai untuk vektor uji; pesan aplikasi tidak memakai ECB, melainkan CBC di bawah ini.

### 4.7 CBC, IV, dan padding

`ManualAES.enkripsi`:

1. Padding PKCS#7: selalu menambah 1–16 byte sehingga panjang menjadi kelipatan 16. Pesan kosong tetap menghasilkan satu blok.
2. IV 16 byte acak dari `os.urandom(16)`.
3. Setiap blok plaintext di-XOR dengan blok ciphertext sebelumnya (IV untuk blok pertama), lalu dienkripsi.
4. Hasil = IV + ciphertext.

`ManualAES.dekripsi` mengambil 16 byte pertama sebagai IV, mendekripsi blok, melakukan XOR dengan ciphertext sebelumnya, lalu membuang padding. Panjang minimum 32 byte (IV + satu blok), dan padding yang tidak valid menghasilkan `DataTidakValid`.

CBC dipilih karena ECB akan menghasilkan ciphertext yang sama untuk plaintext yang sama; dengan IV acak, pesan yang sama menghasilkan ciphertext berbeda. Ini bukan jaminan integritas: tidak ada MAC, sehingga perubahan ciphertext bisa terdeteksi lewat padding/JSON tetapi bukan jaminan kriptografis.

### 4.8 Aturan ASCII dan hex

- **Kunci:** `ManualAES.__init__` menerima `str` atau `bytes`; `str` di-encode ASCII. Panjang wajib tepat 16 byte. Kunci non-ASCII, kurang, atau lebih menghasilkan `KunciTidakValid`.
- **Kunci sesi:** `buat_kunci_sesi` memilih 16 karakter dari `ascii_letters + digits`; hasilnya selalu ASCII.
- **Plaintext:** pesan dikirim sebagai JSON `{"teks": ...}` lalu di-encode UTF-8. ASCII adalah subset UTF-8, jadi teks ASCII yang diminta tugas berjalan. Program tidak menolak UTF-8; ini batasan yang disebut di bagian 9.
- **Ciphertext:** setiap ciphertext dikonversi dengan `.hex()` sebelum masuk JSON, dicetak di konsol, dan ditulis ke log. Contoh output: `[TERKIRIM] Ciphertext AES (HEX) : 71a32c...`.

### 4.9 Vektor uji

`test_aes.py` memverifikasi:

- **FIPS-197 C.1**: key `000102030405060708090a0b0c0d0e0f`, plaintext `00112233445566778899aabbccddeeff`, ciphertext `69c4e0d86a7b0430d8cdb78070b4c55a` (enkripsi dan dekripsi).
- **NIST SP 800-38A F.2.1 CBC-AES128**: key `2b7e151628aed2a6abf7158809cf4f3c`, IV `000102030405060708090a0b0c0d0e0f`, empat blok plaintext, ciphertext `7649abac...586e1a7`.

Vektor ini adalah bukti bahwa implementasi bukan sekadar "bisa bolak-balik" (fungsi yang salah pun bisa bolak-balik), tetapi cocok dengan standar.

---

## 5. KDC manual dan manajemen kunci

### 5.1 Inisialisasi

`KDC.__init__` menerima dictionary kunci master, lalu membuat `ManualAES` untuk setiap kunci. Kunci master tidak dikirim ke node; KDC hanya mengirim tiket/balasan yang sudah dienkripsi.

`KDC.main` membaca `konfigurasi.json` lewat `konfigurasi.muat`, lalu menimpa kunci dengan `--kunci-alice`/`--kunci-bob` bila diberikan. KDC mendengarkan di `--bind` (default `0.0.0.0`) dan `--port`/`kdc.port`.

### 5.2 Langkah 1–2

`KDC.layani_permintaan` melakukan:

1. Validasi `tipe == "permintaan_kdc"`.
2. Validasi `id_a` dan `id_b` terdaftar; tolak ID sama.
3. Validasi `n1` bilangan bulat.
4. Membuat nomor sesi `S-001`, `S-002`, dan seterusnya.
5. Membuat `K_S` dengan `buat_kunci_sesi()`.
6. Membuat tiket JSON `{ks, id_a, id_b, waktu}`, mengenkripsinya dengan `K_B`, dan menyimpan hex-nya.
7. Membuat balasan JSON `{ks, id_a, id_b, n1, tiket}`, mengenkripsinya dengan `K_A`.
8. Mengembalikan envelope `{"tipe":"balasan_kdc","sesi_id":...,"data":hex}`.
9. Mencatat sesi di `self.sesi` dan menulis log `LANGKAH2`.

`KDC.tangani_koneksi` menangani satu koneksi, mengirim error JSON bila validasi gagal, lalu menutup koneksi. KDC berjalan multi-thread untuk melayani permintaan berikutnya.

### 5.3 Registry dan konsol

Konsol KDC (`KDC.konsol`) menyediakan:

- `/sesi` — daftar sesi yang sudah diterbitkan (ID, waktu, pasangan, `K_S`).
- `/kunci` — menampilkan kunci master yang dipegang KDC (hanya untuk demo).
- `/bantu` — daftar perintah.
- `/keluar` — menghentikan KDC.

`--tanpa-konsol` dipakai pada harness otomatis agar KDC tidak membaca stdin.

### 5.4 Keamanan yang perlu disebut

Ini implementasi untuk memahami protokol, bukan sistem produksi:

- Request langkah 1 tidak diautentikasi; KDC mempercayai `ID_A`/`ID_B` yang dikirim (sifat klasik Needham–Schroeder).
- Tiket memiliki `waktu`, tetapi KDC/tujuan tidak melakukan validasi umur tiket; replay tiket belum dicegah.
- Tidak ada MAC/tanda tangan; CBC hanya memberi kerahasiaan, bukan integritas kriptografis.
- Kunci sesi dan kunci master ditampilkan di konsol/log untuk kebutuhan demo.
- `konfigurasi.json` berisi kedua kunci master; pada deployment nyata, tiap host seharusnya hanya menerima bagiannya sendiri atau memakai flag/env yang sesuai.

Batasan ini disebut lagi di bagian 9.

---

## 6. Panduan menjalankan tiga mesin

### 6.1 Prasyarat

- Python 3.8 atau lebih baru. Proyek hanya memakai standard library; tidak perlu `pip install`.
- Tiga mesin di jaringan yang saling terhubung, misalnya:

| Mesin | Peran | Contoh IP | Port |
|---|---|---|---|
| Mesin 1 | KDC | `192.168.1.10` | 5000 |
| Mesin 2 | Alice | `192.168.1.11` | ephemeral (IP sumber, tidak listen) |
| Mesin 3 | Bob | `192.168.1.12` | 5002 |

- Port 5000 dan 5002 tidak dipakai proses lain. Jika bentrok, ganti dengan `--port`/`--kdc-port`/`--lawan-port`.

### 6.2 Konfigurasi

Salin folder proyek ke ketiga mesin. Di `konfigurasi.json`, sesuaikan host:

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
    "host": "192.168.1.11",
    "kunci_master": "KunciAliceKI2026"
  },
  "bob": {
    "id": "bob",
    "host": "192.168.1.12",
    "port": 5002,
    "kunci_master": "KunciBobKI2026XX"
  },
  "jaringan": {
    "timeout": 15.0
  }
}
```

Nilai kunci harus sama dengan yang dipegang KDC:

- KDC: `kdc.kunci_master.alice = KunciAliceKI2026`, `kdc.kunci_master.bob = KunciBobKI2026XX`.
- Alice: `alice.kunci_master = KunciAliceKI2026`.
- Bob: `bob.kunci_master = KunciBobKI2026XX`.

`alice.host` adalah IP sumber koneksi Alice, bukan alamat listener (lihat 2.3). Tidak ada `alice.port`; port sumber diberikan OS. Yang menentukan tujuan koneksi adalah `kdc.host`, `kdc.port`, `bob.host`, dan `bob.port`.

### 6.3 Urutan menjalankan

**Mesin 1 — KDC:**

```bash
cd "Tugas 2 Keamanan Informasi"
python kdc.py --konfigurasi konfigurasi.json --bind 192.168.1.10
```

KDC mencetak `[MENDENGAR] 192.168.1.10:5000`, kemudian kunci master yang dipegangnya. Jangan tutup terminal.

**Mesin 3 — Bob:**

```bash
cd "Tugas 2 Keamanan Informasi"
python node.py --peran bob --konfigurasi konfigurasi.json --bind 192.168.1.12
```

Bob mencetak `[SIAP] bob mendengarkan di 192.168.1.12:5002`. Bob harus siap sebelum Alice dijalankan.

**Mesin 2 — Alice:**

```bash
cd "Tugas 2 Keamanan Informasi"
python node.py --peran alice --konfigurasi konfigurasi.json --bind 192.168.1.11
```

Alice akan mencetak langkah 1–5, `K_S`, lalu masuk konsol. Bob juga mencetak langkah 3–5 dan `SESI] Terbentuk`. `/status` di Alice harus menampilkan `lokal: 192.168.1.11:<port>` dan peer `192.168.1.12:5002`; di Bob, peer harus `192.168.1.11:<port>`.

### 6.4 Alternatif tanpa mengedit JSON (flag CLI)

Di mesin KDC:

```bash
python kdc.py --bind 192.168.1.10 --port 5000 \
  --kunci-alice "KunciAliceKI2026" --kunci-bob "KunciBobKI2026XX"
```

Di mesin Bob:

```bash
python node.py --peran bob \
  --kdc-host 192.168.1.10 --kdc-port 5000 \
  --bind 192.168.1.12 --port 5002 \
  --kunci "KunciBobKI2026XX"
```

Di mesin Alice:

```bash
python node.py --peran alice \
  --kdc-host 192.168.1.10 --kdc-port 5000 \
  --lawan-host 192.168.1.12 --lawan-port 5002 \
  --bind 192.168.1.11 --kunci "KunciAliceKI2026"
```

### 6.5 Firewall

Jika memakai Windows di mesin KDC/Bob (jalankan sebagai Administrator):

```cmd
netsh advfirewall firewall add rule name="KI KDC 5000" dir=in action=allow protocol=TCP localport=5000
netsh advfirewall firewall add rule name="KI Bob 5002" dir=in action=allow protocol=TCP localport=5002
```

Linux dengan ufw:

```bash
sudo ufw allow 5000/tcp
sudo ufw allow 5002/tcp
```

Pastikan kedua mesin berada di jaringan yang sama dan tidak ada NAT yang memblokir koneksi masuk ke Bob.

### 6.6 Uji tiga IP di satu host (yang benar-benar dijalankan)

Konfigurasi default memakai tiga alamat loopback berbeda, bukan tiga port di `127.0.0.1`. Pada Windows, Linux, dan macOS, seluruh `127.0.0.0/8` dapat dipakai sebagai loopback tanpa menambah alias interface.

```bash
# Terminal 1 — KDC
python kdc.py --bind 127.0.0.2

# Terminal 2 — Bob
python node.py --peran bob --bind 127.0.0.4

# Terminal 3 — Alice
python node.py --peran alice --bind 127.0.0.3
```

Yang harus terlihat:

- KDC: `[MENDENGAR] 127.0.0.2:5000`.
- Bob: `[SIAP] bob mendengarkan di 127.0.0.4:5002`.
- Alice: `/status` menampilkan `lokal: 127.0.0.3:<port>` dan `bob @ 127.0.0.4:5002`.
- Bob: `/status` menampilkan peer `127.0.0.3:<port>`.

Harness otomatis menjalankan urutan ini sendiri, dengan port bebas dan `--bind` eksplisit. Ini bukti tiga IP pada satu host, bukan tiga perangkat fisik.

### 6.7 Perintah konsol

Setelah sesi terbentuk, di sisi Alice atau Bob:

```text
Halo Bob, ini pesan pertama
/kirim Pesan lewat perintah
/status
/kunci
Pesan setelah kunci berganti
/bantu
/keluar
```

`/status` menampilkan IP lokal dan peer yang sebenarnya; gunakan ini untuk menunjukkan bahwa koneksi berjalan antar-IP, bukan hanya satu proses.

---

## 7. Wireshark

### 7.1 Capture yang benar-benar dibuat

Capture **sudah** dilakukan, bukan disiapkan secara teori. File:

- [`bukti/pcap/handshake_chat.pcap`](bukti/pcap/handshake_chat.pcap) — 32 paket, 4.896 byte, format pcapng.
- [`bukti/pcap/analisis.txt`](bukti/pcap/analisis.txt) — keluaran `capinfos` dan `tshark` yang dipakai untuk laporan ini.
- [`bukti/pcap/alice.out`](bukti/pcap/alice.out), [`bob.out`](bukti/pcap/bob.out), [`kdc.out`](bukti/pcap/kdc.out) — output ketiga proses pada run capture.
- [`bukti/pcap/alice.log`](bukti/pcap/alice.log), [`bob.log`](bukti/pcap/bob.log), [`kdc.log`](bukti/pcap/kdc.log) — log per kejadian, termasuk frame TX/RX.

Capture dibuat pada 27 Oktober 2026 pukul 23.58 WIB memakai `tshark` 4.6.9 + Npcap pada interface **loopback** (`\Device\NPF_Loopback`), dengan port tetap supaya filter capture sederhana:

```bash
# Terminal capture
tshark -i \Device\NPF_Loopback \
  -f "tcp port 5000 or tcp port 5002" \
  -w bukti/pcap/handshake_chat.pcap

# Terminal 1
python kdc.py --bind 127.0.0.2

# Terminal 2
python node.py --peran bob --bind 127.0.0.4 --balas "Balasan dari Bob" --jumlah 2

# Terminal 3
python node.py --peran alice --kirim "Pesan uji dari Alice" --jumlah 2 --harap-balasan 2
```

`capinfos` mencatat `Number of packets: 32`, `Capture duration: 0.176 s`, `Interface #0: \Device\NPF_Loopback`, dan SHA256 `34bb5529564ef320fa504a0a5430126378c136e73b5748d982722812935ae0ad`. Ini capture TCP/IP nyata, tetapi pada interface loopback; tidak ada frame Ethernet/Wi-Fi di dalamnya.

### 7.2 Bukti tiga IP di dalam pcap

Sembilan segmen data yang terlihat dengan `tshark -Y "tcp.len > 0"`:

| Frame | Source | Sport | Destination | Dport | Panjang | Isi |
|---:|---|---:|---|---:|---:|---|
| 4 | `127.0.0.3` | 48789 | `127.0.0.2` | 5000 | 80 | langkah 1: `permintaan_kdc` |
| 6 | `127.0.0.2` | 5000 | `127.0.0.3` | 48789 | 731 | langkah 2: `balasan_kdc` |
| 15 | `127.0.0.3` | 48790 | `127.0.0.4` | 5002 | 275 | langkah 3: `tiket` |
| 17 | `127.0.0.4` | 5002 | `127.0.0.3` | 48790 | 101 | langkah 4: `tantangan` |
| 19 | `127.0.0.3` | 48790 | `127.0.0.4` | 5002 | 102 | langkah 5: `konfirmasi` |
| 21 | `127.0.0.3` | 48790 | `127.0.0.4` | 5002 | 178 | pesan Alice #1 |
| 23 | `127.0.0.4` | 5002 | `127.0.0.3` | 48790 | 144 | balasan Bob #1 |
| 25 | `127.0.0.3` | 48790 | `127.0.0.4` | 5002 | 178 | pesan Alice #2 |
| 27 | `127.0.0.4` | 5002 | `127.0.0.3` | 48790 | 144 | balasan Bob #2 |

Tiga alamat IP muncul sebagai Source/Destination, dan arah trafik berbalik dua kali: Alice→KDC, KDC→Alice, Alice→Bob, Bob→Alice, lalu pesan dua arah. Ini yang harus ditunjuk untuk membuktikan "tiga IP", bukan sekadar tiga port di satu alamat.

### 7.3 Filter untuk demo

**Capture filter** (pasang sebelum capture):

```text
tcp port 5000 or tcp port 5002
```

**Display filter**:

```text
tcp.port == 5000 || tcp.port == 5002
```

Filter bantu:

```text
tcp.len > 0                          # hanya segmen yang membawa payload
frame contains "permintaan_kdc"      # langkah 1
frame contains "balasan_kdc"         # langkah 2
frame contains "tiket"               # langkah 3
frame contains "tantangan"           # langkah 4
frame contains "konfirmasi"          # langkah 5
frame contains "pesan"               # percakapan
ip.addr == 127.0.0.3                 # semua paket yang melibatkan Alice
```

Karena pcap ini memakai link type NULL/loopback, kolom Ethernet tidak ada. Pada demo Wi-Fi/Ethernet, pilih interface Wi-Fi/Ethernet dan filter yang sama; field IP/TCP tetap sama.

### 7.4 Payload asli dari pcap

Frame 4, langkah 1. Empat byte pertama adalah header panjang `0000004c` (76 byte); JSON setelahnya polos:

```text
0000004c
7b2274697065223a20227065726d696e7461616e5f6b6463222c202269645f61223a2022616c696365222c202269645f62223a2022626f62222c20226e31223a20333935313235343637347d
```

Didekode menjadi:

```json
{"tipe": "permintaan_kdc", "id_a": "alice", "id_b": "bob", "n1": 3951254674}
```

Frame 6, langkah 2. Awal payload:

```text
000002d7
7b2274697065223a202262616c6173616e5f6b6463222c2022736573695f6964223a2022532d303031222c202264617461223a202237393064343636306630333235376131303566313266633730623832303466636164633338623237326165...
```

Artinya: header `0x2d7` = 727 byte payload, lalu JSON `{"tipe": "balasan_kdc", "sesi_id": "S-001", "data": "790d4660f03257a105f12fc70b8204fcadc38b272ae..."}`. Yang terlihat hanya envelope dan `sesi_id`; isi `data` adalah ciphertext `E_KA[...]`, bukan `K_S` dalam teks.

Frame 21, pesan Alice pertama. Payload lengkap:

```text
000000ae
7b2274697065223a2022706573616e222c202264617269223a2022616c696365222c202264617461223a2022343037653538633364306538363463656564656332643334303537393035623331366363393634623030336333343632346536356234313930356634363366383236316130366131653734373331383138386666393535363365303765346434643734333439346334373937613534336135383464363166373065227d
```

Didekode menjadi:

```json
{"tipe": "pesan", "dari": "alice", "data": "407e58c3d0e864ceedec2d34057905b316cc964b003c34624e658a0b0dc0bc4b6e71bffe9caa95c835b8e2ff2811a0ea6e70aaedc772c9a7d52f0ec4daaf1cef"}
```

Field `data` berisi 128 karakter hex = 64 byte: IV 16 byte + dua blok ciphertext 16 byte (plaintext pendek + padding PKCS#7). Plaintext `"Pesan uji dari Alice"` **tidak muncul** di payload. Sebaliknya, frame 23 dan 27 berisi balasan Bob dengan ciphertext berbeda, membuktikan arah sebaliknya juga terenkripsi.

### 7.5 Yang harus ditunjuk saat demo

| Yang ditunjuk | Di mana | Penjelasan |
|---|---|---|
| Tiga alamat IP | Kolom Source/Destination, frame 4/6/15/17 | Alice `127.0.0.3`, KDC `127.0.0.2`, Bob `127.0.0.4` |
| Langkah 1 | Frame 4 | `id_a`, `id_b`, `n1` polos; memang tidak dienkripsi |
| Langkah 2 | Frame 6 | `sesi_id`, field `data` hex `E_KA[...]` |
| Langkah 3 | Frame 15 | Field `tiket` hex `E_KB[K_S, ID_A, ID_B, waktu]` |
| Langkah 4/5 | Frame 17/19 | `E_KS[N2]` dan `E_KS[N2-1]`, masing-masing 64 byte hex |
| Pesan dua arah | Frame 21/23/25/27 | `tipe: "pesan"`, `data` ciphertext; arah bergantian |
| Panjang ciphertext | Field `tcp.len` dan isi `data` | IV + padding membuat ciphertext lebih panjang dari plaintext |

### 7.6 Catatan kejujuran

Capture ini **nyata**, tetapi dari interface loopback pada satu host. Ia membuktikan tiga alamat IP, TCP, envelope JSON, dan ciphertext di on-wire stack; ia **tidak** membuktikan tiga perangkat fisik atau frame Wi-Fi. Untuk demo kelas, ulangi capture pada interface Wi-Fi/Ethernet dengan filter yang sama dan simpan file baru; jangan menyebut pcap loopback sebagai capture jaringan nirkabel.

---

## 8. Hasil pengujian

### 8.1 Unit test AES dan KDC

Perintah:

```bash
python -m unittest test_aes -v
```

Hasil terakhir: **20 test, OK**, exit code 0. Bukti: [`bukti/unit_aes_out.txt`](bukti/unit_aes_out.txt).

| Kelompok | Jumlah | Isi |
|---|---:|---|
| `UjiVektorAES` | 3 | FIPS-197 enkripsi, FIPS-197 dekripsi, NIST SP 800-38A CBC |
| `UjiModeCBC` | 5 | Roundtrip berbagai panjang, UTF-8, IV acak, panjang kelipatan blok, ciphertext tidak memuat plaintext |
| `UjiValidasiKunci` | 7 | Kunci 16 ASCII diterima, pendek, panjang, non-ASCII, blok salah ukuran, ciphertext terpotong, padding rusak |
| `UjiKDC` | 4 | Balasan langkah 2 berisi `K_S`/tiket, ID tidak dikenal ditolak, ID sama ditolak, `K_S` berbeda tiap permintaan |
| `UjiKonfigurasi` | 1 | Kunci valid, tiga host KDC/Alice/Bob berbeda, port KDC/Bob berbeda |

### 8.2 Uji end-to-end tiga proses, tiga IP

Perintah:

```bash
python uji_end_to_end.py
```

Hasil terakhir: **LULUS**, exit code 0. Bukti: [`bukti/e2e_hasil.txt`](bukti/e2e_hasil.txt) dan folder [`bukti/e2e/20261027-234923/`](bukti/e2e/20261027-234923/).

| Skenario | Isi | Hasil | Bukti |
|---|---|---|---|
| `dasar` | Alice mengirim 2 pesan, Bob membalas 2 kali | 2 diterima Alice, 2 diterima Bob, exit 0 | `dasar/alice.out`, `dasar/bob.out`, `dasar/*.log` |
| `rotasi` | Alice mengirim 3 pesan; rotasi kunci setelah pesan #2; Bob membalas 3 kali | 3 diterima, 3 balasan, kunci berubah, exit 0 | `rotasi/alice.out`, `rotasi/bob.out`, `rotasi/*.log` |
| `negatif_kunci_salah` | Alice memakai `KunciSalahSekali`, bukan `KunciAliceKI2026` | Alice gagal membuka balasan KDC, exit 3 | `negatif_kunci_salah/alice.out` |

Angka konkret dari run 27 Oktober 2026 23.11:

- Skenario `dasar`: `K_S = faxB1QYMhpNNLWS8`, sesi KDC `S-001`. Alice mencetak `lokal: 127.0.0.3:12259` dan `bob @ 127.0.0.4:12253`; hasil `2 pesan terkirim, 2 balasan diterima`.
- Skenario `rotasi`: `K_S` awal `QwqUcV0VMi9MlQxi`, setelah rotasi `gIjRjfGYFxzKYFD9`. Alice mencetak `[HASIL] Rotasi kunci setelah pesan #2 berhasil` dan `3 pesan terkirim, 3 balasan diterima`. Bob mencatat `KUNCI_BARU` dengan kunci baru.
- Skenario negatif: `[ERROR] Handshake gagal: gagal membuka balasan KDC dengan kunci master`, exit code 3.

### 8.3 Bukti tiga IP dari log dan `/status`

Harness tidak hanya menghitung pesan. Sejak pass ini, `periksa_umum` juga memeriksa:

- `[STATUS] lokal         : 127.0.0.3:` ada di output Alice.
- `[STATUS] lokal         : 127.0.0.4:` ada di output Bob.
- `PEER=127.0.0.3:` muncul di log KDC (langkah 1) dan log Bob (langkah 3).
- `PEER=127.0.0.4:` muncul di log Alice (langkah 3–5 dan pesan).

Contoh baris nyata dari [`bukti/e2e/20261027-234923/dasar/kdc.log`](bukti/e2e/20261027-234923/dasar/kdc.log):

```text
EVENT=MENDENGAR INFO=bind=127.0.0.2:12252
EVENT=FRAME_RX PEER=127.0.0.3:12258 LEN=80 HEX=0000004c7b2274697065223a...
EVENT=LANGKAH1 PEER=127.0.0.3:12258 TXT='id_a=alice id_b=bob n1=...'
```

Dari [`dasar/alice.out`](bukti/e2e/20261027-234923/dasar/alice.out):

```text
[STATUS] lawan         : bob @ 127.0.0.4:12253
[STATUS] lokal         : 127.0.0.3:12259
```

Jadi bukan sekadar konfigurasi: socket Alice benar-benar memakai `127.0.0.3`, socket Bob `127.0.0.4`, dan KDC melihat sumber `127.0.0.3`.

### 8.4 Apa yang benar-benar diperiksa harness

`uji_end_to_end.py` menjalankan KDC, Bob, dan Alice sebagai proses terpisah:

- KDC dijalankan dengan `--bind 127.0.0.2`; Bob dengan `--bind 127.0.0.4`; Alice memakai `alice.host = 127.0.0.3` sebagai IP sumber.
- Menunggu KDC dan Bob siap lewat log `EVENT=MENDENGAR`.
- Memeriksa jumlah `[DITERIMA #]` dan `[TERKIRIM] Ciphertext AES` di kedua sisi.
- Memeriksa log memuat `LANGKAH1`–`LANGKAH5` dan frame TX/RX.
- Mengambil `K_S` dari log `EVENT=SESI`, mengambil ciphertext pertama dari `EVENT=TX`, mendekripsinya dengan `ManualAES`, lalu membandingkan hasilnya dengan teks yang dikirim (`periksa_ciphertext`).
- Membandingkan ciphertext TX Alice dengan ciphertext RX Bob.
- Memeriksa rotasi benar-benar mengganti `K_S` dan Bob mencatat `KUNCI_BARU`.
- Memeriksa kasus kunci salah berhenti dengan exit code 3.

Angka "20 test" bukan klaim kriptografi; yang membuktikan AES adalah vektor FIPS/NIST, sedangkan harness membuktikan jalur jaringan, protokol, dan alamat IP.

### 8.5 Capture pcap

Capture terpisah dijalankan dengan port tetap 5000/5002 agar filter capture sederhana. Hasilnya [`bukti/pcap/handshake_chat.pcap`](bukti/pcap/handshake_chat.pcap): 32 paket, 9 segmen data, tiga IP, dan ciphertext AES di dalam field `data`. Rincian dan payload hex ada di [bagian 7](#7-wireshark).

### 8.6 Yang tidak dihitung sebagai bukti otomatis

- Uji interaktif console dijalankan setelah pemisahan modul dan transkripnya disimpan di [`bukti/konsol_interaktif.txt`](bukti/konsol_interaktif.txt): pesan biasa, `/status`, `/kunci`, pesan setelah rotasi, `/status` kedua, lalu `/keluar`, dengan exit code 0 di Alice dan Bob.
- Tiga perangkat fisik belum dijalankan; yang sudah ada adalah tiga IP pada satu host dan pcap loopback.
- Workflow GitHub Actions sudah diubah untuk menjalankan `test_aes.py` dan `uji_end_to_end.py`, tetapi belum ada bukti run CI dari pass ini karena perubahan belum di-commit/push.

---

## 9. Batasan dan hal yang belum dikerjakan

1. **Tiga perangkat fisik belum dijalankan.** Tiga IP sudah dibuktikan dengan tiga proses nyata di satu host (`127.0.0.2`, `127.0.0.3`, `127.0.0.4`), tetapi belum pada tiga komputer terpisah. Jangan menyebut uji ini sebagai demo tiga mesin fisik.
2. **Capture berasal dari interface loopback.** Pcap membuktikan tiga alamat IP, TCP, envelope JSON, dan ciphertext, tetapi bukan frame Wi-Fi/Ethernet. Capture pada interface jaringan sungguhan harus dibuat saat demo.
3. **Transkrip interaktif tidak diarsipkan.** Console sudah dipakai saat pengembangan, tetapi tidak ada file transkrip permanen. Skrip demo disediakan untuk mengulang.
4. **Alice tidak membuka listener.** `alice.host` hanya menentukan IP sumber; tidak ada `alice.port`. Ini disengaja, bukan field konfigurasi yang tidak terpakai. Alice menerima balasan pada koneksi keluar yang sama.
5. **Rotasi kunci master tidak live.** Yang bisa diubah tanpa restart adalah kunci sesi lewat `/kunci`. `K_A`/`K_B` memerlukan restart atau flag baru.
6. **Plaintext menerima UTF-8.** Kunci dipaksa ASCII, tetapi plaintext tidak menolak non-ASCII. Untuk strictly ASCII, validasi tambahan belum ada.
7. **Kunci master ada di satu `konfigurasi.json`.** Pada deployment nyata, tiap host sebaiknya hanya memegang kuncinya sendiri; file bersama membuat setiap host yang membaca file bisa melihat kedua kunci.
8. **Tidak ada MAC/timestamp/replay protection.** CBC memberi kerahasiaan, bukan integritas; tiket punya `waktu` tetapi tidak divalidasi umurnya.
9. **Kunci dan `K_S` dicetak ke konsol/log.** Untuk demo ini disengaja; jangan dipakai di produksi.
10. **Pemisahan modul baru pada pass ini.** Protokol handshake/transport ada di `protokol.py`, tampilan/konsol/mode otomatis di `konsol.py`, keadaan sesi di `sesi.py`, dan `node.py` tinggal CLI, `__init__`, serta `main`. Metodenya masih dipakai lewat `Node` (mixin), jadi penjelasan saat demo tetap boleh menyebut `Node.minta_sesi` dan seterusnya.
11. **File DES sudah dibersihkan.** Seluruh berkas tugas 1 (DES) — `cipher_manual.py`, `sender_node-v3.py`, `receiver_node-v3.py`, `test_des.py`, `transport.py`, `uji_lintas_mesin.py`, `PANDUAN_PENGUJIAN.md`, `HASIL_PENGUJIAN.md`, `README_DES_SEBELUMNYA.md`, beserta bukti uji DES di `bukti/` — dihapus dari repository agar isinya hanya AES/KDC. Riwayat lengkapnya masih ada di history commit, dan folder `PPT/` dipindahkan dari git ke lokal (bagian `.gitignore`) untuk memangkas ukuran repository.
12. **Commit/push dilakukan setelah pembersihan.** Semua perubahan pass ini di-commit setelah seluruh uji lulus.

---

## 10. Skrip demo

Durasi target: 6–8 menit. Siapkan tiga terminal dan Wireshark sebelum mulai. Jika hanya ada satu laptop, demo tetap bisa berjalan dengan tiga IP loopback `127.0.0.2/3/4`; pcap [`bukti/pcap/handshake_chat.pcap`](bukti/pcap/handshake_chat.pcap) bisa dipakai sebagai cadangan.

### Persiapan (sebelum masuk kelas)

- Isi `konfigurasi.json` dengan tiga IP mesin (atau pakai default loopback untuk satu laptop).
- Pastikan port 5000/5002 terbuka di firewall.
- Jalankan `python -m unittest test_aes -v` sekali untuk memastikan environment.
- Buka Wireshark di mesin Alice/Bob, pilih interface yang benar (Wi-Fi/Ethernet untuk tiga mesin, loopback untuk satu laptop), isi capture filter `tcp port 5000 or tcp port 5002`, mulai capture.
- Siapkan terminal KDC, Bob, Alice; jangan jalankan Alice dulu.

### Demo

1. **Tunjukkan IP tiga entitas (30 detik).** Di tiap mesin jalankan `ipconfig` (Windows) atau `ip a` (Linux). Tunjukkan `192.168.1.10` (KDC), `192.168.1.11` (Alice), `192.168.1.12` (Bob). Jika memakai satu laptop, tunjukkan `127.0.0.2`, `127.0.0.3`, `127.0.0.4` di `/status` dan pcap. Buka `konfigurasi.json`, tunjukkan `kdc.host`, `bob.host`, dan `alice.host`.

2. **Jalankan KDC (30 detik).** Di mesin KDC:
   ```bash
   python kdc.py --konfigurasi konfigurasi.json --bind 192.168.1.10
   ```
   Jelaskan: KDC memegang `K_A` dan `K_B`; kunci tidak dikirim ke jaringan. Tunjukkan `[MENDENGAR]`.

3. **Jalankan Bob (30 detik).** Di mesin Bob:
   ```bash
   python node.py --peran bob --konfigurasi konfigurasi.json --bind 192.168.1.12
   ```
   Tunjukkan `[SIAP] ...:5002`. Bob belum punya `K_S`; ia menunggu tiket.

4. **Jalankan Alice (1 menit).** Di mesin Alice:
   ```bash
   python node.py --peran alice --konfigurasi konfigurasi.json --bind 192.168.1.11
   ```
   Tunjukkan langkah 1–5:
   - Langkah 1: `ID_A`, `ID_B`, `N1`.
   - Langkah 2: `sesi=S-001`, `K_S`, ciphertext hex.
   - Langkah 3: tiket hex yang dikirim ke Bob.
   - Langkah 4: `E_KS[N2]` dari Bob.
   - Langkah 5: `E_KS[N2-1]` dari Alice.
   Jelaskan bahwa Bob baru bisa membuka tiket dengan `K_B`, dan langkah 5 membuktikan Alice memegang `K_S`.

5. **Tunjukkan Wireshark (1 menit).** Pilih paket langkah 1: `id_a`, `id_b`, `n1` terlihat. Pilih balasan KDC: `data` hex. Pilih langkah 3: `tiket` hex. Pilih langkah 4/5: `data` hex. Tunjukkan tiga IP di kolom Source/Destination. Tekankan: metadata terlihat, isi rahasia tidak. Jika capture live gagal, buka `bukti/pcap/handshake_chat.pcap` dan tunjukkan frame 4, 6, 15, 17, 19, 21, 23.

6. **Kirim pesan dua arah (1 menit).** Di Alice ketik:
   ```text
   Halo Bob, ini pesan dari Alice
   ```
   Tunjukkan ciphertext hex di Alice, lalu plaintext di Bob. Balas dari Bob:
   ```text
   Halo Alice, pesan diterima
   ```
   Tunjukkan Alice menerima balasan. Ini membuktikan dua arah, bukan hanya Alice→Bob.

7. **Tunjukkan status (30 detik).** Di Alice ketik `/status`. Tunjukkan IP lokal (`192.168.1.11` atau `127.0.0.3`), peer (`192.168.1.12:5002` atau `127.0.0.4:5002`), sesi KDC, `K_S`, TX/RX. Ini menunjukkan IP yang benar-benar dipakai socket, bukan hanya isi konfigurasi.

8. **Rotasi kunci (1 menit).** Di Alice ketik `/kunci`. Tunjukkan:
   - Alice meminta sesi baru ke KDC.
   - Tiket baru dikirim dengan kunci lama.
   - Bob mencetak `[KUNCI] Lawan mengganti kunci sesi` dan `K_S` baru.
   - Alice mencetak konfirmasi dan kunci baru aktif.
   Kirim satu pesan lagi; tunjukkan ciphertext baru masih bisa dibuka. Jelaskan kunci lama ditahan sampai konfirmasi agar pesan yang masih di jaringan tidak hilang.

9. **Tutup dengan rapi (30 detik).** `/keluar` di Alice dan Bob. Hentikan capture Wireshark dan simpan `.pcapng` jika diminta.

10. **Opsional — kasus negatif (1 menit).** Di mesin Alice, jalankan dengan `--kunci "KunciSalahSekali"` (16 ASCII). Tunjukkan Alice gagal membuka balasan KDC dan keluar dengan kode 3. Ini membuktikan validasi kunci, tetapi jangan lakukan sebelum demo utama agar waktu tidak habis.

### Kalimat pembuka yang disarankan

> "Ini implementasi AES-128 dan KDC manual. Tiga proses berjalan di tiga IP. KDC hanya mengirim tiket yang dienkripsi dengan kunci master masing-masing; Alice tidak pernah tahu `K_B`, Bob tidak pernah tahu `K_A`. Setelah lima langkah Needham–Schroeder, keduanya memakai `K_S` untuk AES dua arah. Saya akan tunjukkan langkahnya di terminal dan paketnya di Wireshark."

---

## 11. Tanya-jawab examiner

**1. Kenapa AES-nya ditulis sendiri, bukan pakai library?**
Karena tugas meminta implementasi manual. `aes_manual.py` memuat key expansion, S-box, ShiftRows, MixColumns, AddRoundKey, CBC, dan padding; tidak ada import library cipher. `test_aes.py` mencocokkan hasilnya dengan FIPS-197 dan NIST SP 800-38A.

**2. Kenapa memakai CBC, bukan ECB?**
ECB menghasilkan ciphertext sama untuk plaintext sama, sehingga pola pesan terlihat. CBC memakai IV acak per pesan; IV dikirim di depan ciphertext. CBC di sini tidak memberi integritas karena tidak ada MAC.

**3. Dari mana Bob tahu `K_S`?**
Dari tiket `E_KB[K_S || ID_A || ID_B || waktu]` yang dibuat KDC. Hanya Bob yang punya `K_B` untuk membukanya. Alice menerima `K_S` dari balasan KDC yang dienkripsi dengan `K_A`.

**4. Apa fungsi `N1` dan `N2`?**
`N1` mengikat balasan KDC ke permintaan Alice dan mendeteksi balasan lama. `N2` adalah tantangan Bob; Alice harus mengembalikan `N2 - 1` dengan `K_S`, membuktikan ia memegang kunci sesi yang sama dan sesi masih hidup.

**5. Apa yang dienkripsi dengan kunci apa?**
Langkah 2: `E_KA` untuk balasan Alice; tiket di dalamnya `E_KB`. Langkah 3: tiket `E_KB`. Langkah 4 dan 5: `E_KS`. Pesan biasa: `E_KS`. Langkah 1 sengaja polos (ID dan N1), sesuai skenario.

**6. Bagaimana jika kuncinya salah?**
Balasan KDC tidak bisa dibuka dengan kunci master yang salah; padding/JSON gagal dan `Node.minta_sesi` melempar `ProtokolError`. Ini diuji di skenario negatif dengan `KunciSalahSekali` dan exit code 3. Untuk pesan, kunci sesi yang salah menghasilkan `DataTidakValid`.

**7. Bagaimana rotasi kunci bekerja dan kenapa tidak kehilangan pesan?**
`/kunci` meminta `K_S` baru ke KDC, mengirim tiket baru dengan kunci lama, lalu menahan kunci lama sampai peer mengonfirmasi. `Node.buka_payload` mencoba kunci aktif lalu kunci baru selama peralihan. Setelah konfirmasi, kunci baru menjadi aktif di kedua sisi.

**8. Apakah KDC diautentikasi?**
Balasan KDC dienkripsi dengan `K_A`/`K_B`, jadi hanya pemegang kunci master yang bisa membacanya. Namun request langkah 1 tidak diautentikasi; KDC mempercayai ID yang dikirim. Ini sifat skenario klasik, bukan sistem produksi.

**9. Kenapa kunci 16 karakter?**
AES-128 membutuhkan 128 bit = 16 byte. Tugas meminta format ASCII, jadi 16 karakter ASCII adalah representasi paling langsung. Kunci sesi juga 16 karakter ASCII agar konsisten.

**10. Kenapa ciphertext lebih panjang dari plaintext?**
Ada IV 16 byte di depan dan padding PKCS#7 sampai kelipatan 16. Pesan pendek bisa menjadi 32 byte ciphertext (64 karakter hex); pesan yang lebih panjang bertambah per blok.

**11. Bagaimana membuktikan tiga IP, bukan hanya satu mesin?**
Ada dua lapis bukti. Pertama, uji otomatis menjalankan KDC `127.0.0.2`, Alice `127.0.0.3`, Bob `127.0.0.4`; `/status` dan log menunjukkan alamat itu, dan `bukti/pcap/handshake_chat.pcap` memperlihatkannya di Source/Destination. Kedua, saat demo tiga mesin, tunjukkan `ipconfig`/`ip a` di tiap mesin dan ulangi `/status` dengan IP LAN. Yang belum dibuktikan sampai sekarang adalah tiga perangkat fisik, jadi sebutkan batas itu dengan jujur.

**12. Apa fitur tambahan di luar minimum?**
Rotasi kunci sesi tanpa restart dengan masa peralihan kunci lama, registry sesi KDC, log bukti, dan harness tiga proses yang memeriksa ciphertext benar-benar dapat didekripsi. Yang paling layak ditonjolkan adalah rotasi kunci.

**13. Apa kelemahan implementasi ini?**
Tidak ada MAC/tanda tangan, tiket tidak divalidasi umurnya, request KDC tidak diautentikasi, kunci master ada di satu file konfigurasi, dan kunci ditampilkan di konsol/log untuk demo. Ini bukan sistem produksi.

**14. Mengapa kode dipecah menjadi beberapa modul?**
Supaya tiap tanggung jawab punya satu tempat: handshake dan transport di `protokol.py`, tampilan/konsol dan mode otomatis di `konsol.py`, keadaan sesi di `sesi.py`, sedangkan `node.py` hanya menyimpan CLI, `Node.__init__`, dan `main`. Kelas `Node` tetap menjadi satu-satunya kelas yang dijalankan (`class Node(ProtokolNode, KonsolNode)`), jadi alur demo tidak berubah.

---

## 12. Peta berkas dan fungsi

| Berkas | Isi | Fungsi/kelas penting |
|---|---|---|
| [`aes_manual.py`](aes_manual.py) | AES-128 manual, CBC, padding, validasi kunci | `ManualAES`, `ManualAES._perluas_kunci`, `_sub_bytes`, `_shift_rows`, `_mix_columns`, `_add_round_key`, `enkripsi_blok`, `dekripsi_blok`, `enkripsi_cbc`, `dekripsi_cbc`, `enkripsi`, `dekripsi` |
| [`kdc.py`](kdc.py) | KDC, langkah 1–2, registry, console | `buat_kunci_sesi`, `KDC.__init__`, `KDC.layani_permintaan`, `KDC.tangani_koneksi`, `KDC.jalankan`, `KDC.tampilkan_sesi`, `KDC.konsol`, `main` |
| [`node.py`](node.py) | CLI, `Node.__init__`, `main` | `baca_argumen`, `siapkan_stdout`, `Node`, `Node.__init__`, `main` |
| [`protokol.py`](protokol.py) | Handshake langkah 1–5, transport, rotasi kunci | `ProtokolError`, `ProtokolNode`, `ProtokolNode.sumber_koneksi`, `minta_sesi`, `kirim_data`, `buka_payload`, `tangani_pesan`, `tangani_kontrol`, `rotasi_kunci`, `terima_loop`, `jalankan_alice`, `layani_bob`, `dengarkan`, `jalankan_bob` |
| [`konsol.py`](konsol.py) | Tampilan, mode otomatis, konsol interaktif | `KonsolNode`, `cetak`, `blok`, `status`, `mode_otomatis_alice`, `mode_otomatis_bob`, `konsol`, `tutup` |
| [`sesi.py`](sesi.py) | Keadaan sesi bersama konsol dan thread penerima | `Sesi`, `Sesi.pasang`, `Sesi.lepas` |
| [`jaringan.py`](jaringan.py) | Framing TCP 4 byte, JSON, log | `kirim_pesan`, `terima_pesan`, `kirim_json`, `terima_json`, `Catatan.tulis`, `endpoint` |
| [`konfigurasi.py`](konfigurasi.py) | Membaca dan memvalidasi JSON | `muat`, `KonfigurasiError` |
| [`konfigurasi.json`](konfigurasi.json) | IP, port, kunci master | Bagian `kdc`, `alice`, `bob`, `jaringan` |
| [`test_aes.py`](test_aes.py) | 20 unit test | `UjiVektorAES`, `UjiModeCBC`, `UjiValidasiKunci`, `UjiKDC`, `UjiKonfigurasi` |
| [`uji_end_to_end.py`](uji_end_to_end.py) | Harness tiga proses | `jalankan_skenario`, `jalankan_negatif`, `periksa_umum`, `periksa_ciphertext`, `main` |
| [`.github/workflows/test.yml`](.github/workflows/test.yml) | CI Windows + Ubuntu | Menjalankan `python -m unittest test_aes -v` dan `python uji_end_to_end.py` |
| [`README.md`](README.md) | Entry point Tugas 2 | Ringkasan, quick start, tautan PANDUAN_TESTING_DUA_MESIN.md |
| [`LAPORAN.md`](LAPORAN.md) | Laporan ini | 12 ketentuan, diagram, hasil, demo |

Bukti uji DES lama sudah dihapus dari `bukti/` bersama berkas DES; hanya bukti AES/KDC yang tersisa (unit test, E2E, konsol, pcap).

---

## 13. Status pengumpulan

| Item | Status |
|---|---|
| Kode AES + KDC | Ada di folder ini |
| Unit test | 20 lulus, bukti `bukti/unit_aes_out.txt` |
| E2E tiga IP (satu host) | 3 skenario lulus, bukti `bukti/e2e/20261027-234923/` dan `bukti/e2e_hasil.txt` |
| Tiga perangkat fisik | **Belum dijalankan** |
| Capture Wireshark | **Ada**, `bukti/pcap/handshake_chat.pcap` (interface loopback) |
| Laporan Markdown | Selesai di `LAPORAN.md` |
| README Tugas 2 | Selesai di `README.md` |
| Panduan dua terminal (desktop + VM) | Selesai di `PANDUAN_TESTING_DUA_MESIN.md` |
| Commit/push | **Belum dilakukan pada pass ini** |
| Pendaftaran kelompok | Harus dicek di spreadsheet; tidak bisa dibuktikan dari repo |
| Pengumpulan Google Form | Harus dilakukan setelah commit/push |

Checklist sebelum submit:

1. Jalankan demo tiga mesin dan capture pada interface Wi-Fi/Ethernet; simpan bukti baru ke `bukti/`.
2. Cek `konfigurasi.json` di tiap mesin (IP dan kunci benar), lalu jalankan dengan `--bind` sesuai IP mesin.
3. Commit dan push dengan akun anggota yang benar; jangan memakai akun orang lain.
4. Pastikan README menampilkan Tugas 2, bukan DES.
5. Kirim link repo melalui Google Form sebelum deadline.

---

## Lisensi dan tujuan

Dokumen dan kode ini dibuat untuk tugas mata kuliah Keamanan Informasi. Implementasi ini bersifat edukatif: jangan dipakai untuk melindungi data nyata tanpa audit kriptografi, MAC, manajemen kunci yang aman, dan perlindungan replay.
