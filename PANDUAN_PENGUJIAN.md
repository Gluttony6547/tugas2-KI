# Panduan Pengujian DES 2 Arah — Lintas OS, Lintas IP

Dokumen ini menjadi acuan pengujian tugas komunikasi terenkripsi DES. Syarat utama yang dibuktikan: **program berjalan di dua sistem operasi berbeda dengan alamat IP berbeda**, saling mengirim pesan terenkripsi dua arah, dan hasilnya dapat diverifikasi.

## 1. Berkas yang dipakai

| Berkas | Fungsi |
|---|---|
| `cipher_manual.py` | Implementasi manual DES (16 putaran Feistel, S-Box, PKCS#7). Tanpa library kriptografi. |
| `transport.py` | Framing TCP (4 byte panjang + payload) dan pencatat bukti uji. |
| `receiver_node-v3.py` | Node A: server TCP, mendekripsi pesan masuk, mengirim balasan. |
| `sender_node-v3.py` | Node B: client TCP, mengenkripsi pesan, menerima balasan. |
| `test_des.py` | 17 uji otomatis: vektor DES, padding, framing, dan dua proses end-to-end. |
| `uji_lintas_mesin.py` | Otomatisasi lintas mesin: receiver di VM lewat SSH, sender lokal, bukti dan exit code kedua sisi. |

**PSK:** `KunciDES` (tepat 8 byte). Kunci tidak pernah dikirim lewat socket; kedua mesin harus memakai nilai yang sama. Ubah lewat `--key` atau variabel lingkungan `DES_PSK`.

### Mengapa ada framing

`recv(4096)` tidak menjaga batas pesan. Dua pesan yang tiba berdekatan bisa tergabung dalam satu `recv()`, dan ciphertext DES yang terpotong menghasilkan plaintext rusak. Karena itu setiap pesan diberi penanda panjang 4 byte. Pengujian T6 di bawah membuktikan 50 pesan beruntun tetap utuh.

## 2. Prasyarat di kedua mesin

- Python 3.8 atau lebih baru, tanpa paket tambahan.
- Ketiga berkas `.py` (cipher, transport, node) berada di folder yang sama.
- Port 65432 (atau port lain yang Anda pilih) tidak dipakai proses lain.

Salin berkas ke mesin kedua dengan salah satu cara:

```bash
# Dari Windows, sediakan folder lewat HTTP lalu unduh di Linux
python -m http.server 8000
# Di VM Linux
wget http://192.168.207.1:8000/cipher_manual.py
```

Atau gunakan `scp`, folder shared VMware, atau flashdisk.

## 3. Topologi pengujian

### Skenario A — VM Linux NAT (paling mudah, dipakai di panduan ini)

```
Windows 11 (sender) 192.168.1.3 / VMnet8 192.168.207.1
        |
        |  VMnet8 (NAT)
        v
VM Linux (receiver) 192.168.207.128
```

Cek IP masing-masing:

```bash
# Windows
ipconfig
# Linux
ip a
```

Windows dapat menghubungi guest lewat `192.168.207.x` tanpa port forwarding. Arah sebaliknya (Linux → Windows) memakai IP host di VMnet8, yaitu `192.168.207.1`.

### Skenario B — Bridged

VM memakai jaringan fisik sehingga mendapat IP `192.168.1.x`. Kedua arah bisa dimulai dari mesin mana pun, dan ini skenario paling meyakinkan untuk syarat "beda OS, beda IP".

### Skenario C — Dua perangkat fisik

Laptop Windows dan laptop Linux/macOS pada Wi-Fi yang sama. Sama seperti skenario B, tanpa virtualisasi.

### Skenario D — WSL2 Ubuntu di laptop yang sama

WSL2 menjalankan kernel Linux dengan alamat IP sendiri (contoh `172.20.236.11`), jadi syarat beda OS dan beda IP tetap terpenuhi tanpa VM terpisah.

```bash
# Windows: cek distro dan IP Linux
wsl -l -v
wsl -e hostname -I
```

Receiver di WSL (folder proyek terlihat di `/mnt/c/...`):

```bash
cd "/mnt/c/SMT_7/Keamanan Informasi/Tugas 2 Keamanan Informasi"
python3 receiver_node-v3.py 0.0.0.0 55555 --reply "OK dari WSL" \
  --expect "PING dari Windows" --count 1 --log receiver.log
```

Sender di Windows:

```cmd
python sender_node-v3.py 172.20.236.11 55555 --send "PING dari Windows" ^
  --expect "OK dari WSL" --count 1 --log sender.log
```

Dua catatan WSL: IP berubah setiap distro restart (ambil ulang dengan `hostname -I`), dan koneksi Windows → WSL biasanya langsung jalan sedangkan arah sebaliknya butuh aturan firewall untuk port aplikasi.

### Firewall

Jika receiver berjalan di Windows:

```cmd
netsh advfirewall firewall add rule name="DES TCP 65432" dir=in action=allow protocol=TCP localport=65432
```

Perintah ini butuh Command Prompt sebagai Administrator. Di Linux, bila `ufw` aktif:

```bash
sudo ufw allow 65432/tcp
```

Bila penguji dari perangkat lain harus menjangkau VM NAT, tambahkan port forwarding: Virtual Network Editor → NAT Settings → Add → host port `65432`, guest IP `192.168.207.128`, guest port `65432`.

## 4. Uji cepat sebelum demo

Jalankan di **kedua** mesin. Hasilnya harus sama; ini membuktikan implementasi DES identik di kedua OS.

```bash
python sender_node-v3.py --selftest      # Windows
python3 receiver_node-v3.py --selftest   # Linux
```

Keluaran yang diharapkan:

```text
[SELFTEST] key=133457799BBCDFF1 pt=0123456789ABCDEF -> 85E813540F0AB405 (harap 85E813540F0AB405) OK
[SELFTEST] key=0E329232EA6D0D73 pt=8787878787878787 -> 0000000000000000 (harap 0000000000000000) OK
[SELFTEST] LULUS
```

Uji otomatis (boleh di salah satu mesin):

```bash
python -m unittest test_des -v
```

## 5. Matriks pengujian

Kolom "Hasil Windows" diisi dari pengujian yang sudah dilakukan; kolom VM diisi saat Anda menjalankan skenario A/B.

| ID | Skenario | Peran & OS | Kriteria lulus |
|---|---|---|---|
| T1 | Vektor DES | Windows + Linux | Kedua sisi cetak `LULUS`, hex identik |
| T2 | Loopback | Windows saja | 3 pesan, exit 0 |
| T3 | Linux receiver ← Windows sender (NAT) | Linux / Windows | Exit 0, log receiver mencatat IP Windows |
| T4 | Windows receiver ← Linux sender (NAT) | Windows / Linux | Exit 0, membuktikan peran simetris |
| T5 | Bridged atau dua laptop | Linux / Windows | Exit 0, IP berbeda subnet/segmen |
| T6 | 50 pesan cepat | Linux / Windows | 50/50 utuh, tidak ada `\x08` bocor |
| T7 | Kasus negatif | keduanya | Exit code sesuai tabel 6, tanpa traceback |
| T8 | 200 pesan, ukur waktu | Windows | Tidak ada data hilang, waktu tercatat |

## 6. Langkah per skenario

### T3 — Receiver di Linux, Sender di Windows

Terminal VM Linux (Node A):

```bash
python3 receiver_node-v3.py 0.0.0.0 65432 \
  --reply "OK dari Linux" \
  --expect "PING dari Windows" \
  --count 1 \
  --log bukti/T3_receiver.log
```

Command Prompt Windows (Node B), ganti IP dengan hasil `ip a` di VM:

```cmd
python sender_node-v3.py 192.168.207.128 65432 ^
  --send "PING dari Windows" ^
  --expect "OK dari Linux" ^
  --count 1 ^
  --log bukti\T3_sender.log
```

Keluaran yang diharapkan di Windows:

```text
[SUCCESS] Terhubung: 192.168.207.1:51234 -> 192.168.207.128:65432
[TERKIRIM] #1 Ciphertext DES (HEX) : <hex berbeda tiap pesan>
[DITERIMA] #1 Plaintext Hasil      : OK dari Linux
[HASIL] LULUS: 1 pesan terkirim, 1 balasan diterima.
```

Hex ciphertext selalu berubah mengikuti isi pesan; yang penting adalah plaintext hasil dekripsi sama dengan teks yang dikirim. Di log receiver akan terlihat `PEER=192.168.207.1:xxxxx`, bukti kedua pihak memakai IP berbeda.

### T4 — Arah balik: Receiver di Windows, Sender di Linux

Windows:

```cmd
python receiver_node-v3.py 0.0.0.0 65432 ^
  --reply "OK dari Windows" ^
  --expect "PING dari Linux" ^
  --count 1 ^
  --log bukti\T4_receiver.log
```

Linux:

```bash
python3 sender_node-v3.py 192.168.207.1 65432 \
  --send "PING dari Linux" \
  --expect "OK dari Windows" \
  --count 1 \
  --log bukti/T4_sender.log
```

### T6 — 50 pesan cepat

Ulangi T3, ganti `--count 1` menjadi `--count 50` di kedua sisi (biarkan `--send`/`--reply` sama). Setelah selesai, hitung baris log:

```bash
grep -c "EVENT=RX" bukti/T3_receiver.log   # harus 50
grep -c "EVENT=TX" bukti/T3_sender.log     # harus 50
```

### T8 — Beban 200 pesan

```bash
python receiver_node-v3.py 127.0.0.1 65436 --reply "OK" --count 200 --log bukti/T8_receiver.log
python sender_node-v3.py 127.0.0.1 65436 --send "BEBAN" --count 200 --expect "OK" --log bukti/T8_sender.log
```

### T7 — Kasus negatif dan exit code

| Kasus | Perintah | Exit code |
|---|---|---|
| Tidak ada listener | `python sender_node-v3.py 127.0.0.1 65499 --send PING --timeout 2` | 2 |
| PSK berbeda | receiver normal, sender `--key SalahKey` | 3 di receiver (pesan "data tidak cocok dengan PSK"), 2 di sender |
| PSK bukan 8 byte | `--key KunciDES67` | 4 |
| IP tidak terjangkau | `python sender_node-v3.py 10.255.255.1 65432 --send PING --timeout 2` | 2 |
| Balasan tidak sesuai harapan | `--expect "SALAH"` di sender | 3 |

## 7. Mode interaktif untuk demo

Mode ini tetap sama seperti versi sebelumnya, tanpa argumen tambahan:

```bash
python3 receiver_node-v3.py 0.0.0.0 65432   # Node A
python sender_node-v3.py 192.168.207.128 65432   # Node B
```

Ketik pesan, tekan Enter, lalu amati ciphertext hex dan plaintext di kedua terminal. Ketik `exit` untuk berhenti. Untuk presentasi, mode interaktif menunjukkan proses enkripsi, sedangkan mode `--send/--reply` memberi bukti yang dapat diulang dan exit code yang jelas.

## 8. Troubleshooting

| Gejala | Penyebab | Tindakan |
|---|---|---|
| `Gagal terhubung` (exit 2) | listener belum jalan, IP salah, firewall | cek `ip a`/`ipconfig`, jalankan receiver lebih dulu, tambahkan aturan firewall |
| Timeout saat connect | rute NAT/port forwarding belum ada | uji `ping`, tambahkan port forwarding di VMware |
| Timeout saat menunggu balasan | receiver crash atau `--expect` gagal | lihat log receiver |
| `data tidak cocok dengan PSK` | kunci kedua mesin berbeda | samakan `--key` atau `DES_PSK` di kedua sisi |
| `PSK harus tepat 8 byte` | kunci lebih/kurang dari 8 karakter | pakai `KunciDES` atau nilai 8 karakter lain |
| Karakter aneh `?⊐` | kunci berbeda atau berkas versi lama | pastikan ketiga `.py` versi terbaru di kedua mesin |
| Error encoding di Windows | konsol cp1252 | jalankan lewat `cmd`/PowerShell modern; skrip sudah memaksa UTF-8 |
| `Address already in use` | port dipakai proses lain | pakai port lain, mis. 65433 |
| `Gagal membuka ... [WinError 10013]` atau `errno 13` | port masuk rentang yang dipesan Windows/Hyper-V, bukan dipakai aplikasi | pakai `--port 55555`; cek dengan `netsh interface ipv4 show excludedportrange protocol=tcp` |
| `ssh: connect ... port 22: Connection refused` padahal VM bisa di-ping | sshd belum berjalan di VM (host hidup, port tertutup) | di VM: pasang `openssh-server`, `sudo systemctl enable --now ssh`, lalu pastikan `sudo ss -ltnp \| grep ':22'` menampilkan LISTEN |

## 9. Bukti yang dikumpulkan

Simpan di folder `bukti/`:

1. `T1_selftest_*.txt` dari kedua OS.
2. `T3_receiver.log` dan `T3_sender.log` (berisi waktu, IP peer, panjang, hex, teks).
3. `ipconfig_windows.txt` dan `ip_a_linux.txt`.
4. Screenshot terminal kedua mesin yang menampilkan `[SUCCESS]` dengan IP berbeda.
5. `netstat -ano | findstr 65432` saat sesi aktif; harus terlihat pasangan IP:port dalam status `ESTABLISHED`.
6. Tabel hasil di `HASIL_PENGUJIAN.md`.

## 10. Otomatisasi lintas mesin lewat SSH

Menjalankan T3 secara manual berarti membuka dua terminal dan menyalin perintah. `uji_lintas_mesin.py` melakukan hal yang sama secara otomatis: menyalin berkas ke VM, menyalakan receiver di sana, menjalankan sender di host ini, lalu mengambil log dan exit code kedua sisi.

### Persiapan sekali saja

Di VM (Ubuntu/Debian):

```bash
sudo apt install openssh-server
sudo systemctl enable --now ssh
ip a            # catat IP, mis. 192.168.207.128
```

Di komputer penguji, buat kunci dan pasang ke VM:

```bash
ssh-keygen -t ed25519            # tekan Enter sampai selesai, sekali saja
ssh-copy-id siswa@192.168.207.128
ssh siswa@192.168.207.128 true   # harus selesai tanpa diminta sandi
```

Di Windows, klien OpenSSH sudah tersedia (cek dengan `ssh -V`). Bila `ssh-copy-id` tidak ada:

```powershell
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh siswa@192.168.207.128 "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
```

Skrip memakai `BatchMode=yes`, jadi **sandi tidak bisa diketik**. Autentikasi harus lewat kunci; bila gagal, skrip berhenti dengan petunjuk di atas.

### Menjalankan uji

```bash
python uji_lintas_mesin.py --host 192.168.207.128 --user siswa --count 3
```

Alur yang dijalankan:

1. Cek SSH dan Python di VM.
2. `mkdir` folder kerja, lalu `scp` tiga berkas (cipher, transport, receiver).
3. Nyalakan receiver di VM dengan `nohup`, tunggu baris `Menunggu koneksi`.
4. Jalankan sender di host ini dan catat exit code-nya.
5. Ambil `receiver_out.txt`, `receiver.log`, dan `kode_receiver.txt` ke folder bukti, lalu bandingkan jumlah RX/TX.

Keluaran akhir berupa ringkasan seperti ini:

```text
IP lokal         : 192.168.207.1
IP remote        : 192.168.207.128
peer di log      : 192.168.207.1
pesan            : 3
exit sender      : 0
exit receiver    : 0
RX di receiver   : 3
TX di sender     : 3
hasil            : LULUS
[HASIL] LULUS
```

Exit code skrip: `0` lulus, `1` uji berjalan tetapi gagal, `2` masalah setup (SSH, Python, atau receiver tidak siap).

### Opsi yang sering dipakai

| Opsi | Guna |
|---|---|
| `--count 50` | uji banyak pesan (T6) |
| `--pesan`, `--balasan` | teks yang dipertukarkan |
| `--harapan-sender` | memaksa sender mengharapkan teks lain, untuk uji negatif |
| `--remote-dir des-uji` | folder kerja di VM, relatif terhadap home |
| `--identitas ~/.ssh/id_ed25519` | kunci privat tertentu |
| `--ssh-port 2222` | port SSH non-standar |
| `--tanpa-kirim` | lewati scp bila berkas sudah ada di VM |
| `--lokal` | jalankan alur yang sama tanpa SSH, untuk memastikan skrip sehat |
| `--dry-run` | cetak perintah receiver dan sender tanpa menjalankan |

Contoh uji negatif (sender mengharapkan balasan salah, harus berakhir `GAGAL` dengan exit 1):

```bash
python uji_lintas_mesin.py --host 192.168.207.128 --user siswa \
  --count 1 --harapan-sender "BUKAN INI"
```

Bukti tersimpan di `bukti/lintas_mesin/<tanggal-jam>/`: `sender.log`, `sender_out.txt`, `receiver.log`, `receiver_out.txt`, `kode_sender.txt`, `kode_receiver.txt`, `ringkasan.txt`, `perintah.txt`, dan `ip_remote.txt`.

## 11. Catatan keamanan untuk laporan

- DES hanya 56 bit efektif dan sudah dianggap tidak aman; tugas ini menekankan pemahaman algoritma, bukan pemakaian produksi.
- Mode yang dipakai adalah ECB: blok plaintext yang sama menghasilkan ciphertext yang sama, sehingga pola data dapat ditebak.
- PSK disimpan di dalam kode dan tidak ada autentikasi pihak, sehingga rentan MITM.
- Pengembangan lanjutan yang masuk akal: mode CBC dengan IV acak per sesi, kunci dari file/env tanpa nilai bawaan, dan HMAC untuk integritas.
- Pemeriksaan integritas saat ini (`dekripsi_terverifikasi`) bekerja dengan enkripsi ulang karena ECB deterministik; ia mendeteksi PSK salah, bukan menggantikan MAC.
