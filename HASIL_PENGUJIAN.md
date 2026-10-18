# Hasil Pengujian DES 2 Arah

Diisi bertahap: kolom Windows sudah dijalankan, kolom VM Linux diisi saat skenario A/B dijalankan.

## Lingkungan

| Item | Windows (Node B) | Ubuntu WSL2 (Node A) | VM VMware (Node A) |
|---|---|---|---|
| OS | Windows 11 Home 10.0.26200 | Ubuntu, kernel 6.18.33.2 WSL2 | belum dijalankan |
| Python | 3.14.7 | 3.12.3 | belum dijalankan |
| IP utama | 192.168.1.3 (Wi-Fi), 192.168.207.1 (VMnet8) | 172.20.236.11 | 192.168.207.128 (perkiraan NAT) |
| PSK | `KunciDES` | `KunciDES` | harus sama |

## Ringkasan

| ID | Uji | Hasil Windows | Hasil VM | Bukti |
|---|---|---|---|---|
| T1 | Vektor DES (`--selftest`) | Lulus, hex sesuai standar | belum | `bukti/T1_selftest_*.txt` |
| T2 | Loopback 3 pesan | Lulus, exit 0/0 | — | `bukti/T2_*.log` |
| T2b | Bind antarmuka non-loopback `192.168.207.1` + UTF-8 | Lulus, 2 pesan, exit 0/0 | — | `bukti/T3_*.log` (nama berkas lama) |
| T3 | Linux VM receiver ← Windows sender (NAT) | **Diblokir**: port 22/2222/55555/65432 ditolak (sshd tidak listen) | belum | `bukti/T3_blokir_ssh_vm.txt` |
| T4 | Windows receiver ← Linux VM sender (NAT) | Diblokir, alasan sama | belum | `bukti/T3_blokir_ssh_vm.txt` |
| T5 | Bridged / dua perangkat | Belum dijalankan (VM memakai NAT) | belum | — |
| T6 | 50 pesan cepat | Lulus, 50 RX / 50 TX, 0 padding bocor | belum | `bukti/T6_*.log` |
| T7a | Tanpa listener | exit 2 | belum | `bukti/T7a_tanpa_listener.txt` |
| T7b | PSK berbeda | receiver exit 3, sender exit 2 | belum | `bukti/T7b_*.txt` |
| T7c | PSK bukan 8 byte | exit 4 | belum | `bukti/T7c_psk_panjang.txt` |
| T7d | IP tidak terjangkau | exit 2 | belum | `bukti/T7d_ip_tak_terjangkau.txt` |
| T8 | 200 pesan, ukur waktu | Lulus, 0,344 s total | belum | `bukti/T8_waktu.txt` |
| T9 | Mode interaktif (demo) | Lulus, pesan & balasan tampil benar | belum | `bukti/T9_interaktif_*.txt` |
| T10 | Otomatisasi `uji_lintas_mesin.py --lokal` | Lulus, exit 0, 3 RX / 3 TX | belum (butuh kunci SSH) | `bukti/harness_lokal_out.txt`, `bukti/lintas_mesin/20261018-211021/` |
| T10b | Otomatisasi uji negatif (`--harapan-sender` salah) | GAGAL sesuai harapan, exit 1 | — | `bukti/lintas_mesin/` |
| T11 | **Windows sender → Ubuntu WSL2 receiver** | Lulus, 3/3 pesan, exit 0/0 | Lulus (OS & IP berbeda) | `bukti/T11_*.txt`, `bukti/T11_*.log` |
| T12 | **Ubuntu WSL2 sender → Windows receiver** | Lulus, 3/3 pesan, exit 0/0 | Lulus (arah balik) | `bukti/T12_*.txt`, `bukti/T12_*.log` |

## Hasil uji otomatis

```text
python -m unittest test_des -v
Ran 17 tests in 1.210s
OK
```

Cakupan: 2 vektor DES standar, padding 0–17 byte, payload UTF-8 1 KB, framing (pesan berurutan, bacaan 1 byte, frame terpotong, frame melebihi batas, peer menutup), verifikasi PSK, serta end-to-end 50 pesan dan kasus negatif.

## Angka terukur

| Metrik | Nilai |
|---|---|
| Waktu per pertukaran (loopback, pesan 5 byte) | 1,72 ms |
| Waktu per pertukaran (loopback, 50 pesan) | 5,4 ms |
| Throughput 200 pertukaran | 0,344 s |
| Overhead framing | 4 byte per pesan |

Angka ini berasal dari satu host. Latensi lintas mesin akan lebih besar dan perlu diukur ulang saat T3/T4 dijalankan.

## Catatan penting

- T3 di Windows memakai `192.168.207.1` sebagai alamat bind dan tujuan, jadi yang terbukti adalah bind/connect pada antarmuka non-loopback, **bukan** bukti dua host. Bukti lintas OS yang sah ada di T11.
- T11 menjalankan receiver di Ubuntu WSL2 (Python 3.12) dan sender di Windows 11 (Python 3.14) dengan IP berbeda: `172.20.224.1 → 172.20.236.11`. Hasil: 3/3 pesan, exit 0 di kedua sisi, 3 RX dan 3 TX. Ini memenuhi syarat beda OS dan beda IP, walau kedua OS berada di satu perangkat.
- T12 melengkapi arah sebaliknya: sender Ubuntu WSL2 (`172.20.236.11`) → receiver Windows (`172.20.224.1:55555`), 3/3 pesan, exit 0/0. Dengan T11 dan T12, komunikasi dua arah lintas OS sudah terbukti; yang belum hanya varian VMware.
- Percobaan ke VM VMware dilakukan pukul 21:33 dan tercatat di `bukti/T3_blokir_ssh_vm.txt`: mesin `gluttonyVM` (192.168.207.128) hidup, ping 0 ms, tetapi port 22, 2222, 55555, dan 65432 semua `Connection refused`. Artinya belum ada layanan yang mendengarkan, jadi T3/T4/T5 tidak dijalankan dan tidak diisi dengan data rekaan. Setelah `ss -ltnp | grep ':22'` menunjukkan LISTEN di VM, T3 dapat dijalankan dengan satu perintah `uji_lintas_mesin.py`.
- `192.168.207.128` adalah tebakan umum VMware NAT. Cocokkan dengan keluaran `ip a` di VM sebelum menjalankan perintah.
- Default port `65432` sempat masuk rentang port yang dipesan Windows (WinError 10013) di tengah sesi, sehingga pengujian berikutnya memakai `55555`. Bila muncul error itu, pilih port lain; bukan bug program.
- Firewall profil Public di mesin ini mati, sehingga belum ada uji "koneksi diblokir firewall". Kasus T7d memakai IP tak terjangkau sebagai pengganti timeouts.
- Transport SSH/SCP belum diuji end-to-end karena VM tidak menjalankan sshd. Yang sudah diverifikasi: mode `--lokal` (alur penuh: siap, mulai, tunggu, ambil bukti, hitung RX/TX), `--dry-run`, kegagalan preflight SSH (exit 2 dengan petunjuk kunci), kegagalan uji negatif (exit 1), port bentrok (exit 2), dan perintah launcher remote di Ubuntu asli.
- Perintah launcher yang dipakai mode SSH diuji apa adanya di Ubuntu WSL2 (`nohup python3 -c '<snippet>' receiver_node-v3.py ...`): receiver siap, menerima 1 pesan, menulis `kode_receiver.txt` berisi `0`, dan mencetak `[HASIL] LULUS`. Jadi bagian remote-shell-nya valid; yang belum tersentuh hanya lapisan `ssh`/`scp`.
- Log tiap sesi ditulis ulang (`mode="w"`), bukan ditambahkan, supaya hitungan RX/TX di bukti selalu mewakili satu sesi.
