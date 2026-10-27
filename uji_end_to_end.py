# uji_end_to_end.py
"""Uji tiga proses nyata: KDC, Bob, Alice, lalu periksa dua arah dan rotasi kunci.

Setiap skenario memakai port berbeda dan direktori bukti sendiri. Skrip keluar
dengan kode 0 hanya bila semua pemeriksaan lulus.
"""

import argparse
import json
import re
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from aes_manual import ManualAES

BASE = Path(__file__).resolve().parent
PY = sys.executable
PESAN_ALICE = "Pesan uji dari Alice"
PESAN_BOB = "Balasan dari Bob"
IP_KDC = "127.0.0.2"
IP_ALICE = "127.0.0.3"
IP_BOB = "127.0.0.4"


def port_bebas():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def tunggu_log(path, penanda, batas=12.0):
    akhir = time.time() + batas
    while time.time() < akhir:
        if path.exists():
            isi = path.read_text(encoding="utf-8", errors="replace")
            if penanda in isi:
                return True
        time.sleep(0.1)
    return False


def buka_proses(argumen, out_path):
    berkas = open(out_path, "w", encoding="utf-8")
    proses = subprocess.Popen(
        [PY] + argumen,
        cwd=str(BASE),
        stdout=berkas,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
    )
    return proses, berkas


def hentikan(proses, batas=8.0):
    if proses is None or proses.poll() is not None:
        return
    proses.terminate()
    try:
        proses.wait(timeout=batas)
    except subprocess.TimeoutExpired:
        proses.kill()
        proses.wait(timeout=batas)


def baca(path):
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def tulis_konfigurasi(path, port_kdc, port_bob):
    konf = json.loads((BASE / "konfigurasi.json").read_text(encoding="utf-8"))
    konf["kdc"]["host"] = IP_KDC
    konf["kdc"]["port"] = port_kdc
    konf["bob"]["host"] = IP_BOB
    konf["bob"]["port"] = port_bob
    konf["alice"]["host"] = IP_ALICE
    path.write_text(json.dumps(konf, indent=2), encoding="utf-8")
    return konf


def periksa_umum(masalah, nama, out_alice, out_bob, log_alice, log_bob, log_kdc, jumlah):
    if out_alice.count("[DITERIMA #") != jumlah:
        masalah.append(f"{nama}: Alice menerima {out_alice.count('[DITERIMA #')} pesan, "
                       f"harus {jumlah}")
    if out_bob.count("[DITERIMA #") != jumlah:
        masalah.append(f"{nama}: Bob menerima {out_bob.count('[DITERIMA #')} pesan, "
                       f"harus {jumlah}")
    if out_alice.count("[TERKIRIM] Ciphertext AES") != jumlah:
        masalah.append(f"{nama}: jumlah ciphertext terkirim Alice tidak sesuai")
    if out_bob.count("[TERKIRIM] Ciphertext AES") != jumlah:
        masalah.append(f"{nama}: jumlah ciphertext terkirim Bob tidak sesuai")
    if "SESI] Terbentuk" not in out_alice:
        masalah.append(f"{nama}: Alice tidak mencetak sesi terbentuk")
    if "SESI] Terbentuk" not in out_bob:
        masalah.append(f"{nama}: Bob tidak mencetak sesi terbentuk")
    if "[ERROR]" in out_alice:
        masalah.append(f"{nama}: Alice mencetak [ERROR]")
    if "[ERROR]" in out_bob:
        masalah.append(f"{nama}: Bob mencetak [ERROR]")
    if "EVENT=LANGKAH1" not in log_alice:
        masalah.append(f"{nama}: log Alice tidak memuat LANGKAH1")
    if "EVENT=LANGKAH2" not in log_kdc:
        masalah.append(f"{nama}: log KDC tidak memuat LANGKAH2")
    if "EVENT=LANGKAH3" not in log_bob or "EVENT=LANGKAH4" not in log_alice:
        masalah.append(f"{nama}: langkah 3/4 tidak tercatat")
    if "EVENT=LANGKAH5" not in log_bob:
        masalah.append(f"{nama}: langkah 5 tidak tercatat di Bob")
    if f"[STATUS] lokal         : {IP_ALICE}:" not in out_alice:
        masalah.append(f"{nama}: Alice tidak melaporkan IP lokal {IP_ALICE}")
    if f"[STATUS] lokal         : {IP_BOB}:" not in out_bob:
        masalah.append(f"{nama}: Bob tidak melaporkan IP lokal {IP_BOB}")
    if f"PEER={IP_ALICE}:" not in log_kdc:
        masalah.append(f"{nama}: KDC tidak melihat koneksi dari {IP_ALICE}")
    if f"PEER={IP_ALICE}:" not in log_bob:
        masalah.append(f"{nama}: Bob tidak melihat koneksi dari {IP_ALICE}")
    if f"PEER={IP_BOB}:" not in log_alice:
        masalah.append(f"{nama}: Alice tidak melihat peer {IP_BOB}")


def periksa_ciphertext(masalah, nama, log_alice, log_bob, pesan):
    kunci = re.search(r"EVENT=SESI .*?TXT='([A-Za-z0-9]{16})'", log_alice)
    tx = re.search(r"EVENT=TX .*?HEX=([0-9a-f]+)", log_alice)
    rx = re.search(r"EVENT=RX .*?HEX=([0-9a-f]+)", log_bob)
    if not kunci or not tx or not rx:
        masalah.append(f"{nama}: kunci/ciphertext untuk verifikasi tidak ditemukan di log")
        return
    try:
        terbuka = ManualAES(kunci.group(1)).dekripsi(bytes.fromhex(tx.group(1)))
    except Exception as e:  # noqa: BLE001 - laporan uji harus menampilkan sebab
        masalah.append(f"{nama}: ciphertext Alice tidak bisa dibuka: {e}")
        return
    try:
        isi = json.loads(terbuka.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        masalah.append(f"{nama}: plaintext hasil dekripsi bukan JSON: {e}")
        return
    if isi.get("teks") != pesan:
        masalah.append(f"{nama}: plaintext hasil dekripsi {isi.get('teks')!r} != {pesan!r}")
    if tx.group(1) != rx.group(1):
        masalah.append(f"{nama}: ciphertext TX Alice != ciphertext RX Bob")
    if len(tx.group(1)) % 32 != 0:
        masalah.append(f"{nama}: ciphertext bukan kelipatan blok AES")


def jalankan_skenario(nama, jumlah, rotasi_setelah, keluaran):
    folder = keluaran / nama
    folder.mkdir(parents=True, exist_ok=True)
    cfg = folder / "konfigurasi.json"
    port_kdc, port_bob = port_bebas(), port_bebas()
    while port_bob == port_kdc:
        port_bob = port_bebas()
    tulis_konfigurasi(cfg, port_kdc, port_bob)

    log_kdc = folder / "kdc.log"
    log_bob = folder / "bob.log"
    log_alice = folder / "alice.log"
    out_kdc = folder / "kdc.out"
    out_bob = folder / "bob.out"
    out_alice = folder / "alice.out"

    kdc = bob = alice = None
    berkas = []
    masalah = []
    try:
        kdc, f = buka_proses([
            "kdc.py", "--konfigurasi", str(cfg), "--bind", IP_KDC,
            "--tanpa-konsol", "--log", str(log_kdc),
        ], out_kdc)
        berkas.append(f)
        if not tunggu_log(log_kdc, "EVENT=MENDENGAR"):
            masalah.append(f"{nama}: KDC tidak siap")
            return masalah

        bob, f = buka_proses([
            "node.py", "--peran", "bob", "--konfigurasi", str(cfg),
            "--bind", IP_BOB, "--tanpa-konsol", "--log", str(log_bob),
            "--balas", PESAN_BOB, "--jumlah", str(jumlah), "--batas", "25",
        ], out_bob)
        berkas.append(f)
        if not tunggu_log(log_bob, "EVENT=MENDENGAR"):
            masalah.append(f"{nama}: Bob tidak siap mendengarkan")
            return masalah

        argumen_alice = [
            "node.py", "--peran", "alice", "--konfigurasi", str(cfg),
            "--tanpa-konsol", "--log", str(log_alice),
            "--kirim", PESAN_ALICE, "--jumlah", str(jumlah),
            "--harap-balasan", str(jumlah), "--batas", "25",
        ]
        if rotasi_setelah:
            argumen_alice += ["--rotasi-setelah", str(rotasi_setelah)]
        alice, f = buka_proses(argumen_alice, out_alice)
        berkas.append(f)
        try:
            alice.wait(timeout=40)
        except subprocess.TimeoutExpired:
            masalah.append(f"{nama}: Alice melewati batas 40 detik")

        if alice is not None and alice.returncode not in (0, None):
            masalah.append(f"{nama}: exit code Alice {alice.returncode}")
        try:
            bob.wait(timeout=15)
        except subprocess.TimeoutExpired:
            masalah.append(f"{nama}: Bob tidak selesai setelah Alice keluar")
        if bob is not None and bob.returncode not in (0, None):
            masalah.append(f"{nama}: exit code Bob {bob.returncode}")
    finally:
        for proses in (alice, bob, kdc):
            hentikan(proses)
        for f in berkas:
            f.close()

    out_a, out_b = baca(out_alice), baca(out_bob)
    log_a, log_b, log_k = baca(log_alice), baca(log_bob), baca(log_kdc)
    periksa_umum(masalah, nama, out_a, out_b, log_a, log_b, log_k, jumlah)
    periksa_ciphertext(masalah, nama, log_a, log_b, PESAN_ALICE)

    if rotasi_setelah:
        if "Rotasi kunci setelah pesan #" not in out_a:
            masalah.append(f"{nama}: rotasi kunci tidak berhasil")
        if "KUNCI] Lawan mengganti kunci" not in out_b:
            masalah.append(f"{nama}: Bob tidak menerima kunci baru")
        kunci_sesi = re.findall(r"EVENT=SESI .*?TXT='([A-Za-z0-9]{16})'", log_a)
        kunci_aktif = re.findall(r"EVENT=KUNCI_AKTIF .*?TXT='([A-Za-z0-9]{16})'", log_a)
        if not kunci_aktif or kunci_aktif[-1] == (kunci_sesi[0] if kunci_sesi else None):
            masalah.append(f"{nama}: kunci sesi tidak berubah setelah rotasi")
        if "EVENT=KUNCI_BARU" not in log_b and "EVENT=KUNCI_AKTIF" not in log_b:
            masalah.append(f"{nama}: log Bob tidak mencatat kunci baru")

    return masalah


def jalankan_negatif(keluaran):
    folder = keluaran / "negatif_kunci_salah"
    folder.mkdir(parents=True, exist_ok=True)
    cfg = folder / "konfigurasi.json"
    port_kdc = port_bebas()
    tulis_konfigurasi(cfg, port_kdc, port_bebas())
    log_kdc = folder / "kdc.log"
    out_alice = folder / "alice.out"
    masalah = []
    kdc = alice = None
    berkas = []
    try:
        kdc, f = buka_proses([
            "kdc.py", "--konfigurasi", str(cfg), "--bind", IP_KDC,
            "--tanpa-konsol", "--log", str(log_kdc),
        ], folder / "kdc.out")
        berkas.append(f)
        if not tunggu_log(log_kdc, "EVENT=MENDENGAR"):
            return ["negatif: KDC tidak siap"]
        alice, f = buka_proses([
            "node.py", "--peran", "alice", "--konfigurasi", str(cfg),
            "--tanpa-konsol", "--kunci", "KunciSalahSekali", "--batas", "8",
        ], out_alice)
        berkas.append(f)
        try:
            alice.wait(timeout=15)
        except subprocess.TimeoutExpired:
            masalah.append("negatif: Alice tidak berhenti saat kunci master salah")
        if alice.returncode != 3:
            masalah.append(f"negatif: exit code {alice.returncode}, harus 3")
        isi = baca(out_alice)
        if "gagal membuka balasan KDC" not in isi:
            masalah.append("negatif: pesan kegagalan dekripsi tidak muncul")
    finally:
        for proses in (alice, kdc):
            hentikan(proses)
        for f in berkas:
            f.close()
    return masalah


def main():
    p = argparse.ArgumentParser(description="Uji end-to-end KDC + Alice + Bob")
    p.add_argument("--keluaran", default=str(BASE / "bukti" / "e2e"),
                   help="direktori bukti")
    args = p.parse_args()
    stempel = datetime.now().strftime("%Y%m%d-%H%M%S")
    keluaran = Path(args.keluaran) / stempel
    keluaran.mkdir(parents=True, exist_ok=True)

    print(f"[UJI] Bukti disimpan di {keluaran}")
    semua = []
    print("[UJI] Skenario dasar: 2 pesan dua arah...")
    semua += jalankan_skenario("dasar", 2, 0, keluaran)
    print("[UJI] Skenario rotasi kunci: 3 pesan, ganti kunci setelah pesan #2...")
    semua += jalankan_skenario("rotasi", 3, 2, keluaran)
    print("[UJI] Skenario negatif: kunci master Alice salah...")
    semua += jalankan_negatif(keluaran)

    if semua:
        print("\n[HASIL] GAGAL")
        for m in semua:
            print("  - " + m)
        return 1
    print("\n[HASIL] LULUS: dasar, rotasi kunci, dan kasus negatif sesuai harapan.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
