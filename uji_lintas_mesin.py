#!/usr/bin/env python3
"""Uji DES lintas mesin: receiver di VM lewat SSH, sender di host ini.

Skrip menyalin berkas ke VM, menjalankan receiver di sana, menjalankan sender
lokal, lalu mengumpulkan log dan exit code kedua sisi ke folder bukti.
"""

import argparse
import re
import shlex
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent
BERKAS_KIRIM = ["cipher_manual.py", "transport.py", "receiver_node-v3.py"]

SNIPPET_KODE = (
    'import subprocess,sys; r=subprocess.run([sys.executable, *sys.argv[1:]]); '
    'open("kode_receiver.txt","w").write(str(r.returncode))'
)


class GagalUji(Exception):
    pass


def siapkan_stdout():
    # Konsol Windows cp1252 tidak bisa mencetak tanda pisah panjang dan emoji.
    for aliran in (sys.stdout, sys.stderr):
        if hasattr(aliran, "reconfigure"):
            aliran.reconfigure(encoding="utf-8", errors="backslashreplace")


def baca_teks(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def ip_lokal_ke(host: str, port: int) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((host, port))
        return sock.getsockname()[0]
    except OSError:
        return "tidak diketahui"
    finally:
        sock.close()


class MesinSSH:
    def __init__(self, args, bukti: Path):
        self.host = args.host
        self.user = args.user
        self.port_ssh = args.ssh_port
        self.identitas = args.identitas
        self.dir = args.remote_dir
        self.python = args.python_remote
        self.bukti = bukti
        self.ssh = args.ssh_bin
        self.scp = args.scp_bin
        self.target = f"{args.user}@{args.host}" if args.user else args.host
        self.opsi = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
                     "-o", "ConnectTimeout=8"]

    def _perintah_ssh(self):
        opsi = list(self.opsi)
        if self.port_ssh != 22:
            opsi += ["-p", str(self.port_ssh)]
        if self.identitas:
            opsi += ["-i", self.identitas]
        return opsi

    def _perintah_scp(self):
        opsi = list(self.opsi)
        if self.port_ssh != 22:
            opsi += ["-P", str(self.port_ssh)]
        if self.identitas:
            opsi += ["-i", self.identitas]
        return opsi

    def jalankan(self, perintah, timeout=30, periksa=True):
        try:
            hasil = subprocess.run(
                [self.ssh, *self._perintah_ssh(), self.target, perintah],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=timeout,
            )
        except FileNotFoundError:
            raise GagalUji(
                f"klien SSH tidak ditemukan: {self.ssh}. "
                "Di Windows aktifkan OpenSSH Client (Settings > Apps > Optional Features)."
            )
        except subprocess.TimeoutExpired:
            raise GagalUji(f"SSH tidak menjawab dalam {timeout} detik: {perintah[:80]}")
        if periksa and hasil.returncode != 0:
            raise GagalUji(
                f"perintah SSH gagal ({hasil.returncode}): {perintah[:80]}\n"
                f"{hasil.stderr.strip()[:400]}"
            )
        return hasil

    def periksa(self):
        coba = self.jalankan("true", timeout=15, periksa=False)
        if coba.returncode != 0:
            raise GagalUji(
                "tidak bisa masuk ke VM tanpa sandi. Siapkan kunci SSH lebih dulu:\n"
                f"  ssh-keygen -t ed25519            (sekali saja)\n"
                f"  ssh-copy-id -p {self.port_ssh} {self.target}   (Linux/macOS)\n"
                "  Windows: type $env:USERPROFILE\\.ssh\\id_ed25519.pub | "
                f"ssh -p {self.port_ssh} {self.target} \"mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys\"\n"
                f"Pesan: {coba.stderr.strip()[:300]}"
            )
        versi = self.jalankan(f"{self.python} --version", periksa=False)
        if versi.returncode != 0:
            raise GagalUji(
                f"Python tidak siap di VM ({self.python}). "
                f"Pasang: sudo apt install python3. Pesan: {versi.stderr.strip()[:200]}"
            )
        print(f"[SSH] {self.target} siap, {versi.stdout.strip() or versi.stderr.strip()}")

    def siapkan(self, kirim_berkas=True):
        self.jalankan(f"mkdir -p {shlex.quote(self.dir)}")
        if not kirim_berkas:
            return
        tujuan = f"{self.target}:{self.dir}/"
        try:
            hasil = subprocess.run(
                [self.scp, *self._perintah_scp(),
                 *[str(BASE / b) for b in BERKAS_KIRIM], tujuan],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=60,
            )
        except FileNotFoundError:
            raise GagalUji(f"klien SCP tidak ditemukan: {self.scp}")
        if hasil.returncode != 0:
            raise GagalUji(f"gagal menyalin berkas ke VM:\n{hasil.stderr.strip()[:400]}")
        print(f"[SCP] {len(BERKAS_KIRIM)} berkas tersalin ke {self.dir}")

    def skrip(self, nama):
        return nama

    def jalur(self, nama):
        return nama

    def mulai(self, argumen, out, kode):
        kata = " ".join(shlex.quote(a) for a in argumen)
        perintah = (
            f"cd {shlex.quote(self.dir)} && nohup {self.python} -c '{SNIPPET_KODE}' "
            f"{kata} > {shlex.quote(out)} 2>&1 < /dev/null & echo $!"
        )
        hasil = self.jalankan(perintah, timeout=25)
        pid = hasil.stdout.strip().splitlines()[-1] if hasil.stdout.strip() else ""
        if not pid.isdigit():
            raise GagalUji(f"gagal menjalankan receiver di VM: {hasil.stdout} {hasil.stderr}")
        return pid

    def baca(self, nama):
        hasil = self.jalankan(
            f"cat {shlex.quote(self.dir + '/' + nama)} 2>/dev/null || true", periksa=False
        )
        return hasil.stdout

    def kode(self, handle, nama):
        teks = self.baca(nama).strip()
        return int(teks) if teks.isdigit() else None

    def ambil(self, nama_list, tujuan: Path):
        ada = [n for n in nama_list if self.baca(n) != ""]
        if not ada:
            return
        hasil = subprocess.run(
            [self.scp, *self._perintah_scp(),
             *[f"{self.target}:{self.dir}/{n}" for n in ada], str(tujuan)],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=60,
        )
        if hasil.returncode != 0:
            print(f"[PERINGATAN] sebagian bukti gagal diambil: {hasil.stderr.strip()[:300]}")

    def ip(self):
        hasil = self.jalankan(
            "hostname -I 2>/dev/null || ip -4 -o addr show scope global", periksa=False
        )
        ipv4 = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", hasil.stdout)
        return ipv4[0] if ipv4 else (hasil.stdout.strip() or "tidak diketahui")

    def hentikan(self, handle):
        self.jalankan(f"kill {shlex.quote(str(handle))} 2>/dev/null || true", periksa=False)


class MesinLokal:
    """Mode tanpa SSH: receiver dijalankan sebagai proses lokal, alur tetap sama."""

    def __init__(self, args, bukti: Path):
        self.bukti = bukti
        self.proses = None

    def periksa(self):
        if not (BASE / "receiver_node-v3.py").exists():
            raise GagalUji("receiver_node-v3.py tidak ada di folder skrip")
        print("[LOKAL] mode tanpa SSH, receiver berjalan di mesin ini")

    def siapkan(self, kirim_berkas=True):
        pass

    def skrip(self, nama):
        return str(BASE / nama)

    def jalur(self, nama):
        return str(self.bukti / nama)

    def mulai(self, argumen, out, kode):
        keluaran = open(out, "w", encoding="utf-8")
        self.proses = subprocess.Popen(
            [sys.executable, *argumen], cwd=BASE, stdout=keluaran,
            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
        )
        self.keluaran = keluaran
        return self.proses

    def baca(self, nama):
        return baca_teks(Path(self.jalur(nama)))

    def kode(self, handle, nama):
        return handle.poll()

    def ambil(self, nama_list, tujuan: Path):
        pass

    def ip(self):
        return "127.0.0.1"

    def hentikan(self, handle):
        if handle.poll() is None:
            handle.kill()
        self.keluaran.close()


def bangun_argumen(argv):
    p = argparse.ArgumentParser(
        description="Uji DES 2 arah lintas mesin: receiver di VM lewat SSH, sender lokal."
    )
    p.add_argument("--host", help="IP VM (wajib untuk mode SSH)")
    p.add_argument("--user", help="user SSH di VM")
    p.add_argument("--ssh-port", type=int, default=22)
    p.add_argument("--identitas", help="berkas kunci privat SSH")
    p.add_argument("--remote-dir", default="des-uji", help="folder kerja di VM (relatif home)")
    p.add_argument("--python-remote", default="python3")
    p.add_argument("--port", type=int, default=65432, help="port TCP aplikasi DES")
    p.add_argument("--count", type=int, default=3, help="jumlah pesan yang dipertukarkan")
    p.add_argument("--pesan", default="PING lintas mesin", help="teks yang dikirim sender")
    p.add_argument("--balasan", default="OK dari receiver", help="teks balasan receiver")
    p.add_argument("--harapan-sender", help="teks yang diharapkan sender (default: --balasan)")
    p.add_argument("--timeout-siap", type=float, default=25.0, help="detik menunggu receiver siap")
    p.add_argument("--timeout-uji", type=float, default=90.0, help="detik menunggu uji selesai")
    p.add_argument("--timeout-receiver", type=float, default=25.0,
                   help="detik receiver menunggu koneksi lalu keluar")
    p.add_argument("--lokal", action="store_true", help="jalankan receiver lokal, tanpa SSH")
    p.add_argument("--tanpa-kirim", action="store_true", help="lewati scp, berkas sudah ada di VM")
    p.add_argument("--ssh-bin", default="ssh")
    p.add_argument("--scp-bin", default="scp")
    p.add_argument("--keluaran", default="bukti/lintas_mesin", help="folder bukti")
    p.add_argument("--dry-run", action="store_true", help="cetak rencana perintah lalu keluar")
    return p.parse_args(argv)


def main():
    siapkan_stdout()
    args = bangun_argumen(sys.argv[1:])
    harapan_sender = args.harapan_sender or args.balasan
    if not args.lokal and not args.host:
        print("[ERROR] --host wajib diisi, atau pakai --lokal untuk uji tanpa SSH.")
        return 2
    if args.lokal:
        args.host = args.host or "127.0.0.1"

    cap = datetime.now().strftime("%Y%m%d-%H%M%S")
    bukti = BASE / args.keluaran / cap
    mesin = MesinLokal(args, bukti) if args.lokal else MesinSSH(args, bukti)

    argumen_receiver = [
        mesin.skrip("receiver_node-v3.py"),
        "127.0.0.1" if args.lokal else "0.0.0.0",
        str(args.port),
        "--reply", args.balasan,
        "--count", str(args.count),
        "--expect", args.pesan,
        "--log", mesin.jalur("receiver.log"),
        "--timeout", str(args.timeout_receiver),
    ]
    argumen_sender = [
        str(BASE / "sender_node-v3.py"), args.host, str(args.port),
        "--send", args.pesan, "--count", str(args.count), "--expect", harapan_sender,
        "--log", str(bukti / "sender.log"), "--timeout", "20",
    ]

    if args.dry_run:
        print("[DRY-RUN] receiver :", " ".join(shlex.quote(a) for a in argumen_receiver))
        print("[DRY-RUN] sender   :", " ".join(shlex.quote(a) for a in argumen_sender))
        print(f"[DRY-RUN] bukti    : {bukti}")
        return 0

    bukti.mkdir(parents=True, exist_ok=True)
    print(f"[BUKTI] {bukti}")

    handle = None
    try:
        mesin.periksa()
        mesin.siapkan(kirim_berkas=not args.tanpa_kirim)
        print(f"[UJI] {args.count} pesan, {args.pesan!r} <-> {args.balasan!r}")

        handle = mesin.mulai(argumen_receiver, mesin.jalur("receiver_out.txt"), "kode_receiver.txt")

        batas = time.time() + args.timeout_siap
        siap = False
        while time.time() < batas:
            if "Menunggu koneksi" in mesin.baca("receiver_out.txt"):
                siap = True
                break
            if mesin.kode(handle, "kode_receiver.txt") is not None:
                break
            time.sleep(0.3)
        if not siap:
            raise GagalUji(
                "receiver tidak siap. Keluaran VM:\n"
                + baca_teks(bukti / "receiver_out.txt")[-600:]
            )

        mulai = time.perf_counter()
        try:
            pengirim = subprocess.run(
                [sys.executable, *argumen_sender], cwd=BASE, capture_output=True,
                text=True, encoding="utf-8", errors="replace", timeout=args.timeout_uji,
            )
        except subprocess.TimeoutExpired:
            raise GagalUji(f"sender tidak selesai dalam {args.timeout_uji:.0f} detik")
        durasi = time.perf_counter() - mulai
        (bukti / "sender_out.txt").write_text(
            pengirim.stdout + pengirim.stderr, encoding="utf-8"
        )
        (bukti / "kode_sender.txt").write_text(str(pengirim.returncode), encoding="utf-8")

        mesin.ambil(["receiver_out.txt", "receiver.log", "kode_receiver.txt"], bukti)

        batas = time.time() + args.timeout_receiver + 10
        kode_penerima = None
        while time.time() < batas:
            kode_penerima = mesin.kode(handle, "kode_receiver.txt")
            if kode_penerima is not None:
                break
            time.sleep(0.3)
        if kode_penerima is None:
            raise GagalUji("exit code receiver tidak muncul; proses mungkin menggantung")

        (bukti / "kode_receiver.txt").write_text(str(kode_penerima), encoding="utf-8")
        isi_r = baca_teks(bukti / "receiver.log")
        isi_s = baca_teks(bukti / "sender.log")
        rx = isi_r.count("EVENT=RX")
        tx = isi_s.count("EVENT=TX")
        peer = sorted({baris.split("PEER=")[1].split()[0].split(":")[0]
                       for baris in isi_r.splitlines() if "PEER=" in baris})

        ip_lokal = ip_lokal_ke(args.host, args.port)
        info_ip = mesin.ip()
        ip_remote = info_ip.split()[0] if info_ip.split() else "tidak diketahui"
        lulus = (pengirim.returncode == 0 and kode_penerima == 0
                 and rx == args.count and tx == args.count)

        ringkasan = [
            f"waktu            : {datetime.now().isoformat(timespec='seconds')}",
            f"mode             : {'lokal' if args.lokal else 'ssh'}",
            f"host tujuan      : {args.host}:{args.port}",
            f"IP lokal         : {ip_lokal}",
            f"IP remote        : {ip_remote}",
            f"peer di log      : {', '.join(peer) or 'tidak ada'}",
            f"pesan            : {args.count}",
            f"durasi sender    : {durasi:.3f} s",
            f"exit sender      : {pengirim.returncode}",
            f"exit receiver    : {kode_penerima}",
            f"RX di receiver   : {rx}",
            f"TX di sender     : {tx}",
            f"hasil            : {'LULUS' if lulus else 'GAGAL'}",
        ]
        (bukti / "ringkasan.txt").write_text("\n".join(ringkasan) + "\n", encoding="utf-8")
        (bukti / "perintah.txt").write_text(
            "receiver: " + " ".join(shlex.quote(a) for a in argumen_receiver)
            + "\nsender  : " + " ".join(shlex.quote(a) for a in argumen_sender)
            + f"\nbukti   : {bukti}\n",
            encoding="utf-8",
        )
        (bukti / "ip_remote.txt").write_text(info_ip + "\n", encoding="utf-8")

        print("\n" + "-" * 58)
        for baris in ringkasan:
            print(baris)
        print("-" * 58)
        print(f"[HASIL] {'LULUS' if lulus else 'GAGAL'} — bukti di {bukti}")
        if not lulus:
            print("[PETUNJUK] Periksa receiver_out.txt dan sender_out.txt di folder bukti.")
        return 0 if lulus else 1

    except GagalUji as e:
        print(f"\n[GAGAL] {e}")
        return 2
    finally:
        if handle is not None:
            mesin.hentikan(handle)


if __name__ == "__main__":
    sys.exit(main())
