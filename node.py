# node.py
"""Node Alice/Bob: skenario distribusi kunci 5 langkah + komunikasi AES 2 arah.

Langkah (Needham-Schroeder, sesuai PPT):
  1. A -> KDC : ID_A || ID_B || N1
  2. KDC -> A : E_KA[K_S || ID_A || ID_B || N1 || E_KB[K_S || ID_A]]
  3. A -> B   : E_KB[K_S || ID_A]
  4. B -> A   : E_KS[N2]
  5. A -> B   : E_KS[N2 - 1]
Setelah itu Alice dan Bob bertukar pesan dengan E_KS[pesan].

Satu program dipakai untuk kedua peran; Alice yang memulai handshake, Bob
mendengarkan. Setelah sesi terbentuk kedua sisi bisa mengirim dan menerima.
"""

import argparse
import sys
import threading

import konfigurasi
from aes_manual import KunciTidakValid, ManualAES
from jaringan import Catatan
from konsol import KonsolNode
from protokol import ProtokolError, ProtokolNode
from sesi import Sesi


def baca_argumen(argv):
    p = argparse.ArgumentParser(description="Node Alice/Bob - KDC + AES manual 2 arah")
    p.add_argument("--peran", required=True, choices=("alice", "bob"), help="peran node")
    p.add_argument("--konfigurasi", default=None, help="berkas konfigurasi JSON")
    p.add_argument("--id", default=None, help="ID node; menimpa konfigurasi")
    p.add_argument("--kdc-host", default=None, help="IP KDC; menimpa konfigurasi")
    p.add_argument("--kdc-port", type=int, default=None, help="port KDC")
    p.add_argument("--bind", default=None,
                   help="alamat bind: Bob mendengarkan; Alice memakai ini sebagai IP sumber")
    p.add_argument("--port", type=int, default=None, help="port dengarkan Bob")
    p.add_argument("--lawan-host", default=None, help="IP lawan (dipakai Alice)")
    p.add_argument("--lawan-port", type=int, default=None, help="port lawan (dipakai Alice)")
    p.add_argument("--kunci", default=None, help="kunci master node ini (16 ASCII)")
    p.add_argument("--log", default=None, help="berkas catatan kejadian")
    p.add_argument("--tanpa-konsol", action="store_true", help="mode otomatis tanpa input()")
    p.add_argument("--kirim", default=None, help="kirim teks otomatis setelah handshake")
    p.add_argument("--jumlah", type=int, default=1, help="jumlah pesan kirim/balas otomatis")
    p.add_argument("--balas", default=None, help="balas otomatis setiap pesan masuk")
    p.add_argument("--harap-balasan", type=int, default=0, help="tunggu N balasan lalu keluar")
    p.add_argument("--rotasi-setelah", type=int, default=0,
                   help="ganti kunci setelah N pesan terkirim (mode otomatis)")
    p.add_argument("--batas", type=float, default=30.0, help="detik batas mode otomatis")
    return p.parse_args(argv)


def siapkan_stdout():
    for aliran in (sys.stdout, sys.stderr):
        if hasattr(aliran, "reconfigure"):
            aliran.reconfigure(encoding="utf-8", errors="backslashreplace")




class Node(ProtokolNode, KonsolNode):
    def __init__(self, args, konf):
        self.args = args
        self.peran = args.peran
        bagian = konf[self.peran]
        lawan = "bob" if self.peran == "alice" else "alice"
        bagian_lawan = konf[lawan]
        kdc = konf["kdc"]

        self.id_diri = args.id or bagian.get("id", self.peran)
        self.id_lawan = bagian_lawan.get("id", lawan)
        self.kunci_master = ManualAES(args.kunci or bagian["kunci_master"])
        self.kdc_host = args.kdc_host or kdc["host"]
        self.kdc_port = args.kdc_port or kdc["port"]
        self.lawan_host = args.lawan_host or bagian_lawan["host"]
        self.lawan_port = args.lawan_port or bagian_lawan.get("port")
        self.bind = args.bind or (bagian.get("host") if self.peran == "alice" else None)
        self.port = args.port or bagian.get("port")
        self.timeout = konf["jaringan"]["timeout"]
        self.log = Catatan(args.log, self.peran)
        self.sesi = Sesi()
        self.koneksi = None
        self.server = None
        self.thread_penerima = None
        self.thread_server = None
        self.berhenti = threading.Event()
        self.selesai = threading.Event()
        self.ack_kunci = threading.Event()
        self.sisa_balasan = args.jumlah if args.balas else 0
        self.kode = 0
        self.interaktif = not args.tanpa_konsol


def main(argv=None):
    siapkan_stdout()
    args = baca_argumen(argv or sys.argv[1:])
    try:
        konf = konfigurasi.muat(args.konfigurasi)
        node = Node(args, konf)
    except konfigurasi.KonfigurasiError as e:
        print(f"[ERROR] {e}")
        return 4
    except (KunciTidakValid, KeyError) as e:
        print(f"[ERROR] Konfigurasi/kunci tidak valid: {e}")
        return 4

    try:
        if args.peran == "alice":
            node.jalankan_alice()
        else:
            node.jalankan_bob()
    except KeyboardInterrupt:
        print("\n[INFO] Dihentikan pengguna.")
    finally:
        node.tutup()
    return node.kode


if __name__ == "__main__":
    sys.exit(main())
