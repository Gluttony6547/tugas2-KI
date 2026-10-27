# kdc.py
"""Key Distribution Center (KDC) untuk skenario Needham-Schroeder.

Melayani langkah 1-2:
  1. A -> KDC : ID_A || ID_B || N1                  (JSON polos, sesuai PPT)
  2. KDC -> A : E_KA[ K_S || ID_A || ID_B || N1 || E_KB[ K_S || ID_A ] ]

Semua enkripsi memakai ManualAES (CBC, kunci ASCII 16 karakter). KDC memegang
kunci master setiap pengguna dan tidak pernah mengirimkannya ke jaringan.
"""

import argparse
import json
import secrets
import socket
import string
import sys
import threading
from datetime import datetime

import konfigurasi
from aes_manual import KunciTidakValid, ManualAES
from jaringan import Catatan, FrameError, endpoint, kirim_json, terima_json

ALFABET_KUNCI = string.ascii_letters + string.digits
DEFAULT_PORT = 5000


def siapkan_stdout():
    # Konsol Windows bisa memakai cp1252 dan gagal untuk karakter UTF-8.
    for aliran in (sys.stdout, sys.stderr):
        if hasattr(aliran, "reconfigure"):
            aliran.reconfigure(encoding="utf-8", errors="backslashreplace")


def buat_kunci_sesi() -> str:
    """Kunci sesi 16 karakter ASCII, dibuat baru untuk setiap permintaan."""
    return "".join(secrets.choice(ALFABET_KUNCI) for _ in range(16))


def baca_argumen(argv):
    p = argparse.ArgumentParser(description="KDC (Key Distribution Center) AES manual")
    p.add_argument("--konfigurasi", default=None, help="berkas konfigurasi JSON")
    p.add_argument("--bind", default="0.0.0.0", help="alamat dengarkan, default 0.0.0.0")
    p.add_argument("--port", type=int, default=None, help="port KDC; menimpa konfigurasi")
    p.add_argument("--kunci-alice", default=None, help="kunci master Alice (16 ASCII)")
    p.add_argument("--kunci-bob", default=None, help="kunci master Bob (16 ASCII)")
    p.add_argument("--log", default=None, help="berkas catatan kejadian")
    p.add_argument("--tanpa-konsol", action="store_true", help="nonaktifkan konsol interaktif")
    return p.parse_args(argv)


class KDC:
    def __init__(self, kunci_master, log, timeout=15.0):
        self.kunci_master = {k: ManualAES(v) for k, v in kunci_master.items()}
        self.log = log
        self.timeout = timeout
        self.sesi = []
        self._nomor_sesi = 0
        self._kunci_konsol = threading.Lock()
        self.berhenti = threading.Event()
        self._server = None

    def catat(self, *args, **kwargs):
        self.log.tulis(*args, **kwargs)

    def layani_permintaan(self, permintaan):
        """Bangun langkah 2 dari langkah 1, atau kembalikan pesan kesalahan."""
        if not isinstance(permintaan, dict) or permintaan.get("tipe") != "permintaan_kdc":
            raise ValueError("tipe pesan harus 'permintaan_kdc'")

        id_a = permintaan.get("id_a")
        id_b = permintaan.get("id_b")
        n1 = permintaan.get("n1")
        if id_a not in self.kunci_master or id_b not in self.kunci_master:
            raise ValueError(f"identitas tidak terdaftar: {id_a!r} / {id_b!r}")
        if id_a == id_b:
            raise ValueError("ID_A dan ID_B tidak boleh sama")
        if not isinstance(n1, int) or isinstance(n1, bool):
            raise ValueError("N1 harus bilangan bulat")

        with self._kunci_konsol:
            self._nomor_sesi += 1
            sesi_id = f"S-{self._nomor_sesi:03d}"

        ks = buat_kunci_sesi()
        waktu = datetime.now().isoformat(timespec="seconds")
        isi_tiket = {
            "ks": ks,
            "id_a": id_a,
            "id_b": id_b,
            "waktu": waktu,
        }
        tiket = self.kunci_master[id_b].enkripsi(
            json.dumps(isi_tiket, ensure_ascii=True).encode()
        ).hex()

        isi_balasan = {
            "ks": ks,
            "id_a": id_a,
            "id_b": id_b,
            "n1": n1,
            "tiket": tiket,
        }
        data = self.kunci_master[id_a].enkripsi(
            json.dumps(isi_balasan, ensure_ascii=True).encode()
        ).hex()

        with self._kunci_konsol:
            self.sesi.append(
                {
                    "id": sesi_id,
                    "ks": ks,
                    "id_a": id_a,
                    "id_b": id_b,
                    "waktu": waktu,
                }
            )
        print(f"[LANGKAH 1] {id_a} -> KDC: ID_A={id_a} ID_B={id_b} N1={n1}")
        print(f"[LANGKAH 2] KDC -> {id_a}: sesi={sesi_id} K_S={ks}")
        print(f"             E_KA[K_S...tiket] = {data}")
        print(f"             Tiket E_KB[K_S, ID_A] = {tiket}")
        self.catat(
            "LANGKAH2",
            teks=f"sesi={sesi_id} id_a={id_a} id_b={id_b} n1={n1} ks={ks}",
            data=bytes.fromhex(data),
            info=f"tiket={tiket}",
        )
        return {"tipe": "balasan_kdc", "sesi_id": sesi_id, "data": data}

    def tangani_koneksi(self, conn, peer):
        conn.settimeout(self.timeout)
        try:
            permintaan = terima_json(conn, self.log)
            if permintaan is None:
                return
            self.log.tulis(
                "LANGKAH1", peer,
                teks=(f"id_a={permintaan.get('id_a')} "
                      f"id_b={permintaan.get('id_b')} n1={permintaan.get('n1')}"),
            )
            try:
                balasan = self.layani_permintaan(permintaan)
            except (ValueError, KunciTidakValid, FrameError) as e:
                print(f"[TOLAK] {endpoint(peer)}: {e}")
                self.catat("TOLAK", peer, teks=str(e))
                balasan = {"tipe": "error", "pesan": str(e)}
            kirim_json(conn, balasan, self.log)
        except (FrameError, OSError) as e:
            print(f"[ERROR] {endpoint(peer)}: {e}")
            self.catat("ERROR", peer, teks=str(e))
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def jalankan(self, host, port):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(5)
        server.settimeout(1.0)
        self._server = server
        print("=" * 62)
        print("                 KDC - KEY DISTRIBUTION CENTER")
        print("=" * 62)
        print(f"[MENDENGAR] {host}:{port}")
        for nama, cipher in self.kunci_master.items():
            print(f"[KUNCI]     {nama:<6} = {cipher.kunci.decode()} (16 ASCII)")
        print("Ketik /bantu untuk daftar perintah.")
        print("=" * 62 + "\n")
        self.catat("MENDENGAR", info=f"bind={host}:{port}")

        while not self.berhenti.is_set():
            try:
                conn, peer = server.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                break
            threading.Thread(
                target=self.tangani_koneksi, args=(conn, peer), daemon=True
            ).start()

        try:
            server.close()
        except OSError:
            pass

    def tutup(self):
        self.berhenti.set()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass

    def tampilkan_sesi(self):
        with self._kunci_konsol:
            daftar = list(self.sesi)
        if not daftar:
            print("[SESI] Belum ada sesi yang diterbitkan.")
            return
        print(f"[SESI] {len(daftar)} sesi diterbitkan:")
        for s in daftar[-10:]:
            print(f"  {s['id']}  {s['waktu']}  {s['id_a']} <-> {s['id_b']}  K_S={s['ks']}")

    def konsol(self):
        bantuan = (
            "/sesi   daftar sesi yang sudah diterbitkan\n"
            "/kunci  tampilkan kunci master yang dipegang KDC\n"
            "/bantu  daftar perintah\n"
            "/keluar hentikan KDC"
        )
        print("[KONSOL] " + bantuan.replace("\n", "\n[KONSOL] "))
        while not self.berhenti.is_set():
            try:
                baris = input("kdc> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not baris:
                continue
            if baris in ("/keluar", "/exit", "/quit"):
                break
            if baris == "/sesi":
                self.tampilkan_sesi()
            elif baris == "/kunci":
                for nama, cipher in self.kunci_master.items():
                    print(f"[KUNCI] {nama}: {cipher.kunci.decode()} (16 ASCII)")
            elif baris in ("/bantu", "/help"):
                print("[KONSOL] " + bantuan.replace("\n", "\n[KONSOL] "))
            else:
                print("[KONSOL] Perintah tidak dikenal. Ketik /bantu.")
        self.tutup()


def main(argv=None):
    siapkan_stdout()
    args = baca_argumen(argv or sys.argv[1:])
    try:
        konf = konfigurasi.muat(args.konfigurasi)
    except konfigurasi.KonfigurasiError as e:
        print(f"[ERROR] {e}")
        return 4

    bagian = dict(konf["kdc"])
    if args.port is not None:
        bagian["port"] = args.port
    kunci = dict(bagian["kunci_master"])
    if args.kunci_alice:
        kunci["alice"] = args.kunci_alice
    if args.kunci_bob:
        kunci["bob"] = args.kunci_bob
    try:
        log = Catatan(args.log, "kdc")
        kdc = KDC(kunci, log, konf["jaringan"]["timeout"])
    except KunciTidakValid as e:
        print(f"[ERROR] Kunci master tidak valid: {e}")
        return 4

    port = bagian["port"]
    print(f"[INFO] Kunci master dimuat untuk: {', '.join(kunci)}")
    if args.tanpa_konsol:
        try:
            kdc.jalankan(args.bind, port)
        except KeyboardInterrupt:
            pass
        except OSError as e:
            print(f"[ERROR] Gagal mendengarkan di {args.bind}:{port}: {e}")
            log.tutup()
            return 2
    else:
        threading.Thread(
            target=kdc.jalankan, args=(args.bind, port), daemon=True
        ).start()
        try:
            kdc.konsol()
        except KeyboardInterrupt:
            kdc.tutup()
    log.tutup()
    return 0


if __name__ == "__main__":
    sys.exit(main())
