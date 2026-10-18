# receiver_node-v3.py
import argparse
import os
import socket
import sys
import threading

from cipher_manual import ManualDES
from transport import (
    CatatanUji,
    DataTidakCocok,
    FrameError,
    dekripsi_terverifikasi,
    kirim_pesan,
    terima_pesan,
)

KUNCI_BAWAAN = "KunciDES"


def siapkan_stdout():
    # Konsol Windows bisa memakai cp1252 dan gagal saat pesan berisi UTF-8.
    for aliran in (sys.stdout, sys.stderr):
        if hasattr(aliran, "reconfigure"):
            aliran.reconfigure(encoding="utf-8", errors="backslashreplace")


def baca_argumen(argv):
    p = argparse.ArgumentParser(description="Receiver DES 2 arah (Node A)")
    p.add_argument("host", nargs="?", default="0.0.0.0", help="alamat bind, default 0.0.0.0")
    p.add_argument("port", nargs="?", type=int, default=65432)
    p.add_argument("--reply", action="append", metavar="TEKS", help="balas otomatis, boleh diulang")
    p.add_argument("--expect", metavar="TEKS", help="setiap pesan masuk harus sama dengan teks ini")
    p.add_argument("--count", type=int, default=1, help="jumlah pesan yang dilayani")
    p.add_argument("--key", default=os.environ.get("DES_PSK", KUNCI_BAWAAN), help="PSK tepat 8 byte")
    p.add_argument("--log", metavar="BERKAS", help="tulis bukti uji ke berkas")
    p.add_argument("--timeout", type=float, default=30.0, help="detik, untuk accept dan recv")
    p.add_argument("--selftest", action="store_true", help="cetak hasil vektor uji DES lalu keluar")
    return p.parse_args(argv)


def siapkan_kunci(teks):
    kunci = teks.encode("utf-8")
    if len(kunci) != 8:
        print(f"[ERROR] PSK harus tepat 8 byte, diterima {len(kunci)} byte: {teks!r}")
        sys.exit(4)
    return kunci


def selftest():
    vektor = [
        ("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"),
        ("0E329232EA6D0D73", "8787878787878787", "0000000000000000"),
    ]
    lulus = True
    for kunci_hex, pt_hex, ct_hex in vektor:
        hasil = ManualDES(bytes.fromhex(kunci_hex)).encrypt(bytes.fromhex(pt_hex))
        cocok = hasil.hex().upper()[:16] == ct_hex
        lulus &= cocok
        status = "OK" if cocok else "GAGAL"
        print(f"[SELFTEST] key={kunci_hex} pt={pt_hex} -> {hasil.hex().upper()[:16]} "
              f"(harap {ct_hex}) {status}")
    print("[SELFTEST] LULUS" if lulus else "[SELFTEST] GAGAL")
    sys.exit(0 if lulus else 3)


def daftar_pesan(daftar, jumlah):
    if not daftar:
        return [""] * jumlah
    return [daftar[i % len(daftar)] for i in range(jumlah)]


def tampilkan_terima(ciphertext, plaintext, nomor=None):
    label = f" #{nomor}" if nomor else ""
    print("\n" + "=" * 50)
    print(f"[DITERIMA]{label} Ciphertext DES (HEX) : {ciphertext.hex()}")
    print(f"[DITERIMA]{label} Plaintext Hasil      : {plaintext}")
    print("=" * 50)


def main():
    siapkan_stdout()
    args = baca_argumen(sys.argv[1:])
    if args.selftest:
        selftest()

    kunci = siapkan_kunci(args.key)
    cipher = ManualDES(kunci)
    otomatis = bool(args.reply)
    pesan_balasan = daftar_pesan(args.reply or [""], args.count)
    log = CatatanUji(args.log, "receiver")

    print("=" * 60)
    print("      SIMULASI KOMUNIKASI ENKRIPSI DES 2 ARAH - RECEIVER (NODE A)")
    print("=" * 60)
    print(f"[PSK CONFIG] Pre-Shared Key : {kunci.decode('utf-8', 'replace')} (8 byte)")
    print(f"[ALGORITMA]  Cipher Engine  : Manual DES (Data Encryption Standard)")
    print("=" * 60 + "\n", flush=True)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Di Windows SO_REUSEADDR membolehkan dua proses memakai port yang sama,
    # sehingga port bentrok tidak terdeteksi. Di POSIX opsi ini aman dan berguna.
    if os.name != "nt":
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_sock.bind((args.host, args.port))
        server_sock.listen(1)
        if otomatis:
            server_sock.settimeout(args.timeout)
        # Dicetak setelah listen() supaya penanda siap tidak muncul saat bind gagal.
        print(f"[STATUS]     Menunggu koneksi dari Sender di {args.host}:{args.port}...",
              flush=True)
        conn, addr = server_sock.accept()
    except (socket.timeout, TimeoutError):
        print(f"[ERROR] Tidak ada koneksi masuk dalam {args.timeout:.0f} detik.")
        print("        Cek IP tujuan di sender, port forwarding NAT, dan firewall.")
        server_sock.close()
        log.tutup()
        sys.exit(2)
    except OSError as e:
        print(f"[ERROR] Gagal membuka {args.host}:{args.port} -> {e}")
        if getattr(e, "errno", None) == 13 or "10013" in str(e):
            print("        Windows memesan port ini untuk sistem (bukan karena dipakai aplikasi).")
            print("        Coba port lain, mis. --port 55555.")
            print("        Cek: netsh interface ipv4 show excludedportrange protocol=tcp")
        else:
            print("        Port mungkin sudah dipakai proses lain.")
        server_sock.close()
        log.tutup()
        sys.exit(2)

    conn.settimeout(args.timeout)
    lokal = conn.getsockname()
    peer = conn.getpeername()
    print(f"[SUCCESS] Terhubung dengan Sender {peer[0]}:{peer[1]} -> lokal {lokal[0]}:{lokal[1]}\n")
    log.tulis("MULAI", peer, teks=f"lokal={lokal[0]}:{lokal[1]}")

    kode_keluar = 0
    try:
        if otomatis:
            for nomor, balasan in enumerate(pesan_balasan, 1):
                ciphertext = terima_pesan(conn)
                if ciphertext is None:
                    print(f"\n[ERROR] Sender menutup koneksi sebelum pesan #{nomor}.")
                    kode_keluar = 2
                    break
                plaintext = dekripsi_terverifikasi(cipher, ciphertext).decode(
                    "utf-8", errors="replace"
                )
                tampilkan_terima(ciphertext, plaintext, nomor)
                log.tulis("RX", peer, ciphertext, plaintext)
                if args.expect is not None and plaintext != args.expect:
                    print(f"[HASIL] GAGAL: pesan #{nomor} {plaintext!r} != harapan {args.expect!r}")
                    kode_keluar = 3
                    break

                ciphertext_balasan = cipher.encrypt(balasan.encode("utf-8"))
                kirim_pesan(conn, ciphertext_balasan)
                print(f"[TERKIRIM] #{nomor} Ciphertext DES (HEX) : {ciphertext_balasan.hex()}")
                print(f"[TERKIRIM] #{nomor} Panjang           : {len(ciphertext_balasan)} byte")
                log.tulis("TX", peer, ciphertext_balasan, balasan)

            if kode_keluar == 0:
                catatan = "" if args.expect is not None else " (isi tidak diverifikasi)"
                print(f"\n[HASIL] LULUS: {len(pesan_balasan)} pesan diterima, "
                      f"{len(pesan_balasan)} balasan terkirim{catatan}.")
        else:
            def penerima():
                while True:
                    try:
                        ciphertext = terima_pesan(conn)
                    except (FrameError, OSError):
                        break
                    if ciphertext is None:
                        print("\n[INFO] Sender telah memutuskan koneksi.")
                        break
                    try:
                        plaintext = dekripsi_terverifikasi(cipher, ciphertext).decode(
                            "utf-8", errors="replace"
                        )
                    except DataTidakCocok as e:
                        print(f"\n[ERROR] {e}")
                        break
                    tampilkan_terima(ciphertext, plaintext)
                    log.tulis("RX", peer, ciphertext, plaintext)
                    print("[RECEIVER] Masukkan pesan balasan: ", end="", flush=True)

            threading.Thread(target=penerima, daemon=True).start()
            while True:
                pesan = input("[RECEIVER] Masukkan pesan balasan: ")
                if pesan.lower() == "exit":
                    print("[INFO] Menghentikan program...")
                    break
                if not pesan.strip():
                    continue
                ciphertext = cipher.encrypt(pesan.encode("utf-8"))
                kirim_pesan(conn, ciphertext)
                print(f"[TERKIRIM] Ciphertext DES (HEX) : {ciphertext.hex()}")
                log.tulis("TX", peer, ciphertext, pesan)

    except DataTidakCocok as e:
        print(f"\n[ERROR] {e}")
        kode_keluar = 3
    except FrameError as e:
        print(f"\n[ERROR] Frame rusak: {e}")
        kode_keluar = 5
    except (socket.timeout, TimeoutError):
        print(f"\n[ERROR] Timeout menunggu data ({args.timeout:.0f} detik).")
        kode_keluar = 2
    except OSError as e:
        print(f"\n[ERROR] Koneksi terputus: {e}")
        kode_keluar = 2
    except KeyboardInterrupt:
        print("\n[INFO] Program dihentikan pengguna.")
    finally:
        log.tulis("SELESAI", peer, teks=f"exit={kode_keluar}")
        log.tutup()
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()
        server_sock.close()

    sys.exit(kode_keluar)


if __name__ == "__main__":
    main()
