# sender_node-v3.py
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
    p = argparse.ArgumentParser(description="Sender DES 2 arah (Node B)")
    p.add_argument("host", nargs="?", help="IP receiver; ditanyakan bila kosong")
    p.add_argument("port", nargs="?", type=int, default=65432)
    p.add_argument("--send", action="append", metavar="TEKS", help="kirim otomatis, boleh diulang")
    p.add_argument("--expect", metavar="TEKS", help="setiap balasan harus sama dengan teks ini")
    p.add_argument("--count", type=int, default=1, help="jumlah pesan yang dipertukarkan")
    p.add_argument("--key", default=os.environ.get("DES_PSK", KUNCI_BAWAAN), help="PSK tepat 8 byte")
    p.add_argument("--log", metavar="BERKAS", help="tulis bukti uji ke berkas")
    p.add_argument("--timeout", type=float, default=10.0, help="detik, untuk connect dan recv")
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
    otomatis = bool(args.send)
    pesan_keluar = daftar_pesan(args.send or [""], args.count)
    log = CatatanUji(args.log, "sender")

    host = args.host
    if host is None:
        if otomatis:
            host = "127.0.0.1"
        else:
            jawab = input("[SENDER] Masukkan IP Target Receiver (Default '127.0.0.1'): ").strip()
            host = jawab or "127.0.0.1"

    print("=" * 60)
    print("      SIMULASI KOMUNIKASI ENKRIPSI DES 2 ARAH - SENDER (NODE B)")
    print("=" * 60)
    print(f"[PSK CONFIG] Pre-Shared Key : {kunci.decode('utf-8', 'replace')} (8 byte)")
    print(f"[ALGORITMA]  Cipher Engine  : Manual DES (Data Encryption Standard)")
    print(f"[TARGET]     IP Receiver     : {host}")
    print(f"[PORT]       Port Socket    : {args.port}")
    print(f"[STATUS]     Menghubungkan ke Receiver...")
    print("=" * 60 + "\n")

    try:
        client_sock = socket.create_connection((host, args.port), timeout=args.timeout)
    except ConnectionRefusedError:
        print(f"[ERROR] Gagal terhubung ke {host}:{args.port}.")
        print("        Pastikan receiver_node-v3.py berjalan dan firewall mengizinkan port ini.")
        log.tutup()
        sys.exit(2)
    except (socket.timeout, TimeoutError):
        print(f"[ERROR] Timeout {args.timeout:.0f} detik saat menghubungi {host}:{args.port}.")
        print("        Cek rute/NAT/port forwarding dan firewall di mesin receiver.")
        log.tutup()
        sys.exit(2)
    except OSError as e:
        print(f"[ERROR] Kendala jaringan: {e}")
        log.tutup()
        sys.exit(2)

    client_sock.settimeout(args.timeout)
    lokal = client_sock.getsockname()
    peer = client_sock.getpeername()
    print(f"[SUCCESS] Terhubung: {lokal[0]}:{lokal[1]} -> {peer[0]}:{peer[1]}\n")
    log.tulis("MULAI", peer, teks=f"lokal={lokal[0]}:{lokal[1]}")

    kode_keluar = 0
    try:
        if otomatis:
            for nomor, pesan in enumerate(pesan_keluar, 1):
                ciphertext = cipher.encrypt(pesan.encode("utf-8"))
                kirim_pesan(client_sock, ciphertext)
                print(f"[TERKIRIM] #{nomor} Ciphertext DES (HEX) : {ciphertext.hex()}")
                print(f"[TERKIRIM] #{nomor} Panjang           : {len(ciphertext)} byte")
                log.tulis("TX", peer, ciphertext, pesan)

                balasan = terima_pesan(client_sock)
                if balasan is None:
                    print(f"\n[ERROR] Receiver menutup koneksi sebelum balasan #{nomor}.")
                    kode_keluar = 2
                    break
                plaintext = dekripsi_terverifikasi(cipher, balasan).decode(
                    "utf-8", errors="replace"
                )
                tampilkan_terima(balasan, plaintext, nomor)
                log.tulis("RX", peer, balasan, plaintext)
                if args.expect is not None and plaintext != args.expect:
                    print(f"[HASIL] GAGAL: balasan #{nomor} {plaintext!r} != harapan {args.expect!r}")
                    kode_keluar = 3
                    break

            if kode_keluar == 0:
                catatan = "" if args.expect is not None else " (isi tidak diverifikasi)"
                print(f"\n[HASIL] LULUS: {len(pesan_keluar)} pesan terkirim, "
                      f"{len(pesan_keluar)} balasan diterima{catatan}.")
        else:
            def penerima():
                while True:
                    try:
                        ciphertext = terima_pesan(client_sock)
                    except (FrameError, OSError):
                        break
                    if ciphertext is None:
                        print("\n[INFO] Receiver telah memutuskan koneksi.")
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
                    print("[SENDER] Masukkan pesan untuk dikirim: ", end="", flush=True)

            threading.Thread(target=penerima, daemon=True).start()
            while True:
                pesan = input("[SENDER] Masukkan pesan untuk dikirim: ")
                if pesan.lower() == "exit":
                    print("[INFO] Menghentikan program...")
                    break
                if not pesan.strip():
                    continue
                ciphertext = cipher.encrypt(pesan.encode("utf-8"))
                kirim_pesan(client_sock, ciphertext)
                print(f"[TERKIRIM] Ciphertext DES (HEX) : {ciphertext.hex()}")
                log.tulis("TX", peer, ciphertext, pesan)

    except DataTidakCocok as e:
        print(f"\n[ERROR] {e}")
        kode_keluar = 3
    except FrameError as e:
        print(f"\n[ERROR] Frame rusak: {e}")
        kode_keluar = 5
    except (socket.timeout, TimeoutError):
        print(f"\n[ERROR] Timeout menunggu balasan ({args.timeout:.0f} detik).")
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
            client_sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        client_sock.close()

    sys.exit(kode_keluar)


if __name__ == "__main__":
    main()
