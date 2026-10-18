# test_des.py
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

from cipher_manual import ManualDES
from transport import (
    BATAS_FRAME,
    DataTidakCocok,
    FrameError,
    dekripsi_terverifikasi,
    kirim_pesan,
    terima_pesan,
)

KUNCI = b"KunciDES"
PY = sys.executable


class UjiCipher(unittest.TestCase):
    def test_vektor_standar(self):
        hasil = ManualDES(bytes.fromhex("133457799BBCDFF1")).encrypt(
            bytes.fromhex("0123456789ABCDEF")
        )
        self.assertEqual(hasil.hex().upper()[:16], "85E813540F0AB405")

    def test_vektor_nol(self):
        hasil = ManualDES(bytes.fromhex("0E329232EA6D0D73")).encrypt(
            bytes.fromhex("8787878787878787")
        )
        self.assertEqual(hasil.hex().upper()[:16], "0000000000000000")

    def test_roundtrip_panjang_0_sampai_17(self):
        cipher = ManualDES(KUNCI)
        for panjang in range(18):
            with self.subTest(panjang=panjang):
                data = b"A" * panjang
                self.assertEqual(cipher.decrypt(cipher.encrypt(data)), data)

    def test_padding_selalu_kelipatan_8(self):
        cipher = ManualDES(KUNCI)
        for panjang in range(18):
            with self.subTest(panjang=panjang):
                self.assertEqual(len(cipher.encrypt(b"B" * panjang)) % 8, 0)

    def test_utf8_dan_payload_besar(self):
        cipher = ManualDES(KUNCI)
        data = "Halo, dunia! Pesan rahasia — ñ, ü, 🔐, 日本語. " * 32
        hasil = cipher.decrypt(cipher.encrypt(data.encode("utf-8")))
        self.assertEqual(hasil.decode("utf-8"), data)

    def test_kunci_berbeda_tidak_menghasilkan_plaintext(self):
        data = b"rahasia negara"
        terenkripsi = ManualDES(KUNCI).encrypt(data)
        hasil = ManualDES(b"SalahKey").decrypt(terenkripsi)
        self.assertNotEqual(hasil, data)

    def test_verifikasi_kunci(self):
        terenkripsi = ManualDES(KUNCI).encrypt(b"rahasia")
        self.assertEqual(dekripsi_terverifikasi(ManualDES(KUNCI), terenkripsi), b"rahasia")
        with self.assertRaises(DataTidakCocok):
            dekripsi_terverifikasi(ManualDES(b"SalahKey"), terenkripsi)


class UjiFraming(unittest.TestCase):
    def setUp(self):
        self.kirim, self.terima = socket.socketpair()
        self.addCleanup(self.kirim.close)
        self.addCleanup(self.terima.close)

    def test_dua_pesan_berurutan_tetap_terpisah(self):
        kirim_pesan(self.kirim, b"satu")
        kirim_pesan(self.kirim, b"dua")
        self.assertEqual(terima_pesan(self.terima), b"satu")
        self.assertEqual(terima_pesan(self.terima), b"dua")

    def test_bacaan_terpecah_satu_byte(self):
        class RecvSatuByte:
            def __init__(self, sock):
                self.sock = sock

            def recv(self, _):
                return self.sock.recv(1)

        data = b"ciphertext-des" * 4
        kirim_pesan(self.kirim, data)
        self.assertEqual(terima_pesan(RecvSatuByte(self.terima)), data)

    def test_payload_kosong(self):
        kirim_pesan(self.kirim, b"")
        self.assertEqual(terima_pesan(self.terima), b"")

    def test_frame_terpotong(self):
        self.kirim.sendall(struct.pack("!I", 32) + b"1234567890")
        self.kirim.shutdown(socket.SHUT_WR)
        with self.assertRaises(FrameError):
            terima_pesan(self.terima)

    def test_frame_melebihi_batas_ditolak(self):
        self.kirim.sendall(struct.pack("!I", BATAS_FRAME + 1))
        with self.assertRaises(FrameError):
            terima_pesan(self.terima)

    def test_peer_menutup_rapi(self):
        self.kirim.close()
        self.assertIsNone(terima_pesan(self.terima))


def _port_bebas():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _tunggu_teks(path, teks, batas=10.0):
    akhir = time.time() + batas
    while time.time() < akhir:
        if path.exists() and teks in path.read_text(encoding="utf-8", errors="replace"):
            return True
        time.sleep(0.05)
    return False


class UjiEndToEnd(unittest.TestCase):
    def jalankan(self, jumlah, pesan, balasan, expect_pengirim=None, kunci_pengirim=None):
        port = _port_bebas()
        folder = Path(tempfile.mkdtemp(prefix="des_uji_"))
        keluaran = folder / "receiver.out"
        log_receiver = folder / "receiver.log"
        log_sender = folder / "sender.log"

        with open(keluaran, "w", encoding="utf-8") as fout:
            receiver = subprocess.Popen(
                [PY, str(BASE / "receiver_node-v3.py"), "127.0.0.1", str(port),
                 "--reply", balasan, "--count", str(jumlah), "--expect", pesan,
                 "--log", str(log_receiver)],
                cwd=BASE, stdout=fout, stderr=subprocess.STDOUT, text=True,
            )
        self.addCleanup(lambda: receiver.poll() is None and receiver.kill())

        self.assertTrue(
            _tunggu_teks(keluaran, "Menunggu koneksi"),
            f"receiver tidak siap:\n{keluaran.read_text(encoding='utf-8', errors='replace')}",
        )

        harapan = expect_pengirim if expect_pengirim is not None else balasan
        mulai = time.perf_counter()
        perintah_pengirim = [
            PY, str(BASE / "sender_node-v3.py"), "127.0.0.1", str(port),
            "--send", pesan, "--count", str(jumlah), "--expect", harapan,
            "--log", str(log_sender),
        ]
        if kunci_pengirim:
            perintah_pengirim += ["--key", kunci_pengirim]
        pengirim = subprocess.run(
            perintah_pengirim, cwd=BASE, capture_output=True, text=True,
            encoding="utf-8", timeout=180,
        )
        durasi = time.perf_counter() - mulai
        receiver.wait(timeout=60)

        return pengirim, receiver, durasi, log_receiver, log_sender, keluaran

    def test_pertukaran_50_pesan_utuh(self):
        pengirim, receiver, durasi, log_r, log_s, keluaran = self.jalankan(
            50, "PING lintas host", "OK dari receiver"
        )
        self.assertEqual(pengirim.returncode, 0, pengirim.stdout + pengirim.stderr)
        self.assertEqual(receiver.returncode, 0,
                         keluaran.read_text(encoding="utf-8", errors="replace"))
        self.assertIn("[HASIL] LULUS", pengirim.stdout)

        isi_r = log_r.read_text(encoding="utf-8")
        isi_s = log_s.read_text(encoding="utf-8")
        self.assertEqual(isi_r.count("EVENT=RX"), 50)
        self.assertEqual(isi_r.count("EVENT=TX"), 50)
        self.assertEqual(isi_s.count("EVENT=TX"), 50)
        self.assertEqual(isi_s.count("EVENT=RX"), 50)
        self.assertNotIn("\\x08", isi_r)

        print(f"\n[UKUR] 50 pesan dua arah: {durasi:.2f} s "
              f"({durasi / 50 * 1000:.1f} ms per pertukaran)", file=sys.stderr)

    def test_balasan_tidak_sesuai_harapan_gagal(self):
        pengirim, _, _, _, _, _ = self.jalankan(1, "PING", "OK", expect_pengirim="SALAH")
        self.assertEqual(pengirim.returncode, 3, pengirim.stdout + pengirim.stderr)

    def test_psk_berbeda_gagal_jelas(self):
        pengirim, receiver, _, _, _, keluaran = self.jalankan(
            1, "PING", "OK", kunci_pengirim="SalahKey"
        )
        self.assertEqual(receiver.returncode, 3,
                         keluaran.read_text(encoding="utf-8", errors="replace"))
        self.assertIn("PSK", keluaran.read_text(encoding="utf-8", errors="replace"))
        self.assertIn(pengirim.returncode, (2, 3),
                      pengirim.stdout + pengirim.stderr)

    def test_psk_bukan_8_byte_ditolak(self):
        hasil = subprocess.run(
            [PY, str(BASE / "sender_node-v3.py"), "127.0.0.1", "65432",
             "--send", "PING", "--key", "KunciDES67"],
            cwd=BASE, capture_output=True, text=True, encoding="utf-8", timeout=30,
        )
        self.assertEqual(hasil.returncode, 4)
        self.assertIn("8 byte", hasil.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
