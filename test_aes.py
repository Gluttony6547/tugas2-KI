# test_aes.py
import contextlib
import io
import json
import unittest

import konfigurasi
from aes_manual import DataTidakValid, KunciTidakValid, ManualAES
from kdc import KDC


class UjiVektorAES(unittest.TestCase):
    def test_fips_197_c1_enkripsi(self):
        cipher = ManualAES(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
        hasil = cipher.enkripsi_blok(bytes.fromhex("00112233445566778899aabbccddeeff"))
        self.assertEqual(hasil.hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")

    def test_fips_197_c1_dekripsi(self):
        cipher = ManualAES(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
        hasil = cipher.dekripsi_blok(bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"))
        self.assertEqual(hasil.hex(), "00112233445566778899aabbccddeeff")

    def test_nist_sp800_38a_cbc(self):
        kunci = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )
        harapan = (
            "7649abac8119b246cee98e9b12e9197d"
            "5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e22229516"
            "3ff1caa1681fac09120eca307586e1a7"
        )
        cipher = ManualAES(kunci)
        self.assertEqual(cipher.enkripsi_cbc(plaintext, iv).hex(), harapan)
        self.assertEqual(cipher.dekripsi_cbc(bytes.fromhex(harapan), iv), plaintext)


class UjiModeCBC(unittest.TestCase):
    KUNCI = "KunciSesiAlice12"

    def test_putar_balik_berbagai_panjang(self):
        cipher = ManualAES(self.KUNCI)
        for panjang in (0, 1, 15, 16, 17, 31, 32, 33, 1000):
            with self.subTest(panjang=panjang):
                data = ("A" * panjang).encode()
                self.assertEqual(cipher.dekripsi(cipher.enkripsi(data)), data)

    def test_teks_utf8(self):
        cipher = ManualAES(self.KUNCI)
        teks = "Halo, dunia! — ñ, ü, 日本語, 🔐"
        self.assertEqual(cipher.dekripsi(cipher.enkripsi(teks)), teks.encode())

    def test_iv_acak_per_pesan(self):
        cipher = ManualAES(self.KUNCI)
        satu = cipher.enkripsi("pesan sama")
        dua = cipher.enkripsi("pesan sama")
        self.assertNotEqual(satu[:16], dua[:16])
        self.assertNotEqual(satu, dua)

    def test_panjang_ciphertext_kelipatan_blok(self):
        cipher = ManualAES(self.KUNCI)
        for panjang in range(0, 40):
            hasil = cipher.enkripsi(b"B" * panjang)
            self.assertEqual(len(hasil) % 16, 0)
            self.assertGreaterEqual(len(hasil), 32)

    def test_ciphertext_tidak_memuat_plaintext(self):
        cipher = ManualAES(self.KUNCI)
        hasil = cipher.enkripsi(b"RAHASIA123")
        self.assertNotIn(b"RAHASIA123", hasil)


class UjiValidasiKunci(unittest.TestCase):
    def test_kunci_ascii_16_diterima(self):
        self.assertEqual(ManualAES("KunciAliceKI2026").kunci, b"KunciAliceKI2026")

    def test_kunci_terlalu_pendek(self):
        with self.assertRaises(KunciTidakValid):
            ManualAES("pendek")

    def test_kunci_terlalu_panjang(self):
        with self.assertRaises(KunciTidakValid):
            ManualAES("kunci yang jauh terlalu panjang")

    def test_kunci_non_ascii(self):
        with self.assertRaises(KunciTidakValid):
            ManualAES("KunciAliceKÍ2026")

    def test_blok_salah_ukuran(self):
        with self.assertRaises(DataTidakValid):
            ManualAES("KunciAliceKI2026").enkripsi_blok(b"x" * 15)

    def test_ciphertext_terpotong(self):
        with self.assertRaises(DataTidakValid):
            ManualAES("KunciAliceKI2026").dekripsi(b"x" * 16)

    def test_padding_rusak(self):
        cipher = ManualAES("KunciAliceKI2026")
        data = bytearray(cipher.enkripsi("uji padding"))
        data[-1] ^= 0xFF
        with self.assertRaises(DataTidakValid):
            cipher.dekripsi(bytes(data))


class CatatanPalsu:
    def tulis(self, *args, **kwargs):
        pass


class UjiKDC(unittest.TestCase):
    def setUp(self):
        self.ka = "KunciAliceKI2026"
        self.kb = "KunciBobKI2026XX"
        self.kdc = KDC({"alice": self.ka, "bob": self.kb}, CatatanPalsu())

    def test_langkah_2_berisi_sesi_dan_tiket(self):
        n1 = 123456789
        with contextlib.redirect_stdout(io.StringIO()):
            balasan = self.kdc.layani_permintaan({
                "tipe": "permintaan_kdc", "id_a": "alice", "id_b": "bob", "n1": n1,
            })
        isi = json.loads(ManualAES(self.ka).dekripsi(bytes.fromhex(balasan["data"])))
        self.assertEqual(isi["id_a"], "alice")
        self.assertEqual(isi["id_b"], "bob")
        self.assertEqual(isi["n1"], n1)
        self.assertEqual(len(isi["ks"]), 16)

        tiket = json.loads(ManualAES(self.kb).dekripsi(bytes.fromhex(isi["tiket"])))
        self.assertEqual(tiket["ks"], isi["ks"])
        self.assertEqual(tiket["id_a"], "alice")

    def test_identitas_tidak_dikenal_ditolak(self):
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(ValueError):
                self.kdc.layani_permintaan({
                    "tipe": "permintaan_kdc", "id_a": "mallory", "id_b": "bob", "n1": 1,
                })

    def test_id_sama_ditolak(self):
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(ValueError):
                self.kdc.layani_permintaan({
                    "tipe": "permintaan_kdc", "id_a": "alice", "id_b": "alice", "n1": 1,
                })

    def test_kunci_sesi_berbeda_tiap_permintaan(self):
        with contextlib.redirect_stdout(io.StringIO()):
            a = self.kdc.layani_permintaan({
                "tipe": "permintaan_kdc", "id_a": "alice", "id_b": "bob", "n1": 1,
            })
            b = self.kdc.layani_permintaan({
                "tipe": "permintaan_kdc", "id_a": "alice", "id_b": "bob", "n1": 2,
            })
        isi_a = json.loads(ManualAES(self.ka).dekripsi(bytes.fromhex(a["data"])))
        isi_b = json.loads(ManualAES(self.ka).dekripsi(bytes.fromhex(b["data"])))
        self.assertNotEqual(isi_a["ks"], isi_b["ks"])


class UjiKonfigurasi(unittest.TestCase):
    def test_kunci_konfigurasi_valid(self):
        konf = konfigurasi.muat()
        self.assertEqual(len(konf["kdc"]["kunci_master"]), 2)
        for nama in ("alice", "bob"):
            ManualAES(konf["kdc"]["kunci_master"][nama])
            ManualAES(konf[nama]["kunci_master"])
        alamat = {konf[nama]["host"] for nama in ("kdc", "alice", "bob")}
        self.assertEqual(len(alamat), 3, "KDC/Alice/Bob harus memakai tiga IP berbeda")
        self.assertNotEqual(konf["bob"]["port"], konf["kdc"]["port"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
