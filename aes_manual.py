# aes_manual.py
"""AES-128 manual: tanpa library kriptografi, tanpa OpenSSL/pycryptodome.

Kunci wajib 16 karakter ASCII. Plaintext berupa byte UTF-8, ciphertext selalu
ditampilkan pemanggil dalam bentuk hex. Mode yang dipakai CBC dengan IV acak
per pesan; IV ikut dikirim di depan ciphertext (16 byte pertama).
"""

import os


class KunciTidakValid(ValueError):
    """Kunci bukan 16 karakter ASCII."""


class DataTidakValid(ValueError):
    """Ciphertext tidak berbentuk blok 16 byte atau padding rusak."""


# Kotak substitusi AES (FIPS-197, tabel 256 byte).
SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

# Kebalikan SBOX dibuat otomatis supaya tidak ada tabel kedua yang bisa salah ketik.
INV_SBOX = [0] * 256
for _i, _nilai in enumerate(SBOX):
    INV_SBOX[_nilai] = _i

# Konstanta putaran key expansion.
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _kali(a: int, b: int) -> int:
    """Perkalian dua byte di GF(2^8) dengan polinomial 0x11B."""
    hasil = 0
    for _ in range(8):
        if b & 1:
            hasil ^= a
        tinggi = a & 0x80
        a = (a << 1) & 0xFF
        if tinggi:
            a ^= 0x1B
        b >>= 1
    return hasil


class ManualAES:
    """AES-128 dengan mode CBC dan padding PKCS#7."""

    def __init__(self, kunci):
        if isinstance(kunci, str):
            try:
                kunci = kunci.encode("ascii")
            except UnicodeEncodeError as e:
                raise KunciTidakValid("kunci harus ASCII") from e
        if not isinstance(kunci, (bytes, bytearray)) or len(kunci) != 16:
            raise KunciTidakValid(
                f"kunci AES-128 harus 16 byte ASCII, diterima {len(kunci)} byte"
            )
        self.kunci = bytes(kunci)
        self.kunci_putaran = self._perluas_kunci(self.kunci)

    def _perluas_kunci(self, kunci: bytes):
        """44 word (11 kunci putaran x 4 kolom) dari 16 byte kunci."""
        kata = [list(kunci[i:i + 4]) for i in range(0, 16, 4)]
        for i in range(4, 44):
            temp = list(kata[i - 1])
            if i % 4 == 0:
                temp = temp[1:] + temp[:1]              # RotWord
                temp = [SBOX[b] for b in temp]          # SubWord
                temp[0] ^= RCON[i // 4 - 1]             # Rcon
            kata.append([kata[i - 4][j] ^ temp[j] for j in range(4)])
        return [sum(kata[4 * r:4 * r + 4], []) for r in range(11)]

    @staticmethod
    def _sub_bytes(state, kotak):
        return [kotak[b] for b in state]

    @staticmethod
    def _shift_rows(state):
        hasil = list(state)
        for baris in range(1, 4):
            for kolom in range(4):
                # State disimpan kolom-mayor: indeks = baris + 4 * kolom.
                hasil[baris + 4 * kolom] = state[baris + 4 * ((kolom + baris) % 4)]
        return hasil

    @staticmethod
    def _inv_shift_rows(state):
        hasil = list(state)
        for baris in range(1, 4):
            for kolom in range(4):
                hasil[baris + 4 * kolom] = state[baris + 4 * ((kolom - baris) % 4)]
        return hasil

    @staticmethod
    def _mix_columns(state):
        hasil = list(state)
        for kolom in range(4):
            i = 4 * kolom
            s0, s1, s2, s3 = state[i], state[i + 1], state[i + 2], state[i + 3]
            hasil[i] = _kali(s0, 2) ^ _kali(s1, 3) ^ s2 ^ s3
            hasil[i + 1] = s0 ^ _kali(s1, 2) ^ _kali(s2, 3) ^ s3
            hasil[i + 2] = s0 ^ s1 ^ _kali(s2, 2) ^ _kali(s3, 3)
            hasil[i + 3] = _kali(s0, 3) ^ s1 ^ s2 ^ _kali(s3, 2)
        return hasil

    @staticmethod
    def _inv_mix_columns(state):
        hasil = list(state)
        for kolom in range(4):
            i = 4 * kolom
            s0, s1, s2, s3 = state[i], state[i + 1], state[i + 2], state[i + 3]
            hasil[i] = _kali(s0, 14) ^ _kali(s1, 11) ^ _kali(s2, 13) ^ _kali(s3, 9)
            hasil[i + 1] = _kali(s0, 9) ^ _kali(s1, 14) ^ _kali(s2, 11) ^ _kali(s3, 13)
            hasil[i + 2] = _kali(s0, 13) ^ _kali(s1, 9) ^ _kali(s2, 14) ^ _kali(s3, 11)
            hasil[i + 3] = _kali(s0, 11) ^ _kali(s1, 13) ^ _kali(s2, 9) ^ _kali(s3, 14)
        return hasil

    @staticmethod
    def _add_round_key(state, kunci_putaran):
        return [b ^ k for b, k in zip(state, kunci_putaran)]

    def enkripsi_blok(self, blok: bytes) -> bytes:
        if len(blok) != 16:
            raise DataTidakValid("blok AES harus tepat 16 byte")
        putaran = self.kunci_putaran
        state = self._add_round_key(list(blok), putaran[0])
        for r in range(1, 10):
            state = self._sub_bytes(state, SBOX)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, putaran[r])
        state = self._sub_bytes(state, SBOX)
        state = self._shift_rows(state)
        state = self._add_round_key(state, putaran[10])
        return bytes(state)

    def dekripsi_blok(self, blok: bytes) -> bytes:
        if len(blok) != 16:
            raise DataTidakValid("blok AES harus tepat 16 byte")
        putaran = self.kunci_putaran
        state = self._add_round_key(list(blok), putaran[10])
        for r in range(9, 0, -1):
            state = self._inv_shift_rows(state)
            state = self._sub_bytes(state, INV_SBOX)
            state = self._add_round_key(state, putaran[r])
            state = self._inv_mix_columns(state)
        state = self._inv_shift_rows(state)
        state = self._sub_bytes(state, INV_SBOX)
        state = self._add_round_key(state, putaran[0])
        return bytes(state)

    @staticmethod
    def _pad(data: bytes) -> bytes:
        tambah = 16 - len(data) % 16
        return data + bytes([tambah]) * tambah

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        if not data or len(data) % 16 != 0:
            raise DataTidakValid("panjang data bukan kelipatan 16 byte")
        tambah = data[-1]
        if not 1 <= tambah <= 16 or data[-tambah:] != bytes([tambah]) * tambah:
            raise DataTidakValid("padding PKCS#7 rusak (kunci salah atau data diubah)")
        return data[:-tambah]

    def enkripsi_cbc(self, data: bytes, iv: bytes) -> bytes:
        """CBC tanpa padding, dipakai uji vektor NIST dan oleh enkripsi()."""
        if len(iv) != 16:
            raise DataTidakValid("IV harus 16 byte")
        if len(data) % 16 != 0:
            raise DataTidakValid("data CBC harus kelipatan 16 byte")
        hasil = bytearray()
        sebelumnya = iv
        for i in range(0, len(data), 16):
            blok = bytes(x ^ y for x, y in zip(data[i:i + 16], sebelumnya))
            sebelumnya = self.enkripsi_blok(blok)
            hasil.extend(sebelumnya)
        return bytes(hasil)

    def dekripsi_cbc(self, data: bytes, iv: bytes) -> bytes:
        if len(iv) != 16:
            raise DataTidakValid("IV harus 16 byte")
        if len(data) % 16 != 0:
            raise DataTidakValid("ciphertext CBC harus kelipatan 16 byte")
        hasil = bytearray()
        sebelumnya = iv
        for i in range(0, len(data), 16):
            blok = data[i:i + 16]
            terbuka = self.dekripsi_blok(blok)
            hasil.extend(x ^ y for x, y in zip(terbuka, sebelumnya))
            sebelumnya = blok
        return bytes(hasil)

    def enkripsi(self, plaintext) -> bytes:
        """Kembalikan IV (16 byte) + ciphertext CBC berpadding."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        iv = os.urandom(16)
        return iv + self.enkripsi_cbc(self._pad(bytes(plaintext)), iv)

    def dekripsi(self, data: bytes) -> bytes:
        if len(data) < 32 or len(data) % 16 != 0:
            raise DataTidakValid("ciphertext minimal 32 byte dan kelipatan 16 byte")
        iv, isi = data[:16], data[16:]
        return self._unpad(self.dekripsi_cbc(isi, iv))
