# transport.py
"""Framing TCP untuk pesan DES 2 arah.

Setiap pesan diawali 4 byte panjang (big-endian). Tanpa penanda ini dua pesan
yang tiba berdekatan bisa tergabung dalam satu recv(), dan ciphertext DES yang
terpotong menghasilkan plaintext rusak.
"""

import struct
import threading
from datetime import datetime

BATAS_FRAME = 1 << 20
_HEADER = struct.Struct("!I")


class FrameError(Exception):
    """Frame tidak utuh atau melebihi batas."""


class DataTidakCocok(Exception):
    """Ciphertext tidak bisa dibuka dengan PSK yang dipakai."""


def kirim_pesan(sock, data: bytes) -> None:
    if len(data) > BATAS_FRAME:
        raise FrameError(f"payload {len(data)} byte melebihi batas {BATAS_FRAME}")
    sock.sendall(_HEADER.pack(len(data)) + data)


def _recv_tepat(sock, jumlah: int):
    buf = bytearray()
    while len(buf) < jumlah:
        bagian = sock.recv(jumlah - len(buf))
        if not bagian:
            if not buf:
                return None
            raise FrameError(f"koneksi tertutup di tengah frame ({len(buf)}/{jumlah} byte)")
        buf.extend(bagian)
    return bytes(buf)


def terima_pesan(sock):
    """Kembalikan payload, atau None bila peer menutup koneksi dengan rapi."""
    header = _recv_tepat(sock, _HEADER.size)
    if header is None:
        return None
    (panjang,) = _HEADER.unpack(header)
    if panjang > BATAS_FRAME:
        raise FrameError(f"panjang frame {panjang} melebihi batas {BATAS_FRAME}")
    if panjang == 0:
        return b""
    payload = _recv_tepat(sock, panjang)
    if payload is None:
        raise FrameError("koneksi tertutup setelah header")
    return payload


def dekripsi_terverifikasi(cipher, ciphertext: bytes) -> bytes:
    """Buka ciphertext dan pastikan PSK sama.

    ECB deterministik: enkripsi ulang plaintext harus menghasilkan ciphertext
    yang identik. Bila tidak, kunci berbeda atau data rusak, bukan sekadar
    plaintext berisi karakter aneh.
    """
    plaintext = cipher.decrypt(ciphertext)
    if cipher.encrypt(plaintext) != ciphertext:
        raise DataTidakCocok(
            "data tidak cocok dengan PSK: kunci di kedua mesin berbeda atau ciphertext rusak"
        )
    return plaintext


class CatatanUji:
    """Bukti uji: satu baris per kejadian berisi waktu, peran, peer, hex, teks."""

    def __init__(self, path, peran):
        self.peran = peran
        # Mode tulis ulang: satu berkas log mewakili satu sesi uji, bukan akumulasi.
        self._berkas = open(path, "w", encoding="utf-8") if path else None
        self._kunci = threading.Lock()

    def tulis(self, event, peer, data=None, teks=None):
        if self._berkas is None:
            return
        baris = (
            f"{datetime.now().isoformat(timespec='milliseconds')} "
            f"ROLE={self.peran} EVENT={event} PEER={peer[0]}:{peer[1]}"
        )
        if data is not None:
            baris += f" LEN={len(data)} HEX={data.hex()}"
        if teks is not None:
            baris += f" TXT={teks!r}"
        with self._kunci:
            self._berkas.write(baris + "\n")
            self._berkas.flush()

    def tutup(self):
        if self._berkas is not None:
            self._berkas.close()
            self._berkas = None
