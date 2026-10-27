# jaringan.py
"""Framing TCP, pesan JSON, dan catatan uji untuk KDC/Alice/Bob.

Setiap pesan dibingkai 4 byte panjang (big-endian) + payload. Tanpa bingkai,
dua pesan JSON yang tiba berdekatan bisa tergabung dalam satu recv() dan
membuat penerima gagal mem-parse.
"""

import json
import struct
import threading
from datetime import datetime

BATAS_FRAME = 1 << 20
_HEADER = struct.Struct("!I")


class FrameError(Exception):
    """Frame tidak utuh atau melebihi batas."""


def kirim_pesan(sock, data: bytes, catatan=None) -> None:
    if len(data) > BATAS_FRAME:
        raise FrameError(f"payload {len(data)} byte melebihi batas {BATAS_FRAME}")
    frame = _HEADER.pack(len(data)) + data
    sock.sendall(frame)
    _catat_frame(catatan, "FRAME_TX", sock, frame)


def _catat_frame(catatan, event, sock, frame: bytes) -> None:
    if catatan is None:
        return
    try:
        peer = sock.getpeername()
    except OSError:
        peer = None
    catatan.tulis(event, peer, data=frame)


def _terima_tepat(sock, jumlah: int):
    buf = bytearray()
    while len(buf) < jumlah:
        bagian = sock.recv(jumlah - len(buf))
        if not bagian:
            if not buf:
                return None
            raise FrameError(f"koneksi tertutup di tengah frame ({len(buf)}/{jumlah} byte)")
        buf.extend(bagian)
    return bytes(buf)


def terima_pesan(sock, catatan=None):
    """Kembalikan payload, atau None bila peer menutup koneksi dengan rapi."""
    header = _terima_tepat(sock, _HEADER.size)
    if header is None:
        return None
    (panjang,) = _HEADER.unpack(header)
    if panjang > BATAS_FRAME:
        raise FrameError(f"panjang frame {panjang} melebihi batas {BATAS_FRAME}")
    if panjang == 0:
        _catat_frame(catatan, "FRAME_RX", sock, header)
        return b""
    payload = _terima_tepat(sock, panjang)
    if payload is None:
        raise FrameError("koneksi tertutup setelah header")
    _catat_frame(catatan, "FRAME_RX", sock, header + payload)
    return payload


def kirim_json(sock, objek, catatan=None) -> None:
    kirim_pesan(
        sock,
        json.dumps(objek, ensure_ascii=True).encode("utf-8"),
        catatan=catatan,
    )


def terima_json(sock, catatan=None):
    payload = terima_pesan(sock, catatan=catatan)
    if payload is None:
        return None
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise FrameError(f"payload bukan JSON valid: {e}") from e


def endpoint(peer) -> str:
    if not peer:
        return "-"
    if isinstance(peer, (tuple, list)) and len(peer) >= 2:
        return f"{peer[0]}:{peer[1]}"
    return str(peer)


class Catatan:
    """Satu baris per kejadian, siap dipakai sebagai bukti pengujian."""

    def __init__(self, path, peran):
        self.peran = peran
        self._berkas = open(path, "w", encoding="utf-8") if path else None
        self._kunci = threading.Lock()

    def tulis(self, event, peer=None, data=None, teks=None, info=None):
        if self._berkas is None:
            return
        waktu = datetime.now().isoformat(timespec="milliseconds")
        baris = f"{waktu} ROLE={self.peran} EVENT={event}"
        if peer:
            baris += f" PEER={endpoint(peer)}"
        if info:
            baris += f" INFO={info}"
        if data is not None:
            baris += f" LEN={len(data)} HEX={data.hex()}"
        if teks is not None:
            baris += f" TXT={teks!r}"
        with self._kunci:
            if self._berkas is None:
                return
            try:
                self._berkas.write(baris + "\n")
                self._berkas.flush()
            except (ValueError, OSError):
                # Berkas sudah ditutup saat program berhenti; catatan tidak wajib.
                pass

    def tutup(self):
        with self._kunci:
            if self._berkas is not None:
                self._berkas.close()
                self._berkas = None
