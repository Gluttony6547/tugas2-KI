# sesi.py
"""Keadaan sesi AES yang dipakai bersama konsol dan thread penerima."""

import threading
from datetime import datetime


class Sesi:
    """Keadaan sesi yang dipakai bersama oleh konsol dan thread penerima."""

    def __init__(self):
        self.lock = threading.RLock()
        self.terbentuk = False
        self.cipher = None
        self.kunci = None
        self.cipher_baru = None
        self.kunci_baru = None
        self.id_baru = None
        self.id = None
        self.lawan = None
        self.peer = None
        self.lokal = None
        self.mulai = None
        self.menunggu_ack = False
        self.nonce_ganti = None
        self.tx = 0
        self.rx = 0

    def pasang(self, cipher, kunci, sesi_id, lawan, peer, lokal):
        with self.lock:
            self.cipher = cipher
            self.kunci = kunci
            self.cipher_baru = None
            self.kunci_baru = None
            self.id_baru = None
            self.id = sesi_id
            self.lawan = lawan
            self.peer = peer
            self.lokal = lokal
            self.terbentuk = True
            self.menunggu_ack = False
            self.mulai = datetime.now().strftime("%H:%M:%S")
            self.tx = 0
            self.rx = 0

    def lepas(self):
        with self.lock:
            self.terbentuk = False
            self.cipher = None
            self.cipher_baru = None
            self.kunci_baru = None
            self.id_baru = None
            self.menunggu_ack = False
