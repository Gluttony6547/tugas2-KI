# konfigurasi.py
"""Pemuatan konfigurasi KDC/Alice/Bob dari satu berkas JSON."""

import json
import os

BERKAS_BAWAAN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "konfigurasi.json")


class KonfigurasiError(Exception):
    pass


def muat(path=None):
    path = path or BERKAS_BAWAAN
    if not os.path.exists(path):
        raise KonfigurasiError(f"berkas konfigurasi tidak ditemukan: {path}")
    try:
        with open(path, encoding="utf-8") as f:
            isi = json.load(f)
    except json.JSONDecodeError as e:
        raise KonfigurasiError(f"JSON tidak valid di {path}: {e}") from e
    for bagian in ("kdc", "alice", "bob"):
        if bagian not in isi:
            raise KonfigurasiError(f"bagian '{bagian}' tidak ada di {path}")
    pengaturan = isi.setdefault("jaringan", {})
    pengaturan.setdefault("timeout", 15.0)
    return isi
