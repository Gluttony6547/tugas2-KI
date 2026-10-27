# konsol.py
"""Tampilan, mode otomatis, dan konsol interaktif Node."""

import socket
import threading
import time

from jaringan import endpoint


class KonsolNode:
    """Mixin tampilan/konsol: dipakai Node untuk peran Alice maupun Bob."""

    def cetak(self, teks=""):
        print(teks, flush=True)

    def blok(self, judul, isi):
        self.cetak("\n" + "=" * 62)
        self.cetak(judul)
        for baris in isi:
            self.cetak(baris)
        self.cetak("=" * 62)

    def status(self):
        with self.sesi.lock:
            sesi = self.sesi
            self.cetak("[STATUS] peran         : " + self.peran)
            self.cetak("[STATUS] ID node       : " + self.id_diri)
            self.cetak("[STATUS] KDC           : " + f"{self.kdc_host}:{self.kdc_port}")
            self.cetak("[STATUS] K_A/K_B (ASCII): " + self.kunci_master.kunci.decode())
            if sesi.terbentuk:
                self.cetak("[STATUS] lawan         : " + f"{sesi.lawan} @ {endpoint(sesi.peer)}")
                self.cetak("[STATUS] lokal         : " + endpoint(sesi.lokal))
                self.cetak("[STATUS] sesi KDC      : " + str(sesi.id))
                self.cetak("[STATUS] K_S (ASCII)   : " + str(sesi.kunci))
                self.cetak("[STATUS] mulai         : " + str(sesi.mulai))
                self.cetak(f"[STATUS] pesan         : TX={sesi.tx} RX={sesi.rx}")
                self.cetak("[STATUS] status        : " + (
                    "menunggu konfirmasi ganti kunci" if sesi.menunggu_ack else "aktif"
                ))
            else:
                self.cetak("[STATUS] sesi          : belum terbentuk")

    # ---------- mode otomatis ----------

    def mode_otomatis_alice(self):
        self.status()
        for nomor in range(1, max(1, self.args.jumlah) + 1):
            if not self.kirim_data(self.args.kirim or ""):
                self.kode = 3
                break
            if self.args.rotasi_setelah == nomor:
                kunci_lama = self.sesi.kunci
                if not self.rotasi_kunci():
                    self.kode = 3
                    break
                if not self.ack_kunci.wait(10) or self.sesi.kunci == kunci_lama:
                    self.cetak("[HASIL] GAGAL: rotasi kunci tidak terkonfirmasi")
                    self.kode = 3
                    break
                self.cetak(f"[HASIL] Rotasi kunci setelah pesan #{nomor} berhasil.")
            time.sleep(0.05)
        if self.kode != 0:
            self.tutup()
            return
        if self.args.harap_balasan:
            if not self.selesai.wait(self.args.batas):
                self.cetak(f"[HASIL] GAGAL: hanya {self.sesi.rx} balasan dalam "
                           f"{self.args.batas:.0f} detik")
                self.kode = 3
            elif self.sesi.rx < self.args.harap_balasan:
                self.cetak(f"[HASIL] GAGAL: balasan {self.sesi.rx} < "
                           f"{self.args.harap_balasan}")
                self.kode = 3
            else:
                self.cetak(f"[HASIL] LULUS: {self.sesi.tx} pesan terkirim, "
                           f"{self.sesi.rx} balasan diterima.")
        else:
            time.sleep(0.5)
            self.cetak(f"[HASIL] {self.sesi.tx} pesan terkirim.")
        self.tutup()

    def mode_otomatis_bob(self):
        self.selesai.wait(self.args.batas)
        self.status()
        with self.sesi.lock:
            terbentuk = self.sesi.terbentuk
            diterima = self.sesi.rx
        if not terbentuk and diterima == 0:
            if self.kode == 0:
                self.cetak(f"[HASIL] GAGAL: tidak ada sesi dalam {self.args.batas:.0f} detik")
                self.kode = 3
        else:
            self.cetak(f"[HASIL] Sesi selesai: {diterima} pesan diterima, "
                       f"{self.sesi.tx} pesan dibalas.")
        self.tutup()

    # ---------- konsol ----------

    def konsol(self):
        self.cetak("[KONSOL] /kirim <teks>, /kunci, /status, /bantu, /keluar")
        while not self.berhenti.is_set():
            try:
                baris = input(f"[{self.id_diri}] > ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not baris:
                continue
            if baris.startswith("/"):
                perintah, _, sisa = baris.partition(" ")
                if perintah == "/keluar":
                    break
                if perintah == "/bantu":
                    self.cetak("[KONSOL] /kirim <teks>  kirim pesan terenkripsi")
                    self.cetak("[KONSOL] /kunci        minta K_S baru ke KDC (tanpa restart)")
                    self.cetak("[KONSOL] /status       tampilkan IP, sesi, dan kunci")
                    self.cetak("[KONSOL] /keluar       keluar dari program")
                elif perintah == "/status":
                    self.status()
                elif perintah == "/kunci":
                    self.rotasi_kunci()
                elif perintah == "/kirim":
                    if not sisa.strip():
                        self.cetak("[KONSOL] Gunakan: /kirim <teks>")
                    else:
                        self.kirim_data(sisa.strip())
                else:
                    self.cetak("[KONSOL] Perintah tidak dikenal. Ketik /bantu.")
            else:
                self.kirim_data(baris)
        self.tutup()

    def tutup(self):
        self.berhenti.set()
        if self.koneksi is not None:
            try:
                self.koneksi.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.koneksi.close()
            except OSError:
                pass
        if self.server is not None:
            try:
                self.server.close()
            except OSError:
                pass
        for utas in (self.thread_penerima, self.thread_server):
            if utas is not None and utas is not threading.current_thread():
                utas.join(timeout=2)
        self.log.tutup()
