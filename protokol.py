# protokol.py
"""Handshake KDC/Alice/Bob, transport, dan rotasi kunci."""

import json
import secrets
import socket
import threading
import time
from datetime import datetime

from aes_manual import DataTidakValid, ManualAES
from jaringan import FrameError, endpoint, kirim_json, terima_json


class ProtokolError(Exception):
    pass


class ProtokolNode:
    """Mixin protokol: dipakai Node supaya tiap peran punya satu alamat."""

    def sumber_koneksi(self):
        """Alice memakai bind/konfigurasi sebagai IP sumber; Bob memakainya untuk listen."""
        if self.peran == "alice" and self.bind and self.bind != "0.0.0.0":
            return (self.bind, 0)
        return None

    # ---------- langkah 1-2: minta tiket ke KDC ----------

    def minta_sesi(self, id_lawan):
        n1 = secrets.randbits(32)
        permintaan = {
            "tipe": "permintaan_kdc",
            "id_a": self.id_diri,
            "id_b": id_lawan,
            "n1": n1,
        }
        self.cetak(f"[LANGKAH 1] {self.id_diri} -> KDC : "
                   f"ID_A={self.id_diri} ID_B={id_lawan} N1={n1}")
        self.log.tulis("LANGKAH1", teks=f"n1={n1} id_b={id_lawan}")

        try:
            with socket.create_connection(
                (self.kdc_host, self.kdc_port), timeout=self.timeout,
                source_address=self.sumber_koneksi(),
            ) as s:
                kirim_json(s, permintaan, self.log)
                balasan = terima_json(s, self.log)
        except OSError as e:
            raise ProtokolError(
                f"tidak bisa menghubungi KDC {self.kdc_host}:{self.kdc_port} ({e})"
            ) from e

        if not balasan:
            raise ProtokolError("KDC menutup koneksi tanpa balasan")
        if balasan.get("tipe") == "error":
            raise ProtokolError("KDC menolak: " + str(balasan.get("pesan")))
        if balasan.get("tipe") != "balasan_kdc":
            raise ProtokolError("balasan KDC tidak dikenal: " + str(balasan.get("tipe")))

        data = bytes.fromhex(balasan["data"])
        try:
            isi = json.loads(self.kunci_master.dekripsi(data).decode())
        except (DataTidakValid, ValueError, UnicodeDecodeError) as e:
            raise ProtokolError("gagal membuka balasan KDC dengan kunci master") from e

        if isi.get("n1") != n1:
            raise ProtokolError("N1 pada balasan KDC tidak cocok (kemungkinan replay)")
        if isi.get("id_a") != self.id_diri or isi.get("id_b") != id_lawan:
            raise ProtokolError("identitas pada balasan KDC tidak cocok")
        kunci_sesi = isi.get("ks")
        ManualAES(kunci_sesi)  # validasi 16 karakter ASCII

        self.cetak(f"[LANGKAH 2] KDC -> {self.id_diri} : sesi={balasan.get('sesi_id')}")
        self.cetak(f"            E_KA[K_S || ID_A || ID_B || N1 || tiket] (HEX) =")
        self.cetak(f"            {balasan['data']}")
        self.cetak(f"            K_S yang dibuka = {kunci_sesi} (16 ASCII)")
        self.cetak(f"            Tiket untuk lawan (HEX) = {isi['tiket']}")
        self.log.tulis(
            "LANGKAH2",
            data=data,
            teks=f"sesi={balasan.get('sesi_id')} ks={kunci_sesi} tiket={isi['tiket']}",
        )
        return {"ks": kunci_sesi, "tiket": isi["tiket"], "sesi_id": balasan.get("sesi_id")}

    # ---------- pengirim / penerima ----------

    def kirim_data(self, teks):
        with self.sesi.lock:
            if not self.sesi.terbentuk:
                self.cetak("[KIRIM] Belum ada sesi; tunggu handshake selesai.")
                return False
            if self.sesi.menunggu_ack:
                self.cetak("[KIRIM] Sedang ganti kunci; tunggu konfirmasi lawan.")
                return False
            if self.koneksi is None:
                self.cetak("[KIRIM] Tidak ada koneksi aktif.")
                return False
            cipher = self.sesi.cipher
            isi = json.dumps({"teks": teks}, ensure_ascii=True).encode()
            try:
                ct = cipher.enkripsi(isi)
                kirim_json(self.koneksi, {
                    "tipe": "pesan",
                    "dari": self.id_diri,
                    "data": ct.hex(),
                }, self.log)
            except (OSError, DataTidakValid) as e:
                self.cetak(f"[KIRIM] Gagal: {e}")
                return False
            self.sesi.tx += 1
            peer = self.sesi.peer
        self.cetak(f"[TERKIRIM] Ciphertext AES (HEX) : {ct.hex()}")
        self.cetak(f"[TERKIRIM] Panjang ciphertext   : {len(ct)} byte")
        self.log.tulis("TX", peer, data=ct, teks=teks)
        return True

    def buka_payload(self, data_hex):
        """Coba kunci aktif, lalu kunci baru bila sedang menunggu konfirmasi.

        Pesan yang dikirim lawan tepat sebelum ganti kunci masih memakai kunci
        lama, jadi keduanya harus bisa dibuka selama masa peralihan.
        """
        data = bytes.fromhex(data_hex)
        with self.sesi.lock:
            kandidat = [self.sesi.cipher]
            if self.sesi.cipher_baru is not None:
                kandidat.append(self.sesi.cipher_baru)
        galat = None
        for cipher in kandidat:
            if cipher is None:
                continue
            try:
                return json.loads(cipher.dekripsi(data).decode())
            except (DataTidakValid, ValueError, UnicodeDecodeError) as e:
                galat = e
        raise ProtokolError(f"payload tidak bisa dibuka dengan kunci aktif: {galat}")

    def tangani_pesan(self, msg, peer):
        try:
            isi = self.buka_payload(msg["data"])
            teks = isi["teks"]
        except (KeyError, ProtokolError) as e:
            raise ProtokolError(f"pesan tidak bisa dibuka dengan K_S saat ini: {e}") from e
        with self.sesi.lock:
            self.sesi.rx += 1
            nomor = self.sesi.rx
        self.blok(f"[DITERIMA #{nomor}] dari {msg.get('dari')} @ {endpoint(peer)}", [
            f"Ciphertext AES (HEX) : {msg['data']}",
            f"Plaintext            : {teks}",
        ])
        self.log.tulis("RX", peer, data=bytes.fromhex(msg["data"]), teks=teks)
        if self.args.harap_balasan and nomor >= self.args.harap_balasan:
            self.selesai.set()
        if self.args.balas and self.sisa_balasan > 0:
            if self.kirim_data(self.args.balas):
                self.sisa_balasan -= 1

    def tangani_kontrol(self, msg, peer):
        with self.sesi.lock:
            if self.sesi.cipher is None:
                raise ProtokolError("pesan kontrol datang tanpa sesi aktif")
        isi = self.buka_payload(msg["data"])

        if isi.get("aksi") == "ganti_kunci":
            isi_tiket = json.loads(
                self.kunci_master.dekripsi(bytes.fromhex(isi["tiket"])).decode()
            )
            if isi_tiket.get("id_b") != self.id_diri:
                raise ProtokolError("tiket kunci baru bukan untuk node ini")
            kunci_baru = isi_tiket["ks"]
            cipher_baru = ManualAES(kunci_baru)
            with self.sesi.lock:
                self.sesi.cipher = cipher_baru
                self.sesi.kunci = kunci_baru
                self.sesi.cipher_baru = None
                self.sesi.kunci_baru = None
                self.sesi.id = isi.get("sesi_id", self.sesi.id)
            self.cetak(f"\n[KUNCI] Lawan mengganti kunci sesi. K_S baru = {kunci_baru}")
            self.log.tulis("KUNCI_BARU", peer, teks=kunci_baru)

            balasan = json.dumps(
                {"aksi": "ganti_kunci_ok", "nonce": isi.get("nonce")},
                ensure_ascii=True,
            ).encode()
            with self.sesi.lock:
                ct = self.sesi.cipher.enkripsi(balasan)
                kirim_json(self.koneksi, {"tipe": "kontrol", "data": ct.hex()}, self.log)
            self.cetak("[KUNCI] Konfirmasi dikirim dengan kunci baru.")
            return

        if isi.get("aksi") == "ganti_kunci_ok":
            with self.sesi.lock:
                cocok = isi.get("nonce") == self.sesi.nonce_ganti
                if cocok and self.sesi.cipher_baru is not None:
                    self.sesi.cipher = self.sesi.cipher_baru
                    self.sesi.kunci = self.sesi.kunci_baru
                    if self.sesi.id_baru is not None:
                        self.sesi.id = self.sesi.id_baru
                    self.sesi.cipher_baru = None
                    self.sesi.kunci_baru = None
                    self.sesi.id_baru = None
                self.sesi.menunggu_ack = False
                self.sesi.nonce_ganti = None
                kunci = self.sesi.kunci
            self.ack_kunci.set()
            if cocok:
                self.cetak("\n[KUNCI] Lawan mengonfirmasi; kunci baru aktif di kedua sisi.")
                self.log.tulis("KUNCI_AKTIF", peer, teks=str(kunci))
            else:
                self.cetak("\n[KUNCI] Konfirmasi tidak cocok; periksa status sesi.")
            return

        raise ProtokolError(f"aksi kontrol tidak dikenal: {isi.get('aksi')}")

    def rotasi_kunci(self):
        with self.sesi.lock:
            if not self.sesi.terbentuk:
                self.cetak("[KUNCI] Belum ada sesi aktif.")
                return
            if self.sesi.menunggu_ack:
                self.cetak("[KUNCI] Masih menunggu konfirmasi ganti kunci sebelumnya.")
                return False
            lawan = self.sesi.lawan
            self.sesi.menunggu_ack = True
            cipher_lama = self.sesi.cipher
            self.ack_kunci.clear()

        self.cetak("[KUNCI] Meminta sesi baru ke KDC...")
        try:
            baru = self.minta_sesi(lawan)
        except ProtokolError as e:
            with self.sesi.lock:
                self.sesi.menunggu_ack = False
            self.cetak(f"[KUNCI] Gagal: {e}")
            return False

        nonce = secrets.randbits(32)
        with self.sesi.lock:
            if not self.sesi.terbentuk or self.koneksi is None:
                self.sesi.menunggu_ack = False
                return False
            self.sesi.nonce_ganti = nonce
            self.sesi.cipher_baru = ManualAES(baru["ks"])
            self.sesi.kunci_baru = baru["ks"]
            self.sesi.id_baru = baru["sesi_id"]
            isi = json.dumps(
                {"aksi": "ganti_kunci", "tiket": baru["tiket"], "nonce": nonce,
                 "sesi_id": baru["sesi_id"]},
                ensure_ascii=True,
            ).encode()
            try:
                ct = cipher_lama.enkripsi(isi)
                kirim_json(self.koneksi, {"tipe": "kontrol", "data": ct.hex()}, self.log)
            except (OSError, DataTidakValid) as e:
                self.sesi.menunggu_ack = False
                self.sesi.cipher_baru = None
                self.sesi.kunci_baru = None
                self.sesi.id_baru = None
                self.cetak(f"[KUNCI] Gagal mengirim tiket baru: {e}")
                return False
        self.cetak(f"[KUNCI] Tiket baru dikirim dengan kunci lama. K_S baru = {baru['ks']}")
        self.cetak("[KUNCI] Menunggu konfirmasi lawan sebelum memakai kunci baru...")
        return True

    def terima_loop(self, conn, peer):
        conn.settimeout(None)
        try:
            while not self.berhenti.is_set():
                msg = terima_json(conn, self.log)
                if msg is None:
                    self.cetak("\n[INFO] Lawan menutup koneksi.")
                    break
                tipe = msg.get("tipe")
                with self.sesi.lock:
                    cipher = self.sesi.cipher
                if cipher is None:
                    raise ProtokolError("data datang sebelum sesi terbentuk")
                if tipe == "pesan":
                    self.tangani_pesan(msg, peer)
                elif tipe == "kontrol":
                    self.tangani_kontrol(msg, peer)
                else:
                    self.cetak(f"[INFO] Pesan tipe tidak dikenal: {tipe}")
        except (FrameError, OSError, DataTidakValid, ProtokolError, KeyError,
                ValueError, UnicodeDecodeError) as e:
            if not self.berhenti.is_set():
                self.cetak(f"\n[ERROR] Koneksi/sesi: {e}")
                self.log.tulis("ERROR", peer, teks=str(e))
        finally:
            with self.sesi.lock:
                self.sesi.lepas()
            if self.koneksi is conn:
                self.koneksi = None
            self.cetak("[INFO] Sesi berakhir.")
            self.log.tulis("TUTUP", peer)
            self.selesai.set()
            try:
                conn.close()
            except OSError:
                pass

    # ---------- peran Alice ----------

    def jalankan_alice(self):
        self.cetak("=" * 62)
        self.cetak("        NODE ALICE - PENERIMA TIKET + PENGIRIM/PENERIMA AES")
        self.cetak("=" * 62)
        self.cetak(f"[KDC]     {self.kdc_host}:{self.kdc_port}")
        self.cetak(f"[LAWAN]   {self.id_lawan} di {self.lawan_host}:{self.lawan_port}")
        self.cetak(f"[KUNCI]   K_A = {self.kunci_master.kunci.decode()} (16 ASCII)")
        self.cetak("=" * 62 + "\n")
        self.log.tulis("MULAI", info=f"role=alice kdc={self.kdc_host}:{self.kdc_port}")

        try:
            hasil = self.minta_sesi(self.id_lawan)
            self.cetak(f"[LANGKAH 3] {self.id_diri} -> {self.id_lawan} : "
                       "kirim tiket E_KB[K_S, ID_A]")
            conn = socket.create_connection(
                (self.lawan_host, self.lawan_port), timeout=self.timeout,
                source_address=self.sumber_koneksi(),
            )
            self.koneksi = conn
            conn.settimeout(self.timeout)
            kirim_json(conn, {
                "tipe": "tiket",
                "dari": self.id_diri,
                "tiket": hasil["tiket"],
            }, self.log)
            self.log.tulis("LANGKAH3", conn.getpeername(), teks=hasil["tiket"])
            self.cetak(f"[LANGKAH 3] Tiket (HEX) = {hasil['tiket']}")

            balasan = terima_json(conn, self.log)
            if not balasan or balasan.get("tipe") != "tantangan":
                raise ProtokolError("Bob tidak mengirim tantangan N2")
            cipher = ManualAES(hasil["ks"])
            n2 = int(cipher.dekripsi(bytes.fromhex(balasan["data"])).decode())
            self.cetak(f"[LANGKAH 4] {self.id_lawan} -> {self.id_diri} : "
                       f"E_KS[N2] (HEX) = {balasan['data']}")
            self.cetak(f"            N2 = {n2}")
            self.log.tulis("LANGKAH4", conn.getpeername(), data=bytes.fromhex(balasan["data"]))

            jawaban = cipher.enkripsi(str(n2 - 1).encode())
            kirim_json(conn, {"tipe": "konfirmasi", "data": jawaban.hex()}, self.log)
            self.cetak(f"[LANGKAH 5] {self.id_diri} -> {self.id_lawan} : "
                       f"E_KS[N2-1] (HEX) = {jawaban.hex()}")

            conn.settimeout(None)
            self.sesi.pasang(
                cipher, hasil["ks"], hasil["sesi_id"], self.id_lawan,
                conn.getpeername(), conn.getsockname(),
            )
            waktu = datetime.now().strftime("%H:%M:%S")
            self.cetak(f"[SESI] Terbentuk {waktu} dengan {self.id_lawan} "
                       f"@ {endpoint(conn.getpeername())}")
            self.cetak(f"[SESI] K_S = {hasil['ks']} (16 ASCII), sesi KDC {hasil['sesi_id']}")
            self.log.tulis("SESI", conn.getpeername(), teks=hasil["ks"])
        except (ProtokolError, FrameError, OSError, DataTidakValid, ValueError) as e:
            self.cetak(f"[ERROR] Handshake gagal: {e}")
            self.log.tulis("GAGAL", teks=str(e))
            self.kode = 3
            return
        finally:
            if self.koneksi is not None and not self.sesi.terbentuk:
                try:
                    self.koneksi.close()
                except OSError:
                    pass
                self.koneksi = None

        self.thread_penerima = threading.Thread(
            target=self.terima_loop, args=(self.koneksi, self.koneksi.getpeername()),
            daemon=True,
        )
        self.thread_penerima.start()

        if self.interaktif:
            self.konsol()
        else:
            self.mode_otomatis_alice()

    # ---------- peran Bob ----------

    def layani_bob(self, conn, peer):
        conn.settimeout(self.timeout)
        try:
            msg = terima_json(conn, self.log)
            if not msg or msg.get("tipe") != "tiket":
                raise ProtokolError("Alice tidak mengirim tiket langkah 3")
            tiket = bytes.fromhex(msg["tiket"])
            self.cetak(f"\n[LANGKAH 3] diterima dari {endpoint(peer)}: "
                       f"E_KB[K_S, ID_A] (HEX) = {msg['tiket']}")
            isi = json.loads(self.kunci_master.dekripsi(tiket).decode())
            if isi.get("id_b") != self.id_diri:
                raise ProtokolError("tiket bukan untuk ID node ini")
            kunci = isi["ks"]
            cipher = ManualAES(kunci)
            id_a = isi.get("id_a")
            self.log.tulis("LANGKAH3", peer, data=tiket, teks=f"id_a={id_a} ks={kunci}")

            n2 = secrets.randbits(32)
            tantangan = cipher.enkripsi(str(n2).encode())
            kirim_json(conn, {"tipe": "tantangan", "data": tantangan.hex()}, self.log)
            self.cetak(f"[LANGKAH 4] {self.id_diri} -> {id_a} : "
                       f"E_KS[N2] (HEX) = {tantangan.hex()}")
            self.cetak(f"            N2 = {n2}")
            self.log.tulis("LANGKAH4", peer, data=tantangan)

            jawab = terima_json(conn, self.log)
            if not jawab or jawab.get("tipe") != "konfirmasi":
                raise ProtokolError("Alice tidak mengirim konfirmasi N2-1")
            nilai = int(cipher.dekripsi(bytes.fromhex(jawab["data"])).decode())
            self.cetak(f"[LANGKAH 5] diterima: E_KS[N2-1] (HEX) = {jawab['data']}")
            if nilai != n2 - 1:
                raise ProtokolError("konfirmasi langkah 5 salah; sesi ditolak")
            self.log.tulis("LANGKAH5", peer, data=bytes.fromhex(jawab["data"]))

            conn.settimeout(None)
            self.koneksi = conn
            self.sesi.pasang(
                cipher, kunci, None, id_a, peer, conn.getsockname()
            )
            waktu = datetime.now().strftime("%H:%M:%S")
            self.cetak(f"[SESI] Terbentuk {waktu} dengan {id_a} @ {endpoint(peer)}")
            self.cetak(f"[SESI] K_S = {kunci} (16 ASCII)")
            self.log.tulis("SESI", peer, teks=kunci)
            if not self.interaktif:
                self.status()
            self.terima_loop(conn, peer)
        except (ProtokolError, FrameError, OSError, DataTidakValid, KeyError,
                ValueError, UnicodeDecodeError) as e:
            self.cetak(f"\n[ERROR] Handshake/ sesi dari {endpoint(peer)}: {e}")
            self.log.tulis("GAGAL", peer, teks=str(e))
            self.selesai.set()
            try:
                conn.close()
            except OSError:
                pass

    def dengarkan(self):
        alamat_bind = self.bind or "0.0.0.0"
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((alamat_bind, self.port))
            server.listen(5)
        except OSError as e:
            self.cetak(f"[ERROR] Gagal mendengarkan di {alamat_bind}:{self.port}: {e}")
            self.kode = 2
            self.selesai.set()
            return
        server.settimeout(1.0)
        self.server = server
        self.cetak(f"[SIAP] {self.id_diri} mendengarkan di {alamat_bind}:{self.port}")
        self.cetak(f"[INFO] IP yang dipakai untuk koneksi akan tampil di status.")
        self.log.tulis("MENDENGAR", info=f"bind={alamat_bind}:{self.port}")

        while not self.berhenti.is_set():
            try:
                conn, peer = server.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                break
            lokal = conn.getsockname()
            self.cetak(f"\n[KONEKSI] {endpoint(peer)} -> {endpoint(lokal)}")
            self.layani_bob(conn, peer)
            self.cetak(f"[INFO] Menunggu koneksi berikutnya di {alamat_bind}:{self.port}")
        try:
            server.close()
        except OSError:
            pass

    def jalankan_bob(self):
        self.cetak("=" * 62)
        self.cetak("        NODE BOB - PENERIMA TIKET + PENERIMA/PENGIRIM AES")
        self.cetak("=" * 62)
        alamat_bind = self.bind or "0.0.0.0"
        self.cetak(f"[KDC]     {self.kdc_host}:{self.kdc_port}")
        self.cetak(f"[DENGAR]  {alamat_bind}:{self.port}")
        self.cetak(f"[KUNCI]   K_B = {self.kunci_master.kunci.decode()} (16 ASCII)")
        self.cetak("=" * 62 + "\n")
        self.log.tulis("MULAI", info=f"role=bob bind={alamat_bind}:{self.port}")

        self.thread_server = threading.Thread(target=self.dengarkan, daemon=True)
        self.thread_server.start()
        time.sleep(0.2)
        if self.kode == 2:
            return

        if self.interaktif:
            self.konsol()
        else:
            self.mode_otomatis_bob()
