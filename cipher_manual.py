# cipher_manual_v3.py
"""
MODUL IMPLEMENTASI MANUAL ALGORITMA KRIPTOGRAFI SIMETRIS DES (DATA ENCRYPTION STANDARD)
Dibuat murni tanpa library enkripsi eksternal untuk Tugas Keamanan Informasi (KI).
"""

class ManualDES:
    # Initial Permutation (IP)
    IP = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    # Final Permutation (FP / IP-1)
    FP = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ]

    # Expansion Permutation (E)
    E = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]

    # Permutation P
    P = [
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
    ]

    # Permuted Choice 1 (PC1)
    PC1 = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ]

    # Permuted Choice 2 (PC2)
    PC2 = [
        14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32
    ]

    # S-Boxes
    S_BOX = [
        # S1
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        # S2
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        # S3
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        # S4
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        # S5
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        # S6
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        # S7
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        # S8
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]

    SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    def __init__(self, key: bytes):
        # DES mengharapkan key 8 byte (64 bit)
        if len(key) < 8:
            key = key.ljust(8, b'\0')
        else:
            key = key[:8]
        self.key = key
        self.subkeys = self._generate_subkeys(key)

    @staticmethod
    def _bytes_to_bits(data: bytes) -> list:
        bits = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits

    @staticmethod
    def _bits_to_bytes(bits: list) -> bytes:
        byte_list = []
        for i in range(0, len(bits), 8):
            byte_val = 0
            for bit in bits[i:i+8]:
                byte_val = (byte_val << 1) | bit
            byte_list.append(byte_val)
        return bytes(byte_list)

    @staticmethod
    def _permute(bits: list, table: list) -> list:
        return [bits[i - 1] for i in table]

    def _generate_subkeys(self, key: bytes) -> list:
        key_bits = self._bytes_to_bits(key)
        key_56 = self._permute(key_bits, self.PC1)
        C = key_56[:28]
        D = key_56[28:]
        
        subkeys = []
        for shift in self.SHIFT_SCHEDULE:
            C = C[shift:] + C[:shift]
            D = D[shift:] + D[:shift]
            combined = C + D
            sub_48 = self._permute(combined, self.PC2)
            subkeys.append(sub_48)
        return subkeys

    def _feistel_function(self, R_32: list, subkey_48: list) -> list:
        E_48 = self._permute(R_32, self.E)
        xor_res = [b ^ k for b, k in zip(E_48, subkey_48)]
        
        s_out_bits = []
        for i in range(8):
            block = xor_res[i*6 : (i+1)*6]
            row = (block[0] << 1) | block[5]
            col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
            val = self.S_BOX[i][row][col]
            s_out_bits.extend([(val >> (3 - b)) & 1 for b in range(4)])
            
        return self._permute(s_out_bits, self.P)

    def _process_block(self, block_8bytes: bytes, subkeys: list) -> bytes:
        bits = self._bytes_to_bits(block_8bytes)
        permuted_bits = self._permute(bits, self.IP)
        
        L = permuted_bits[:32]
        R = permuted_bits[32:]
        
        for k in subkeys:
            f_res = self._feistel_function(R, k)
            new_R = [l ^ f for l, f in zip(L, f_res)]
            L = R
            R = new_R
            
        final_bits = R + L
        fp_bits = self._permute(final_bits, self.FP)
        return self._bits_to_bytes(fp_bits)

    def _pad_pkcs7(self, data: bytes) -> bytes:
        pad_len = 8 - (len(data) % 8)
        return data + bytes([pad_len] * pad_len)

    def _unpad_pkcs7(self, data: bytes) -> bytes:
        if not data or len(data) % 8 != 0:
            return data
        pad_len = data[-1]
        if 1 <= pad_len <= 8 and data[-pad_len:] == bytes([pad_len]) * pad_len:
            return data[:-pad_len]
        return data

    def encrypt(self, plaintext: bytes) -> bytes:
        padded = self._pad_pkcs7(plaintext)
        ciphertext = bytearray()
        for i in range(0, len(padded), 8):
            block = padded[i:i+8]
            ciphertext.extend(self._process_block(block, self.subkeys))
        return bytes(ciphertext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) % 8 != 0:
            return b""
        reversed_subkeys = list(reversed(self.subkeys))
        plaintext_padded = bytearray()
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i+8]
            plaintext_padded.extend(self._process_block(block, reversed_subkeys))
        return self._unpad_pkcs7(bytes(plaintext_padded))
