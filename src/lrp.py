# pylint: disable=line-too-long, invalid-name

"""
Leakage Resilient Primitive (AN12304).

NOTE: This implementation is suitable only for use on PCD side (the device which reads/interacts with the NFC tag).
You shouldn't use this code on PICC (NFC tag/card) side and it shouldn't be ported to JavaCards or similar,
because in such case it may be not resistant to the side channel attacks.
"""
import binascii
import io
from typing import Generator, List, Optional, Union

from Crypto.Cipher import AES
from Crypto.Protocol.SecretSharing import _Element
from Crypto.Util.strxor import strxor


def remove_pad(pt: bytes):
    padl = 0

    for b in pt[::-1]:
        padl += 1

        if b == 0x80:
            break

        if b != 0x00:
            raise RuntimeError('Invalid padding')

    return pt[:-padl]


def nibbles(x: Union[bytes, str]) -> Generator[int, None, None]:
    """
    Generate integers out of x (bytes), applicable for m = 4
    """
    if isinstance(x, bytes):
        x = x.hex()

    for nb in x:
        yield binascii.unhexlify("0" + nb)[0]


def incr_counter(r: bytes):
    max_bit_len = len(r) * 8

    ctr_orig = int.from_bytes(r, byteorder='big', signed=False)
    ctr_incr = ctr_orig + 1

    if ctr_incr.bit_length() > max_bit_len:
        # we have overflow, reset counter to zero
        return b"\x00" * len(r)

    return ctr_incr.to_bytes(len(r), byteorder='big')


def e(k: bytes, v: bytes) -> bytes:
    """
    Simple AES/ECB encrypt `v` with key `k`
    """
    cipher = AES.new(k, AES.MODE_ECB)
    return cipher.encrypt(v)


def d(k: bytes, v: bytes) -> bytes:
    """
    Simple AES/ECB decrypt `v` with key `k`
    """
    cipher = AES.new(k, AES.MODE_ECB)
    return cipher.decrypt(v)


class LRP:
    def __init__(self, key: bytes, u: int, r: Optional[bytes] = None, pad: bool = True):
        """
        Leakage Resilient Primitive
        :param key: secret key from which updated keys will be derived
        :param u: number of updated key to use (counting from 0)
        :param r: IV/counter value (default: all zeros)
        :param pad: whether to use bit padding or no (default: True)
        """
        if r is None:
            r = b"\x00" * 16

        self.key = key
        self.u = u
        self.r = r
        self.pad = pad

        self.p = LRP.generate_plaintexts(key)
        self.ku = LRP.generate_updated_keys(key)
        self.kp = self.ku[self.u]

    @staticmethod
    def generate_plaintexts(k: bytes, m: int = 4) -> List[bytes]:
        """
        Algorithm 1
        """
        h = k
        h = e(h, b"\x55" * 16)
        p = []

        for _ in range(0, 2**m):
            p.append(e(h, b"\xaa" * 16))
            h = e(h, b"\x55" * 16)

        return p

    @staticmethod
    def generate_updated_keys(k: bytes, q: int = 4) -> List[bytes]:
        """
        Algorithm 2
        """
        h = k
        h = e(h, b"\xaa" * 16)
        uk = []

        for _ in range(0, q):
            uk.append(e(h, b"\xaa" * 16))
            h = e(h, b"\x55" * 16)

        return uk

    @staticmethod
    def eval_lrp(p: List[bytes], kp: bytes, x: Union[bytes, str], final: bool) -> bytes:
        """
        Algorithm 3 assuming m = 4
        """
        y = kp

        for x_i in nibbles(x):
            p_j = p[x_i]
            y = e(y, p_j)

        if final:
            y = e(y, b"\x00" * 16)

        return y

    def encrypt(self, data: bytes) -> bytes:
        """
        LRICB encrypt and update counter (LRICBEnc)
        :param data: plaintext
        :return: ciphertext
        """
        pt_stream = io.BytesIO()
        ct_stream = io.BytesIO()
        pt_stream.write(data)

        if self.pad:
            pt_stream.write(b"\x80")

            while pt_stream.getbuffer().nbytes % AES.block_size != 0:
                pt_stream.write(b"\x00")
        elif pt_stream.getbuffer().nbytes % AES.block_size != 0:
            raise RuntimeError("Parameter pt must have length multiple of AES block size.")
        elif pt_stream.getbuffer().nbytes == 0:
            raise RuntimeError("Zero length pt not supported.")

        pt_stream.seek(0)

        while True:
            block = pt_stream.read(AES.block_size)

            if len(block) == 0:
                break

            y = LRP.eval_lrp(self.p, self.kp, self.r, final=True)
            ct_stream.write(e(y, block))
            self.r = incr_counter(self.r)

        return ct_stream.getvalue()

    def decrypt(self, data: bytes) -> bytes:
        """
        LRICB decrypt and update counter (LRICBDecs)
        :param data: ciphertext
        :return: plaintext
        """
        ct_stream = io.BytesIO()
        ct_stream.write(data)
        ct_stream.seek(0)

        pt_stream = io.BytesIO()

        while True:
            block = ct_stream.read(AES.block_size)

            if len(block) == 0:
                break

            y = LRP.eval_lrp(self.p, self.kp, self.r, final=True)
            pt_stream.write(d(y, block))
            self.r = incr_counter(self.r)

        pt = pt_stream.getvalue()

        if self.pad:
            pt = remove_pad(pt)

        return pt

    def cmac(self, data: bytes) -> bytes:
        """
        Calculate CMAC_LRP
        (Huge thanks to @Pharisaeus for help with polynomial math.)
        :param data: message to be authenticated
        :return: CMAC result
        """
        stream = io.BytesIO(data)

        k0 = LRP.eval_lrp(self.p, self.kp, b"\x00" * 16, True)

        k1 = (_Element(k0) * _Element(2)).encode()  # type: ignore
        k2 = (_Element(k0) * _Element(4)).encode()  # type: ignore

        y = b"\x00" * AES.block_size

        while True:
            x = stream.read(AES.block_size)

            if len(x) < AES.block_size or stream.tell() == stream.getbuffer().nbytes:
                break

            y = strxor(x, y)
            y = LRP.eval_lrp(self.p, self.kp, y, True)

        pad_bytes = 0

        if len(x) < AES.block_size:
            pad_bytes = AES.block_size - len(x)
            x = x + b"\x80" + (b"\x00" * (pad_bytes - 1))

        y = strxor(x, y)

        if not pad_bytes:
            y = strxor(y, k1)
        else:
            y = strxor(y, k2)

        return LRP.eval_lrp(self.p, self.kp, y, True)


__all__ = ['LRP']
