import binascii
import hashlib
import hmac

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

# NOTE:
# Key diversification methods were modified as of 2023-01-24
# If you rely on the previous diversification methods,
# please use legacy_derive.py

DIV_CONST1 = binascii.unhexlify("50494343446174614b6579")
DIV_CONST2 = binascii.unhexlify("536c6f744d61737465724b6579")
DIV_CONST3 = binascii.unhexlify("446976426173654b6579")


def hmac_sha256(key, msg, no_trunc=False):
    hmac_code = hmac.new(key, msg, digestmod=hashlib.sha256).digest()
    return hmac_code if no_trunc else hmac_code[0:16]


# derive a key which is UID-diversified
def derive_tag_key(master_key: bytes, uid: bytes, key_no: int):
    if master_key == (b"\x00" * 16):
        return b"\x00" * 16

    cmac_code = CMAC.new(hmac_sha256(master_key, DIV_CONST2 + bytes([key_no])), ciphermod=AES)
    cmac_code.update(b"\x01" + hmac_sha256(hmac_sha256(master_key, DIV_CONST3, no_trunc=True), uid))
    return cmac_code.digest()


# derive a key which is not UID-diversified
def derive_undiversified_key(master_key: bytes, key_no: int):
    if key_no != 1:
        raise RuntimeError("Only key #1 can be derived in undiversified mode.")

    if master_key == (b"\x00" * 16):
        return b"\x00" * 16

    return hmac_sha256(master_key, DIV_CONST1)
