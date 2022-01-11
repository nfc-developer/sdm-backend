import hashlib
import base64
import binascii


# derive a key which is UID-diversified
def derive_tag_key(master_key: bytes, uid: bytes, key_no: int) -> bytes:
    if master_key == (b"\x00" * 16):
        return b"\x00" * 16

    return hashlib.pbkdf2_hmac('sha512', master_key, b"key" + uid + bytes([key_no]), 5000, 16)


# derive a key which is not UID-diversified
def derive_undiversified_key(master_key: bytes, key_no: int) -> bytes:
    if master_key == (b"\x00" * 16):
        return b"\x00" * 16

    return hashlib.pbkdf2_hmac('sha512', master_key, b"key_no_uid" + bytes([key_no]), 5000, 16)

