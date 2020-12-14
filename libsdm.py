"""
This code was implemented based on the examples provided in:
* AN12196: NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints
"""

import io
import struct
from typing import Optional, Tuple

from Crypto.Hash import CMAC
from Crypto.Cipher import AES

import config


class InvalidMessage(RuntimeError):
    pass


def calculate_sdmmac(sdm_file_read_key: bytes,
                     picc_data: bytes,
                     enc_file_data: Optional[bytes] = None) -> bytes:
    """
    Calculate SDMMAC for NTAG 424 DNA
    :param sdm_file_read_key: MAC calculation key (K_SDMFileReadKey)
    :param picc_data: [ UID ][ SDMReadCtr ]
    :param enc_file_data: SDMEncFileData (if used)
    :return: calculated SDMMAC (8 bytes)
    """
    sv2stream = io.BytesIO()
    sv2stream.write(b"\x3C\xC3\x00\x01\x00\x80")
    sv2stream.write(picc_data)

    while sv2stream.getbuffer().nbytes % AES.block_size != 0:
        # zero padding till the end of the block
        sv2stream.write(b"\x00")

    c2 = CMAC.new(sdm_file_read_key, ciphermod=AES)
    c2.update(sv2stream.getvalue())
    sdmmac = CMAC.new(c2.digest(), ciphermod=AES)

    if enc_file_data:
        sdmmac_param_text = "&{}=".format(config.SDMMAC_PARAM)
        
        if not config.SDMMAC_PARAM:
            sdmmac_param_text = ""

        sdmmac.update(enc_file_data.hex().upper().encode('ascii') + sdmmac_param_text.encode('ascii'))

    return bytes(bytearray([sdmmac.digest()[i] for i in range(16) if i % 2 == 1]))


def decrypt_file_data(sdm_file_read_key: bytes,
                      picc_data: bytes,
                      read_ctr: bytes,
                      enc_file_data: bytes) -> bytes:
    """
    Decrypt SDMEncFileData for NTAG 424 DNA
    :param sdm_file_read_key: SUN decryption key (K_SDMFileReadKey)
    :param picc_data: PICCDataTag [ || UID ][ || SDMReadCtr ]]
    :param read_ctr: SDMReadCtr
    :param enc_file_data: SDMEncFileData
    :return: decrypted file data (bytes)
    """
    sv1stream = io.BytesIO()
    sv1stream.write(b"\xC3\x3C\x00\x01\x00\x80")
    sv1stream.write(picc_data)

    while sv1stream.getbuffer().nbytes % AES.block_size != 0:
        # zero padding till the end of the block
        sv1stream.write(b"\x00")

    cm = CMAC.new(sdm_file_read_key, ciphermod=AES)
    cm.update(sv1stream.getvalue())
    k_ses_sdm_file_read_enc = cm.digest()
    ive = AES.new(k_ses_sdm_file_read_enc, AES.MODE_ECB) \
        .encrypt(read_ctr + b"\x00" * 13)
    # in datasheet it is written that KSDMMetaReadKey should be used,
    # but actually seems to be KSesSDMFileReadENC
    return AES.new(k_ses_sdm_file_read_enc, AES.MODE_CBC, IV=ive) \
        .decrypt(enc_file_data)


def validate_plain_sun(uid: bytes, read_ctr: bytes, sdmmac: bytes, sdm_file_read_key: bytes):
    read_ctr_ba = bytearray(read_ctr)
    read_ctr_ba.reverse()

    datastream = io.BytesIO()
    datastream.write(uid)
    datastream.write(read_ctr_ba)

    proper_sdmmac = calculate_sdmmac(sdm_file_read_key, datastream.getvalue())

    if sdmmac != proper_sdmmac:
        raise InvalidMessage("Message is not properly signed - invalid MAC")

    read_ctr_num = struct.unpack('>I', b"\x00" + read_ctr)[0]
    return uid, read_ctr_num


def decrypt_sun_message(sdm_meta_read_key: bytes,
                        sdm_file_read_key: bytes,
                        picc_enc_data: bytes,
                        sdmmac: bytes,
                        enc_file_data: Optional[bytes] = None) -> Tuple[bytes, bytes, int, Optional[bytes]]:
    """
    Decrypt SUN message for NTAG 424 DNA
    :param sdm_meta_read_key: SUN decryption key (K_SDMMetaReadKey)
    :param sdm_file_read_key: MAC calculation key (K_SDMFileReadKey)
    :param ciphertext: Encrypted SUN message
    :param mac: SDMMAC of the SUN message
    :param enc_file_data: SDMEncFileData (if present)
    :return: Tuple: PICCDataTag (1 byte), Tag UID (bytes), Read counter (int), File data (bytes; only if present)
    :raises:
        InvalidMessage: if SUN message is invalid
    """
    cipher = AES.new(sdm_meta_read_key, AES.MODE_CBC, IV=b'\x00' * 16)
    plaintext = cipher.decrypt(picc_enc_data)
    pstream = io.BytesIO(plaintext)
    datastream = io.BytesIO()

    picc_data_tag = pstream.read(1)
    uid_mirroring_en = (picc_data_tag[0] & 0x80) == 0x80
    sdm_read_ctr_en = (picc_data_tag[0] & 0x40) == 0x40
    uid_length = (picc_data_tag[0] & 0x0F)

    uid = None
    read_ctr = None
    read_ctr_num = None
    file_data = None

    # so far this is the only length mentioned by datasheet
    # dont read the buffer any further if we don't recognize it
    if uid_length not in [0x07]:
        # fake SDMMAC calculation to avoid potential timing attacks
        calculate_sdmmac(sdm_file_read_key, b"\x00" * 10, enc_file_data)
        raise InvalidMessage("Unsupported UID length")

    if uid_mirroring_en:
        uid = pstream.read(uid_length)
        datastream.write(uid)

    if sdm_read_ctr_en:
        read_ctr = pstream.read(3)
        datastream.write(read_ctr)
        read_ctr_num = struct.unpack("<I", read_ctr + b"\x00")[0]

    if sdmmac != calculate_sdmmac(sdm_file_read_key, datastream.getvalue(), enc_file_data):
        raise InvalidMessage("Message is not properly signed - invalid MAC")

    if enc_file_data:
        if not read_ctr:
            raise InvalidMessage("SDMReadCtr is required to decipher SDMENCFileData.")

        file_data = decrypt_file_data(sdm_file_read_key, datastream.getvalue(), read_ctr, enc_file_data)

    return picc_data_tag, uid, read_ctr_num, file_data
