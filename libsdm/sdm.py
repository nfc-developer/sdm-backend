# pylint: disable=invalid-name, line-too-long

"""
This code was implemented based on the examples provided in:
* AN12196: NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints
"""

import io
import struct
from enum import Enum
from typing import Callable, Optional

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

import config
from libsdm.lrp import LRP


class EncMode(Enum):
    AES = 0
    LRP = 1


class ParamMode(Enum):
    SEPARATED = 0
    BULK = 1


class InvalidMessage(RuntimeError):
    pass


def calculate_sdmmac(param_mode: ParamMode,
                     sdm_file_read_key: bytes,
                     picc_data: bytes,
                     enc_file_data: Optional[bytes] = None,
                     mode: Optional[EncMode] = None) -> bytes:
    """
    Calculate SDMMAC for NTAG 424 DNA
    :param param_mode: Type of dynamic URL encoding (ParamMode)
    :param sdm_file_read_key: MAC calculation key (K_SDMFileReadKey)
    :param picc_data: [ UID ][ SDMReadCtr ]
    :param enc_file_data: SDMEncFileData (if used)
    :param mode: Encryption mode used by PICC - EncMode.AES (default) or EncMode.LRP
    :return: calculated SDMMAC (8 bytes)
    """
    if mode is None:
        mode = EncMode.AES

    input_buf = io.BytesIO()

    if enc_file_data:
        sdmmac_param_text = f"&{config.SDMMAC_PARAM}="

        if param_mode == ParamMode.BULK or not config.SDMMAC_PARAM:
            sdmmac_param_text = ""

        input_buf.write(enc_file_data.hex().upper().encode('ascii') + sdmmac_param_text.encode('ascii'))

    if mode == EncMode.AES:
        sv2stream = io.BytesIO()
        sv2stream.write(b"\x3C\xC3\x00\x01\x00\x80")
        sv2stream.write(picc_data)

        while sv2stream.getbuffer().nbytes % AES.block_size != 0:
            # zero padding till the end of the block
            sv2stream.write(b"\x00")

        c2 = CMAC.new(sdm_file_read_key, ciphermod=AES)
        c2.update(sv2stream.getvalue())
        sdmmac = CMAC.new(c2.digest(), ciphermod=AES)
        sdmmac.update(input_buf.getvalue())
        mac_digest = sdmmac.digest()
    elif mode == EncMode.LRP:
        sv2stream = io.BytesIO()
        sv2stream.write(b"\x00\x01\x00\x80")
        sv2stream.write(picc_data)

        while (sv2stream.getbuffer().nbytes + 2) % AES.block_size != 0:
            # zero padding till the end of the block
            sv2stream.write(b"\x00")

        sv2stream.write(b"\x1E\xE1")
        sv = sv2stream.getvalue()

        lrp_master = LRP(sdm_file_read_key, 0)
        master_key = lrp_master.cmac(sv)

        lrp_session_macing = LRP(master_key, 0)
        mac_digest = lrp_session_macing.cmac(input_buf.getvalue())
    else:
        raise InvalidMessage("Invalid encryption mode.")

    return bytes(bytearray([mac_digest[i] for i in range(16) if i % 2 == 1]))


def decrypt_file_data(sdm_file_read_key: bytes,
                      picc_data: bytes,
                      read_ctr: bytes,
                      enc_file_data: bytes,
                      mode: Optional[EncMode] = None) -> bytes:
    """
    Decrypt SDMEncFileData for NTAG 424 DNA
    :param sdm_file_read_key: SUN decryption key (K_SDMFileReadKey)
    :param picc_data: PICCDataTag [ || UID ][ || SDMReadCtr ]]
    :param read_ctr: SDMReadCtr
    :param enc_file_data: SDMEncFileData
    :param mode: Encryption mode used by PICC - EncMode.AES (default) or EncMode.LRP
    :return: decrypted file data (bytes)
    """
    if mode is None:
        mode = EncMode.AES

    if mode == EncMode.AES:
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

    if mode == EncMode.LRP:
        sv2stream = io.BytesIO()
        sv2stream.write(b"\x00\x01\x00\x80")
        sv2stream.write(picc_data)

        while (sv2stream.getbuffer().nbytes + 2) % AES.block_size != 0:
            # zero padding till the end of the block
            sv2stream.write(b"\x00")

        sv2stream.write(b"\x1E\xE1")
        sv = sv2stream.getvalue()

        lrp_master = LRP(sdm_file_read_key, 0)
        master_key = lrp_master.cmac(sv)

        lrp_session_encing = LRP(master_key, 1, read_ctr + b"\x00\x00\x00", pad=False)
        return lrp_session_encing.decrypt(enc_file_data)

    raise InvalidMessage("Invalid encryption mode")


def validate_plain_sun(uid: bytes, read_ctr: bytes, sdmmac: bytes, sdm_file_read_key: bytes, mode: Optional[EncMode] = None):
    if mode is None:
        mode = EncMode.AES

    read_ctr_ba = bytearray(read_ctr)
    read_ctr_ba.reverse()

    data_stream = io.BytesIO()
    data_stream.write(uid)
    data_stream.write(read_ctr_ba)

    proper_sdmmac = calculate_sdmmac(ParamMode.SEPARATED,
                                     sdm_file_read_key,
                                     data_stream.getvalue(),
                                     mode=mode)

    if sdmmac != proper_sdmmac:
        raise InvalidMessage("Message is not properly signed - invalid MAC")

    read_ctr_num = struct.unpack('>I', b"\x00" + read_ctr)[0]
    return {
        "encryption_mode": mode,
        "uid": uid,
        "read_ctr": read_ctr_num
    }


def get_encryption_mode(picc_enc_data: bytes):
    if len(picc_enc_data) == 16:
        return EncMode.AES

    if len(picc_enc_data) == 24:
        return EncMode.LRP

    raise InvalidMessage("Unsupported encryption mode.")


# pylint: disable=too-many-arguments, too-many-locals
def decrypt_sun_message(param_mode: ParamMode,
                        sdm_meta_read_key: bytes,
                        sdm_file_read_key: Callable[[bytes], bytes],
                        picc_enc_data: bytes,
                        sdmmac: bytes,
                        enc_file_data: Optional[bytes] = None) -> dict:
    """
    Decrypt SUN message for NTAG 424 DNA
    :param param_mode: Type of dynamic URL encoding (ParamMode)
    :param sdm_meta_read_key: SUN decryption key (K_SDMMetaReadKey)
    :param sdm_file_read_key: MAC calculation key (K_SDMFileReadKey)
    :param ciphertext: Encrypted SUN message
    :param mac: SDMMAC of the SUN message
    :param enc_file_data: SDMEncFileData (if present)
    :return: dict: picc_data_tag (1 byte), uid (bytes), read_ctr (int), file_data (bytes; only if present), encryption_mode (EncMode.AES or EncMode.LRP)
    :raises:
        InvalidMessage: if SUN message is invalid
    """
    mode = get_encryption_mode(picc_enc_data)

    if mode == EncMode.AES:
        cipher = AES.new(sdm_meta_read_key, AES.MODE_CBC, IV=b'\x00' * 16)
        plaintext = cipher.decrypt(picc_enc_data)
    elif mode == EncMode.LRP:
        picc_rand = picc_enc_data[0:8]
        picc_enc_data_stripped = picc_enc_data[8:]
        cipher = LRP(sdm_meta_read_key, 0, picc_rand, pad=False)
        plaintext = cipher.decrypt(picc_enc_data_stripped)
    else:
        raise InvalidMessage("Invalid encryption mode.")

    p_stream = io.BytesIO(plaintext)
    data_stream = io.BytesIO()

    picc_data_tag = p_stream.read(1)
    uid_mirroring_en = (picc_data_tag[0] & 0x80) == 0x80
    sdm_read_ctr_en = (picc_data_tag[0] & 0x40) == 0x40
    uid_length = picc_data_tag[0] & 0x0F

    uid = None
    read_ctr = None
    read_ctr_num = None
    file_data = None

    # so far this is the only length mentioned by datasheet
    # dont read the buffer any further if we don't recognize it
    if uid_length not in [0x07]:
        # fake SDMMAC calculation to avoid potential timing attacks
        calculate_sdmmac(param_mode, sdm_file_read_key(b"\x00" * 7), b"\x00" * 10, enc_file_data, mode=mode)
        raise InvalidMessage("Unsupported UID length")

    if uid_mirroring_en:
        uid = p_stream.read(uid_length)
        data_stream.write(uid)

    if sdm_read_ctr_en:
        read_ctr = p_stream.read(3)
        data_stream.write(read_ctr)
        read_ctr_num = struct.unpack("<I", read_ctr + b"\x00")[0]

    if uid is None:
        raise InvalidMessage("UID cannot be None.")

    file_key = sdm_file_read_key(uid)

    if sdmmac != calculate_sdmmac(param_mode,
                                  file_key,
                                  data_stream.getvalue(),
                                  enc_file_data,
                                  mode=mode):
        raise InvalidMessage("Message is not properly signed - invalid MAC")

    if enc_file_data:
        if not read_ctr:
            raise InvalidMessage("SDMReadCtr is required to decipher SDMENCFileData.")

        file_data = decrypt_file_data(file_key, data_stream.getvalue(),
                                      read_ctr, enc_file_data, mode=mode)

    return {
        "picc_data_tag": picc_data_tag,
        "uid": uid,
        "read_ctr": read_ctr_num,
        "file_data": file_data,
        "encryption_mode": mode
    }
