"""
This code was implemented based on the examples provided in:
* AN12196: NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints
"""

import binascii

import config
from ntag424 import decrypt_sun_message, InvalidMessage


def test_sun1():
    # From AN12196 page 12
    # https://ntag.nxp.com/424?e=EF963FF7828658A599F3041510671E88&c=94EED9EE65337086
    data_tag, uid, read_ctr_num, file_data = decrypt_sun_message(
        sdm_meta_read_key=binascii.unhexlify('00000000000000000000000000000000'),
        sdm_file_read_key=binascii.unhexlify('00000000000000000000000000000000'),
        picc_enc_data=binascii.unhexlify("EF963FF7828658A599F3041510671E88"),
        sdmmac=binascii.unhexlify("94EED9EE65337086"))

    assert data_tag == b"\xc7"
    assert uid == b"\x04\xde\x5f\x1e\xac\xc0\x40"
    assert read_ctr_num == 61
    assert file_data is None


def test_sun2():
    # FROM AN12196 page 18
    # https://www.my424dna.com/?picc_data=FD91EC264309878BE6345CBE53BADF40&enc=CEE9A53E3E463EF1F459635736738962&cmac=ECC1E7F6C6C73BF6
    original_sdmmac_param = config.SDMMAC_PARAM
    config.SDMMAC_PARAM = "cmac"
    data_tag, uid, read_ctr_num, file_data = decrypt_sun_message(
        sdm_meta_read_key=binascii.unhexlify('00000000000000000000000000000000'),
        sdm_file_read_key=binascii.unhexlify('00000000000000000000000000000000'),
        picc_enc_data=binascii.unhexlify("FD91EC264309878BE6345CBE53BADF40"),
        sdmmac=binascii.unhexlify("ECC1E7F6C6C73BF6"),
        enc_file_data=binascii.unhexlify("CEE9A53E3E463EF1F459635736738962"))
    config.SDMMAC_PARAM = original_sdmmac_param

    assert data_tag == b'\xc7'
    assert uid == b'\x04\x95\x8C\xAA\x5C\x5E\x80'
    assert read_ctr_num == 8
    assert file_data == b'xxxxxxxxxxxxxxxx'


def test_sun2_wrong_sdmmac():
    try:
        original_sdmmac_param = config.SDMMAC_PARAM
        config.SDMMAC_PARAM = "cmac"
        decrypt_sun_message(
            sdm_meta_read_key=binascii.unhexlify('00000000000000000000000000000000'),
            sdm_file_read_key=binascii.unhexlify('00000000000000000000000000000000'),
            picc_enc_data=binascii.unhexlify("FD91EC264309878BE6345CBE53BADF40"),
            sdmmac=binascii.unhexlify("3CC1E7F6C6C33B33"),
            enc_file_data=binascii.unhexlify("CEE9A53E3E463EF1F459635736738962"))
    except InvalidMessage as e:
        # this is expected
        pass
    else:
        raise RuntimeError("InvalidSDMMAC was not thrown as expected")
    finally:
        config.SDMMAC_PARAM = original_sdmmac_param


test_sun1()
test_sun2()
test_sun2_wrong_sdmmac()
