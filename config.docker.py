import binascii
import os

SDM_META_READ_KEY = binascii.unhexlify(os.environ.get("SDM_META_READ_KEY", "00000000000000000000000000000000"))
SDM_FILE_READ_KEY = binascii.unhexlify(os.environ.get("SDM_FILE_READ_KEY", "00000000000000000000000000000000"))

ENC_PICC_DATA_PARAM = os.environ.get("ENC_PICC_DATA_PARAM", "picc_data")
ENC_FILE_DATA_PARAM = os.environ.get("ENC_FILE_DATA_PARAM", "enc")
SDMMAC_PARAM = os.environ.get("SDMMAC_PARAM", "cmac")
