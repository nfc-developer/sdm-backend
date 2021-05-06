import binascii
import os

SDM_META_READ_KEY = binascii.unhexlify(os.environ.get("SDM_META_READ_KEY", "00000000000000000000000000000000"))
SDM_FILE_READ_KEY = binascii.unhexlify(os.environ.get("SDM_FILE_READ_KEY", "00000000000000000000000000000000"))

ENC_PICC_DATA_PARAM = os.environ.get("ENC_PICC_DATA_PARAM", "picc_data")
ENC_FILE_DATA_PARAM = os.environ.get("ENC_FILE_DATA_PARAM", "enc")

UID_PARAM = os.environ.get("UID_PARAM", "uid")
CTR_PARAM = os.environ.get("CTR_PARAM", "ctr")

SDMMAC_PARAM = os.environ.get("SDMMAC_PARAM", "cmac")

REQUIRE_LRP = (os.environ.get("REQUIRE_LRP", "0") == "1")
