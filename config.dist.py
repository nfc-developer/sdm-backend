SDM_META_READ_KEY = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
SDM_FILE_READ_KEY = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

# for encrypted mirroring
ENC_PICC_DATA_PARAM = "picc_data"
ENC_FILE_DATA_PARAM = "enc"

# for plaintext mirroring
UID_PARAM = "uid"
CTR_PARAM = "ctr"

# always applied
SDMMAC_PARAM = "cmac"

# accept only SDM using LRP, disallow usage of AES
REQUIRE_LRP = False
