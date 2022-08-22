"""
Quick tests against arbitrarily chosen LRP test vectors from AN12304
"""

import binascii

from Crypto.Protocol.SecretSharing import _Element

from lrp import LRP, nibbles, incr_counter


def test_incr_counter():
    assert b"\x01" == incr_counter(b"\x00")
    assert b"\x02" == incr_counter(b"\x01")
    assert b"\x00" == incr_counter(b"\xFF")
    assert b"\x12\x12" == incr_counter(b"\x12\x11")
    assert b"\x00\x00" == incr_counter(b"\xFF\xFF")
    assert b"\x00\x01" == incr_counter(b"\x00\x00")
    assert b"\x00\x02" == incr_counter(b"\x00\x01")
    assert b"\x00\x00\x00\x00" == incr_counter(b"\xFF\xFF\xFF\xFF")


def test_vectors_generate_plaintexts():
    p = LRP.generate_plaintexts(b"\x56\x78\x26\xB8\xDA\x8E\x76\x84\x32\xA9\x54\x8D\xBE\x4A\xA3\xA0")
    assert p[0] == b"\xAC\x20\xD3\x9F\x53\x41\xFE\x98\xDF\xCA\x21\xDA\x86\xBA\x79\x14"
    assert p[15] == b"\x71\xB4\x44\xAF\x25\x7A\x93\x21\x53\x11\xD7\x58\xDD\x33\x32\x47"


def test_vectors_generate_updated_keys():
    uk = LRP.generate_updated_keys(b"\x56\x78\x26\xB8\xDA\x8E\x76\x84\x32\xA9\x54\x8D\xBE\x4A\xA3\xA0")
    assert uk[0] == b"\x16\x3D\x14\xED\x24\xED\x93\x53\x73\x56\x8E\xC5\x21\xE9\x6C\xF4"
    assert uk[2] == b"\xFE\x30\xAB\x50\x46\x7E\x61\x78\x3B\xFE\x6B\x5E\x05\x60\x16\x0E"


def test_nibbles():
    assert list(nibbles(b"\x13\x59")) == [1, 3, 5, 9]
    assert list(nibbles(b"\x4B\x07\x3B\x24\x7C\xD4\x8F\x7E\x0A")) \
        == [4, 0xB, 0, 7, 3, 0xB, 2, 4, 7, 0xC, 0xD, 4, 8, 0xF, 7, 0xE, 0, 0xA]


def test_eval_lrp():
    p = LRP.generate_plaintexts(binascii.unhexlify("567826B8DA8E768432A9548DBE4AA3A0"))
    uk = LRP.generate_updated_keys(binascii.unhexlify("567826B8DA8E768432A9548DBE4AA3A0"))
    assert LRP.eval_lrp(p, uk[2], b"\x13\x59", final=True).hex() \
        == "1ba2c0c578996bc497dd181c6885a9dd"

    p = LRP.generate_plaintexts(binascii.unhexlify("88B95581002057A93E421EFE4076338B"))
    uk = LRP.generate_updated_keys(binascii.unhexlify("88B95581002057A93E421EFE4076338B"))
    assert LRP.eval_lrp(p, uk[2], b"\x77\x29\x9D", final=True).hex() \
        == "E9C04556A214AC3297B83E4BDF46F142".lower()

    p = LRP.generate_plaintexts(binascii.unhexlify("9AFF3EF56FFEC3153B1CADB48B445409"))
    uk = LRP.generate_updated_keys(binascii.unhexlify("9AFF3EF56FFEC3153B1CADB48B445409"))
    assert LRP.eval_lrp(p, uk[3], b"\x4B\x07\x3B\x24\x7C\xD4\x8F\x7E\x0A", final=False).hex() \
        == "909415E5C8BE77563050F2227E17C0E4".lower()


def test_lricb_enc():
    key = binascii.unhexlify("E0C4935FF0C254CD2CEF8FDDC32460CF")
    pt = binascii.unhexlify("012D7F1653CAF6503C6AB0C1010E8CB0")

    lrp = LRP(key, 0, b"\xC3\x31\x5D\xBF", pad=True)
    ct = lrp.encrypt(pt)
    assert ct.hex().upper() == "FCBBACAA4F29182464F99DE41085266F480E863E487BAAF687B43ED1ECE0D623"


def test_lricb_dec():
    key = binascii.unhexlify("E0C4935FF0C254CD2CEF8FDDC32460CF")
    ct = binascii.unhexlify("FCBBACAA4F29182464F99DE41085266F480E863E487BAAF687B43ED1ECE0D623")

    lrp = LRP(key, 0, b"\xC3\x31\x5D\xBF", pad=True)
    pt = lrp.decrypt(ct)
    assert pt.hex().upper() == "012D7F1653CAF6503C6AB0C1010E8CB0"


def test_cmac_subkeys():
    k = binascii.unhexlify("8195088CE6C393708EBBE6C7914ECB0B")
    kx = binascii.unhexlify("2D22571A33B2965A9B49FF4395A43046")

    k0 = LRP.eval_lrp(LRP.generate_plaintexts(k), LRP.generate_updated_keys(k)[0], b"\x00" * 16, True)
    assert (_Element(k0) * _Element(4)).encode().hex() == kx.hex()


def test_cmac():
    k = binascii.unhexlify("8195088CE6C393708EBBE6C7914ECB0B")
    lrp = LRP(k, 0, b"\x00" * 16, True)
    assert lrp.cmac(binascii.unhexlify("BBD5B85772C7")).hex() \
        == "AD8595E0B49C5C0DB18E77355F5AAFF6".lower()

    k = binascii.unhexlify("E2F84A0B0AF40EFEB3EEA215A436605C")
    lrp = LRP(k, 0, b"\x00" * 16, True)
    assert lrp.cmac(binascii.unhexlify("8BF1DDA9FE445560A4F4EB9CE0")).hex() \
        == "D04382DF71BC293FEC4BB10BDB13805F".lower()

    k = binascii.unhexlify("5AA9F6C6DE5138113DF5D6B6C77D5D52")
    lrp = LRP(k, 0, b"\x00" * 16, True)
    assert lrp.cmac(binascii.unhexlify("A4434D740C2CB665FE5396959189383F")).hex() \
        == "8B43ADF767E46B692E8F24E837CB5EFC".lower()
