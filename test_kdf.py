import binascii

from derive import derive_undiversified_key, derive_tag_key


def test_kdf_factory_key():
    master_key = binascii.unhexlify("00000000000000000000000000000000")
    assert derive_undiversified_key(master_key, 1).hex() \
           == "00000000000000000000000000000000"
    assert derive_tag_key(master_key, binascii.unhexlify("010203040506AB"), 1).hex() \
           == "00000000000000000000000000000000"
    assert derive_tag_key(master_key, binascii.unhexlify("03030303030303"), 2).hex() \
           == "00000000000000000000000000000000"


def test_kdf_k1():
    master_key = binascii.unhexlify("C9EB67DF090AFF47C3B19A2516680B9D")
    assert derive_undiversified_key(master_key, 1).hex() \
           == "a13086f194d7bdfd108dd11716ea2bdf"
    assert derive_tag_key(master_key, binascii.unhexlify("010203040506AB"), 1).hex() \
           == "f18cdd9389d47ae7ab381e80e5ab6fe3"
    assert derive_tag_key(master_key, binascii.unhexlify("03030303030303"), 2).hex() \
           == "85f7cc459a5b4b2f5d1a5019ded61c88"


def test_kdf_k2():
    master_key = binascii.unhexlify("B95F4C27E3D0BC333792EA968545217F")
    assert derive_undiversified_key(master_key, 1).hex() \
           == "3a553c40846fda656faa0fce4f45fdbd"
    assert derive_tag_key(master_key, binascii.unhexlify("010203040506AB"), 1).hex() \
           == "00883874c67dd23032b2acd10d771635"
    assert derive_tag_key(master_key, binascii.unhexlify("05050505050505"), 2).hex() \
           == "89ae686de793fdf48057ee6e78505cfc"
