"""
A short example how to decrypt and validate CMAC for a simple SDM in LRP mode on NTAG 424 DNA.
"""

import io

from lrp import LRP

import binascii

key = binascii.unhexlify("00000000000000000000000000000000")

# suppose that our NDEF URI payload is:
# https://AAE1508939ECF6FF26BCE407959AB1A5EC022819A35CD293x5E3DB82C19E3865F
# (this is just an example)
# settings: LRP mode, encrypted PICCData mirroring with CMAC
# with SDM MAC input offset: 7, SDM MAC offset: 56, PICC Data offset: 7
# the dynamic part is:
msg = "AAE1508939ECF6FF26BCE407959AB1A5EC022819A35CD293x5E3DB82C19E3865F"

# break it into pieces
iv = msg[:16]
picc_data, cmac = msg[16:].split('x')

# decrypt our message
lrp = LRP(key, 0, binascii.unhexlify(iv), pad=False)
decrypted_msg = lrp.decrypt(binascii.unhexlify(picc_data))
assert decrypted_msg.hex() == "c7042e1d222a63806a000016e2ca89d1"

# create session key
# SV = 00h || 01h || 00h || 80h [ || UID] [ || SDMReadCtr] [ || ZeroPadding] || 1Eh || E1h
svstream = io.BytesIO()
svstream.write(b"\x00\x01\x00\x80")
svstream.write(decrypted_msg[1:11])  # UID || SDMReadCtr

while (svstream.getbuffer().nbytes + 2) % 16 != 0:
    svstream.write(b"\x00")

svstream.write(b"\x1E\xE1")

assert svstream.getbuffer().nbytes % 16 == 0

# generate master key
lrp = LRP(key, 0, b"\x00" * 16, pad=False)
master_key = lrp.cmac(svstream.getvalue())

assert master_key.hex() == "99c2fd9c885c2ca3c9089c20057310c0"

# generate actual MAC_LRP
mac_obj = LRP(master_key, 0, b"\x00" * 16, pad=False)
# everything in hex since PICCData till the MAC offset
msg_no_cmac = (msg.split('x')[0] + 'x').encode('ascii')
full_tag = mac_obj.cmac(msg_no_cmac)
short_tag = bytes(bytearray([full_tag[i] for i in range(16) if i % 2 == 1])).hex()

assert short_tag == cmac.lower()
print('cmac', short_tag.upper())
