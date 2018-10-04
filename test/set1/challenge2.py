import cpals
import binascii

print(cpals.fixed_xor(binascii.unhexlify('1c0111001f010100061a024b53535009181c'), binascii.unhexlify('686974207468652062756c6c277320657965')))
print binascii.hexlify(cpals.fixed_xor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965'))