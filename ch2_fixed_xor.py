# cryptopals challenge2 
import binascii

def fixed_xor(str1, str2):
    byte_str1 =  bytearray(binascii.unhexlify(str1))
    byte_str2 =  bytearray(binascii.unhexlify(str2))
    size = len(byte_str1) if byte_str1<byte_str2 else len(byte_str2)
    xord_byte_array = bytearray(size)

    for i in range(size):
        xord_byte_array[i] = byte_str1[i] ^ byte_str2[i]
    
    return binascii.hexlify(xord_byte_array)

