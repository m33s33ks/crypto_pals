import binascii
from collections import Counter
from Crypto.Cipher import AES
from itertools import combinations, izip


def hex2base64(string):
    return string.decode('hex').encode('base64')


def base642hex(string):
    return string.decode('base64').encode('hex')


def unhex(hex):
    return binascii.unhexlify(hex)


def fixed_xor(str1, str2):
    byte_str1 = bytearray(str1)
    byte_str2 = bytearray(str2)
    size = len(byte_str1) if byte_str1 < byte_str2 else len(byte_str2)
    xord_byte_array = bytearray(size)
    for i in range(size):
        xord_byte_array[i] = byte_str1[i] ^ byte_str2[i]
    return xord_byte_array


# xors a bytearray with a given key
# returns an xored bytearray
def xor(message, key):
    byte_message = message
    byte_key = bytearray(key)
    size = len(byte_message)
    xord_byte_array = bytearray(size)
    for i in range(size):
        xord_byte_array[i] = byte_message[i] ^ byte_key[0]
    return xord_byte_array


# checks a message for letter frequency
# after the message has been xored within a range of keys 1 to 122 TODO Outsource this and just keep the freq check
# also checking for non printable characters and adding a malus to them
# returns the most likely key with the lowest score
def frequency_check(message):
    mostly_english = {"Meh": 10000, "Meh2": 10000, "Meh3": 10000}
    frequency = {"e": 13, "t": 9, "a": 8, "o": 7, "i": 6}

    for one in range(1, 122):
        message_xor = xor(message, chr(one))
        message_d = str(message_xor)
        # turn it into all lower chars
        counter = Counter(str(message_d.lower()))
        frequency_m = get_percentage(counter, len(message))
        score = 0

        #  compare the english frequency from the frequency list with the counter result
        for key in frequency:
            if frequency_m[key] != 0:
                # the score is how much the result differs
                score += abs(frequency[key] - frequency_m[key])
            else:
                score += frequency[key]
        # another malus for \x00 chars since they seem to pop up a lot
        weird_chars = counter['\x00']
        score += weird_chars * 20

        # add a malus for not ascii normal written characters like |{}~ or NULL
        for char in counter:
            if ord(char) < 32 or ord(char) > 122 or ord(char) < 97 > 64:
                score += 20

        # remove a higher score from the dictionary with possible english sentences and add the new one with a better score
        # rewrote this so only the int value of the tested key is the key and the value is the achieved score
        if score < mostly_english[max(mostly_english, key=mostly_english.get)] and len(mostly_english):
            key_to_delete = max(mostly_english, key=lambda k: mostly_english[k])
            del mostly_english[key_to_delete]
            mostly_english[one] = score
        elif score < mostly_english[max(mostly_english, key=mostly_english.get)]:
            mostly_english[one] = score
    # rewrote the return to just return the highest scoring value
    return min(mostly_english, key=lambda k: mostly_english[k])


# returns a dictionary with a percentual distribution score per character
def get_percentage(counter, m_length):
    dictionary = {"e": None, "t": None, "a": None, "o": None, "i": None}
    for x in dictionary:
        n = counter[x]
        percent = (n * 100) / m_length
        dictionary[x] = percent
    return dictionary


def repeating_key_xor(str1, key):
    byte_str1 = bytearray(str1)
    byte_key = bytearray(key)
    size = len(byte_str1)
    xord_byte_array = bytearray(size)
    index = 0

    while index < size - 1:
        for b in range(len(key)):
            xord_byte_array[index] = byte_str1[index] ^ byte_key[b]
            if index < size - 1:
                index += 1
            else:
                break

    return binascii.hexlify(xord_byte_array)


def break_repeatingkey_xor(cipher):
    # find the keysize
    cipher_bytes = bytearray(cipher)
    keysize = find_keysize(cipher_bytes)
    # break the ciphertext into block of keysize length
    key_string = ""
    for blocks in range(keysize):
        block = bytearray()
        for byte in range(blocks, len(cipher_bytes), keysize):
            block.append(cipher_bytes[byte])
        keychar = frequency_check(block)
        key_string += chr(keychar)
    print "[+] Possible Key assembled: [" + key_string + "]"
    print "[+] Begin decryption...\n\n"
    print binascii.unhexlify(repeating_key_xor(cipher, key_string))


def hamming_distance(bytes1, bytes2):
    return sum(bin(b1 ^ b2).count("1") for b1, b2 in zip(bytes1, bytes2))


def normalized_hamming(data, keysize):
    return hamming_distance(data[:-keysize], data[keysize:])


def find_keysize(cipher_bytes):
    return min(range(2, 41), key=lambda x: normalized_hamming(cipher_bytes, x))


def decr_aes_ecb(cipherm, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(cipherm)


def detect_aes_ecb(data, block_size):
    myrange = range(0, len(data), block_size)
    inds = combinations(zip(myrange, myrange[1:]), 2)
    return any(data[i1:i2] == data[j1:j2] for (i1, i2), (j1, j2) in inds)


def pkcs7_padding(msg, blocksize):
    reminder = len(msg) % blocksize
    print hex(reminder)
    return chr(hex(reminder))




