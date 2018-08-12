import binascii
from operator import itemgetter
from collections import Counter

def hex2base64(str):
	return str.decode('hex').encode('base64')


def fixed_xor(str1, str2):
	byte_str1 = bytearray(binascii.unhexlify(str1))
	byte_str2 = bytearray(binascii.unhexlify(str2))
	size = len(byte_str1) if byte_str1 < byte_str2 else len(byte_str2)
	xord_byte_array = bytearray(size)

	for i in range(size):
		xord_byte_array[i] = byte_str1[i] ^ byte_str2[i]

	return binascii.hexlify(xord_byte_array)


def xor(message, key):
	byte_message = bytearray(binascii.unhexlify(message))
	byte_key = bytearray(key)
	size = len(byte_message)
	xord_byte_array = bytearray(size)
	for i in range(size):
		xord_byte_array[i] = byte_message[i] ^ byte_key[0]
	return xord_byte_array


def frequency_check(messages):
	mostly_english = {"Meh": 888, "Meh2": 999, "Meh3": 777}
	frequency = {"e": 13, "t": 9, "a": 8, "o": 7, "i": 6}

	for message in messages:
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

			# add a malus for not ascii normal written characters like |{}~ or NULL
			for char in counter:
				if ord(char) < 32 or ord(char) > 122 or ord(char) < 97 > 64:
					score += 20

			# remove a higher score from the dictionary with possible english sentences and add the new one with a better score
			if score < mostly_english[max(mostly_english, key=mostly_english.get)] and len(mostly_english):
				key_to_delete = max(mostly_english, key=lambda k: mostly_english[k])
				del mostly_english[key_to_delete]
				mostly_english["[+] key: ord{ " + str(one) + " } or char{ " + chr(one) + " } message: " + message_d + "]"] = score
			elif score < mostly_english[max(mostly_english, key=mostly_english.get)]:
				mostly_english["[+] key: ord{ " + str(one) + " } or char{ " + chr(one) + " } message: " + message_d + "]"] = score

	return sorted(mostly_english.items(), key=itemgetter(1))


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