# cryptopals challenge3
import binascii
from operator import itemgetter
from collections import Counter

mostly_english = {"Meh": 888, "Meh2": 999, "Meh3": 777}
gkey = None


def xor(message, key):
	# fugly workaround so i dont lose the actual key
	global gkey
	byte_message = bytearray(binascii.unhexlify(message))
	byte_key = bytearray(key)
	size = len(byte_message)
	xord_byte_array = bytearray(size)
	gkey = byte_key[0]
	for i in range(size):
		xord_byte_array[i] = byte_message[i] ^ byte_key[0]
	return xord_byte_array


def frequency_check(message):
	global mostly_english
	global gkey
	frequency = {"e": 13, "t": 9, "a": 8, "o": 7, "i": 6}
	message_d = message.decode()
	# turn it into all lower chars
	counter = Counter(str(message_d.lower()))
	frequency_m = get_percentage(counter, len(message))
	score = 0
	#  the english frequency from the frequency list with the counter result
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
		mostly_english["[+] key: ord{ "+str(gkey)+" } or char{ "+chr(gkey)+" } message: "+message_d+"]"] = score
	elif score < mostly_english[max(mostly_english, key=mostly_english.get)]:
		mostly_english["[+] key: ord{ "+str(gkey)+" } or char{ "+chr(gkey)+" } message: "+message_d+"]"] = score


def get_percentage(counter, m_length):
	dictionary = {"e": None, "t": None, "a": None, "o": None, "i": None}
	for x in dictionary:
		n = counter[x]
		percent = (n * 100) / m_length
		dictionary[x] = percent
	return dictionary


for one in range(97, 122):
	frequency_check(xor('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736', chr(one)))

# should sort the lists, does it but i get a type warning
for k, v in sorted(mostly_english.items(), key=itemgetter(1)):
	print("%s: %s" % (k, v))
