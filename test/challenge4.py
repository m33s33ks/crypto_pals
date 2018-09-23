import cpals
import binascii

messages = list()

with open("4.txt") as f:
	for line in f:
		messages.append(line.rstrip())

solution = cpals.frequency_check(bytearray(binascii.unhexlify(messages)))

# this broke because i can't just expect the xor function to handle messages. TODO Fix this
for k, v in solution:
	print("%s: %s" % (k, v))
