import cpals

messages = ['1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736']

solution = cpals.frequency_check(messages)

for k, v in solution:
	print("%s: %s" % (k, v))
