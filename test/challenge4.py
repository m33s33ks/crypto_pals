import cpals

messages = list()

with open("4.txt") as f:
	for line in f:
		messages.append(line.rstrip())

solution = cpals.frequency_check(messages)
for k, v in solution:
	print("%s: %s" % (k, v))
