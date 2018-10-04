import cpals
import binascii

filename = '8.txt'
with open(filename) as fobj:
    lines = (line.rstrip() for line in fobj)
    for line in lines:
        if cpals.detect_aes_ecb(line, 16):
            print line


print cpals.decr_aes_ecb('\n'.join(lines), 'YELLOW SUBMARINE')