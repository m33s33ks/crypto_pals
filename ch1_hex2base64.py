# cryptopals challenge1

def hex2base64(str):
	return str.decode('hex').encode('base64')
