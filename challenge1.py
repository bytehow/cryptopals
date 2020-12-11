import codecs

def hex_to_b64(hex):
    decoded = codecs.decode(input, 'hex')
    b64encoded = codecs.encode(decoded, 'base64').decode().strip()
    return b64encoded

input = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
expected = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

assert hex_to_b64(input) == expected
