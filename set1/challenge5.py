import codecs
import itertools
from pprint import pprint

def hex_xor(s, key):
    encrypted_lines = []
    key_iter = itertools.cycle(codecs.encode(key))
    raw_line = bytearray([c ^ next(key_iter) for c in codecs.encode(s)])

    return codecs.encode(raw_line, 'hex').decode()

input = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""

expected = """0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"""

key = 'ICE'

result = hex_xor(input, key)
assert result == expected
print('Success!')
