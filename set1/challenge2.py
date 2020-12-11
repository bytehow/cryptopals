import codecs

def hex_xor(s1, s2):
    assert len(s1) == len(s2), 'inputs should be equal length'

    bytes1 = codecs.decode(s1, 'hex')
    bytes2 = codecs.decode(s2, 'hex')

    raw = bytearray([b1 ^ b2 for b1, b2 in zip(bytes1, bytes2)])
    return  codecs.encode(raw, 'hex').decode()

s1 = '1c0111001f010100061a024b53535009181c'
s2 = '686974207468652062756c6c277320657965'
expected = '746865206b696420646f6e277420706c6179'

assert hex_xor(s1, s2) == expected
print('Success!')
