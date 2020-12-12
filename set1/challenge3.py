import codecs
import functools
from collections import Counter
from pprint import pprint

def hex_xor(s, b):
    assert isinstance(b, int)
    s = codecs.decode(s, 'hex')

    raw = bytearray([c ^ b for c in s])
    return codecs.encode(raw, 'hex')

def bytes_to_str(array):
    return codecs.decode(array, 'hex').decode('ascii')


def find_candidates(s1, minimum=1):
    candidates = []
    for i in range(256):
        decrypted = hex_xor(s1, i)
        try:
            decrypted_str = bytes_to_str(decrypted)
        except UnicodeDecodeError:
            continue

        counter = Counter(decrypted_str.lower())
        frequency_list = counter.most_common()

        # Check 6 most common
        score = functools.reduce(lambda val, pair: val + int(pair[0] in 'etaoin'),
            frequency_list[:6], 0)
        
        # Check 6 least common
        score += functools.reduce(lambda val, pair: val + int(pair[0] in 'shrdlu'),
                frequency_list[-6:], 0)

        if score >= minimum:
            candidates.append((hex(i), decrypted_str, score))

    return sorted(candidates, key=lambda x: x[2], reverse=True)

input = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
candidates = find_candidates(input, minimum=3)

print('Possible keys:')
print('*' * 80)
pprint(candidates)
