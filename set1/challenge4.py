import codecs
import functools
import itertools
from collections import Counter, namedtuple
from pprint import pprint

def hex_xor(s, b):
    assert isinstance(b, int)
    s = codecs.decode(s, 'hex')

    raw = bytearray([c ^ b for c in s])
    return codecs.encode(raw, 'hex')

def bytes_to_str(array):
    return codecs.decode(array, 'hex').decode('ascii')

def get_score(s):
    counter = Counter(s.lower())
    frequency_list = counter.most_common()
    # Check 6 most common
    score = functools.reduce(lambda val, pair: val + int(pair[0] in 'etaoin'),
        frequency_list[:6], 0)
    
    # Check 6 least common
    score += functools.reduce(lambda val, pair: val + int(pair[0] in 'shrdlu'),
            frequency_list[-6:], 0)

    return score

def find_candidates(ciphertexts, minimum=1):
    candidates = []
    for c, k in itertools.product(ciphertexts, range(256)):
        decrypted = hex_xor(c, k)
        try:
            decrypted_str = bytes_to_str(decrypted)
        except UnicodeDecodeError:
            continue

        score = get_score(decrypted_str)

        if score >= minimum:
            candidates.append((hex(k), c, score, decrypted_str))

    return sorted(candidates, key=lambda x: x[2], reverse=True)

with open('./challenge-data/4.txt') as f:
    ciphertexts = [l.strip() for l in f.readlines()]

candidates = find_candidates(ciphertexts, minimum=5)

print('Possible keys:')
print('*' * 80)

Candidate = namedtuple('Candidate', 'key ciphertext score plaintext')

for candidate in candidates:
    c = Candidate(*candidate)
    print(f"{bytes(c.plaintext.encode())}\n\t{c.key}\t{c.ciphertext}\t{c.score}\n")
