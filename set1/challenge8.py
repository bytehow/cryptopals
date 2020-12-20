import itertools
import codecs

from base64 import b64decode
from collections import Counter

def consume_bytes(it, n):
    # Consume exactly n elements or stop if not enough elements
    it = iter(it)
    elems = list(itertools.islice(it, n))
    
    while len(elems) == n:
        yield bytes(elems)
        elems = list(itertools.islice(it, n))

def find_possible_aes_ecb_128(ciphertexts):
    candidates = []
    for ciphertext in ciphertexts:
        counter = Counter(consume_bytes(ciphertext, 16))
        dups = {k: v for k,v in counter.items() if v > 1}
        if dups:
            candidates.append(ciphertext)

    return candidates

if __name__ == '__main__':
    with open('./challenge-data/8.txt', 'r') as f:
        hex_ciphertexts = [l.strip() for l in f.readlines()]

    ciphertexts = [codecs.decode(l, 'hex') for l in hex_ciphertexts]
    candidates = find_possible_aes_ecb_128(ciphertexts)

    assert len(candidates) == 1, 'Found multiple candidates'
    print(candidates[0])
