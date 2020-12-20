import codecs
import base64
import itertools
import statistics

def int_to_bin(i):
    return bin(i)[2:]

def str_to_bin(s):
    return int_to_bin(str_to_int(s))

def str_to_int(s):
    return int(codecs.encode(s.encode(), 'hex'), 16)

def hamming(s1, s2):
    assert len(s1) == len(s2)
    s1i = str_to_int(s1)
    s1b = str_to_bin(s1)
    s2i = str_to_int(s2)

    diff = int_to_bin(s1i ^ s2i).rjust(len(s1b), '0')
    return diff.count('1')

def consume_str(it, n):
    # Consume exactly n elements or return None if not enough elements
    elems = list(itertools.islice(it, n))
    if len(elems) != n:
        return None

    return ''.join(elems)

def find_key_length_candidates(ciphertext, n, min=2, top=3):
    avg_distances = []

    for i in range(min, n + 1):
        # Calcualte hamming distance average for all pairs of consecutive i-size blocks
        ciphertext_str = ciphertext.decode()
        block_iter = iter(ciphertext_str)
        first = consume_str(block_iter, i)
        second = consume_str(block_iter, i)
        
        distances = []
        while None not in [first, second]:
            distances.append(hamming(first, second) / i)
            first = consume_str(block_iter, i)
            second = consume_str(block_iter, i)

        avg_distances.append((i, statistics.mean(distances)))
    candidates = sorted(avg_distances, key=lambda distance: distance[1])[:top]
    return [c[0] for c in candidates]

def get_score(s):
    english_frequencies = {
        ' ': 14, # Just has to be higehr than everything else
        'a': 8.167,
        'b': 1.492,
        'c': 2.782,
        'd': 4.253,
        'e': 12.70,
        'f': 2.228,
        'g': 2.015,
        'h': 6.094,
        'i': 6.966,
        'j': 0.153,
        'k': 0.772,
        'l': 4.025,
        'm': 2.406,
        'n': 6.749,
        'o': 7.507,
        'p': 1.929,
        'q': 0.095,
        'r': 5.987,
        's': 6.327,
        't': 9.056,
        'u': 2.758,
        'v': 0.978,
        'w': 2.360,
        'x': 0.150,
        'y': 1.974,
        'z': 0.074,
    }

    score = 0
    for c in s.lower():
        if c in english_frequencies:
            score += english_frequencies[c]
    return score

def find_single_candidates(ciphertext, top=3):
    scores = []
    for key in range(1, 256):
        raw = bytearray([c ^ key for c in ciphertext])
        try:
            decrypted_str = raw.decode()
        except UnicodeDecodeError:
            continue

        score = get_score(decrypted_str)
        scores.append((chr(key), score))

    candidates = sorted(scores, key=lambda score: score[1], reverse=True)[:top]
    return [c[0] for c in candidates]

def find_key_candidates(ciphertext, key_length, top=3):
    columns = [ciphertext[i::key_length] for i in range(key_length)]
    single_candidates = [find_single_candidates(column, top=top) for column in columns]
    keys = [''.join(key) for key in zip(*single_candidates)]

    return keys

def find_keys(ciphertext, key_lengths, keys_per_length=3):
    key_candidates = []
    for key_length in key_lengths:
        key_candidates.extend(find_key_candidates(ciphertext, key_length, top=keys_per_length))

    return key_candidates

def xor(ciphertext, key):
    key_iter = itertools.cycle(codecs.encode(key))
    raw_line = bytearray([c ^ next(key_iter) for c in ciphertext])
    return raw_line.decode()

def try_keys(ciphertext, keys, minimum=3, top=3):
    scores = []
    for key in keys:
        try:
            decrypted_str = xor(ciphertext, key)
        except UnicodeDecodeError:
            print('error')
            continue
        score = get_score(decrypted_str)

        if score >= minimum:
            key_hex = codecs.encode(key.encode(), 'hex')
            scores.append((key, score, decrypted_str))

    candidates = sorted(scores, key=lambda score: score[1], reverse=True)[:top]
    return candidates
    

def main(ciphertext):
    key_lengths = find_key_length_candidates(ciphertext, 40)
    keys = find_keys(ciphertext, key_lengths)
    plaintexts = try_keys(ciphertext, keys, minimum=1, top=3)
    for p in plaintexts:
        print(f'Key: "{p[0]}", Score: {p[1]}, Decrypt attempt: ')
        print('-' * 100)
        print(p[2])
        print('*' * 100)

if __name__ == '__main__':
    with open('./challenge-data/6.txt', 'r') as f:
        file_contents = f.read()
        ciphertext = base64.b64decode(file_contents)

    main(ciphertext)
