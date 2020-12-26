import os
import random
import itertools
import base64
from collections import Counter

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

UNKNOWN_STRING = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')

KEY = os.urandom(16)

def consume_bytes(it, n):
    it = iter(it)
    elems = list(itertools.islice(it, n))
    
    while elems:
        yield bytes(elems)
        elems = list(itertools.islice(it, n))

def encrypt_aes_ecb_128(plaintext, key):
    assert len(key) == 16
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def pad(input, block_size):
    # PKCS#7 Padding
    array = bytearray(input)
    n = block_size - (len(array) % block_size)
    array.extend([n] * n)
    return array

def xor(block1, block2):
    assert len(block1) == len(block2)
    return bytes([a ^ b for a, b in zip(block1, block2)])

def encrypt_aes(plaintext, key):
    padded = pad(plaintext, 16)
    ciphertext = bytearray()

    for block in consume_bytes(padded, 16):
        ciphertext_block = encrypt_aes_ecb_128(block, key)
        ciphertext.extend(ciphertext_block)

    return ciphertext

def encryption_oracle(plaintext, encoded=False):
    if encoded:
        return encrypt_aes(plaintext + UNKNOWN_STRING, KEY)
    else:
        return encrypt_aes(plaintext.encode() + UNKNOWN_STRING, KEY)

def determine_block_size():
    for i in range(1, 33):
        plaintext = 'a' * i * 3 # Make 3 identical blocks of size i
        ciphertext = encryption_oracle(plaintext)
        block_iter = iter(ciphertext[::i])

        # If we have 3 identical characters at the beginning of 
        # our guessed block length, then we've found the block length
        if next(block_iter) == next(block_iter) == next(block_iter):
            return i

def detect_ecb():
    # Ensure that at least 4 16 byte blocks are exactly the same.
    plaintext = 'x' * 64
    ciphertext = encryption_oracle(plaintext)
    counter = Counter(consume_bytes(ciphertext, 16))
    dups = {k: v for k,v in counter.items() if v >= 4}

    if dups:
        print(dups)
        return True

    return False

def decrypt_secret(block_size):
    import codecs
    secret = bytearray()
    complete = False
    block_to_compare = 0

    while not complete:
        for i in range(block_size - 1, -1, -1):
            # Grab the last block_size - 1 chars from secret and pad if not enough chars
            rainbow_prefix = secret[-(block_size - 1):].zfill(block_size - 1)
            rainbow = {}

            for j in range(256):
                plaintext_block = rainbow_prefix + bytes([j])
                ciphertext_block = encryption_oracle(plaintext_block, encoded=True)[:block_size]
                rainbow[str(ciphertext_block)] = j
            
            block_start = block_size * block_to_compare
            block_end = block_start + block_size
            padding = bytes().zfill(i)

            ciphertext = encryption_oracle(padding, encoded=True)
            ciphertext_block = ciphertext[block_start:block_end]

            # If we hit the trailing padding, we're done
            match = rainbow[str(ciphertext_block)]
            if match == 1:
                complete = True
                break
            else:
                print(chr(match), end='')
                secret.append(match)

        block_to_compare += 1

    return secret

if __name__ == '__main__':
    is_ecb = detect_ecb()
    print(f'Is AES ECB: {is_ecb}')

    block_size = determine_block_size()
    print(f'Block size: {block_size}')

    print('Decrypting secret:')
    print('-' * 50)
    decrypt_secret(block_size)
    # print(secret.decode())
