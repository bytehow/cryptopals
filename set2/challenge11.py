import os
import random
import itertools
from collections import Counter

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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

def encrypt_aes(plaintext, key, cbc_mode=True):
    with_noise = os.urandom(random.randint(5, 10)) + \
        plaintext + os.urandom(random.randint(5, 10))

    padded = pad(with_noise, 16)
    iv =  os.urandom(16)
    ciphertext = bytearray(iv)

    if cbc_mode:
        print('Encrypting with AES CBC')
        prev = iv
        for block in consume_bytes(padded, 16):
            combined = xor(prev, block)
            ciphertext_block = encrypt_aes_ecb_128(combined, key)
            ciphertext.extend(ciphertext_block)
            prev = ciphertext_block
    else:
        print('Encrypting with AES ECB')
        for block in consume_bytes(padded, 16):
            ciphertext_block = encrypt_aes_ecb_128(block, key)
            ciphertext.extend(ciphertext_block)

    return ciphertext

def encryption_oracle(plaintext):
    cbc_mode = bool(random.randint(0,1))
    key = os.urandom(16)
    return encrypt_aes(plaintext.encode(), key, cbc_mode=cbc_mode)

def detect_mode():
    # Ensure that at least 3 16 byte blocks are exactly the same.
    # The random noise will ruin alignment for first block
    # but the remaining blocks should still form at least 3 repeated
    # plaintext blocks
    plaintext = 'x' * 64
    ciphertext = encryption_oracle(plaintext)
    counter = Counter(consume_bytes(ciphertext, 16))
    dups = {k: v for k,v in counter.items() if v > 1}

    if dups:
        print('Detected AES ECB')
    else:
        print('Detected AES CBC')

if __name__ == '__main__':
    for i in range(5):
        detect_mode()
