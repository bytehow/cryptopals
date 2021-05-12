import os
import random
import itertools
import base64
import codecs
from collections import Counter

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pprint import pprint

UNKNOWN_STRING = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
MAX_RAND_PREFIX = 16 * 3 # Prefix can be as long as 3 blocks
RAND_PREFIX = codecs.encode(os.urandom(random.randint(1, MAX_RAND_PREFIX)), 'hex')
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

def encrypt_aes(plaintext, key):
    padded = pad(plaintext, 16)
    ciphertext = bytearray()

    for block in consume_bytes(padded, 16):
        ciphertext_block = encrypt_aes_ecb_128(block, key)
        ciphertext.extend(ciphertext_block)

    return ciphertext

def encryption_oracle(plaintext, encoded=False):
    if encoded:
        return encrypt_aes(RAND_PREFIX + plaintext + UNKNOWN_STRING, KEY)
    else:
        return encrypt_aes(RAND_PREFIX + plaintext.encode() + UNKNOWN_STRING, KEY)

def determine_block_size():
    for i in range(1, 33):
        matching_blocks = 2
        plaintext = bytes().zfill(i * (matching_blocks + 2)) # two blocks will be consumed by padding out prefix
        ciphertext = encryption_oracle(plaintext, encoded=True)

        # If we have at least matching_blocks matches, then we've found the block size
        probable_block_size = (i // 8 + 1) * 8
        counter = Counter(consume_bytes(ciphertext, probable_block_size))
        dups = {k: v for k,v in counter.items() if v >= matching_blocks}
        if dups:
            return probable_block_size

def determine_prefix_padding(block_size):
    # Figure out how much we need to pad random prefix before we get predicatble ciphertext block boundaries

    pad_len = 0
    while True:
        dummy = bytes().zfill((block_size * 2) + pad_len)
        # dummy = bytes([ord('A')] * (block_size * 2 + pad_len))
        ciphertext = encryption_oracle(dummy, encoded=True)

        blocks_iter = enumerate(consume_bytes(ciphertext, block_size))
        _, prev = next(blocks_iter, (None, None)) # Don't care about first block index
        i, curr = next(blocks_iter, (None, None))
        while curr:
            if prev == curr:
                return i + 1, dummy
            else:
                prev = curr
                i, curr = next(blocks_iter, (None, None))

        pad_len += 1

def detect_ecb():
    # Ensure that at least 4 16 byte blocks are exactly the same. One block might get
    # consumed by prefix as padding
    plaintext = 'x' * (5 * 16)
    ciphertext = encryption_oracle(plaintext)
    counter = Counter(consume_bytes(ciphertext, 16))
    dups = {k: v for k,v in counter.items() if v >= 4}

    if dups:
        return True

    return False

def decrypt_secret(block_size, block_to_compare, prefix_padding):
    secret = bytearray()
    complete = False
    rainbow_block_start = block_size * block_to_compare
    rainbow_block_end = rainbow_block_start + block_size

    # Within each block, cycle through all possible incomlpete blocks.
    # Each incomplete block length determines how many characters from
    # the secret string are pulled into the current incomlpete block.
    # Guess the last character of each incomplete block until all block_size characters
    # are known at block_to_compare. Then move on to block_to_compare += 1, and start again.
    while not complete:
        for i in range(block_size - 1, -1, -1):
            # Grab the last block_size - 1 chars from secret and pad if not enough chars
            rainbow_prefix = secret[-(block_size - 1):].zfill(block_size - 1)
            rainbow = {}

            for j in range(256):
                plaintext_block = prefix_padding + rainbow_prefix + bytes([j])
                ciphertext = encryption_oracle(plaintext_block, encoded=True)

                ciphertext_block = ciphertext[rainbow_block_start:rainbow_block_end]
                rainbow[str(ciphertext_block)] = j

            block_start = block_size * block_to_compare
            block_end = block_start + block_size
            padding = prefix_padding + bytes().zfill(i)
            ciphertext = encryption_oracle(padding, encoded=True)
            ciphertext_block = ciphertext[block_start:block_end]

            match = rainbow[str(ciphertext_block)]
            if match == 1:
                complete = True
                break
            else:
                # Print out each character without line buffering
                print(chr(match), end='', flush=True)
                secret.append(match)

        block_to_compare += 1


if __name__ == '__main__':
    is_ecb = detect_ecb()
    print(f'Is AES ECB: {is_ecb}')

    block_size = determine_block_size()
    print(f'Block size: {block_size}')

    start_block, prefix_padding = determine_prefix_padding(block_size)
    print(f'Prefix padding length: {len(prefix_padding)}')
    print(f'Starting block: {start_block}')

    print('Decrypting secret 🧐:')
    print('-' * 50)
    decrypt_secret(block_size, start_block, prefix_padding)
    print('-' * 50)
    print('Complete! 🙌')
