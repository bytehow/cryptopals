import itertools
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = 'YELLOW SUBMARINE'
IV = bytes([0] * 16)

def encrypt_aes_ecb_128(plaintext, key):
    assert len(key) == 16
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def decrypt_aes_ecb_128(plaintext, key):
    assert len(key) == 16
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(plaintext) + decryptor.finalize()

def consume_bytes(it, n):
    it = iter(it)
    elems = list(itertools.islice(it, n))
    
    while elems:
        yield bytes(elems)
        elems = list(itertools.islice(it, n))

def encrypt_aes_cbc(plaintext, key, iv):
    ciphertext = bytearray()
    padded = pad(plaintext, 16)

    prev = iv
    for block in consume_bytes(padded, 16):
        combined = xor(prev, block)
        ciphertext_block = encrypt_aes_ecb_128(combined, key)
        ciphertext.extend(ciphertext_block)
        prev = ciphertext_block

    return ciphertext

def decrypt_aes_cbc(ciphertext, key, iv):
    plaintext = bytearray()

    prev = iv
    for block in consume_bytes(ciphertext, 16):
        combined = decrypt_aes_ecb_128(block, key)
        plaintext_block = xor(prev, combined)
        plaintext.extend(plaintext_block)
        prev = block

    return unpad(plaintext)

def xor(block1, block2):
    assert len(block1) == len(block2)
    return bytes([a ^ b for a, b in zip(block1, block2)])

def pad(input, block_size):
    # PKCS#7 Padding
    array = bytearray(input)
    n = block_size - (len(array) % block_size)
    array.extend([n] * n)
    return array

def unpad(input):
    array = bytearray(input)
    n = array[-1]
    return array[:-n]

if __name__ == '__main__':
    with open('./challenge-data/10.txt', 'r') as f:
        ciphertext = base64.b64decode(f.read())

    plaintext = decrypt_aes_cbc(ciphertext, KEY.encode(), IV)
    print(plaintext.decode())
