import os
import re
import codecs
from urllib.parse import parse_qs, urlencode

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ID_BYTES = 4
KEY = os.urandom(16)

def parse_profile(encoded):
    parsed = parse_qs(encoded)
    for k, v in parsed.items():
        if isinstance(v, list) and len(v) == 1:
            parsed[k] = v[0]

    return { k.decode(): v.decode() for k,v in parsed.items() }

def encode_profile(profile):
    return urlencode(profile)


def profile_for(email):
    id = int.from_bytes(os.urandom(ID_BYTES), 'big')
    email = re.sub(r'[?&=]', '', email)

    profile = {
        'id': str(id),
        'email': email,
        'role': 'user'
    }

    return profile

def encrypt_aes_ecb_128(plaintext):
    cipher = Cipher(algorithms.AES(KEY), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def decrypt_aes_ecb_128(plaintext):
    cipher = Cipher(algorithms.AES(KEY), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(plaintext) + decryptor.finalize()

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

def encrypt(plaintext):
    padded = pad(plaintext.encode(), 16)
    encrypted =  encrypt_aes_ecb_128(padded)
    return codecs.encode(encrypted, 'hex')

def decrypt(hex_str):
    ciphertext = codecs.decode(hex_str, 'hex')
    decrypted = decrypt_aes_ecb_128(ciphertext)
    unpadded = unpad(decrypted)
    return unpadded

def main():
    orig = profile_for('byte@how?.com&hey=foo')
    print(f'Generated profile: {orig}')

    encoded = encode_profile(orig)
    print(f'Encoded profile: {encoded}')

    encrypted = encrypt(encoded)
    print(f'Encrypted profile: {encrypted}')

    decrypted = decrypt(encrypted)
    print(f'Decrypted: {decrypted}')

    parsed = parse_profile(decrypted)
    print(f'Parsed: {parsed}')

    print(f'Matched: {parsed == orig}')

if __name__ == '__main__':
    main()

