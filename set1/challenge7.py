import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = 'YELLOW SUBMARINE'

def decrypt_aes_ecb_128(ciphertext, key):
    assert len(key) == 16
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


if __name__ == '__main__':
    with open('./challenge-data/7.txt', 'r') as f:
        ciphertext = base64.b64decode(f.read())

    plaintext = decrypt_aes_ecb_128(ciphertext, KEY.encode()).decode()
    print(plaintext)
