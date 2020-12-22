
def pkcs7(input, block_size):
    array = bytearray(input)
    n = block_size - (len(array) % block_size)
    array.extend([n] * n)
    return array

if __name__ == '__main__':
    input = 'YELLOW SUBMARINE'
    print(pkcs7(input.encode(), 20))
