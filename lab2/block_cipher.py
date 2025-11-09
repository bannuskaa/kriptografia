import json

def xor(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b)])

def pad(padding:str, data: bytes, block_size: int) -> bytes:
    padding_len = (-len(data)) % block_size
    if padding == 'zero':
        return data + b"\x00" * padding_len
    elif padding == 'DES':
        return data + b"\x80" + b"\x00" * (padding_len -1)
    elif padding == 'SF':
        return data + bytes([padding_len] * padding_len)
    else:
        raise ValueError("Unknown padding type")

def unpad(padding:str, data: bytes, block_size: int) -> bytes:
    if padding == 'zero':
        return data.rstrip(b"\x00")
    elif padding == 'DES':
        i = len(data)-1
        while i >= 0 and data[i] == 0x00:
            i -= 1
        if i >= 0 and data[i] == 0x80:
            return data[:i]
    elif padding == 'SF':
        pad_len = data[-1]
        return data[:-pad_len] if 1 <= pad_len <= block_size and data[-pad_len:] == bytes([pad_len])*pad_len else data
    else:
        raise ValueError("Unknown padding type")

def encrypt_vigenere_bytes(data: bytes, key: bytes) -> bytes:
    ciphertext = bytearray()
    key_len = len(key)

    for i, byte in enumerate(data):
        key_byte = key[i % key_len]
        ciphertext.append((byte + key_byte) % 256)

    return bytes(ciphertext)


def decrypt_vigenere_bytes(data: bytes, key: bytes) -> bytes:
    plaintext = bytearray()
    key_len = len(key)

    for i, byte in enumerate(data):
        key_byte = key[i % key_len]
        plaintext.append((byte - key_byte) % 256)

    return bytes(plaintext)

def encrypt_des_bytes(data: bytes, key: bytes) -> bytes:
    key = key[:8]
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes")
    encrypted = bytearray()
    for i in range(0, len(data), 8):
        block = data[i:i+8]
        block = block.ljust(8, b"\0")
        encrypted_block = bytes([b ^ k for b, k in zip(block, key)])
        encrypted += encrypted_block
    return bytes(encrypted)

def decrypt_des_bytes(data: bytes, key: bytes) -> bytes:
    key = key[:8]
    return encrypt_des_bytes(data, key) 

def ecb_encrypt(data: bytes, vig_key , des_key , block_size: int, algorithm,_) -> bytes:
    encrypted = bytearray()
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        if algorithm == "Vigenere":
            encrypted += encrypt_vigenere_bytes(block, vig_key)
        elif algorithm == "DES":
            encrypted += encrypt_des_bytes(block, des_key)
    return bytes(encrypted)

def ecb_decrypt(data: bytes, vig_key , des_key , block_size: int,algorithm,_) -> bytes:
    decrypted = bytearray()
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        if algorithm == 'Vigenere':
            decrypted += decrypt_vigenere_bytes(block, vig_key)
        elif algorithm == 'DES':
            decrypted += decrypt_des_bytes(block, des_key)
    return bytes(decrypted)

def cbc_encrypt(data: bytes, vig_key , des_key , block_size: int,algorithm,iv_hex) -> bytes:
    out = bytearray()
    prev = iv_hex
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        x = xor(block, prev)
        if algorithm == 'Vigenere':
            c = encrypt_vigenere_bytes(x, vig_key)
        elif algorithm == 'DES':
            c = encrypt_des_bytes(x, des_key)
        out += c
        prev = c
    return bytes(out)

def cbc_decrypt(data: bytes, vig_key , des_key , block_size: int,algorithm,iv_hex) -> bytes:
    out = bytearray()
    prev = iv_hex
    for i in range(0, len(data), block_size):
        c = data[i:i+block_size]
        if algorithm == 'Vigenere':
            x = decrypt_vigenere_bytes(c, vig_key)
        elif algorithm == 'DES':
            x = decrypt_des_bytes(c, des_key)
        p = xor(x, prev)
        out += p
        prev = c
    return bytes(out)

def cfb_encrypt(data: bytes, vig_key , des_key , block_size: int,algorithm,iv_hex) -> bytes:
    out = bytearray()
    prev = iv_hex
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        if algorithm == 'Vigenere':
            x = encrypt_vigenere_bytes(prev, vig_key)
        elif algorithm == 'DES':
            x = encrypt_des_bytes(prev, des_key)
        c = xor(x,block)
        out += c
        prev = c
    return bytes(out)

def cfb_decrypt(data: bytes, vig_key , des_key , block_size: int,algorithm,iv_hex) -> bytes:
    out = bytearray()
    prev = iv_hex
    for i in range(0, len(data), block_size):
        c = data[i:i+block_size]
        if algorithm == 'Vigenere':
            x = encrypt_vigenere_bytes(prev, vig_key)
        elif algorithm == 'DES':
            x = encrypt_des_bytes(prev, des_key)
        p = xor(x, c)
        out += p
        prev = c
    return bytes(out)

def ofb_encrypt(data: bytes, vig_key , des_key , block_size: int, algorithm, iv: bytes) -> bytes:
    out = bytearray()
    feedback = iv
    for i in range(0, len(data), block_size):
        if algorithm == 'Vigenere':
            keystream = encrypt_vigenere_bytes(feedback, vig_key)
        elif algorithm == 'DES':
            keystream = encrypt_des_bytes(feedback, des_key)
        block = data[i:i+block_size]
        out += xor(keystream[:len(block)], block)
        feedback = keystream  
    return bytes(out)

def ctr_encrypt(data: bytes , vig_key , des_key , block_size: int, algorithm, iv: bytes) -> bytes:
    out = bytearray()
    n = int.from_bytes(iv, "big") 
    for i in range(0, len(data), block_size):
        n_block = n.to_bytes(block_size, "big", signed=False)[-block_size:]
        if algorithm == 'Vigenere':
            e = encrypt_vigenere_bytes(n_block, vig_key)
        elif algorithm == 'DES':
            e = encrypt_des_bytes(n_block, des_key)
        block = data[i:i+block_size]
        c = xor(e[:len(block)], block)
        out += c
        n += 1
    return bytes(out)

def read_file(filename) -> bytes:
    with open(filename, "rb") as f:
        return f.read()  

def read_config(config_filename):   
    with open(config_filename, "r") as f:
        config = json.load(f)

    block_size = config["block_size_bits"]
    algorithm = config["algorithm"]
    mode = config["mode"]
    vig_key = config["vig_key"]
    des_key = config["des_key"]
    iv_hex = config["iv_hex"]
    padding = config["padding"] 
    input_file = config["input_file"]
    output_file = config["output_file"]

    return block_size, algorithm, mode, vig_key,des_key, iv_hex, padding, input_file, output_file

def main():
    with open("example.txt", "w") as f:
        f.write("Hello, this is a test file for encryption!\n")
        f.write("It contains multiple lines and symbols: 1234567890 !@#$%^&*()")

    block_size, algorithm, mode, vig_key, des_key, iv_hex, padding, input_file, output_file = read_config("block_cipher_config.json")
    data = read_file(input_file)
    vig_key = bytes.fromhex(vig_key)  
    des_key = bytes.fromhex(des_key)  
    iv_hex = bytes.fromhex(iv_hex)

    encrypt_functions = {
        "ECB": ecb_encrypt,
        "CBC": cbc_encrypt,
        "CFB": cfb_encrypt,
        "OFB": ofb_encrypt,
        "CTR": ctr_encrypt
    }

    decrypt_functions = {
        "ECB": ecb_decrypt,
        "CBC": cbc_decrypt,
        "CFB": cfb_decrypt,
        "OFB": ofb_encrypt,
        "CTR": ctr_encrypt
    }

    encrypt_func = encrypt_functions[mode]
    decrypt_func = decrypt_functions[mode]

    data = pad(padding, data, block_size)
    encrypted_data = encrypt_func(data, vig_key , des_key , block_size, algorithm, iv_hex)
     
    decrypted_data = unpad(padding, decrypt_func(encrypted_data, vig_key , des_key , block_size, algorithm, iv_hex) , block_size)
    with open(output_file , "wb") as f:
        f.write(decrypted_data)

main()
