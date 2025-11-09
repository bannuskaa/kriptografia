import os
import pytest
from block_cipher import *

TEST_FILE = 'aurela-redenica-RzepwUMbDps-unsplash.jpg'  
BLOCK_SIZE_BITS = 64 
BLOCK_SIZE = BLOCK_SIZE_BITS // 8
DES_KEY = b"12345678"    
VIG_KEY = b"41424344"  
IV = b"\x00" * BLOCK_SIZE 

def load_test_file():
    with open(TEST_FILE, "rb") as f:
        return f.read()

def run_test(mode_encrypt, mode_decrypt, algorithm):
    data = load_test_file()
    padded = pad("zero", data, BLOCK_SIZE)
    encrypted = mode_encrypt(padded, VIG_KEY,DES_KEY, BLOCK_SIZE, algorithm, IV)
    decrypted = mode_decrypt(encrypted,VIG_KEY,DES_KEY, BLOCK_SIZE, algorithm, IV)
    unpadded = unpad("zero", decrypted, BLOCK_SIZE)
    assert unpadded == data, f"Failed: {algorithm} mode test"

@pytest.mark.parametrize("mode_funcs, mode_name", [
    ((ecb_encrypt, ecb_decrypt), "ECB"),
    ((cbc_encrypt, cbc_decrypt), "CBC"),
    ((cfb_encrypt, cfb_decrypt), "CFB"),
    ((ofb_encrypt, ofb_encrypt),       "OFB"),
    ((ctr_encrypt, ctr_encrypt),       "CTR")
])

@pytest.mark.parametrize("algorithm", ["Vigenere", "DES"])

def test_modes(algorithm,  mode_funcs, mode_name):
    enc_func, dec_func = mode_funcs
    run_test(enc_func, dec_func, algorithm)

