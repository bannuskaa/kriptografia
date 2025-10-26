#!/usr/bin/env python3 -tt
"""
File: crypto.py
---------------
Assignment 1: Cryptography
Name: Bereczki Anna

"""
import utils
import random

# Caesar Cipher

def encrypt_caesar(plaintext,shift=3):
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            base = 'A' if char.isupper() else 'a'
            ciphertext += chr((ord(char) - ord(base) + shift) % 26 + ord(base))
        else:
            ciphertext += char
    return ciphertext

def decrypt_caesar(ciphertext,shift=3):
    return encrypt_caesar(ciphertext, - shift)

# Vigenere Cipher

def encrypt_vigenere(plaintext, keyword):
    ciphertext = ""
    keyword = keyword.lower()
    key_index = 0

    for char in plaintext:
        if char.isalpha():
            shift = ord(keyword[key_index % len(keyword)]) - ord('a')
            base = ord('A') if char.isupper() else ord('a')
            ciphertext += chr((ord(char) - base + shift) % 26 + base)
            key_index += 1
        else:
            ciphertext += char
    return ciphertext


def decrypt_vigenere(ciphertext, keyword):
    plaintext = ""
    keyword = keyword.lower()
    key_index = 0

    for char in ciphertext:
        if char.isalpha():
            shift = ord(keyword[key_index % len(keyword)]) - ord('a')
            base = ord('A') if char.isupper() else ord('a')
            plaintext += chr((ord(char) - base - shift) % 26 + base)
            key_index += 1
        else:
            plaintext += char
    return plaintext

# Merkle-Hellman Knapsack Cryptosystem

def generate_private_key(n=8):
    """Generate a private key for use in the Merkle-Hellman Knapsack Cryptosystem.

    Following the instructions in the handout, construct the private key components
    of the MH Cryptosystem. This consistutes 3 tasks:

    1. Build a superincreasing sequence `w` of length n
        (Note: you can check if a sequence is superincreasing with `utils.is_superincreasing(seq)`)
    2. Choose some integer `q` greater than the sum of all elements in `w`
    3. Discover an integer `r` between 2 and q that is coprime to `q` (you can use utils.coprime)

    You'll need to use the random module for this function, which has been imported already

    Somehow, you'll have to return all of these values out of this function! Can we do that in Python?!

    @param n bitsize of message to send (default 8)
    @type n int

    @return 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.
    """
    w = []
    w.append(random.randint(2,10))
    for _ in range(1,n):
        w.append(random.randint(sum(w)+1,2*sum(w)))
    
    q = random.randint(sum(w)+1,2*sum(w))

    r = random.randint(2,q-1)
    while not utils.coprime(r,q):
         r= random.randint(2,q-1)

    return (tuple(w), q, r)


def create_public_key(private_key):
    """Create a public key corresponding to the given private key.

    To accomplish this, you only need to build and return `beta` as described in the handout.

        beta = (b_1, b_2, ..., b_n) where b_i = r × w_i mod q

    Hint: this can be written in one line using a list comprehension

    @param private_key The private key
    @type private_key 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.

    @return n-tuple public key
    """
    (w, q, r) = private_key

    beta = tuple((r * w_i) % q for w_i in w)

    return beta

def encrypt_mh(message, public_key):
    """Encrypt an outgoing message using a public key.

    1. Separate the message into chunks the size of the public key (in our case, fixed at 8)
    2. For each byte, determine the 8 bits (the `a_i`s) using `utils.byte_to_bits`
    3. Encrypt the 8 message bits by computing
         c = sum of a_i * b_i for i = 1 to n
    4. Return a list of the encrypted ciphertexts for each chunk in the message

    Hint: think about using `zip` at some point

    @param message The message to be encrypted
    @type message bytes
    @param public_key The public key of the desired recipient
    @type public_key n-tuple of ints

    @return list of ints representing encrypted bytes
    """
    ciphertext = []
    for byte in message:
        bits = utils.byte_to_bits(byte)  
        c = sum(a_i * b_i for a_i, b_i in zip(bits, public_key))
        ciphertext.append(c)
    return ciphertext

def decrypt_mh(message, private_key):
    """Decrypt an incoming message using a private key

    1. Extract w, q, and r from the private key
    2. Compute s, the modular inverse of r mod q, using the
        Extended Euclidean algorithm (implemented at `utils.modinv(r, q)`)
    3. For each byte-sized chunk, compute
         c' = cs (mod q)
    4. Solve the superincreasing subset sum using c' and w to recover the original byte
    5. Reconsitite the encrypted bytes to get the original message back

    @param message Encrypted message chunks
    @type message list of ints
    @param private_key The private key of the recipient
    @type private_key 3-tuple of w, q, and r

    @return bytearray or str of decrypted characters
    """
    (w, q, r) = private_key 
    s=utils.modinv(r, q)

    og_message = []

    for c in message:
        c1 = (c*s) % q
        bits = []
        for w_i in reversed(w):
            if c1 >= w_i:
                bits.insert(0, 1)
                c1 -= w_i
            else:
                bits.insert(0, 0)
        value = 0
        for bit in bits:
            value = (value << 1) | bit
        og_message.append(value)  
    og_message = ''.join(chr(n) for n in og_message)
    return og_message 

def encrypt_scytale(plaintext, circumference = 5):
    ciphertext=""
    for i in range(circumference):
        j=i
        while j< len(plaintext):
            ciphertext += plaintext[j]
            j+=circumference
    return ciphertext

def decrypt_scytale(ciphertext, circumference = 5 ):
    plaintext=[''] * len(ciphertext)
    k=0
    for i in range(circumference):
        j=i
        while j< len(ciphertext):
            plaintext[j] = ciphertext[k]
            k += 1
            j+=circumference

    return ''.join(plaintext)

def encrypt_railfence(plaintext, num_rails = 3):
    if num_rails == 1:
        return plaintext
    rails = [''] * num_rails
    rail = 0
    direction = 1 
    for char in plaintext:
        rails[rail] += char
        rail += direction
        if rail == 0 or rail == num_rails - 1:
            direction *= -1 

    return ''.join(rails)

def decrypt_railfence(ciphertext, num_rails = 3):
    if num_rails == 1:
        return ciphertext

    pattern = []
    rail = 0
    direction = 1
    for _ in range(len(ciphertext)):
        pattern.append(rail)
        rail += direction
        if rail == 0 or rail == num_rails - 1:
            direction *= -1
    rail_lengths = [pattern.count(i) for i in range(num_rails)]
    rails = []
    index = 0
    for length in rail_lengths:
        rails.append(list(ciphertext[index:index+length]))
        index += length
    result = []
    for r in pattern:
        result.append(rails[r].pop(0))

    return ''.join(result)



        
