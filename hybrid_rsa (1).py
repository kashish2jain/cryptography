"""
Vigenere + RSA Algorithm

Authors: Kashish Jain & Swain Subrat Kumar
Date   : 17th October, 2021
"""
import gmpy2
import random

from typing import List

from gmpy2 import mpz, powmod, is_strong_prp
from Crypto.Util import number

def vigenere_generate_key(message: str, key: str) -> str:
    """
    To generate the entire key from the message
    
    Args:
    -----
    message(str): Plaintext message
    key(str)    : Key for encryption

    Returns:
    -------
    crafted_key: Key according to the message length
    """
    key = list(key)
    message_length = len(message)
    key_length = len(key)
    if message_length == key_length:
        return(key)
    else:
        for i in range(message_length -key_length):
            key.append(key[i % key_length])
    
    crafted_key = "".join(key)

    return crafted_key

def vigenere_encrypt(message: str, key: str) -> str:
    """
    To encrypt the message using vigenere cipher
    
    Args:
    -----
    message(str): Plaintext message
    key(str)    : Key for encryption

    Returns:
    -------
    cipher_text: Encrypted message
    """
    cipher_text = ""

    for k, m in zip(key, message):
        c = (ord(m) + ord(k)) % 26
        c = c + ord('A')
        cipher_text += chr(c)
    
    return cipher_text

def vigenere_decrypt(cipher: str, key: str) -> str:
    """
    To decrypt the cipher using vigenere cipher
    
    Args:
    -----
    cipher(str) : Cipher text
    key(str)    : Key for decryption

    Returns:
    -------
    message: Decrypted plain text
    """
    message = ""

    for k, c in zip(key, cipher):
        m = (ord(c) - ord(k) + 26) % 26
        m = m + ord('A')
        message += chr(m)
    
    return message

def get_sp(bits: int=1024):
    """
    Generate strong prime
    """
    while(True):
        p=number.getPrime(bits)
        if (is_strong_prp(p, 10)):
            return p

def rsa_generate_key_pair(p: int, q: int) -> tuple:
    """
    Generate key pair from p and q
    Args:
    ----
    p(int): first prime number
    q(int): second co-prime number

    Returns:
    ((e, n), (d, n)): key pair
    """
    # sanity check
    assert gmpy2.is_prime(p) and gmpy2.is_prime(q), "p and q must be prime"
    assert mpz(p) != mpz(q), "p and q must not be equal"

    n   = mpz(p) * mpz(q)
    phi = mpz(mpz(p) - 1) * mpz(mpz(q) - 1)

    e = random.randrange(1, mpz(phi))
    g = gmpy2.gcd(mpz(e), mpz(phi))
    while mpz(g) != 1:
        e = random.randrange(1, mpz(phi))
        g = gmpy2.gcd(mpz(e), mpz(phi))
    
    # d = modInverse(mpz(e), mpz(phi))
    # e = 65537
    d = gmpy2.divm(1, mpz(e), mpz(phi))

    return ((e, n), (d, n))

def rsa_encrypt(key: tuple, message: List[int]) -> List[int]:
    """
    Encrypt using RSA
    """
    e, n = key
    cipher = [powmod(char, mpz(e), mpz(n)) for char in message]

    return cipher

def rsa_decrypt(key: tuple, cipher_text: str):
    """
    Decrypt using RSA
    """
    d, n = key
    plain_text = [powmod(char, mpz(d), mpz(n)) for char in cipher_text]

    return plain_text


message = "GEEKSFORGEEKSXC"
key = "AYUSH"

pa, qa = get_sp(), get_sp()
pb, qb = get_sp(), get_sp()

# pa, qa = 17, 19
# pb, qb = 23, 37

print(f"Actual message: {message}")

############### VIGENERE CIPHER ###############
key = vigenere_generate_key(message, key)
print(f"V Crafted key: {key}")

cipher_text = vigenere_encrypt(message, key)
print(f"V Cipher text: {cipher_text}")

##################### RSA #####################
cipher_text = [ord(char) for char in cipher_text]
key         = [ord(char) for char in key]

pka, ska = rsa_generate_key_pair(pa, qa)
pkb, skb = rsa_generate_key_pair(pb, qb)

crypted_msg = rsa_encrypt(ska, cipher_text)
crypted_key = rsa_encrypt(ska, key)

C       = rsa_encrypt(pkb, crypted_msg)
K_prime = rsa_encrypt(pkb, crypted_key)

crypted_msg = rsa_decrypt(skb, C)
crypted_key = rsa_decrypt(skb, K_prime)

cipher_text = rsa_decrypt(pka, crypted_msg)
key         = rsa_decrypt(pka, crypted_key)

cipher_text = [chr(mpz(char) % 26) for char in cipher_text]
key         = [chr(mpz(char) % 26) for char in key]

message = vigenere_decrypt(cipher_text, key)
print(f"Plain text: {message}")
