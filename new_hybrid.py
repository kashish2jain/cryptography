"""
Vigenere + RSA Algorithm

Authors: Kashish Jain & Swain Subrat Kumar
Date   : 17th October, 2021
"""
import gmpy2
import math
import random

from typing import List

from gmpy2 import mpz, powmod, is_strong_prp
from Crypto.Util import number

file_names = ["./keys/pa.txt", "./keys/qa.txt", "./keys/pb.txt", "./keys/qb.txt"]

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

    for  m in range(len(message)):
        c = (ord(message[m]) + ord(key[m])) % 26
        c = c + ord('A')
        cipher_text += (chr(c))
    
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

def coprime(phin: int):
    p=2
    while(mpz(p)!=mpz(phin)):
        if( 1==mpz(gmpy2.gcd(p, phin))):
            return p 
        p+=1

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
    #e=coprime(phi)
    
    e = random.randrange(1, mpz(phi))
    g = gmpy2.gcd(mpz(e), mpz(phi))
    while mpz(g) != 1:
        e = random.randrange(1, mpz(phi))
        g = gmpy2.gcd(mpz(e), mpz(phi))
 
    
    # d = modInverse(mpz(e), mpz(phi))
    # e = 65537
    d = gmpy2.divm(1, mpz(e), mpz(phi))

    return ((e, n), (d, n))

def make_block(column: str):
    retVal=0
    ichar=0
    col=column.upper()
    ichar=(len(col)-1)
    while (ichar >= 0):
        colPiece=col[ichar]
        colNum=int(ord(colPiece)) - 65
        retVal=retVal + colNum * ((int)(math.pow(26, len(col) - (ichar + 1))))
        ichar=ichar-1
    return retVal

def rsa_encrypt(key: tuple,  message: int) -> int:
    """
    Encrypt using RSA
    """
    e, n = key
    
    cipher = powmod(mpz(message), mpz(e), mpz(n)) 

    return cipher

def rsa_decrypt(key: tuple, cipher_text: int)-> int:
    """
    Decrypt using RSA
    """
    d, n = key
    plain_text = powmod(mpz(cipher_text), mpz(d), mpz(n)) 

    return plain_text

def dec_base(num,base):
    st=""
    while(mpz(num)!=0):
      val=mpz(num)%mpz(base)
      val=mpz(val)+mpz(65)
      
      st=chr(val)+st
      num=int(mpz(num)/mpz(base))
      if((num==0) and (len(st)!=5)):
        st='A'+st

    return st

def save_keys(pa, qa, pb, qb):
    vals = [pa, qa, pb, qb]

    for f, v in zip(file_names, vals):
        infile = open(f, "w")
        infile.write(str(v))

def load_keys():
    vals = []
    for f in file_names:
        infile = open(f, "r")
        vals.append(int(infile.read()))
    
    return vals[0], vals[1], vals[2], vals[3]

if __name__ == "__main__":
    plain_text = """
        kasishjainisnowonateamsmeetforthecolassignmentkasishjainisnowonateamsmeetforthecolassi
        gnmentkasishjainisnowonateamsmeetforthecolassignmentkasishjainisnowonateamsmeetforthec
        olassignmentkasishjainisnowonateamsmeetforthecolassignmentkasishjainisnowonateamsmeetf
        orthecolassignmentkasishjainisnowonateamsmeetforthecolassignmentkasishjainisnowonateam
        smeetforthecolassignmentkasishjainisnowonateamsmeetforthecolassignmentkasishjainisnowo
        nateamsmeetforthecolassignmentkasishjainisnowonateamsmeetforthecolassignmentkasishjain
        isnowonateamsmeetforthecolassignmentkasishjainisnowonateamsmeetforthecolassignmentkasi
        gnmentkasishjainisnowonateamsmeetforthecolassignmentkasishjainisnowonateamsmeetforthec
        olassignmentkasishjainisnowonateamsmeetforthecolassignmentkasishjainisnowonateamsmeetf
        orthecolassignmentkasishjainisnowonateamsmeetforthecolassignmentkasishjainisnowonateam
        smeetforthecolassignmentkasishjainisnowonateamsmeetforthecolassignmentkasishjainisnowo
        nateamsmeetforthecolassignmentkasishjainisnowonateamsmeetforthecolassignmentkasishjain
        isnowonateamsmeetforthecolassignmentshjainisnowonateamsmeetforthecolassi
    """
    plain_text=plain_text.replace(" ", "")
    plain_text=plain_text.upper()
    rem=gmpy2.t_mod(len(plain_text),5)
    if(rem!=0):
        for i in range((5-rem)):
            plain_text=plain_text+'Z'

    key = "seeyou"
    key=key.replace(" ", "")
    key=key.upper()

    # pa, qa = get_sp(), get_sp()
    # pb, qb = get_sp(), get_sp()

    # save_keys(pa, qa, pb, qb)
    pa, qa, pb, qb = load_keys()

    print(f"Actual message: {plain_text}")

    ############### VIGENERE CIPHER ###############
    key = vigenere_generate_key(plain_text, key)
    ck  = key
    print(f"V Crafted key: {key}")
    cipher_text2 = []
    key2         = []
    l=""
    cipher_text8 = vigenere_encrypt(plain_text, key)
    print(f"V Cipher text: {cipher_text8}")
    n=5
    stp=""
    stp1=""

    cipher_text1 = [cipher_text8[i:i+n] for i in range(0, len(cipher_text8), n)]
    key1 = [key[i:i+n] for i in range(0, len(key), n)]

    ##################### RSA #####################
    pka, ska = rsa_generate_key_pair(pa, qa)
    pkb, skb = rsa_generate_key_pair(pb,qb)

    for each,each1 in zip(cipher_text1,key1):
        cipher_text: int=make_block(each)
        key: int=make_block(each1)

        # print("C0:",cipher_text)
        p=cipher_text
    
        crypted_msg = rsa_encrypt(ska, cipher_text)
        crypted_key = rsa_encrypt(ska, key)
        # print("C1:",crypted_msg)

        C       = rsa_encrypt(pkb, crypted_msg)
        K_prime = rsa_encrypt(pkb, crypted_key)
        # print("C2:",C)

        crypted_msg = rsa_decrypt(skb, C)
        crypted_key = rsa_decrypt(skb, K_prime)
        # print("C3:",crypted_msg)

        cipher_text = rsa_decrypt(pka, crypted_msg)
        key         = rsa_decrypt(pka, crypted_key)
        # print("C4:",cipher_text)

        # stp = stp + dec_base(p, 26)
        stp = stp + dec_base(cipher_text, 26)
        
        #print("stp:",stp)

    print(stp)

    if(stp != cipher_text8):
        print("Not Equal")
    else:
        print("Equal")
    
    message = vigenere_decrypt(stp, ck)
    print(f"Plain text: {message}")

    if(plain_text != message):
        print("Not Equal")
    else:
        print("Equal")
