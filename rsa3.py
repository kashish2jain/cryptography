import random

'''
Euclid's algorithm for determining the greatest common divisor
Use iteration to make it faster for larger integers
'''


def Key_generator(plaintext, key):
    if len(plaintext) == len(key):
        return (key)
    else:
        append=len(plaintext) - len(key)
        for i in range(append):
            key=key + key[i % len(key)]
    # print(key)
    return (key)


def encryption(plaintext, key):
    encrypt_text1=""
    for i in range(len(plaintext)):
        val=(ord(plaintext[i]) + ord(key[i])) % 26
        val+=ord('A')
        encrypt_text1=encrypt_text1 + (chr(val))
    return (encrypt_text1)


def decryption(cipher_text, key):
    plain_text=""
    for i in range(len(cipher_text)):
        val=(ord(cipher_text[i]) - ord(key[i]) + 26) % 26
        val+=ord('A')
        plain_text=plain_text + (chr(val))
    return (plain_text)




def gcd(a, b):
    while b != 0:
        a, b=b, a % b
    return a


'''
Euclid's extended algorithm for finding the multiplicative inverse of two numbers
'''


def modInverse(a, m):
    for x in range(1, m):
        if (((a % m) * (x % m)) % m == 1):
            return x
    return -1
def multiplicative_inverse(e, phi):
    d=0
    x1=0
    x2=1
    y1=1
    temp_phi=phi

    while e > 0:
        temp1=temp_phi / e
        temp2=temp_phi - temp1 * e
        temp_phi=e
        e=temp2

        x=x2 - temp1 * x1
        y=d - temp1 * y1

        x2=x1
        x1=x
        d=y1
        y1=y

    if temp_phi == 1:
        return d + phi


'''
Tests to see if a number is prime.
'''


def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num ** 0.5) + 2, 2):
        if num % n == 0:
            return False
    return True


def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
    # n = pq
    n=p * q

    # Phi is the totient of n
    phi=(p - 1) * (q - 1)

    # Choose an integer e such that e and phi(n) are coprime
    e=random.randrange(1, phi)

    # Use Euclid's Algorithm to verify that e and phi(n) are comprime
    g=gcd(e, phi)
    while g != 1:
        e=random.randrange(1, phi)
        g=gcd(e, phi)

    # Use Extended Euclid's Algorithm to generate the private key
    d=modInverse(e,phi)
    #d=multiplicative_inverse(e, phi)

    # Return public and private keypair
    # Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))


def encrypt(pk, plaintext):
    # Unpack the key into it's components
    key, n=pk
    # Convert each letter in the plaintext to numbers based on the character using a^b mod m


    cipher=[(ord(char) ** key) % n for char in plaintext]
    # Return the array of bytes
    return cipher

def dencrypt(pk, plaintext):
    # Unpack the key into it's components
    key, n=pk
    # Convert each letter in the plaintext to numbers based on the character using a^b mod m


    cipher=[(char ** key) % n for char in plaintext]
    # Return the array of bytes
    return cipher


def decrypt(pk, ciphertext):
    # Unpack the key into its components

    key, n=pk

    # Generate the plaintext based on the ciphertext and key using a^b mod m
    plain=[(char ** key) % n for char in ciphertext]
    # Return the array of bytes as a string
    return plain

def rdecrypt(pk, ciphertext):
    # Unpack the key into its components

    key, n=pk

    # Generate the plaintext based on the ciphertext and key using a^b mod m
    plain=[chr((char ** key) % n) for char in ciphertext]
    # Return the array of bytes as a string
    return ''.join(plain)
ptfilename=input("Enter name of Plain text input file: ")
inputfile=open(ptfilename, "r")
plain_text=inputfile.read();
plain_text=plain_text.replace(" ", "")
plain_text=plain_text.upper()
keyfilename=input("Enter name of key file: ")
keyfile=open(keyfilename, "r")
keyword=keyfile.read();
keyword=keyword.replace(" ", "")
keyword=keyword.upper()

key=Key_generator(plain_text, keyword)
cipher_text=encryption(plain_text, key)
print("Encrypted message:", cipher_text)
print("Decrypted message:", decryption(cipher_text, key))

#RSA PART
print ("RSA Encrypter/ Decrypter for sender")
p=int(input("Enter a prime number (17, 19, 23, etc): "))
q=int(input("Enter another prime number (Not one you entered above): "))
print("Generating your public/private keypairs now . . .")
spublic, sprivate=generate_keypair(p, q)
print ("RSA Encrypter/ Decrypter for receiver")
p=int(input("Enter a prime number (17, 19, 23, etc): "))
q=int(input("Enter another prime number (Not one you entered above): "))
print("Generating your public/private keypairs now . . .")
rpublic, rprivate=generate_keypair(p, q)
print("Your sender public and private  key is ")
print(spublic,sprivate)
print(" and reciever public and private key is ")
print( rpublic,rprivate)
#message=input("Enter a message to encrypt with your private key: ")







encrypted_msg=encrypt(sprivate, cipher_text)
kprime=encrypt(sprivate, key)
print(encrypted_msg)
print(kprime)
c=dencrypt(rpublic,encrypted_msg )
kpprime=dencrypt(rpublic,kprime)
print("Your encrypted message is: ")
print(''.join(map(lambda x: str(x), c)))
print("Your encrypted key is: ")
print(''.join(map(lambda x: str(x), kpprime)))
print("now c and kpprime has been send to receiver")
#print("Decrypting message with public key ", private, " . . .")
print("now started decrypting the message")
cprime=decrypt(rprivate,c)
kbar=decrypt(rprivate,kpprime)
#print(''.join(map(lambda x: str(x), cprime)))
#cprime=''.join(map(lambda x: str(x), cprime))
#print(''.join(map(lambda x: str(x), kbar)))
#kbar=''.join(map(lambda x: str(x), kbar))
print(cprime)
print(kbar)
clast=rdecrypt(spublic,cprime)
klast=rdecrypt(spublic,kbar)
print(clast)
print(klast)
msg=decryption(clast,klast)
print("Your  user given message is:")
print(msg)