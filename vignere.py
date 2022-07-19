def Key_generator(plaintext, key):
     if len(plaintext) == len(key):
        return (key)
     else:
        append=len(plaintext) - len(key)
        for i in range(append):
           key=key+key[i % len(key)]
     #print(key)
     return (key)


def encryption(plaintext, key):
    encrypt_text1=""
    for i in range(len(plaintext)):
        val=(ord(plaintext[i]) + ord(key[i])) % 26
        val+=ord('A')
        encrypt_text1=encrypt_text1+(chr(val))
    return (encrypt_text1)


def decryption(cipher_text, key):
    plain_text=""
    for i in range(len(cipher_text)):
        val=(ord(cipher_text[i]) - ord(key[i]) + 26) % 26
        val+=ord('A')
        plain_text=plain_text+(chr(val))
    return (plain_text)


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