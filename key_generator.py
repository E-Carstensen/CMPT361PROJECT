#Project 361 group 6, Samuel Brownlee, Eric Carstensen, Simon Gordon, Evan Stewart
#key generator.py

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
import sys
import os, glob, datetime
import socket

#random key generator for private and public
key1 = RSA.generate(2048)
key2 = RSA.generate(2048)
key3 = RSA.generate(2048)
key4 = RSA.generate(2048)
key5 = RSA.generate(2048)
key6 = RSA.generate(2048)

if key1 == key2:
    print("thye are teh same")

#public/private key gen

#server
pub_key_ser = key1.publickey()
pri_key_ser = key1

f = open('server_public.pem','wb')
f.write(pub_key_ser.exportKey('PEM'))
f.close()

f = open('server_private.pem','wb')
f.write(pri_key_ser.exportKey('PEM'))
f.close()


#client1
pub_key_cli1 = key2.publickey()
pri_key_cli1 = key2

f = open('client1_public.pem','wb')
f.write(pub_key_cli1.exportKey('PEM'))
f.close()

f = open('client1_private.pem','wb')
f.write(pri_key_cli1.exportKey('PEM'))
f.close()


#client2
pub_key_cli2 = key3.publickey()
pri_key_cli2 = key3

f = open('client2_public.pem','wb')
f.write(pub_key_cli2.exportKey('PEM'))
f.close()

f = open('client2_private.pem','wb')
f.write(pri_key_cli2.exportKey('PEM'))
f.close()


#client3
pub_key_cli3 = key4.publickey()
pri_key_cli3 = key4

f = open('client3_public.pem','wb')
f.write(pub_key_cli3.exportKey('PEM'))
f.close()

f = open('client3_private.pem','wb')
f.write(pri_key_cli3.exportKey('PEM'))
f.close()


#client4
pub_key_cli4 = key5.publickey()
pri_key_cli4 = key5

f = open('client4_public.pem','wb')
f.write(pub_key_cli4.exportKey('PEM'))
f.close()

f = open('client4_private.pem','wb')
f.write(pri_key_cli4.exportKey('PEM'))
f.close()


#client5
pub_key_cli5 = key6.publickey()
pri_key_cli5 = key6

f = open('client5_public.pem','wb')
f.write(pub_key_cli5.exportKey('PEM'))
f.close()

f = open('client5_private.pem','wb')
f.write(pri_key_cli5.exportKey('PEM'))
f.close()
