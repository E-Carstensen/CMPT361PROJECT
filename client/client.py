# This is an example from "Computer Networking: A Top Down Approach" textbook chapter 2
import json
import socket
import os, glob, datetime
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

#test comment
def client():
    # Server Information
    serverName = '127.0.0.1' #'localhost'
    serverPort = 12000

    #Create client socket that useing IPv4 and TCP protocols
    try:
        connectionSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:',e)
        sys.exit(1)

    try:
        #Client connect with the server
        connectionSocket.connect((serverName,serverPort))

        # Client receives a message and send it to the client
        message = connectionSocket.recv(2048)

        message = priv_decrypt(message, )

        # Client terminate connection with the server
        connectionSocket.close()

    except socket.error as e:
        print('An error occured:',e)
        connectionSocket.close()
        sys.exit(1)






#Takes a string and returns a symetric encrypted binary
def sym_encrypt(message, key):
    #Generate cipher block
    cipher = AES.new(key, AES.MODE_ECB)
    # Encrypt the message
    ct_bytes = cipher.encrypt(pad(message.encode('ascii'),16))
    return ct_bytes

#Takes an encrypted binary and returns a Decrypted string
def sym_decrypt(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    Padded_message = cipher.decrypt(message)
    #Remove padding
    Encodedmessage = unpad(Padded_message,16)
    return (Encodedmessage.decode('ascii'))

#Takes a string and a public key returns a public encrypted binary
def pub_encrypt(message, key):
    cipher_rsa_en = PKCS1_OAEP.new(key)
    enc_data = cipher_rsa_en.encrypt(message.encode('ascii'))
    return(enc_data)

#Takes a public encrypted binary and a private key and returns a Decrypted string
def priv_decrypt(message, key):
    cipher_rsa_dec = PKCS1_OAEP.new(key)
    dec_data = cipher_rsa_dec.decrypt(message)
    print(dec_data.decode('ascii'))



#----------
client()
