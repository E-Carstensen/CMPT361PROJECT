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

    #Read server public key
    with open("keys/server_public.pem", "r") as f:
        server_pub = RSA.import_key(f.read())

    # Server Information
    serverName = '127.0.0.1' #'localhost'
    serverPort = 12020

    temp = input("Enter the server IP or name:")
    if (len(temp) != 0):
        serverName = temp


    #Create client socket that useing IPv4 and TCP protocols
    try:
        connectionSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:',e)
        sys.exit(1)

    try:
        #Client connect with the server
        connectionSocket.connect((serverName,serverPort))

        #Take, Format, encrypt, and send login info
        user_name = input("Enter your username: ")
        password = input("Enter your password: ")
        login = "\n".join((user_name, password))
        login_en = pub_encrypt(login, server_pub)
        connectionSocket.send(login_en)

        #Recieve encrypted symmetric key
        sym_key_en = connectionSocket.recv(2048)

        if (sym_key_en == "Invalid username or password".encode('ascii')):
            print("Invalid username or password")
            connectionSocket.close()
            return

        with open("keys/" + user_name + "_public.pem", "rb") as f:
            client_pub = RSA.import_key(f.read())

        with open("keys/" + user_name + "_private.pem", "rb") as f:
            client_priv = RSA.import_key(f.read())


        sym_key = priv_decrypt(sym_key_en, client_priv, False)

        #Main menu loop
        while 1:
            # Client receives a message and send it to the client
            message = connectionSocket.recv(2048)

            message = sym_decrypt(message, sym_key)

            print(message)





        # Client terminate connection with the server
        connectionSocket.close()

    except socket.error as e:
        print('An error occured:',e)
        connectionSocket.close()
        sys.exit(1)






#Takes a string and returns a symetric encrypted binary
def sym_encrypt(message, key, string = True):
    #Generate cipher block
    cipher = AES.new(key, AES.MODE_ECB)
    # Encrypt the message
    if string:
        message = message.encode('ascii')
    ct_bytes = cipher.encrypt(pad(message,16))
    return ct_bytes

#Takes an encrypted binary and returns a Decrypted string
def sym_decrypt(message, key, string = True):
    cipher = AES.new(key, AES.MODE_ECB)
    Padded_message = cipher.decrypt(message)
    #Remove padding
    Encodedmessage = unpad(Padded_message,16)
    if string:
        Encodedmessage = Encodedmessage.decode('ascii')
    return (Encodedmessage)

#Takes a string and a public key returns a public encrypted binary
def pub_encrypt(message, key, string = True):
    cipher_rsa_en = PKCS1_OAEP.new(key)
    if string:
        message = message.encode('ascii')
    enc_data = cipher_rsa_en.encrypt(message)
    return(enc_data)

#Takes a public encrypted binary and a private key and returns a Decrypted string
def priv_decrypt(message, key, string = True):
    cipher_rsa_dec = PKCS1_OAEP.new(key)
    dec_data = cipher_rsa_dec.decrypt(message)
    if string:
        dec_data = dec_data.decode('ascii')
    return (dec_data)

class Email:
    from_user = str
    to_user = str
    date = datetime.datetime
    title = str
    content_length = int
    content = str

    def __init__(self, from_user:str, to_user:str, date:datetime.datetime, title:str, content_length:str, content:str):
        self.from_user = from_user
        self.to_user = to_user
        self.date = date
        self.title = title
        self.content_length = content_length
        self.content = content

    def __str__(self):
        return f"From: {self.from_user}\nTo: {self.to_user}\nDate: {self.date}\nTitle: {self.title}\nContent Length: {self.content_length}\nContent: {self.content}"

    def __repr__(self):
        return f"From: {self.from_user}\nTo: {self.to_user}\nDate: {self.date}\nTitle: {self.title}\nContent Length: {self.content_length}\nContent: {self.content}"

    def send_email():
        pass
        # TODO: Get length of the email
        # TODO: encrypt the length
        # TODO: send the length
        # TODO: store email as a string (i.e. self.__str__()) in a variable
        # TODO: encrypt the email string using the sym_encrypt() function
        # TODO: send the encrypted email to the server

#----------
client()
