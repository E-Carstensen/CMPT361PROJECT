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
        message = connectionSocket.recv(2048).decode('ascii')
        
        #Client send message to the server
        message = input(message).encode('ascii')
        connectionSocket.send(message)
        
        # Client receives a message from the server and print it
        message = connectionSocket.recv(2048)
        print(message.decode('ascii'))
        
        # Client terminate connection with the server
        connectionSocket.close()
        
    except socket.error as e:
        print('An error occured:',e)
        connectionSocket.close()
        sys.exit(1)

#----------
client()