#Project 361 group 6, Samuel Brownlee, Eric Carstensen, Simon Gordon, Evan Stewart
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
    serverPort = 12049

    temp = input("Enter the server IP or name: ")
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

        #debug = True #DEBUG
        #if (debug):
        #    user_name = 'client1'
        #    password = 'password1'


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
            menu_text_en = connectionSocket.recv(2048)
            menu_text = sym_decrypt(menu_text_en, sym_key)
            choice = input(menu_text)
            while (choice not in ["1", "2", "3", "4"]):
                choice = input("Invalid input\n" + menu_text)
            choice_en = sym_encrypt(choice, sym_key)
            connectionSocket.send(choice_en)

            if (choice == "1"): #send emails
                email = create_email(user_name)
                email_en = sym_encrypt(str(email), sym_key)
                email.content_length = len(email_en)

                #email_en = sym_encrypt(str(email), sym_key)
                connectionSocket.send(sym_encrypt(str(email.content_length), sym_key))

                #confirm that they got the size, times the email sending better
                confirm = connectionSocket.recv(2048)
                confirm = sym_decrypt(confirm, sym_key)
                if (confirm == 'size OK'):

                    #send the email
                    connectionSocket.sendall(sym_encrypt(str(email), sym_key))
                    print("The message is sent to the server.")
                else:
                    print("failed to send email, No comfirm back")

            elif (choice == "2"): #list inbox
                view_inbox_subprotocol(connectionSocket, sym_key)
            elif (choice == "3"): #read email from list
                message = sym_decrypt(connectionSocket.recv(2048), sym_key)
                if message == "ERROR1":
                    print("Invalid selection. Inbox list not generated.\n")
                    connectionSocket.send(sym_encrypt("OK", sym_key))
                # Ask the user to enter the email to be read.
                # Send the name of the email to the server.
                else:
                    message = input(message)
                    connectionSocket.send(sym_encrypt(message, sym_key))
                    # Receive size of email from server.
                    size = sym_decrypt(connectionSocket.recv(2048), sym_key)
                    if size == "ERROR2":
                        print("Invalid selection. View inbox for accepted options.\n")
                        connectionSocket.send(sym_encrypt("OK", sym_key))
                    else:
                        connectionSocket.send(sym_encrypt("OK", sym_key))
                        #Recieve formatted email string
                        data = connectionSocket.recv(2048)

                        #Receive data until it equals size.
                        while (len(data) < int(size)):
                            data += connectionSocket.recv(2048)
                        # Print the entire email gathered in data. thanks to newline, I can
                        # print the entire email in just one print statements. newlines added
                        # to match the formatting on the assignment document. See page 9.
                        print("\n" + sym_decrypt(data, sym_key) + "\n")


            elif (choice == "4"): #end connection
                print("The connection is terminated with the server.")
                break
            else:
                #loop
                pass

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

#Returns Email class item with variable filled
def create_email(sender):

    email = Email()

    email.from_user = sender
    email.to_user = input("Enter destinations (separated by ;): ")
    email.title = input("Enter title: ")
    load_file = input("Would you like to load contents from a file?(Y/N) ")
    while (load_file.lower() != 'n' and load_file.lower() != "y"):
        load_file = input("Would you like to load contents from a file?(Y/N) ")

    if (load_file.lower() == 'n'):
        email.content = input("Enter message contents: ")
    else:
        file_name = input("Enter filename: ")
        try:
            with open(sender + "/" + file_name, 'r') as f:
                email.content = f.read()
        except:
            print("Invailid File Name")
            return

    email.content_length = len(str(email.content))
    return email

def view_inbox_subprotocol(connectionSocket: socket.socket, sym_key: bytes):
    #Recieve inbox size
    inbox_size_en = connectionSocket.recv(2048)
    inbox_size = sym_decrypt(inbox_size_en, sym_key)
    inbox_size = int(inbox_size)

    #Send confirmation
    connectionSocket.send(sym_encrypt("size OK", sym_key))

    #Recieve inbox
    inbox_en = connectionSocket.recv(2048)

    #Keep recieving all bytes
    while (len(inbox_en) < inbox_size):
        inbox_en += connectionSocket.recv(2048)

    inbox = sym_decrypt(inbox_en, sym_key)
    print(inbox)

class Email:
    from_user = str
    to_user = str
    date = datetime.datetime
    title = str
    content_length = int
    content = str
# from_user:str, to_user:str, date:datetime.datetime, title:str, content_length:str, content:str
    def __init__(self):
        #self.from_user = from_user
        #self.to_user = to_user
        #self.date = date
        #self.title = title
        #self.content_length = content_length
        #self.content = content
        pass

    def __str__(self):
        return f"From: {self.from_user}\nTo: {self.to_user}\nDate: {self.date}\nTitle: {self.title}\nContent Length: {self.content_length}\nContent: {self.content}"

    def __repr__(self):
        return f"From: {self.from_user}\nTo: {self.to_user}\nDate: {self.date}\nTitle: {self.title}\nContent Length: {self.content_length}\nContent: {self.content}"



#----------
client()
