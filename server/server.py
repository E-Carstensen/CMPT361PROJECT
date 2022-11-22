# This is an example from "Computer Networking: A Top Down Approach" textbook chapter 2
# You can try this with nc localhost 12000


import json
import socket
import os,glob, datetime
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes


#
def main():

    with open("server_public.pem", "rb") as f:
        server_pub = f.read()

    with open("server_private.pem", "rb") as f:
        server_priv = f.read()


    #Server port
    serverPort = 12000

    serverSocket = create_socket(serverPort)

    #The server can only have one connection in its queue waiting for acceptance
    serverSocket.listen(5)

    while 1:
        try:
            #Server accepts client connection
            connectionSocket, addr = serverSocket.accept()
            print(addr,'   ',connectionSocket)
            pid = os.fork()

            # If it is a client process
            if  pid== 0:

                serverSocket.close()

                #Main action goes here
                while 1:
                    #
                    #Recieve Username and Password
                    login = connectionSocket.recv(2048)
                    login = priv_decrypt(login, server_pub)
                    login = login.split('\n')
                    user_name = login[0]
                    pswrd = login[1]

                    #Compare against Json
                    with open("user_pass.json", "r") as f:
                        user_pass = json.load(f)


                    if (user_name in user_pass and user_pass[user_name] == pswrd):
                        #Get users public key
                        with open(user_name + "_public.pem", "rb") as f:
                            user_pub = f.read()


                        sym_key = get_random_bytes(16)
                        connectionSocket.send(pub_encrypt(sym_key, user_pub))

                   #Else send unencrypted �Invalid username or password�, print info, and terminate
                    else:
                        connectionSocket.send("Invalid username or password".encode('ascii'))
                        print("The received clientinformation: [client_username] is invalid (ConnectionTerminated).")
                        connectionSocket.close()
                        return


                   #
                    menu_text = '''Select the operation:
    1) Create and send an email
    2) Display the inbox list
    3) Display the email contents
    4) Terminate the connection
choice: '''

                    menu_text_en = sym_encrypt(menu_text, sym_key)
                    connectionSocket.send(menu_text_en)


                    choice_en = connectionSocket.recv(2048)
                    choice = sym_decrypt(choice_en, sym_key)

                    if (choice == "1"):
                        pass
                    elif (choice == "2"):
                        pass
                    elif (choice == "3"):
                        pass
                    elif (choice == "4"):
                        pass
                    else:
                        pass


                    #TEST





                #End of main loop, close connection and return
                connectionSocket.close()
                return

            #Is parent process, close connection, keep serverSocket open
            connectionSocket.close()

        except socket.error as e:
            print('An error occured:',e)
            serverSocket.close()
            sys.exit(1)
        except:
            print('Goodbye')
            serverSocket.close()
            sys.exit(0)


    #End server function, close sockets
    if pid != 0:
        serverSocket.close()
        return


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



def create_socket(serverPort):
     #Create server socket that uses IPv4 and TCP protocols
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in server socket creation:',e)
        sys.exit(1)

    #Associate 12000 port number to the server socket
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print('Error in server socket binding:',e)
        sys.exit(1)

    print('The server is ready to accept connections')
    return serverSocket

#-------
main()
