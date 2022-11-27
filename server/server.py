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


    with open("keys/server_public.pem", "r") as f:
        server_pub = RSA.import_key(f.read())

    with open("keys/server_private.pem", "r") as f:
        server_priv = RSA.import_key(f.read())


    #Server port
    serverPort = 12047

    serverSocket = create_socket(serverPort)

    #The server can only have one connection in its queue waiting for acceptance
    serverSocket.listen(5)

    while 1:
        try:
            #Server accepts client connection
            connectionSocket, addr = serverSocket.accept()
            #print(addr,'   ',connectionSocket)
            pid = os.fork()

            # If it is a client process
            if  pid== 0:

                serverSocket.close()

                #Recieve Username and Password
                login = connectionSocket.recv(2048)
                login = priv_decrypt(login, server_priv)
                login = login.split('\n')
                user_name = login[0]
                pswrd = login[1]

                #Compare against Json
                with open("user_pass.json", "r") as f:
                    user_pass = json.load(f)

                #Compare given user_name and password with json file
                if (user_name in user_pass and user_pass[user_name] == pswrd):
                    #Get users public key
                    with open("keys/" + user_name + "_public.pem", "rb") as f:
                        user_pub = RSA.import_key(f.read())

                    #Generate, encrypt and send symmetric key
                    sym_key = get_random_bytes(16)
                    sym_key_en = pub_encrypt(sym_key, user_pub, False)
                    connectionSocket.send(sym_key_en)

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

                #Main menu loop
                while 1:

                    #Send menu
                    connectionSocket.send(menu_text_en)

                    #Recieve user choice
                    choice_en = connectionSocket.recv(2048)
                    choice = sym_decrypt(choice_en, sym_key)
                    print(choice)

                    if (choice == "1"): #send
                        send_email(sym_key, connectionSocket)
                        print("done", flush=True) #TODO delete
                    elif (choice == "2"): #get list
                        pass
                    elif (choice == "3"): #open email
                        pass
                    elif (choice == "4"): #end connection
                        break
                    else: #loop
                        pass



                #End of main loop, close connection and return
                connectionSocket.close()
                return

            #Is parent process, close connection, keep serverSocket open
            connectionSocket.close()

        except socket.error as e:
            print('An error occured:',e)
            serverSocket.close()
            sys.exit(1)
        except Exception as e:
            print('Goodbye', e)
            serverSocket.close()
            sys.exit(0)


    #End server function, close sockets
    if pid != 0:
        serverSocket.close()
        return


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
        message = message.encde('ascii')
    enc_data = cipher_rsa_en.encrypt(message)
    return(enc_data)

#Takes a public encrypted binary and a private key and returns a Decrypted string
def priv_decrypt(message, key, string = True):
    cipher_rsa_dec = PKCS1_OAEP.new(key)
    dec_data = cipher_rsa_dec.decrypt(message)
    if string:
        dec_data = dec_data.decode('ascii')
    return (dec_data)


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

#Recieves email from client and creates Email class object from data
def send_email(sym_key, connectionSocket):

    #Recieve expected size or entire encrypted email
    size = connectionSocket.recv(2048)
    size = sym_decrypt(size, sym_key)
    print("the data is sending currently 1", flush=True)
    sys.stdout.flush()
    #Recieve formatted email string
    data = connectionSocket.recv(2048) #crashes!!!!!!!!!!!!!!!!!!!!!!!

    print("the data is sending currently 2", flush=True)
    sys.stdout.flush()
    #While size of data recieved is less than expected, recieve more data
    while (len(data) < int(size)):
        data += connectionSocket.recv(2048)
    print("stuck at the receiving end", flush=True)
    sys.stdout.flush()
    #Decrypt recieved data to string
    header = sym_decrypt(data, sym_key)
    #Split string on \n character
    header_split = header.split('\n')

    #Create new email object based on hard coded order in header string
    email = Email()
    email.from_user = header_split[0][6:]
    email.to_user = header_split[1][4:]
    email.title = header_split[3][7:]
    #Dont have to send length with whole email - Maybe send before
    email.content_length = size

    email.content = ''.join(header_split[5:])[9:]

    #Add recieved date and time
    email.date = datetime.datetime.now()

    print(f"done with the print\n\nseems to be stuck here??", flush=True)
    sys.stdout.flush()


    print(str(email), flush=True)
    return email

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
        return f"From: {self.from_user}\nTo: {self.to_user}\nDate: {str(self.date)}\nTitle: {self.title}\nContent Length: {self.content_length}\nContent: {self.content}"

    def __repr__(self):
        return f"From: {self.from_user}\nTo: {self.to_user}\nDate: {str(self.date)}\nTitle: {self.title}\nContent Length: {self.content_length}\nContent: {self.content}"

#-------
main()
