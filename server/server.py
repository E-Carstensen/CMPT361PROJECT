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

                    print(f"Connection Accepted and Symmetric Key Generated for client: {user_name}")

               #Else send unencrypted �Invalid username or password�, print info, and terminate
                else:
                    connectionSocket.send("Invalid username or password".encode('ascii'))
                    print("The received clientinformation: [client_username] is invalid (ConnectionTerminated).")
                    connectionSocket.close()
                    return

               #menu text that is displayed to user after each input
                menu_text = '''Select the operation:
        1) Create and send an email
        2) Display the inbox list
        3) Display the email contents
        4) Terminate the connection

        choice: '''

                menu_text_en = sym_encrypt(menu_text, sym_key)

                #Main menu loop-------------------------------------------------
                while 1:

                    #Send menu
                    connectionSocket.send(menu_text_en)

                    #Recieve user choice
                    choice_en = connectionSocket.recv(2048)
                    choice = sym_decrypt(choice_en, sym_key)
                    #print(choice)

                    if (choice == "1"): #send
                        send_email(sym_key, connectionSocket)
                    elif (choice == "2"): #get list
                        pass
                    elif (choice == "3"): #open email
                        message = "Enter the email index you wish to view: "
                        connectionSocket.send(sym_encrypt(message, sym_key))
                        selection = sym_decrypt(connectionSocket.recv(2048), sym_key)
                        readEmailContents(user_name, selection, sym_key, connectionSocket)
                    elif (choice == "4"): #end connection
                        break
                    else: #loop
                        pass



                #End of main loop, close connection and return------------------
                print(f"Terminating connection with {user_name}")
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

    #confirm back to client TODO CHECK SIZE MAX
    confirm = "size OK"
    confirm = sym_encrypt(confirm, sym_key)
    connectionSocket.send(confirm)

    #Recieve formatted email string
    data = connectionSocket.recv(2048)

    #While size of data recieved is less than expected, recieve more data
    while (len(data) < int(size)):
        data += connectionSocket.recv(2048)

    #Decrypt recieved data to string
    header = sym_decrypt(data, sym_key)

    #Split string on \n character
    header_split = header.split('\n')

    #Create new email object based on hard coded order in header string
    email = Email()
    email.from_user = header_split[0][6:]
    email.to_user = header_split[1][4:]
    email.title = header_split[3][7:]
    email.content = ''.join(header_split[5:])[9:]
    email.content_length = len(str(email.content))
    #Add recieved date and time
    email.date = datetime.datetime.now()
    #server print
    print(f"An email from {str(email.from_user)} is sent to {str(email.to_user)} has a conent length of {str(email.content_length)} .")

    #making values to store the emails in their inboxes
    user_from = str(email.from_user)
    user_to = str(email.to_user)
    inboxes = user_to.split(";")
    title = str(email.title)
    directory = os.getcwd()
    for name in inboxes:
        path = os.path.join(directory+"/"+name)
        if (os.path.exists(path)): #check if there is a folder to send to
            full_path_name = os.path.join(path, user_from+"_"+title+".txt")
            email_string = str(email)
            with open(full_path_name, 'w') as f:
                f.write(email_string)

    return email

# This function for the time being takes the cleint name and email name, and reads and sends the contents to
# the client. The argument for 'clientName' will probably get removed when the "view inbox function" gets
# added, as they are interdependant, and this operation should work off of that function's information.
def readEmailContents(clientName, emailName, sym_key, connectionSocket):
    directory = os.getcwd()
    path = os.path.join(directory+"/"+clientName)

    # If the path exists, execute the read operation.
    # NOTE: This does not seem to prevent error flags, but judging that this
    # function will be pretty encapsulated, I don't think it'll matter.
    if (os.path.exists(path)):
        # create the full path name.
        full_path_name = os.path.join(path, emailName + ".txt")
        with open(full_path_name, 'r') as f:
            # read file contents into 'content', tokenize, and store in an array 'emailArr'.
            content = f.read()
            emailLen = str(len(content))
            print(emailLen)
            connectionSocket.send(sym_encrypt(emailLen, sym_key))
            print("Sent")
            clientAccept = sym_decrypt(connectionSocket.recv(2048), sym_key)
            print(clientAccept)
            if clientAccept == "OK":
                connectionSocket.sendall(sym_encrypt(str(content), sym_key))
            else:
                connectionSocket.send(sym_encrypt("client refused send", sym_key))
            
    f.close()


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
        return f"From: {self.from_user}\nTo: {self.to_user}\nDate: {str(self.date)}\nTitle: {self.title}\nContent Length: {self.content_length}\nContent: \n{self.content}"

    def __repr__(self):
        return f"From: {self.from_user}\nTo: {self.to_user}\nDate: {str(self.date)}\nTitle: {self.title}\nContent Length: {self.content_length}\nContent: \n{self.content}"

#-------
main()
