import json
import socket
import os,glob, datetime
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# Forge a pathname to the email based on the function arguments.
directory = os.getcwd()
path = os.path.join(directory+"/"+"client2")

# If the path exists, execute the read operation.
# NOTE: This does not seem to prevent error flags, but judging that this
# function will be pretty encapsulated, I don't think it'll matter.
if (os.path.exists(path)):
	# create the full path name.
    full_path_name = os.path.join(path, "client1_Test.txt")
    with open(full_path_name, 'r') as f:
        # read file contents into 'content', tokenize, and store in an array 'emailArr'.
        content = f.read()
        emailLen = len(content)
        
    f.close()