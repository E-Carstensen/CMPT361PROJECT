from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP

#TODO REMEMBER THAT IT NEEDS THESE LIBARIES ABOVE TO WORK, BOTH PY should have

f = open('client1_public.pem','rb')    #getting the key for encryption
key = f.read()          #storing key
f.close()               #closing a file
pub_rsa = RSA.import_key(key)
cipher1 = PKCS1_OAEP.new(pub_rsa)


f = open('client1_private.pem','rb')    #getting the key for encryption
key = f.read()          #storing key
f.close()               #closing a file
pri_rsa = RSA.import_key(key)
cipher2 = PKCS1_OAEP.new(pri_rsa)


# The message to encrypt
message = input('Enter the message to be encrypted: ')

# Encrypt the message
ct_bytes = cipher1.encrypt(message.encode('ascii'))
print('The encrypted message:',ct_bytes)

# Decrypting the message
Encodedmessage = cipher2.decrypt(ct_bytes)
#Remove padding
print(Encodedmessage.decode('ascii'))
