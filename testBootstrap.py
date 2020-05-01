import logging
import pickle
import socket
import threading
import time
from random import random

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP



HOST = '192.168.0.105'
PORT = 65432

format = '%(asctime)s: %(message)s'
logging.basicConfig(format=format, level=logging.INFO, datefmt='%H:%M:%S')
permissions = ['one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'alpha', 'beta', 'gamma', 'delta']

def bootstrap(msg, session_key, nonce, tag):
    # change the RSA key size per implementation
    key = RSA.generate(1024)

    # write the private key
    private_key = key.export_key()
    file_out = open('client-private.pem', 'wb')
    file_out.write(private_key)
    file_out.close()

    # write the public key
    public_key = key.publickey().export_key()
    file_out = open('client-receiver.pem', 'wb')
    file_out.write(public_key)
    file_out.close()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as c:
        c.connect((HOST, PORT))
        arr = (msg, session_key, nonce, tag, public_key)
        data_string = pickle.dumps(arr)
        c.send(data_string)
        data = c.recv(1024)
        print('Received', repr(data))

# get server public key and create session key
recipient_key = RSA.importKey(open('server-receiver.pem').read())
session_key = get_random_bytes(16)

# encrypt the message
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest('bootstrap'.encode('utf-8'))
begin = time.time()
bootstrap(ciphertext, session_key, cipher_aes.nonce, tag)
end = time.time()
print('Time to complete bootstrap: {}'.format(end - begin))