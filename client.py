import logging
import pickle
import socket
import threading
import time
from random import random

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP



HOST = '127.0.0.1'
PORT = 65432

format = '%(asctime)s: %(message)s'
logging.basicConfig(format=format, level=logging.INFO, datefmt='%H:%M:%S')
permissions = ['one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'alpha', 'beta', 'gamma', 'delta']

def client_thread(msg, session_key, nonce, tag, pub_key):
    # logging.info('I am thread {}'.format(thread_num))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as c:
        c.connect((HOST, PORT))
        perm_list = {}
        for perm in permissions:
            ran = random()
            if ran < 0.5:
                perm_list[perm] = False
            else:
                perm_list[perm] = True
        arr = (msg, session_key, nonce, tag, pub_key, 'common', perm_list)
        data_string = pickle.dumps(arr)
        c.send(data_string)
        data = c.recv(1024)
        print('Received', repr(data))

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
bootstrap(ciphertext, session_key, cipher_aes.nonce, tag)

for i in range(10):

    # change the RSA key size per implementation
    key = RSA.generate(1024)

    # write the private key
    private_key = key.export_key()
    file_out = open('client-private-{}.pem'.format(i), 'wb')
    file_out.write(private_key)
    file_out.close()

    # write the public key
    public_key = key.publickey().export_key()
    file_out = open('client-receiver-{}.pem'.format(i), 'wb')
    file_out.write(public_key)
    file_out.close()

    # msg that will be sent to the server
    msg = 'adduser'.encode('utf-8')

    # get server public key and create session key
    recipient_key = RSA.importKey(open('server-receiver.pem').read())
    session_key = get_random_bytes(16)

    # encrypt the message
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(msg)

    # send message, session key, nonce, tag, and thread #
    t = threading.Thread(target=client_thread, args=(ciphertext, session_key, cipher_aes.nonce, tag, public_key))
    t.start()

    t.join()

    # msg that will be sent to the server
    msg = 'getpermissions'.encode('utf-8')

    # get server public key and create session key
    recipient_key = RSA.importKey(open('server-receiver.pem').read())
    session_key = get_random_bytes(16)

    # encrypt the message
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(msg)

    # send message, session key, nonce, tag, and thread #
    t = threading.Thread(target=client_thread, args=(ciphertext, session_key, cipher_aes.nonce, tag, public_key))
    t.start()