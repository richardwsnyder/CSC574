import logging
import pickle
import socket
import threading
import time

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP



HOST = '127.0.0.1'
PORT = 65432

format = '%(asctime)s: %(message)s'
logging.basicConfig(format=format, level=logging.INFO, datefmt='%H:%M:%S')

def client_thread(msg, session_key, nonce, tag, thread_num):
    # logging.info('I am thread {}'.format(thread_num))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as c:
        c.connect((HOST, PORT))
        arr = (msg, session_key, nonce, tag)
        data_string = pickle.dumps(arr)
        c.send(data_string)
        data = c.recv(1024)
        print('Received', repr(data))

for i in range(10):
    # msg that will be sent to the server
    msg = 'Hello world, I am number {}'.format(i).encode('utf-8')

    # get server public key and create session key
    recipient_key = RSA.importKey(open('server-receiver.pem').read())
    session_key = get_random_bytes(16)

    # encrypt the message
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(msg)

    # send message, session key, nonce, tag, and thread #
    t = threading.Thread(target=client_thread, args=(ciphertext, session_key, cipher_aes.nonce, tag, i))
    t.start()
