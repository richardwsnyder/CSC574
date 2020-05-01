import logging
import pickle
import signal
import socket
from sys import getsizeof
import threading

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

# change the RSA key size per implementation
key = RSA.generate(1024)

# write the private key
private_key = key.export_key()
file_out = open('server-private.pem', 'wb')
file_out.write(private_key)
file_out.close()

# write the public key
public_key = key.publickey().export_key()
file_out = open('server-receiver.pem', 'wb')
file_out.write(public_key)
file_out.close()

HOST = '127.0.0.1'
PORT = 65432

format = '%(asctime)s: %(message)s'
logging.basicConfig(format=format, level=logging.INFO, datefmt='%H:%M:%S')

designations = {}

first_user = True

def keyboardInterruptHandler(signal, frame):
    print('KeyboardInterrupt (ID: {}) has been caught. Cleaning up...'.format(signal))
    print('len:', len(designations))
    print('sizeof:', getsizeof(designations))
    exit(0)

signal.signal(signal.SIGINT, keyboardInterruptHandler)

def add_user(pub_key, designation):
    if pub_key in designations:
        return 'Already in node'
    designations[pub_key] = designation
    return 'New user added'

def bootstrap(pub_key):
    global first_user
    designation = ''
    if first_user == True:
        designation = 'master'
        first_user = False
    else:
        return 'There is already a master user bootstrapped'
    designations[pub_key] = designation
    return 'Successfully bootstrapped'

def server_thread(conn, addr):
    logging.info('Connection with addr %s: starting', addr)
    with conn:
        # receive msg, session key, nonce, and tag
        data = conn.recv(2048)
        ret = ''
        if not data:
            ret = 'Did not properly send data'.encode()
            conn.send(ret)
        data_arr = pickle.loads(data)
        msg = data_arr[0]
        session_key = data_arr[1]
        nonce = data_arr[2]
        tag = data_arr[3]
        pub_key = data_arr[4]
        
        # decrypt msg
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        unencrypted_data = cipher_aes.decrypt_and_verify(msg, tag)

        decoded_encrypted_data = unencrypted_data.decode()

        if decoded_encrypted_data == 'bootstrap':
            ret = bootstrap(pub_key).encode()
            print(ret)

        elif decoded_encrypted_data == 'adduser':
            designation = data_arr[5]
            ret = add_user(pub_key, designation).encode()
            print(ret)
        # send back unencrypted version of msg
        conn.send(ret)

logging.info('Main: about to start server')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=server_thread, args=(conn, addr))
        t.start()