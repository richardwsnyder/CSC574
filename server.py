import logging
import pickle
import signal
import socket
from sys import getsizeof
import threading
import time

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

# change the RSA key size per implementation
key = RSA.generate(2048)

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
default_master_permissions = {'one': True, 'two': True, 'three': True, 'four': True, 'five': True, 'six': True, 'seven': True, 'eight': True, 'nine': True, 
                              'alpha': True, 'beta': True, 'gamma': True, 'delta': True}
default_common_permissions = {'one': False, 'two': False, 'three': False, 'four': False, 'five': False, 'six': False, 'seven': False, 'eight': False, 'nine': False, 
                              'alpha': False, 'beta': False, 'gamma': False, 'delta': False}
user_permissions = {}

first_user = True

def keyboardInterruptHandler(signal, frame):
    print('KeyboardInterrupt (ID: {}) has been caught. Cleaning up...'.format(signal))
    print('len:', len(designations))
    print('sizeof designations:', getsizeof(designations))
    print('sizeof user_permissions:', getsizeof(user_permissions))
    exit(0)

signal.signal(signal.SIGINT, keyboardInterruptHandler)

def add_user(pub_key, designation, perm_list):
    if pub_key in designations:
        return 'Already in node'
    designations[pub_key] = designation
    if designation == 'common':
        user_permission = default_common_permissions.copy()
        for perm in perm_list:
            user_permission[perm] = perm_list[perm]
        user_permissions[pub_key] = user_permission
    else:
        user_permissions[pub_key] = default_master_permissions
    return 'New user added with pub_key ' + str(pub_key)

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

def get_permissions(pub_key):
    permissions = {}
    try:
        permissions = user_permissions[pub_key]
        return str(permissions)
    except KeyError:
        return 'public key does not exist in permissions matrix'


def server_thread(conn, addr):
    # logging.info('Connection with addr %s: starting', addr)
    with conn:
        # receive msg, session key, nonce, and tag
        data = conn.recv(4096)
        ret = ''
        if not data:
            ret = 'Did not properly send data'.encode()
            conn.send(ret)
        begin = time.time()
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

        elif decoded_encrypted_data == 'adduser':
            designation = data_arr[5]
            perm_list = data_arr[6]
            ret = add_user(pub_key, designation, perm_list).encode()

        elif decoded_encrypted_data == 'getpermissions':
            ret = get_permissions(pub_key).encode()
        end = time.time()
        output = open('results.txt', 'a')
        output.write('Time it took to do {}: {}\n'.format(decoded_encrypted_data, end - begin))
        # send back return message
        conn.send(ret)

logging.info('Main: about to start server')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=server_thread, args=(conn, addr))
        t.start()
