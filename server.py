import logging
import pickle
import socket
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
logging.info('Main: about to start server')

def server_thread(conn, addr):
    logging.info('Connection with addr %s: starting', addr)
    with conn:
        while True:
            # receive msg, session key, nonce, and tag
            data = conn.recv(1024)
            if not data:
                break
            data_arr = pickle.loads(data)
            msg = data_arr[0]
            session_key = data_arr[1]
            nonce = data_arr[2]
            tag = data_arr[3]

            # # decrypt msg
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
            unencrypted_data = cipher_aes.decrypt_and_verify(msg, tag)

            # send back unencrypted version of msg
            conn.send(unencrypted_data)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=server_thread, args=(conn, addr))
        t.start()