import socket
import threading
import _thread
import functools
from datetime import datetime
from flask import jsonify
import sys
import json
import ssl
import pickle
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
encoding = 'utf-8'
BUFFER_SIZE = 40960
done = False
location = "server_files/"

private_key = 1
public_key = -1

def run_cloud(proxy_port):
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # bind t public host and port
    serversocket.bind(("127.0.0.1", proxy_port))
    serversocket.listen(5)
    timestamp = datetime.now()
    print(f"{timestamp} : Cloud server started")

    while True:
        # open up proxy server
        (clientsocket, address) = serversocket.accept()
        data = clientsocket.recv(BUFFER_SIZE)
        threading.Thread(target=clients_thread, args=(clientsocket,address,data)).start()
        if done:
            serversocket.close()
    return

def clients_thread(clientsocket, address, data):
    data = data.decode(encoding='utf-8')
    print(type(data))
    print(data)
    json_data = json.loads(data)
    print(type(json_data))
    print(type(json_data["key"]))
    print(type(json_data["username"]))
    load_client_key_file(json_data["username"])
    clientsocket.sendall()
    return 0

def check_client_key():
    return

def exchange_keys():
    return

def load_client_key_file(client_name):
    with open(location + "user/" + client_name + "/public_key.pem", "rb") as key_file:
        client_public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )
    return client_public_key

# Function: initialise_keys
# Usage: used to initialise public and private key values or the user if they don't already exist
# Return: nothing
def initialise_keys():
    private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )   
    write_key_files(public_pem,private_pem)
    #print(peck)
    return 0

# Function: write_key_files
# Usage: writes the public and private pem for the server to two files
# Return: nothing
def write_key_files(public_pem, private_pem):
    if not os.path.exists(os.path.dirname(location + '/keys/')):
        os.makedirs(os.path.dirname(location + '/keys/'), exist_ok=True)
        os.makedirs(os.path.dirname(location + '/files/'), exist_ok=True)
    with open(location + '/keys/'+'public_key.pem', 'wb') as f1:
        f1.write(public_pem)

    with open(location + '/keys/'+'private_key.pem', 'wb') as f2:
        f2.write(private_pem)
    print("Keys generated for server")
    return 0

# Function: load_key_files
# Usage: loads the private and public keys for the server and updates the global variables, used on startup
# Return: nothing
def load_key_files():
    global private_key, public_key
    with open(location + 'keys/'+ "private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )
    with open(location + 'keys/'+ "public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# Function: do_keys_exist
# Usage: Checks that there are locally stored private and public keys for the server
# Return: True if both keys are stored locally, false if otherwise
def do_keys_exist():
    return os.path.isfile(location + 'keys/public_key.pem') and os.path.isfile(location + 'keys/private_key.pem')

# Function: main
# Usage: runs code on main, takes no arguments
# Return: nothing
def main():
    if(do_keys_exist()):
        load_key_files()
    else:
        print("Server missing public/private key, generating keys for Server")
        initialise_keys()
        load_key_files()
    run_cloud(6060)

if __name__ == "__main__":
    main()
