import socket
import threading
import _thread
import functools
from datetime import datetime
import sys
import ssl
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
encoding = 'utf-8'

BUFFER_SIZE = 40960
private_key = 1
public_key = -1
server_key = -1
location = -1
username = -1


def start_socket(login, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    port = 6060

    client_socket.connect(("127.0.0.1", port))
    data = build_json("paul",public_key,"","","","")
    print(type(data))
    client_socket.sendall(data)
    #client_socket.sendall(data)
    return

def send_file(file):
    return 0

def build_json(username, key, format, group, filename, data):
    public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )  
    json_build = {
    "username": username,
    "key": str(public_pem),
    "group": group,
    "filename": filename,
    "data": data
    }   
    return json.dumps(json_build).encode(encoding='utf-8')

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

def write_key_files(public_pem, private_pem):
    if not os.path.exists(os.path.dirname(location + '/keys/')):
        os.makedirs(os.path.dirname(location + '/keys/'), exist_ok=True)
        os.makedirs(os.path.dirname(location + '/files/'), exist_ok=True)
    with open(location + '/keys/'+'public_key.pem', 'wb') as f1:
        f1.write(public_pem)

    with open(location + '/keys/'+'private_key.pem', 'wb') as f2:
        f2.write(private_pem)
    print("Keys generated for new user " + username)
    return 0


def load_key_files():
    global private_key, public_key
    with open(location + '/keys/'+ "private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )
    with open(location + '/keys/'+ "public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )
    return 0

def do_keys_exist():
    print(os.path.dirname(location + '/keys/public_key.pem'))
    return os.path.isfile(location + '/keys/public_key.pem') and os.path.isfile(location + '/keys/private_key.pem')

def main():
    global location
    global username
    port = -1
    print("Booting up client")
    print(len(sys.argv))
    if(len(sys.argv)==3):
        login = sys.argv[1]
        port = int(sys.argv[2])
    else:
        login = "paul"
        port = 6060
    location = 'client_files/user/' + login
    username = login
    if(do_keys_exist()):
        load_key_files()
    else:
        print("User " + username + " does not exist, generating keys for new user")
        initialise_keys()
        load_key_files()
    start_socket(login,port)

if __name__ == "__main__":
    main()