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
encoding = 'utf-8'
BUFFER_SIZE = 40960
private_key = -1
public_key = -1

def start_socket(port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    port = 6060

    client_socket.connect(("127.0.0.1", port))
    data = build_json("paul","123")
    print(type(data))
    client_socket.sendall(data)
    #client_socket.sendall(data)
    return

def send_file(file):
    return 0

def build_json(username, public_key):
    json_build = {
    "username": username,
    "public_key": public_key
    }   
    return json.dumps(json_build).encode(encoding='utf-8')

def initialise_keys(username):
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
    write_key_files(username,public_pem,private_pem)
    #print(peck)
    return 0

def write_key_files(username,public_pem, private_pem):
    with open('client_files/user/'+ username + '/keys/'+'public_key.pem', 'wb') as f1:
        f1.write(public_pem)

    with open('client_files/user/'+ username + '/keys/'+'private_key.pem', 'wb') as f2:
        f2.write(private_pem)
    return 0

def load_key_files():
    return 0
initialise_keys("paul")
start_socket(6060)