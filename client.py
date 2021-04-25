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

# Function:
# Usage: 
# Return: 

# Function:_start socket
# Usage: starts a connection with the 
# Return: 
def start_socket(login, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    port = 6060

    client_socket.connect(("127.0.0.1", port))
    data = build_json("paul",key=public_key,flag="HELLO")
    print(type(data))
    client_socket.sendall(data)
    #client_socket.sendall(data)
    return

# Function: add_file
# Usage: used for adding a file to the cloud, must mention user and group
# Return: 
def add_file(file):
    return 0

# Function: get_file
# Usage: used for getting a file from the cloud, must mention user and group
# Return: 
def get_file(file):
    return 0

# Function: get_file
# Usage: used for getting a file from the cloud, must mention user and group
# Return: 
def remove_file(file):
    return 0

# Function: view_files
# Usage: used for viewing the list of files in a specific group, must mention user and group
# Return: 
def view_files(file):
    return 0

# Function: view groups
# Usage: used for viewing a list of groups the user is in
# Return: nothing
def view_groups(file):
    return 0

# Function: get server key
# Usage: used for getting the server's public key
# Return: nothing
def get_server_key():
    return 0

# Function: encrypt_for_server
# Usage: encrypts data using the server's public key
# Return: nothing
def encrypt_for_server(data_to_encrypt):
    encryted_data = server_key.encrypt(
     data_to_encrypt,
     padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA256()),
         algorithm=hashes.SHA256(),
         label=None
     )
    )
    return encryted_data

# Function: decrypt_from_server
# Usage: decrypts data from the server using the private key of the client
# Return: nothing
def decrypt_from_server(encryted_data):
    data = private_key.decrypt(
         encryted_data,
         padding.OAEP(
             mgf=padding.MGF1(algorithm=hashes.SHA256()),
             algorithm=hashes.SHA256(),
             label=None
         )
     )
    return data

# Function: decrypt_from_group
# Usage: decrypts data from a group using the client private key to find the group key
# Return: nothing
def decrypt_group_data():
    return 0

# Function: build_json
# Usage: builds a json file of data to be sent in over a socket connection, used to transfer data between client and server
# Return: the json file of data
def build_json(username, key="", flag="", group="", filename="", data="", group_key=""):
    public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )  
    json_build = {
    "username": username,
    "flag": flag,
    "key": public_pem.decode(encoding='utf-8'),
    "group": group,
    "group key": group_key,
    "filename": filename,
    "data": data
    }   
    return json.dumps(json_build).encode(encoding='utf-8')

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
# Usage: writes the public and private pem for the user to two files
# Return: nothing
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

# Function: load_key_files
# Usage: loads the private and public keys for the user and updates the global variables, used on startup
# Return: nothing
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

def load_server_key_file():
    return 0

# Function: do_keys_exist
# Usage: Checks that there are locally stored private and public keys for the user
# Return: True if both keys are stored locally, false if otherwise
def do_keys_exist():
    print(os.path.dirname(location + '/keys/public_key.pem'))
    return os.path.isfile(location + '/keys/public_key.pem') and os.path.isfile(location + '/keys/private_key.pem')

# Function: main
# Usage: runs code on main, takes two arguments (username and port no.) on startup, otherwise defaults to user Paul
# Return: nothing
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