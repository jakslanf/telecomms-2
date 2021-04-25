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
import base64
encoding = 'utf-8'

BUFFER_SIZE = 40960
private_key = 1
public_key = -1
server_key = -1
location = -1
username = ""
command_wanted = ""
group_wanted = ""
file_wanted = ""
done = False

# Function:
# Usage: 
# Return: 

# Function:_start socket
# Usage: starts a connection with the 
# Return: 
def start_socket(login, port):
    global server_key
    global command_wanted
    global group_wanted
    global file_wanted
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #host = socket.gethostname()
    port = 6060

    client_socket.connect(("127.0.0.1", port))
    server_key = load_server_key_file()
    #data = build_json(username,key=public_key,flag=command_wanted,group=group_wanted,filename=file_wanted)
    if (command_wanted == "ADD"):
        file_data = encrypt_for_server(load_file(file_wanted))
        data = build_json(username,key=public_key,flag=command_wanted,group=group_wanted,filename=file_wanted,encrypdata=file_data)
    if (command_wanted == "REMOVE"):
        file_data = encrypt_for_server(load_file(file_wanted))
        data = build_json(username,key=public_key,flag=command_wanted,group=group_wanted,filename=file_wanted)
    print(type(data))
    client_socket.sendall(data)
    if (command_wanted == "HELLO" or command_wanted == "VIEW" or command_wanted == "GET"):
        reply = bytes()
        reply = recvall(client_socket)
        print(reply)
        json_data=json.loads(reply)
        if not does_server_key_exist():
            print("Sever key for does not already exist in storage, writing now")
            write_server_key_file(json_data["key"].encode(encoding='utf-8'))
        server_key = load_server_key_file()
        print("Encrypted connection established with server")
    #print(decrypt_from_server(reply))
    client_socket.close()
    return

def load_file(file):
    return open(location + "/files/" + file_wanted, "rb").read()


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
    encrypted_b64 = encryted_data.encode()
    encrypted = base64.b64decode(encrypted_b64)
    data = private_key.decrypt(
         encrypted,
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

def recvall(sock):
    recvdata = b''
    while True:
        part = sock.recv(BUFFER_SIZE)
        recvdata += part
        if len(part) < BUFFER_SIZE:
            break
    return recvdata

# Function: build_json
# Usage: builds a json file of data to be sent in over a socket connection, used to transfer data between client and server
# Return: the json file of data
def build_json(username, key="", flag="", group="", filename="", encrypdata=b'', group_key=""):
    public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )  
    encrypted_b64 = base64.b64encode(encrypdata)
    encrypted_b64_string = encrypted_b64.decode()
    json_build = {
    "username": username,
    "flag": flag,
    "key": public_pem.decode(encoding='utf-8'),
    "group": group,
    "group_key": group_key,
    "filename": filename,
    "data": encrypted_b64_string
    }
    print(type(json_build["data"]))
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


# Function: does_client_key_exist
# Usage: Checks that there are locally stored public key for client
# Return: True if key exists locally
def does_server_key_exist():
    print("Checking for server key in storage")
    print(os.path.isfile(location + "/keys/server_public_key.pem"))
    return os.path.isfile(location + "/keys/server_public_key.pem")

def load_server_key_file():
    with open(location + "/keys/server_public_key.pem", "rb") as key_file:
        server_public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )
    return server_public_key

def write_server_key_file(server_pem):
    #os.makedirs(os.path.dirname(location + "user/" + client_name + "/public_key.pem"), exist_ok=True)
    with open(location + "/keys/server_public_key.pem", 'wb') as f1:
        f1.write(server_pem)

# Function: do_keys_exist
# Usage: Checks that there are locally stored private and public keys for the user
# Return: True if both keys are stored locally, false if otherwise
def do_keys_exist():
    print(os.path.dirname(location + '/keys/public_key.pem'))
    return os.path.isfile(location + '/keys/public_key.pem') and os.path.isfile(location + '/keys/private_key.pem')

def print_help():
    print("Here's a list of handy commands %% replace anything in brackets with the appropriate name")
    print("python client.py [username] [command] [group] [file]")
    print("python client.py [username] HELLO %% establish a connection with the server")
    print("python client.py [username] ADD [group] [file] %% add a file to a group folder")
    print("python client.py [username] REMOVE [group]  [file] %% add a file to a group folder")
    print("python client.py [username] VIEW [group] [file] %% view a list of files in a group folder")
    print("python client.py [username] VIEW [group] /%% view a list of groups you have access to")

# Function: main
# Usage: runs code on main, takes two arguments (username and port no.) on startup, otherwise defaults to user Paul
# Return: nothing
def main():
    global location
    global username
    global command_wanted
    global group_wanted
    global file_wanted
    port = 6060
    print("Booting up client")
    print(len(sys.argv))
    if(len(sys.argv)==4 or len(sys.argv)==5):
        print("Using command line arguments")
        login = str(sys.argv[1])
        command_wanted = str(sys.argv[2])
        group_wanted = str(sys.argv[3])
        file_wanted = ""
        if len(sys.argv)==5:
            file_wanted = sys.argv[4]
        location = 'client_files/user/' + login
        username = login
        if(do_keys_exist()):
            load_key_files()
        else:
            print("User " + username + " does not exist, generating keys for new user")
            initialise_keys()
            load_key_files()
        start_socket(login,port)
    else:
        print("ERROR: Invalid Arguments")
        print_help()

if __name__ == "__main__":
    main()