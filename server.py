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
import base64
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
        data = recvall(clientsocket)
        threading.Thread(target=clients_thread, args=(clientsocket,address,data)).start()
        if done:
            serversocket.close()
    return

def clients_thread(clientsocket, address, data):
    data = data.decode(encoding='utf-8')
    print(type(data))
    print(data)
    json_data = json.loads(data)
    user = json_data["username"]
    if not does_client_key_exist(user):
        print("Client key for " + user + " does not already exist in storage, writing now")
        write_client_key_file(user,json_data["key"].encode(encoding='utf-8'))
    client_key = load_client_key_file(user)
    if(json_data["flag"] == "HELLO"):
        response_to_client = build_json(user,key=public_key,flag="HELLO")
        clientsocket.send(response_to_client)
        print("Encrypted connection established with client " + user)
    elif (json_data["flag"] == "ADD"):
        response_to_client = add_file_message(json_data,client_key)
        #clientsocket.sendall(response_to_client)
        print("File added by " + user)
    elif (json_data["flag"] == "REMOVE"):
        print("remove time")
        response_to_client = remove_file_message(json_data,client_key)
        #clientsocket.sendall(response_to_client)
        print("File removed by " + user)
    elif (json_data["flag"] == "VIEW" and json_data["group"] == "" ):
        response_to_client = view_groups_message(json_data,client_key)
        clientsocket.sendall(response_to_client)
        print("Groups viewd by " + user)
    elif (json_data["flag"] == "VIEW"):
        response_to_client = view_files_message(json_data,client_key)
        clientsocket.sendall(response_to_client)
        print("Files viewd by " + user)
    clientsocket.close()
    return 0

# Function: add_file
# Usage: used for adding a file to the cloud, must mention user and group
# Return: 
def add_file_message(json_data,client_key):
    encrypted_data = json_data["data"]
    normal_data = decrypt_from_client(encrypted_data)
    print(normal_data)
    add_file_to_group(json_data["group"],json_data["filename"],normal_data)
    #are they authorised for this group?
    #decrypt the data in question
    #encrypt with group encryption
    #place in folder
    return 0

def add_file_to_group(group,filename, filedata):
    f = open(location + 'group/'+group+"/"+filename, "wb")
    f.write(filedata)
    f.close()

# Function: get_file
# Usage: used for getting a file from the cloud, must mention user and group
# Return: 
def get_file_message(json_data,client_key):
    return_data = -1
    #are they authorised for this group?
    #send encrypted data
    #encrypt the group key and send too
    return return_data

# Function: get_file
# Usage: used for getting a file from the cloud, must mention user and group
# Return: 
def remove_file_message(json_data,client_key):
    remove_file_from_group(json_data["group"],json_data["filename"])
     #are they authorised for this group?
     #delete file
    return 0

def remove_file_from_group(group,filename):
    os.remove(location + 'group/'+group+"/"+filename)
    return 0

# Function: view_files
# Usage: used for viewing the list of files in a specific group, must mention user and group
# Return: 
def view_files_message(json_data,client_key):
    return_data = -1
    #are they authorised for this group?
     #send back a list of file names encrypted
    return return_data

# Function: view groups
# Usage: used for viewing a list of groups the user is in
# Return: nothing
def view_groups_message(json_data,client_key):
    return_data = -1
    #send back a list of groups they are authorised for
    return return_data

def add_user_to_group(username, group):
    if not does_group_exist(group):
        return -1
    if is_user_in_group(username,group):
        return 0
    file = open(location + 'permissions/'+group+'.txt', 'a')
    file.write(username + "\n")
    file.close()
    return 0

def remove_user_from_group(username, group):
    if not does_group_exist(group):
        return -1
    if not is_user_in_group(username,group):
        return 0
    preexisting = open(location + 'permissions/'+group+'.txt', 'r').readlines()
    file = open(location + 'permissions/'+group+'.txt', "w")
    for line in preexisting:
        if line.strip("\n") != username:
            file.write(line)
    file.close()
    return 0

def create_group(group):
    os.makedirs(os.path.dirname(location + 'group/'+group+"/"), exist_ok=True)
    os.makedirs(os.path.dirname(location + 'permissions/'), exist_ok=True)
    file = open(location + 'permissions/'+group+'.txt', 'a+')
    file = open(location + 'permissions/'+group+'.txt', 'r')
    file.close()
    return 0

def does_group_exist(group):
    os.makedirs(os.path.dirname(location + 'group/'), exist_ok=True)
    os.makedirs(os.path.dirname(location + 'permissions/'), exist_ok=True)
    return os.path.isdir(location + 'group/'+ group)

def is_user_in_group(username,group):
    if(not does_group_exist(group)):
        return False
    file = open(location + 'permissions/'+group+'.txt', 'a+')
    grouplist = open(location + 'permissions/'+group+'.txt', 'r').readlines()
    for line in grouplist:
        if line == username + "\n":
            return True
    return False

def do_permissions_exist(group):
    return False

def is_same_key(username, maybe_client_public_key):
    new_pem =  maybe_client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )  
    stored_pem = load_client_key_file(username).public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return (str(new_pem) == str(stored_pem))

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

# Function: does_client_key_exist
# Usage: Checks that there are locally stored public key for client
# Return: True if key exists locally
def does_client_key_exist(client_name):
    print("checking for file")
    print(os.path.isfile(location + "user/" + client_name + "/public_key.pem"))
    return os.path.isfile(location + "user/" + client_name + "/public_key.pem")

def load_client_key_file(client_name):
    with open(location + "user/" + client_name + "/public_key.pem", "rb") as key_file:
        client_public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )
    return client_public_key

def write_client_key_file(client_name, client_pem):
    os.makedirs(os.path.dirname(location + "user/" + client_name + "/public_key.pem"), exist_ok=True)
    with open(location + "user/" + client_name + "/public_key.pem", 'wb') as f1:
        f1.write(client_pem)
    
def get_group_list(username):
    return_string = ""
    with os.scandir(location+'/group') as listOfEntries:
        for entry in listOfEntries:
            if entry.is_dir() and is_user_in_group(username,entry.name):
                return_string = return_string + entry.name + "\n"
    return return_string

def get_group_file_list(group):
    return_string = ""
    with os.scandir(location+'/group/'+group) as listOfEntries:
        for entry in listOfEntries:
            if entry.is_file():
                return_string = return_string + entry.name + "\n"
    return return_string


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
        os.makedirs(os.path.dirname(location), exist_ok=True)
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

# Function: encrypt_for_server
# Usage: encrypts data using the server's public key
# Return: nothing
def encrypt_for_client(data_to_encrypt,client_key):
    encryted_data = client_key.encrypt(
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
def decrypt_from_client(encryted_data):
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


# Function: main
# Usage: runs code on main, takes no arguments
# Return: nothing
def main():
    create_group("hello")
    add_user_to_group("paul","book_club1")
    print(get_group_list("paul"))
    print(get_group_file_list("book_club"))
    if(do_keys_exist()):
        load_key_files()
    else:
        print("Server missing public/private key, generating keys for Server")
        initialise_keys()
        load_key_files()
    run_cloud(6060)

if __name__ == "__main__":
    main()
