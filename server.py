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
encoding = 'utf-8'
BUFFER_SIZE = 40960
done = False

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
    return 0

def check_client_key():
    return

def exchange_keys():
    return

run_cloud(6060)