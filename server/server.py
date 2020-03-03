"""
    server.py - host an SSL server that checks passwords

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:
    Ethan Shuler
    John Henry Fitzgerald
    Israel Miles
"""

import socket
import hashlib
import uuid
import socket
import os
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

host = "localhost"
port = 10001


# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)


# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
    f = open('private.pem', 'r')
    key = RSA.importKey(f.read())
    decrypted = key.decrypt(session_key)
    return decrypted 


# Write a function that decrypts a message using the session key
def decrypt_message(client_message, session_key):
    client_message = base64.b64decode(client_message)
    iv = client_message[:16]
    cipher_aes = AES.new(session_key, AES.MODE_CFB, iv)
    return cipher_aes.decrypt(client_message[16:]).decode('utf-8')


# Encrypt a message using the session key
def encrypt_message(message, session_key):
    message = pad_message(message)
    iv = Random.new().read(16) #init vector
    cipher_aes = AES.new(session_key, AES.MODE_CFB, iv)
    return base64.b64encode(iv + cipher_aes.encrypt(message))


# Receive 1024 bytes from the client
def receive_message(connection):
    return connection.recv(1024)


# Sends message to client
def send_message(connection, data):
    if not data:
        print("Can't send empty string")
        return
    if type(data) != bytes:
        data = data.encode()
    connection.sendall(data)


# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't. The delimiters are newlines and tabs
def verify_hash(user, password):
    try:
        reader = open("passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")
            if line[0] == user:
                # DONE: Generate the hashed password

                salt = line[1]
                hashed_password = hashlib.sha256(
                    (password + salt).encode('utf-8')).hexdigest()
                return hashed_password == line[2]
        reader.close()
    except FileNotFoundError:
        return False
    return False
                
    
def verify_mac(user, user_doc, user_mac):
    try:
        reader = open("passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")
            if line[0] == user:
                hashed_mac = hashlib.sha256(
                    (user_mac + line[1]).encode('utf-8')).hexdigest()
                return hashed_mac == line[3]
        reader.close()
    except FileNotFoundError:
        return "File error"
    return "File error"


def authenticate_mac(user_mac, user_doc):
    user_clearance = user_mac.split(",")[0]
    user_categories = user_mac.split("{")[1][:-1].split(",")
    
    if user_clearance == "U":
        user_clearance = 0
    elif user_clearance == "C":
        user_clearance = 1
    elif user_clearance == "S":
        user_clearance = 2
    elif user_clearance == "TS":
        user_clearance = 3
        
    try:
        reader = open("document_permissions.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split(":")
            if len(line) > 1:
                doc_name = line[0]
                doc_clearance = line[1].split(",")[0].replace(" ","")
                doc_categories = line[1].split("{")[1][:-1].replace(" ","").split(",")
                while("" in doc_categories) : 
                    doc_categories.remove("") 
                
                match = False
                read = False
                write = False
                
                print(doc_name)
                if doc_name == user_doc:
                    if doc_clearance == "U":
                        doc_clearance = 0
                    elif doc_clearance == "C":
                        doc_clearance = 1
                    elif doc_clearance == "S":
                        doc_clearance = 2
                    elif doc_clearance == "TS":
                        doc_clearance = 3

                    if user_clearance > doc_clearance:
                        if not doc_categories:
                            read = True
                        if all(elem in user_categories for elem in doc_categories):
                            read = True
                    elif user_clearance == doc_clearance:
                        if not doc_categories:
                            read = True
                            write = True
                        if all(elem in user_categories for elem in doc_categories):
                            read = True
                            write = True
                    elif user_clearance < doc_clearance:
                        write = True
                    match = True
                        
                if match:
                    if read and write:
                        return "You have the following privileges for the file: rw"
                    elif read:
                        return "You have the following privileges for the file: r"
                    elif write:
                        return "You have the following privileges for the file: w"
                    else:
                        return "You have the following privileges for the file: "
                    
        reader.close()
    except FileNotFoundError:
        return "File error"
    return "File error"
        
    

def main():
    # Set up network connection listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    print('starting up on {} port {}'.format(*server_address))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)

    try:
        while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                # Receive encrypted key from client
                encrypted_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                plaintext_key = decrypt_key(encrypted_key)

                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)

                # DONE: Decrypt message from client
                message_in = decrypt_message(ciphertext_message, plaintext_key)

                # DONE: Split response from user into the username and password
                message_in = message_in.split()
                username = message_in[0]
                password = message_in[1]
                user_doc = message_in[2]
                user_mac = message_in[3]
                #print(username, password, user_doc, user_mac)

                # DONE: Encrypt response to client
                if verify_hash(username,password):
                    response_to_client = "Password accepted. Welcome!\n"
                    #TODO MAC Authorization
                else:
                    response_to_client = "Username/Password combination does not exist."
                    
                if verify_mac(username, user_doc, user_mac):
                    response_to_client = response_to_client + "Valid MAC credentials. Authenticating Mac..."
                    response_to_client = response_to_client + authenticate_mac(user_mac, user_doc)
                else:
                    response_to_client = response_to_client + "User MAC credentials do not exist. Permission denied."
                    
                cipertext_response = encrypt_message(response_to_client, plaintext_key)

                # Send encrypted response
                send_message(connection, cipertext_response)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()
