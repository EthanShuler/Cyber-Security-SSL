"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:
    Ethan Shuler
    John Henry Fitzgerald
    Israel Miles
"""

import socket
import os
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64


host = "localhost"
port = 10001


# A helper function that you may find useful for AES encryption
# Is this the best way to pad a message?!?!
def pad_message(message):
    return message + " "*((16-len(message)) % 16)


# TODO: Generate a cryptographically random AES key
def generate_key():
    # DONE: Implement this function
    return os.urandom(16)


# Takes an AES session key and encrypts it using the appropriate
# key and return the value
def encrypt_handshake(session_key):
    # DONE: Implement this function - use public key
    f = open('public.pem', 'r')
    pub_key = RSA.importKey(f.read())
    encrypted = pub_key.encrypt(session_key, 32)
    return encrypted[0]


# Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
    message = pad_message(message)
    iv = Random.new().read(16) #init vector
    cipher_aes = AES.new(session_key, AES.MODE_CFB, iv)
    return base64.b64encode(iv + cipher_aes.encrypt(message))


# Decrypts the message using AES. Same as server function
def decrypt_message(client_message, session_key):
    client_message = base64.b64decode(client_message)
    iv = client_message[:16]
    cipher_aes = AES.new(session_key, AES.MODE_CFB, iv)
    return cipher_aes.decrypt(client_message[16:]).decode('utf-8')


# Sends a message over TCP
def send_message(sock, message):
    sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data


def main():
    user = input("What's your username? ")
    password = input("What's your password? ")
    user_mac = input("What are your MAC credentials?\n")

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        print("Document list:")
        print("  user_info\n  intelligence_briefing\n  battle_plans\n  defence_budget\n  ranking_chart")  
        user_doc = input("Enter the name of the document you want to access:\n")
        # Message that we need to send
        message = user + ' ' + password + ' ' + user_doc + ' ' + user_mac

        # Generate random AES key
        key = generate_key()

        # Encrypt the session key using server's public key
        encrypted_key = encrypt_handshake(key)

        # Initiate handshake
        send_message(sock, encrypted_key)

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)

        # DONE: Encrypt message and send to server
        enc_message = encrypt_message(message, key)
        send_message(sock, enc_message)

        # DONE: Receive and decrypt response from server
        data = receive_message(sock)
        print(decrypt_message(data, key))
    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()
