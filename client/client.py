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
from Crypto.Cipher import Random
from Crypto.PublicKey import RSA


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
    # TODO: Implement this function - use public key
    f = open('rsa.pub', 'r')
    pub_key = RSA.importKey(f.read())
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(pub_key, AES.MODE_CFB, iv)
    return iv + cipher.encrypt(session_key)


# Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
    # UNTESTED: Implement this function
    #Can change MODE_EAX to MODE_CBC or something else
    message = pad_message(message)
    iv = Random.new().read(AES.block_size) #init vector
    cipher_aes = AES.new(session_key, AES.MODE_CFB, iv)
    return base64.b64encode(iv + cipher_aes.encrypt(message))


# Decrypts the message using AES. Same as server function
def decrypt_message(client_message, session_key):
    # UNTESTED: Implement this function
    #Can change MODE_EAX to MODE_CBC or something else
    #Can replace nonce with an initialization vector if needed
    client_message = base64.b64decode(client_message)
    iv = client_message[:16]
    cipher_aes = AES.new(session_key, AES.MODE_CFB, iv)
    #NEED TO DEPAD THIS SOMEHOW!!
    return cipher_aes.decrypt(f[16:])


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

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        # Message that we need to send
        message = user + ' ' + password

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
        enc_message = encrypt_message(message, encrypted_key)
        send_message(sock, enc_message)

        # DONE: Receive and decrypt response from server
        data = receive_message(sock)
        decrypt_message(data, session_key)
    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()
