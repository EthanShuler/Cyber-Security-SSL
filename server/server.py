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

host = "localhost"
port = 10001


# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)


# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
    # UNTESTED: Implement this function
    f = open('rsa', 'r')
    cipher_rsa = RSA.importKey(f.read())
    session_key = cipher_rsa.decrypt(session_key)
    return session_key



# Write a function that decrypts a message using the session key
def decrypt_message(client_message, session_key):
    # UNTESTED: Implement this function
    #Can change MODE_EAX to MODE_CBC or something else
    #Can replace nonce with an initialization vector if needed
    client_message = base64.b64decode(client_message)
    iv = client_message[:16]
    cipher_aes = AES.new(session_key, AES.MODE_EAX, iv)
    #NEED TO DEPAD THIS SOMEHOW!!
    return cipher_aes.decrypt(f[16:])


# Encrypt a message using the session key
def encrypt_message(message, session_key):
    # UNTESTED: Implement this function
    #Can change MODE_EAX to MODE_CBC or something else

    message = pad_message(message)
    iv = Random.new().read(AES.block_size) #init vector
    cipher_aes = AES.new(session_key, AES.MODE_EAX, iv)
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
                ciphertext_message = decrypt_message(ciphertext_message, plaintext_key)

                # DONE: Split response from user into the username and password
                username = ciphertext_message.split()[1]
                password = ciphertext_message.split()[2]

                # DONE: Encrypt response to client
                if verify_hash(username,password):
                    response_to_client = "Password accepted. Welcome!"
                else:
                    response_to_client = "Username/Password combination does not exist"
                cipertext_response = encrypt_message(response_to_client, plaintext_key)

                # Send encrypted response
                send_message(connection, ciphertext_response)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()
