"""
    add_user.py - Stores a new username along with salt/password

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    The solution contains the same number of lines (plus imports)
"""


import random
import hashlib
import uuid
import re


MAC_REGEX = re.compile('[A-Z]{1,2},\{([A-Z],{0,1})*\}')

user = input("Enter a username: ")
password = input("Enter a password: ")

print("Please enter your MAC credentials using the example format:")
print("Clearance Levels (Low->High): (U)nclassified, (C)lassified, (S)ecret, (T)op(S)ecret")
print("<CLEARANCE>,{<CATEGORIES>}")
print("Example: TS,{A,B}")

user_creds = False
valid_clearances = ['U', 'C', 'S', 'TS']

while not user_creds:
    mac_user_creds = input("MAC Credentials: ")
    mac_user_creds = mac_user_creds.replace(" ","")
    
    clearance = mac_user_creds.split(',')[0]
    print(clearance)
    
    if MAC_REGEX.match(mac_user_creds):
        user_creds = True
    else:
        print("Please enter valid credentials...")
        
    if clearance not in valid_clearances:
        print("Please enter valid credentials...")
        user_creds = False

# TODO: Create a salt and hash the password

salt = uuid.uuid4().hex
hashed_password = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
hashed_mac_creds = hashlib.sha256((mac_user_creds + salt).encode('utf-8')).hexdigest()

try:
    reading = open("passfile.txt", 'r')
    for line in reading.read().split('\n'):
        if line.split('\t')[0] == user:
            print("User already exists!")
            exit(1)
    reading.close()
except FileNotFoundError:
    pass

with open("passfile.txt", 'a+') as writer:
    writer.write("{0}\t{1}\t{2}\t{3}\n".format(user, salt, hashed_password, hashed_mac_creds))
    print("User successfully added!")
