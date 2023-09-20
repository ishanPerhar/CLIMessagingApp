import socket
import os
import sys
import json
import random
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Global Variables
server_port = 13000
BLOCK_SIZE = 32
menu = "Select the operations:\n\t\t1) Create and send an email\n\t\t2) Display\
 the inbox list\n\t\t3) Display the email contents\n\t\t4) Terminate the connection"


def load_key(filename):
    """
    Purpose: load key from key tiles into a variable

    Parameters:
        str: filename

    returns:
        bstr: binary string key
    """
    with open(filename, "rb") as file:
        key = file.read()
        key = RSA.importKey(key)
    return key


def decrypt_message(priv_key, enc_msg):
    """
    Purpose: decrypt encrypted message

    Parameters:
        priv_key(bstr): private key for server
        enc_msg(bstr): encrypted message that needs to be decrypted

    Returns:
        Decrypted_msg(bstr): decrypted message
    """
    key = RSA.import_key(priv_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(enc_msg)


def verify_signature(pubkey, msgDigest, signature):
    """
    Purpose: verify users signature

    Parameters:
        pubkey(bstr): clients publickey

        msgDigest(bstr): encrypted message digest

        signature(bstr): signature of client from thier priv key
    Returns:
        bool: True if signature is verified and false otherwise
    """

    key = RSA.import_key(pubkey)

    h = SHA256.new(msgDigest)

    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


def is_authorized(username, password):
    """
    Purpose: check whether user is authorized to access the application

    Parameters:
        username(str): username of user
        password(str): password of user

    Returns:
        True(boolean) if user is authorized to access the application
        False(boolean) if user is not authorized to access the application
    """
    # open json db of users and passwords
    with open("user_pass.json", "r") as file:
        users = json.load(file)

    # if user is authorized return true else false
    if username in users and password == users[username]:
        return True
    else:
        return False


def termination_protocol(client_socket, username):
    """
    Purpose: Terminate our session with the client

    Parameters:
        client_socket: users socket connection
        username(str): username of user

    Returns: None
    """
    client_socket.close()
    print(f"Terminating connection with {username}")


def check_folders(username):
    """
    Purpose: checks if folder exists for receipient if not creates one

    Parameters:
        username(str): username of receipient

    Returns: None
    """
    if not os.path.exists(username):
        os.makedirs(username)


def email_protocol(client_socket, aes_cipher, username):
    """
    Purpose: Run our send email protocol

    Parameters:
        client_socket: user connection
        aes_cipher(str): AES encryption using symmetric key
        username(str): username of user
    Return: None
    """
    msg = "Send the email".encode()
    # encrypt the messageS
    msg = aes_cipher.encrypt(pad(msg, BLOCK_SIZE))
    # send msg to client
    client_socket.send(msg)
    # receive encrypted file size send ok then receive message
    enc_file_size = client_socket.recv(4096)
    enc_file_size = aes_cipher.decrypt(enc_file_size)
    enc_file_size = unpad(enc_file_size, BLOCK_SIZE)
    file_size = enc_file_size.decode("ascii")
    file_size = int(file_size)
    client_socket.send("OK".encode())
    email = b""
    while len(email) < file_size:
        data = client_socket.recv(4096)
        email += data

    # decrypt and unpad and decode email
    email = aes_cipher.decrypt(email)
    email = unpad(email, BLOCK_SIZE)
    email = email.decode("ascii")
    email = email.split(",")

    # break received data into individual fields and peice together proper email format
    sender = email[0]
    to = email[1]
    # split receipients into a list
    to = to.split(";")
    date = datetime.now()
    title = email[2]
    content_length = email[3]
    content = email[4]

    # format the email to match the specifications
    email = f"From: {sender}\nTo: {to}\nTime and Date: {date}\nTitle: {title}\nContent Length: {content_length}\nContent:\n{content}"

    # check if a folder exists per receipient if not creates one
    for name in to:
        check_folders(name)
        filename = f"{sender}_{title}.txt"
        file_path = os.path.join(name, filename)
        with open(file_path, "w") as file:
            file.write(email)


def view_inbox(user, aescipher, clientsocket):
    """
    Purpose: View contents of the users inbox(directory)

    Parameters:
        user(str): user of the application
        aescipher(bstring): cipher to encrypt data
        clientsocket: socket connection to client
    Returns: None
    """
    folder_path = os.path.join(os.getcwd(), user)
    exists = True
    # check if folder exists
    if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
        os.mkdir(folder_path)

    inbox = []

    # retrieve emails from inbox
    for filename in os.listdir(folder_path):
        # change file path to include filename
        file_path = os.path.join(folder_path, filename)
        # get date email was received
        date = os.path.getctime(file_path)
        # convert to datetime object
        date = datetime.fromtimestamp(date)

        data = f"{filename};{date}"
        inbox.append(data)

    inbox = ",".join(map(str, inbox))

    # encrypt size of inbox send to client wait for ok then encrypt and send inbox
    size = len(inbox)
    fsize = str(len(inbox)).encode()
    enc_fsize = aescipher.encrypt(pad(fsize, BLOCK_SIZE))
    clientsocket.send(enc_fsize)

    if size == 0:
        pass
    else:
        # receive ok
        ok = clientsocket.recv(1024)

        # encrypt send inbox
        inbox = inbox.encode()
        inbox = aescipher.encrypt(pad(inbox, BLOCK_SIZE))
        clientsocket.send(inbox)


def view_message(client_socket, aes_cipher, username):
    """
    Purpose: View a particular message depending on index chosen by user

    Parameters:
        client_socket    : Socket for communication with client
        aes_cipher(bstr) : Cipher for aes 256 symmetric encryption
        usernames(str)   : user of the application

    Returns: None
    """
    prompt = "Enter the email index you wish to view: "

    # encode, pad, and encrypt prompt
    prompt = prompt.encode()
    prompt = pad(prompt, BLOCK_SIZE)
    enc_prompt = aes_cipher.encrypt(prompt)

    # send to the client
    client_socket.send(enc_prompt)

    # receive clients choice
    index = client_socket.recv(4096)

    # decrypt, unpad, decode, cast into an int users index choice
    index = aes_cipher.decrypt(index)
    index = unpad(index, BLOCK_SIZE)
    index = index.decode("ascii")
    index = int(index)

    # retrieve the message
    msg = get_msg(username, index)

    # encode, pad, and encrypt the message
    msg = msg.encode()
    msg = pad(msg, BLOCK_SIZE)
    enc_msg = aes_cipher.encrypt(msg)

    # get size of the encrypted message and encrypt it and send it to the client
    fsize = str(len(enc_msg)).encode()
    fsize = pad(fsize, BLOCK_SIZE)
    enc_fsize = aes_cipher.encrypt(fsize)
    client_socket.send(enc_fsize)

    # receive ok from client then send encrypted message
    ok = client_socket.recv(4096)
    client_socket.send(enc_msg)


def get_msg(username, index):
    """
    Purpose: get the message from the index given

    Parameters:
            username (string): current user
            index (int): index of the message

    Returns:
            msg (string): message contents
    """
    # create file path by getting current working directory and adding the username to it
    filepath = os.path.join(os.getcwd(), username)

    # check if directory exists
    if not os.path.isdir(filepath):
        os.makedirs(filepath)
        response = "No Messages"
        return response

    # get list of files
    files = os.listdir(filepath)

    # check if index is within range
    if index < 0 or index >= len(files):
        response = "Invalid Index."
        return response

    # create new path for the targeted message
    filename = files[index]
    filepath = os.path.join(filepath, filename)

    # read contents of the message
    with open(filepath, "r") as file:
        msg = file.read()

    return msg


def sign_is_valid(key, message, signature):
    """%%%
    Purpose: Check if signed message is valid

    Parameters:
               key: clients public key
               message: message server reseived from client unencrypted
               signature: signature from client

    Returns: True if valid signature, False if not valid
    """
    h = SHA256.new(message)  # hash message from client
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


def server():
    """
    Purpose: Run our server for secure mail transfer protocol

    Parameters: None

    Returns: None
    """
    # create TCP socket using IPv4
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print("Error creating socket", e)
        sys.exit(1)

    # Associate port # with the socket
    try:
        server_socket.bind(("", server_port))
    except socket.error as e:
        print("Error in socket binding:", e)

    # listen for connectiosn have a queue of 5
    server_socket.listen(5)

    # Server Loop
    while True:
        client_socket, addr = server_socket.accept()

        # fork the client
        pid = os.fork()

        if pid == 0:
            print(f"Connection established with {server_socket} at {addr}")
            # receive credentials
            enc_credentials = client_socket.recv(4096)

            # load server private key and rsa cipher
            server_private_key = load_key("server_private.pem")
            rsa_cipher = PKCS1_OAEP.new(server_private_key)

            # decrypt and decode user credentials
            credentials = rsa_cipher.decrypt(enc_credentials)
            credentials = credentials.decode("ascii")

            # split credentials into username and password
            credentials = credentials.split(",")
            username = credentials[0]
            password = credentials[1]

            client_socket.send("ok".encode())

            signature = client_socket.recv(1024)

            publickey = load_key(f"{username}_public.pem")

            valid = sign_is_valid(publickey, enc_credentials, signature)

            if valid == False:
                client_socket.close()
                print("Connection Terminated invalid signature.")
            else:
                # call function to see if user is authorized
                auth = is_authorized(username, password)

                # if user is authorized generate an aes 256 key otherwise send unencrypted termination msg
                if auth == True:
                    # get client public key
                    client_public_key = load_key(f"{username}_public.pem")

                    # generate aes 256 key
                    sym_key = get_random_bytes(32)

                    # generate an rsa cipher to encrypt aes key
                    rsa_cipher = PKCS1_OAEP.new(client_public_key)

                    # encrypt sym_key using rsa_cipher
                    enc_sym_key = b"ENC:"
                    enc_sym_key = enc_sym_key + rsa_cipher.encrypt(sym_key)

                    # send to the client and print server prompt
                    client_socket.send(enc_sym_key)
                    print(
                        f"Connection Accepted and Symmetric Key Generated for client: {username}"
                    )

                    # receive OK from client
                    ok = client_socket.recv(1024)

                    # generate aes cipher encrypt menu using sym_key send to client
                    aes_cipher = AES.new(sym_key, AES.MODE_ECB)

                    menu = "Select the operations:\n\t\t1) Create and send an email\n\t\t2) Display the inbox list\n\t\t3) Display the email contents\n\t\t4) Terminate the connection\nchoice: ".encode()

                    menu = aes_cipher.encrypt(pad(menu, BLOCK_SIZE))

                    client_socket.send(menu)

                    choice = "not 4"

                    while choice != "4":
                        # receive client choice
                        choice = client_socket.recv(1024)
                        choice = aes_cipher.decrypt(choice)
                        choice = unpad(choice, BLOCK_SIZE)
                        choice = choice.decode("ascii")

                        # Control flow for users choice
                        if choice == "1":
                            email_protocol(client_socket, aes_cipher, username)
                        elif choice == "2":
                            view_inbox(username, aes_cipher, client_socket)
                        elif choice == "3":
                            view_message(client_socket, aes_cipher, username)

                    # call termination protocol
                    termination_protocol(client_socket, username)

                else:
                    # send client the response unencrypted
                    response = "Invalid username or password".encode()
                    client_socket.send(response)
                    # print prompt to server that connection has been terminated
                    print(
                        f"The received client information:is invalid (Connection Terminated)."
                    )
        else:
            client_socket.close()


################################################################
server()
