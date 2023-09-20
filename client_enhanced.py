import re
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

# global variables
server_port = 13000
BLOCK_SIZE = 32


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


def encrypted_message_digest(message, public_key):
    """
    Purpose: Encrypt message using server public key

    Parameters:
        message (str): message to be encrypted
        public_key (bstr): server public key
    Returns:
        encrypted_message (bstr): encrypted message digest
    """
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    enc_msg = cipher.encrypt(message)
    encrypted_message_digest = SHA256.new(enc_msg).digest()
    return encrypted_message_digest


def sign_message(private_key, m_digest):
    """
    Purpose: Sign message using clients private key

    Parameter:
        private_key(bstr): Clients private key
        m_disgest(bstr): message digest to be signed

    Return:
        signature (bstr): signature

    """
    h = SHA256.new(m_digest)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature


def is_encrypted(message):
    """
    Purpose: determin whether a response starts with ENC: indicating encryption

    Parameters:
        message(str): message we want to determine is encrypted or not

    returns:
        True(bool) if response starts with ENC:
        False(bool) otherwise
    """
    prefix = b"ENC:"
    return message.startswith(prefix)


def termination_protocol(client_socket):
    """
    Purpose: Terminate our session with the client

    Parameters:
        client_socket: user connection socket

    Returns: None
    """
    client_socket.close()
    print("The connection is terminated with the server")


def upload_file():
    """
    Purpose: Upload file contents into a variable

    Parameters: None

    Returns:
        msg(str): contents of the file
    """
    filename = input("Enter filename: ")
    try:
        with open(filename, "r") as file:
            msg = file.read()
            return msg
    except FileNotFoundError:
        print("File not found. Please make sure it exists")
        return None


def email_protocol(client_socket, aes_cipher, username):
    """
    Purpose: Run our send email protocol

    Parameters:
        client_socket: user connection

    Return: None
    """
    # receive msg to send email from the server
    msg = client_socket.recv(4096)
    # decrypt and unpad msg
    msg = aes_cipher.decrypt(msg)
    msg = unpad(msg, BLOCK_SIZE)
    msg = msg.decode()

    # ask user email destination usernames separated by ;
    users = input("Enter destinations (separated by ;): ")
    # ask user for the title
    title = input("Enter title: ")
    # ask user if they want to load their message from a file
    load = input("Would you like to load contents from a file?(Y/N): ").upper()

    if load in ("Y", "N"):
        pass
    else:
        print("Invalid input please enter either y or n")

    if load == "Y":
        content = upload_file()
        while content == None:
            content = upload_file()

        while len(content) > 1000000:
            reupload = input(
                "File to large (>1000000) would you like to uplaod another file(Y/N): "
            ).upper()
            while reupload != "Y" or reupload != "N":
                reupload = input("Would you like to upload another file(Y/N): ").upper()
            if reupload == "Y":
                content = upload_file()
                while content == None:
                    content = upload_file()

    elif load == "N":
        content = input("Enter message contents: ")
        while len(content) > 1000000:
            content = input("Msg too long please re-enter msg (<1000000 chars): ")

    else:
        load = input
    # construct the message to be sent
    email = f"{username},{users},{title},{len(content)},{content}".encode()

    # encrypt the message
    enc_email = aes_cipher.encrypt(pad(email, BLOCK_SIZE))
    file_size = str(len(enc_email)).encode()
    enc_file_size = aes_cipher.encrypt(pad(file_size, BLOCK_SIZE))

    # send to the file size to server wait for ok and then send email and print prompt to user
    client_socket.send(enc_file_size)
    ok = client_socket.recv(1024)
    client_socket.send(enc_email)
    print("The message has been sent to the server")


def view_inbox(client_socket, aes_cipher):
    """
    Purpose: Display content of our inbox

    Parameters:
            client_socket : socket connection to server
            aes_cipher : AES cipher to encrypt/decrypt messages
    Returns: None
    """
    # receive contents of inbox
    fsize = client_socket.recv(4096)

    # decrypt fsize
    fsize = aes_cipher.decrypt(fsize)
    fsize = unpad(fsize, BLOCK_SIZE)
    fsize = fsize.decode("ascii")
    fsize = int(fsize)

    if fsize == 0:
        print("You have no messages")

    else:
        # send ok
        client_socket.send("OK".encode())

        # receive inbox
        inbox = b""
        while len(inbox) < fsize:
            data = client_socket.recv(4096)
            inbox += data

        # decrypt inbox
        inbox = aes_cipher.decrypt(inbox)
        inbox = unpad(inbox, BLOCK_SIZE)
        inbox = inbox.decode("ascii")

        inbox = inbox.split(",")

        # print inbox
        print("Index\tFrom\t\tDatetime\t\t\t\t\t\t\tTitle")
        for index, item in enumerate(inbox):
            (
                sender,
                date,
            ) = item.split(";")
            # get title from our filename
            title = sender.split("_")[1]
            # cut out .txt from our title
            title = title.replace(".txt", "")
            # grab who the email is from
            sender = sender.split("_")[0]
            print(f"{index}\t\t{sender}\t\t{date}\t\t\t{title}")


def view_message(client_socket, aes_cipher):
    """
    Purpose : View a particular message in users inbox

    Parameters :
            client_socket : socket connection with server
            aes_cipher : AES cipher for symmetric encryption and decryption

    Returns:    None
    """
    # receive encrypted prompt from server
    enc_prompt = client_socket.recv(4096)

    # decrypt, unpad, decode prompt
    enc_prompt = aes_cipher.decrypt(enc_prompt)
    enc_prompt = unpad(enc_prompt, BLOCK_SIZE)
    prompt = enc_prompt.decode("ascii")

    # display prompt get user input
    choice = input(prompt)

    # encode, pad, encrypt choice
    choice = choice.encode()
    choice = pad(choice, BLOCK_SIZE)
    enc_choice = aes_cipher.encrypt(choice)

    # send to server
    client_socket.send(enc_choice)

    # receive encrypted file size to be received
    enc_fsize = client_socket.recv(4096)
    fsize = aes_cipher.decrypt(enc_fsize)
    fsize = unpad(fsize, BLOCK_SIZE)
    fsize = int(fsize.decode("ascii"))

    if fsize == 0:
        print("No messages")
    else:
        # send ok to server
        client_socket.send("OK".encode())
        msg = b""
        while len(msg) < fsize:
            data = client_socket.recv(4096)
            msg += data

        # decrypt msg, unpad msg, decode msg, print msg
        msg = aes_cipher.decrypt(msg)
        msg = unpad(msg, BLOCK_SIZE)
        msg = msg.decode("ascii")
        print(msg)


def Sign_message(key, message):
    """
    Purpose : Make signatures out of message given%%%

    Parameters :
            key : Clients private key, used to sign message given
            message : message to be signed

    Returns:    Signature: the signed message in a hash format
    """
    h = SHA256.new(message)  # make hash of message
    signature = pkcs1_15.new(key).sign(h)  # use hash to make signature
    return signature


def client():
    """
    Purpose: Runs the client side of our secure mail transfer protocol app

    Parameters: None

    Returns: None
    """
    # grab server name from user
    server_name = input("Enter the server IP or name: ")

    # create TCP socket and connect to server
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print("Error in creating client socket", e)
        sys.exit(1)

    # connect to server
    try:
        client_socket.connect((server_name, server_port))

        # request username and password from user
        username = input("Enter your username: ")
        password = input("Enter your password: ")

        # load keys create rsa cipher
        server_public_key = load_key("server_public.pem")
        rsa_cipher = PKCS1_OAEP.new(server_public_key)
        private_key = load_key(f"{username}_private.pem")

        # encrypt credentials and send to server for authorization
        credentials = f"{username},{password}".encode()
        enc_credentials = rsa_cipher.encrypt(credentials)
        signature = sign_message(private_key, enc_credentials)

        client_socket.send(enc_credentials)

        ok = client_socket.recv(1024)

        client_socket.send(signature)

        # receive symm key if authorized otherwise terminate connection
        response = client_socket.recv(4096)
        encrypted = is_encrypted(response)

        # control flow on whether response is encrypted or not
        if encrypted == False:
            response = response.decode("ascii")
            print(f"{response}\nTerminating.")
            client_socket.close()
            sys.exit(0)
        else:
            # load client public key and decrypt symmetric key
            client_private_key = load_key(f"{username}_private.pem")
            rsa_cipher = PKCS1_OAEP.new(client_private_key)
            response = response[4:]
            sym_key = rsa_cipher.decrypt(response)
            # send OK bcak to the server
            ok = "OK".encode()
            client_socket.send(ok)

            # receive and decrypt menu from server
            menu = client_socket.recv(4096)
            aes_cipher = AES.new(sym_key, AES.MODE_ECB)
            menu = aes_cipher.decrypt(menu)
            menu = unpad(menu, BLOCK_SIZE)
            menu = menu.decode("ascii")

            choice = "placeholder"

            while choice != "4":
                # print menu and prompt user for their choice
                choice = input(menu)

                # encrypt choice with symmetric key and send to server
                response = choice.encode()
                response = pad(response, BLOCK_SIZE)
                response = aes_cipher.encrypt(response)
                client_socket.send(response)

                # control flow depending on user choice
                if choice == "1":
                    email_protocol(client_socket, aes_cipher, username)
                elif choice == "2":
                    view_inbox(client_socket, aes_cipher)
                elif choice == "3":
                    view_message(client_socket, aes_cipher)

            # call termination protocol
            termination_protocol(client_socket)

    except socket.error as e:
        print("Error has occured: ", e)
        client_socket.close()
        sys.exit(1)


################################################################
client()
