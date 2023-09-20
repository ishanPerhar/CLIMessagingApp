
import re
import socket
import os
import sys
import json
import random
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, HMAC

block_size = 32



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
    except(ValueError, TypeError):
        return False


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


symkey = get_random_bytes(32)

spubkey = load_key("server_public.pem")
print(f"server pub key: {spubkey}")
sprivkey = load_key("server_private.pem")
print(f"server priv key: {sprivkey}")
cpubkey = load_key("client1_public.pem")
print(f"Client pub key: {cpubkey}")
cprivkey = load_key("client1_private.pem")
print(f"Client priv key: {cprivkey}")

user ='username'
passwd = 'password'


rsa_cipher = PKCS1_OAEP.new(spubkey)
rsa_sign_cipher = pkcs1_15.new(spubkey)

print(f"Cipher: {rsa_cipher}")
print(f"sign cipher: {rsa_sign_cipher}")

msg = f"{user},{passwd}".encode()


signature = Sign_message(cprivkey, msg)
print(f"signature: {signature}")

data = f"{msg},{signature}"
print(f"data: {data}")

encData = rsa_cipher.encrypt(data)
print(f"encData: {encData}")


rsa_cipher1 = PKCS1_OAEP.new(sprivkey)

verify = sign_is_valid(cpubkey, enc_msg, signature)
print(f"sig match: {verify}")
