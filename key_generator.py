from Crypto.PublicKey import RSA

'''
Purpose: Generates private key for a given user

Parameters:
    str: user (whos the key for?)

Returns: None
'''
def generatePrivateKey(user):
    key = RSA.generate(2048)
    prvKey = key.export_key()
    filename = f"{user}" + "_private.pem"
    fOut = open(filename, "wb")
    fOut.write(prvKey)
    fOut.close()

'''
Purpose: Generates public key for a given user

Parameters:
    str: user (whos the key for?)

Returns: None
'''
def generatePublicKey(user):
    key = RSA.generate(2048)
    pubKey = key.publickey().export_key()
    filename = f"{user}"+"_public.pem"
    fOut = open(filename, "wb")
    fOut.write(pubKey)
    fOut.close()

def generate_keys(user):
    key = RSA.generate(2048)

    prvKey = key.export_key()
    filename = f"{user}" + "_private.pem"
    fOut = open(filename, "wb")
    fOut.write(prvKey)
    fOut.close()

    pubKey = key.publickey().export_key()
    filename = f"{user}"+"_public.pem"
    fOut = open(filename, "wb")
    fOut.write(pubKey)
    fOut.close()


#================================================================================================

#list of clients to iterate over to create keys
clients = ["client1", "client2", "client3", "client4", "client5"]

#key = RSA.generate(2048)

#for loop to create keys for each client
'''
for user in clients:
    generatePublicKey(user)
    generatePrivateKey(user)

#generates key for server
generatePrivateKey('server')
generatePublicKey('server')
'''
for user in clients:
    generate_keys(user)

generate_keys('server')
