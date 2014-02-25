def encrypt_RSA(key, message):
    '''
    param: public_key_loc Path to public key
    param: message String to be encrypted
    return base64 encoded encrypted string
    '''
    from M2Crypto import RSA, BIO 
    #key = open(public_key_loc, "r").read() 
    pubkey = str(key).encode('utf8') 
    bio = BIO.MemoryBuffer(pubkey) 
    rsa = RSA.load_pub_key_bio(bio) 
    encrypted = rsa.public_encrypt(message, RSA.pkcs1_oaep_padding)
    return encrypted.encode('base64')
    
def generate_RSA(bits=8192):
    '''
    Generate an RSA keypair with an exponent of 65537 in PEM format
    param: bits The key length in bits
    Return private key and public key
    '''
    from M2Crypto import RSA, BIO
    new_key = RSA.gen_key(bits, 65537)
    memory = BIO.MemoryBuffer()
    new_key.save_key_bio(memory, cipher=None)
    private_key = memory.getvalue()
    new_key.save_pub_key_bio(memory)
    return private_key, memory.getvalue()

def decrypt_RSA(key, package):
    '''
    param: public_key_loc Path to your private key
    param: package String to be decrypted
    return decrypted string
    '''
    from base64 import b64decode 
    from M2Crypto import BIO, RSA 
    #key = open(private_key_loc, "r").read() 
    priv_key = BIO.MemoryBuffer(key.encode('utf8')) 
    key = RSA.load_key_bio(priv_key) 
    decrypted = key.private_decrypt(b64decode(package), RSA.pkcs1_oaep_padding) 
    return decrypted

message = "I HAVE THE COOLEST THING TO SHOW DEVAN!!!"
keys = generate_RSA();
privatekey = keys[0]
publickey = keys[1]
crypttext = encrypt_RSA(publickey,message)
plaintext = decrypt_RSA(privatekey,crypttext)
print plaintext
