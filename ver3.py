from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
import subprocess

# get random number x times to use as seed
def getNumbers(size):
    p = subprocess.Popen('./genRNG.exe',shell=False,stdout=subprocess.PIPE)
    number = int(p.stdout.read())
    number = number.to_bytes(1,'big')
    priv_number = number
    for i in range(1,size):
        p = subprocess.Popen('./genRNG.exe',shell=False,stdout=subprocess.PIPE)
        number = int(p.stdout.read())
        number = number.to_bytes(1,'big')
        priv_number += number
    priv_number = int.from_bytes(priv_number, 'big')
    return priv_number + 1

# generate key from seed
def genKey():
    private_value = getNumbers(3)
    curve = ec.SECP256R1()
    priv_key = ec.derive_private_key(private_value, curve)

    return priv_key

# save private key to file
def savePrivKey(pk, filename = 'privkey.txt'):
    pem = pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

# load private key from file
def loadPrivKey(filename = 'privkey.txt'):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = load_pem_private_key(pemlines, None, default_backend())
    return private_key

def savePubKey(pk, filename = 'pubkey.txt'):
    pem = pk.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

def loadPubKey(filename = 'pubkey.txt'):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    pub_key = load_pem_public_key(pemlines, default_backend())
    return pub_key

if __name__ == '__main__':
    # hashing algorith used in generating signature
    signature_algorithm = ec.ECDSA(hashes.SHA256())
    
    try:
        # load keys from file
        priv_key = loadPrivKey()
        pub_key = loadPubKey()
    except:
        # generating private key
        priv_key = genKey()
        print('Private key: 0x%x' % priv_key.private_numbers().private_value)
        # generate public key from private key
        pub_key = priv_key.public_key()
        # save keys to file
        savePrivKey(priv_key)
        savePubKey(pub_key)
    
    print('Private key: 0x%x' % priv_key.private_numbers().private_value)
    print('Public key: 0x%s' % pub_key.public_bytes(serialization.Encoding.X962,
                                                                   serialization.PublicFormat.CompressedPoint).hex())

    # set text to sign
    text = "test text"
    text = bytes(text, "utf-8")
    # sign text
    signature = priv_key.sign(text, signature_algorithm)

    # set modified text
    #text = b"modified test text"

    print('Signature: 0x%s' % signature.hex())

    # check if signature is valid for this text
    try:
        pub_key.verify(signature, text, signature_algorithm)
        print('Verification OK')
    except InvalidSignature:
        print('Verification failed')

    input()
    