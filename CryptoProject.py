from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, dsa, ec
import os
import time
#
#
#
#ECC
#
#
#
#
#
beforeECC1024 = time.perf_counter()
private_keyECC1024 = ec.generate_private_key(
    ec.SECP192R1()
)

public_keyECC1024 = private_keyECC1024.public_key()
afterECC1024 = time.perf_counter()

beforeECC2048 = time.perf_counter()
private_keyECC2048 = ec.generate_private_key(
    ec.SECP192R1()
)

public_keyECC2048 = private_keyECC2048.public_key()
afterECC2048 = time.perf_counter()

beforeECC7680 = time.perf_counter()
private_keyECC7680 = ec.generate_private_key(
    ec.SECP192R1()
)

public_keyECC7680 = private_keyECC7680.public_key()
afterECC7680 = time.perf_counter()

beforeECC15360 = time.perf_counter()
private_keyECC15360 = ec.generate_private_key(
    ec.SECP192R1()
)

public_keyECC15360 = private_keyECC15360.public_key()
afterECC15360 = time.perf_counter()
#
#
#
#SIGN ECC
#
#
#

message = os.urandom(50)

beforeECCSIGN1024 = time.perf_counter()
# We can sign the message using "hash-then-sign".
signatureECC1024 = private_keyECC1024.sign(
    message,
    ec.ECDSA(hashes.SHA256())
)
afterECCSIGN1024 = time.perf_counter()

beforeECCSIGN2048 = time.perf_counter()
# We can sign the message using "hash-then-sign".
signatureECC2048 = private_keyECC2048.sign(
    message,
    ec.ECDSA(hashes.SHA256())
)
afterECCSIGN2048 = time.perf_counter()

beforeECCSIGN7680 = time.perf_counter()
# We can sign the message using "hash-then-sign".
signatureECC7680 = private_keyECC7680.sign(
    message,
    ec.ECDSA(hashes.SHA256())
)
afterECCSIGN7680 = time.perf_counter()

beforeECCSIGN15360 = time.perf_counter()
# We can sign the message using "hash-then-sign".
signatureECC15360 = private_keyECC15360.sign(
    message,
    ec.ECDSA(hashes.SHA256())
)
afterECCSIGN15360 = time.perf_counter()
#
#
#
#ECC VERIFY
#
#
#
# We can verify the signature.  If the signature is invalid it will
# raise an Exception.
beforeECCVERIFY1024 = time.perf_counter()
public_keyECC1024.verify(
    signatureECC1024,
    message,
    ec.ECDSA(hashes.SHA256())
)
afterECCVERIFY1024 = time.perf_counter()

beforeECCVERIFY2048 = time.perf_counter()
public_keyECC2048.verify(
    signatureECC2048,
    message,
    ec.ECDSA(hashes.SHA256())
)
afterECCVERIFY2048 = time.perf_counter()

beforeECCVERIFY7680 = time.perf_counter()
public_keyECC7680.verify(
    signatureECC7680,
    message,
    ec.ECDSA(hashes.SHA256())
)
afterECCVERIFY7680 = time.perf_counter()

beforeECCVERIFY15360 = time.perf_counter()
public_keyECC15360.verify(
    signatureECC15360,
    message,
    ec.ECDSA(hashes.SHA256())
)
afterECCVERIFY15360 = time.perf_counter()

#print()
#print("Message: " + message.hex())
#print()
#print("Signature: " + signatureECC1024.hex())
#print()
#print("Signature: " + signatureECC2048.hex())
#print()
#print("Signature: " + signatureECC7680.hex())
#print()
#print("Signature: " + signatureECC15360.hex())
#
#
#
#
#ECC END
#
#
#
#
#
#DSA START
#
#
#
beforeDSA1024 = time.perf_counter()
private_keyDSA1024 = dsa.generate_private_key(
    key_size=1024
)

public_keyDSA1024 = private_keyDSA1024.public_key()
afterDSA1024 = time.perf_counter()

beforeDSA2048 = time.perf_counter()
private_keyDSA2048 = dsa.generate_private_key(
    key_size=2048 
)

public_keyDSA2048  = private_keyDSA2048 .public_key()
afterDSA2048= time.perf_counter()







message = os.urandom(50)

beforeDSASIGN1024 = time.perf_counter()
# We can sign the message using "hash-then-sign".
signatureDSA1024 = private_keyDSA1024.sign(
    message,
    hashes.SHA256()
)
afterDSASIGN1024 = time.perf_counter()

beforeDSASIGN2048 = time.perf_counter()
# We can sign the message using "hash-then-sign".
signatureDSA2048 = private_keyDSA2048.sign(
    message,
    hashes.SHA256()
)
afterDSASIGN2048 = time.perf_counter()


beforeDSAVERIFY1024 = time.perf_counter()
# We can verify the signature.  If the signature is invalid it will
# raise an Exception.
public_keyDSA1024.verify(
    signatureDSA1024,
    message,
    hashes.SHA256()
)
afterDSAVERIFY1024 = time.perf_counter()

beforeDSAVERIFY2048 = time.perf_counter()
# We can verify the signature.  If the signature is invalid it will
# raise an Exception.
public_keyDSA2048.verify(
    signatureDSA2048,
    message,
    hashes.SHA256()
)
afterDSAVERIFY2048 = time.perf_counter()



#print()
#print("Message: " + message.hex())
#print()
#print("Signature: " + signatureDSA1024.hex())
#print()
#print("Signature: " + signatureDSA2048.hex())
#print()
#print("Signature: " + signatureDSA7680.hex())
#print()
#print("Signature: " + signatureDSA15360.hex())

#
#
#
#
#DSA END
#
#
#
#
#KEY PAIR GEN FOR RSA START
#
#
#
before1024 = time.perf_counter()

private_key1024 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024
)
after1024 = time.perf_counter()

before2048 = time.perf_counter()

private_key2048 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

after2048 = time.perf_counter()

before7680 = time.perf_counter()

private_key7680 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=7680
)

after7680 = time.perf_counter()

before15360 = time.perf_counter()

private_key15360 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=15360
)

after15360 = time.perf_counter()
#
#
#
#
#
#
#
#KEYPAIR GENERATION FOR RSA END
#
#
#
#
#
#
#

public_key1024= private_key1024.public_key()
public_key2048= private_key2048.public_key()
public_key7680 = private_key7680.public_key()
public_key15360 = private_key15360.public_key()
#
#
#
#
#RSA SIGN
message = os.urandom(1024)

# We can sign the message using "hash-then-sign".
beforeRSASIGN1024 = time.perf_counter()
signatureRSA1024 = private_key1024.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
afterRSASIGN1024 = time.perf_counter()

beforeRSASIGN2048 = time.perf_counter()
signatureRSA2048 = private_key2048.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
afterRSASIGN2048 = time.perf_counter()

beforeRSASIGN7680 = time.perf_counter()
signatureRSA7680 = private_key7680.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
afterRSASIGN7680 = time.perf_counter()

beforeRSASIGN15360 = time.perf_counter()
signatureRSA15360 = private_key15360.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
afterRSASIGN15360 = time.perf_counter()
#
#
#RSA VERIFY
#
#
# We can verify the signature.  If the signature is invalid it will
# raise an Exception.
beforeRSAVERIFY1024 = time.perf_counter()
public_key1024.verify(
    signatureRSA1024,
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
afterRSAVERIFY1024 = time.perf_counter()

beforeRSAVERIFY2048 = time.perf_counter()
public_key2048.verify(
    signatureRSA2048,
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
afterRSAVERIFY2048 = time.perf_counter()

beforeRSAVERIFY7680 = time.perf_counter()
public_key7680.verify(
    signatureRSA7680,
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
afterRSAVERIFY7680 = time.perf_counter()

beforeRSAVERIFY15360 = time.perf_counter()
public_key15360.verify(
    signatureRSA15360,
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
afterRSAVERIFY15360 = time.perf_counter()

#print()
#print("Message: " + message.hex())
#print()
#print("Signature: " + signatureRSA1024.hex())
#print()
#print("Signature: " + signatureRSA2048.hex())
#print()
#print("Signature: " + signatureRSA7680.hex())
#print()
#print("Signature: " + signatureRSA15360.hex())
#
public_key_str1024 = public_key1024.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.PKCS1
)
public_key_str2048 = public_key2048.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.PKCS1
)
public_key_str7680 = public_key7680.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.PKCS1
)
public_key_str15360 = public_key15360.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.PKCS1
)

long_plaintext = os.urandom(10 * 1024)



def split_message(message, chunk_size):
    return [message[i:i+chunk_size] for i in range(0, len(message), chunk_size)]

def encrypt_message(public_key, message, chunk_size):
    encrypted_chunks = []
    for chunk in split_message(message, chunk_size):
        encrypted_chunks.append(public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ))
    return encrypted_chunks

def decrypt_message(private_key, encrypted_chunks):
    decrypted_chunks = []
    for chunk in encrypted_chunks:
        decrypted_chunks.append(private_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ))
    return b"".join(decrypted_chunks)
#
#
#
#print("Plaintext: " + long_plaintext.hex())
#print("Ciphertext: " + long_ciphertext.hex())
#print("Original Plaintext: " + long_plaintext_2.hex())

#Keypair generation for RSA
print(f"{after1024 - before1024:0.4f} seconds for 80 Bytes RSA")
print(f"{after2048 - before2048:0.4f} seconds for 112 Bytes RSA")
print(f"{after7680 - before7680:0.4f} seconds for 192 Bytes RSA")
print(f"{after15360 - before15360:0.4f} seconds for 256 Bytes RSA")

#Keypair generation for DSA
print(f"{afterDSA1024 - beforeDSA1024:0.4f} seconds for 80 Bytes DSA")
print(f"{afterDSA2048 - beforeDSA2048:0.4f} seconds for 112 Bytes DSA")


#RSA SIGNATURE 
print(f"{afterRSASIGN1024 - beforeRSASIGN1024:0.4f} seconds for 80 Bytes RSA to sign")
print(f"{afterRSASIGN2048 - beforeRSASIGN2048:0.4f} seconds for 112 Bytes RSA to sign")
print(f"{afterRSASIGN7680 - beforeRSASIGN7680:0.4f} seconds for 192 Bytes RSA to sign")
print(f"{afterRSASIGN15360 - beforeRSASIGN15360:0.4f} seconds for 256 Bytes RSA to sign")

#RSA VERIFY
print(f"{afterRSAVERIFY1024 - beforeRSAVERIFY1024:0.4f} seconds for 80 Bytes RSA to verify signature")
print(f"{afterRSAVERIFY2048 - beforeRSAVERIFY2048:0.4f} seconds for 112 Bytes RSA to verify signature")
print(f"{afterRSAVERIFY7680 - beforeRSAVERIFY7680:0.4f} seconds for 192 Bytes RSA to verify signature")
print(f"{afterRSAVERIFY15360 - beforeRSAVERIFY15360:0.4f} seconds for 256 Bytes RSA to verify signature")

#DSA SIGNATURE 
print(f"{afterDSASIGN1024 - beforeDSASIGN1024:0.4f} seconds for 80 Bytes DSA to sign")
print(f"{afterDSASIGN2048 - beforeDSASIGN2048:0.4f} seconds for 112 Bytes DSA to sign")

#DSA VERIFY
print(f"{afterDSAVERIFY1024 - beforeDSAVERIFY1024:0.4f} seconds for 80 Bytes DSA to verify signature")
print(f"{afterDSAVERIFY2048 - beforeDSAVERIFY2048:0.4f} seconds for 112 Bytes DSA to verify signature")


#Keypair generation for ECC
print(f"{afterECC1024 - beforeECC1024:0.4f} seconds for 80 Bytes ECC")
print(f"{afterECC2048 - beforeECC2048:0.4f} seconds for 112 Bytes ECC")
print(f"{afterECC7680 - beforeECC7680:0.4f} seconds for 192 Bytes ECC")
print(f"{afterECC15360 - beforeECC15360:0.4f} seconds for 256 Bytes ECC")

#ECC SIGNATURE 
print(f"{afterECCSIGN1024 - beforeECCSIGN1024:0.4f} seconds for 80 Bytes ECC to sign")
print(f"{afterECCSIGN2048 - beforeECCSIGN2048:0.4f} seconds for 112 Bytes ECC to sign")
print(f"{afterECCSIGN7680 - beforeECCSIGN7680:0.4f} seconds for 192 Bytes ECC to sign")
print(f"{afterECCSIGN15360 - beforeECCSIGN15360:0.4f} seconds for 256 Bytes ECC to sign")

#ECC VERIFY
print(f"{afterECCVERIFY1024 - beforeECCVERIFY1024:0.4f} seconds for 80 Bytes ECC to verify signature")
print(f"{afterECCVERIFY2048 - beforeECCVERIFY2048:0.4f} seconds for 112 Bytes ECC to verify signature")
print(f"{afterECCVERIFY7680 - beforeECCVERIFY7680:0.4f} seconds for 192 Bytes ECC to verify signature")
print(f"{afterECCVERIFY15360 - beforeECCVERIFY15360:0.4f} seconds for 256 Bytes ECC to verify signature")


#ENCRYPT
before1024E = time.perf_counter()
long_ciphertext1024 = encrypt_message(public_key1024, long_plaintext, 32)
after1024E = time.perf_counter()

before2048E = time.perf_counter()
long_ciphertext2048 = encrypt_message(public_key2048, long_plaintext, 32)
after2048E = time.perf_counter()

before7680E = time.perf_counter()
long_ciphertext7680 = encrypt_message(public_key7680, long_plaintext, 32)
after7680E = time.perf_counter()

before15360E = time.perf_counter()
long_ciphertext15360 = encrypt_message(public_key15360, long_plaintext, 32)
after15360E = time.perf_counter()


#We can decrypt the ciphertext.
#before1024D = time.perf_counter()
#long_plaintext1024 = decrypt_message(private_key1024, long_ciphertext1024)
# long_plaintext1024= private_key1024.decrypt(
#     long_ciphertext1024,
#     padding.OAEP(
#         mgf=padding.MGF1(algorithm=hashes.SHA256()),
#         algorithm=hashes.SHA256(),
#         label=None
#     )
# )
#after1024D = time.perf_counter()

#before2048D = time.perf_counter()
#long_plaintext2048= private_key2048.decrypt(
#    long_ciphertext2048,
##    padding.OAEP(
#       mgf=padding.MGF1(algorithm=hashes.SHA256()),
#        algorithm=hashes.SHA256(),
#        label=None
#    )
#)
#after2048D = time.perf_counter()

#before7680D = time.perf_counter()
#long_plaintext7680= private_key7680.decrypt(
#   long_ciphertext7680,
#    padding.OAEP(
#        mgf=padding.MGF1(algorithm=hashes.SHA256()),
#        algorithm=hashes.SHA256(),
#        label=None
#    )
#)
#after7680D = time.perf_counter()

#before15360D = time.perf_counter()
#long_plaintext15360= private_key15360.decrypt(
#   long_ciphertext15360,
#    padding.OAEP(
#        mgf=padding.MGF1(algorithm=hashes.SHA256()),
#       algorithm=hashes.SHA256(),
#       label=None
#    )
#)
#after15360D = time.perf_counter()



#DECRYPT#
before1024D = time.perf_counter()
long_plaintext_1024 = decrypt_message(private_key1024, long_ciphertext1024)
after1024D = time.perf_counter()

before2048D = time.perf_counter()
long_plaintext_2048 = decrypt_message(private_key2048, long_ciphertext2048)
after2048D = time.perf_counter()

before7680D = time.perf_counter()
long_plaintext_7680 = decrypt_message(private_key7680, long_ciphertext7680)
after7680D = time.perf_counter()


before15360D = time.perf_counter()
long_plaintext_15360 = decrypt_message(private_key15360, long_ciphertext15360)
after15360D = time.perf_counter()

print(f"{after1024E - before1024E:0.4f} seconds for 80 Bytes RSA Encryption")
print(f"{after2048E - before2048E:0.4f} seconds for 112 Bytes RSA Encryption")
print(f"{after7680E - before7680E:0.4f} seconds for 192 Bytes RSA Encryption")
print(f"{after15360E - before15360E:0.4f} seconds for 256 Bytes RSA Encryption")

print(f"{after1024D - before1024D:0.4f} seconds for 80 Bytes RSA Decryption")
print(f"{after2048D - before2048D:0.4f} seconds for 112 Bytes RSA Decryption")
print(f"{after7680D - before7680D:0.4f} seconds for 192 Bytes RSA Decryption")
print(f"{after15360D - before15360D:0.4f} seconds for 256 Bytes RSA Decryption")