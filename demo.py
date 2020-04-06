# Author:  Mrunal Shah

# This program does the following:
#-----------------------------------#
# based on the approved NIST curve, calculates the domain parameters 
# implements Crypto math functions(gcd(), egcd(), modulo_inverse()
# implements ECC group operations(point_add(), point_double(), point_multiply()
# implements compute_session_key() for sender(Alice) and Receiver(Bob)
# implements set of RSA functions(generate_RSA_key_pair(),sign_message(), verify_message()
# implements AES_GCM_encryption(), and AES_GCM_deryption()
# implements set of sender and receiver communication functions
# Using above listed functions, program prints the original message to be encrypted,

# HOW DOES THIS PROGRAM WORK?
#---------------------------#
# Notation:  Alice(sender), Bob (receiver)
# Protocols and Techniques used:  ECC - DH, RSA, AES_GCM,PKCS V1_5(for signature) 
# ALice and Bob's public key is generated based on Eliptic Curve Cryptology and exchanged
# ALice and Bob Computes the session Key which can be used to encrypt/decrypt
# FIrst Alice sends the message to Bob.  This message is encrypted using AES_GCM
# This encrypted message is signed by Alice 
# Bob Received this signed message.  Bob first verifies Alice's signature
# if Bob is able to verify Alice's signature, Bob decrypts Alice's message
# Bob also sends the message using above described steps
# Alice verifies Bob's signature and if verified, decrypts the message


################### LIMITATION OF THIS PROGRAM #####################

# I did not set up TCP communication hence no real network communicaiton
# Encryption/Decryption of built in(hard coded) simple message for DEMO purpose
# This program can be extended to do file or video encryption/decryption

####################################################################

from Crypto.Util.number import *
import binascii
from Crypto.PublicKey import RSA
from Crypto import Random
import Crypto
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii

#curve: secp224r1 #NIST approved curve
#E:y2=x3+ax+b

# Domain Paramteres: Prime(p), Cofficient(A), Cofficient(B), generator(g), Cardinality or order(n) are listed below
# p and n verified also from FIPS 186-4, D 1.2.2

p = 26959946667150639794667015087019630673557916260026308143510066298881
A = 26959946667150639794667015087019630673557916260026308143510066298878 
B = 18958286285566608000408668544493926415504680968679321075787234672564
g = (19277929113566293071110308034699488026831934219452440156649784352033, 19926808758034470970197974370888749184205991990603949537637343198772)
n = 26959946667150639794667015087019625940457807714424391721682722368061
ad = 8355882032338256687175970479737883859254410949327016799159414742396  # ALice's Private key
bd = 26514066837753305883996537210901385382633443172214292506297895715341 # Bob - Receiver Private Key


# Crypto Math Functions
def gcd(a,b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)

def egcd(a,b):   #sa + tb and returns (s,t)
    if b == 0:
        return (1, 0)
    else:
        q,r = divmod(a, b) #quotent and remainder
        (s,t) = egcd(b,r)  
        return (t,s-q*t) # Return s, t

def modulo_inverse(a, p): #p = modulo, a to be inversed
    if gcd(a,p) == 1:  #inverse exists
        s,t = egcd(a, p)
        return s % p
    else:
        print "inverse does not exist for: ", a," mod ", p


#following set of functions provide group operations (doubling, addition, and multiplication)
#on Elliptic Curve

def point_double(pt):
    x1, y1 = pt
    x2 = x1
    y2 = y1
    s_quotent = 3 * x1 * x1 + A
    s_divisior = modulo_inverse(2 * y1, p)
    s = (s_quotent * s_divisior) % p
    x3 = (s*s - x1 -x2) % p
    y3 = (s * (x1 - x3) - y1) % p
    return (x3, y3)

def point_add(pt1, pt2):
    x1, y1 = pt1
    x2, y2 = pt2
    s_quotent = y2 - y1
    s_divisior = modulo_inverse(x2-x1, p)
    s = (s_quotent * s_divisior) % p
    x3 = (s*s - x1 -x2) % p
    y3 = (s * (x1 - x3) - y1) % p
    return (x3, y3)

def point_multiply(pt, d):
    if d == 0:
        return 0
    elif d == 1:
        return pt
    elif (d % 2 == 1):
        return point_add(pt, point_multiply(pt, d -1))
    else:
        return point_multiply(point_double(pt), d/2)

def compute_session_key(pt,d):
    return point_multiply(pt,d)


#Following set of functions generetae RSA key pair, signature and verifications

def generate_RSA_key_pair(bits):
    keyPair = RSA.generate(bits)
    pubKey = keyPair.publickey()
    return keyPair, pubKey

def sign_message(msg, KeyPair):
    hash = SHA256.new(msg)
    signer = PKCS115_SigScheme(KeyPair)
    signature = signer.sign(hash)
    print "Signature"
    print "-----------------------------------------------------------------"
    print binascii.hexlify(signature)
    print
    print
    return signature

def verify_signature(signature,pubKey,msg):
    hash = SHA256.new(msg)
    verifier = PKCS115_SigScheme(pubKey)
    try:
        verifier.verify(hash, signature)
        return 1
    except:
        return 0



#following set of functions generate AES encryption and decryption
#in GCM mode.  These functions use computed session Key as "shared Secret"
#for encryption and decryption

def AES_GCM_encryption(session_key, plain_msg):
    cipher = AES.new(session_key, AES.MODE_GCM)
    ctxt, tag = cipher.encrypt_and_digest(plain_msg)
    nonce = cipher.nonce
    return ctxt, tag, nonce

def AES_GCM_decryption(session_key, ctxt, nonce, tag):
    cipher = AES.new(session_key, AES.MODE_GCM, nonce)
    ptxt = cipher.decrypt_and_verify(ctxt,tag)
    return ptxt

#*********Sender and Receiver Communication functions

def Alice_Bob_publicKey_exchange():
    alice_public = point_multiply(g, ad)
    bob_public = point_multiply(g, bd)
    return alice_public, bob_public

def compute_Alice_session_key():
    alice_public, bob_public = Alice_Bob_publicKey_exchange()
    xAlice, yAlice = compute_session_key(bob_public, ad)      
    Alice_session_key = hashlib.md5(str(xAlice)).hexdigest() # Sender(ALice)'s Session Key, Hashed to insure 128 bit key length
    return Alice_session_key

def Alice_send_signed_encrypted_message_to_Bob(KeyPair):
    msg_to_encrypt = "From Alice to Bob: sending this message to BOB by encrypting in AES GCM Mode."
    print "Original Message from Alice that is being encrypted"
    print "--------------------------------------------------------------------------"
    print msg_to_encrypt
    print
    print

    Alice_session_key = compute_Alice_session_key()
    encrypted_msg,tag,nonce = AES_GCM_encryption(Alice_session_key, msg_to_encrypt)   # Encryption in GCM mode

    print "CIPHER text of the Alice's Message to Bob original message in hex"
    print "---------------------------------------------------------------------------"
    print encrypted_msg.encode('hex')
    print
    print

    signature = sign_message(encrypted_msg, KeyPair) #sign encrypted message with Alice's Signature
    return encrypted_msg,nonce,signature,tag

def Alice_authenticates_decrypts_message(signature, pubKey, encrypted_msg,nonce, tag):
    sig_status = verify_signature(signature ,pubKey,encrypted_msg)
    if sig_status == 1:
        print "Alice validates Bob's signature, so message will be decrypted"
        print
        Alice_session_key = compute_Alice_session_key()
        decrypted = AES_GCM_decryption(Alice_session_key, encrypted_msg,nonce, tag)
        print "Recovered Bob's Original Message"
        print "---------------------------------------------------------------------------"
        print decrypted
        print
        print

    else:
        print
        print "Bob's Signature signature NOT VALIDATED, Exiting without further processing"
        sys.exit()

def compute_Bob_session_key():
    alice_public, bob_public = Alice_Bob_publicKey_exchange()
    xBob,yBob = compute_session_key(alice_public, bd)
    Bob_session_key = hashlib.md5(str(xBob)).hexdigest()
    return Bob_session_key

def Bob_authenticates_decrypts_message(signature, pubKey, encrypted_msg,nonce, tag):
    sig_status = verify_signature(signature ,pubKey,encrypted_msg)
    if sig_status == 1:
        print "Bob validates Alice's signature, so message will be decrypted"
        print
        Bob_session_key = compute_Bob_session_key()
        decrypted = AES_GCM_decryption(Bob_session_key, encrypted_msg,nonce, tag)
        print "Recovered Alice's Original Message"
        print "---------------------------------------------------------------------------"
        print decrypted
        print
        print

    else:
        print
        print "Alice's signature NOT VALIDATED, Exiting without further processeing"
        sys.exit()

def Bob_send_signed_encrypted_message_to_Alice(KeyPair):
    msg_to_encrypt = "From Bob to Alice: sending this message to Alice by encrypting in AES GCM Mode."
    print "Original Message from Bob that is being encrypted"
    print "--------------------------------------------------------------------------"
    print msg_to_encrypt
    print
    print

    Bob_session_key = compute_Bob_session_key()
    encrypted_msg,tag,nonce = AES_GCM_encryption(Bob_session_key, msg_to_encrypt)   # Encryption in GCM mode

    print "CIPHER text of Bob's message to Alice the original message in hex"
    print "---------------------------------------------------------------------------"
    print encrypted_msg.encode('hex')
    print
    print

    signature = sign_message(encrypted_msg, KeyPair) #sign encrypted message with Alice's Signature
    return encrypted_msg,nonce,signature,tag

def main():
    KeyPair, pubKey = generate_RSA_key_pair(2048)
    encrypted_msg, nonce, signature, tag = Alice_send_signed_encrypted_message_to_Bob(KeyPair)
    Bob_authenticates_decrypts_message(signature, pubKey, encrypted_msg,  nonce,tag)

    enc_msg, bnonce, bsignature, btag = Bob_send_signed_encrypted_message_to_Alice(KeyPair)
    Alice_authenticates_decrypts_message(bsignature, pubKey, enc_msg,  bnonce,btag)


if __name__ == '__main__':
    main()


