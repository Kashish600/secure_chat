import socket
import os
import struct
import hashlib
import hmac

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = "localhost"
PORT = 5000

def recv_exact(sock, length):
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data

# Load Certificates

with open("rootCA.pem", "rb") as f:
    root_cert = x509.load_pem_x509_certificate(f.read())

with open("server.key", "rb") as f:
    server_private_key = serialization.load_pem_private_key(f.read(), None)

with open("server.crt", "rb") as f:
    server_cert_bytes = f.read()
    server_cert = x509.load_pem_x509_certificate(server_cert_bytes)

def verify_certificate(cert_bytes):
    cert = x509.load_pem_x509_certificate(cert_bytes)
    root_cert.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm
    )
    return cert

# Key Derivation

def derive_keys(shared_secret, nonceA, nonceB):
    key_material = hashlib.sha256(shared_secret + nonceA + nonceB).digest()
    return key_material[:16], key_material[16:]

# Encryption 

def encrypt_message(enc_key, mac_key, seq, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    header = struct.pack("I", seq) + iv + ciphertext
    mac = hmac.new(mac_key, header, hashlib.sha256).digest()

    return header + mac

def decrypt_message(enc_key, mac_key, data):
    seq = struct.unpack("I", data[:4])[0]
    iv = data[4:20]
    mac_received = data[-32:]
    ciphertext = data[20:-32]

    mac_calculated = hmac.new(mac_key, data[:-32], hashlib.sha256).digest()
    if mac_received != mac_calculated:
        raise Exception("MAC verification failed")

    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return seq, plaintext.decode()


server = socket.socket()
server.bind((HOST, PORT))
server.listen(1)

print("Server listening...")
conn, addr = server.accept()
print("Connected:", addr)

# Certificate Exchange 

client_cert_bytes = recv_exact(conn, 1236)
client_cert = verify_certificate(client_cert_bytes)
conn.send(server_cert_bytes)

#ECDH Handshake 

server_ec_private = ec.generate_private_key(ec.SECP256R1())
server_ec_public = server_ec_private.public_key()
server_nonce = os.urandom(16)

server_ec_public_bytes = server_ec_public.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
)

signature = server_private_key.sign(
    server_ec_public_bytes + server_nonce,
    padding.PKCS1v15(),
    hashes.SHA256()
)

# Send structured
conn.send(struct.pack("I", len(server_ec_public_bytes)))
conn.send(server_ec_public_bytes)
conn.send(server_nonce)
conn.send(struct.pack("I", len(signature)))
conn.send(signature)

# Receive structured
length = struct.unpack("I", recv_exact(conn, 4))[0]
client_ec_public_bytes = recv_exact(conn, length)
client_nonce = recv_exact(conn, 16)
sig_length = struct.unpack("I", recv_exact(conn, 4))[0]
client_signature = recv_exact(conn, sig_length)

client_cert.public_key().verify(
    client_signature,
    client_ec_public_bytes + client_nonce,
    padding.PKCS1v15(),
    hashes.SHA256()
)

client_ec_public = serialization.load_pem_public_key(client_ec_public_bytes)
shared_secret = server_ec_private.exchange(ec.ECDH(), client_ec_public)

enc_key, mac_key = derive_keys(shared_secret, client_nonce, server_nonce)

print("Secure channel established.")

seq_send = 0

while True:
    data = conn.recv(8192)
    seq, message = decrypt_message(enc_key, mac_key, data)
    print("Client:", message)

    reply = input("You: ")
    packet = encrypt_message(enc_key, mac_key, seq_send, reply)
    conn.send(packet)
    seq_send += 1