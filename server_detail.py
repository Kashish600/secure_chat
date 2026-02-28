import socket
import os
import struct
import hashlib
import hmac

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DEBUG = True
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

# Load certificates
with open("rootCA.pem", "rb") as f:
    root_cert = x509.load_pem_x509_certificate(f.read())

with open("server.key", "rb") as f:
    server_private_key = serialization.load_pem_private_key(f.read(), None)

with open("server.crt", "rb") as f:
    server_cert_bytes = f.read()
    server_cert = x509.load_pem_x509_certificate(server_cert_bytes)

def verify_certificate(cert_bytes):
    cert = x509.load_pem_x509_certificate(cert_bytes)
    if DEBUG:
        print("\n--- Certificate Verification ---")
        print("Subject:", cert.subject)
        print("Issuer:", cert.issuer)

    root_cert.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm
    )

    if DEBUG:
        print("Certificate verified successfully.\n")

    return cert

def derive_keys(shared_secret, nonceA, nonceB):
    key_material = hashlib.sha256(shared_secret + nonceA + nonceB).digest()
    enc_key = key_material[:16]
    mac_key = key_material[16:]

    if DEBUG:
        print("Shared Secret:", shared_secret.hex())
        print("Derived Encryption Key:", enc_key.hex())
        print("Derived MAC Key:", mac_key.hex(), "\n")

    return enc_key, mac_key

def encrypt_message(enc_key, mac_key, seq, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    header = struct.pack("I", seq) + iv + ciphertext
    mac = hmac.new(mac_key, header, hashlib.sha256).digest()

    if DEBUG:
        print("\n--- Encrypting Message ---")
        print("Plaintext:", plaintext)
        print("IV:", iv.hex())
        print("Ciphertext:", ciphertext.hex())
        print("HMAC:", mac.hex(), "\n")

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

    if DEBUG:
        print("\n--- Decrypting Message ---")
        print("Sequence:", seq)
        print("HMAC Verified Successfully")
        print("Decrypted Plaintext:", plaintext.decode(), "\n")

    return seq, plaintext.decode()

server = socket.socket()
server.bind((HOST, PORT))
server.listen(1)

print("Server listening...")
conn, addr = server.accept()
print("Connected:", addr)

# Certificate exchange
client_cert_bytes = recv_exact(conn, len(server_cert_bytes))
client_cert = verify_certificate(client_cert_bytes)
conn.send(server_cert_bytes)

# ECDH
server_ec_private = ec.generate_private_key(ec.SECP256R1())
server_ec_public = server_ec_private.public_key()
server_nonce = os.urandom(16)

if DEBUG:
    print("Ephemeral EC key pair generated.")

server_ec_public_bytes = server_ec_public.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
)

signature = server_private_key.sign(
    server_ec_public_bytes + server_nonce,
    padding.PKCS1v15(),
    hashes.SHA256()
)

conn.send(struct.pack("I", len(server_ec_public_bytes)))
conn.send(server_ec_public_bytes)
conn.send(server_nonce)
conn.send(struct.pack("I", len(signature)))
conn.send(signature)

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

print("Secure channel established.\n")

seq_send = 0

while True:
    data = conn.recv(8192)
    seq, message = decrypt_message(enc_key, mac_key, data)
    print("Client:", message)

    reply = input("You: ")
    packet = encrypt_message(enc_key, mac_key, seq_send, reply)
    conn.send(packet)
    seq_send += 1