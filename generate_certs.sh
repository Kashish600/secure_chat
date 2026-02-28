#!/bin/bash

# Root CA
openssl genrsa -out rootCA.key 2048
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 365 \
-subj "/C=IN/ST=Jammu/O=SecureChat/CN=RootCA" \
-out rootCA.pem

# Server
openssl genrsa -out server.key 2048
openssl req -new -key server.key \
-subj "/C=IN/ST=Jammu/O=SecureChat/CN=Server" \
-out server.csr

openssl x509 -req -in server.csr -CA rootCA.pem -CAkey rootCA.key \
-CAcreateserial -out server.crt -days 365 -sha256

# Client
openssl genrsa -out client.key 2048
openssl req -new -key client.key \
-subj "/C=IN/ST=Jammu/O=SecureChat/CN=Client" \
-out client.csr

openssl x509 -req -in client.csr -CA rootCA.pem -CAkey rootCA.key \
-CAcreateserial -out client.crt -days 365 -sha256

echo "Certificates generated."