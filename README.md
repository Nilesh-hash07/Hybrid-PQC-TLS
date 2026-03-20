# Hybrid PQC TLS - X25519 + ML-KEM-768

Hybrid TLS 1.3 implementation combining classical X25519 ECDH with post-quantum ML-KEM-768 (Kyber) key exchange.

## Overview

This project implements a hybrid TLS handshake that protects against "harvest now, decrypt later" attacks by combining classical and post-quantum cryptography. Both X25519 and ML-KEM-768 key exchanges occur in parallel, and the resulting secrets are combined to derive session keys.

## Features

- Hybrid key exchange: X25519 + ML-KEM-768
- TLS 1.3 protocol
- Real-time connection logging
- Wireshark-verified handshake capture

## Quick Start

```bash
# Generate certificates
cd certs
openssl req -x509 -new -nodes -newkey rsa:4096 -keyout ca.key -out ca.crt -days 365 -subj "/CN=Hybrid PQC CA/O=Project/C=FR"
openssl req -new -nodes -newkey rsa:2048 -keyout server.key -out server.csr -subj "/CN=localhost/O=Project/C=FR"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365
cd ..

# Build
cd src && make && cd ..

# Run server
export LD_LIBRARY_PATH=/opt/openssl-3.5/lib64:$LD_LIBRARY_PATH
export OPENSSL_CONF=/opt/openssl-3.5/ssl/openssl-pqc.cnf
./src/hybrid_server

# Run client (another terminal)
export LD_LIBRARY_PATH=/opt/openssl-3.5/lib64:$LD_LIBRARY_PATH
export OPENSSL_CONF=/opt/openssl-3.5/ssl/openssl-pqc.cnf
./src/hybrid_client

