#!/bin/bash
# generate-certs.sh - Generate certificates for hybrid TLS
# Run: chmod +x generate-certs.sh && ./generate-certs.sh

echo "========================================="
echo "Hybrid TLS Certificate Generation Script"
echo "========================================="

# Go to project root (assuming script is in scripts/)
cd "$(dirname "$0")/.."

# Create certs directory
mkdir -p certs
cd certs

# Generate CA certificate
echo "[1/3] Generating CA certificate..."
openssl req -x509 -new -nodes -newkey rsa:4096 \
    -keyout ca.key -out ca.crt -days 365 \
    -subj "/CN=Hybrid PQC CA/O=Project/C=FR"

# Generate server private key and CSR
echo "[2/3] Generating server certificate request..."
openssl req -new -nodes -newkey rsa:2048 \
    -keyout server.key -out server.csr \
    -subj "/CN=localhost/O=Project/C=FR"

# Sign server certificate with CA
echo "[3/3] Signing server certificate..."
openssl x509 -req -in server.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365

echo ""
echo "Certificates generated in ./certs/"
echo ""
echo "Files created:"
ls -la *.crt *.key
echo ""
echo "WARNING: Private keys (.key files) should never be committed to git"
