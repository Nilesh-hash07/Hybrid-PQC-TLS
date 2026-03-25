# Hybrid PQC TLS - X25519 + ML-KEM-768

A production-ready implementation of hybrid TLS 1.3 combining classical X25519 Elliptic Curve Diffie-Hellman with post-quantum ML-KEM-768 (Kyber) key exchange, following ANSSI February 2026 guidance.

## Overview

This project implements a hybrid TLS handshake that protects against Harvest Now, Decrypt Later (HNDL) attacks by combining classical and post-quantum cryptography. When a client connects, both X25519 and ML-KEM-768 key exchanges occur in parallel, and the resulting secrets are cryptographically combined to derive session keys. An attacker must break both algorithms to compromise the session. The implementation follows the French National Cybersecurity Agency (ANSSI) February 2026 technical guidance which recommends hybridization rather than pure post-quantum migration to ensure security during the transition period.

## Features

- Hybrid Key Exchange: X25519 (classical) + ML-KEM-768 (post-quantum) in parallel
- TLS 1.3 Protocol: Forced minimum version for modern security guarantees
- Backward Compatibility: Falls back to classical X25519 when client lacks PQC support
- Real-Time Logging: Comprehensive handshake logging with hybrid status detection
- Wireshark Support: Full packet capture compatibility for handshake verification
- ANSSI Compliant: Follows February 2026 guidance for gradual PQC migration
- Provider Architecture: Uses OpenSSL 3.5+ provider system for modular algorithm loading
- Multi-Platform: Tested on Kali Linux, compatible with any Linux distribution

## Security Properties

| Component | Algorithm | Security Level | Standard |
|-----------|----------|----------------|----------|
| Classical | X25519 | 128-bit | RFC 7748 |
| Post-Quantum | ML-KEM-768 | NIST Level 3 (AES-192 equivalent) | FIPS 203 |
| Combined | Hybrid Secret | 128-bit + Level 3 | ANSSI Guidance |

Threat Model:

- Harvest Now, Decrypt Later (HNDL): Attackers collect encrypted data today, decrypt with quantum computers tomorrow. Mitigation: Hybrid session keys ensure quantum computers cannot decrypt historical traffic.

- Classical Cryptanalysis: Breakthrough against elliptic curve cryptography. Mitigation: Post-quantum component remains secure.

- PQC Implementation Weakness: Vulnerability in new ML-KEM algorithm. Mitigation: Classical component remains secure.

## Architecture

Client sends ClientHello offering X25519MLKEM768 and X25519 groups. Server responds with ServerHello selecting X25519MLKEM768. Client sends Key Share containing X25519 public key and ML-KEM-768 ciphertext. Server sends Key Share containing its X25519 public key and ML-KEM-768 ciphertext. Both parties derive classical_secret via X25519 and pq_secret via ML-KEM-768 decapsulation. The hybrid_secret is computed as HKDF-Extract(salt, classical_secret || pq_secret). Session keys are derived via HKDF-Expand(hybrid_secret, "hybrid tls13", length).

The implementation consists of client and server components. The client contains Provider Loader, SSL Context Manager, Group Offer Engine, Key Share Generator, Secret Derivation Module, and Response Parser. The server contains Provider Loader, SSL Context Manager, Group Configuration Module, Key Share Generator, Secret Derivation Module, and Connection Logger. Both components interface through the TLS 1.3 Protocol layer implemented via OpenSSL 3.5 with OQS provider.

## Requirements

- Operating System: Kali Linux or any Linux distribution
- OpenSSL: 3.5.0 or higher (built from source with OQS provider)
- liboqs: 0.9.0 or higher
- oqs-provider: 0.6.0 or higher
- GCC: 9.0 or higher
- Make: 4.0 or higher
- Wireshark / tshark: Optional for packet capture and analysis

## Installation

Step 1: Clone the Repository
git clone https://github.com/Nilesh-hash07/Hybrid-PQC-TLS.git
cd Hybrid-PQC-TLS

Step 2: Install OpenSSL 3.5.0 with OQS Provider
sudo ./scripts/setup-openssl.sh

This script installs build dependencies, downloads and compiles OpenSSL 3.5.0 to /opt/openssl-3.5, builds liboqs and installs to /opt/oqs, builds oqs-provider, configures OpenSSL, and creates wrapper script /usr/local/bin/openssl-pqc. The process takes 10-15 minutes.

Step 3: Generate Certificates
./scripts/generate-certs.sh

This creates self-signed certificates in the certs directory: Certificate Authority with 4096-bit RSA key, server certificate signed by the CA with 2048-bit RSA key, and validity period of 365 days.

Step 4: Build the Project
cd src && make && cd ..

This compiles hybrid_server and hybrid_client binaries.

## Usage

Setting Up Environment:
export LD_LIBRARY_PATH=/opt/openssl-3.5/lib64:$LD_LIBRARY_PATH
export OPENSSL_CONF=/opt/openssl-3.5/ssl/openssl-pqc.cnf

Starting the Server:
./src/hybrid_server

Expected server output shows loading providers, creating SSL context, setting hybrid groups, loading certificates, creating socket, and server ready on port 4433.

Starting the Client:
./src/hybrid_client

Expected client output shows loading providers, creating SSL context, offering hybrid groups, connecting to server, performing TLS handshake, and displaying connection details including protocol TLSv1.3, cipher TLS_AES_256_GCM_SHA384, key exchange X25519MLKEM768 with NID 16781804/0x10011EC, and HYBRID ACTIVE status.

## Wireshark Capture

To capture the hybrid handshake for verification:
sudo tcpdump -i lo -w capture.pcap port 4433

Run the server and client, then analyze with:
tshark -r capture.pcap -Y "tls.handshake.type == 1" -V | grep -A10 "supported_groups"

## ANSSI Compliance

This implementation follows ANSSI February 2026 guidance:
- Hybrid approach combining classical and quantum-safe algorithms
- Protects against harvest now, decrypt later attacks
- Backward compatible with classical-only clients
- Uses NIST-standardized ML-KEM-768
- Implements defense in depth principle

## License
Apache License 2.0 - see LICENSE and NOTICE files for details.
