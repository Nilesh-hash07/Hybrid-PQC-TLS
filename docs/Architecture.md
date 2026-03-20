# Hybrid PQC TLS - Architecture Document

## System Overview

This implementation provides hybrid TLS 1.3 key exchange combining classical X25519 Elliptic Curve Diffie-Hellman (ECDH) with post-quantum ML-KEM-768 (Kyber) Key Encapsulation Mechanism, following ANSSI February 2026 guidance for post-quantum transition.

## Key Exchange Process

### Hybrid Key Derivation
The session key is derived from both classical and post-quantum components:

classical_secret = X25519(priv_c, pub_s) = X25519(priv_s, pub_c)
pq_secret = ML-KEM-768.Decaps(priv_s, ct) = ML-KEM-768.Encaps(pub_c)

hybrid_secret = HKDF-Extract(salt, classical_secret || pq_secret)
session_keys = HKDF-Expand(hybrid_secret, "hybrid tls13", length)

### Security Properties
- Classical security: X25519 (128-bit security level)
- Post-quantum security: ML-KEM-768 (NIST Level 3, equivalent to AES-192)
- Hybrid security: Attacker must break BOTH algorithms to compromise the session
- Protects against "harvest now, decrypt later" attacks

## Protocol Flow

### 1. Client Hello
The client initiates connection offering hybrid and fallback groups:

Extension: supported_groups
    Groups:
        X25519MLKEM768 (0x11EC)  # Hybrid primary
        X25519 (0x1D)             # Classical fallback
        P-256 (0x17)              # Additional fallback

Extension: key_share
    Key Shares:
        Group: X25519MLKEM768
            Key Exchange Length: 1184 bytes
            Content: X25519 public key + ML-KEM-768 ciphertext
        Group: X25519
            Key Exchange Length: 32 bytes
            Content: X25519 public key

### 2. Server Hello
Server selects the highest mutually supported group:

Extension: key_share
    Key Share:
        Group: X25519MLKEM768 (selected)
        Key Exchange Length: 1184 bytes
        Content: Server's X25519 public key + ML-KEM-768 ciphertext

### 3. Handshake Completion
Both parties derive the same hybrid secret:
- Client combines its X25519 private key with server's public key
- Client decapsulates ML-KEM-768 ciphertext using its private key
- Server combines its X25519 private key with client's public key
- Server decapsulates ML-KEM-768 ciphertext using its private key
- Both derive identical hybrid_secret via HKDF

## Implementation Architecture

### Server Components

src/hybrid_server.c contains:
- Provider Loader: Loads default and OQS providers
- SSL Context Manager: Creates and configures SSL_CTX
- Certificate Handler: Loads and validates certificates
- Group Configurator: Sets X25519MLKEM768:X25519:P-256 groups
- Connection Logger: Records handshake details to hybrid_handshake.log
- Main Loop: Accepts and handles client connections

### Client Components

src/hybrid_client.c contains:
- Provider Loader: Loads default and OQS providers
- SSL Context Manager: Creates client SSL_CTX
- Group Offer Engine: Offers X25519MLKEM768:X25519:P-256
- Connection Handler: Connects to server on port 4433
- Handshake Verifier: Checks negotiated group and displays results
- Response Parser: Receives and displays server HTTP response

## Key Functions

### Provider Loading
int load_providers(void) {
    OSSL_PROVIDER_load(NULL, "default");        // Classical algorithms
    OSSL_PROVIDER_load(NULL, "oqsprovider");    // Post-quantum algorithms
    OSSL_PROVIDER_load(NULL, "/opt/openssl-3.5/lib64/ossl-modules/oqsprovider.so");
}

### Group Configuration
const char *groups = "X25519MLKEM768:X25519:P-256";
SSL_CTX_set1_groups_list(ctx, groups);

### Handshake Verification
int curve_nid = SSL_get_negotiated_group(ssl);
if (curve_nid == 0x10011EC || curve_nid == 412) {
    printf("→ HYBRID ACTIVE (X25519 + ML-KEM-768)\n");
}

### Connection Logging
void log_connection(SSL *ssl, const char *client_ip) {
    FILE *log = fopen("logs/hybrid_handshake.log", "a");
    fprintf(log, "\n=== Connection at %s", ctime(&now));
    fprintf(log, "Client: %s\n", client_ip);
    fprintf(log, "Protocol: %s\n", SSL_get_version(ssl));
    fprintf(log, "Cipher: %s\n", SSL_get_cipher_name(ssl));
    fprintf(log, "Key exchange: %s\n", get_curve_name(SSL_get_negotiated_group(ssl)));
}

## Component Interaction Diagram

┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│    Client       │         │    Network      │         │    Server       │
├─────────────────┤         ├─────────────────┤         ├─────────────────┤
│ - Loads providers│         │                 │         │ - Loads providers│
│ - Creates SSL ctx│         │   TCP port      │         │ - Creates SSL ctx│
│ - Offers groups  │────────▶│    4433         │────────▶│ - Sets groups    │
│ - Sends key share│         │                 │         │ - Selects group  │
│ - Derives secret │◄────────│  TLS handshake  │◄────────│ - Derives secret │
│ - Verifies group │         │                 │         │ - Logs connection│
└─────────────────┘         └─────────────────┘         └─────────────────┘

## Dependencies

| Component | Version | Source | Purpose |
|-----------|---------|--------|---------|
| OpenSSL | 3.5.0+ | openssl.org | TLS implementation, crypto primitives |
| liboqs | 0.9.0+ | openquantumsafe.org | Post-quantum algorithm implementations |
| oqs-provider | 0.6.0+ | openquantumsafe.org | OpenSSL 3.x provider for liboqs |
| GCC | 9.0+ | gnu.org | C compiler |
| Make | 4.0+ | gnu.org | Build automation |

## Build Configuration

### Makefile Structure
CC = gcc
OPENSSL_DIR = /opt/openssl-3.5
CFLAGS = -Wall -Wextra -O2 -I$(OPENSSL_DIR)/include
LDFLAGS = -L$(OPENSSL_DIR)/lib64 -Wl,-rpath=$(OPENSSL_DIR)/lib64
LIBS = -lssl -lcrypto

all: hybrid_server hybrid_client

hybrid_server: hybrid_server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

hybrid_client: hybrid_client.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

## Runtime Environment

### Required Environment Variables
export LD_LIBRARY_PATH=/opt/openssl-3.5/lib64:$LD_LIBRARY_PATH
export OPENSSL_CONF=/opt/openssl-3.5/ssl/openssl-pqc.cnf

### OpenSSL Configuration (openssl-pqc.cnf)
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
module = /opt/openssl-3.5/lib64/ossl-modules/oqsprovider.so

## Successful Handshake Output

Server:
========================================
  Hybrid TLS Server
========================================

[1/7] Loading providers... OK
[2/7] Creating SSL context... OK
[3/7] Setting hybrid groups... OK (X25519MLKEM768:X25519:P-256)
[4/7] Loading certificate... OK
[5/7] Loading private key... OK
[6/7] Creating socket... OK
[7/7] Server ready on port 4433

Client connected: 127.0.0.1:53844
  TLS handshake... SUCCESS
  Cipher: TLS_AES_256_GCM_SHA384
  Key exchange: X25519MLKEM768 (NID: 16781804/0x10011EC)
  → HYBRID ACTIVE (X25519 + ML-KEM-768)

Client:
========================================
  Hybrid TLS Client
========================================

[1/5] Loading providers... OK
[2/5] Creating SSL context... OK
[3/5] Offering X25519+ML-KEM-768... OK
[4/5] Connecting to 127.0.0.1:4433... OK
[5/5] Performing TLS handshake... SUCCESS

=== Connection Established ===
Protocol: TLSv1.3
Cipher: TLS_AES_256_GCM_SHA384
Key exchange: X25519MLKEM768 (NID: 16781804/0x10011EC)
→ HYBRID ACTIVE (X25519 + ML-KEM-768)

## Log File Example (logs/hybrid_handshake.log)

=== Connection at Fri Mar 20 12:34:56 2026
Client: 127.0.0.1
Protocol: TLSv1.3
Cipher: TLS_AES_256_GCM_SHA384
Key exchange: X25519MLKEM768 (NID: 16781804/0x10011EC)
STATUS: HYBRID PQC ACTIVE (X25519+ML-KEM-768)

## ANSSI Alignment

This implementation follows ANSSI February 2026 guidance:

1. Hybrid Approach: Combines classical (X25519) and post-quantum (ML-KEM-768)
2. Confidentiality Priority: Protects against "harvest now, decrypt later"
3. Gradual Migration: Backward compatible with classical-only clients
4. Algorithm Diversity: Uses different mathematical foundations (ECDH + lattice)
5. Standard Compliance: Uses NIST-standardized ML-KEM-768

## References

1. ANSSI Technical Guidance for Post-Quantum Cryptography Transition (February 2026)
2. NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)
3. RFC 7748: Elliptic Curves for Security (X25519)
4. RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
5. Open Quantum Safe Project Documentation
