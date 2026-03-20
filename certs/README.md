# Certificates Directory

## Purpose

This directory contains the public certificate infrastructure components required for hybrid TLS operation. Private key material is deliberately excluded from version control as a matter of security best practice.

## Contents

| File | Type | Description |
|------|------|-------------|
| `ca.crt` | X.509 Certificate | Certificate Authority public certificate for validating server certificates |
| `server.crt` | X.509 Certificate | Server certificate presented during TLS handshake |

## Security Considerations

Private key files (`.key`), certificate signing requests (`.csr`), and serial tracking files (`.srl`) are not stored in this repository. These artifacts are considered sensitive and must be generated locally on the deployment system.

The following patterns are enforced via `.gitignore`.
