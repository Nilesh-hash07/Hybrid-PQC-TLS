#!/bin/bash
# run-client.sh - Launch hybrid TLS client
# Run: chmod +x run-client.sh && ./run-client.sh

# Go to project root
cd "$(dirname "$0")/.."

# Set environment
export LD_LIBRARY_PATH=/opt/openssl-3.5/lib64:$LD_LIBRARY_PATH
export OPENSSL_CONF=/opt/openssl-3.5/ssl/openssl-pqc.cnf

# Check if client binary exists
if [ ! -f src/hybrid_client ]; then
    echo "Client binary not found. Run 'cd src && make' first."
    exit 1
fi

# Run client
echo "Starting hybrid TLS client..."
./src/hybrid_client
