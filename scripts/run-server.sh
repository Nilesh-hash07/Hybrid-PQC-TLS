#!/bin/bash
# run-server.sh - Launch hybrid TLS server
# Run: chmod +x run-server.sh && ./run-server.sh

# Go to project root
cd "$(dirname "$0")/.."

# Set environment
export LD_LIBRARY_PATH=/opt/openssl-3.5/lib64:$LD_LIBRARY_PATH
export OPENSSL_CONF=/opt/openssl-3.5/ssl/openssl-pqc.cnf

# Check if server binary exists
if [ ! -f src/hybrid_server ]; then
    echo "Server binary not found. Run 'cd src && make' first."
    exit 1
fi

# Run server
echo "Starting hybrid TLS server..."
./src/hybrid_server
