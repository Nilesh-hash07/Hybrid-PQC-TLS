#!/bin/bash
# setup-openssl.sh - Build OpenSSL 3.5.0 with OQS provider
# Run: chmod +x setup-openssl.sh && sudo ./setup-openssl.sh

set -e  # Exit on error

echo "========================================="
echo "OpenSSL 3.5.0 + OQS Provider Build Script"
echo "========================================="

# Update and install dependencies
echo "[1/6] Installing build dependencies..."
apt-get update
apt-get install -y build-essential cmake ninja-build git wget curl libssl-dev zlib1g-dev

# Build OpenSSL 3.5.0
echo "[2/6] Building OpenSSL 3.5.0..."
cd /root
wget -q https://github.com/openssl/openssl/releases/download/openssl-3.5.0/openssl-3.5.0.tar.gz
tar -xzf openssl-3.5.0.tar.gz
cd openssl-3.5.0
./config --prefix=/opt/openssl-3.5 --openssldir=/opt/openssl-3.5/ssl shared zlib
make -j$(nproc)
make install
echo "/opt/openssl-3.5/lib64" > /etc/ld.so.conf.d/openssl-3.5.conf
ldconfig

# Build liboqs
echo "[3/6] Building liboqs..."
cd /root
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/opt/oqs -DOPENSSL_ROOT_DIR=/opt/openssl-3.5 ..
make -j$(nproc)
make install

# Build oqs-provider
echo "[4/6] Building oqs-provider..."
cd /root
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
mkdir build && cd build
cmake -DCMAKE_PREFIX_PATH="/opt/openssl-3.5;/opt/oqs" -DOPENSSL_ROOT_DIR=/opt/openssl-3.5 ..
make -j$(nproc)
make install

# Copy provider to OpenSSL modules
echo "[5/6] Installing oqs-provider..."
mkdir -p /opt/openssl-3.5/lib64/ossl-modules
cp /opt/oqs/lib/ossl-modules/oqsprovider.so /opt/openssl-3.5/lib64/ossl-modules/

# Create OpenSSL config
echo "[6/6] Creating OpenSSL configuration..."
cat > /opt/openssl-3.5/ssl/openssl-pqc.cnf << 'EOF'
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
EOF

# Create wrapper script
cat > /usr/local/bin/openssl-pqc << 'EOF'
#!/bin/bash
export OPENSSL_CONF=/opt/openssl-3.5/ssl/openssl-pqc.cnf
export LD_LIBRARY_PATH=/opt/openssl-3.5/lib64:$LD_LIBRARY_PATH
export PATH=/opt/openssl-3.5/bin:$PATH
exec /opt/openssl-3.5/bin/openssl "$@"
EOF
chmod +x /usr/local/bin/openssl-pqc

echo ""
echo "Build complete!"
echo ""
echo "To use PQC OpenSSL:"
echo "  export LD_LIBRARY_PATH=/opt/openssl-3.5/lib64:\$LD_LIBRARY_PATH"
echo "  export OPENSSL_CONF=/opt/openssl-3.5/ssl/openssl-pqc.cnf"
echo "  or use: openssl-pqc"
