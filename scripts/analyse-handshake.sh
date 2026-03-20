#!/bin/bash
# analyze-handshake.sh - Analyze captured PQC TLS handshake
# Run: chmod +x analyze-handshake.sh && ./analyze-handshake.sh <pcap-file>

if [ -z "$1" ]; then
    echo "Usage: $0 <pcap-file>"
    echo "Example: $0 captures/hybrid-handshake.pcap"
    exit 1
fi

PCAP_FILE="$1"

if [ ! -f "$PCAP_FILE" ]; then
    echo "File not found: $PCAP_FILE"
    exit 1
fi

echo "========================================="
echo "Hybrid TLS Handshake Analysis"
echo "========================================="
echo "File: $PCAP_FILE"
echo ""

# Check for Client Hello
echo "[1/4] Client Hello - Supported Groups:"
tshark -r "$PCAP_FILE" -Y "tls.handshake.type == 1" -V 2>/dev/null | grep -A10 "Extension: supported_groups" | grep "Supported Group" | head -10
echo ""

# Check for Server Hello selected group
echo "[2/4] Server Hello - Selected Group:"
tshark -r "$PCAP_FILE" -Y "tls.handshake.type == 2" -V 2>/dev/null | grep -A5 "Extension: key_share" | grep "Group:"
echo ""

# Check for hybrid group specifically
echo "[3/4] Hybrid Group Detection:"
if tshark -r "$PCAP_FILE" -V 2>/dev/null | grep -q "X25519MLKEM768"; then
    echo "X25519MLKEM768 hybrid group FOUND"
else
    echo "No hybrid group detected"
fi
echo ""

# Show handshake summary
echo "[4/4] Handshake Summary:"
tshark -r "$PCAP_FILE" -Y "tls.handshake.type" -T fields -e frame.time_relative -e tls.handshake.type 2>/dev/null | head -5
