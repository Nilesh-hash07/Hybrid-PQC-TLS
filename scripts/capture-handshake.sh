#!/bin/bash
# capture-handshake.sh - Capture hybrid TLS handshake with tcpdump
# Run: chmod +x capture-handshake.sh && sudo ./capture-handshake.sh

# Go to project root
cd "$(dirname "$0")/.."

# Create captures directory
mkdir -p captures
cd captures

# Set capture file name with timestamp
CAPTURE_FILE="hybrid-handshake-$(date +%Y%m%d-%H%M%S).pcap"

echo "========================================="
echo "Hybrid TLS Handshake Capture Script"
echo "========================================="
echo "Capture file: $CAPTURE_FILE"
echo ""
echo "Starting packet capture on loopback interface..."
echo "Press Ctrl+C to stop capture"
echo ""

# Start capture
sudo tcpdump -i lo -w "$CAPTURE_FILE" port 4433

echo ""
echo "Capture saved to: captures/$CAPTURE_FILE"
echo ""
echo "To analyze:"
echo "  wireshark captures/$CAPTURE_FILE"
echo "  or"
echo "  tshark -r captures/$CAPTURE_FILE -Y \"tls.handshake.type == 1\" -V"
