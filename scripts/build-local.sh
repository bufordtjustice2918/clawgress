#!/bin/bash
# Clawgress Local Docker Build Script
# Builds Clawgress ISO using local vyos-build with Docker

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VYOS_BUILD_DIR="/home/kavan/.openclaw/vyos/vyos-build"
ISO_OUTPUT_DIR="/home/kavan/.openclaw/clawgress-iso"

echo "=========================================="
echo "Clawgress Local Docker Build"
echo "=========================================="
echo ""

# Verify modifications are in place
echo "Checking Clawgress modifications..."
if [ ! -f "$VYOS_BUILD_DIR/data/live-build-config/hooks/live/50-clawgress-bind9.chroot" ]; then
    echo "ERROR: bind9 hook not found!"
    echo "Run: ./scripts/setup-local-build.sh first"
    exit 1
fi

if [ ! -f "$VYOS_BUILD_DIR/data/live-build-config/includes.chroot/config/clawgress/policy.json" ]; then
    echo "ERROR: policy.json not found!"
    echo "Run: ./scripts/setup-local-build.sh first"
    exit 1
fi

echo "✓ Modifications verified"
echo ""

# Create output directory
mkdir -p "$ISO_OUTPUT_DIR"

# Check if we have the Docker image
if ! sudo docker image inspect vyos/vyos-build:current &>/dev/null; then
    echo "Pulling vyos-build Docker image..."
    sudo docker pull vyos/vyos-build:current
fi

echo "Starting build container..."
echo "This will take 30-60 minutes..."
echo ""

# Run the build
sudo docker run --rm --privileged \
    -v "$VYOS_BUILD_DIR:/vyos" \
    -v "$ISO_OUTPUT_DIR:/output" \
    -w /vyos \
    vyos/vyos-build:current \
    bash -c "
        ./build-vyos-image \
            --architecture amd64 \
            --build-type release \
            --version 1.5.0-clawgress \
            generic
        
        # Copy ISO to output mount
        cp build/*.iso /output/ 2>/dev/null || true
    "

# Check if ISO was created
ISO_FILE=$(ls -t "$ISO_OUTPUT_DIR"/*.iso 2>/dev/null | head -1)

if [ -f "$ISO_FILE" ]; then
    echo ""
    echo "=========================================="
    echo "BUILD SUCCESSFUL!"
    echo "=========================================="
    echo "ISO: $ISO_FILE"
    ls -lh "$ISO_FILE"
    echo ""
    echo "Test with:"
    echo "  ./scripts/test-iso.sh $ISO_FILE"
else
    echo ""
    echo "=========================================="
    echo "BUILD FAILED"
    echo "=========================================="
    echo "Check logs in: $VYOS_BUILD_DIR/build/"
    exit 1
fi
