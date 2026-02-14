#!/bin/bash
# Test Clawgress ISO in QEMU

ISO_FILE="${1:-/home/kavan/.openclaw/clawgress-iso/clawgress-1.5.0.iso}"

if [ ! -f "$ISO_FILE" ]; then
    echo "ISO not found: $ISO_FILE"
    echo "Usage: $0 <path-to-iso>"
    exit 1
fi

echo "Testing ISO: $ISO_FILE"
echo "Creating disk image..."

mkdir -p /tmp/clawgress-test
qemu-img create -f qcow2 /tmp/clawgress-test/test-disk.qcow2 10G

echo "Booting in QEMU (Ctrl+A then X to exit)..."
qemu-system-x86_64 \
    -m 2048 \
    -smp 2 \
    -cdrom "$ISO_FILE" \
    -drive file=/tmp/clawgress-test/test-disk.qcow2,format=qcow2 \
    -boot d \
    -nographic \
    -serial mon:stdio \
    -display none
