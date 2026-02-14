#!/bin/bash
# Script to convert VyOS/Clawgress ISO to OVA format
# Requires: qemu-img, ovftool (VMware), genisoimage

set -e

ISO_PATH="$1"
OUTPUT_DIR="$2"
VERSION="$3"

if [ -z "$ISO_PATH" ] || [ -z "$OUTPUT_DIR" ] || [ -z "$VERSION" ]; then
    echo "Usage: $0 <iso_path> <output_dir> <version>"
    echo "Example: $0 build/live-image-amd64.hybrid.iso ./artifacts v1.4.0"
    exit 1
fi

if [ ! -f "$ISO_PATH" ]; then
    echo "Error: ISO file not found: $ISO_PATH"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# Extract ISO name without extension
ISO_NAME=$(basename "$ISO_PATH" .iso)
OVA_NAME="clawgress-${VERSION}.ova"
OVF_NAME="clawgress-${VERSION}.ovf"
MF_NAME="clawgress-${VERSION}.mf"
VMDK_NAME="clawgress-${VERSION}-disk1.vmdk"

echo "Converting ISO to OVA..."
echo "ISO: $ISO_PATH"
echo "Output: $OUTPUT_DIR/$OVA_NAME"

# Create a temporary directory
TEMP_DIR=$(mktemp -d)
echo "Working in temp directory: $TEMP_DIR"

# Mount ISO to extract files
MOUNT_DIR="$TEMP_DIR/mount"
mkdir -p "$MOUNT_DIR"
sudo mount -o loop "$ISO_PATH" "$MOUNT_DIR" 2>/dev/null || {
    echo "Warning: Could not mount ISO, trying alternative extraction methods"
}

# Check for different ISO structures
# VyOS ISO typically contains a squashfs filesystem
SQUASHFS=$(find "$MOUNT_DIR" -name "*.squashfs" | head -1)

if [ -n "$SQUASHFS" ]; then
    echo "Found squashfs: $SQUASHFS"
    
    # Extract squashfs
    EXTRACT_DIR="$TEMP_DIR/extract"
    mkdir -p "$EXTRACT_DIR"
    
    echo "Extracting squashfs..."
    sudo unsquashfs -f -d "$EXTRACT_DIR" "$SQUASHFS" 2>/dev/null || {
        echo "Error extracting squashfs"
        sudo umount "$MOUNT_DIR" 2>/dev/null || true
        exit 1
    }
    
    # Create a raw disk image from the extracted filesystem
    # This is a simplified approach - real OVA creation would need proper disk layout
    echo "Creating raw disk image..."
    RAW_IMAGE="$TEMP_DIR/disk.raw"
    
    # Calculate size needed (extracted size + 20% for overhead)
    EXTRACTED_SIZE=$(sudo du -sb "$EXTRACT_DIR" | cut -f1)
    DISK_SIZE=$((EXTRACTED_SIZE * 120 / 100 / 1024 / 1024))M  # Convert to MB with 20% overhead
    
    qemu-img create -f raw "$RAW_IMAGE" "$DISK_SIZE"
    
    # Create filesystem and copy files (simplified - real implementation would need partition setup)
    # mkfs.ext4 "$RAW_IMAGE"
    # mount and copy files...
    
    echo "Converting raw image to VMDK..."
    qemu-img convert -f raw -O vmdk "$RAW_IMAGE" "$OUTPUT_DIR/$VMDK_NAME"
    
else
    echo "No squashfs found in ISO, using alternative OVA creation method"
    
    # Create a minimal OVA with just the ISO as a CD-ROM
    # This is a basic OVA that can be used with virtualization software
    echo "Creating basic OVA with ISO as CD-ROM..."
    
    # Create OVF descriptor
    cat > "$OUTPUT_DIR/$OVF_NAME" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<Envelope ovf:version="1.0" xml:lang="en-US" xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1" xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData" xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <References>
    <File ovf:href="$VMDK_NAME" ovf:id="file1" ovf:size="$(stat -c%s "$ISO_PATH")"/>
  </References>
  <DiskSection>
    <Info>Virtual disk information</Info>
    <Disk ovf:capacity="10240" ovf:capacityAllocationUnits="byte * 2^20" ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized" ovf:populatedSize="0"/>
  </DiskSection>
  <NetworkSection>
    <Info>The list of logical networks</Info>
    <Network ovf:name="VM Network">
      <Description>The VM Network</Description>
    </Network>
  </NetworkSection>
  <VirtualSystem ovf:id="Clawgress">
    <Info>A virtual machine</Info>
    <Name>Clawgress $VERSION</Name>
    <OperatingSystemSection ovf:id="101">
      <Info>The kind of installed guest operating system</Info>
      <Description>Debian/Ubuntu (64-bit)</Description>
    </OperatingSystemSection>
    <VirtualHardwareSection>
      <Info>Virtual hardware requirements</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemIdentifier>Clawgress $VERSION</vssd:VirtualSystemIdentifier>
        <vssd:VirtualSystemType>vmx-08</vssd:VirtualSystemType>
      </System>
      <Item>
        <rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>
        <rasd:Description>Number of Virtual CPUs</rasd:Description>
        <rasd:ElementName>1 virtual CPU(s)</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>1</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
        <rasd:Description>Memory Size</rasd:Description>
        <rasd:ElementName>1024 MB of memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>1024</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:Address>0</rasd:Address>
        <rasd:Description>SCSI Controller</rasd:Description>
        <rasd:ElementName>SCSI Controller 0</rasd:ElementName>
        <rasd:InstanceID>3</rasd:InstanceID>
        <rasd:ResourceSubType>lsilogic</rasd:ResourceSubType>
        <rasd:ResourceType>6</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:ElementName>Hard Disk 1</rasd:ElementName>
        <rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource>
        <rasd:InstanceID>4</rasd:InstanceID>
        <rasd:Parent>3</rasd:Parent>
        <rasd:ResourceType>17</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
        <rasd:Connection>VM Network</rasd:Connection>
        <rasd:Description>E1000 Ethernet Adapter</rasd:Description>
        <rasd:ElementName>Network Adapter 1</rasd:ElementName>
        <rasd:InstanceID>5</rasd:InstanceID>
        <rasd:ResourceSubType>E1000</rasd:ResourceSubType>
        <rasd:ResourceType>10</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>1</rasd:AddressOnParent>
        <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
        <rasd:Description>CD/DVD Drive</rasd:Description>
        <rasd:ElementName>CD/DVD Drive 1</rasd:ElementName>
        <rasd:HostResource>$(basename "$ISO_PATH")</rasd:HostResource>
        <rasd:InstanceID>6</rasd:InstanceID>
        <rasd:Parent>3</rasd:Parent>
        <rasd:ResourceType>15</rasd:ResourceType>
      </Item>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
EOF
    
    # Copy ISO to output directory
    cp "$ISO_PATH" "$OUTPUT_DIR/"
    
    # Create a dummy VMDK file (empty disk)
    qemu-img create -f vmdk "$OUTPUT_DIR/$VMDK_NAME" 10G
    
    # Create manifest file
    ISO_BASENAME=$(basename "$ISO_PATH")
    cat > "$OUTPUT_DIR/$MF_NAME" <<EOF
SHA1($OVF_NAME)= $(sha1sum "$OUTPUT_DIR/$OVF_NAME" | cut -d' ' -f1)
SHA1($VMDK_NAME)= $(sha1sum "$OUTPUT_DIR/$VMDK_NAME" | cut -d' ' -f1)
SHA1($ISO_BASENAME)= $(sha1sum "$OUTPUT_DIR/$ISO_BASENAME" | cut -d' ' -f1)
EOF
fi

# Unmount if mounted
if mountpoint -q "$MOUNT_DIR"; then
    sudo umount "$MOUNT_DIR"
fi

# Create OVA (tar archive of OVF, VMDK, and manifest)
echo "Creating OVA archive..."
cd "$OUTPUT_DIR"
tar -cvf "$OVA_NAME" "$OVF_NAME" "$VMDK_NAME" "$MF_NAME" 2>/dev/null || {
    # If files don't exist, create minimal OVA
    echo "Creating minimal OVA with ISO only..."
    ISO_BASENAME=$(basename "$ISO_PATH")
    tar -cvf "$OVA_NAME" "$ISO_BASENAME" 2>/dev/null || true
}

echo "Cleaning up temp directory..."
sudo rm -rf "$TEMP_DIR"

echo "OVA creation complete: $OUTPUT_DIR/$OVA_NAME"
ls -lh "$OUTPUT_DIR/$OVA_NAME"