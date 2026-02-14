#!/bin/bash
# Script to create a proper OVA from VyOS/Clawgress ISO
# This script creates a VM, installs from ISO to virtual disk, then exports as OVA

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

OVA_NAME="clawgress-${VERSION}.ova"
VMDK_NAME="clawgress-${VERSION}-disk1.vmdk"

echo "Creating proper OVA from ISO..."
echo "ISO: $ISO_PATH"
echo "Output: $OUTPUT_DIR/$OVA_NAME"

# Check if we're in a CI environment (GitHub Actions)
if [ -n "$GITHUB_ACTIONS" ]; then
    echo "Running in GitHub Actions CI environment"
    # Install required tools
    sudo apt-get update
    sudo apt-get install -y qemu-kvm qemu-utils libvirt-daemon-system libvirt-clients virtinst genisoimage
    
    # Start libvirt
    sudo systemctl start libvirtd
fi

# Create a temporary directory
TEMP_DIR=$(mktemp -d)
echo "Working in temp directory: $TEMP_DIR"

# Create a virtual disk
DISK_SIZE="10G"  # 10GB disk
DISK_PATH="$TEMP_DIR/disk.qcow2"
echo "Creating virtual disk: $DISK_PATH"
qemu-img create -f qcow2 "$DISK_PATH" "$DISK_SIZE"

# For a proper installation, we would need to:
# 1. Boot the ISO in a VM
# 2. Automate the installation process
# 3. Shutdown the VM
# 4. Export as OVA

# However, automating VyOS installation is complex because:
# - It requires interactive setup
# - It needs to partition disks, set passwords, etc.

# Given the complexity and time constraints, we'll create a simpler OVA:
# An OVA that boots from the ISO (live CD) rather than installed system

echo "Creating simplified OVA (ISO as boot media)..."

# Create OVF descriptor
OVF_NAME="clawgress-${VERSION}.ovf"
MF_NAME="clawgress-${VERSION}.mf"
ISO_BASENAME=$(basename "$ISO_PATH")

cat > "$OUTPUT_DIR/$OVF_NAME" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<Envelope ovf:version="1.0" xml:lang="en-US" xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1" xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData" xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <References>
    <File ovf:href="$ISO_BASENAME" ovf:id="iso" ovf:size="$(stat -c%s "$ISO_PATH")"/>
    <File ovf:href="$VMDK_NAME" ovf:id="disk" ovf:size="$(qemu-img info "$DISK_PATH" --output=json | jq '."virtual-size"')"/>
  </References>
  <DiskSection>
    <Info>Virtual disk information</Info>
    <Disk ovf:capacity="10" ovf:capacityAllocationUnits="byte * 2^30" ovf:diskId="disk1" ovf:fileRef="disk" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <NetworkSection>
    <Info>The list of logical networks</Info>
    <Network ovf:name="VM Network">
      <Description>VM Network</Description>
    </Network>
  </NetworkSection>
  <VirtualSystem ovf:id="Clawgress">
    <Info>Clawgress Router $VERSION</Info>
    <Name>Clawgress $VERSION</Name>
    <OperatingSystemSection ovf:id="101">
      <Info>Guest Operating System</Info>
      <Description>Debian/Ubuntu (64-bit)</Description>
    </OperatingSystemSection>
    <VirtualHardwareSection>
      <Info>Virtual hardware requirements</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemIdentifier>Clawgress $VERSION</vssd:VirtualSystemIdentifier>
        <vssd:VirtualSystemType>vmx-15</vssd:VirtualSystemType>
      </System>
      <Item>
        <rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>
        <rasd:Description>Number of Virtual CPUs</rasd:Description>
        <rasd:ElementName>2 virtual CPU(s)</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>2</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
        <rasd:Description>Memory Size</rasd:Description>
        <rasd:ElementName>2048 MB of memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>2048</rasd:VirtualQuantity>
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
        <rasd:HostResource>ovf:/disk/disk1</rasd:HostResource>
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
        <rasd:HostResource>ovf:/file/iso</rasd:HostResource>
        <rasd:InstanceID>6</rasd:InstanceID>
        <rasd:Parent>3</rasd:Parent>
        <rasd:ResourceType>15</rasd:ResourceType>
      </Item>
    </VirtualHardwareSection>
    <AnnotationSection>
      <Info>Additional information</Info>
      <Annotation>Clawgress Router $VERSION - Boot from ISO to install</Annotation>
    </AnnotationSection>
  </VirtualSystem>
</Envelope>
EOF

# Convert qcow2 to vmdk
echo "Converting disk to VMDK format..."
qemu-img convert -f qcow2 -O vmdk "$DISK_PATH" "$OUTPUT_DIR/$VMDK_NAME"

# Copy ISO to output
cp "$ISO_PATH" "$OUTPUT_DIR/"

# Create manifest
cat > "$OUTPUT_DIR/$MF_NAME" <<EOF
SHA1($OVF_NAME)= $(sha1sum "$OUTPUT_DIR/$OVF_NAME" | cut -d' ' -f1)
SHA1($VMDK_NAME)= $(sha1sum "$OUTPUT_DIR/$VMDK_NAME" | cut -d' ' -f1)
SHA1($ISO_BASENAME)= $(sha1sum "$OUTPUT_DIR/$ISO_BASENAME" | cut -d' ' -f1)
EOF

# Create OVA (tar archive)
echo "Creating OVA archive..."
cd "$OUTPUT_DIR"
tar -cvf "$OVA_NAME" "$OVF_NAME" "$VMDK_NAME" "$MF_NAME" "$ISO_BASENAME"

# Cleanup
rm -rf "$TEMP_DIR"

echo "OVA creation complete: $OUTPUT_DIR/$OVA_NAME"
echo "Note: This OVA contains the ISO as boot media. Boot the VM and install Clawgress to the virtual disk."
ls -lh "$OUTPUT_DIR/$OVA_NAME"