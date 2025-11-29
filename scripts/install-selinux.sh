#!/bin/bash
# install-selinux.sh - Install SELinux policy module for pci-segment
# PCI-DSS Requirements 2.2.4 and 2.2.5
#
# Usage: sudo ./scripts/install-selinux.sh
#
# Requires: selinux-policy-devel, policycoreutils

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE_DIR="${SCRIPT_DIR}/../pkg/security/profiles/selinux"
POLICY_NAME="pci_segment"

# Colors for output (no emojis per project standards)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

# Check if SELinux is enabled
if ! command -v getenforce &> /dev/null; then
    log_error "SELinux tools not found. Install with: yum install policycoreutils"
    exit 1
fi

SELINUX_MODE=$(getenforce)
if [[ "$SELINUX_MODE" == "Disabled" ]]; then
    log_error "SELinux is disabled. Enable it in /etc/selinux/config and reboot."
    exit 1
fi

log_info "SELinux is in ${SELINUX_MODE} mode"

# Check for required tools
for cmd in checkmodule semodule_package semodule semanage restorecon; do
    if ! command -v "$cmd" &> /dev/null; then
        log_error "Required command '$cmd' not found."
        log_error "Install with: yum install policycoreutils-python-utils selinux-policy-devel"
        exit 1
    fi
done

# Create working directory
WORK_DIR=$(mktemp -d)
trap "rm -rf ${WORK_DIR}" EXIT

log_info "Building SELinux policy module..."

# Copy policy files
cp "${PROFILE_DIR}/${POLICY_NAME}.te" "${WORK_DIR}/"
cp "${PROFILE_DIR}/${POLICY_NAME}.fc" "${WORK_DIR}/"

cd "${WORK_DIR}"

# Compile the policy module
log_info "Compiling type enforcement policy..."
if ! checkmodule -M -m -o "${POLICY_NAME}.mod" "${POLICY_NAME}.te"; then
    log_error "Failed to compile SELinux policy"
    exit 1
fi

# Package the module with file contexts
log_info "Packaging policy module..."
if ! semodule_package -o "${POLICY_NAME}.pp" -m "${POLICY_NAME}.mod" -f "${POLICY_NAME}.fc"; then
    log_error "Failed to package SELinux policy"
    exit 1
fi

# Remove old module if exists
if semodule -l | grep -q "^${POLICY_NAME}"; then
    log_info "Removing existing policy module..."
    semodule -r "${POLICY_NAME}" || true
fi

# Install the new module
log_info "Installing policy module..."
if ! semodule -i "${POLICY_NAME}.pp"; then
    log_error "Failed to install SELinux policy module"
    exit 1
fi

# Create required directories with correct contexts
log_info "Creating directories with SELinux contexts..."
mkdir -p /etc/pci-segment
mkdir -p /var/log/pci-segment
mkdir -p /var/lib/pci-segment

# Apply file contexts
log_info "Applying file contexts..."
restorecon -Rv /etc/pci-segment
restorecon -Rv /var/log/pci-segment
restorecon -Rv /var/lib/pci-segment

# Apply context to binary if it exists
if [[ -f /usr/local/bin/pci-segment ]]; then
    restorecon -v /usr/local/bin/pci-segment
fi

# Verify installation
log_info "Verifying installation..."
if semodule -l | grep -q "^${POLICY_NAME}"; then
    log_info "SELinux policy module '${POLICY_NAME}' installed successfully"
else
    log_error "Policy module installation verification failed"
    exit 1
fi

# Show file contexts
echo ""
log_info "File contexts applied:"
ls -lZ /usr/local/bin/pci-segment 2>/dev/null || echo "  (binary not yet installed)"
ls -ldZ /etc/pci-segment
ls -ldZ /var/log/pci-segment
ls -ldZ /var/lib/pci-segment

echo ""
log_info "Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Install the pci-segment binary to /usr/local/bin/"
echo "  2. Run: restorecon -v /usr/local/bin/pci-segment"
echo "  3. Update systemd service to include SELinux context:"
echo "     SELinuxContext=system_u:system_r:pci_segment_t:s0"
echo "  4. Set environment variable for verification:"
echo "     PCI_SEGMENT_SELINUX_PROFILE=pci_segment_t"
echo ""
echo "To verify the process is running in the correct domain:"
echo "  ps -eZ | grep pci-segment"
