#!/bin/bash
# install-apparmor.sh - Install AppArmor profile for pci-segment
# PCI-DSS Requirements 2.2.4 and 2.2.5
#
# Usage: sudo ./scripts/install-apparmor.sh
#
# Requires: apparmor, apparmor-utils

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE_DIR="${SCRIPT_DIR}/../pkg/security/profiles/apparmor"
PROFILE_NAME="pci-segment"
APPARMOR_DIR="/etc/apparmor.d"

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

# Check if AppArmor is enabled
if ! command -v aa-status &> /dev/null; then
    log_error "AppArmor tools not found. Install with: apt install apparmor-utils"
    exit 1
fi

# Check AppArmor status
if ! aa-status &> /dev/null; then
    log_error "AppArmor is not running. Enable with: systemctl enable --now apparmor"
    exit 1
fi

log_info "AppArmor is active"

# Check for required tools
for cmd in apparmor_parser aa-status; do
    if ! command -v "$cmd" &> /dev/null; then
        log_error "Required command '$cmd' not found."
        log_error "Install with: apt install apparmor apparmor-utils"
        exit 1
    fi
done

# Verify source profile exists
SOURCE_PROFILE="${PROFILE_DIR}/${PROFILE_NAME}"
if [[ ! -f "$SOURCE_PROFILE" ]]; then
    log_error "Profile not found: ${SOURCE_PROFILE}"
    exit 1
fi

# Create required directories
log_info "Creating directories..."
mkdir -p /etc/pci-segment
mkdir -p /var/log/pci-segment
mkdir -p /var/lib/pci-segment

# Set ownership for service account if it exists
if id pci-segment &>/dev/null; then
    chown pci-segment:pci-segment /var/log/pci-segment
    chown pci-segment:pci-segment /var/lib/pci-segment
fi

# Copy profile to AppArmor directory
log_info "Installing AppArmor profile..."
cp "${SOURCE_PROFILE}" "${APPARMOR_DIR}/${PROFILE_NAME}"
chmod 644 "${APPARMOR_DIR}/${PROFILE_NAME}"

# Parse and load the profile
log_info "Loading profile..."
if ! apparmor_parser -r "${APPARMOR_DIR}/${PROFILE_NAME}"; then
    log_error "Failed to load AppArmor profile"
    log_error "Check syntax with: apparmor_parser -p ${APPARMOR_DIR}/${PROFILE_NAME}"
    exit 1
fi

# Verify profile is loaded
log_info "Verifying installation..."
if aa-status 2>/dev/null | grep -q "${PROFILE_NAME}"; then
    log_info "AppArmor profile '${PROFILE_NAME}' loaded successfully"
else
    log_warn "Profile may be loaded but not enforcing (binary not running)"
fi

# Show current AppArmor status for pci-segment
echo ""
log_info "AppArmor status:"
aa-status 2>/dev/null | grep -A1 "profiles are in enforce mode" || true
aa-status 2>/dev/null | grep "${PROFILE_NAME}" || echo "  Profile loaded, waiting for binary execution"

echo ""
log_info "Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Install the pci-segment binary to /usr/local/bin/"
echo "  2. Update systemd service to include AppArmor profile:"
echo "     AppArmorProfile=${PROFILE_NAME}"
echo "  3. Set environment variable for verification:"
echo "     PCI_SEGMENT_APPARMOR_PROFILE=${PROFILE_NAME}"
echo ""
echo "To verify the process is confined:"
echo "  aa-status | grep ${PROFILE_NAME}"
echo "  cat /proc/\$(pgrep pci-segment)/attr/current"
echo ""
echo "To test in complain mode first:"
echo "  aa-complain /etc/apparmor.d/${PROFILE_NAME}"
echo ""
echo "To switch to enforce mode:"
echo "  aa-enforce /etc/apparmor.d/${PROFILE_NAME}"
