#!/bin/bash

# PCI-GUARD Demo Script
# This script demonstrates the key features of PCI-GUARD

set -e

BINARY="./pci-guard"
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}===============================================================${NC}"
echo -e "${BLUE}   [PCI-GUARD] Demo - PCI-DSS v4.0 Microsegmentation${NC}"
echo -e "${BLUE}===============================================================${NC}"
echo ""

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo -e "${RED}Error: pci-guard binary not found${NC}"
    echo "Run: make build"
    exit 1
fi

echo -e "${GREEN}[OK] PCI-GUARD binary found${NC}"
echo ""

# Demo 1: Show help
echo -e "${YELLOW}��� Demo 1: CLI Overview ���${NC}"
$BINARY --help
echo ""
read -p "Press Enter to continue..."
echo ""

# Demo 2: Validate a good policy
echo -e "${YELLOW}��� Demo 2: Validate PCI-Compliant Policy ���${NC}"
echo -e "${BLUE}Policy: examples/policies/cde-isolation.yaml${NC}"
echo ""
$BINARY validate -f examples/policies/cde-isolation.yaml
echo ""
read -p "Press Enter to continue..."
echo ""

# Demo 3: Validate a bad policy
echo -e "${YELLOW}��� Demo 3: Detect PCI Violations ���${NC}"
echo -e "${BLUE}Policy: examples/policies/invalid-policy.yaml${NC}"
echo -e "${RED}(This should FAIL with PCI-DSS violation)${NC}"
echo ""
$BINARY validate -f examples/policies/invalid-policy.yaml || true
echo ""
read -p "Press Enter to continue..."
echo ""

# Demo 4: Generate compliance report
echo -e "${YELLOW}--- Demo 4: Generate Compliance Report ---${NC}"
echo -e "${BLUE}Generating HTML report...${NC}"
echo ""
$BINARY report -f examples/policies/cde-isolation.yaml -o demo-report.html
echo ""
echo -e "${GREEN}[OK] Report generated: demo-report.html${NC}"
echo ""

# Demo 5: Generate JSON report
echo -e "${YELLOW}--- Demo 5: JSON Report for Automation ---${NC}"
echo -e "${BLUE}Generating JSON report...${NC}"
echo ""
$BINARY report -f examples/policies/cde-isolation.yaml -o demo-report.json --format=json
echo ""
echo -e "${GREEN}[OK] JSON report contents:${NC}"
cat demo-report.json | head -20
echo "..."
echo ""
read -p "Press Enter to continue..."
echo ""

# Demo 6: Validate multiple policies
echo -e "${YELLOW}--- Demo 6: Validate Database Policy ---${NC}"
echo -e "${BLUE}Policy: examples/policies/cde-database.yaml${NC}"
echo ""
$BINARY validate -f examples/policies/cde-database.yaml
echo ""

# Summary
echo ""
echo -e "${BLUE}===============================================================${NC}"
echo -e "${GREEN}[OK] Demo Complete!${NC}"
echo -e "${BLUE}===============================================================${NC}"
echo ""
echo -e "${YELLOW}Key Features Demonstrated:${NC}"
echo "  * PCI-DSS policy validation (Req 1.2, 1.3)"
echo "  * Wildcard access detection (0.0.0.0/0)"
echo "  * Compliance report generation (HTML/JSON)"
echo "  * CDE isolation enforcement"
echo ""
echo -e "${YELLOW}Generated Files:${NC}"
echo "  * demo-report.html - Open in browser for full report"
echo "  * demo-report.json - Machine-readable for automation"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "  1. Open demo-report.html in your browser"
echo "  2. Try: $BINARY enforce -f examples/policies/cde-isolation.yaml"
echo "  3. Create your own policies in examples/policies/"
echo ""
