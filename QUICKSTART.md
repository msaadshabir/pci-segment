# Quick Start Guide - PCI-GUARD

Get up and running with PCI-GUARD in 5 minutes!

## Installation

### Option 1: Download Pre-built Binary (Fastest)

```bash
# macOS (Apple Silicon)
curl -L https://github.com/saad-build/pci-segment/releases/latest/download/pci-guard-darwin-arm64 -o pci-guard
chmod +x pci-guard
sudo mv pci-guard /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/saad-build/pci-segment/releases/latest/download/pci-guard-darwin-amd64 -o pci-guard
chmod +x pci-guard
sudo mv pci-guard /usr/local/bin/

# Linux (x86_64)
curl -L https://github.com/saad-build/pci-segment/releases/latest/download/pci-guard-linux-amd64 -o pci-guard
chmod +x pci-guard
sudo mv pci-guard /usr/local/bin/
```

### Option 2: Build from Source

```bash
git clone https://github.com/saad-build/pci-segment.git
cd pci-segment
make build
```

## Verify Installation

```bash
pci-guard --version
# Output: pci-guard version 1.0.0
```

## 5-Minute Tutorial

### Step 1: Validate Your First Policy (30 seconds)

```bash
# Download example policy
curl -O https://raw.githubusercontent.com/saad-build/pci-segment/main/examples/policies/cde-isolation.yaml

# Validate it
pci-guard validate -f cde-isolation.yaml
```

**Expected Output:**

```
[POLICY] cde-isolation
   API Version: pci-guard/v1
   Kind: NetworkPolicy
   PCI-DSS: [Req 1.2, Req 1.3]
   Status: [OK] VALID

[OK] All policies are valid and PCI-DSS compliant
```

### Step 2: Test PCI Violation Detection (30 seconds)

```bash
# Create a policy that violates PCI-DSS
cat > bad-policy.yaml <<EOF
apiVersion: pci-guard/v1
kind: NetworkPolicy
metadata:
  name: bad-policy
  annotations:
    pci-dss: "Req 1.3"
spec:
  podSelector:
    matchLabels:
      pci-env: cde
  ingress:
  - from:
    - ipBlock:
        cidr: 0.0.0.0/0  # VIOLATION!
    ports:
    - protocol: TCP
      port: 443
EOF

# Try to validate it
pci-guard validate -f bad-policy.yaml
```

**Expected Output:**

```
Error: validation failed: CDE policy cannot allow access from 0.0.0.0/0 (PCI-DSS Req 1.3 violation)
```

### Step 3: Generate Compliance Report (1 minute)

```bash
# Generate HTML report
pci-guard report -f cde-isolation.yaml -o my-report.html

# Open in browser
open my-report.html  # macOS
xdg-open my-report.html  # Linux
```

### Step 4: Create Your Own Policy (2 minutes)

```bash
# Create a policy for your payment gateway
cat > payment-gateway.yaml <<EOF
apiVersion: pci-guard/v1
kind: NetworkPolicy
metadata:
  name: payment-gateway-policy
  annotations:
    pci-dss: "Req 1.2, Req 1.3"
    description: "Isolate payment gateway from internal networks"
spec:
  podSelector:
    matchLabels:
      pci-env: cde
      app: payment-gateway

  # Allow outbound to payment processor only
  egress:
  - to:
    - ipBlock:
        cidr: 203.0.113.0/24  # Replace with your payment processor IPs
    ports:
    - protocol: TCP
      port: 443

  # Allow inbound from web tier only
  ingress:
  - from:
    - ipBlock:
        cidr: 10.0.1.0/24  # Replace with your web tier subnet
    ports:
    - protocol: TCP
      port: 8443
EOF

# Validate your policy
pci-guard validate -f payment-gateway.yaml
```

### Step 5: Enforce Policies (1 minute)

```bash
# Start enforcement (requires sudo on macOS for pf)
sudo pci-guard enforce -f payment-gateway.yaml

# The enforcer will generate firewall rules and start blocking
# unauthorized traffic to your CDE
```

## Common Use Cases

### Use Case 1: Audit Preparation

```bash
# Generate report for all policies
pci-guard report -f policies/*.yaml -o audit-report.html

# Generate JSON for automation
pci-guard report -f policies/*.yaml -o audit-data.json --format=json
```

### Use Case 2: CI/CD Integration

```yaml
# .github/workflows/pci-compliance.yml
name: PCI Compliance Check
on: [push, pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Validate PCI Policies
        run: |
          curl -L https://github.com/saad-build/pci-segment/releases/latest/download/pci-guard-linux-amd64 -o pci-guard
          chmod +x pci-guard
          ./pci-guard validate -f policies/*.yaml
```

### Use Case 3: Development Testing

```bash
# Validate policies on file change
find policies/ -name "*.yaml" | entr pci-guard validate -f /_
```

## Troubleshooting

### Error: "policy validation failed"

**Cause**: Policy violates PCI-DSS requirements

**Solution**: Check error messages for specific violations

```bash
pci-guard validate -f your-policy.yaml -v
```

### Error: "permission denied" (macOS)

**Cause**: pf (packet filter) requires root privileges

**Solution**: Use sudo

```bash
sudo pci-guard enforce -f your-policy.yaml
```

### Error: "failed to load policy"

**Cause**: Invalid YAML syntax

**Solution**: Validate YAML syntax

```bash
# Check YAML syntax
yamllint your-policy.yaml

# Or use a YAML validator online
```

## Next Steps

### Learn More

- Read the [Full Documentation](README.md)
- Study [Example Policies](examples/policies/)
- Review [Design Document](DESIGN.md)

### Advanced Usage

- Set up [Cloud Integration](docs/cloud-integration.md) (AWS/Azure)
- Configure [Real-time Monitoring](docs/monitoring.md)
- Integrate with [CI/CD](docs/cicd-integration.md)

### Get Involved

- Report [Issues](https://github.com/saad-build/pci-segment/issues)
- Submit [Pull Requests](CONTRIBUTING.md)
- Join [Discussions](https://github.com/saad-build/pci-segment/discussions)

## Quick Reference

### Commands

```bash
# Validate policy
pci-guard validate -f <policy.yaml>

# Enforce policies
pci-guard enforce -f <policy.yaml>

# Generate report
pci-guard report -f <policy.yaml> -o <output.html>

# Show version
pci-guard --version

# Get help
pci-guard --help
pci-guard <command> --help
```

### Policy Template

```yaml
apiVersion: pci-guard/v1
kind: NetworkPolicy
metadata:
  name: my-policy
  annotations:
    pci-dss: "Req 1.2, Req 1.3"
spec:
  podSelector:
    matchLabels:
      pci-env: cde # Required for CDE policies
  egress:
    - to:
        - ipBlock:
            cidr: 10.0.10.0/24
      ports:
        - protocol: TCP
          port: 443
```

## Support

- **Documentation**: [README.md](README.md)
- **Issues**: [GitHub Issues](https://github.com/saad-build/pci-segment/issues)
- **Email**: saad@example.com

---

**Ready to secure your CDE? Start with `pci-guard validate`!**
