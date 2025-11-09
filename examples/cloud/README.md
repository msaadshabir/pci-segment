# Cloud Integration Guide

This guide explains how to use pci-segment to automatically enforce PCI-DSS policies in AWS and Azure.

## Overview

pci-segment can automatically sync your PCI-DSS network policies to cloud security resources:

- **AWS**: Security Groups
- **Azure**: Network Security Groups (NSGs)

This enables auto-remediation: any drift from your policies is automatically corrected.

---

## Features

-**Automatic Sync**: Create/update cloud security groups based on policies -**Validation**: Check existing cloud resources for PCI-DSS compliance -**Dry Run Mode**: Preview changes before applying -**Tagging**: Automatic tagging for tracking and compliance -**Multi-Cloud**: Support for AWS and Azure -**Drift Detection**: Identify resources that don't match policies

---

## Prerequisites

### AWS

**Required IAM Permissions:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSecurityGroups",
        "ec2:CreateSecurityGroup",
        "ec2:DeleteSecurityGroup",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupEgress",
        "ec2:CreateTags",
        "ec2:DescribeVpcs"
      ],
      "Resource": "*"
    }
  ]
}
```

**Authentication Methods:**

1. AWS Profile (recommended for local)
2. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
3. IAM instance profile (recommended for EC2)

### Azure

**Required Permissions:**

- `Microsoft.Network/networkSecurityGroups/read`
- `Microsoft.Network/networkSecurityGroups/write`
- `Microsoft.Network/networkSecurityGroups/delete`

**Authentication:**

- Service Principal with Client Secret

---

## Quick Start

### 1. Create Cloud Configuration

**AWS Example (`aws-config.yaml`):**

```yaml
provider: aws
region: us-east-1
dry_run: true # Preview changes first

aws:
  profile: default
  vpc_ids:
    - vpc-0123456789abcdef0

tags:
  Environment: production
  ManagedBy: pci-segment
```

**Azure Example (`azure-config.yaml`):**

```yaml
provider: azure
region: eastus
dry_run: true

azure:
  subscription_id: YOUR_SUBSCRIPTION_ID
  tenant_id: YOUR_TENANT_ID
  client_id: YOUR_CLIENT_ID
  client_secret: YOUR_CLIENT_SECRET
  resource_groups:
    - pci-cde-rg

tags:
  Environment: production
  ManagedBy: pci-segment
```

### 2. Sync Policies to Cloud (Dry Run)

```bash
# Preview changes without applying
pci-segment cloud-sync \
  -f examples/policies/cde-isolation.yaml \
  -c aws-config.yaml \
  --dry-run
```

**Output:**

```
[OK] Loaded 1 polic(ies)

[VALIDATING] Policies...
[OK] Policy 'cde-isolation' is valid

[CONNECTING] to aws us-east-1...

[DRY RUN] Showing changes without applying...

[SYNC RESULTS]
   Provider: aws
   Dry Run: true
   Resources Added: 1
   Resources Updated: 0
   Resources Deleted: 0

   Changes:
   [OK] create: pci-segment-cde-isolation - Created security group in VPC vpc-0123456789abcdef0

[OK] Cloud sync complete
```

### 3. Apply Changes

```bash
# Remove --dry-run to apply changes
pci-segment cloud-sync \
  -f examples/policies/cde-isolation.yaml \
  -c aws-config.yaml
```

### 4. Validate Compliance

```bash
# Check if cloud resources match policies
pci-segment cloud-validate \
  -f examples/policies/cde-isolation.yaml \
  -c aws-config.yaml
```

**Output:**

```
[CONNECTING] to aws us-east-1...

[VALIDATING] Cloud resources...

[VALIDATION REPORT]
   Provider: aws
  Timestamp: <RFC3339 time>
   Resources Checked: 3
   Status: [!] NON-COMPLIANT

   Violations (1):

   1. legacy-sg - critical
      Resource ID: sg-0abcdef1234567890
      Policy: wildcard-check
      Issue: Security group allows access from 0.0.0.0/0 (violates PCI-DSS Req 1.3)
      Fix: Remove wildcard CIDR and specify exact IP ranges

[!] Cloud resources are not compliant with PCI-DSS policies
```

---

## Usage Examples

### Sync Multiple Policies

```bash
pci-segment cloud-sync \
  -f examples/policies/*.yaml \
  -c aws-config.yaml
```

### Validate with JSON Output

```bash
pci-segment cloud-validate \
  -f examples/policies/cde-isolation.yaml \
  -c azure-config.yaml \
  --format=json > compliance-report.json
```

### Cross-Cloud Deployment

```bash
# Sync to AWS
pci-segment cloud-sync -f policies/ -c aws-config.yaml

# Sync to Azure
pci-segment cloud-sync -f policies/ -c azure-config.yaml
```

---

## How It Works

### Policy to Cloud Mapping

**PCI-DSS Policy:**

```yaml
apiVersion: pci-segment/v1
kind: NetworkPolicy
metadata:
  name: cde-isolation
  annotations:
    pci-dss: "Req 1.2, Req 1.3"
spec:
  podSelector:
    matchLabels:
      pci-env: cde
  ingress:
    - from:
        - ipBlock:
            cidr: 10.0.20.0/24
      ports:
        - protocol: TCP
          port: 9090
  egress:
    - to:
        - ipBlock:
            cidr: 10.0.10.0/24
      ports:
        - protocol: TCP
          port: 443
```

**Resulting AWS Security Group:**

- **Name**: `pci-segment-cde-isolation`
- **Tags**:
  - `pci-segment/managed: true`
  - `pci-segment/policy: cde-isolation`
  - `pci-dss: Req 1.2, Req 1.3`
- **Ingress Rules**:
  - Allow TCP port 9090 from 10.0.20.0/24
- **Egress Rules**:
  - Allow TCP port 443 to 10.0.10.0/24

---

## Best Practices

### 1. Always Use Dry Run First

```bash
pci-segment cloud-sync -f policies/ -c config.yaml --dry-run
```

Review changes before applying.

### 2. Version Control Your Configs

```bash
git add examples/cloud/*.yaml
git commit -m "Update cloud config for production"
```

### 3. Use IAM Roles (AWS) or Managed Identity (Azure)

Avoid hardcoding credentials in configuration files.

### 4. Tag Everything

```yaml
tags:
  Environment: production
  Owner: security-team
  Compliance: pci-dss
  ManagedBy: pci-segment
```

### 5. Regular Validation

```bash
# Run daily
pci-segment cloud-validate -f policies/ -c config.yaml --format=json > report.json
```

### 6. Separate Configs per Environment

```
cloud/
  ├── aws-dev.yaml
  ├── aws-staging.yaml
  ├── aws-prod.yaml
  ├── azure-dev.yaml
  └── azure-prod.yaml
```

---

## Troubleshooting

### AWS: "No default VPC found"

**Solution:** Specify VPC IDs explicitly:

```yaml
aws:
  vpc_ids:
    - vpc-0123456789abcdef0
```

### Azure: "Authentication failed"

**Solution:** Verify service principal credentials:

```bash
az login --service-principal \
  --username YOUR_CLIENT_ID \
  --password YOUR_CLIENT_SECRET \
  --tenant YOUR_TENANT_ID
```

### "Policy validation failed"

**Solution:** Validate policies locally first:

```bash
pci-segment validate -f policies/your-policy.yaml
```

### Permissions Errors

**AWS:**

```bash
# Test permissions
aws ec2 describe-security-groups --profile your-profile
```

**Azure:**

```bash
# Test permissions
az network nsg list --resource-group pci-cde-rg
```

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Sync to Cloud

on:
  push:
    branches: [main]
    paths:
      - "policies/**"

jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup pci-segment
        run: |
          curl -L https://github.com/msaadshabir/pci-segment/releases/latest/download/pci-segment-linux-amd64 -o pci-segment
          chmod +x pci-segment

      - name: Validate policies
        run: ./pci-segment validate -f policies/*.yaml

      - name: Sync to AWS
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: ./pci-segment cloud-sync -f policies/ -c aws-config.yaml

      - name: Validate AWS resources
        run: ./pci-segment cloud-validate -f policies/ -c aws-config.yaml
```

---

## Security Considerations

1. **Least Privilege**: Grant only necessary IAM/RBAC permissions
2. **Audit Logging**: Enable CloudTrail (AWS) or Activity Log (Azure)
3. **Secrets Management**: Use AWS Secrets Manager or Azure Key Vault
4. **Network Isolation**: Run pci-segment from a secure bastion/jump host
5. **Review Changes**: Always use `--dry-run` in production

---

## Limitations

- **Stateful Rules**: Cloud security groups are stateful (allow implies return traffic)
- **Rule Limits**: AWS: 60 ingress + 60 egress per SG; Azure: 200 total per NSG
- **Regional**: Must sync separately to each region
- **Managed Only**: Only updates resources with `pci-segment/managed` tag

---

## Next Steps

- [Example Policies](../policies/)
- [Main README](../../README.md)
- [Contributing Guide](../../CONTRIBUTING.md)

---

**Need Help?**

[Full Documentation](../../README.md)
[Report Issues](https://github.com/msaadshabir/pci-segment/issues)
[Discussions](https://github.com/msaadshabir/pci-segment/discussions)
