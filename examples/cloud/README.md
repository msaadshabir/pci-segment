# Cloud Integration Guide

This guide explains how to use pci-segment to automatically enforce PCI-DSS policies in AWS and Azure.

## Overview

pci-segment automatically syncs PCI-DSS network policies to cloud security resources:

- **AWS**: Security Groups
- **Azure**: Network Security Groups (NSGs)

Features include automatic sync, validation, dry run mode, tagging, multi-cloud support, and drift detection.

## Prerequisites

### AWS

Required IAM permissions:

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

Authentication methods:

1. AWS Profile (recommended for local development)
2. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
3. IAM instance profile (recommended for EC2)

### Azure

Required permissions:

- `Microsoft.Network/networkSecurityGroups/read`
- `Microsoft.Network/networkSecurityGroups/write`
- `Microsoft.Network/networkSecurityGroups/delete`

Authentication: Service Principal with Client Secret

## Quick Start

### 1. Create Cloud Configuration

**AWS (`aws-config.yaml`):**

```yaml
provider: aws
region: us-east-1
dry_run: true

aws:
  profile: default
  vpc_ids:
    - vpc-0123456789abcdef0

tags:
  Environment: production
  ManagedBy: pci-segment
```

**Azure (`azure-config.yaml`):**

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

### 2. Sync Policies (Dry Run)

```bash
pci-segment cloud-sync \
  -f examples/policies/cde-isolation.yaml \
  --cloud-config aws-config.yaml \
  --dry-run
```

### 3. Apply Changes

```bash
pci-segment cloud-sync \
  -f examples/policies/cde-isolation.yaml \
  --cloud-config aws-config.yaml
```

### 4. Validate Compliance

```bash
pci-segment cloud-validate \
  -f examples/policies/cde-isolation.yaml \
  --cloud-config aws-config.yaml
```

## Usage Examples

```bash
# Sync multiple policies
pci-segment cloud-sync -f examples/policies/*.yaml --cloud-config aws-config.yaml

# Validate with JSON output
pci-segment cloud-validate -f policies/ --cloud-config azure-config.yaml --format=json > report.json

# Cross-cloud deployment
pci-segment cloud-sync -f policies/ --cloud-config aws-config.yaml
pci-segment cloud-sync -f policies/ --cloud-config azure-config.yaml

# Using Global Config
# If you set `cloud.config_file` in /etc/pci-segment/config.yaml, you can omit --cloud-config:
pci-segment --config /etc/pci-segment/config.yaml cloud-sync -f examples/policies/*.yaml --dry-run
pci-segment --config /etc/pci-segment/config.yaml cloud-validate -f examples/policies/*.yaml
```

## Policy to Cloud Mapping

A policy like this:

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

Creates an AWS Security Group with:

- Name: `pci-segment-cde-isolation`
- Tags: `pci-segment/managed: true`, `pci-segment/policy: cde-isolation`, `pci-dss: Req 1.2, Req 1.3`
- Ingress: Allow TCP 9090 from 10.0.20.0/24
- Egress: Allow TCP 443 to 10.0.10.0/24

## Best Practices

1. **Always use dry run first** to review changes before applying
2. **Version control configs** for audit trail
3. **Use IAM roles** (AWS) or Managed Identity (Azure) instead of static credentials
4. **Tag resources** for tracking and compliance
5. **Run validation regularly** as part of CI/CD or scheduled jobs
6. **Separate configs per environment** (dev, staging, prod)

## CI/CD Integration

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

      - name: Validate and sync
        env:
          AWS_ACCESS_KEY_ID: \${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: \${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: |
          ./pci-segment validate -f policies/*.yaml
          ./pci-segment cloud-sync -f policies/ --cloud-config aws-config.yaml
          ./pci-segment cloud-validate -f policies/ --cloud-config aws-config.yaml
```

## Troubleshooting

| Problem                     | Solution                                                                 |
| --------------------------- | ------------------------------------------------------------------------ |
| No default VPC found        | Specify VPC IDs in config: `aws.vpc_ids`                                 |
| Azure authentication failed | Verify service principal credentials with `az login --service-principal` |
| Policy validation failed    | Validate locally first: `pci-segment validate -f policy.yaml`            |
| AWS permission errors       | Test with: `aws ec2 describe-security-groups --profile your-profile`     |
| Azure permission errors     | Test with: `az network nsg list --resource-group pci-cde-rg`             |

## Limitations

- Cloud security groups are stateful (allow implies return traffic)
- Rule limits: AWS has 60 ingress + 60 egress per SG; Azure has 200 total per NSG
- Regional: Must sync separately to each region
- Only updates resources with `pci-segment/managed` tag

## Security Considerations

- Grant only necessary IAM/RBAC permissions
- Enable CloudTrail (AWS) or Activity Log (Azure)
- Use secrets management (AWS Secrets Manager, Azure Key Vault)
- Run pci-segment from a secure bastion host
- Always review changes with `--dry-run` in production
