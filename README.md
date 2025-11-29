# pci-segment

Open-source PCI-DSS v4.0 network segmentation for fintech.

Automate compliance for Requirements 1.2 and 1.3 with policy-as-code, cloud auto-remediation, and auditor-ready reports. Free alternative to commercial tools costing $50k+/year.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)](https://go.dev)
[![PCI-DSS](https://img.shields.io/badge/PCI--DSS-v4.0-green)](https://www.pcisecuritystandards.org)
[![Linux](https://img.shields.io/badge/Linux-eBPF-FCC624?logo=linux&logoColor=black)](https://ebpf.io)
[![AWS](https://img.shields.io/badge/AWS-Security_Groups-FF9900?logo=amazon-aws&logoColor=white)](https://aws.amazon.com)
[![Azure](https://img.shields.io/badge/Azure-NSG-0078D4?logo=microsoft-azure&logoColor=white)](https://azure.microsoft.com)
[![macOS](https://img.shields.io/badge/macOS-pf_firewall-000000?logo=apple&logoColor=white)](https://www.apple.com/macos)

## The Problem

80% of PCI-DSS failures stem from poor network segmentation.

| Challenge                             | pci-segment Solution            |
| ------------------------------------- | ------------------------------- |
| Commercial tools cost $50k-$100k/year | Free, open-source (MIT license) |
| Complex setup, vendor lock-in         | Single binary, YAML policies    |
| Manual compliance validation          | Automated reports for auditors  |
| No cloud integration                  | AWS/Azure auto-remediation      |

## What It Does

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│ YAML Policy │─────▶│ Policy Engine│─────▶│ Enforcement │
│ (Req 1.2/1.3│      │  Validator   │      │ eBPF / Cloud│
└─────────────┘      └──────┬───────┘      └─────────────┘
                            │
                     ┌──────▼───────┐
                     │   Reporter   │
                     │  HTML / JSON │
                     └──────────────┘
```

### Core Capabilities

| Feature            | Description                                    | Status           |
| ------------------ | ---------------------------------------------- | ---------------- |
| Policy Validation  | Enforce PCI-DSS Req 1.2/1.3 with YAML          | Production-ready |
| Cloud Sync         | Auto-update AWS Security Groups and Azure NSGs | Production-ready |
| Drift Detection    | Find non-compliant cloud resources             | Production-ready |
| Compliance Reports | Generate HTML/JSON for QSA audits              | Production-ready |
| Host Enforcement   | eBPF packet filtering (Linux)                  | Production-ready |

### Compliance Coverage

| Requirement | Implementation                                 |
| ----------- | ---------------------------------------------- |
| Req 1.2     | Network segmentation via default-deny policies |
| Req 1.3     | CDE isolation with explicit allow rules only   |
| Req 10.2    | Audit logging of all enforcement events        |
| Req 12.10   | Executive summary reports for assessors        |

## Quick Start

### Installation

```bash
# macOS (Apple Silicon)
curl -L https://github.com/msaadshabir/pci-segment/releases/latest/download/pci-segment-darwin-arm64 -o pci-segment
chmod +x pci-segment && sudo mv pci-segment /usr/local/bin/

# Linux (x86_64)
curl -L https://github.com/msaadshabir/pci-segment/releases/latest/download/pci-segment-linux-amd64 -o pci-segment
chmod +x pci-segment && sudo mv pci-segment /usr/local/bin/

# Build from source (Go 1.25+)
git clone https://github.com/msaadshabir/pci-segment.git
cd pci-segment && go build -o pci-segment .
```

### Basic Usage

**Validate a policy:**

```bash
pci-segment validate -f examples/policies/cde-isolation.yaml
```

**Sync to cloud (AWS/Azure):**

```bash
pci-segment cloud-sync -f examples/policies/*.yaml -c cloud-config.yaml --dry-run
```

**Generate compliance report:**

```bash
pci-segment report -f examples/policies/*.yaml -o audit-report.html
```

### Linux Privilege Hardening

For production deployments:

```bash
# Create service account (one-time)
sudo groupadd --system pci-segment || true
sudo useradd --system --gid pci-segment --home-dir /var/lib/pci-segment \
  --create-home --shell /usr/sbin/nologin pci-segment || true

# Enforce with automatic privilege drop
sudo PCI_SEGMENT_PRIVILEGE_USER=pci-segment \
     PCI_SEGMENT_PRIVILEGE_GROUP=pci-segment \
     pci-segment enforce -f policies/*.yaml
```

By default the CLI drops root after attaching eBPF programs, retaining only `CAP_BPF` and `CAP_NET_ADMIN` and installing a seccomp-bpf denylist to block dangerous syscalls. See [docs/HARDENING.md](docs/HARDENING.md) for full guidance.

### Example Policy

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

  egress:
    - to:
        - ipBlock:
            cidr: 10.0.10.0/24
      ports:
        - protocol: TCP
          port: 443

  ingress:
    - from:
        - ipBlock:
            cidr: 10.0.20.0/24
      ports:
        - protocol: TCP
          port: 9090
```

## Command Reference

```bash
pci-segment <command> [flags]

Commands:
  validate        Validate policies against PCI-DSS requirements
  enforce         Apply policies (host-based enforcement)
  report          Generate HTML/JSON compliance reports
  cloud-sync      Sync policies to AWS/Azure security groups
  cloud-validate  Check cloud resources for compliance

Global Flags:
  -f, --file      Policy file(s) (supports globs)
  -v, --verbose   Detailed output
  -h, --help      Show help
```

## Production Readiness

| Component                   | Status           | Notes                          |
| --------------------------- | ---------------- | ------------------------------ |
| AWS/Azure Cloud Integration | Production-ready | Deploy today                   |
| Policy Validation Engine    | Production-ready | Deploy today                   |
| Compliance Reporting        | Production-ready | Deploy today                   |
| Linux eBPF Enforcement      | Production-ready | Requires Linux kernel 5.4+     |
| Audit Logging               | Production-ready | Tamper-proof, 90-day retention |
| Prometheus Metrics          | Production-ready | :9090/metrics endpoint         |

### Known Limitations

**Host Enforcement:**

- Linux eBPF: Production-ready (kernel 5.4+, IPv4 only)
- macOS pf: Development/testing only
- Windows: Not yet supported (planned)

**Infrastructure:**

- Single instance only (no HA/clustering)

**Cloud Features:**

- Security Groups are stateful
- AWS/Azure only (GCP planned)

See [ROADMAP.md](ROADMAP.md) for detailed status.

## Architecture

| Layer            | Technology               | Purpose                             |
| ---------------- | ------------------------ | ----------------------------------- |
| Policy Engine    | Go + YAML                | Parse and validate PCI-DSS policies |
| Enforcer         | eBPF (Linux), pf (macOS) | Kernel-level packet filtering       |
| Cloud Integrator | AWS/Azure SDKs           | Sync to Security Groups/NSGs        |
| Reporter         | HTML templates           | Generate QSA audit reports          |
| CLI              | Cobra framework          | User interface                      |

### Security Model

| Threat              | Mitigation                                 |
| ------------------- | ------------------------------------------ |
| Policy bypass       | Kernel-level enforcement (eBPF)            |
| Label spoofing      | Validation against trusted inventory       |
| Credential exposure | Never log secrets, use cloud IAM roles     |
| Enforcer compromise | Drop privileges, seccomp, SELinux/AppArmor |

## Documentation

- [Cloud Integration Guide](examples/cloud/README.md)
- [Hardening Guide](docs/HARDENING.md)
- [Audit Logging](pkg/audit/README.md)
- [eBPF Implementation](pkg/enforcer/bpf/README.md)

## License

MIT License - see [LICENSE](LICENSE) for details.
