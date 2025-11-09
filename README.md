# pci-segment

**Open-source PCI-DSS v4.0 network segmentation for fintech**

Automate compliance for Requirements 1.2 & 1.3 with policy-as-code, cloud auto-remediation, and auditor-ready reports. Free alternative to $50k+/year commercial tools.

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)](https://go.dev)
[![PCI-DSS](https://img.shields.io/badge/PCI--DSS-v4.0-green)](https://www.pcisecuritystandards.org)
[![Linux](https://img.shields.io/badge/Linux-eBPF-FCC624?logo=linux&logoColor=black)](https://ebpf.io)
[![AWS](https://img.shields.io/badge/AWS-Security_Groups-FF9900?logo=amazon-aws&logoColor=white)](https://aws.amazon.com)
[![Azure](https://img.shields.io/badge/Azure-NSG-0078D4?logo=microsoft-azure&logoColor=white)](https://azure.microsoft.com)
[![macOS](https://img.shields.io/badge/macOS-pf_firewall-000000?logo=apple&logoColor=white)](https://www.apple.com/macos)

[Quick Start](#quick-start) • [Documentation](#documentation) • [Cloud Integration](examples/cloud/README.md) • [Roadmap](ROADMAP.md)

</div>

---

## The Problem

**80% of PCI-DSS failures** stem from poor network segmentation _(Verizon 2023 PCI Report)_

| Challenge                             | pci-segment Solution            |
| ------------------------------------- | ------------------------------- |
| Commercial tools cost $50k-$100k/year | Free, open-source (MIT license) |
| Complex setup, vendor lock-in         | Single binary, YAML policies    |
| Manual compliance validation          | Automated reports for auditors  |
| No cloud integration                  | AWS/Azure auto-remediation      |

---

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

| Feature                | Description                                  | Status               |
| ---------------------- | -------------------------------------------- | -------------------- |
| **Policy Validation**  | Enforce PCI-DSS Req 1.2/1.3 with YAML        | Production-ready     |
| **Cloud Sync**         | Auto-update AWS Security Groups & Azure NSGs | Production-ready     |
| **Drift Detection**    | Find non-compliant cloud resources           | Production-ready     |
| **Compliance Reports** | Generate HTML/JSON for QSA audits            | Production-ready     |
| **Host Enforcement**   | eBPF packet filtering (Linux)                | **Production-ready** |

### Compliance Coverage

<details>
<summary><b>PCI-DSS Requirements Mapped</b></summary>

| Requirement   | Implementation                                 |
| ------------- | ---------------------------------------------- |
| **Req 1.2**   | Network segmentation via default-deny policies |
| **Req 1.3**   | CDE isolation with explicit allow rules only   |
| **Req 10.2**  | Audit logging of all enforcement events        |
| **Req 12.10** | Executive summary reports for assessors        |

</details>

---

## Quick Start

### Installation

```bash
# macOS (Apple Silicon)
curl -L https://github.com/msaadshabir/pci-segment/releases/latest/download/pci-segment-darwin-arm64 -o pci-segment
chmod +x pci-segment && sudo mv pci-segment /usr/local/bin/

# Linux (x86_64)
curl -L https://github.com/msaadshabir/pci-segment/releases/latest/download/pci-segment-linux-amd64 -o pci-segment
chmod +x pci-segment && sudo mv pci-segment /usr/local/bin/

# Or build from source (Go 1.25+)
git clone https://github.com/msaadshabir/pci-segment.git
cd pci-segment && go build -o pci-segment .
```

### Basic Usage

**1. Validate a policy**

```bash
pci-segment validate -f examples/policies/cde-isolation.yaml
```

**2. Sync to cloud** (AWS/Azure)

```bash
pci-segment cloud-sync -f examples/policies/*.yaml -c cloud-config.yaml --dry-run
```

**3. Generate compliance report**

```bash
pci-segment report -f examples/policies/*.yaml -o audit-report.html
```

#### Linux privilege hardening (required for production)

```bash
# One-time setup (create service account)
sudo groupadd --system pci-segment || true
sudo useradd --system --gid pci-segment --home-dir /var/lib/pci-segment \
  --create-home --shell /usr/sbin/nologin pci-segment || true

# Enforce with automatic privilege drop
sudo PCI_SEGMENT_PRIVILEGE_USER=pci-segment \
     PCI_SEGMENT_PRIVILEGE_GROUP=pci-segment \
     pci-segment enforce -f policies/*.yaml
```

By default the CLI drops root after attaching eBPF programs, retaining only
`CAP_BPF` and `CAP_NET_ADMIN` and installing a seccomp-bpf denylist to block
dangerous syscalls like `ptrace`, module loading, and mount operations. Use
`PCI_SEGMENT_SKIP_PRIVILEGE_DROP=1`, `PCI_SEGMENT_DISABLE_SECCOMP=1`, or
`--allow-root` for development overrides. See [`docs/HARDENING.md`](docs/HARDENING.md)
for full guidance.

<details>
<summary><b>Show example policy</b></summary>

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
      pci-env: cde # CDE workloads only

  egress: # Allow outbound to payment processors only
    - to:
        - ipBlock:
            cidr: 10.0.10.0/24
      ports:
        - protocol: TCP
          port: 443

  ingress: # Allow inbound from monitoring only
    - from:
        - ipBlock:
            cidr: 10.0.20.0/24
      ports:
        - protocol: TCP
          port: 9090
```

</details>

---

## Documentation

### Command Reference

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

<details>
<summary><b>Cloud Sync Examples</b></summary>

```bash
# Preview AWS Security Group changes
pci-segment cloud-sync \
  -f policies/*.yaml \
  -c aws-config.yaml \
  --dry-run

# Apply Azure NSG updates
pci-segment cloud-sync \
  -f policies/cde-isolation.yaml \
  -c azure-config.yaml

# Validate compliance across cloud
pci-segment cloud-validate \
  -f policies/*.yaml \
  -c cloud-config.yaml \
  --format=json > report.json
```

See [Cloud Integration Guide](examples/cloud/README.md) for setup details.

For host hardening, follow [`docs/HARDENING.md`](docs/HARDENING.md).

</details>

<details>
<summary><b>Policy Examples</b></summary>

**CDE Database Access**

```yaml
apiVersion: pci-segment/v1
kind: NetworkPolicy
metadata:
  name: cde-database
  annotations:
    pci-dss: "Req 1.2, Req 1.3"
spec:
  podSelector:
    matchLabels:
      pci-env: cde
      tier: database
  ingress:
    - from:
        - ipBlock:
            cidr: 10.0.1.0/24 # App servers only
      ports:
        - protocol: TCP
          port: 5432 # PostgreSQL
  egress: [] # Database cannot initiate outbound
```

More examples in [`examples/policies/`](examples/policies/)

</details>

---

## Production Readiness

### Current Status

| Component                   | Status               | Notes                                       |
| --------------------------- | -------------------- | ------------------------------------------- |
| AWS/Azure Cloud Integration | **Production-ready** | Deploy today                                |
| Policy Validation Engine    | **Production-ready** | Deploy today                                |
| Compliance Reporting        | **Production-ready** | Deploy today                                |
| Linux eBPF Enforcement      | **Production-ready** | Deploy today (requires Linux kernel 5.4+)   |
| Audit Logging               | **Production-ready** | Persistent, tamper-proof (90-day retention) |
| Monitoring/Alerting         | **Planned**          | [Phase 2](ROADMAP.md#phase-2)               |

**Important**: For production PCI-DSS compliance:

- **Cloud**: Use AWS/Azure integration (production-ready)
- **Linux hosts**: Use eBPF enforcement (production-ready, requires kernel 5.4+)
- **Audit logging**: Persistent storage with tamper detection (production-ready)
- **Privilege hardening**: Run `pci-segment enforce` as root only for start-up; it now
  automatically drops to the `pci-segment` service account, retains only
  `CAP_BPF`/`CAP_NET_ADMIN`, and applies a seccomp-bpf denylist. Set
  `PCI_SEGMENT_SKIP_PRIVILEGE_DROP=1`, `PCI_SEGMENT_DISABLE_SECCOMP=1`, or pass
  `--allow-root` for development overrides.

See [ROADMAP.md](ROADMAP.md) for complete feature status.

### Known Limitations

<details>
<summary><b>Production Deployment Constraints</b></summary>

**Host Enforcement**

- Linux eBPF: **Production-ready** (kernel 5.4+, IPv4 only)
- macOS pf: Development/testing only, requires sudo
- Windows: Not yet supported (planned Phase 3)

**Infrastructure**

- Single instance only (no HA/clustering)
- No real-time metrics export (Prometheus planned Phase 2)

**Cloud Features**

- Security Groups are stateful (differs from traditional firewalls)
- AWS/Azure only (GCP planned Phase 3)

</details>

---

## Roadmap

### Completed

- [x] PCI-DSS policy engine & validation
- [x] AWS Security Groups auto-sync
- [x] Azure NSG auto-sync
- [x] Cloud drift detection
- [x] HTML/JSON compliance reports
- [x] CLI with dry-run support
- [x] **eBPF packet filtering (Linux kernel-level enforcement)**
- [x] **Persistent audit logging with tamper detection**
- [x] Azure NSG auto-sync
- [x] Cloud drift detection
- [x] HTML/JSON compliance reports
- [x] CLI with dry-run support
- [x] **eBPF packet filtering (Linux kernel-level enforcement)**

### In Progress

- Security hardening (SELinux/AppArmor profiles, expanded input validation)
- Observability (Prometheus metrics, Grafana dashboards)
- High availability (leader election, distributed config)
- Platform expansion (Windows WFP, Kubernetes operator)

See the simplified [ROADMAP.md](ROADMAP.md) for current priorities and timelines.

---

## Architecture

### Components

| Layer                | Technology               | Purpose                             |
| -------------------- | ------------------------ | ----------------------------------- |
| **Policy Engine**    | Go + YAML                | Parse and validate PCI-DSS policies |
| **Enforcer**         | eBPF (Linux), pf (macOS) | Kernel-level packet filtering       |
| **Cloud Integrator** | AWS/Azure SDKs           | Sync to Security Groups/NSGs        |
| **Reporter**         | HTML templates           | Generate QSA audit reports          |
| **CLI**              | Cobra framework          | User interface                      |

### Security Model

| Threat              | Mitigation                             |
| ------------------- | -------------------------------------- |
| Policy bypass       | Kernel-level enforcement (eBPF)        |
| Label spoofing      | Validation against trusted inventory   |
| Credential exposure | Never log secrets, use cloud IAM roles |
| Enforcer compromise | Drop privileges, minimal syscalls      |

---

## Contributing

Contributions welcome! We need help with:

- **eBPF development** (kernel networking experts)
- **Security hardening** (penetration testing)
- **Platform support** (Windows WFP, GCP)
- **Documentation** (tutorials, use cases)

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
git clone https://github.com/msaadshabir/pci-segment.git
cd pci-segment
make deps     # Install dependencies
make build    # Build binary
make test     # Run tests
make lint     # Run linters
```

---

## Support

- **Documentation**: [examples/cloud/README.md](examples/cloud/README.md)
- **Issues**: [GitHub Issues](https://github.com/msaadshabir/pci-segment/issues)
- **Discussions**: [GitHub Discussions](https://github.com/msaadshabir/pci-segment/discussions)
- **Security**: Report vulnerabilities via GitHub Security Advisories

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Why pci-segment?

**Solves a $50k/year problem for payment processors**

| Traditional Approach               | pci-segment                |
| ---------------------------------- | -------------------------- |
| Illumio, Tufin: $50k-$100k/year    | Free, open-source          |
| Vendor lock-in, complex deployment | Single binary, YAML config |
| No cloud integration               | AWS/Azure auto-remediation |
| Manual compliance validation       | Automated QSA reports      |

Built for the fintech community with production-grade Go, eBPF, and cloud-native architecture.

---

<div align="center">

**[Get Started](#quick-start)** • **[Read the Docs](#documentation)** • **[View Roadmap](ROADMAP.md)**

_Production-ready cloud features available today_

</div>
