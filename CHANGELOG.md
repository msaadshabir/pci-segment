# Changelog

All notable changes to pci-segment will be documented in this file.

## [Unreleased]

### Added

- **Cloud Integration** (Production-Ready)
  - AWS Security Group synchronization with auto-remediation
  - Azure Network Security Group (NSG) synchronization
  - Cloud resource validation and drift detection
  - `pci-segment cloud-sync` command with dry-run support
  - `pci-segment cloud-validate` command with text/JSON output
  - Multi-cloud support (AWS and Azure)
  - Automatic tagging for managed resources
  - Cloud configuration via YAML files
  - Example configurations for AWS and Azure
  - Comprehensive cloud integration documentation
  - Test coverage for cloud provider implementations

### Documentation

- **Updated Roadmap** - Added detailed production readiness assessment
  - Phase 1: Critical security features (eBPF, audit logging, hardening)
  - Phase 2: Enterprise features (monitoring, HA)
  - Phase 3: Additional platforms (Windows, GCP, Kubernetes)
  - Phase 4: Enhanced compliance (SOC2, GDPR, SIEM)
- **Enhanced Limitations Section** - Transparent about current gaps
  - eBPF enforcement is skeleton-only (not production-ready)
  - Audit logging needs persistent storage
  - No real-time monitoring yet
- **Created ROADMAP.md** - Detailed 12-week implementation plan

### Known Issues

- **Linux eBPF Enforcement**: Skeleton implementation only, does not block traffic
  - Use cloud integration for production deployments
  - Full implementation planned for Phase 1 (4 weeks)
- **Audit Logging**: Events stored in memory only, not persistent
  - Not compliant with PCI-DSS Req 10.2
  - Persistent storage planned for Phase 1 (1 week)
- **No Monitoring**: No Prometheus metrics or alerting
  - Manual compliance checks only
  - Planned for Phase 2 (2 weeks)

## [1.0.0] - Current Release

### Implemented Features

- **PCI-DSS Policy Engine**

  - Policy validation against PCI-DSS v4.0 Requirements 1.2 and 1.3
  - YAML-based policy definitions with API version `pci-segment/v1`
  - Wildcard access detection (blocks `0.0.0.0/0` to CDE)
  - CDE label validation (`pci-env: cde`)

- **OS-Native Enforcement**

  - macOS packet filter (pf) implementation - fully functional
  - Linux eBPF enforcement structure (implementation pending)
  - Interface-based design for cross-platform support

- **Compliance Reporter**

  - HTML report generation with audit-ready formatting
  - JSON report output for automation and integration
  - Executive summary with compliance status
  - Policy inventory and validation details

- **Command-Line Interface**

  - `pci-segment validate` - Validate policies against PCI-DSS requirements
  - `pci-segment enforce` - Enforce network segmentation policies
  - `pci-segment report` - Generate compliance reports
  - Verbose mode and multiple output formats

- **Documentation**
  - Comprehensive README with installation and usage instructions
  - Quick start guide for 5-minute setup
  - Contributing guidelines
  - Project structure documentation

### Planned Features

- Real-time monitoring and alerting system
- Windows WFP (Windows Filtering Platform) support
- PDF report generation
- Kubernetes Cilium integration
- SOC2/GDPR policy templates
- Threat intelligence integration
- Multi-region cloud deployment
- GCP Cloud Firewall support

### Technical Stack

- **Language**: Go 1.23+
- **Enforcement**: eBPF (Linux), pf (macOS)
- **CLI Framework**: Cobra
- **Configuration**: YAML
- **Testing**: Go test framework with table-driven tests
- **Build System**: Make
- **CI/CD**: GitHub Actions

### Project Metadata

- **License**: MIT
- **Repository**: https://github.com/msaadshabir/pci-segment
- **Binary Name**: `pci-segment`
- **API Version**: `pci-segment/v1`
