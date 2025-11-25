# Roadmap

## Vision

Automate PCI-DSS network segmentation and reporting with minimal operational overhead—single binary, policy-as-code, secure by default.

## Status Overview

| Area | Status | Notes |
|------|--------|-------|
| Policy engine and validation | Done | Covers Req 1.2 / 1.3 |
| Cloud sync (AWS/Azure) | Done | Drift detection included |
| Linux eBPF enforcement | Done | High-performance packet filter |
| Audit logging | Done | Tamper-evident, 90-day retention |
| CLI and documentation | Done | Commands documented |
| Privilege hardening | In Progress | Seccomp + capability drop done; MAC policies pending |
| Monitoring and metrics | Planned | Prometheus/Grafana |
| High availability | Planned | Leader election and state sync |
| Windows support | Planned | WFP integration |
| Kubernetes integration | Planned | Policy generation/operator |

## Recently Completed

- eBPF enforcement with XDP + TC programs for kernel-level filtering
- Persistent audit logging with rotation, integrity checks, and compression
- Privilege drop with seccomp-bpf syscall denylist
- Cloud drift detection for non-compliant Security Groups and NSGs
- Strict policy validation before enforcement activation

## In Progress

| Goal | Outcome | Acceptance Criteria |
|------|---------|---------------------|
| SELinux/AppArmor profiles | Harden host execution | Policies load; only needed syscalls and file paths allowed |
| Metrics endpoint | Operational visibility | Core counters exported; less than 1s scrape impact |
| Input validation hardening | Safer policy ingestion | All file paths sanitized; ports and protocols bounds-checked |
| IAM integrations | Credential security | Support role-based auth without static secrets |

## Backlog

**High Availability**
- Leader election with failover under 5 seconds
- Distributed configuration store

**Observability**
- Alert rules and violation rate tracking
- Dashboard library for Grafana

**Platform Expansion**
- Windows WFP enforcer
- GCP firewall sync
- Kubernetes operator

**Compliance Enhancements**
- SOC2/GDPR report templates
- PDF export
- SIEM connectors

**Security Enhancements**
- Fuzzing for policy parser
- Keyring-based secret storage
- Threat feed auto-block integration

## Performance Targets

| Metric | Target |
|--------|--------|
| Packet filter latency | < 100 microseconds |
| Throughput loss at 10Gbps | < 2% |
| Audit log retention | 90 days minimum |
| Enforcement uptime | 99.9% (post-HA) |
| Policy validation coverage | 100% required fields |

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Kernel feature variance | Graceful fallback; compatibility test matrix |
| Performance regression | Continuous benchmarking; perf gates in CI |
| Privilege escalation | Capability minimization + seccomp + MAC profiles |
| Credential leakage | Prefer IAM roles; never log secrets |
| Community adoption | Improve docs; add guided examples |

## Contribution Focus

Looking for help with:
- Host MAC profiles (SELinux/AppArmor)
- Monitoring stack integration
- Windows WFP enforcer
- Kubernetes operator
- Threat intelligence integration

See `CONTRIBUTING.md` for workflow and standards.
