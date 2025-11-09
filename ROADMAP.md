# pci-segment Roadmap

Modern, phase-free overview of direction and priorities. Focus is on clarity and transparent status.

## Vision

Automate PCI-DSS network segmentation and reporting with minimal operational overhead—single binary, policy-as-code, secure by default.

## Core Capabilities (Current)

| Area                       | Status  | Notes                                            |
| -------------------------- | ------- | ------------------------------------------------ |
| Policy engine & validation | Stable  | Covers Req 1.2 / 1.3                             |
| Cloud sync (AWS/Azure)     | Stable  | Drift detection included                         |
| Linux eBPF enforcement     | Stable  | High-performance packet filter                   |
| Audit logging              | Stable  | Tamper-evident, 90-day retention                 |
| CLI & docs                 | Stable  | Commands documented                              |
| Privilege hardening        | Partial | Seccomp + capability drop done; policies pending |
| Monitoring & metrics       | Planned | Prometheus/Grafana upcoming                      |
| High availability          | Planned | Leader election & state sync                     |
| Windows support            | Planned | WFP integration                                  |
| Kubernetes integration     | Planned | Policy generation/operator                       |

## Recently Delivered

| Item                     | Summary                                                    |
| ------------------------ | ---------------------------------------------------------- |
| eBPF Enforcement         | XDP + TC programs, kernel-level filtering                  |
| Persistent Audit Logging | Rotation, integrity checks, compression                    |
| Privilege Drop + Seccomp | Non-root execution, capability reduction, syscall denylist |
| Cloud Drift Detection    | Detects non-compliant SG/NSG state                         |
| Enforcer Validation      | Strict policy validation before activation                 |

## Near-Term

| Goal                         | Outcome                | Acceptance                                                 |
| ---------------------------- | ---------------------- | ---------------------------------------------------------- |
| SELinux/AppArmor profiles    | Harden host execution  | Policies load; only needed syscalls & file paths allowed   |
| Metrics endpoint (/metrics)  | Operational visibility | Core counters exported; <1s scrape impact                  |
| Input validation hardening   | Safer policy ingestion | All file paths sanitized; ports & protocols bounds-checked |
| IAM integrations (AWS/Azure) | Credential security    | Support role-based auth without static secrets             |

## Backlog

| Theme                   | Items                                                   |
| ----------------------- | ------------------------------------------------------- |
| High Availability       | Leader election, failover <5s, distributed config store |
| Observability Expansion | Alert rules, violation rates, dashboard library         |
| Platform Expansion      | Windows (WFP), GCP firewall sync, Kubernetes operator   |
| Compliance Enhancements | SOC2/GDPR templates, PDF export, SIEM connectors        |
| Security Enhancements   | Fuzzing parser, keyring storage, threat feed auto-block |

## Metrics Targets

| Metric                     | Target               |
| -------------------------- | -------------------- |
| Packet filter latency      | <100µs               |
| Throughput loss @10Gbps    | <2%                  |
| Audit log retention        | ≥90 days             |
| Enforcement uptime         | 99.9% (post-HA)      |
| Policy validation coverage | 100% required fields |

## Risks & Mitigations

| Risk                    | Mitigation                                       |
| ----------------------- | ------------------------------------------------ |
| Kernel feature variance | Graceful fallback; compat test matrix            |
| Performance regression  | Continuous benchmarking; perf gates in CI        |
| Privilege escalation    | Capability minimization + seccomp + MAC profiles |
| Credential leakage      | Prefer IAM roles; never log secrets              |
| Community adoption lag  | Improve docs; add guided examples                |

## Contribution Focus

Looking for help with: host MAC profiles, monitoring stack, Windows WFP, Kubernetes operator, threat intelligence integration.

See `CONTRIBUTING.md` for workflow and standards.

## Contact & Support

- Issues & Features: GitHub Issues
- Questions: GitHub Discussions
- Security: security@pci-segment.org

---

Version: 1.0.0  
Status: Active Development
