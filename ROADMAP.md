# Roadmap

Automate PCI-DSS network segmentation and reporting with minimal operational overhead—single binary, policy-as-code, secure by default.

## Features

| Feature                                                  | Status      |
| -------------------------------------------------------- | ----------- |
| Policy engine and validation (Req 1.2/1.3)               | Done        |
| Cloud sync (AWS/Azure) with drift detection              | Done        |
| Linux eBPF enforcement                                   | Done        |
| Audit logging (tamper-evident, 90-day retention)         | Done        |
| CLI and documentation                                    | Done        |
| Privilege hardening (seccomp, capability drop)           | Done        |
| SELinux/AppArmor profiles                                | Done        |
| Prometheus metrics endpoint                              | Done        |
| Health check endpoint (`/healthz`)                       | Done        |
| Enforcer unit tests                                      | Done        |
| Integration test suite                                   | In Progress |
| Daemon mode with systemd service                         | Planned     |
| Configuration file (`/etc/pci-segment/config.yaml`)      | Planned     |
| Policy rollback with state snapshots                     | Planned     |
| Graceful shutdown with connection draining               | Planned     |
| Log levels (debug, info, warn, error)                    | Planned     |
| Dry-run diff output                                      | Planned     |
| Policy signing and verification                          | Planned     |
| Secrets manager integration (Vault, AWS Secrets Manager) | Planned     |
| Fleet-wide policy distribution                           | Planned     |
| Multi-tenancy with namespace isolation                   | Planned     |
| Role-based access control (RBAC)                         | Planned     |
| API server mode                                          | Planned     |
| Break-glass emergency disable                            | Planned     |
| High availability (leader election, state sync)          | Planned     |
| Backup and restore                                       | Planned     |
| Benchmark tests in CI                                    | Planned     |
| Fuzzing for policy parser                                | Planned     |
| Docker Compose for local dev                             | Planned     |
| Helm chart                                               | Planned     |
| Terraform examples                                       | Planned     |
| Windows WFP enforcer                                     | Planned     |
| GCP firewall sync                                        | Planned     |
| Kubernetes operator                                      | Planned     |
| Prometheus alert rules                                   | Planned     |
| Grafana dashboards                                       | Planned     |
| Change approval workflow integration                     | Planned     |
| Scheduled report generation                              | Planned     |
| SOC2/GDPR report templates                               | Planned     |
| PDF export                                               | Planned     |
| SIEM connectors                                          | Planned     |
| Threat feed auto-block                                   | Planned     |

## Performance Targets

| Metric                    | Target             |
| ------------------------- | ------------------ |
| Packet filter latency     | < 100 microseconds |
| Throughput loss at 10Gbps | < 2%               |
| Audit log retention       | 90 days minimum    |
| Enforcement uptime        | 99.9% (post-HA)    |
