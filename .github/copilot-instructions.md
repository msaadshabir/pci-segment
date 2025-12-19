## Project Overview

pci-segment is a Go CLI for PCI-DSS network segmentation. It validates YAML policies against PCI-DSS Requirements 1.2/1.3, syncs to AWS Security Groups and Azure NSGs, enforces via eBPF (Linux) or pf (macOS), and generates HTML/JSON compliance reports.

## Architecture

```
Policy YAML -> pkg/policy/engine.go (validate) -> pkg/enforcer/ (OS-specific) -> kernel
                                               -> pkg/cloud/ (AWS/Azure sync)
                                               -> pkg/reporter/ (HTML/JSON output)
```

**Data flow**: CLI commands in `cmd/` orchestrate `pkg/` packages. The `policy.Engine` loads and validates YAML, then passes `[]policy.Policy` to enforcers or cloud integrators.

**Key interfaces**:

- `enforcer.Enforcer` - platform-agnostic enforcement (`Start`, `Stop`, `AddPolicy`)
- `cloud.Integrator` - cloud provider abstraction (`Sync`, `Validate`, `GetResources`)

## Platform-Specific Code

Use build tags with file suffixes. Real implementation goes in `_linux.go`, stubs in `_stub.go`:

```go
//go:build !linux
// +build !linux
```

Pattern: `NewEBPFEnforcerV2` returns real enforcer on Linux, error stub on other platforms.
See `pkg/enforcer/ebpf_impl.go` (Linux) vs `pkg/enforcer/ebpf_stub.go` (non-Linux).

## Build and Test

```bash
make deps      # go mod download && tidy
make build     # builds to bin/pci-segment
make test      # go test -v ./...
make lint      # requires golangci-lint
make validate-example  # validates examples/policies/cde-isolation.yaml
```

Set `PCI_SEGMENT_INTERFACE=eth0` to override default network interface for eBPF.

## Global Configuration

The CLI supports a global YAML config file via the root flag `--config`. Use it to provide defaults across commands (log level, cloud config path, privilege overrides, interface).

Precedence is: flags > environment variables > config file > defaults.

Cloud commands use `--cloud-config` (short `-c`) for the provider config file; `--config` is reserved for the global config.

## Policy Structure

Policies use Kubernetes NetworkPolicy-inspired YAML with PCI-DSS annotations:

```yaml
apiVersion: pci-segment/v1
kind: NetworkPolicy
metadata:
  name: cde-isolation
  annotations:
    pci-dss: "Req 1.2, Req 1.3" # Required for compliance tracking
spec:
  podSelector:
    matchLabels:
      pci-env: cde # CDE policies must have this label
```

Validation rules in `pkg/policy/engine.go`:

- CDE policies reject `0.0.0.0/0` (wildcard) access
- Ports must be 0-65535
- `pci-env: cde` label required for CDE policies

## Error Handling

Wrap errors with context, lowercase messages, no trailing punctuation:

```go
return fmt.Errorf("loading policy %s: %w", filename, err)
```

For AWS/Azure SDK errors, include resource identifiers:

```go
return fmt.Errorf("failed to describe security group %s: %w", sgID, err)
```

## Testing Patterns

Table-driven tests with subtest names. See `pkg/policy/engine_test.go`:

```go
tests := []struct {
    name          string
    policy        Policy
    expectedValid bool
    expectedError string
}{...}
for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {...})
}
```

Use `t.TempDir()` for file-based tests. Mock cloud APIs by implementing interfaces.

## Security Constraints

- Never log secrets or cardholder data (PCI-DSS Req 3.4)
- Validate all CIDR inputs with `net.ParseCIDR`
- Port range validation before int32 conversion (see `#nosec G115` comments)
- Use `filepath.Clean` on user-provided paths
- Privilege code in `pkg/security/privilege/` drops root after eBPF attach

Environment variables for privilege control:

- `PCI_SEGMENT_PRIVILEGE_USER` / `PCI_SEGMENT_PRIVILEGE_GROUP` - service account
- `PCI_SEGMENT_SKIP_PRIVILEGE_DROP=1` - testing only
- `PCI_SEGMENT_DISABLE_SECCOMP=1` - testing only
- `PCI_SEGMENT_SELINUX_PROFILE` - expected SELinux domain (e.g., `pci_segment_t`)
- `PCI_SEGMENT_APPARMOR_PROFILE` - expected AppArmor profile (e.g., `pci-segment`)
- `PCI_SEGMENT_SKIP_MAC_VERIFY=1` - skip MAC verification (testing only)

## Audit Logging

`pkg/audit/` provides tamper-evident logging with SHA-256 checksums:

- JSON lines format with `fsync` after each write
- Automatic rotation by size (MB) or daily
- 90-day retention by default
- Integrity verification on startup

## Prometheus Metrics

`pkg/metrics/` provides Prometheus metrics endpoint on the `enforce` command:

```bash
pci-segment enforce -f policies/*.yaml --metrics-addr=:9090
```

Metrics exposed at `/metrics` with `pci_segment_` prefix:

- `pci_segment_enforcer_*` - packet counts, running state, policies loaded
- `pci_segment_policy_*` - validation counts, load duration, CDE policy count
- `pci_segment_audit_*` - events logged, failed writes, checksum failures
- `pci_segment_cloud_*` - sync operations, duration, resources managed

Health endpoints: `/healthz` (liveness), `/readyz` (readiness)

## Logging

`pkg/log/` provides structured logging using Go's `log/slog`:

```bash
pci-segment validate -f policy.yaml                    # default: info level
pci-segment validate -f policy.yaml --log-level=debug  # verbose output
pci-segment validate -f policy.yaml --verbose          # alias for debug
pci-segment validate -f policy.yaml --log-level=error  # quiet mode
```

Use the log package in code:

```go
import "github.com/msaadshabir/pci-segment/pkg/log"

log.Debug("loading policy", "file", filename)
log.Info("policy validated", "name", pol.Name, "requirements", reqs)
log.Warn("policy has warnings", "warnings", result.Warnings)
log.Error("validation failed", "error", err)
```

## Output Standards

- No emojis in this project anywhere or in CLI output
- State assumptions explicitly
- Provide complete, production-ready code with imports

## Remove AI code slop

Check the diff against main, and remove all AI generated slop introduced in this branch.

This includes:

- Extra comments that a human wouldn't add or is inconsistent with the rest of the file
- Extra defensive checks or try/catch blocks that are abnormal for that area of the codebase (especially if called by trusted / validated codepaths)
- Casts to any to get around type issues
- Any other style that is inconsistent with the file

Report at the end with only a 1-3 sentence summary of what you changed
