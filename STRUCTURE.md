# PCI-GUARD Project Structure

```
pci-segment/
 README.md                    # Main documentation
 LICENSE                      # MIT License
 CONTRIBUTING.md             # Contribution guidelines
 Makefile                    # Build automation
 demo.sh                     # Interactive demo script
 go.mod                      # Go module definition
 go.sum                      # Go dependencies
 main.go                     # Application entry point
‚
 cmd/                        # CLI commands
‚    root.go                # Root command & flags
‚    enforce.go             # Enforce policies command
‚    validate.go            # Validate policies command
‚    report.go              # Generate reports command
‚
 pkg/                        # Core packages
‚    policy/                # Policy engine
‚   ‚    types.go           # Policy data structures
‚   ‚    engine.go          # Policy parser & validator
‚   ‚    engine_test.go     # Unit tests
‚   ‚
‚    enforcer/              # OS-level enforcement
‚   ‚    enforcer.go        # Interface & factory
‚   ‚    pf_darwin.go       # macOS pf implementation
‚   ‚    ebpf_linux.go      # Linux eBPF implementation
‚   ‚
‚    reporter/              # Compliance reporting
‚        reporter.go        # HTML/JSON/PDF generation
‚
 examples/                   # Example policies & demos
     policies/              # Sample PCI-DSS policies
         cde-isolation.yaml      # CDE isolation policy
         cde-database.yaml       # Database access policy
         invalid-policy.yaml     # Invalid policy for testing
```

## Component Details

### Core Modules

#### `cmd/` - Command Line Interface

- **root.go**: Base command with global flags
- **enforce.go**: Start enforcement of policies
- **validate.go**: Validate policies against PCI-DSS
- **report.go**: Generate compliance reports

#### `pkg/policy/` - Policy Engine

- **types.go**: Data structures for policies

  - `Policy`: Network policy definition
  - `Spec`: Policy specification
  - `Rule`: Ingress/egress rules
  - `ValidationResult`: Validation outcomes

- **engine.go**: Core policy logic
  - `LoadFromFile()`: Parse YAML policies
  - `Validate()`: PCI-DSS compliance checking
  - `MatchesTraffic()`: Traffic matching logic

#### `pkg/enforcer/` - OS Enforcement

- **enforcer.go**: Platform-agnostic interface

  - `Enforcer` interface
  - `NewEnforcer()`: OS-specific factory

- **pf_darwin.go**: macOS packet filter

  - Generate pf rules
  - Load/unload anchors
  - Event logging

- **ebpf_linux.go**: Linux eBPF (future)
  - eBPF program loading
  - Cgroup attachment
  - BPF maps management

#### `pkg/reporter/` - Compliance Reports

- **reporter.go**: Report generation
  - `GenerateReport()`: Build report data
  - `ExportHTML()`: HTML reports for humans
  - `ExportJSON()`: JSON for automation

### Policy Files

#### `examples/policies/cde-isolation.yaml`

Complete CDE isolation policy demonstrating:

- Proper `pci-env: cde` labeling
- Restricted egress to payment processors
- Limited ingress for monitoring
- PCI-DSS annotations

#### `examples/policies/cde-database.yaml`

Database-specific policy showing:

- Tier-based segmentation
- Application server access only
- No outbound connections
- Port-specific rules

#### `examples/policies/invalid-policy.yaml`

Intentionally violates PCI-DSS:

- Allows `0.0.0.0/0` access
- Used for testing validation
- Demonstrates error detection

## Data Flow

```
1. Policy Loading
   YAML File  engine.LoadFromFile()  Policy struct

2. Validation
   Policy  engine.Validate()  ValidationResult

3. Enforcement
   Policy  enforcer.AddPolicy()  OS rules (pf/eBPF)

4. Reporting
   Policies + Events  reporter.GenerateReport()  HTML/JSON
```

## Build Artifacts

```
bin/
 pci-guard           # Compiled binary

Generated at runtime:
 compliance-report.html    # HTML report
 compliance-report.json    # JSON report
 /var/log/pci-guard.log   # Enforcement logs (future)
```

## Testing Structure

```
pkg/
 policy/
‚    engine_test.go      # Policy engine tests
 enforcer/
‚    enforcer_test.go    # Enforcer tests (future)
 reporter/
     reporter_test.go    # Reporter tests (future)
```

## Development Workflow

```bash
# 1. Development
make deps          # Install dependencies
make build         # Build binary
make test          # Run tests

# 2. Testing
make validate-example   # Test policy validation
make report-example     # Test report generation

# 3. Demo
./demo.sh         # Run interactive demo

# 4. Cleanup
make clean        # Remove build artifacts
```

## File Naming Conventions

- `*_darwin.go` - macOS-specific code
- `*_linux.go` - Linux-specific code
- `*_test.go` - Unit tests
- `*.yaml` - Policy files

## Key Design Decisions

1. **OS-Specific Files**: Build tags separate Linux/macOS code
2. **Interface-Based**: Enforcer uses interface for portability
3. **YAML Policies**: Kubernetes-style for familiarity
4. **Single Binary**: No external dependencies for deployment
5. **Cobra CLI**: Industry-standard CLI framework

## Future Extensions

```
pkg/
 cloud/                 # Cloud integrations
‚    aws/              # AWS Security Groups
‚    azure/            # Azure NSGs
‚
 monitoring/           # Real-time monitoring
‚    alerts.go         # Alert manager
‚    metrics.go        # Prometheus metrics
‚
 integrations/         # SIEM integrations
     splunk.go         # Splunk forwarder
     datadog.go        # Datadog agent
```
