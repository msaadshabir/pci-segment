# Contributing to PCI-GUARD

Thank you for your interest in contributing to PCI-GUARD! This document provides guidelines and instructions for contributing.

## How to Contribute

### Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Search existing issues before creating a new one
- Include reproduction steps, expected vs actual behavior
- Provide system information (OS, Go version, etc.)

### Submitting Pull Requests

1. **Fork the repository**

   ```bash
   git clone https://github.com/saad-build/pci-segment.git
   cd pci-segment
   ```

2. **Create a feature branch**

   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**

   - Write tests for new features
   - Update documentation
   - Follow code style guidelines

4. **Test your changes**

   ```bash
   make test
   make build
   make validate-example
   ```

5. **Commit your changes**

   ```bash
   git add .
   git commit -m "feat: add new feature"
   ```

   Follow [Conventional Commits](https://www.conventionalcommits.org/):

   - `feat:` New features
   - `fix:` Bug fixes
   - `docs:` Documentation changes
   - `test:` Test additions/changes
   - `refactor:` Code refactoring
   - `chore:` Maintenance tasks

6. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   ```
   Then open a Pull Request on GitHub

## Development Setup

### Prerequisites

- Go 1.22 or higher
- Make
- Git

### Local Development

```bash
# Clone the repository
git clone https://github.com/saad-build/pci-segment.git
cd pci-segment

# Install dependencies
make deps

# Build the binary
make build

# Run tests
make test

# Run example workflow
make run-example
```

## Code Style

### Go Code Guidelines

- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Use `gofmt` for formatting: `make fmt`
- Write meaningful variable names
- Add comments for exported functions
- Keep functions small and focused

### Example

```go
// ValidatePolicy validates a policy against PCI-DSS requirements
func (e *Engine) ValidatePolicy(policy *Policy) ValidationResult {
    result := ValidationResult{
        Valid: true,
        Errors: make([]string, 0),
    }

    // Validation logic here

    return result
}
```

## Testing Guidelines

### Writing Tests

- Place tests in `*_test.go` files
- Use table-driven tests for multiple scenarios
- Test edge cases and error conditions
- Aim for >80% code coverage

### Example Test

```go
func TestValidatePolicy(t *testing.T) {
    tests := []struct {
        name     string
        policy   Policy
        expected bool
    }{
        {
            name: "valid CDE policy",
            policy: Policy{
                APIVersion: "pci-guard/v1",
                // ... policy details
            },
            expected: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := ValidatePolicy(&tt.policy)
            if result.Valid != tt.expected {
                t.Errorf("got %v, want %v", result.Valid, tt.expected)
            }
        })
    }
}
```

## Documentation

### Documentation Standards

- Update README.md for user-facing changes
- Add godoc comments for exported types/functions
- Update design documents for architectural changes
- Include examples in documentation

## Security

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Instead, email: security@example.com

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Priority Areas

We especially welcome contributions in these areas:

### High Priority

- [ ] AWS/Azure cloud integrations
- [ ] Real-time monitoring and alerting
- [ ] Kubernetes NetworkPolicy generation
- [ ] Additional policy examples

### Medium Priority

- [ ] PDF report generation
- [ ] SIEM integrations (Splunk, Datadog)
- [ ] Windows WFP enforcer
- [ ] Performance optimizations

### Low Priority

- [ ] Web UI dashboard
- [ ] Policy testing framework
- [ ] Multi-cloud support (GCP)
- [ ] Threat intelligence integration

## Checklist

Before submitting your PR, ensure:

- [ ] Code builds without errors: `make build`
- [ ] All tests pass: `make test`
- [ ] Code is formatted: `make fmt`
- [ ] Documentation is updated
- [ ] Commit messages follow conventions
- [ ] PR description explains changes
- [ ] New features have tests
- [ ] Breaking changes are documented

## Questions?

- **General questions**: GitHub Discussions
- **Bug reports**: GitHub Issues
- **Feature requests**: GitHub Issues
- **Security issues**: security@example.com

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to PCI-GUARD!
