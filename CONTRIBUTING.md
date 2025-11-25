# Contributing

Thank you for your interest in contributing to pci-segment.

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Search existing issues before creating a new one
- Include reproduction steps, expected vs actual behavior, and system information (OS, Go version)

## Pull Requests

1. Fork and clone the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make changes with tests and documentation updates
4. Run validation: `make test && make build && make validate-example`
5. Commit using [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` New features
   - `fix:` Bug fixes
   - `docs:` Documentation changes
   - `test:` Test additions/changes
   - `refactor:` Code refactoring
   - `chore:` Maintenance tasks
6. Push and open a Pull Request

## Development Setup

Prerequisites: Go 1.25+, Make, Git

```bash
git clone https://github.com/msaadshabir/pci-segment.git
cd pci-segment
make deps      # Install dependencies
make build     # Build binary
make test      # Run tests
make fmt       # Format code
```

## Code Style

- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Use `gofmt` for formatting
- Add comments for exported functions
- Keep functions small and focused
- Write table-driven tests for multiple scenarios
- Aim for >80% code coverage

## Priority Areas

**Near-Term**
- SELinux/AppArmor profiles
- Prometheus metrics and Grafana dashboards
- Input validation improvements
- IAM-based authentication (AWS roles, Azure Managed Identity)

**Backlog**
- High availability (leader election, distributed config)
- Windows WFP enforcer
- Kubernetes operator
- SIEM integrations and PDF export

## Security Issues

Do not open public issues for security vulnerabilities. Report via GitHub Security Advisories.

## PR Checklist

- [ ] Code builds: `make build`
- [ ] Tests pass: `make test`
- [ ] Code formatted: `make fmt`
- [ ] Documentation updated
- [ ] New features have tests
- [ ] Breaking changes documented

## Questions

- General questions: GitHub Discussions
- Bug reports: GitHub Issues
- Feature requests: GitHub Issues

By contributing, you agree that your contributions will be licensed under the MIT License.
