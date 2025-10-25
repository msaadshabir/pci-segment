package enforcer

import (
	"fmt"
	"os"
	"runtime"

	"github.com/msaadshabir/pci-segment/pkg/policy"
)

// Enforcer interface for OS-specific enforcement
type Enforcer interface {
	// Start begins enforcement of policies
	Start() error

	// Stop stops enforcement
	Stop() error

	// AddPolicy adds a policy to enforce
	AddPolicy(policy *policy.Policy) error

	// RemovePolicy removes a policy
	RemovePolicy(policyName string) error

	// GetEvents returns enforcement events
	GetEvents() []policy.EnforcementEvent

	// IsRunning returns whether enforcer is active
	IsRunning() bool
}

// NewEnforcer creates an OS-appropriate enforcer
func NewEnforcer() (Enforcer, error) {
	switch runtime.GOOS {
	case "linux":
		return newLinuxEnforcer()
	case "darwin":
		return NewPFEnforcer()
	case "windows":
		return nil, fmt.Errorf("Windows WFP enforcer not yet implemented (Phase 2)")
	default:
		return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// newLinuxEnforcer creates a Linux-specific enforcer
func newLinuxEnforcer() (Enforcer, error) {
	// Use production eBPF enforcer
	// Default to eth0, can be configured via environment variable
	iface := "eth0"
	if envIface := os.Getenv("PCI_SEGMENT_INTERFACE"); envIface != "" {
		iface = envIface
	}

	enforcer, err := NewEBPFEnforcerV2(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to create eBPF enforcer: %w", err)
	}

	return enforcer, nil
}

// StubEnforcer is a placeholder for platforms without full implementation
type StubEnforcer struct {
	running bool
}

func (e *StubEnforcer) Start() error {
	fmt.Println("Note: Using stub enforcer (eBPF requires Linux)")
	e.running = true
	return nil
}

func (e *StubEnforcer) Stop() error {
	e.running = false
	return nil
}

func (e *StubEnforcer) AddPolicy(policy *policy.Policy) error {
	fmt.Printf("Added policy: %s\n", policy.Metadata.Name)
	return nil
}

func (e *StubEnforcer) RemovePolicy(_ string) error {
	return nil
}

func (e *StubEnforcer) GetEvents() []policy.EnforcementEvent {
	return []policy.EnforcementEvent{}
}

func (e *StubEnforcer) IsRunning() bool {
	return e.running
}
