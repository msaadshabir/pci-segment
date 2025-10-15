package enforcer

import (
	"fmt"
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
	// On Linux, this would return NewEBPFEnforcer()
	// For now, we'll return a stub
	return &StubEnforcer{}, nil
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

func (e *StubEnforcer) RemovePolicy(policyName string) error {
	return nil
}

func (e *StubEnforcer) GetEvents() []policy.EnforcementEvent {
	return []policy.EnforcementEvent{}
}

func (e *StubEnforcer) IsRunning() bool {
	return e.running
}
