package enforcer

import (
	"fmt"
	"sync"

	"github.com/saad-build/pci-segment/pkg/policy"
)

// EBPFEnforcer implements enforcement using Linux eBPF
type EBPFEnforcer struct {
	policies []policy.Policy
	events   []policy.EnforcementEvent
	running  bool
	mu       sync.RWMutex
}

// NewEBPFEnforcer creates a new eBPF-based enforcer for Linux
func NewEBPFEnforcer() (*EBPFEnforcer, error) {
	return &EBPFEnforcer{
		policies: make([]policy.Policy, 0),
		events:   make([]policy.EnforcementEvent, 0),
		running:  false,
	}, nil
}

// Start begins enforcement of policies
func (e *EBPFEnforcer) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return fmt.Errorf("enforcer already running")
	}

	// In production, this would:
	// 1. Load eBPF program into kernel
	// 2. Attach to cgroup or network interface
	// 3. Set up maps for policy rules
	fmt.Println("Starting eBPF enforcer...")
	fmt.Println("Note: Full eBPF implementation requires kernel >=4.18 and libbpf")

	e.running = true
	return nil
}

// Stop stops enforcement
func (e *EBPFEnforcer) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return nil
	}

	// In production: detach eBPF programs and clean up maps
	fmt.Println("Stopping eBPF enforcer...")

	e.running = false
	return nil
}

// AddPolicy adds a policy to enforce
func (e *EBPFEnforcer) AddPolicy(pol *policy.Policy) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.policies = append(e.policies, *pol)

	// In production: update eBPF maps with new rules
	fmt.Printf("Added policy: %s\n", pol.Metadata.Name)

	return nil
}

// RemovePolicy removes a policy
func (e *EBPFEnforcer) RemovePolicy(policyName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	newPolicies := make([]policy.Policy, 0)
	for _, p := range e.policies {
		if p.Metadata.Name != policyName {
			newPolicies = append(newPolicies, p)
		}
	}

	e.policies = newPolicies

	// In production: update eBPF maps
	fmt.Printf("Removed policy: %s\n", policyName)

	return nil
}

// GetEvents returns enforcement events
func (e *EBPFEnforcer) GetEvents() []policy.EnforcementEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return append([]policy.EnforcementEvent{}, e.events...)
}

// IsRunning returns whether enforcer is active
func (e *EBPFEnforcer) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.running
}
