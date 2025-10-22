//go:build !linux
// +build !linux

package enforcer

import (
	"fmt"

	"github.com/msaadshabir/pci-segment/pkg/policy"
)

// EBPFEnforcerV2 stub for non-Linux systems
type EBPFEnforcerV2 struct{}

// NewEBPFEnforcerV2 returns an error on non-Linux systems
func NewEBPFEnforcerV2(interfaceName string) (*EBPFEnforcerV2, error) {
	return nil, fmt.Errorf("eBPF enforcement is only supported on Linux")
}

// Stub methods to satisfy Enforcer interface
func (e *EBPFEnforcerV2) Start() error {
	return fmt.Errorf("not implemented on this platform")
}

func (e *EBPFEnforcerV2) Stop() error {
	return fmt.Errorf("not implemented on this platform")
}

func (e *EBPFEnforcerV2) AddPolicy(pol *policy.Policy) error {
	return fmt.Errorf("not implemented on this platform")
}

func (e *EBPFEnforcerV2) RemovePolicy(policyName string) error {
	return fmt.Errorf("not implemented on this platform")
}

func (e *EBPFEnforcerV2) GetEvents() []policy.EnforcementEvent {
	return nil
}

func (e *EBPFEnforcerV2) IsRunning() bool {
	return false
}

func (e *EBPFEnforcerV2) GetStats() (uint64, uint64, uint64, error) {
	return 0, 0, 0, fmt.Errorf("not implemented on this platform")
}
