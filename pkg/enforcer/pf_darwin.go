//go:build darwin

package enforcer

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/msaadshabir/pci-segment/pkg/policy"
)

// PFEnforcer implements enforcement using macOS pf (packet filter)
type PFEnforcer struct {
	policies []policy.Policy
	events   []policy.EnforcementEvent
	running  bool
	mu       sync.RWMutex
}

// NewPFEnforcer creates a new pf-based enforcer for macOS
func NewPFEnforcer() (Enforcer, error) {
	return &PFEnforcer{
		policies: make([]policy.Policy, 0),
		events:   make([]policy.EnforcementEvent, 0),
		running:  false,
	}, nil
}

// Start begins enforcement of policies
func (e *PFEnforcer) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return fmt.Errorf("enforcer already running")
	}

	// Generate pf rules from policies
	rules := e.generatePFRules()

	// Write rules to pf anchor file
	anchorPath := "/etc/pf.anchors/pci-segment"
	if err := e.writePFAnchor(anchorPath, rules); err != nil {
		return fmt.Errorf("failed to write pf anchor: %w", err)
	}

	// Load the anchor into pf
	if err := e.loadPFAnchor(); err != nil {
		return fmt.Errorf("failed to load pf anchor: %w", err)
	}

	e.running = true
	return nil
}

// Stop stops enforcement
func (e *PFEnforcer) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return nil
	}

	// Flush pf anchor
	cmd := exec.Command("pfctl", "-a", "pci-segment", "-F", "all")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to flush pf anchor: %w", err)
	}

	e.running = false
	return nil
}

// AddPolicy adds a policy to enforce
func (e *PFEnforcer) AddPolicy(pol *policy.Policy) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.policies = append(e.policies, *pol)

	// If already running, reload rules
	if e.running {
		return e.reloadRules()
	}

	return nil
}

// RemovePolicy removes a policy
func (e *PFEnforcer) RemovePolicy(policyName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	newPolicies := make([]policy.Policy, 0)
	for _, p := range e.policies {
		if p.Metadata.Name != policyName {
			newPolicies = append(newPolicies, p)
		}
	}

	e.policies = newPolicies

	// If already running, reload rules
	if e.running {
		return e.reloadRules()
	}

	return nil
}

// GetEvents returns enforcement events
func (e *PFEnforcer) GetEvents() []policy.EnforcementEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return append([]policy.EnforcementEvent{}, e.events...)
}

// IsRunning returns whether enforcer is active
func (e *PFEnforcer) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.running
}

// generatePFRules generates pf rules from policies
func (e *PFEnforcer) generatePFRules() string {
	var rules strings.Builder

	rules.WriteString("# pci-segment - PCI-DSS Compliant Network Segmentation\n")
	rules.WriteString(fmt.Sprintf("# Generated: %s\n\n", time.Now().Format(time.RFC3339)))

	// Default deny for CDE
	rules.WriteString("# Default deny (PCI-DSS Req 1.3)\n")
	rules.WriteString("block drop all\n\n")

	// Generate rules for each policy
	for _, pol := range e.policies {
		rules.WriteString(fmt.Sprintf("# Policy: %s\n", pol.Metadata.Name))
		if pciReq, ok := pol.Metadata.Annotations["pci-dss"]; ok {
			rules.WriteString(fmt.Sprintf("# PCI-DSS: %s\n", pciReq))
		}

		// Generate egress rules
		for _, rule := range pol.Spec.Egress {
			for _, peer := range rule.To {
				if peer.IPBlock != nil {
					for _, port := range rule.Ports {
						protocol := strings.ToLower(port.Protocol)
						if protocol == "" {
							protocol = "tcp"
						}
						rules.WriteString(fmt.Sprintf("pass out proto %s to %s port %d\n",
							protocol, peer.IPBlock.CIDR, port.Port))
					}
				}
			}
		}

		// Generate ingress rules
		for _, rule := range pol.Spec.Ingress {
			for _, peer := range rule.From {
				if peer.IPBlock != nil {
					for _, port := range rule.Ports {
						protocol := strings.ToLower(port.Protocol)
						if protocol == "" {
							protocol = "tcp"
						}
						rules.WriteString(fmt.Sprintf("pass in proto %s from %s to any port %d\n",
							protocol, peer.IPBlock.CIDR, port.Port))
					}
				}
			}
		}

		rules.WriteString("\n")
	}

	return rules.String()
}

// writePFAnchor writes rules to pf anchor file
func (e *PFEnforcer) writePFAnchor(path, rules string) error {
	// In production, this would write to /etc/pf.anchors/pci-segment
	// For demo, we'll just simulate
	fmt.Printf("Would write to %s:\n%s\n", path, rules)
	return nil
}

// loadPFAnchor loads the anchor into pf
func (e *PFEnforcer) loadPFAnchor() error {
	// In production: pfctl -a pci-segment -f /etc/pf.anchors/pci-segment
	// For demo, we simulate
	fmt.Println("Would execute: pfctl -a pci-segment -f /etc/pf.anchors/pci-segment")
	return nil
}

// reloadRules reloads pf rules
func (e *PFEnforcer) reloadRules() error {
	rules := e.generatePFRules()
	if err := e.writePFAnchor("/etc/pf.anchors/pci-segment", rules); err != nil {
		return err
	}
	return e.loadPFAnchor()
}

// logEvent logs an enforcement event
func (e *PFEnforcer) logEvent(event policy.EnforcementEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.events = append(e.events, event)

	// Keep only last 1000 events
	if len(e.events) > 1000 {
		e.events = e.events[len(e.events)-1000:]
	}
}
