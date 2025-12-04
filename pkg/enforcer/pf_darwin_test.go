//go:build darwin

package enforcer

import (
	"strings"
	"testing"

	"github.com/msaadshabir/pci-segment/pkg/policy"
)

func TestPFEnforcerLifecycle(t *testing.T) {
	enforcer, err := NewPFEnforcer()
	if err != nil {
		t.Fatalf("NewPFEnforcer() failed: %v", err)
	}

	pf := enforcer.(*PFEnforcer)

	if pf.IsRunning() {
		t.Error("should not be running initially")
	}

	// Start uses simulated pf commands in non-root mode
	if err := pf.Start(); err != nil {
		t.Errorf("Start() failed: %v", err)
	}

	if !pf.IsRunning() {
		t.Error("should be running after Start()")
	}

	if err := pf.Start(); err == nil {
		t.Error("Start() should fail when already running")
	}

	// Stop tries to run pfctl which requires root - mark as not running first
	pf.mu.Lock()
	pf.running = false
	pf.mu.Unlock()

	// Stop when not running should be a no-op
	if err := pf.Stop(); err != nil {
		t.Errorf("Stop() when not running failed: %v", err)
	}
}

func TestPFEnforcerAddRemovePolicy(t *testing.T) {
	enforcer, _ := NewPFEnforcer()
	pf := enforcer.(*PFEnforcer)

	pol := &policy.Policy{
		Metadata: policy.Metadata{
			Name: "test-policy",
		},
	}

	if err := pf.AddPolicy(pol); err != nil {
		t.Errorf("AddPolicy() failed: %v", err)
	}

	if len(pf.policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(pf.policies))
	}

	if err := pf.RemovePolicy("test-policy"); err != nil {
		t.Errorf("RemovePolicy() failed: %v", err)
	}

	if len(pf.policies) != 0 {
		t.Errorf("expected 0 policies, got %d", len(pf.policies))
	}
}

func TestPFEnforcerGetEvents(t *testing.T) {
	enforcer, _ := NewPFEnforcer()
	pf := enforcer.(*PFEnforcer)

	events := pf.GetEvents()
	if events == nil {
		t.Error("GetEvents() should return non-nil slice")
	}
}

func TestGeneratePFRulesEmpty(t *testing.T) {
	enforcer, _ := NewPFEnforcer()
	pf := enforcer.(*PFEnforcer)

	rules := pf.generatePFRules()

	if !strings.Contains(rules, "pci-segment") {
		t.Error("rules should contain header comment")
	}
	if !strings.Contains(rules, "block drop all") {
		t.Error("rules should contain default deny")
	}
}

func TestGeneratePFRulesIngress(t *testing.T) {
	enforcer, _ := NewPFEnforcer()
	pf := enforcer.(*PFEnforcer)

	pf.policies = []policy.Policy{
		{
			Metadata: policy.Metadata{
				Name: "test-ingress",
				Annotations: map[string]string{
					"pci-dss": "Req 1.2",
				},
			},
			Spec: policy.Spec{
				Ingress: []policy.Rule{
					{
						From: []policy.Peer{
							{IPBlock: &policy.IPBlock{CIDR: "10.0.0.0/24"}},
						},
						Ports: []policy.Port{
							{Protocol: "TCP", Port: 443},
						},
					},
				},
			},
		},
	}

	rules := pf.generatePFRules()

	if !strings.Contains(rules, "Policy: test-ingress") {
		t.Error("rules should contain policy name")
	}
	if !strings.Contains(rules, "PCI-DSS: Req 1.2") {
		t.Error("rules should contain PCI-DSS annotation")
	}
	if !strings.Contains(rules, "pass in proto tcp from 10.0.0.0/24 to any port 443") {
		t.Errorf("rules should contain ingress rule, got: %s", rules)
	}
}

func TestGeneratePFRulesEgress(t *testing.T) {
	enforcer, _ := NewPFEnforcer()
	pf := enforcer.(*PFEnforcer)

	pf.policies = []policy.Policy{
		{
			Metadata: policy.Metadata{
				Name: "test-egress",
			},
			Spec: policy.Spec{
				Egress: []policy.Rule{
					{
						To: []policy.Peer{
							{IPBlock: &policy.IPBlock{CIDR: "192.168.1.0/24"}},
						},
						Ports: []policy.Port{
							{Protocol: "UDP", Port: 53},
						},
					},
				},
			},
		},
	}

	rules := pf.generatePFRules()

	if !strings.Contains(rules, "pass out proto udp to 192.168.1.0/24 port 53") {
		t.Errorf("rules should contain egress rule, got: %s", rules)
	}
}

func TestGeneratePFRulesDefaultProtocol(t *testing.T) {
	enforcer, _ := NewPFEnforcer()
	pf := enforcer.(*PFEnforcer)

	pf.policies = []policy.Policy{
		{
			Metadata: policy.Metadata{Name: "test-default"},
			Spec: policy.Spec{
				Ingress: []policy.Rule{
					{
						From:  []policy.Peer{{IPBlock: &policy.IPBlock{CIDR: "10.0.0.0/8"}}},
						Ports: []policy.Port{{Port: 80}},
					},
				},
			},
		},
	}

	rules := pf.generatePFRules()

	if !strings.Contains(rules, "pass in proto tcp") {
		t.Error("empty protocol should default to tcp")
	}
}

func TestGeneratePFRulesMultiplePolicies(t *testing.T) {
	enforcer, _ := NewPFEnforcer()
	pf := enforcer.(*PFEnforcer)

	pf.policies = []policy.Policy{
		{
			Metadata: policy.Metadata{Name: "policy-1"},
			Spec: policy.Spec{
				Ingress: []policy.Rule{
					{
						From:  []policy.Peer{{IPBlock: &policy.IPBlock{CIDR: "10.0.0.0/24"}}},
						Ports: []policy.Port{{Protocol: "TCP", Port: 443}},
					},
				},
			},
		},
		{
			Metadata: policy.Metadata{Name: "policy-2"},
			Spec: policy.Spec{
				Egress: []policy.Rule{
					{
						To:    []policy.Peer{{IPBlock: &policy.IPBlock{CIDR: "10.0.1.0/24"}}},
						Ports: []policy.Port{{Protocol: "TCP", Port: 5432}},
					},
				},
			},
		},
	}

	rules := pf.generatePFRules()

	if !strings.Contains(rules, "Policy: policy-1") {
		t.Error("should contain first policy")
	}
	if !strings.Contains(rules, "Policy: policy-2") {
		t.Error("should contain second policy")
	}
}

func TestGeneratePFRulesNilIPBlock(t *testing.T) {
	enforcer, _ := NewPFEnforcer()
	pf := enforcer.(*PFEnforcer)

	pf.policies = []policy.Policy{
		{
			Metadata: policy.Metadata{Name: "test-nil"},
			Spec: policy.Spec{
				Ingress: []policy.Rule{
					{
						From:  []policy.Peer{{IPBlock: nil}},
						Ports: []policy.Port{{Protocol: "TCP", Port: 80}},
					},
				},
			},
		},
	}

	rules := pf.generatePFRules()

	if strings.Contains(rules, "pass in proto tcp") {
		t.Error("nil IPBlock should not generate rule")
	}
}

func TestPFEnforcerLogEvent(t *testing.T) {
	enforcer, _ := NewPFEnforcer()
	pf := enforcer.(*PFEnforcer)

	for i := 0; i < 1005; i++ {
		pf.logEvent(policy.EnforcementEvent{Action: "test"})
	}

	if len(pf.events) != 1000 {
		t.Errorf("expected 1000 events (capped), got %d", len(pf.events))
	}
}
