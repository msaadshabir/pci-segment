//go:build linux
// +build linux

package enforcer

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/msaadshabir/pci-segment/pkg/policy"
)

func TestPolicyToRules(t *testing.T) {
	// Create enforcer
	enforcer, err := NewEBPFEnforcerV2("lo")
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}

	// Test policy
	pol := &policy.Policy{
		APIVersion: "pci-segment/v1",
		Kind:       "NetworkPolicy",
		Metadata: policy.Metadata{
			Name: "test-policy",
			Annotations: map[string]string{
				"pci-dss": "Req 1.2, Req 1.3",
			},
		},
		Spec: policy.Spec{
			Ingress: []policy.Rule{
				{
					From: []policy.Peer{
						{
							IPBlock: &policy.IPBlock{
								CIDR: "10.0.0.0/24",
							},
						},
					},
					Ports: []policy.Port{
						{
							Protocol: "TCP",
							Port:     443,
						},
					},
				},
			},
		},
	}

	// Convert policy to rules
	rules, err := enforcer.policyToRules(pol, true)
	if err != nil {
		t.Fatalf("Failed to convert policy: %v", err)
	}

	// Verify rules
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule")
	}

	rule := rules[0]
	if rule.Protocol != ProtoTCP {
		t.Errorf("Expected protocol TCP (6), got %d", rule.Protocol)
	}
	if rule.DstPortMin != 443 {
		t.Errorf("Expected port 443, got %d", rule.DstPortMin)
	}
	if rule.Action != ActionAllow {
		t.Errorf("Expected action ALLOW (0), got %d", rule.Action)
	}
}

func TestIPConversion(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want uint32
	}{
		{"localhost", "127.0.0.1", 0x0100007F},
		{"private", "10.0.0.1", 0x0100000A},
		{"public", "8.8.8.8", 0x08080808},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			got := ipToUint32(ip)
			if got != tt.want {
				t.Errorf("ipToUint32(%s) = 0x%08X, want 0x%08X", tt.ip, got, tt.want)
			}

			// Test reverse conversion
			gotStr := ipToString(got)
			if gotStr != tt.ip {
				t.Errorf("ipToString(0x%08X) = %s, want %s", got, gotStr, tt.ip)
			}
		})
	}
}

func TestProtoConversion(t *testing.T) {
	tests := []struct {
		str  string
		want uint8
	}{
		{"TCP", ProtoTCP},
		{"UDP", ProtoUDP},
		{"ICMP", ProtoICMP},
		{"OTHER", 0},
	}

	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			got := protoStringToInt(tt.str)
			if got != tt.want {
				t.Errorf("protoStringToInt(%s) = %d, want %d", tt.str, got, tt.want)
			}

			if tt.want != 0 {
				gotStr := protoToString(tt.want)
				if gotStr != tt.str {
					t.Errorf("protoToString(%d) = %s, want %s", tt.want, gotStr, tt.str)
				}
			}
		})
	}
}

func TestActionConversion(t *testing.T) {
	tests := []struct {
		action uint8
		want   string
	}{
		{ActionAllow, "ALLOWED"},
		{ActionDeny, "BLOCKED"},
		{99, "BLOCKED"}, // Unknown = BLOCKED
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := actionToString(tt.action)
			if got != tt.want {
				t.Errorf("actionToString(%d) = %s, want %s", tt.action, got, tt.want)
			}
		})
	}
}

func TestEnforcerLifecycle(t *testing.T) {
	// Skip if not root
	if !isRoot() {
		t.Skip("Skipping test: requires root privileges")
	}

	enforcer, err := NewEBPFEnforcerV2("lo")
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}

	// Should not be running initially
	if enforcer.IsRunning() {
		t.Error("Enforcer should not be running initially")
	}

	// Start enforcer
	if err := enforcer.Start(); err != nil {
		t.Fatalf("Failed to start enforcer: %v", err)
	}

	// Should be running
	if !enforcer.IsRunning() {
		t.Error("Enforcer should be running after Start()")
	}

	// Starting again should fail
	if err := enforcer.Start(); err == nil {
		t.Error("Starting enforcer twice should fail")
	}

	// Stop enforcer
	if err := enforcer.Stop(); err != nil {
		t.Errorf("Failed to stop enforcer: %v", err)
	}

	// Should not be running
	if enforcer.IsRunning() {
		t.Error("Enforcer should not be running after Stop()")
	}

	// Stopping again should not error
	if err := enforcer.Stop(); err != nil {
		t.Errorf("Stopping enforcer twice should not error: %v", err)
	}
}

func TestAddPolicy(t *testing.T) {
	// Skip if not root
	if !isRoot() {
		t.Skip("Skipping test: requires root privileges")
	}

	enforcer, err := NewEBPFEnforcerV2("lo")
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}

	// Start enforcer
	if err := enforcer.Start(); err != nil {
		t.Fatalf("Failed to start enforcer: %v", err)
	}
	defer func() {
		if err := enforcer.Stop(); err != nil {
			t.Errorf("Failed to stop enforcer: %v", err)
		}
	}()

	// Create test policy
	pol := &policy.Policy{
		APIVersion: "pci-segment/v1",
		Kind:       "NetworkPolicy",
		Metadata: policy.Metadata{
			Name: "test-cde-isolation",
			Annotations: map[string]string{
				"pci-dss": "Req 1.2, Req 1.3",
			},
		},
		Spec: policy.Spec{
			Ingress: []policy.Rule{
				{
					From: []policy.Peer{
						{
							IPBlock: &policy.IPBlock{
								CIDR: "10.0.1.0/24",
							},
						},
					},
					Ports: []policy.Port{
						{
							Protocol: "TCP",
							Port:     443,
						},
					},
				},
			},
			Egress: []policy.Rule{
				{
					To: []policy.Peer{
						{
							IPBlock: &policy.IPBlock{
								CIDR: "10.0.2.0/24",
							},
						},
					},
					Ports: []policy.Port{
						{
							Protocol: "TCP",
							Port:     5432,
						},
					},
				},
			},
		},
	}

	// Add policy
	if err := enforcer.AddPolicy(pol); err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	// Verify policy was added
	events := enforcer.GetEvents()
	t.Logf("Events after adding policy: %d", len(events))
}

func TestRemovePolicy(t *testing.T) {
	// Skip if not root
	if !isRoot() {
		t.Skip("Skipping test: requires root privileges")
	}

	enforcer, err := NewEBPFEnforcerV2("lo")
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}

	if err := enforcer.Start(); err != nil {
		t.Fatalf("Failed to start enforcer: %v", err)
	}
	defer func() {
		if err := enforcer.Stop(); err != nil {
			t.Errorf("Failed to stop enforcer: %v", err)
		}
	}()

	pol := &policy.Policy{
		Metadata: policy.Metadata{
			Name: "test-policy",
		},
		Spec: policy.Spec{
			Ingress: []policy.Rule{
				{
					From: []policy.Peer{
						{
							IPBlock: &policy.IPBlock{
								CIDR: "10.0.0.0/8",
							},
						},
					},
				},
			},
		},
	}

	// Add policy
	if err := enforcer.AddPolicy(pol); err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	// Remove policy
	if err := enforcer.RemovePolicy("test-policy"); err != nil {
		t.Fatalf("Failed to remove policy: %v", err)
	}

	// Removing again should fail
	if err := enforcer.RemovePolicy("test-policy"); err == nil {
		t.Error("Removing non-existent policy should fail")
	}
}

func TestGetStats(t *testing.T) {
	// Skip if not root
	if !isRoot() {
		t.Skip("Skipping test: requires root privileges")
	}

	enforcer, err := NewEBPFEnforcerV2("lo")
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}

	if err := enforcer.Start(); err != nil {
		t.Fatalf("Failed to start enforcer: %v", err)
	}
	defer func() {
		if err := enforcer.Stop(); err != nil {
			t.Errorf("Failed to stop enforcer: %v", err)
		}
	}()

	// Get stats (should be 0 initially)
	allowed, blocked, total, err := enforcer.GetStats()
	if err != nil {
		t.Fatalf("Failed to get stats: %v", err)
	}

	t.Logf("Stats: allowed=%d, blocked=%d, total=%d", allowed, blocked, total)
}

func TestEventProcessing(t *testing.T) {
	// Skip if not root
	if !isRoot() {
		t.Skip("Skipping test: requires root privileges")
	}

	enforcer, err := NewEBPFEnforcerV2("lo")
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}

	if err := enforcer.Start(); err != nil {
		t.Fatalf("Failed to start enforcer: %v", err)
	}
	defer func() {
		if err := enforcer.Stop(); err != nil {
			t.Errorf("Failed to stop enforcer: %v", err)
		}
	}()

	// Add a policy
	pol := &policy.Policy{
		Metadata: policy.Metadata{
			Name: "test-monitoring",
		},
		Spec: policy.Spec{
			Ingress: []policy.Rule{
				{
					From: []policy.Peer{
						{
							IPBlock: &policy.IPBlock{
								CIDR: "127.0.0.0/8",
							},
						},
					},
				},
			},
		},
	}

	if err := enforcer.AddPolicy(pol); err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	// Wait for events
	time.Sleep(2 * time.Second)

	// Check events
	events := enforcer.GetEvents()
	t.Logf("Captured %d events", len(events))

	// Events might be empty if no traffic on lo interface
	// This is expected in test environment
}

// Helper function to check if running as root
func isRoot() bool {
	return os.Geteuid() == 0
}

// Benchmark tests

func BenchmarkPolicyToRules(b *testing.B) {
	enforcer, _ := NewEBPFEnforcerV2("lo")

	pol := &policy.Policy{
		Spec: policy.Spec{
			Ingress: []policy.Rule{
				{
					From: []policy.Peer{
						{
							IPBlock: &policy.IPBlock{
								CIDR: "10.0.0.0/24",
							},
						},
					},
					Ports: []policy.Port{
						{Protocol: "TCP", Port: 443},
					},
				},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = enforcer.policyToRules(pol, true)
	}
}

func BenchmarkIPConversion(b *testing.B) {
	ip := net.ParseIP("10.0.1.100")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ipToUint32(ip)
	}
}

func TestPolicyToRulesEmptyPeers(t *testing.T) {
	enforcer, err := NewEBPFEnforcerV2("lo")
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}

	pol := &policy.Policy{
		Metadata: policy.Metadata{Name: "empty-peers"},
		Spec: policy.Spec{
			Ingress: []policy.Rule{
				{
					From:  []policy.Peer{},
					Ports: []policy.Port{{Protocol: "TCP", Port: 443}},
				},
			},
		},
	}

	rules, err := enforcer.policyToRules(pol, true)
	if err != nil {
		t.Fatalf("policyToRules failed: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules for empty peers, got %d", len(rules))
	}
}

func TestPolicyToRulesNilIPBlock(t *testing.T) {
	enforcer, err := NewEBPFEnforcerV2("lo")
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}

	pol := &policy.Policy{
		Metadata: policy.Metadata{Name: "nil-ipblock"},
		Spec: policy.Spec{
			Ingress: []policy.Rule{
				{
					From:  []policy.Peer{{IPBlock: nil}},
					Ports: []policy.Port{{Protocol: "TCP", Port: 80}},
				},
			},
		},
	}

	rules, err := enforcer.policyToRules(pol, true)
	if err != nil {
		t.Fatalf("policyToRules failed: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules for nil IPBlock, got %d", len(rules))
	}
}

func TestPolicyToRulesEmptyPorts(t *testing.T) {
	enforcer, err := NewEBPFEnforcerV2("lo")
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}

	pol := &policy.Policy{
		Metadata: policy.Metadata{Name: "empty-ports"},
		Spec: policy.Spec{
			Ingress: []policy.Rule{
				{
					From:  []policy.Peer{{IPBlock: &policy.IPBlock{CIDR: "10.0.0.0/24"}}},
					Ports: []policy.Port{},
				},
			},
		},
	}

	rules, err := enforcer.policyToRules(pol, true)
	if err != nil {
		t.Fatalf("policyToRules failed: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("expected 1 rule for empty ports, got %d", len(rules))
	}
}

func TestPolicyToRulesMultiplePeers(t *testing.T) {
	enforcer, err := NewEBPFEnforcerV2("lo")
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}

	pol := &policy.Policy{
		Metadata: policy.Metadata{Name: "multi-peers"},
		Spec: policy.Spec{
			Ingress: []policy.Rule{
				{
					From: []policy.Peer{
						{IPBlock: &policy.IPBlock{CIDR: "10.0.0.0/24"}},
						{IPBlock: &policy.IPBlock{CIDR: "192.168.1.0/24"}},
					},
					Ports: []policy.Port{{Protocol: "TCP", Port: 443}},
				},
			},
		},
	}

	rules, err := enforcer.policyToRules(pol, true)
	if err != nil {
		t.Fatalf("policyToRules failed: %v", err)
	}
	if len(rules) != 2 {
		t.Errorf("expected 2 rules for 2 peers, got %d", len(rules))
	}
}

func TestPolicyToRulesMultiplePorts(t *testing.T) {
	enforcer, err := NewEBPFEnforcerV2("lo")
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}

	pol := &policy.Policy{
		Metadata: policy.Metadata{Name: "multi-ports"},
		Spec: policy.Spec{
			Ingress: []policy.Rule{
				{
					From: []policy.Peer{
						{IPBlock: &policy.IPBlock{CIDR: "10.0.0.0/24"}},
					},
					Ports: []policy.Port{
						{Protocol: "TCP", Port: 80},
						{Protocol: "TCP", Port: 443},
					},
				},
			},
		},
	}

	rules, err := enforcer.policyToRules(pol, true)
	if err != nil {
		t.Fatalf("policyToRules failed: %v", err)
	}
	if len(rules) != 2 {
		t.Errorf("expected 2 rules for 2 ports, got %d", len(rules))
	}
}

func TestPolicyToRulesEgress(t *testing.T) {
	enforcer, err := NewEBPFEnforcerV2("lo")
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}

	pol := &policy.Policy{
		Metadata: policy.Metadata{Name: "egress-test"},
		Spec: policy.Spec{
			Egress: []policy.Rule{
				{
					To: []policy.Peer{
						{IPBlock: &policy.IPBlock{CIDR: "10.0.2.0/24"}},
					},
					Ports: []policy.Port{{Protocol: "TCP", Port: 5432}},
				},
			},
		},
	}

	rules, err := enforcer.policyToRules(pol, false)
	if err != nil {
		t.Fatalf("policyToRules failed: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("expected 1 egress rule, got %d", len(rules))
	}
}

func TestProtoConversionUnknown(t *testing.T) {
	got := protoToString(200)
	if got != "proto-200" {
		t.Errorf("protoToString(200) = %s, want proto-200", got)
	}
}

func TestIPv6ToUint32(t *testing.T) {
	ip := net.ParseIP("::1")
	got := ipToUint32(ip)
	if got != 0 {
		t.Errorf("ipToUint32(::1) = %d, want 0 (IPv6 not supported)", got)
	}
}

func TestIPToStringZero(t *testing.T) {
	got := ipToString(0)
	if got != "0.0.0.0" {
		t.Errorf("ipToString(0) = %s, want 0.0.0.0", got)
	}
}
