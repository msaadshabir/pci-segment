package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEngineLoadFromFile(t *testing.T) {
	engine := NewEngine()

	// Create a temporary policy file
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "test-policy.yaml")

	validPolicy := `apiVersion: pci-segment/v1
kind: NetworkPolicy
metadata:
  name: test-policy
  annotations:
    pci-dss: "Req 1.3"
spec:
  podSelector:
    matchLabels:
      pci-env: cde
`

	if err := os.WriteFile(policyFile, []byte(validPolicy), 0644); err != nil {
		t.Fatalf("Failed to write test policy: %v", err)
	}

	if err := engine.LoadFromFile(policyFile); err != nil {
		t.Errorf("LoadFromFile failed: %v", err)
	}

	policies := engine.GetPolicies()
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}

	if policies[0].Metadata.Name != "test-policy" {
		t.Errorf("Expected policy name 'test-policy', got '%s'", policies[0].Metadata.Name)
	}
}

func TestValidatePCICompliance(t *testing.T) {
	engine := NewEngine()

	tests := []struct {
		name          string
		policy        Policy
		expectedValid bool
		expectedError string
	}{
		{
			name: "valid CDE policy",
			policy: Policy{
				APIVersion: "pci-segment/v1",
				Kind:       "NetworkPolicy",
				Metadata: Metadata{
					Name: "valid-cde",
					Annotations: map[string]string{
						"pci-dss": "Req 1.2, Req 1.3",
					},
				},
				Spec: Spec{
					PodSelector: PodSelector{
						MatchLabels: map[string]string{
							"pci-env": "cde",
						},
					},
					Egress: []Rule{
						{
							To: []Peer{
								{
									IPBlock: &IPBlock{
										CIDR: "10.0.10.0/24",
									},
								},
							},
							Ports: []Port{
								{Protocol: "TCP", Port: 443},
							},
						},
					},
				},
			},
			expectedValid: true,
		},
		{
			name: "invalid API version",
			policy: Policy{
				APIVersion: "invalid/v1",
				Kind:       "NetworkPolicy",
				Metadata: Metadata{
					Name: "invalid-version",
				},
			},
			expectedValid: false,
			expectedError: "invalid apiVersion",
		},
		{
			name: "wildcard access violation",
			policy: Policy{
				APIVersion: "pci-segment/v1",
				Kind:       "NetworkPolicy",
				Metadata: Metadata{
					Name: "wildcard-policy",
					Annotations: map[string]string{
						"pci-dss": "Req 1.3",
					},
				},
				Spec: Spec{
					PodSelector: PodSelector{
						MatchLabels: map[string]string{
							"pci-env": "cde",
						},
					},
					Ingress: []Rule{
						{
							From: []Peer{
								{
									IPBlock: &IPBlock{
										CIDR: "0.0.0.0/0",
									},
								},
							},
							Ports: []Port{
								{Protocol: "TCP", Port: 443},
							},
						},
					},
				},
			},
			expectedValid: false,
			expectedError: "0.0.0.0/0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Validate(&tt.policy)

			if result.Valid != tt.expectedValid {
				t.Errorf("Expected valid=%v, got valid=%v", tt.expectedValid, result.Valid)
			}

			if !tt.expectedValid && tt.expectedError != "" {
				found := false
				for _, err := range result.Errors {
					if contains(err, tt.expectedError) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected error containing '%s', got errors: %v", tt.expectedError, result.Errors)
				}
			}
		})
	}
}

func TestIPInCIDR(t *testing.T) {
	tests := []struct {
		ip       string
		cidr     string
		expected bool
	}{
		{"10.0.10.5", "10.0.10.0/24", true},
		{"10.0.11.5", "10.0.10.0/24", false},
		{"192.168.1.1", "192.168.0.0/16", true},
		{"192.169.1.1", "192.168.0.0/16", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip+"_in_"+tt.cidr, func(t *testing.T) {
			result := ipInCIDR(tt.ip, tt.cidr)
			if result != tt.expected {
				t.Errorf("ipInCIDR(%s, %s) = %v, expected %v", tt.ip, tt.cidr, result, tt.expected)
			}
		})
	}
}

func TestGetPolicyByName(t *testing.T) {
	engine := NewEngine()

	policy := Policy{
		APIVersion: "pci-segment/v1",
		Kind:       "NetworkPolicy",
		Metadata: Metadata{
			Name: "test-policy",
		},
		Spec: Spec{
			PodSelector: PodSelector{
				MatchLabels: map[string]string{
					"pci-env": "cde",
				},
			},
		},
	}

	engine.policies = append(engine.policies, policy)

	// Test finding existing policy
	found := engine.GetPolicyByName("test-policy")
	if found == nil {
		t.Error("Expected to find policy, got nil")
	}

	// Test not finding non-existent policy
	notFound := engine.GetPolicyByName("nonexistent")
	if notFound != nil {
		t.Error("Expected nil for non-existent policy, got policy")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
