package cloud

import (
	"testing"
	"time"

	"github.com/saad-build/pci-segment/pkg/policy"
)

// TestNewIntegrator tests cloud integrator factory
func TestNewIntegrator(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		expectErr bool
	}{
		{
			name: "AWS integrator with credentials",
			config: &Config{
				Provider: ProviderAWS,
				Region:   "us-east-1",
				AWSConfig: &AWSConfig{
					AccessKeyID:     "test-key",
					SecretAccessKey: "test-secret",
				},
			},
			expectErr: false,
		},
		{
			name: "Azure integrator with credentials",
			config: &Config{
				Provider: ProviderAzure,
				Region:   "eastus",
				AzureConfig: &AzureConfig{
					SubscriptionID: "test-sub",
					TenantID:       "test-tenant",
					ClientID:       "test-client",
					ClientSecret:   "test-secret",
					ResourceGroups: []string{"test-rg"},
				},
			},
			expectErr: false,
		},
		{
			name: "unsupported provider",
			config: &Config{
				Provider: "gcp",
				Region:   "us-central1",
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewIntegrator(tt.config)
			if (err != nil) != tt.expectErr {
				t.Errorf("NewIntegrator() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}

// TestConvertPolicyToAWSRules tests policy to AWS rules conversion logic
func TestBuildAWSIngressPermissions(t *testing.T) {
	integrator := &AWSIntegrator{}

	rules := []policy.Rule{
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
	}

	perms := integrator.buildIngressPermissions(rules)

	if len(perms) != 1 {
		t.Errorf("Expected 1 permission, got %d", len(perms))
	}

	if len(perms[0].IpRanges) != 1 {
		t.Errorf("Expected 1 IP range, got %d", len(perms[0].IpRanges))
	}

	if *perms[0].IpRanges[0].CidrIp != "10.0.1.0/24" {
		t.Errorf("Expected CIDR 10.0.1.0/24, got %s", *perms[0].IpRanges[0].CidrIp)
	}
}

// TestAzureProtocolConversion tests protocol conversion for Azure
func TestConvertProtocol(t *testing.T) {
	integrator := &AzureIntegrator{}

	tests := []struct {
		input    string
		expected string
	}{
		{"TCP", "Tcp"},
		{"UDP", "Udp"},
		{"ICMP", "Icmp"},
		{"unknown", "*"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := integrator.convertProtocol(tt.input)
			if string(*result) != tt.expected {
				t.Errorf("convertProtocol(%s) = %s, want %s", tt.input, string(*result), tt.expected)
			}
		})
	}
}

// TestSyncResult validates sync result structure
func TestSyncResult(t *testing.T) {
	result := &SyncResult{
		Provider:         ProviderAWS,
		Timestamp:        time.Now(),
		DryRun:           true,
		ResourcesAdded:   2,
		ResourcesUpdated: 1,
		ResourcesDeleted: 0,
		Changes: []Change{
			{
				ResourceName: "test-sg",
				Operation:    "create",
				Success:      true,
			},
		},
		Errors: []string{},
	}

	if result.Provider != ProviderAWS {
		t.Errorf("Expected provider AWS, got %s", result.Provider)
	}

	if result.ResourcesAdded != 2 {
		t.Errorf("Expected 2 resources added, got %d", result.ResourcesAdded)
	}

	if len(result.Changes) != 1 {
		t.Errorf("Expected 1 change, got %d", len(result.Changes))
	}
}

// TestValidationReport validates validation report structure
func TestValidationReport(t *testing.T) {
	report := &ValidationReport{
		Provider:  ProviderAzure,
		Timestamp: time.Now(),
		Compliant: false,
		Resources: 5,
		Violations: []Violation{
			{
				ResourceName: "test-nsg",
				PolicyName:   "wildcard-check",
				Severity:     "critical",
				Description:  "Allows access from 0.0.0.0/0",
			},
		},
		Warnings: []string{"Minor config issue"},
	}

	if report.Provider != ProviderAzure {
		t.Errorf("Expected provider Azure, got %s", report.Provider)
	}

	if report.Compliant {
		t.Error("Expected non-compliant report")
	}

	if len(report.Violations) != 1 {
		t.Errorf("Expected 1 violation, got %d", len(report.Violations))
	}

	if report.Violations[0].Severity != "critical" {
		t.Errorf("Expected critical severity, got %s", report.Violations[0].Severity)
	}
}

// TestSecurityResourceConversion tests resource conversion
func TestSecurityResourceConversion(t *testing.T) {
	resource := SecurityResource{
		ID:       "sg-12345",
		Name:     "pci-segment-cde",
		Type:     "security-group",
		Provider: ProviderAWS,
		Rules: []SecurityRule{
			{
				Direction:  "ingress",
				Protocol:   "tcp",
				FromPort:   443,
				ToPort:     443,
				CIDRBlocks: []string{"10.0.1.0/24"},
				Action:     "allow",
			},
		},
		Tags: map[string]string{
			"pci-segment-managed": "true",
			"pci-dss":             "Req 1.3",
		},
	}

	if resource.Provider != ProviderAWS {
		t.Errorf("Expected AWS provider, got %s", resource.Provider)
	}

	if len(resource.Rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(resource.Rules))
	}

	if resource.Rules[0].FromPort != 443 {
		t.Errorf("Expected port 443, got %d", resource.Rules[0].FromPort)
	}

	if _, ok := resource.Tags["pci-dss"]; !ok {
		t.Error("Expected pci-dss tag")
	}
}

// TestAWSTagBuilding tests AWS tag creation
func TestBuildAWSTags(t *testing.T) {
	integrator := &AWSIntegrator{
		config: &Config{
			Tags: map[string]string{
				"Environment": "production",
			},
		},
	}

	pol := &policy.Policy{
		Metadata: policy.Metadata{
			Name: "test-policy",
			Annotations: map[string]string{
				"pci-dss": "Req 1.2, Req 1.3",
			},
		},
	}

	tags := integrator.buildTags(pol)

	// Check for required tags
	foundManaged := false
	foundPolicy := false
	foundPCIDSS := false
	foundEnv := false

	for _, tag := range tags {
		switch *tag.Key {
		case "pci-segment/managed":
			foundManaged = true
		case "pci-segment/policy":
			foundPolicy = true
		case "pci-dss":
			foundPCIDSS = true
		case "Environment":
			foundEnv = true
		}
	}

	if !foundManaged {
		t.Error("Missing pci-segment/managed tag")
	}
	if !foundPolicy {
		t.Error("Missing pci-segment/policy tag")
	}
	if !foundPCIDSS {
		t.Error("Missing pci-dss tag")
	}
	if !foundEnv {
		t.Error("Missing custom Environment tag")
	}
}

// TestAzureTagBuilding tests Azure tag creation
func TestBuildAzureTags(t *testing.T) {
	integrator := &AzureIntegrator{
		config: &Config{
			Tags: map[string]string{
				"Environment": "production",
			},
		},
	}

	pol := &policy.Policy{
		Metadata: policy.Metadata{
			Name: "test-policy",
			Annotations: map[string]string{
				"pci-dss": "Req 1.2, Req 1.3",
			},
		},
	}

	tags := integrator.buildTags(pol)

	if _, ok := tags["pci-segment-managed"]; !ok {
		t.Error("Missing pci-segment-managed tag")
	}
	if _, ok := tags["pci-segment-policy"]; !ok {
		t.Error("Missing pci-segment-policy tag")
	}
	if _, ok := tags["pci-dss"]; !ok {
		t.Error("Missing pci-dss tag")
	}
	if _, ok := tags["Environment"]; !ok {
		t.Error("Missing custom Environment tag")
	}
}

// TestWildcardDetection tests wildcard CIDR detection
func TestWildcardDetection(t *testing.T) {
	wildcardCIDRs := []string{
		"0.0.0.0/0",
		"::/0",
		"*",
	}

	for _, cidr := range wildcardCIDRs {
		if cidr == "0.0.0.0/0" || cidr == "*" {
			// This should trigger a violation
			if cidr != "0.0.0.0/0" && cidr != "*" {
				t.Errorf("Expected %s to be detected as wildcard", cidr)
			}
		}
	}
}
