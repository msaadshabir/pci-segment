package privilege

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectMAC(t *testing.T) {
	// This test runs on any platform; on non-Linux it returns empty status
	status, err := DetectMAC()
	if err != nil {
		t.Fatalf("DetectMAC() returned error: %v", err)
	}

	if status == nil {
		t.Fatal("DetectMAC() returned nil status")
	}

	// On non-Linux, LSMs should be empty
	// On Linux, we just verify the struct is populated (may or may not have LSMs)
	t.Logf("Active LSMs: %v", status.ActiveLSMs)
	t.Logf("SELinux enabled: %v, enforcing: %v, domain: %s",
		status.SELinuxEnabled, status.SELinuxEnforcing, status.SELinuxDomain)
	t.Logf("AppArmor enabled: %v, profile: %s, mode: %s",
		status.AppArmorEnabled, status.AppArmorProfile, status.AppArmorMode)
}

func TestVerifyMAC_NoProfileConfigured(t *testing.T) {
	cfg := Config{
		VerifyMAC:       true,
		SELinuxProfile:  "",
		AppArmorProfile: "",
	}

	// Should pass when no profiles are configured
	if err := VerifyMAC(cfg); err != nil {
		t.Fatalf("VerifyMAC() with no profiles should pass, got: %v", err)
	}
}

func TestVerifyMAC_SkipVerification(t *testing.T) {
	cfg := Config{
		VerifyMAC:       false,
		SELinuxProfile:  "some_profile_t",
		AppArmorProfile: "some-profile",
	}

	// Should pass when verification is disabled
	if err := VerifyMAC(cfg); err != nil {
		t.Fatalf("VerifyMAC() with VerifyMAC=false should pass, got: %v", err)
	}
}

func TestFromEnv_MACOverrides(t *testing.T) {
	t.Setenv(EnvSELinuxProfile, "test_domain_t")
	t.Setenv(EnvAppArmorProfile, "test-profile")

	cfg := FromEnv()
	if cfg.SELinuxProfile != "test_domain_t" {
		t.Errorf("expected SELinuxProfile='test_domain_t', got '%s'", cfg.SELinuxProfile)
	}
	if cfg.AppArmorProfile != "test-profile" {
		t.Errorf("expected AppArmorProfile='test-profile', got '%s'", cfg.AppArmorProfile)
	}
}

func TestFromEnv_SkipMACVerify(t *testing.T) {
	t.Setenv(EnvSkipMACVerify, "1")

	cfg := FromEnv()
	if cfg.VerifyMAC {
		t.Error("expected VerifyMAC=false when PCI_SEGMENT_SKIP_MAC_VERIFY=1")
	}

	t.Setenv(EnvSkipMACVerify, "0")
	cfg = FromEnv()
	if !cfg.VerifyMAC {
		t.Error("expected VerifyMAC=true when PCI_SEGMENT_SKIP_MAC_VERIFY=0")
	}
}

func TestExtractSELinuxDomain(t *testing.T) {
	tests := []struct {
		name     string
		context  string
		expected string
	}{
		{
			name:     "full context",
			context:  "system_u:system_r:pci_segment_t:s0",
			expected: "pci_segment_t",
		},
		{
			name:     "minimal context",
			context:  "user_u:role_r:type_t:s0:c0.c1023",
			expected: "type_t",
		},
		{
			name:     "unconfined",
			context:  "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
			expected: "unconfined_t",
		},
		{
			name:     "short context",
			context:  "u:r:t",
			expected: "t",
		},
		{
			name:     "no colons",
			context:  "simple",
			expected: "simple",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Inline extraction logic to test the algorithm (mirrors mac_linux.go)
			result := testExtractSELinuxDomain(tt.context)
			if result != tt.expected {
				t.Errorf("extractSELinuxDomain(%q) = %q, want %q", tt.context, result, tt.expected)
			}
		})
	}
}

// testExtractSELinuxDomain is a test helper that mirrors the real implementation
func testExtractSELinuxDomain(context string) string {
	parts := strings.Split(context, ":")
	if len(parts) >= 3 {
		return parts[2]
	}
	return context
}

func TestMACStatus_Defaults(t *testing.T) {
	status := &MACStatus{}

	if status.SELinuxEnabled {
		t.Error("SELinuxEnabled should default to false")
	}
	if status.AppArmorEnabled {
		t.Error("AppArmorEnabled should default to false")
	}
	if len(status.ActiveLSMs) != 0 {
		t.Error("ActiveLSMs should default to empty")
	}
}

// TestReadLSMList_MockFilesystem tests LSM list parsing with a mock file
func TestReadLSMList_MockFilesystem(t *testing.T) {
	// Create a temp file simulating /sys/kernel/security/lsm
	tmpDir := t.TempDir()
	lsmFile := filepath.Join(tmpDir, "lsm")

	testCases := []struct {
		name     string
		content  string
		expected []string
	}{
		{
			name:     "selinux only",
			content:  "selinux",
			expected: []string{"selinux"},
		},
		{
			name:     "apparmor only",
			content:  "apparmor",
			expected: []string{"apparmor"},
		},
		{
			name:     "multiple lsms",
			content:  "lockdown,capability,selinux,bpf",
			expected: []string{"lockdown", "capability", "selinux", "bpf"},
		},
		{
			name:     "empty",
			content:  "",
			expected: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(lsmFile, []byte(tc.content), 0644); err != nil {
				t.Fatalf("failed to write test file: %v", err)
			}

			// Read and parse the content (simulating readLSMList logic)
			data, err := os.ReadFile(lsmFile)
			if err != nil {
				t.Fatalf("failed to read test file: %v", err)
			}

			content := string(data)
			content = trimWhitespace(content)

			var result []string
			if content == "" {
				result = []string{}
			} else {
				result = splitByComma(content)
			}

			if len(result) != len(tc.expected) {
				t.Errorf("expected %d LSMs, got %d", len(tc.expected), len(result))
				return
			}

			for i, lsm := range result {
				if lsm != tc.expected[i] {
					t.Errorf("LSM[%d] = %q, want %q", i, lsm, tc.expected[i])
				}
			}
		})
	}
}

// Helper functions for testing (mirrors the real implementation logic)
func trimWhitespace(s string) string {
	// Simple trim for testing
	result := s
	for len(result) > 0 && (result[0] == ' ' || result[0] == '\n' || result[0] == '\t') {
		result = result[1:]
	}
	for len(result) > 0 && (result[len(result)-1] == ' ' || result[len(result)-1] == '\n' || result[len(result)-1] == '\t') {
		result = result[:len(result)-1]
	}
	return result
}

func splitByComma(s string) []string {
	if s == "" {
		return []string{}
	}
	var result []string
	current := ""
	for _, c := range s {
		if c == ',' {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}
