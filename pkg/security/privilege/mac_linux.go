//go:build linux

package privilege

import (
	"fmt"
	"os"
	"strings"
)

// MACStatus represents the current Mandatory Access Control state.
type MACStatus struct {
	// ActiveLSMs lists the Linux Security Modules currently active.
	ActiveLSMs []string

	// SELinuxEnabled indicates if SELinux is among the active LSMs.
	SELinuxEnabled bool

	// SELinuxEnforcing indicates if SELinux is in enforcing mode.
	SELinuxEnforcing bool

	// SELinuxDomain is the current process domain (e.g., "pci_segment_t").
	SELinuxDomain string

	// AppArmorEnabled indicates if AppArmor is among the active LSMs.
	AppArmorEnabled bool

	// AppArmorProfile is the current profile name and mode (e.g., "pci-segment (enforce)").
	AppArmorProfile string

	// AppArmorMode is the enforcement mode: "enforce", "complain", or "unconfined".
	AppArmorMode string
}

// DetectMAC reads kernel security state to determine active LSMs and current confinement.
func DetectMAC() (*MACStatus, error) {
	status := &MACStatus{}

	// Read active LSMs from /sys/kernel/security/lsm
	lsms, err := readLSMList()
	if err != nil {
		// Not fatal; LSM detection may fail on older kernels
		status.ActiveLSMs = []string{}
	} else {
		status.ActiveLSMs = lsms
		for _, lsm := range lsms {
			switch strings.ToLower(lsm) {
			case "selinux":
				status.SELinuxEnabled = true
			case "apparmor":
				status.AppArmorEnabled = true
			}
		}
	}

	// Detect SELinux state
	if status.SELinuxEnabled {
		status.SELinuxEnforcing = isSELinuxEnforcing()
		domain, err := readSELinuxDomain()
		if err == nil {
			status.SELinuxDomain = domain
		}
	}

	// Detect AppArmor state
	if status.AppArmorEnabled {
		profile, mode, err := readAppArmorProfile()
		if err == nil {
			status.AppArmorProfile = profile
			status.AppArmorMode = mode
		}
	}

	return status, nil
}

// VerifyMAC checks that the process is running under the expected MAC profile.
// Returns nil if verification passes or is not applicable.
func VerifyMAC(cfg Config) error {
	if !cfg.VerifyMAC {
		return nil
	}

	// Skip if no profiles configured
	if cfg.SELinuxProfile == "" && cfg.AppArmorProfile == "" {
		return nil
	}

	status, err := DetectMAC()
	if err != nil {
		return fmt.Errorf("mac: failed to detect security state: %w", err)
	}

	// Verify SELinux if configured
	if cfg.SELinuxProfile != "" {
		if err := verifySELinux(cfg.SELinuxProfile, status); err != nil {
			return err
		}
	}

	// Verify AppArmor if configured
	if cfg.AppArmorProfile != "" {
		if err := verifyAppArmor(cfg.AppArmorProfile, status); err != nil {
			return err
		}
	}

	return nil
}

// verifySELinux checks that the process is running in the expected SELinux domain.
func verifySELinux(expectedDomain string, status *MACStatus) error {
	if !status.SELinuxEnabled {
		return fmt.Errorf("mac: selinux profile %q expected but selinux is not enabled", expectedDomain)
	}

	if !status.SELinuxEnforcing {
		// Warn but don't fail in permissive mode
		fmt.Printf("[WARN] SELinux is in permissive mode; enforcement not active\n")
	}

	// Extract domain from full context (user:role:type:level)
	domain := extractSELinuxDomain(status.SELinuxDomain)

	if domain != expectedDomain {
		return fmt.Errorf("mac: running in selinux domain %q, expected %q (see docs/HARDENING.md)", domain, expectedDomain)
	}

	fmt.Printf("[HARDENING] SELinux domain verified: %s\n", domain)
	return nil
}

// verifyAppArmor checks that the process is confined by the expected AppArmor profile.
func verifyAppArmor(expectedProfile string, status *MACStatus) error {
	if !status.AppArmorEnabled {
		return fmt.Errorf("mac: apparmor profile %q expected but apparmor is not enabled", expectedProfile)
	}

	if status.AppArmorMode == "unconfined" {
		return fmt.Errorf("mac: process is unconfined, expected apparmor profile %q (see docs/HARDENING.md)", expectedProfile)
	}

	if status.AppArmorProfile != expectedProfile {
		return fmt.Errorf("mac: running under apparmor profile %q, expected %q (see docs/HARDENING.md)", status.AppArmorProfile, expectedProfile)
	}

	if status.AppArmorMode == "complain" {
		fmt.Printf("[WARN] AppArmor profile %s is in complain mode; violations logged but not blocked\n", expectedProfile)
	}

	fmt.Printf("[HARDENING] AppArmor profile verified: %s (%s)\n", status.AppArmorProfile, status.AppArmorMode)
	return nil
}

// readLSMList reads the active LSM list from /sys/kernel/security/lsm.
func readLSMList() ([]string, error) {
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return nil, fmt.Errorf("reading lsm list: %w", err)
	}

	content := strings.TrimSpace(string(data))
	if content == "" {
		return []string{}, nil
	}

	return strings.Split(content, ","), nil
}

// isSELinuxEnforcing checks if SELinux is in enforcing mode.
func isSELinuxEnforcing() bool {
	data, err := os.ReadFile("/sys/fs/selinux/enforce")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "1"
}

// readSELinuxDomain reads the current process's SELinux context.
func readSELinuxDomain() (string, error) {
	data, err := os.ReadFile("/proc/self/attr/current")
	if err != nil {
		return "", fmt.Errorf("reading selinux context: %w", err)
	}
	return strings.TrimSpace(strings.TrimRight(string(data), "\x00")), nil
}

// extractSELinuxDomain extracts the type/domain from a full SELinux context.
// Context format: user:role:type:level (e.g., "system_u:system_r:pci_segment_t:s0")
func extractSELinuxDomain(context string) string {
	parts := strings.Split(context, ":")
	if len(parts) >= 3 {
		return parts[2]
	}
	return context
}

// readAppArmorProfile reads the current process's AppArmor profile and mode.
func readAppArmorProfile() (profile string, mode string, err error) {
	// Read from /proc/self/attr/current for AppArmor
	data, err := os.ReadFile("/proc/self/attr/apparmor/current")
	if err != nil {
		// Fallback to older path
		data, err = os.ReadFile("/proc/self/attr/current")
		if err != nil {
			return "", "", fmt.Errorf("reading apparmor profile: %w", err)
		}
	}

	content := strings.TrimSpace(strings.TrimRight(string(data), "\x00"))

	// Parse format: "profile_name (mode)" or "unconfined"
	if content == "unconfined" {
		return "unconfined", "unconfined", nil
	}

	// Look for mode in parentheses
	if idx := strings.LastIndex(content, " ("); idx != -1 {
		profile = content[:idx]
		mode = strings.TrimSuffix(content[idx+2:], ")")
		return profile, mode, nil
	}

	return content, "enforce", nil
}

// LogMACStatus logs the current MAC state for audit purposes.
func LogMACStatus() {
	status, err := DetectMAC()
	if err != nil {
		fmt.Printf("[WARN] Could not detect MAC status: %v\n", err)
		return
	}

	if len(status.ActiveLSMs) > 0 {
		fmt.Printf("[MAC] Active LSMs: %s\n", strings.Join(status.ActiveLSMs, ", "))
	}

	if status.SELinuxEnabled {
		mode := "permissive"
		if status.SELinuxEnforcing {
			mode = "enforcing"
		}
		fmt.Printf("[MAC] SELinux: %s, domain=%s\n", mode, status.SELinuxDomain)
	}

	if status.AppArmorEnabled {
		fmt.Printf("[MAC] AppArmor: profile=%s, mode=%s\n", status.AppArmorProfile, status.AppArmorMode)
	}

	if !status.SELinuxEnabled && !status.AppArmorEnabled {
		fmt.Printf("[MAC] No MAC enforcement active (SELinux/AppArmor not detected)\n")
	}
}
