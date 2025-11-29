//go:build !linux

package privilege

// MACStatus represents the current Mandatory Access Control state.
// On non-Linux platforms, MAC is not applicable.
type MACStatus struct {
	ActiveLSMs       []string
	SELinuxEnabled   bool
	SELinuxEnforcing bool
	SELinuxDomain    string
	AppArmorEnabled  bool
	AppArmorProfile  string
	AppArmorMode     string
}

// DetectMAC returns an empty status on non-Linux platforms.
// SELinux and AppArmor are Linux-specific LSMs.
func DetectMAC() (*MACStatus, error) {
	return &MACStatus{
		ActiveLSMs: []string{},
	}, nil
}

// VerifyMAC is a no-op on non-Linux platforms.
// MAC enforcement (SELinux/AppArmor) is Linux-specific.
func VerifyMAC(_ Config) error {
	return nil
}

// LogMACStatus is a no-op on non-Linux platforms.
func LogMACStatus() {
	// MAC not applicable on non-Linux
}
