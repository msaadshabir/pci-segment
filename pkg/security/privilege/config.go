package privilege

import (
	"fmt"
	"os"
	"strings"
)

const (
	// EnvTargetUser allows overriding the target service user for privilege dropping.
	EnvTargetUser = "PCI_SEGMENT_PRIVILEGE_USER"

	// EnvTargetGroup allows overriding the target service group for privilege dropping.
	EnvTargetGroup = "PCI_SEGMENT_PRIVILEGE_GROUP"

	// EnvSkipDrop disables privilege dropping when set to a truthy value.
	EnvSkipDrop = "PCI_SEGMENT_SKIP_PRIVILEGE_DROP"

	// EnvDisableSeccomp disables seccomp hardening when set to a truthy value.
	EnvDisableSeccomp = "PCI_SEGMENT_DISABLE_SECCOMP"
)

// Config encapsulates how privileges should be reduced before enforcement starts.
type Config struct {
	TargetUser      string
	TargetGroup     string
	KeepCaps        []string
	EnableSeccomp   bool
	SeccompDenylist []string
}

var defaultSeccompDenylist = []string{
	"ptrace",
	"process_vm_readv",
	"process_vm_writev",
	"keyctl",
	"add_key",
	"request_key",
	"userfaultfd",
	"init_module",
	"finit_module",
	"delete_module",
	"kexec_load",
	"kexec_file_load",
	"open_by_handle_at",
	"mount",
	"umount2",
	"pivot_root",
	"move_mount",
	"clone3",
}

// DefaultConfig returns hardening defaults suitable for Linux enforcement.
func DefaultConfig() Config {
	return Config{
		TargetUser:  "pci-segment",
		TargetGroup: "pci-segment",
		KeepCaps: []string{
			"CAP_NET_ADMIN",
			"CAP_BPF",
		},
		EnableSeccomp:   true,
		SeccompDenylist: append([]string(nil), defaultSeccompDenylist...),
	}
}

// FromEnv builds a Config by applying environment overrides on top of defaults.
func FromEnv() Config {
	cfg := DefaultConfig()

	if v := os.Getenv(EnvTargetUser); v != "" {
		cfg.TargetUser = v
	}
	if v := os.Getenv(EnvTargetGroup); v != "" {
		cfg.TargetGroup = v
	}
	if truthy(os.Getenv(EnvDisableSeccomp)) {
		cfg.EnableSeccomp = false
	}

	return cfg
}

// SkipRequested reports whether the caller opted out of privilege dropping.
func SkipRequested() bool {
	v := os.Getenv(EnvSkipDrop)
	if v == "" {
		return false
	}

	return truthy(v)
}

// Validate ensures the configuration is usable before attempting privilege changes.
func (c Config) Validate() error {
	if c.TargetUser == "" {
		return fmt.Errorf("privilege: target user must be specified")
	}
	if c.TargetGroup == "" {
		return fmt.Errorf("privilege: target group must be specified")
	}
	if len(c.KeepCaps) == 0 {
		return fmt.Errorf("privilege: at least one capability must be retained")
	}
	return nil
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "false", "no":
		return false
	default:
		return true
	}
}
