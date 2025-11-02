package privilege

import (
	"fmt"
	"os"
)

const (
	// EnvTargetUser allows overriding the target service user for privilege dropping.
	EnvTargetUser = "PCI_SEGMENT_PRIVILEGE_USER"

	// EnvTargetGroup allows overriding the target service group for privilege dropping.
	EnvTargetGroup = "PCI_SEGMENT_PRIVILEGE_GROUP"

	// EnvSkipDrop disables privilege dropping when set to a truthy value.
	EnvSkipDrop = "PCI_SEGMENT_SKIP_PRIVILEGE_DROP"
)

// Config encapsulates how privileges should be reduced before enforcement starts.
type Config struct {
	TargetUser  string
	TargetGroup string
	KeepCaps    []string
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

	return cfg
}

// SkipRequested reports whether the caller opted out of privilege dropping.
func SkipRequested() bool {
	v := os.Getenv(EnvSkipDrop)
	if v == "" {
		return false
	}

	switch v {
	case "0", "false", "FALSE", "no", "NO":
		return false
	default:
		return true
	}
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
