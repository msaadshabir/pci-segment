package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	yaml "gopkg.in/yaml.v3"
)

type Config struct {
	Log       LogConfig       `yaml:"log"`
	Enforce   EnforceConfig   `yaml:"enforce"`
	Privilege PrivilegeConfig `yaml:"privilege"`
	Cloud     CloudConfig     `yaml:"cloud"`
}

type LogConfig struct {
	Level *string `yaml:"level"`
}

type EnforceConfig struct {
	Compliance  *string `yaml:"compliance"`
	AllowRoot   *bool   `yaml:"allow_root"`
	MetricsAddr *string `yaml:"metrics_addr"`
	MetricsPath *string `yaml:"metrics_path"`
	Interface   *string `yaml:"interface"`
}

type PrivilegeConfig struct {
	User            *string `yaml:"user"`
	Group           *string `yaml:"group"`
	SkipDrop        *bool   `yaml:"skip_drop"`
	DisableSeccomp  *bool   `yaml:"disable_seccomp"`
	SELinuxProfile  *string `yaml:"selinux_profile"`
	AppArmorProfile *string `yaml:"apparmor_profile"`
	SkipMACVerify   *bool   `yaml:"skip_mac_verify"`
}

type CloudConfig struct {
	ConfigFile *string `yaml:"config_file"`
	DryRun     *bool   `yaml:"dry_run"`
}

func LoadFromFile(path string) (*Config, error) {
	cleanPath := filepath.Clean(path)
	data, err := os.ReadFile(cleanPath) // #nosec G304 - file path from CLI argument, validated by filepath.Clean
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config YAML: %w", err)
	}

	return &cfg, nil
}
