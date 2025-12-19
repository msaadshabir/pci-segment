package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte(`log:
  level: debug
enforce:
  compliance: pci
  allow_root: true
  metrics_addr: ":9090"
  metrics_path: "/metrics"
  interface: "eth0"
privilege:
  user: "pci-segment"
  group: "pci-segment"
  disable_seccomp: true
  skip_drop: true
  selinux_profile: "pci_segment_t"
  apparmor_profile: "pci-segment"
  skip_mac_verify: true
cloud:
  config_file: "cloud-config.yaml"
  dry_run: true
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}

	if cfg.Log.Level == nil || *cfg.Log.Level != "debug" {
		t.Fatalf("unexpected log.level: %#v", cfg.Log.Level)
	}
	if cfg.Enforce.AllowRoot == nil || !*cfg.Enforce.AllowRoot {
		t.Fatalf("unexpected enforce.allow_root: %#v", cfg.Enforce.AllowRoot)
	}
	if cfg.Enforce.MetricsAddr == nil || *cfg.Enforce.MetricsAddr != ":9090" {
		t.Fatalf("unexpected enforce.metrics_addr: %#v", cfg.Enforce.MetricsAddr)
	}
	if cfg.Privilege.User == nil || *cfg.Privilege.User != "pci-segment" {
		t.Fatalf("unexpected privilege.user: %#v", cfg.Privilege.User)
	}
	if cfg.Cloud.ConfigFile == nil || *cfg.Cloud.ConfigFile != "cloud-config.yaml" {
		t.Fatalf("unexpected cloud.config_file: %#v", cfg.Cloud.ConfigFile)
	}
	if cfg.Cloud.DryRun == nil || !*cfg.Cloud.DryRun {
		t.Fatalf("unexpected cloud.dry_run: %#v", cfg.Cloud.DryRun)
	}
}

func TestLoadFromFile_RejectsUnknownFields(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte("log:\n  levell: debug\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := LoadFromFile(path); err == nil {
		t.Fatalf("expected error for unknown field")
	}
}
