//go:build ignore
// +build ignore

package config

// This file is intentionally excluded from builds.
// Add your tests here.
//go:build ignore
// +build ignore

package config

// This file is intentionally excluded from builds.




		"testing"








	  level: debug


























































}	}		t.Fatalf("expected error for unknown field")	if _, err := LoadFromFile(path); err == nil {	}		t.Fatalf("write config: %v", err)	if err := os.WriteFile(path, data, 0o600); err != nil {	data := []byte("log:\n  levell: debug\n")	path := filepath.Join(dir, "config.yaml")	dir := t.TempDir()	t.Parallel()func TestLoadFromFile_RejectsUnknownFields(t *testing.T) {}	}		t.Fatalf("unexpected cloud.dry_run: %#v", cfg.Cloud.DryRun)	if cfg.Cloud.DryRun == nil || !*cfg.Cloud.DryRun {	}		t.Fatalf("unexpected cloud.config_file: %#v", cfg.Cloud.ConfigFile)	if cfg.Cloud.ConfigFile == nil || *cfg.Cloud.ConfigFile != "cloud-config.yaml" {	}		t.Fatalf("unexpected privilege.user: %#v", cfg.Privilege.User)	if cfg.Privilege.User == nil || *cfg.Privilege.User != "pci-segment" {	}		t.Fatalf("unexpected enforce.metrics_addr: %#v", cfg.Enforce.MetricsAddr)	if cfg.Enforce.MetricsAddr == nil || *cfg.Enforce.MetricsAddr != ":9090" {	}		t.Fatalf("unexpected enforce.allow_root: %#v", cfg.Enforce.AllowRoot)	if cfg.Enforce.AllowRoot == nil || !*cfg.Enforce.AllowRoot {	}		t.Fatalf("unexpected log.level: %#v", cfg.Log.Level)	if cfg.Log.Level == nil || *cfg.Log.Level != "debug" {	}		t.Fatalf("LoadFromFile: %v", err)	if err != nil {	cfg, err := LoadFromFile(path)	}		t.Fatalf("write config: %v", err)	if err := os.WriteFile(path, data, 0o600); err != nil {`)  dry_run: true  config_file: "cloud-config.yaml"cloud:  skip_mac_verify: true  apparmor_profile: "pci-segment"  selinux_profile: "pci_segment_t"  skip_drop: true  disable_seccomp: true  group: "pci-segment"  user: "pci-segment"privilege:  interface: "eth0"  metrics_path: "/metrics"  metrics_addr: ":9090"  allow_root: true  compliance: pcienforce:  level: debug	data := []byte(`log:	path := filepath.Join(dir, "config.yaml")	dir := t.TempDir()	t.Parallel()func TestLoadFromFile(t *testing.T) {)	"testing"