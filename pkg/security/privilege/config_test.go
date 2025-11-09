package privilege

import "testing"

func TestConfigValidate(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected default config to validate, got %v", err)
	}

	cfg.TargetUser = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error when target user is empty")
	}

	cfg = DefaultConfig()
	cfg.TargetGroup = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error when target group is empty")
	}

	cfg = DefaultConfig()
	cfg.KeepCaps = nil
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error when no capabilities provided")
	}
}

func TestFromEnvOverrides(t *testing.T) {
	t.Setenv(EnvTargetUser, "custom-user")
	t.Setenv(EnvTargetGroup, "custom-group")

	cfg := FromEnv()
	if cfg.TargetUser != "custom-user" {
		t.Fatalf("expected target user override, got %s", cfg.TargetUser)
	}
	if cfg.TargetGroup != "custom-group" {
		t.Fatalf("expected target group override, got %s", cfg.TargetGroup)
	}
}

func TestFromEnvSeccompToggle(t *testing.T) {
	t.Setenv(EnvDisableSeccomp, "1")

	cfg := FromEnv()
	if cfg.EnableSeccomp {
		t.Fatal("expected seccomp to be disabled when env var is truthy")
	}

	t.Setenv(EnvDisableSeccomp, "0")
	cfg = FromEnv()
	if !cfg.EnableSeccomp {
		t.Fatal("expected seccomp to remain enabled when env var is falsy")
	}
}

func TestSkipRequested(t *testing.T) {
	t.Setenv(EnvSkipDrop, "false")
	if SkipRequested() {
		t.Fatal("expected skip to be false when env=false")
	}

	t.Setenv(EnvSkipDrop, "1")
	if !SkipRequested() {
		t.Fatal("expected skip to be true when env=1")
	}
}
