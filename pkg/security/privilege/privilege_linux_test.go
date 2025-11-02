//go:build linux

package privilege

import (
	"os/user"
	"testing"
)

func TestLookupCapability(t *testing.T) {
	capNames := []string{"CAP_NET_ADMIN", "cap_bpf", "CAP_SYS_ADMIN"}
	for _, name := range capNames {
		if _, err := lookupCapability(name); err != nil {
			t.Fatalf("expected capability %s to resolve: %v", name, err)
		}
	}

	if _, err := lookupCapability("CAP_UNKNOWN"); err == nil {
		t.Fatal("expected unsupported capability to return error")
	}
}

func TestResolveIDsUsesExistingUser(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatalf("failed to lookup current user: %v", err)
	}

	gid := current.Gid
	if gid == "" {
		gid = current.Username
	}

	uid, gidInt, err := resolveIDs(current.Username, gid)
	if err != nil {
		t.Fatalf("resolveIDs returned error: %v", err)
	}

	if uid <= 0 {
		t.Fatalf("unexpected uid result: %d", uid)
	}
	if gidInt <= 0 {
		t.Fatalf("unexpected gid result: %d", gidInt)
	}
}

func TestEnsureSkipsWhenRequested(t *testing.T) {
	t.Setenv(EnvSkipDrop, "1")

	cfg := DefaultConfig()
	current, err := user.Current()
	if err != nil {
		t.Fatalf("failed to lookup current user: %v", err)
	}

	cfg.TargetUser = current.Username
	cfg.TargetGroup = current.Gid

	if err := Ensure(cfg); err != nil {
		t.Fatalf("ensure should skip without error when skip env set: %v", err)
	}
}
