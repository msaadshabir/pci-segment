package enforcer

import (
	"runtime"
	"testing"

	"github.com/msaadshabir/pci-segment/pkg/policy"
)

func TestStubEnforcerLifecycle(t *testing.T) {
	stub := &StubEnforcer{}

	if stub.IsRunning() {
		t.Error("stub should not be running initially")
	}

	if err := stub.Start(); err != nil {
		t.Errorf("Start() failed: %v", err)
	}

	if !stub.IsRunning() {
		t.Error("stub should be running after Start()")
	}

	if err := stub.Stop(); err != nil {
		t.Errorf("Stop() failed: %v", err)
	}

	if stub.IsRunning() {
		t.Error("stub should not be running after Stop()")
	}

	if err := stub.Stop(); err != nil {
		t.Error("Stop() should be idempotent")
	}
}

func TestStubEnforcerAddPolicy(t *testing.T) {
	stub := &StubEnforcer{}

	pol := &policy.Policy{
		Metadata: policy.Metadata{
			Name: "test-policy",
		},
	}

	if err := stub.AddPolicy(pol); err != nil {
		t.Errorf("AddPolicy() failed: %v", err)
	}
}

func TestStubEnforcerRemovePolicy(t *testing.T) {
	stub := &StubEnforcer{}

	if err := stub.RemovePolicy("nonexistent"); err != nil {
		t.Errorf("RemovePolicy() should not error: %v", err)
	}
}

func TestStubEnforcerGetEvents(t *testing.T) {
	stub := &StubEnforcer{}

	events := stub.GetEvents()
	if events == nil {
		t.Error("GetEvents() should return non-nil slice")
	}
	if len(events) != 0 {
		t.Error("GetEvents() should return empty slice")
	}
}

func TestNewEnforcerReturnsImplementation(t *testing.T) {
	enforcer, err := NewEnforcer()

	switch runtime.GOOS {
	case "linux":
		if err != nil {
			t.Logf("Linux enforcer creation failed (may need root): %v", err)
			return
		}
		if enforcer == nil {
			t.Error("expected non-nil enforcer on Linux")
		}
	case "darwin":
		if err != nil {
			t.Errorf("expected no error on darwin: %v", err)
		}
		if enforcer == nil {
			t.Error("expected non-nil enforcer on darwin")
		}
	case "windows":
		if err == nil {
			t.Error("expected error on windows")
		}
	default:
		if err == nil {
			t.Errorf("expected error on unsupported OS: %s", runtime.GOOS)
		}
	}
}
