//go:build !darwin

package enforcer

// NewPFEnforcer returns a stub enforcer when building on non-macOS platforms.
func NewPFEnforcer() (Enforcer, error) {
	return &StubEnforcer{}, nil
}
