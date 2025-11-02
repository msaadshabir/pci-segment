//go:build !linux

package privilege

// Ensure is a no-op on non-Linux platforms where Linux capabilities are unavailable.
func Ensure(cfg Config) error {
	return nil
}
