//go:build linux && !cgo

package privilege

import "fmt"

func installSeccompFilter(denylist []string) error {
	if len(denylist) == 0 {
		return nil
	}

	return fmt.Errorf("privilege: seccomp filter requested but binary built without cgo support; rebuild with cgo enabled")
}
