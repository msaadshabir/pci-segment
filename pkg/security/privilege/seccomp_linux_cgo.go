//go:build linux && cgo

package privilege

import (
    "errors"
    "fmt"

    seccomp "github.com/seccomp/libseccomp-golang"
    "golang.org/x/sys/unix"
)

func installSeccompFilter(denylist []string) error {
    if len(denylist) == 0 {
        return nil
    }

    if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
        return fmt.Errorf("privilege: enable no_new_privs before seccomp: %w", err)
    }

    filter, err := seccomp.NewFilter(seccomp.ActAllow)
    if err != nil {
        return fmt.Errorf("privilege: create seccomp filter: %w", err)
    }

    denyAction := seccomp.ActErrno.SetReturnCode(int16(unix.EPERM))

    for _, name := range denylist {
        sc, scErr := seccomp.GetSyscallFromName(name)
        if scErr != nil {
            if errors.Is(scErr, seccomp.ErrSyscallDoesNotExist) {
                continue
            }
            return fmt.Errorf("privilege: lookup syscall %q for seccomp: %w", name, scErr)
        }

        if err := filter.AddRule(sc, denyAction); err != nil {
            return fmt.Errorf("privilege: add seccomp rule for %q: %w", name, err)
        }
    }

    if err := filter.SetNoNewPrivsBit(true); err != nil {
        return fmt.Errorf("privilege: set seccomp no_new_privs bit: %w", err)
    }

    if err := filter.Load(); err != nil {
        return fmt.Errorf("privilege: load seccomp filter: %w", err)
    }

    return nil
}
