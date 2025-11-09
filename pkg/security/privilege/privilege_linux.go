//go:build linux

package privilege

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"

	seccomp "github.com/seccomp/libseccomp-golang"
	"github.com/syndtr/gocapability/capability"
	"golang.org/x/sys/unix"
)

// Ensure enforces least-privilege execution for the current process on Linux.
func Ensure(cfg Config) error {
	if SkipRequested() {
		if os.Geteuid() == 0 {
			fmt.Println("[WARN] Privilege drop skipped via PCI_SEGMENT_SKIP_PRIVILEGE_DROP; running as root")
		}
		return nil
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	if os.Geteuid() != 0 {
		return nil // Nothing to do if already non-root.
	}

	uid, gid, err := resolveIDs(cfg.TargetUser, cfg.TargetGroup)
	if err != nil {
		return fmt.Errorf("privilege: resolve target identity failed: %w (see docs/HARDENING.md)", err)
	}

	keepCaps, err := toCapabilities(cfg.KeepCaps)
	if err != nil {
		return err
	}

	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("privilege: enabling PR_SET_KEEPCAPS failed: %w", err)
	}

	if err := dropSupplementaryGroups(gid); err != nil {
		return err
	}

	if err := unix.Setresgid(gid, gid, gid); err != nil {
		return fmt.Errorf("privilege: setresgid failed: %w", err)
	}

	if err := unix.Setresuid(uid, uid, uid); err != nil {
		return fmt.Errorf("privilege: setresuid failed: %w", err)
	}

	if err := unix.Prctl(unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("privilege: clearing ambient caps failed: %w", err)
	}

	if err := applyCapabilities(keepCaps); err != nil {
		return err
	}

	if cfg.EnableSeccomp {
		if err := installSeccompFilter(cfg.SeccompDenylist); err != nil {
			return fmt.Errorf("privilege: seccomp filter install failed: %w (see docs/HARDENING.md)", err)
		}
	}

	if os.Geteuid() == 0 {
		return fmt.Errorf("privilege: expected to run as non-root after drop, still uid=0")
	}

	fmt.Printf("[HARDENING] Running as %s:%s with restricted capabilities\n", cfg.TargetUser, cfg.TargetGroup)
	return nil
}

func resolveIDs(userName, groupName string) (int, int, error) {
	u, err := user.Lookup(userName)
	if err != nil {
		return 0, 0, fmt.Errorf("privilege: lookup user %q: %w", userName, err)
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("privilege: parse uid %q: %w", u.Uid, err)
	}

	grp := groupName
	if grp == "" {
		grp = u.Gid
	}

	if gid, convErr := strconv.Atoi(grp); convErr == nil {
		return uid, gid, nil
	}

	g, lookupErr := user.LookupGroup(grp)
	if lookupErr != nil {
		return 0, 0, fmt.Errorf("privilege: lookup group %q: %w", grp, lookupErr)
	}

	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("privilege: parse gid %q: %w", g.Gid, err)
	}

	return uid, gid, nil
}

func dropSupplementaryGroups(primaryGID int) error {
	if err := unix.Setgroups([]int{primaryGID}); err != nil {
		return fmt.Errorf("privilege: setgroups failed: %w", err)
	}
	return nil
}

func applyCapabilities(retain []capability.Cap) error {
	caps, err := capability.NewPid2(0)
	if err != nil {
		return fmt.Errorf("privilege: retrieve capabilities: %w", err)
	}

	for _, set := range []capability.CapType{capability.BOUNDING, capability.PERMITTED, capability.EFFECTIVE, capability.INHERITABLE, capability.AMBIENT} {
		caps.Clear(set)
	}

	for _, keep := range retain {
		for _, set := range []capability.CapType{capability.BOUNDING, capability.PERMITTED, capability.EFFECTIVE, capability.INHERITABLE, capability.AMBIENT} {
			caps.Set(set, keep)
		}
	}

	if err := caps.Apply(capability.BOUNDS); err != nil {
		return fmt.Errorf("privilege: apply bounding caps: %w", err)
	}
	if err := caps.Apply(capability.AMBIENT); err != nil {
		return fmt.Errorf("privilege: apply ambient caps: %w", err)
	}
	if err := caps.Apply(capability.CAPS); err != nil {
		return fmt.Errorf("privilege: apply capability sets: %w", err)
	}

	return nil
}

func toCapabilities(names []string) ([]capability.Cap, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("privilege: no capabilities requested")
	}

	result := make([]capability.Cap, 0, len(names))
	for _, name := range names {
		capConst, err := lookupCapability(strings.TrimSpace(name))
		if err != nil {
			return nil, err
		}
		result = append(result, capConst)
	}
	return result, nil
}

func lookupCapability(name string) (capability.Cap, error) {
	switch strings.ToUpper(name) {
	case "CAP_NET_ADMIN":
		return capability.CAP_NET_ADMIN, nil
	case "CAP_BPF":
		return capability.CAP_BPF, nil
	case "CAP_SYS_ADMIN":
		return capability.CAP_SYS_ADMIN, nil
	case "CAP_NET_RAW":
		return capability.CAP_NET_RAW, nil
	default:
		return 0, fmt.Errorf("privilege: unsupported capability %q", name)
	}
}

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
