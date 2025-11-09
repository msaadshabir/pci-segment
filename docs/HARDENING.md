# Privilege & Syscall Hardening

The enforcement path needs `CAP_BPF` and `CAP_NET_ADMIN` for eBPF attach. The
binary starts with elevated privileges only long enough to load programs, then
drops to the `pci-segment` service account, retaining a minimal capability set
and enabling a seccomp-bpf denylist of risky syscalls.

## 1. Create the Service Account (Once Per Host)

```bash
sudo groupadd --system pci-segment || true
sudo useradd \
  --system \
  --gid pci-segment \
  --home-dir /var/lib/pci-segment \
  --create-home \
  --shell /usr/sbin/nologin \
  pci-segment || true
```

## 2. Systemd Service (Capability Wrapper)

```bash
sudo tee /etc/systemd/system/pci-segment.service >/dev/null <<'EOF'
[Unit]
Description=PCI Segment Enforcement
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/pci-segment enforce -f /etc/pci-segment/policies/*.yaml
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN
User=root
Group=root
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now pci-segment.service
```

The binary relinquishes root and continues as `pci-segment` after attaching the
programs, so the unit only keeps the minimum capability set alive for startup.

## 3. Development Overrides

- `PCI_SEGMENT_SKIP_PRIVILEGE_DROP=1`: skip the downgrade entirely.
- `PCI_SEGMENT_PRIVILEGE_USER` / `PCI_SEGMENT_PRIVILEGE_GROUP`: override the
  target account without recompiling.
- `PCI_SEGMENT_DISABLE_SECCOMP=1`: bypass the seccomp filter (only for local
  debugging when unsupported syscalls are required).
- `--allow-root`: per-invocation override from the CLI.

Use overrides only for local testing. Production deployments **must** keep the
defaults to satisfy PCI-DSS Requirement 2.2.4.

## 4. Seccomp Enforcement

After the privilege drop completes, the binary installs a seccomp-bpf filter that
denies risky kernel interfaces (`ptrace`, `userfaultfd`, module loading, mount
operations, etc.). The filter runs in allow-by-default mode but blocks these
dangerous syscalls with `EPERM`, aligning with PCI-DSS 2.2.5 guidance on
restricting system functions.

If the host kernel is too old to support a listed syscall, the filter skips that
entry automatically. Use the disable override above if you need to run
unsupported tooling locally.

## 5. Verification Checklist

After enabling the service:

```bash
sudo systemctl status pci-segment.service
ps -o user,group,cap_eff,cmd -C pci-segment
```

Expected results:

- The process runs as `pci-segment` (or the configured override).
- `cap_eff` contains only `cap_bpf,cap_net_admin`.
- `seccomp` should appear under `CapPrm` in `/proc/<pid>/status`, confirming the
  filter is active.
- Audit logs continue to appear under `/var/log/pci-segment/`.

If the drop fails, the CLI exits with a descriptive error pointing back to this
guide. Overrides should be removed once debugging is complete.
