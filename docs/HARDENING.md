# Privilege and Syscall Hardening

The enforcement path needs `CAP_BPF` and `CAP_NET_ADMIN` for eBPF attach. The binary starts with elevated privileges only long enough to load programs, then drops to the `pci-segment` service account, retaining a minimal capability set and enabling a seccomp-bpf denylist of risky syscalls.

## Security Layers

| Layer        | Technology          | Purpose                                        |
| ------------ | ------------------- | ---------------------------------------------- |
| DAC          | Unix user/group     | Run as `pci-segment` service account           |
| Capabilities | Linux capabilities  | Retain only `CAP_BPF` + `CAP_NET_ADMIN`        |
| Seccomp      | seccomp-bpf         | Block dangerous syscalls (ptrace, mount, etc.) |
| MAC          | SELinux or AppArmor | Confine file/network access to policy          |

## Create the Service Account

Run once per host:

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

## Systemd Service

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

The binary relinquishes root and continues as `pci-segment` after attaching the programs. The unit only keeps the minimum capability set alive for startup.

## Development Overrides

| Variable/Flag                       | Purpose                                      |
| ----------------------------------- | -------------------------------------------- |
| `PCI_SEGMENT_SKIP_PRIVILEGE_DROP=1` | Skip privilege downgrade entirely            |
| `PCI_SEGMENT_PRIVILEGE_USER`        | Override target user without recompiling     |
| `PCI_SEGMENT_PRIVILEGE_GROUP`       | Override target group without recompiling    |
| `PCI_SEGMENT_DISABLE_SECCOMP=1`     | Bypass seccomp filter (local debugging only) |
| `--allow-root`                      | Per-invocation CLI override                  |

Use overrides only for local testing. Production deployments must keep the defaults to satisfy PCI-DSS Requirement 2.2.4.

## Seccomp Enforcement

After the privilege drop completes, the binary installs a seccomp-bpf filter that denies risky kernel interfaces (`ptrace`, `userfaultfd`, module loading, mount operations, etc.). The filter runs in allow-by-default mode but blocks dangerous syscalls with `EPERM`, aligning with PCI-DSS 2.2.5 guidance on restricting system functions.

If the host kernel is too old to support a listed syscall, the filter skips that entry automatically.

## Verification

After enabling the service:

```bash
sudo systemctl status pci-segment.service
ps -o user,group,cap_eff,cmd -C pci-segment
```

Expected results:

- Process runs as `pci-segment` (or the configured override)
- `cap_eff` contains only `cap_bpf,cap_net_admin`
- `seccomp` appears under `CapPrm` in `/proc/<pid>/status`
- Audit logs continue to appear under `/var/log/pci-segment/`

If the drop fails, the CLI exits with a descriptive error pointing back to this guide.

## SELinux (RHEL/Fedora/CentOS)

SELinux provides mandatory access control with type enforcement. The `pci_segment_t` domain restricts the binary to its required file and network access.

### Install SELinux Policy

```bash
# Install dependencies
sudo yum install policycoreutils-python-utils selinux-policy-devel

# Run installation script
sudo ./scripts/install-selinux.sh

# Apply context to binary
sudo restorecon -v /usr/local/bin/pci-segment
```

### Systemd with SELinux

Update the service file to transition to the confined domain:

```bash
sudo tee /etc/systemd/system/pci-segment.service >/dev/null <<'EOF'
[Unit]
Description=PCI Segment Enforcement
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/pci-segment enforce -f /etc/pci-segment/policies/*.yaml
Environment=PCI_SEGMENT_SELINUX_PROFILE=pci_segment_t
SELinuxContext=system_u:system_r:pci_segment_t:s0
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
sudo systemctl restart pci-segment.service
```

### Verify SELinux Confinement

```bash
# Check process domain
ps -eZ | grep pci-segment
# Expected: system_u:system_r:pci_segment_t:s0 ... pci-segment

# Check for denials
ausearch -m avc -ts recent | grep pci_segment
```

## AppArmor (Ubuntu/Debian)

AppArmor provides path-based mandatory access control. The `pci-segment` profile restricts file access and capabilities.

### Install AppArmor Profile

```bash
# Install dependencies
sudo apt install apparmor apparmor-utils

# Run installation script
sudo ./scripts/install-apparmor.sh
```

### Systemd with AppArmor

Update the service file to use the AppArmor profile:

```bash
sudo tee /etc/systemd/system/pci-segment.service >/dev/null <<'EOF'
[Unit]
Description=PCI Segment Enforcement
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/pci-segment enforce -f /etc/pci-segment/policies/*.yaml
Environment=PCI_SEGMENT_APPARMOR_PROFILE=pci-segment
AppArmorProfile=pci-segment
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
sudo systemctl restart pci-segment.service
```

### Verify AppArmor Confinement

```bash
# Check profile status
sudo aa-status | grep pci-segment

# Check process confinement
cat /proc/$(pgrep pci-segment)/attr/current
# Expected: pci-segment (enforce)

# Test in complain mode first (logs violations without blocking)
sudo aa-complain /etc/apparmor.d/pci-segment

# Switch to enforce mode
sudo aa-enforce /etc/apparmor.d/pci-segment
```

## MAC Environment Variables

| Variable                        | Purpose                                         |
| ------------------------------- | ----------------------------------------------- |
| `PCI_SEGMENT_SELINUX_PROFILE`   | Expected SELinux domain (e.g., `pci_segment_t`) |
| `PCI_SEGMENT_APPARMOR_PROFILE`  | Expected AppArmor profile (e.g., `pci-segment`) |
| `PCI_SEGMENT_SKIP_MAC_VERIFY=1` | Skip MAC verification (testing only)            |

When a profile is specified, the binary verifies it is running under that MAC profile after privilege drop. This provides defense-in-depth: even if an attacker bypasses the binary, the kernel enforces the MAC policy.
