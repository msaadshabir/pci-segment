# Privilege Hardening Guide

The enforcement path requires `CAP_BPF` and `CAP_NET_ADMIN` to attach the eBPF
program. By default the CLI drops root privileges and continues as the
`pci-segment` service account while retaining only those two capabilities.

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

## 2. Grant Capability-Bearing Wrapper (Systemd Example)

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
- `--allow-root`: per-invocation override from the CLI.

Use overrides only for local testing. Production deployments **must** keep the
defaults to satisfy PCI-DSS Requirement 2.2.4.

## 4. Verification Checklist

After enabling the service:

```bash
sudo systemctl status pci-segment.service
ps -o user,group,cap_eff,cmd -C pci-segment
```

Expected results:

- The process runs as `pci-segment` (or the configured override).
- `cap_eff` contains only `cap_bpf,cap_net_admin`.
- Audit logs continue to appear under `/var/log/pci-segment/`.

If the drop fails, the CLI exits with a descriptive error pointing back to this
guide. Overrides should be removed once debugging is complete.
