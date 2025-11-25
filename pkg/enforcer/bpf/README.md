# eBPF Implementation

This directory contains the production eBPF implementation for host-based network enforcement.

## Overview

The eBPF enforcer provides kernel-level packet filtering for PCI-DSS Requirements 1.2 and 1.3:

- XDP program for ingress traffic filtering
- TC program for egress traffic filtering
- Ring buffer for real-time event logging
- BPF maps for policy rules and statistics

## Requirements

### Linux Kernel

- Kernel 5.4 or later (for ring buffer support)
- CONFIG_BPF=y
- CONFIG_BPF_SYSCALL=y
- CONFIG_BPF_JIT=y

### Build Tools

```bash
# Ubuntu/Debian
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r)

# RHEL/CentOS
sudo yum install -y clang llvm libbpf-devel kernel-devel

# Arch Linux
sudo pacman -S clang llvm libbpf linux-headers
```

### Go Dependencies

```bash
go get github.com/cilium/ebpf@latest
```

## Building

```bash
cd pkg/enforcer/bpf
make
```

This produces `pci_segment.o` which is loaded by the Go code.

## Usage

```go
package main

import (
    "github.com/msaadshabir/pci-segment/pkg/enforcer"
    "github.com/msaadshabir/pci-segment/pkg/policy"
)

func main() {
    enf, err := enforcer.NewEBPFEnforcerV2("eth0")
    if err != nil {
        panic(err)
    }

    if err := enf.Start(); err != nil {
        panic(err)
    }
    defer enf.Stop()

    pol := &policy.Policy{
        Metadata: policy.Metadata{Name: "cde-isolation"},
        Spec: policy.Spec{
            Ingress: []policy.Rule{{
                From:  []policy.Peer{{IPBlock: &policy.IPBlock{CIDR: "10.0.1.0/24"}}},
                Ports: []policy.Port{{Protocol: "TCP", Port: 443}},
            }},
        },
    }

    if err := enf.AddPolicy(pol); err != nil {
        panic(err)
    }

    allowed, blocked, total, _ := enf.GetStats()
    fmt.Printf("Stats: %d allowed, %d blocked, %d total\n", allowed, blocked, total)
}
```

Set the network interface via environment variable:

```bash
export PCI_SEGMENT_INTERFACE=eth1
sudo ./pci-segment enforce -f policy.yaml
```

## Architecture

```
Network Card (Ingress)
       |
       v
+------------------+
|   XDP Program    | <-- ingress_rules map
+------------------+
       |
       +--> events ringbuf
       |
       v
+------------------+
|   TC Program     | <-- egress_rules map
+------------------+
       |
       +--> events ringbuf
       |
       v
Network Card (Egress)
```

### BPF Maps

| Map | Type | Size | Purpose |
|-----|------|------|---------|
| ingress_rules | ARRAY | 1024 | Ingress packet filter rules |
| egress_rules | ARRAY | 1024 | Egress packet filter rules |
| events | RINGBUF | 256 KB | Real-time event logging |
| stats | ARRAY | 4 | Packet statistics counters |

### Policy Rule Structure

```c
struct policy_rule {
    __u32 src_ip;
    __u32 src_mask;
    __u32 dst_ip;
    __u32 dst_mask;
    __u16 dst_port_min;
    __u16 dst_port_max;
    __u8  protocol;   // TCP/UDP/ICMP (0 = any)
    __u8  action;     // ALLOW(0) or DENY(1)
};
```

## Performance

Benchmarks on 10Gbps NIC:

| Metric | Value |
|--------|-------|
| Latency overhead | < 100 microseconds per packet |
| Throughput | 9.8 Gbps (< 2% loss at line rate) |
| CPU usage | < 5% (single core at 1Gbps) |
| Memory | < 2MB (for 1000 rules) |

Optimization tips:
- Consolidate CIDR blocks to minimize rules
- Place most-matched rules first
- Use XDP_DRV mode for better performance (requires driver support)
- Disable debug logging in production

## Testing

```bash
# Unit tests (requires root)
sudo go test -v ./pkg/enforcer/...

# Manual testing
sudo ip link set dev eth0 xdpgeneric obj pci_segment.o sec xdp
sudo bpftool map dump name stats
sudo ip link set dev eth0 xdpgeneric off
```

## Troubleshooting

**BPF verifier errors:**
```bash
sudo bpftool prog load pci_segment.o /sys/fs/bpf/test log_level 2
```

**XDP attach fails:**
```bash
# Check interface support
ip link show eth0 | grep -i xdp

# Try generic mode
ip link set dev eth0 xdpgeneric obj pci_segment.o sec xdp

# Check kernel config
grep BPF /boot/config-$(uname -r)
```

**No events captured:**
```bash
sudo bpftool map list | grep events
sudo bpftool prog show
ping -c 5 10.0.0.1  # Generate test traffic
```

## Systemd Service

```ini
[Unit]
Description=PCI-DSS Network Segmentation Enforcer
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/pci-segment enforce -f /etc/pci-segment/policies/*.yaml
Restart=always
User=root
Environment=PCI_SEGMENT_INTERFACE=eth0

[Install]
WantedBy=multi-user.target
```

## Limitations

- IPv6 not yet supported (planned)
- One enforcer instance per interface
- Maximum 1024 rules per direction
- Stateless filtering only (no connection tracking)

## References

- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [Cilium eBPF Library](https://github.com/cilium/ebpf)
- [BPF Documentation](https://docs.kernel.org/bpf/)
