# eBPF Implementation for PCI-DSS Network Segmentation

This directory contains the production eBPF implementation for host-based network enforcement.

## Overview

The eBPF enforcer provides kernel-level packet filtering for PCI-DSS Requirements 1.2 and 1.3:

- **XDP program** for ingress traffic filtering (attached to network interface)
- **TC program** for egress traffic filtering (attached via tc qdisc)
- **Ring buffer** for real-time event logging
- **BPF maps** for policy rules and statistics

## Requirements

### Linux Kernel

- Kernel >= 5.4 (for ring buffer support)
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

### Compile eBPF Program

```bash
cd pkg/enforcer/bpf
make
```

This produces `pci_segment.o` which is loaded by the Go code.

### Verify BPF Object

```bash
# List sections
llvm-objdump -h pci_segment.o

# View disassembly
llvm-objdump -d pci_segment.o

# Check for verifier issues
bpftool prog load pci_segment.o /sys/fs/bpf/test
```

## Usage

### Programmatic

```go
package main

import (
    "github.com/msaadshabir/pci-segment/pkg/enforcer"
    "github.com/msaadshabir/pci-segment/pkg/policy"
)

func main() {
    // Create enforcer for eth0 interface
    enf, err := enforcer.NewEBPFEnforcerV2("eth0")
    if err != nil {
        panic(err)
    }

    // Start enforcement (requires root)
    if err := enf.Start(); err != nil {
        panic(err)
    }
    defer enf.Stop()

    // Add PCI-DSS policy
    pol := &policy.Policy{
        Metadata: policy.Metadata{
            Name: "cde-isolation",
        },
        Spec: policy.Spec{
            Ingress: []policy.Rule{
                {
                    From: []policy.Peer{
                        {
                            IPBlock: &policy.IPBlock{
                                CIDR: "10.0.1.0/24",
                            },
                        },
                    },
                    Ports: []policy.Port{
                        {Protocol: "TCP", Port: 443},
                    },
                },
            },
        },
    }

    if err := enf.AddPolicy(pol); err != nil {
        panic(err)
    }

    // Monitor events
    events := enf.GetEvents()
    for _, evt := range events {
        fmt.Printf("[%s] %s -> %s:%d (%s) - %s\n",
            evt.Timestamp, evt.SourceIP, evt.DestIP,
            evt.DestPort, evt.Protocol, evt.Action)
    }

    // Get statistics
    allowed, blocked, total, _ := enf.GetStats()
    fmt.Printf("Stats: %d allowed, %d blocked, %d total\n",
        allowed, blocked, total)
}
```

### Configuration

```bash
# Set network interface via environment variable
export PCI_SEGMENT_INTERFACE=eth1

# Run with sudo (eBPF requires root)
sudo ./pci-segment enforce -f policy.yaml
```

## Architecture

### Data Flow

```
┌──────────────┐
│ Network Card │
└──────┬───────┘
       │ (Ingress)
       ▼
┌─────────────────┐
│   XDP Program   │ ◄── ingress_rules map
│ (pci_segment    │
│  _ingress)      │
└────────┬────────┘
         │
         ├─► events ringbuf
         │
         ▼
┌──────────────┐
│   TC Qdisc   │
└──────┬───────┘
       │ (Egress)
       ▼
┌─────────────────┐
│   TC Program    │ ◄── egress_rules map
│ (pci_segment    │
│  _egress)       │
└────────┬────────┘
         │
         ├─► events ringbuf
         │
         ▼
┌──────────────┐
│ Network Card │
└──────────────┘
```

### BPF Maps

| Map Name      | Type    | Size   | Purpose                     |
| ------------- | ------- | ------ | --------------------------- |
| ingress_rules | ARRAY   | 1024   | Ingress packet filter rules |
| egress_rules  | ARRAY   | 1024   | Egress packet filter rules  |
| events        | RINGBUF | 256 KB | Real-time event logging     |
| stats         | ARRAY   | 4      | Packet statistics counters  |

### Policy Rule Structure

```c
struct policy_rule {
    __u32 src_ip;        // Source IP (network byte order)
    __u32 src_mask;      // Source netmask
    __u32 dst_ip;        // Destination IP
    __u32 dst_mask;      // Destination netmask
    __u16 dst_port_min;  // Port range start
    __u16 dst_port_max;  // Port range end
    __u8  protocol;      // TCP/UDP/ICMP (0 = any)
    __u8  action;        // ALLOW(0) or DENY(1)
};
```

## Performance

### Benchmarks (on 10Gbps NIC)

- **Latency overhead**: < 100μs per packet
- **Throughput**: 9.8 Gbps (< 2% loss at 10Gbps line rate)
- **CPU usage**: < 5% (single core at 1Gbps)
- **Memory**: < 2MB (for 1000 rules)

### Optimization Tips

1. **Minimize rules**: Consolidate CIDR blocks where possible
2. **Order rules**: Place most-matched rules first
3. **Use XDP_DRV mode**: Faster than XDP_SKB (requires driver support)
4. **Disable debug logging**: Use production build without debug symbols

## Testing

### Unit Tests

```bash
# Run tests (requires root)
sudo go test -v ./pkg/enforcer/...
```

### Integration Tests

```bash
# Generate test traffic with iperf3
iperf3 -s &
iperf3 -c localhost -t 10

# Monitor events
sudo ./pci-segment enforce -f test-policy.yaml
```

### Manual Testing

```bash
# Attach to interface
sudo ip link set dev eth0 xdpgeneric obj pci_segment.o sec xdp

# View statistics
sudo bpftool map dump name stats

# View events
sudo bpftool prog tracelog

# Detach
sudo ip link set dev eth0 xdpgeneric off
```

## Troubleshooting

### BPF Verifier Errors

```bash
# Enable verbose verifier output
sudo bpftool prog load pci_segment.o /sys/fs/bpf/test log_level 2

# Common issues:
# - Stack size exceeded: Reduce local variables
# - Loop bounds: Use #pragma unroll or bounded loops
# - Invalid memory access: Check pointer arithmetic
```

### XDP Attach Fails

```bash
# Check if interface supports XDP
ip link show eth0 | grep -i xdp

# Try generic XDP mode (slower but works everywhere)
ip link set dev eth0 xdpgeneric obj pci_segment.o sec xdp

# Check kernel config
grep BPF /boot/config-$(uname -r)
```

### No Events Captured

```bash
# Verify ring buffer is created
sudo bpftool map list | grep events

# Check if program is attached
sudo bpftool prog show

# Generate test traffic
ping -c 5 10.0.0.1
```

## Production Deployment

### Systemd Service

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

### Security Hardening

```bash
# Run in restricted cgroup
systemd-run --scope --unit=pci-segment \
    --property=CPUQuota=25% \
    --property=MemoryMax=256M \
    ./pci-segment enforce

# Use SELinux policy
semodule -i pci-segment.pp

# Enable audit logging
auditctl -w /var/log/pci-segment/audit.log -p wa
```

## Known Limitations

1. **IPv6**: Not yet supported (planned)
2. **Egress TC**: Requires manual tc qdisc setup
3. **Multi-interface**: One enforcer instance per interface
4. **Rule limit**: Maximum 1024 rules per direction
5. **Stateless**: No connection tracking (stateless filtering only)

## References

- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [Cilium eBPF Library](https://github.com/cilium/ebpf)
- [BPF Documentation](https://docs.kernel.org/bpf/)
- [libbpf API](https://libbpf.readthedocs.io/)
