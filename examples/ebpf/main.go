// Example: Using the eBPF enforcer for PCI-DSS compliance
//
// This example demonstrates how to use the production eBPF enforcer
// to enforce PCI-DSS network segmentation policies on Linux.
//
// Requirements:
// - Linux kernel >= 5.4
// - Root privileges
// - Compiled eBPF program (pkg/enforcer/bpf/pci_segment.o)
//
// Build:
//   go build -o example-ebpf examples/ebpf/main.go
//
// Run:
//   sudo ./example-ebpf

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/msaadshabir/pci-segment/pkg/enforcer"
	"github.com/msaadshabir/pci-segment/pkg/policy"
)

func main() {
	// Check if running as root
	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "Error: This program requires root privileges\n")
		fmt.Fprintf(os.Stderr, "Please run with: sudo %s\n", os.Args[0])
		os.Exit(1)
	}

	fmt.Println("PCI-DSS eBPF Enforcement Example")
	fmt.Println("=================================")
	fmt.Println()

	// Create enforcer for default interface (eth0)
	// Override with: export PCI_SEGMENT_INTERFACE=eth1
	iface := "eth0"
	if envIface := os.Getenv("PCI_SEGMENT_INTERFACE"); envIface != "" {
		iface = envIface
	}

	fmt.Printf("Creating eBPF enforcer for interface: %s\n", iface)
	enf, err := enforcer.NewEBPFEnforcerV2(iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create enforcer: %v\n", err)
		os.Exit(1)
	}

	// Start enforcement
	fmt.Println("Starting eBPF enforcement...")
	if err := enf.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start enforcer: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		fmt.Println("\nStopping enforcer...")
		enf.Stop()
	}()

	fmt.Println("Enforcer started successfully")
	fmt.Println()

	// Create PCI-DSS compliant policy for CDE isolation
	cdePolicy := &policy.Policy{
		APIVersion: "pci-segment/v1",
		Kind:       "NetworkPolicy",
		Metadata: policy.Metadata{
			Name: "cde-isolation",
			Annotations: map[string]string{
				"pci-dss":     "Req 1.2, Req 1.3",
				"description": "Isolate Cardholder Data Environment",
			},
		},
		Spec: policy.Spec{
			PodSelector: policy.PodSelector{
				MatchLabels: map[string]string{
					"pci-env": "cde",
				},
			},
			Ingress: []policy.Rule{
				{
					From: []policy.Peer{
						{
							// Allow only from application tier
							IPBlock: &policy.IPBlock{
								CIDR: "10.0.1.0/24",
							},
						},
					},
					Ports: []policy.Port{
						{
							Protocol: "TCP",
							Port:     443, // HTTPS only
						},
					},
				},
			},
			Egress: []policy.Rule{
				{
					To: []policy.Peer{
						{
							// Allow only to payment processor
							IPBlock: &policy.IPBlock{
								CIDR: "10.0.10.0/24",
							},
						},
					},
					Ports: []policy.Port{
						{
							Protocol: "TCP",
							Port:     443,
						},
					},
				},
			},
		},
	}

	// Add the policy
	fmt.Println("Adding CDE isolation policy...")
	if err := enf.AddPolicy(cdePolicy); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to add policy: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Policy added successfully")
	fmt.Println()

	// Add monitoring policy
	monitoringPolicy := &policy.Policy{
		APIVersion: "pci-segment/v1",
		Kind:       "NetworkPolicy",
		Metadata: policy.Metadata{
			Name: "allow-monitoring",
			Annotations: map[string]string{
				"pci-dss":     "Req 10.2",
				"description": "Allow monitoring from security tools",
			},
		},
		Spec: policy.Spec{
			Ingress: []policy.Rule{
				{
					From: []policy.Peer{
						{
							// Allow from monitoring subnet
							IPBlock: &policy.IPBlock{
								CIDR: "10.0.20.0/24",
							},
						},
					},
					Ports: []policy.Port{
						{
							Protocol: "TCP",
							Port:     9090, // Prometheus
						},
						{
							Protocol: "TCP",
							Port:     8080, // Health checks
						},
					},
				},
			},
		},
	}

	fmt.Println("Adding monitoring policy...")
	if err := enf.AddPolicy(monitoringPolicy); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to add monitoring policy: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Monitoring policy added successfully")
	fmt.Println()

	// Print status
	fmt.Println("Enforcement Status:")
	fmt.Println("------------------")
	fmt.Printf("Running: %v\n", enf.IsRunning())
	fmt.Printf("Interface: %s\n", iface)
	fmt.Printf("Policies: 2 (cde-isolation, allow-monitoring)\n")
	fmt.Println()

	// Monitor events in a goroutine
	stopMonitoring := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Get statistics
				allowed, blocked, total, err := enf.GetStats()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to get stats: %v\n", err)
					continue
				}

				fmt.Printf("[%s] Stats: %d total, %d allowed, %d blocked (%.1f%% blocked)\n",
					time.Now().Format("15:04:05"),
					total, allowed, blocked,
					float64(blocked)/float64(total)*100)

				// Get recent events
				events := enf.GetEvents()
				if len(events) > 0 {
					fmt.Printf("Recent events: %d\n", len(events))
					// Show last 3 events
					start := len(events) - 3
					if start < 0 {
						start = 0
					}
					for _, evt := range events[start:] {
						fmt.Printf("  [%s] %s -> %s:%d (%s) - %s\n",
							evt.Timestamp.Format("15:04:05"),
							evt.SourceIP, evt.DestIP, evt.DestPort,
							evt.Protocol, evt.Action)
					}
				}
				fmt.Println()

			case <-stopMonitoring:
				return
			}
		}
	}()

	// Wait for interrupt signal
	fmt.Println("Enforcer is running. Press Ctrl+C to stop.")
	fmt.Println("Monitoring events every 5 seconds...")
	fmt.Println()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nReceived interrupt signal")
	close(stopMonitoring)
	time.Sleep(100 * time.Millisecond)

	// Final statistics
	allowed, blocked, total, err := enf.GetStats()
	if err == nil {
		fmt.Println("\nFinal Statistics:")
		fmt.Println("-----------------")
		fmt.Printf("Total packets: %d\n", total)
		fmt.Printf("Allowed: %d (%.1f%%)\n", allowed, float64(allowed)/float64(total)*100)
		fmt.Printf("Blocked: %d (%.1f%%)\n", blocked, float64(blocked)/float64(total)*100)
	}

	events := enf.GetEvents()
	fmt.Printf("Total events captured: %d\n", len(events))

	fmt.Println("\nShutdown complete.")
}
