//go:build linux
// +build linux

package enforcer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/msaadshabir/pci-segment/pkg/audit"
	"github.com/msaadshabir/pci-segment/pkg/policy"
)

const (
	// MaxRules is the maximum number of policy rules
	MaxRules = 1024

	// Action constants (must match C code)
	ActionAllow = 0
	ActionDeny  = 1

	// Protocol constants
	ProtoTCP  = 6
	ProtoUDP  = 17
	ProtoICMP = 1
)

// PolicyRule represents a BPF policy rule (must match C struct)
type PolicyRule struct {
	SrcIP      uint32
	SrcMask    uint32
	DstIP      uint32
	DstMask    uint32
	DstPortMin uint16
	DstPortMax uint16
	Protocol   uint8
	Action     uint8
	_          uint16 // Padding for alignment
}

// EnforcementEventBPF represents an event from the BPF program
type EnforcementEventBPF struct {
	Timestamp uint64
	SrcIP     uint32
	DstIP     uint32
	DstPort   uint16
	Protocol  uint8
	Action    uint8
	RuleID    uint32
}

// EBPFEnforcerV2 implements enforcement using Linux eBPF with cilium/ebpf
type EBPFEnforcerV2 struct {
	// BPF objects
	objs        *bpfObjects
	ingressLink link.Link
	egressLink  link.Link
	eventReader *ringbuf.Reader

	// Policies and events
	policies []policy.Policy
	events   []policy.EnforcementEvent // Kept for backward compatibility
	running  bool
	mu       sync.RWMutex

	// Audit logger (persistent storage)
	auditLogger audit.Logger

	// Network interface
	ifaceName string

	// Event processing
	stopEventLoop chan struct{}
	wg            sync.WaitGroup
}

// bpfObjects contains all BPF maps and programs
type bpfObjects struct {
	// Programs
	IngressProg *ebpf.Program `ebpf:"pci_segment_ingress"`
	EgressProg  *ebpf.Program `ebpf:"pci_segment_egress"`

	// Maps
	IngressRules *ebpf.Map `ebpf:"ingress_rules"`
	EgressRules  *ebpf.Map `ebpf:"egress_rules"`
	Events       *ebpf.Map `ebpf:"events"`
	Stats        *ebpf.Map `ebpf:"stats"`
}

// NewEBPFEnforcerV2 creates a new production-ready eBPF enforcer
func NewEBPFEnforcerV2(interfaceName string) (*EBPFEnforcerV2, error) {
	if interfaceName == "" {
		interfaceName = "eth0" // Default interface
	}

	// Initialize audit logger with PCI-DSS compliant defaults
	auditCfg := audit.DefaultConfig()
	auditLogger, err := audit.NewLogger(auditCfg)
	if err != nil {
		// Fall back to in-memory only if audit logger fails
		fmt.Fprintf(os.Stderr, "WARNING: Failed to initialize audit logger: %v\n", err)
		fmt.Fprintf(os.Stderr, "WARNING: Audit events will be stored in memory only\n")
		auditLogger = nil
	}

	return &EBPFEnforcerV2{
		policies:      make([]policy.Policy, 0),
		events:        make([]policy.EnforcementEvent, 0, 10000),
		auditLogger:   auditLogger,
		running:       false,
		ifaceName:     interfaceName,
		stopEventLoop: make(chan struct{}),
	}, nil
}

// Start begins enforcement of policies
func (e *EBPFEnforcerV2) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return fmt.Errorf("enforcer already running")
	}

	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("eBPF enforcement requires root privileges")
	}

	// Load BPF object file
	spec, err := ebpf.LoadCollectionSpec("pkg/enforcer/bpf/pci_segment.o")
	if err != nil {
		return fmt.Errorf("failed to load BPF spec: %w", err)
	}

	// Create collection
	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("failed to load BPF objects: %w", err)
	}
	e.objs = &objs

	// Attach XDP program to interface for ingress
	iface, err := net.InterfaceByName(e.ifaceName)
	if err != nil {
		_ = objs.IngressProg.Close()
		_ = objs.EgressProg.Close()
		_ = objs.IngressRules.Close()
		_ = objs.EgressRules.Close()
		_ = objs.Events.Close()
		_ = objs.Stats.Close()
		return fmt.Errorf("failed to find interface %s: %w", e.ifaceName, err)
	}

	e.ingressLink, err = link.AttachXDP(link.XDPOptions{
		Program:   objs.IngressProg,
		Interface: iface.Index,
	})
	if err != nil {
		_ = objs.IngressProg.Close()
		_ = objs.EgressProg.Close()
		_ = objs.IngressRules.Close()
		_ = objs.EgressRules.Close()
		_ = objs.Events.Close()
		_ = objs.Stats.Close()
		return fmt.Errorf("failed to attach XDP program: %w", err)
	}

	// Attach TC program for egress (would require tc qdisc setup in production)
	// For now, we'll skip egress enforcement and log a warning
	fmt.Printf("Warning: Egress enforcement not yet attached (requires TC qdisc setup)\n")

	// Open ring buffer for events
	e.eventReader, err = ringbuf.NewReader(objs.Events)
	if err != nil {
		_ = e.ingressLink.Close()
		_ = objs.IngressProg.Close()
		_ = objs.EgressProg.Close()
		_ = objs.IngressRules.Close()
		_ = objs.EgressRules.Close()
		_ = objs.Events.Close()
		_ = objs.Stats.Close()
		return fmt.Errorf("failed to open event ring buffer: %w", err)
	}

	// Start event processing goroutine
	e.wg.Add(1)
	go e.processEvents()

	e.running = true
	fmt.Printf("eBPF enforcer started on interface %s\n", e.ifaceName)
	return nil
}

// Stop stops enforcement
func (e *EBPFEnforcerV2) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return nil
	}

	// Stop event processing
	close(e.stopEventLoop)
	e.wg.Wait()

	// Close ring buffer reader
	if e.eventReader != nil {
		_ = e.eventReader.Close() // Best effort cleanup
	}

	// Detach programs
	if e.ingressLink != nil {
		_ = e.ingressLink.Close() // Best effort cleanup
	}
	if e.egressLink != nil {
		_ = e.egressLink.Close() // Best effort cleanup
	}

	// Close BPF objects
	if e.objs != nil {
		_ = e.objs.IngressProg.Close()  // Best effort cleanup
		_ = e.objs.EgressProg.Close()   // Best effort cleanup
		_ = e.objs.IngressRules.Close() // Best effort cleanup
		_ = e.objs.EgressRules.Close()  // Best effort cleanup
		_ = e.objs.Events.Close()       // Best effort cleanup
		_ = e.objs.Stats.Close()        // Best effort cleanup
	}

	// Close audit logger (flush and persist)
	if e.auditLogger != nil {
		if err := e.auditLogger.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: Failed to close audit logger: %v\n", err)
		}
	}

	e.running = false
	fmt.Println("eBPF enforcer stopped")
	return nil
}

// AddPolicy adds a policy to enforce
func (e *EBPFEnforcerV2) AddPolicy(pol *policy.Policy) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return fmt.Errorf("enforcer not running")
	}

	// Convert policy to BPF rules
	ingressRules, err := e.policyToRules(pol, true)
	if err != nil {
		return fmt.Errorf("failed to convert ingress rules: %w", err)
	}

	egressRules, err := e.policyToRules(pol, false)
	if err != nil {
		return fmt.Errorf("failed to convert egress rules: %w", err)
	}

	// Update BPF maps
	if err := e.updateRulesMap(e.objs.IngressRules, ingressRules); err != nil {
		return fmt.Errorf("failed to update ingress rules: %w", err)
	}

	if err := e.updateRulesMap(e.objs.EgressRules, egressRules); err != nil {
		return fmt.Errorf("failed to update egress rules: %w", err)
	}

	e.policies = append(e.policies, *pol)
	fmt.Printf("Added policy: %s (%d ingress rules, %d egress rules)\n",
		pol.Metadata.Name, len(ingressRules), len(egressRules))

	return nil
}

// RemovePolicy removes a policy
func (e *EBPFEnforcerV2) RemovePolicy(policyName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return fmt.Errorf("enforcer not running")
	}

	// Find and remove policy
	newPolicies := make([]policy.Policy, 0)
	found := false
	for _, p := range e.policies {
		if p.Metadata.Name != policyName {
			newPolicies = append(newPolicies, p)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("policy not found: %s", policyName)
	}

	e.policies = newPolicies

	// Rebuild all rules from remaining policies
	// In production, this should be optimized with rule IDs
	if err := e.rebuildAllRules(); err != nil {
		return fmt.Errorf("failed to rebuild rules: %w", err)
	}

	fmt.Printf("Removed policy: %s\n", policyName)
	return nil
}

// GetEvents returns enforcement events
func (e *EBPFEnforcerV2) GetEvents() []policy.EnforcementEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Return a copy
	eventsCopy := make([]policy.EnforcementEvent, len(e.events))
	copy(eventsCopy, e.events)
	return eventsCopy
}

// IsRunning returns whether enforcer is active
func (e *EBPFEnforcerV2) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.running
}

// GetStats returns enforcement statistics
func (e *EBPFEnforcerV2) GetStats() (allowed, blocked, total uint64, err error) {
	if !e.running {
		return 0, 0, 0, fmt.Errorf("enforcer not running")
	}

	var key uint32
	var value uint64

	// Get allowed packets
	key = 0
	if err := e.objs.Stats.Lookup(&key, &value); err != nil {
		return 0, 0, 0, err
	}
	allowed = value

	// Get blocked packets
	key = 1
	if err := e.objs.Stats.Lookup(&key, &value); err != nil {
		return 0, 0, 0, err
	}
	blocked = value

	// Get total packets
	key = 2
	if err := e.objs.Stats.Lookup(&key, &value); err != nil {
		return 0, 0, 0, err
	}
	total = value

	return allowed, blocked, total, nil
}

// processEvents reads events from the ring buffer
func (e *EBPFEnforcerV2) processEvents() {
	defer e.wg.Done()

	for {
		select {
		case <-e.stopEventLoop:
			return
		default:
			record, err := e.eventReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}

			// Parse event
			if len(record.RawSample) < 24 { // sizeof(EnforcementEventBPF)
				continue
			}

			var bpfEvt EnforcementEventBPF
			bpfEvt.Timestamp = binary.LittleEndian.Uint64(record.RawSample[0:8])
			bpfEvt.SrcIP = binary.LittleEndian.Uint32(record.RawSample[8:12])
			bpfEvt.DstIP = binary.LittleEndian.Uint32(record.RawSample[12:16])
			bpfEvt.DstPort = binary.LittleEndian.Uint16(record.RawSample[16:18])
			bpfEvt.Protocol = record.RawSample[18]
			bpfEvt.Action = record.RawSample[19]
			bpfEvt.RuleID = binary.LittleEndian.Uint32(record.RawSample[20:24])

			// Convert to policy.EnforcementEvent
			evt := policy.EnforcementEvent{
				Timestamp:  time.Now(), // Use current time instead of boot time
				SourceIP:   ipToString(bpfEvt.SrcIP),
				DestIP:     ipToString(bpfEvt.DstIP),
				DestPort:   int(bpfEvt.DstPort),
				Protocol:   protoToString(bpfEvt.Protocol),
				Action:     actionToString(bpfEvt.Action),
				PolicyName: e.getRulePolicyName(bpfEvt.RuleID),
				PCIDSSReq:  "Req 1.2, Req 1.3",
			}

			// Log to persistent audit storage
			if e.auditLogger != nil {
				if err := e.auditLogger.Log(evt); err != nil {
					fmt.Fprintf(os.Stderr, "ERROR: Failed to log audit event: %v\n", err)
				}
			}

			// Store event in-memory (for GetEvents compatibility)
			e.mu.Lock()
			e.events = append(e.events, evt)
			// Keep only last 10000 events
			if len(e.events) > 10000 {
				e.events = e.events[len(e.events)-10000:]
			}
			e.mu.Unlock()
		}
	}
}

// policyToRules converts a policy to BPF rules
func (e *EBPFEnforcerV2) policyToRules(pol *policy.Policy, ingress bool) ([]PolicyRule, error) {
	rules := make([]PolicyRule, 0)

	ruleSet := pol.Spec.Ingress
	if !ingress {
		ruleSet = pol.Spec.Egress
	}

	for _, rule := range ruleSet {
		// Get peers (from/to)
		peers := rule.From
		if !ingress {
			peers = rule.To
		}

		for _, peer := range peers {
			if peer.IPBlock == nil {
				continue // Skip non-IP rules for now
			}

			// Parse CIDR
			_, ipNet, err := net.ParseCIDR(peer.IPBlock.CIDR)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %s: %w", peer.IPBlock.CIDR, err)
			}

			srcIP, srcMask := uint32(0), uint32(0)
			dstIP := ipToUint32(ipNet.IP)
			dstMask := ipToUint32(net.IP(ipNet.Mask))

			// For each port in the rule
			if len(rule.Ports) == 0 {
				// No ports specified = any port
				bpfRule := PolicyRule{
					SrcIP:      srcIP,
					SrcMask:    srcMask,
					DstIP:      dstIP,
					DstMask:    dstMask,
					DstPortMin: 0,
					DstPortMax: 0,
					Protocol:   0, // Any protocol
					Action:     ActionAllow,
				}
				rules = append(rules, bpfRule)
			} else {
				for _, port := range rule.Ports {
					// Port validation is done by policy engine (0-65535 check)
					// Safe conversion to uint16
					if port.Port < 0 || port.Port > 65535 {
						continue // Skip invalid ports (shouldn't happen due to validation)
					}
					proto := protoStringToInt(port.Protocol)
					bpfRule := PolicyRule{
						SrcIP:      srcIP,
						SrcMask:    srcMask,
						DstIP:      dstIP,
						DstMask:    dstMask,
						DstPortMin: uint16(port.Port), // #nosec G115 - validated above
						DstPortMax: uint16(port.Port), // #nosec G115 - validated above
						Protocol:   proto,
						Action:     ActionAllow,
					}
					rules = append(rules, bpfRule)
				}
			}
		}
	}

	return rules, nil
}

// updateRulesMap updates a BPF map with rules
func (e *EBPFEnforcerV2) updateRulesMap(m *ebpf.Map, rules []PolicyRule) error {
	// Clear existing rules by writing empty rules
	var emptyRule PolicyRule
	for i := uint32(0); i < MaxRules; i++ {
		if err := m.Update(&i, &emptyRule, ebpf.UpdateAny); err != nil {
			return err
		}
	}

	// Write new rules
	for i, rule := range rules {
		if i >= MaxRules {
			return fmt.Errorf("too many rules (max %d)", MaxRules)
		}
		key := uint32(i) // #nosec G115 - checked against MaxRules (1024) above
		if err := m.Update(&key, &rule, ebpf.UpdateAny); err != nil {
			return err
		}
	}

	return nil
}

// rebuildAllRules rebuilds all BPF rules from current policies
func (e *EBPFEnforcerV2) rebuildAllRules() error {
	allIngressRules := make([]PolicyRule, 0)
	allEgressRules := make([]PolicyRule, 0)

	for _, pol := range e.policies {
		ingressRules, err := e.policyToRules(&pol, true)
		if err != nil {
			return err
		}
		allIngressRules = append(allIngressRules, ingressRules...)

		egressRules, err := e.policyToRules(&pol, false)
		if err != nil {
			return err
		}
		allEgressRules = append(allEgressRules, egressRules...)
	}

	if err := e.updateRulesMap(e.objs.IngressRules, allIngressRules); err != nil {
		return err
	}

	if err := e.updateRulesMap(e.objs.EgressRules, allEgressRules); err != nil {
		return err
	}

	return nil
}

// getRulePolicyName gets the policy name for a rule ID
func (e *EBPFEnforcerV2) getRulePolicyName(_ uint32) string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Simplified: just return first policy name
	if len(e.policies) > 0 {
		return e.policies[0].Metadata.Name
	}
	return "unknown"
}

// Helper functions

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	// Use little-endian to match BPF byte order expectations
	return uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
}

func ipToString(ip uint32) string {
	// Convert from little-endian uint32 back to IP string
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func protoToString(proto uint8) string {
	switch proto {
	case ProtoTCP:
		return "TCP"
	case ProtoUDP:
		return "UDP"
	case ProtoICMP:
		return "ICMP"
	default:
		return fmt.Sprintf("proto-%d", proto)
	}
}

func actionToString(action uint8) string {
	if action == ActionAllow {
		return "ALLOWED"
	}
	return "BLOCKED"
}

func protoStringToInt(proto string) uint8 {
	switch proto {
	case "TCP":
		return ProtoTCP
	case "UDP":
		return ProtoUDP
	case "ICMP":
		return ProtoICMP
	default:
		return 0 // Any protocol
	}
}
