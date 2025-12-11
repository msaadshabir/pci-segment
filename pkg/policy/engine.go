package policy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

// Engine handles policy parsing and validation
type Engine struct {
	policies   []Policy
	policyMap  map[string]Policy // Index for O(1) policy lookup by name (stored by value for stability)
	cidrCache  map[string]*net.IPNet // Cache for parsed CIDR blocks
}

// NewEngine creates a new policy engine
func NewEngine() *Engine {
	return &Engine{
		policies:  make([]Policy, 0),
		policyMap: make(map[string]Policy),
		cidrCache: make(map[string]*net.IPNet),
	}
}

// LoadFromFile loads a policy from a YAML file
func (e *Engine) LoadFromFile(filename string) error {
	securePath := filepath.Clean(filename)

	data, err := os.ReadFile(securePath) // #nosec G304 -- file path originates from trusted CLI flag, sanitized above
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return fmt.Errorf("failed to parse policy YAML: %w", err)
	}

	// Validate policy
	result := e.Validate(&policy)
	if !result.Valid {
		return fmt.Errorf("policy validation failed: %s", strings.Join(result.Errors, ", "))
	}

	e.policies = append(e.policies, policy)
	// Update index for fast lookup - store by value for stability
	e.policyMap[policy.Metadata.Name] = policy
	return nil
}

// Validate validates a policy against PCI-DSS requirements
func (e *Engine) Validate(policy *Policy) ValidationResult {
	result := ValidationResult{
		Valid:           true,
		Errors:          make([]string, 0),
		Warnings:        make([]string, 0),
		PCIRequirements: make([]string, 0),
	}

	// Check API version
	if policy.APIVersion != "pci-segment/v1" {
		result.Errors = append(result.Errors, "invalid apiVersion, expected 'pci-segment/v1'")
		result.Valid = false
	}

	// Check kind
	if policy.Kind != "NetworkPolicy" {
		result.Errors = append(result.Errors, "invalid kind, expected 'NetworkPolicy'")
		result.Valid = false
	}

	// Check metadata
	if policy.Metadata.Name == "" {
		result.Errors = append(result.Errors, "metadata.name is required")
		result.Valid = false
	}

	// Extract PCI-DSS requirements from annotations
	if pciReq, ok := policy.Metadata.Annotations["pci-dss"]; ok {
		result.PCIRequirements = append(result.PCIRequirements, pciReq)
	} else {
		result.Warnings = append(result.Warnings, "no pci-dss annotation found, compliance tracking unavailable")
	}

	// Validate ports in all rules
	for _, rule := range policy.Spec.Ingress {
		for _, port := range rule.Ports {
			if port.Port < 0 || port.Port > 65535 {
				result.Errors = append(result.Errors, fmt.Sprintf("invalid ingress port %d, must be between 0 and 65535", port.Port))
				result.Valid = false
			}
		}
	}
	for _, rule := range policy.Spec.Egress {
		for _, port := range rule.Ports {
			if port.Port < 0 || port.Port > 65535 {
				result.Errors = append(result.Errors, fmt.Sprintf("invalid egress port %d, must be between 0 and 65535", port.Port))
				result.Valid = false
			}
		}
	}

	// Validate CDE labeling (PCI Requirement 1.2)
	if isCDEPolicy(policy) {
		// isCDEPolicy already validates that pci-env label exists and equals 'cde'

		// Check for overly permissive rules (PCI Requirement 1.3)
		if hasWildcardAccess(policy) {
			result.Errors = append(result.Errors, "CDE policy cannot allow access from 0.0.0.0/0 (PCI-DSS Req 1.3 violation)")
			result.Valid = false
		}

		// Validate egress restrictions
		if len(policy.Spec.Egress) == 0 {
			result.Warnings = append(result.Warnings, "no egress rules defined, all outbound traffic will be blocked")
		}

		// Check for specific payment processor IPs
		if !e.hasSpecificIPs(policy) {
			result.Warnings = append(result.Warnings, "consider using specific IP ranges instead of broad CIDRs for better segmentation")
		}
	}

	return result
}

// GetPolicies returns all loaded policies
func (e *Engine) GetPolicies() []Policy {
	return e.policies
}

// GetPolicyByName returns a policy by name using O(1) map lookup
func (e *Engine) GetPolicyByName(name string) *Policy {
	if policy, ok := e.policyMap[name]; ok {
		return &policy
	}
	return nil
}

// isCDEPolicy checks if policy targets CDE environment
func isCDEPolicy(policy *Policy) bool {
	if env, ok := policy.Spec.PodSelector.MatchLabels["pci-env"]; ok {
		return env == "cde"
	}
	return false
}

// hasWildcardAccess checks for 0.0.0.0/0 access
func hasWildcardAccess(policy *Policy) bool {
	// Check ingress rules
	for _, rule := range policy.Spec.Ingress {
		for _, peer := range rule.From {
			if peer.IPBlock != nil {
				if isWildcardCIDR(peer.IPBlock.CIDR) {
					return true
				}
			}
		}
	}

	// Check egress rules
	for _, rule := range policy.Spec.Egress {
		for _, peer := range rule.To {
			if peer.IPBlock != nil {
				if isWildcardCIDR(peer.IPBlock.CIDR) {
					return true
				}
			}
		}
	}

	return false
}

// isWildcardCIDR checks if CIDR is 0.0.0.0/0 or ::/0
func isWildcardCIDR(cidr string) bool {
	return cidr == "0.0.0.0/0" || cidr == "::/0"
}

// hasSpecificIPs checks if policy uses specific IPs vs broad ranges
func (e *Engine) hasSpecificIPs(policy *Policy) bool {
	for _, rule := range policy.Spec.Egress {
		for _, peer := range rule.To {
			if peer.IPBlock != nil {
				ipNet, err := e.parseCIDR(peer.IPBlock.CIDR)
				if err != nil {
					continue
				}
				ones, bits := ipNet.Mask.Size()
				// Consider /24 or smaller as specific
				if bits == 32 && ones >= 24 {
					return true
				}
				if bits == 128 && ones >= 64 {
					return true
				}
			}
		}
	}
	return false
}

// MatchesTraffic checks if traffic matches any policy
func (e *Engine) MatchesTraffic(srcIP, dstIP string, dstPort int, protocol string) (*Policy, bool) {
	for _, policy := range e.policies {
		if matchesPolicy(&policy, srcIP, dstIP, dstPort, protocol) {
			return &policy, true
		}
	}
	return nil, false
}

// matchesPolicy checks if traffic matches a specific policy
func matchesPolicy(policy *Policy, srcIP, dstIP string, dstPort int, protocol string) bool {
	// Check egress rules
	for _, rule := range policy.Spec.Egress {
		if matchesRule(&rule, dstIP, dstPort, protocol) {
			return true
		}
	}

	// Check ingress rules
	for _, rule := range policy.Spec.Ingress {
		if matchesRule(&rule, srcIP, dstPort, protocol) {
			return true
		}
	}

	return false
}

// matchesRule checks if traffic matches a specific rule
func matchesRule(rule *Rule, ip string, port int, protocol string) bool {
	// Check IP match
	ipMatches := false
	peers := rule.To
	if len(peers) == 0 {
		peers = rule.From
	}

	for _, peer := range peers {
		if peer.IPBlock != nil {
			if ipInCIDR(ip, peer.IPBlock.CIDR) {
				ipMatches = true
				break
			}
		}
	}

	if !ipMatches {
		return false
	}

	// Check port and protocol match
	for _, p := range rule.Ports {
		if p.Port == port {
			if p.Protocol == "" || strings.EqualFold(p.Protocol, protocol) {
				return true
			}
		}
	}

	return false
}

// parseCIDR parses a CIDR with caching for performance
func (e *Engine) parseCIDR(cidr string) (*net.IPNet, error) {
	// Check cache first
	if ipNet, ok := e.cidrCache[cidr]; ok {
		return ipNet, nil
	}

	// Parse and cache
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	e.cidrCache[cidr] = ipNet
	return ipNet, nil
}

// ipInCIDR checks if IP is in CIDR range
func ipInCIDR(ipStr, cidr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	return ipNet.Contains(ip)
}
