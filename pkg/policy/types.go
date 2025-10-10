package policy

import "time"

// Policy represents a PCI-DSS network policy
type Policy struct {
	APIVersion string   `yaml:"apiVersion" json:"apiVersion"`
	Kind       string   `yaml:"kind" json:"kind"`
	Metadata   Metadata `yaml:"metadata" json:"metadata"`
	Spec       Spec     `yaml:"spec" json:"spec"`
}

// Metadata contains policy metadata including PCI-DSS annotations
type Metadata struct {
	Name        string            `yaml:"name" json:"name"`
	Annotations map[string]string `yaml:"annotations,omitempty" json:"annotations,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// Spec defines the network policy specification
type Spec struct {
	PodSelector PodSelector `yaml:"podSelector,omitempty" json:"podSelector,omitempty"`
	Ingress     []Rule      `yaml:"ingress,omitempty" json:"ingress,omitempty"`
	Egress      []Rule      `yaml:"egress,omitempty" json:"egress,omitempty"`
}

// PodSelector matches workloads by labels
type PodSelector struct {
	MatchLabels map[string]string `yaml:"matchLabels,omitempty" json:"matchLabels,omitempty"`
}

// Rule represents ingress/egress rules
type Rule struct {
	From  []Peer `yaml:"from,omitempty" json:"from,omitempty"`
	To    []Peer `yaml:"to,omitempty" json:"to,omitempty"`
	Ports []Port `yaml:"ports,omitempty" json:"ports,omitempty"`
}

// Peer represents a network peer
type Peer struct {
	IPBlock           *IPBlock     `yaml:"ipBlock,omitempty" json:"ipBlock,omitempty"`
	PodSelector       *PodSelector `yaml:"podSelector,omitempty" json:"podSelector,omitempty"`
	NamespaceSelector *PodSelector `yaml:"namespaceSelector,omitempty" json:"namespaceSelector,omitempty"`
}

// IPBlock represents an IP CIDR range
type IPBlock struct {
	CIDR   string   `yaml:"cidr" json:"cidr"`
	Except []string `yaml:"except,omitempty" json:"except,omitempty"`
}

// Port represents a network port
type Port struct {
	Protocol string `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	Port     int    `yaml:"port" json:"port"`
}

// ValidationResult represents policy validation outcome
type ValidationResult struct {
	Valid           bool     `json:"valid"`
	Errors          []string `json:"errors,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
	PCIRequirements []string `json:"pci_requirements,omitempty"`
}

// EnforcementEvent represents a single enforcement action
type EnforcementEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	SourceIP   string    `json:"source_ip"`
	DestIP     string    `json:"dest_ip"`
	DestPort   int       `json:"dest_port"`
	Protocol   string    `json:"protocol"`
	Action     string    `json:"action"` // ALLOWED, BLOCKED
	PolicyName string    `json:"policy_name"`
	PCIDSSReq  string    `json:"pci_dss_req,omitempty"`
}
