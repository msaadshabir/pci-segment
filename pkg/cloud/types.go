// Package cloud provides cloud provider integrations for PCI-DSS policy enforcement
package cloud

import (
	"time"

	"github.com/msaadshabir/pci-segment/pkg/policy"
)

// Provider represents a cloud provider type
type Provider string

const (
	// ProviderAWS represents Amazon Web Services
	ProviderAWS Provider = "aws"
	// ProviderAzure represents Microsoft Azure
	ProviderAzure Provider = "azure"
)

// Integrator defines the interface for cloud provider integrations
type Integrator interface {
	// Sync applies policies to cloud security groups/NSGs
	Sync(policies []policy.Policy) (*SyncResult, error)

	// Validate checks if cloud resources match policies
	Validate(policies []policy.Policy) (*ValidationReport, error)

	// GetResources returns current cloud network security resources
	GetResources() ([]SecurityResource, error)

	// Close cleans up cloud provider connections
	Close() error
}

// Config holds cloud provider configuration
type Config struct {
	Provider Provider          `yaml:"provider" json:"provider"`
	Region   string            `yaml:"region" json:"region"`
	Tags     map[string]string `yaml:"tags,omitempty" json:"tags,omitempty"`
	DryRun   bool              `yaml:"dry_run" json:"dry_run"`

	// AWS-specific config
	AWSConfig *AWSConfig `yaml:"aws,omitempty" json:"aws,omitempty"`

	// Azure-specific config
	AzureConfig *AzureConfig `yaml:"azure,omitempty" json:"azure,omitempty"`
}

// AWSConfig holds AWS-specific configuration
type AWSConfig struct {
	Profile         string   `yaml:"profile,omitempty" json:"profile,omitempty"`
	AccessKeyID     string   `yaml:"access_key_id,omitempty" json:"access_key_id,omitempty"`
	SecretAccessKey string   `yaml:"secret_access_key,omitempty" json:"secret_access_key,omitempty"`
	VPCIDs          []string `yaml:"vpc_ids,omitempty" json:"vpc_ids,omitempty"`
}

// AzureConfig holds Azure-specific configuration
type AzureConfig struct {
	SubscriptionID string   `yaml:"subscription_id" json:"subscription_id"`
	TenantID       string   `yaml:"tenant_id,omitempty" json:"tenant_id,omitempty"`
	ClientID       string   `yaml:"client_id,omitempty" json:"client_id,omitempty"`
	ClientSecret   string   `yaml:"client_secret,omitempty" json:"client_secret,omitempty"` // #nosec G117 -- configuration field required for Azure client-secret auth
	ResourceGroups []string `yaml:"resource_groups,omitempty" json:"resource_groups,omitempty"`
}

// SecurityResource represents a cloud security resource
type SecurityResource struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Type     string            `json:"type"` // security-group, nsg
	Provider Provider          `json:"provider"`
	Rules    []SecurityRule    `json:"rules"`
	Tags     map[string]string `json:"tags,omitempty"`
}

// SecurityRule represents a cloud security rule
type SecurityRule struct {
	ID          string   `json:"id"`
	Direction   string   `json:"direction"` // ingress, egress
	Protocol    string   `json:"protocol"`
	FromPort    int      `json:"from_port,omitempty"`
	ToPort      int      `json:"to_port,omitempty"`
	CIDRBlocks  []string `json:"cidr_blocks,omitempty"`
	Description string   `json:"description,omitempty"`
	Action      string   `json:"action"` // allow, deny
}

// SyncResult contains the results of a cloud sync operation
type SyncResult struct {
	Provider         Provider  `json:"provider"`
	Timestamp        time.Time `json:"timestamp"`
	DryRun           bool      `json:"dry_run"`
	ResourcesAdded   int       `json:"resources_added"`
	ResourcesUpdated int       `json:"resources_updated"`
	ResourcesDeleted int       `json:"resources_deleted"`
	Changes          []Change  `json:"changes"`
	Errors           []string  `json:"errors,omitempty"`
}

// Change represents a single cloud resource change
type Change struct {
	ResourceID   string `json:"resource_id"`
	ResourceName string `json:"resource_name"`
	Operation    string `json:"operation"` // create, update, delete
	Details      string `json:"details"`
	Success      bool   `json:"success"`
	Error        string `json:"error,omitempty"`
}

// ValidationReport contains cloud resource validation results
type ValidationReport struct {
	Provider   Provider    `json:"provider"`
	Timestamp  time.Time   `json:"timestamp"`
	Compliant  bool        `json:"compliant"`
	Resources  int         `json:"resources_checked"`
	Violations []Violation `json:"violations,omitempty"`
	Warnings   []string    `json:"warnings,omitempty"`
}

// Violation represents a policy violation in cloud resources
type Violation struct {
	ResourceID   string `json:"resource_id"`
	ResourceName string `json:"resource_name"`
	PolicyName   string `json:"policy_name"`
	Severity     string `json:"severity"` // critical, high, medium, low
	Description  string `json:"description"`
	Remediation  string `json:"remediation"`
}
