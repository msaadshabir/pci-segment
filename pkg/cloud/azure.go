package cloud

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/msaadshabir/pci-segment/pkg/policy"
)

// AzureIntegrator implements CloudIntegrator for Azure
type AzureIntegrator struct {
	client *armnetwork.SecurityGroupsClient
	config *Config
	ctx    context.Context
}

// NewAzureIntegrator creates a new Azure cloud integrator
func NewAzureIntegrator(cfg *Config) (*AzureIntegrator, error) {
	if cfg.AzureConfig == nil {
		return nil, fmt.Errorf("Azure configuration is required")
	}

	ctx := context.Background()

	// Create credential
	var cred *azidentity.ClientSecretCredential
	var err error

	if cfg.AzureConfig.ClientID != "" && cfg.AzureConfig.ClientSecret != "" && cfg.AzureConfig.TenantID != "" {
		cred, err = azidentity.NewClientSecretCredential(
			cfg.AzureConfig.TenantID,
			cfg.AzureConfig.ClientID,
			cfg.AzureConfig.ClientSecret,
			nil,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create Azure credentials: %w", err)
		}
	} else {
		return nil, fmt.Errorf("Azure ClientID, ClientSecret, and TenantID are required")
	}

	// Create NSG client
	client, err := armnetwork.NewSecurityGroupsClient(cfg.AzureConfig.SubscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure NSG client: %w", err)
	}

	return &AzureIntegrator{
		client: client,
		config: cfg,
		ctx:    ctx,
	}, nil
}

// Sync applies PCI-DSS policies to Azure Network Security Groups
func (a *AzureIntegrator) Sync(policies []policy.Policy) (*SyncResult, error) {
	result := &SyncResult{
		Provider:  ProviderAzure,
		Timestamp: time.Now(),
		DryRun:    a.config.DryRun,
		Changes:   make([]Change, 0),
		Errors:    make([]string, 0),
	}

	for _, pol := range policies {
		if err := a.syncPolicy(&pol, result); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("policy %s: %v", pol.Metadata.Name, err))
		}
	}

	return result, nil
}

// syncPolicy synchronizes a single policy to Azure
func (a *AzureIntegrator) syncPolicy(pol *policy.Policy, result *SyncResult) error {
	nsgName := fmt.Sprintf("pci-segment-%s", pol.Metadata.Name)

	resourceGroups := a.config.AzureConfig.ResourceGroups
	if len(resourceGroups) == 0 {
		return fmt.Errorf("at least one resource group must be specified")
	}

	for _, rgName := range resourceGroups {
		if err := a.syncNetworkSecurityGroup(rgName, nsgName, pol, result); err != nil {
			return err
		}
	}

	return nil
}

// syncNetworkSecurityGroup creates or updates an NSG
func (a *AzureIntegrator) syncNetworkSecurityGroup(resourceGroup, nsgName string, pol *policy.Policy, result *SyncResult) error {
	// Check if NSG exists
	existing, err := a.client.Get(a.ctx, resourceGroup, nsgName, nil)
	exists := err == nil

	// Build NSG properties
	nsgProps := armnetwork.SecurityGroup{
		Location: to.Ptr(a.config.Region),
		Tags:     a.buildTags(pol),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{
			SecurityRules: a.buildSecurityRules(pol),
		},
	}

	if !a.config.DryRun {
		poller, err := a.client.BeginCreateOrUpdate(a.ctx, resourceGroup, nsgName, nsgProps, nil)
		if err != nil {
			return fmt.Errorf("failed to create/update NSG: %w", err)
		}

		_, err = poller.PollUntilDone(a.ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to complete NSG operation: %w", err)
		}
	}

	if exists {
		result.Changes = append(result.Changes, Change{
			ResourceID:   *existing.ID,
			ResourceName: nsgName,
			Operation:    "update",
			Details:      fmt.Sprintf("Updated NSG in resource group %s", resourceGroup),
			Success:      true,
		})
		result.ResourcesUpdated++
	} else {
		result.Changes = append(result.Changes, Change{
			ResourceName: nsgName,
			Operation:    "create",
			Details:      fmt.Sprintf("Created NSG in resource group %s", resourceGroup),
			Success:      true,
		})
		result.ResourcesAdded++
	}

	return nil
}

// buildSecurityRules converts PCI-DSS policy rules to Azure NSG rules
func (a *AzureIntegrator) buildSecurityRules(pol *policy.Policy) []*armnetwork.SecurityRule {
	rules := make([]*armnetwork.SecurityRule, 0)
	priority := int32(100)

	// Add ingress rules
	for i, rule := range pol.Spec.Ingress {
		for j, port := range rule.Ports {
			for k, peer := range rule.From {
				if peer.IPBlock != nil {
					ruleName := fmt.Sprintf("ingress-%d-%d-%d", i, j, k)
					rules = append(rules, &armnetwork.SecurityRule{
						Name: to.Ptr(ruleName),
						Properties: &armnetwork.SecurityRulePropertiesFormat{
							Priority:                 to.Ptr(priority),
							Direction:                to.Ptr(armnetwork.SecurityRuleDirectionInbound),
							Access:                   to.Ptr(armnetwork.SecurityRuleAccessAllow),
							Protocol:                 a.convertProtocol(port.Protocol),
							SourcePortRange:          to.Ptr("*"),
							DestinationPortRange:     to.Ptr(fmt.Sprintf("%d", port.Port)),
							SourceAddressPrefix:      to.Ptr(peer.IPBlock.CIDR),
							DestinationAddressPrefix: to.Ptr("*"),
							Description:              to.Ptr("PCI-DSS Policy Ingress"),
						},
					})
					priority++
				}
			}
		}
	}

	// Add egress rules
	for i, rule := range pol.Spec.Egress {
		for j, port := range rule.Ports {
			for k, peer := range rule.To {
				if peer.IPBlock != nil {
					ruleName := fmt.Sprintf("egress-%d-%d-%d", i, j, k)
					rules = append(rules, &armnetwork.SecurityRule{
						Name: to.Ptr(ruleName),
						Properties: &armnetwork.SecurityRulePropertiesFormat{
							Priority:                 to.Ptr(priority),
							Direction:                to.Ptr(armnetwork.SecurityRuleDirectionOutbound),
							Access:                   to.Ptr(armnetwork.SecurityRuleAccessAllow),
							Protocol:                 a.convertProtocol(port.Protocol),
							SourcePortRange:          to.Ptr("*"),
							DestinationPortRange:     to.Ptr(fmt.Sprintf("%d", port.Port)),
							SourceAddressPrefix:      to.Ptr("*"),
							DestinationAddressPrefix: to.Ptr(peer.IPBlock.CIDR),
							Description:              to.Ptr("PCI-DSS Policy Egress"),
						},
					})
					priority++
				}
			}
		}
	}

	// Add default deny rule (lowest priority)
	rules = append(rules, &armnetwork.SecurityRule{
		Name: to.Ptr("default-deny-all"),
		Properties: &armnetwork.SecurityRulePropertiesFormat{
			Priority:                 to.Ptr(int32(4096)),
			Direction:                to.Ptr(armnetwork.SecurityRuleDirectionInbound),
			Access:                   to.Ptr(armnetwork.SecurityRuleAccessDeny),
			Protocol:                 to.Ptr(armnetwork.SecurityRuleProtocolAsterisk),
			SourcePortRange:          to.Ptr("*"),
			DestinationPortRange:     to.Ptr("*"),
			SourceAddressPrefix:      to.Ptr("*"),
			DestinationAddressPrefix: to.Ptr("*"),
			Description:              to.Ptr("PCI-DSS Default Deny (Req 1.3)"),
		},
	})

	return rules
}

// convertProtocol converts policy protocol to Azure protocol
func (a *AzureIntegrator) convertProtocol(protocol string) *armnetwork.SecurityRuleProtocol {
	switch strings.ToLower(protocol) {
	case "tcp":
		return to.Ptr(armnetwork.SecurityRuleProtocolTCP)
	case "udp":
		return to.Ptr(armnetwork.SecurityRuleProtocolUDP)
	case "icmp":
		return to.Ptr(armnetwork.SecurityRuleProtocolIcmp)
	default:
		return to.Ptr(armnetwork.SecurityRuleProtocolAsterisk)
	}
}

// buildTags creates Azure tags from policy metadata
func (a *AzureIntegrator) buildTags(pol *policy.Policy) map[string]*string {
	tags := map[string]*string{
		"pci-segment-managed": to.Ptr("true"),
		"pci-segment-policy":  to.Ptr(pol.Metadata.Name),
	}

	if pciReq, ok := pol.Metadata.Annotations["pci-dss"]; ok {
		tags["pci-dss"] = to.Ptr(pciReq)
	}

	// Add custom tags from config
	for k, v := range a.config.Tags {
		tags[k] = to.Ptr(v)
	}

	return tags
}

// Validate checks if Azure resources comply with policies
func (a *AzureIntegrator) Validate(policies []policy.Policy) (*ValidationReport, error) {
	report := &ValidationReport{
		Provider:   ProviderAzure,
		Timestamp:  time.Now(),
		Compliant:  true,
		Violations: make([]Violation, 0),
		Warnings:   make([]string, 0),
	}

	resourceGroups := a.config.AzureConfig.ResourceGroups
	for _, rgName := range resourceGroups {
		pager := a.client.NewListPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(a.ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list NSGs: %w", err)
			}

			for _, nsg := range page.Value {
				report.Resources++
				violations := a.validateNetworkSecurityGroup(nsg, policies)
				if len(violations) > 0 {
					report.Compliant = false
					report.Violations = append(report.Violations, violations...)
				}
			}
		}
	}

	return report, nil
}

// validateNetworkSecurityGroup checks an NSG for policy violations
func (a *AzureIntegrator) validateNetworkSecurityGroup(nsg *armnetwork.SecurityGroup, policies []policy.Policy) []Violation {
	violations := make([]Violation, 0)

	// Only validate NSGs managed by pci-segment
	if nsg.Tags == nil || nsg.Tags["pci-segment-managed"] == nil {
		return violations
	}

	// Check for wildcard access (0.0.0.0/0 or *)
	if nsg.Properties != nil && nsg.Properties.SecurityRules != nil {
		for _, rule := range nsg.Properties.SecurityRules {
			if rule.Properties == nil {
				continue
			}

			// Check for overly permissive source
			if rule.Properties.SourceAddressPrefix != nil &&
				(*rule.Properties.SourceAddressPrefix == "*" || *rule.Properties.SourceAddressPrefix == "0.0.0.0/0") &&
				rule.Properties.Access != nil && *rule.Properties.Access == armnetwork.SecurityRuleAccessAllow {

				violations = append(violations, Violation{
					ResourceID:   *nsg.ID,
					ResourceName: *nsg.Name,
					PolicyName:   "wildcard-check",
					Severity:     "critical",
					Description:  fmt.Sprintf("NSG rule '%s' allows access from any source (violates PCI-DSS Req 1.3)", *rule.Name),
					Remediation:  "Modify rule to specify exact source IP ranges",
				})
			}
		}
	}

	return violations
}

// GetResources retrieves all Azure network security resources
func (a *AzureIntegrator) GetResources() ([]SecurityResource, error) {
	resources := make([]SecurityResource, 0)

	resourceGroups := a.config.AzureConfig.ResourceGroups
	for _, rgName := range resourceGroups {
		pager := a.client.NewListPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(a.ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list NSGs: %w", err)
			}

			for _, nsg := range page.Value {
				// Only include NSGs managed by pci-segment
				if nsg.Tags == nil || nsg.Tags["pci-segment-managed"] == nil {
					continue
				}

				resource := SecurityResource{
					ID:       *nsg.ID,
					Name:     *nsg.Name,
					Type:     "nsg",
					Provider: ProviderAzure,
					Rules:    make([]SecurityRule, 0),
					Tags:     make(map[string]string),
				}

				// Convert tags
				for k, v := range nsg.Tags {
					if v != nil {
						resource.Tags[k] = *v
					}
				}

				// Convert security rules
				if nsg.Properties != nil && nsg.Properties.SecurityRules != nil {
					for _, rule := range nsg.Properties.SecurityRules {
						if rule.Properties == nil {
							continue
						}

						sr := SecurityRule{
							ID:       *rule.ID,
							Protocol: string(*rule.Properties.Protocol),
							Action:   strings.ToLower(string(*rule.Properties.Access)),
						}

						if rule.Properties.Direction != nil {
							sr.Direction = strings.ToLower(string(*rule.Properties.Direction))
						}

						if rule.Properties.SourceAddressPrefix != nil {
							sr.CIDRBlocks = []string{*rule.Properties.SourceAddressPrefix}
						}

						if rule.Properties.Description != nil {
							sr.Description = *rule.Properties.Description
						}

						resource.Rules = append(resource.Rules, sr)
					}
				}

				resources = append(resources, resource)
			}
		}
	}

	return resources, nil
}

// Close cleans up Azure client resources
func (a *AzureIntegrator) Close() error {
	// Azure SDK doesn't require explicit cleanup
	return nil
}
