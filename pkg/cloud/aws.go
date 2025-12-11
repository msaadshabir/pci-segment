package cloud

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/msaadshabir/pci-segment/pkg/policy"
)

// AWSIntegrator implements CloudIntegrator for AWS
type AWSIntegrator struct {
	client *ec2.Client
	config *Config
	ctx    context.Context
}

// NewAWSIntegrator creates a new AWS cloud integrator
func NewAWSIntegrator(cfg *Config) (*AWSIntegrator, error) {
	if cfg.AWSConfig == nil {
		return nil, fmt.Errorf("AWS configuration is required")
	}

	ctx := context.Background()
	var awsCfg aws.Config
	var err error

	// Load AWS credentials
	if cfg.AWSConfig.AccessKeyID != "" && cfg.AWSConfig.SecretAccessKey != "" {
		awsCfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(cfg.Region),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				cfg.AWSConfig.AccessKeyID,
				cfg.AWSConfig.SecretAccessKey,
				"",
			)),
		)
	} else if cfg.AWSConfig.Profile != "" {
		awsCfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(cfg.Region),
			config.WithSharedConfigProfile(cfg.AWSConfig.Profile),
		)
	} else {
		// Use default credentials chain (env vars, instance profile, etc.)
		awsCfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(cfg.Region),
		)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &AWSIntegrator{
		client: ec2.New(ec2.Options{Credentials: awsCfg.Credentials, Region: cfg.Region}),
		config: cfg,
		ctx:    ctx,
	}, nil
}

// Sync applies PCI-DSS policies to AWS Security Groups
func (a *AWSIntegrator) Sync(policies []policy.Policy) (*SyncResult, error) {
	result := &SyncResult{
		Provider:  ProviderAWS,
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

// syncPolicy synchronizes a single policy to AWS
func (a *AWSIntegrator) syncPolicy(pol *policy.Policy, result *SyncResult) error {
	// Generate Security Group name from policy
	sgName := fmt.Sprintf("pci-segment-%s", pol.Metadata.Name)
	sgDescription := fmt.Sprintf("PCI-DSS Policy: %s", pol.Metadata.Annotations["pci-dss"])

	// Check if security group exists
	vpcIDs := a.config.AWSConfig.VPCIDs
	if len(vpcIDs) == 0 {
		// Get default VPC
		vpcs, err := a.client.DescribeVpcs(a.ctx, &ec2.DescribeVpcsInput{
			Filters: []types.Filter{
				{
					Name:   aws.String("isDefault"),
					Values: []string{"true"},
				},
			},
		})
		if err != nil {
			return fmt.Errorf("failed to get default VPC: %w", err)
		}
		if len(vpcs.Vpcs) > 0 {
			vpcIDs = []string{*vpcs.Vpcs[0].VpcId}
		} else {
			return fmt.Errorf("no VPC specified and no default VPC found")
		}
	}

	// Process VPCs concurrently for better performance
	if len(vpcIDs) > 1 {
		return a.syncSecurityGroupsConcurrent(vpcIDs, sgName, sgDescription, pol, result)
	}

	// Single VPC - no need for concurrency overhead
	for _, vpcID := range vpcIDs {
		if err := a.syncSecurityGroup(vpcID, sgName, sgDescription, pol, result); err != nil {
			return err
		}
	}

	return nil
}

// syncSecurityGroupsConcurrent syncs to multiple VPCs concurrently
func (a *AWSIntegrator) syncSecurityGroupsConcurrent(vpcIDs []string, sgName, sgDescription string, pol *policy.Policy, result *SyncResult) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(vpcIDs))
	var resultMu sync.Mutex

	for _, vpcID := range vpcIDs {
		wg.Add(1)
		go func(vpc string) {
			defer wg.Done()

			// Create a temporary result for this goroutine
			tempResult := &SyncResult{
				Changes: make([]Change, 0),
				Errors:  make([]string, 0),
			}

			if err := a.syncSecurityGroup(vpc, sgName, sgDescription, pol, tempResult); err != nil {
				errChan <- fmt.Errorf("VPC %s: %w", vpc, err)
				return
			}

			// Merge results safely
			resultMu.Lock()
			result.Changes = append(result.Changes, tempResult.Changes...)
			result.Errors = append(result.Errors, tempResult.Errors...)
			result.ResourcesAdded += tempResult.ResourcesAdded
			result.ResourcesUpdated += tempResult.ResourcesUpdated
			resultMu.Unlock()
		}(vpcID)
	}

	wg.Wait()
	close(errChan)

	// Return first error if any
	for err := range errChan {
		return err
	}

	return nil
}

// syncSecurityGroup creates or updates a security group
func (a *AWSIntegrator) syncSecurityGroup(vpcID, sgName, sgDescription string, pol *policy.Policy, result *SyncResult) error {
	// Check for existing security group
	existingSGs, err := a.client.DescribeSecurityGroups(a.ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("group-name"),
				Values: []string{sgName},
			},
			{
				Name:   aws.String("vpc-id"),
				Values: []string{vpcID},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to describe security groups: %w", err)
	}

	var sgID string
	if len(existingSGs.SecurityGroups) > 0 {
		// Update existing security group
		sgID = *existingSGs.SecurityGroups[0].GroupId
		if err := a.updateSecurityGroup(sgID, pol, result); err != nil {
			return err
		}
		result.ResourcesUpdated++
	} else {
		// Create new security group
		if !a.config.DryRun {
			createOutput, err := a.client.CreateSecurityGroup(a.ctx, &ec2.CreateSecurityGroupInput{
				GroupName:   aws.String(sgName),
				Description: aws.String(sgDescription),
				VpcId:       aws.String(vpcID),
				TagSpecifications: []types.TagSpecification{
					{
						ResourceType: types.ResourceTypeSecurityGroup,
						Tags:         a.buildTags(pol),
					},
				},
			})
			if err != nil {
				return fmt.Errorf("failed to create security group: %w", err)
			}
			sgID = *createOutput.GroupId
		}

		result.Changes = append(result.Changes, Change{
			ResourceID:   sgID,
			ResourceName: sgName,
			Operation:    "create",
			Details:      fmt.Sprintf("Created security group in VPC %s", vpcID),
			Success:      true,
		})
		result.ResourcesAdded++

		// Add rules to new security group
		if !a.config.DryRun && sgID != "" {
			if err := a.addSecurityGroupRules(sgID, pol); err != nil {
				return err
			}
		}
	}

	return nil
}

// updateSecurityGroup updates an existing security group's rules
func (a *AWSIntegrator) updateSecurityGroup(sgID string, pol *policy.Policy, result *SyncResult) error {
	// Get current rules
	sg, err := a.client.DescribeSecurityGroups(a.ctx, &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{sgID},
	})
	if err != nil {
		return fmt.Errorf("failed to describe security group: %w", err)
	}

	if len(sg.SecurityGroups) == 0 {
		return fmt.Errorf("security group not found: %s", sgID)
	}

	// Revoke all existing rules
	if !a.config.DryRun {
		if len(sg.SecurityGroups[0].IpPermissions) > 0 {
			_, err = a.client.RevokeSecurityGroupIngress(a.ctx, &ec2.RevokeSecurityGroupIngressInput{
				GroupId:       aws.String(sgID),
				IpPermissions: sg.SecurityGroups[0].IpPermissions,
			})
			if err != nil {
				return fmt.Errorf("failed to revoke ingress rules: %w", err)
			}
		}

		if len(sg.SecurityGroups[0].IpPermissionsEgress) > 0 {
			_, err = a.client.RevokeSecurityGroupEgress(a.ctx, &ec2.RevokeSecurityGroupEgressInput{
				GroupId:       aws.String(sgID),
				IpPermissions: sg.SecurityGroups[0].IpPermissionsEgress,
			})
			if err != nil {
				return fmt.Errorf("failed to revoke egress rules: %w", err)
			}
		}
	}

	// Add new rules
	if !a.config.DryRun {
		if err := a.addSecurityGroupRules(sgID, pol); err != nil {
			return err
		}
	}

	result.Changes = append(result.Changes, Change{
		ResourceID:   sgID,
		ResourceName: *sg.SecurityGroups[0].GroupName,
		Operation:    "update",
		Details:      "Updated security group rules",
		Success:      true,
	})

	return nil
}

// addSecurityGroupRules adds rules based on policy
func (a *AWSIntegrator) addSecurityGroupRules(sgID string, pol *policy.Policy) error {
	// Add ingress rules
	if len(pol.Spec.Ingress) > 0 {
		ingressPerms := a.buildIngressPermissions(pol.Spec.Ingress)
		if len(ingressPerms) > 0 {
			_, err := a.client.AuthorizeSecurityGroupIngress(a.ctx, &ec2.AuthorizeSecurityGroupIngressInput{
				GroupId:       aws.String(sgID),
				IpPermissions: ingressPerms,
			})
			if err != nil {
				return fmt.Errorf("failed to authorize ingress: %w", err)
			}
		}
	}

	// Add egress rules
	if len(pol.Spec.Egress) > 0 {
		egressPerms := a.buildEgressPermissions(pol.Spec.Egress)
		if len(egressPerms) > 0 {
			_, err := a.client.AuthorizeSecurityGroupEgress(a.ctx, &ec2.AuthorizeSecurityGroupEgressInput{
				GroupId:       aws.String(sgID),
				IpPermissions: egressPerms,
			})
			if err != nil {
				return fmt.Errorf("failed to authorize egress: %w", err)
			}
		}
	}

	return nil
}

// buildIngressPermissions converts policy ingress rules to AWS permissions
func (a *AWSIntegrator) buildIngressPermissions(rules []policy.Rule) []types.IpPermission {
	return a.buildPermissions(rules, true)
}

// buildEgressPermissions converts policy egress rules to AWS permissions
func (a *AWSIntegrator) buildEgressPermissions(rules []policy.Rule) []types.IpPermission {
	return a.buildPermissions(rules, false)
}

// buildPermissions converts policy rules to AWS permissions (DRY helper)
func (a *AWSIntegrator) buildPermissions(rules []policy.Rule, isIngress bool) []types.IpPermission {
	perms := make([]types.IpPermission, 0)
	description := "PCI-DSS Policy Egress"
	if isIngress {
		description = "PCI-DSS Policy Ingress"
	}

	for _, rule := range rules {
		for _, port := range rule.Ports {
			// Validate port range to prevent integer overflow
			if port.Port < 0 || port.Port > 65535 {
				continue // Skip invalid ports
			}

			perm := types.IpPermission{
				IpProtocol: aws.String(strings.ToLower(port.Protocol)),
				FromPort:   aws.Int32(int32(port.Port)), // #nosec G115 - validated range 0-65535
				ToPort:     aws.Int32(int32(port.Port)), // #nosec G115 - validated range 0-65535
			}

			// Add CIDR blocks from rule
			peers := rule.To
			if isIngress {
				peers = rule.From
			}
			for _, peer := range peers {
				if peer.IPBlock != nil {
					perm.IpRanges = append(perm.IpRanges, types.IpRange{
						CidrIp:      aws.String(peer.IPBlock.CIDR),
						Description: aws.String(description),
					})
				}
			}

			if len(perm.IpRanges) > 0 {
				perms = append(perms, perm)
			}
		}
	}

	return perms
}

// buildTags creates AWS tags from policy metadata
func (a *AWSIntegrator) buildTags(pol *policy.Policy) []types.Tag {
	tags := []types.Tag{
		{
			Key:   aws.String("Name"),
			Value: aws.String(fmt.Sprintf("pci-segment-%s", pol.Metadata.Name)),
		},
		{
			Key:   aws.String("pci-segment/managed"),
			Value: aws.String("true"),
		},
		{
			Key:   aws.String("pci-segment/policy"),
			Value: aws.String(pol.Metadata.Name),
		},
	}

	if pciReq, ok := pol.Metadata.Annotations["pci-dss"]; ok {
		tags = append(tags, types.Tag{
			Key:   aws.String("pci-dss"),
			Value: aws.String(pciReq),
		})
	}

	// Add custom tags from config
	for k, v := range a.config.Tags {
		tags = append(tags, types.Tag{
			Key:   aws.String(k),
			Value: aws.String(v),
		})
	}

	return tags
}

// Validate checks if AWS resources comply with policies
func (a *AWSIntegrator) Validate(_ []policy.Policy) (*ValidationReport, error) {
	report := &ValidationReport{
		Provider:   ProviderAWS,
		Timestamp:  time.Now(),
		Compliant:  true,
		Violations: make([]Violation, 0),
		Warnings:   make([]string, 0),
	}

	// Get all security groups managed by pci-segment
	sgs, err := a.client.DescribeSecurityGroups(a.ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("tag:pci-segment/managed"),
				Values: []string{"true"},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe security groups: %w", err)
	}

	report.Resources = len(sgs.SecurityGroups)

	// Validate each security group against policies
	for _, sg := range sgs.SecurityGroups {
		violations := a.validateSecurityGroup(&sg, nil)
		if len(violations) > 0 {
			report.Compliant = false
			report.Violations = append(report.Violations, violations...)
		}
	}

	return report, nil
}

// validateSecurityGroup checks a security group for policy violations
func (a *AWSIntegrator) validateSecurityGroup(sg *types.SecurityGroup, _ []policy.Policy) []Violation {
	violations := make([]Violation, 0)

	// Check for wildcard access (0.0.0.0/0)
	for _, perm := range sg.IpPermissions {
		for _, ipRange := range perm.IpRanges {
			if *ipRange.CidrIp == "0.0.0.0/0" {
				violations = append(violations, Violation{
					ResourceID:   *sg.GroupId,
					ResourceName: *sg.GroupName,
					PolicyName:   "wildcard-check",
					Severity:     "critical",
					Description:  "Security group allows access from 0.0.0.0/0 (violates PCI-DSS Req 1.3)",
					Remediation:  "Remove wildcard CIDR and specify exact IP ranges",
				})
			}
		}
	}

	return violations
}

// GetResources retrieves all AWS security resources
func (a *AWSIntegrator) GetResources() ([]SecurityResource, error) {
	resources := make([]SecurityResource, 0)

	sgs, err := a.client.DescribeSecurityGroups(a.ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("tag:pci-segment/managed"),
				Values: []string{"true"},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe security groups: %w", err)
	}

	for _, sg := range sgs.SecurityGroups {
		resource := SecurityResource{
			ID:       *sg.GroupId,
			Name:     *sg.GroupName,
			Type:     "security-group",
			Provider: ProviderAWS,
			Rules:    make([]SecurityRule, 0),
			Tags:     make(map[string]string),
		}

		// Convert tags
		for _, tag := range sg.Tags {
			resource.Tags[*tag.Key] = *tag.Value
		}

		// Convert ingress rules
		for _, perm := range sg.IpPermissions {
			for _, ipRange := range perm.IpRanges {
				rule := SecurityRule{
					Direction:  "ingress",
					Protocol:   *perm.IpProtocol,
					CIDRBlocks: []string{*ipRange.CidrIp},
					Action:     "allow",
				}
				if perm.FromPort != nil {
					rule.FromPort = int(*perm.FromPort)
				}
				if perm.ToPort != nil {
					rule.ToPort = int(*perm.ToPort)
				}
				resource.Rules = append(resource.Rules, rule)
			}
		}

		// Convert egress rules
		for _, perm := range sg.IpPermissionsEgress {
			for _, ipRange := range perm.IpRanges {
				rule := SecurityRule{
					Direction:  "egress",
					Protocol:   *perm.IpProtocol,
					CIDRBlocks: []string{*ipRange.CidrIp},
					Action:     "allow",
				}
				if perm.FromPort != nil {
					rule.FromPort = int(*perm.FromPort)
				}
				if perm.ToPort != nil {
					rule.ToPort = int(*perm.ToPort)
				}
				resource.Rules = append(resource.Rules, rule)
			}
		}

		resources = append(resources, resource)
	}

	return resources, nil
}

// Close cleans up AWS client resources
func (a *AWSIntegrator) Close() error {
	// AWS SDK v2 doesn't require explicit cleanup
	return nil
}
