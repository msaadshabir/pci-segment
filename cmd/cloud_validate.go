package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/msaadshabir/pci-segment/pkg/cloud"
	"github.com/msaadshabir/pci-segment/pkg/log"
	"github.com/msaadshabir/pci-segment/pkg/policy"
	"github.com/spf13/cobra"
)

var cloudValidateCmd = &cobra.Command{
	Use:   "cloud-validate",
	Short: "Validate cloud resources against PCI-DSS policies",
	Long: `Check if existing cloud security groups/NSGs comply with PCI-DSS policies.
Reports violations and provides remediation guidance.`,
	Example: `  pci-segment cloud-validate -f policies/cde-isolation.yaml -c cloud-config.yaml
	  pci-segment cloud-validate -f policies/*.yaml -c cloud-config.yaml --format=json`,
	RunE: runCloudValidate,
}

var (
	outputFormat string
)

func init() {
	rootCmd.AddCommand(cloudValidateCmd)
	cloudValidateCmd.Flags().StringVarP(&policyFile, "file", "f", "", "policy file(s) to validate against (required)")
	cloudValidateCmd.Flags().StringVarP(&cloudConfigFile, "cloud-config", "c", "", "cloud configuration file")
	cloudValidateCmd.Flags().StringVar(&outputFormat, "format", "text", "output format (text, json)")
	if err := cloudValidateCmd.MarkFlagRequired("file"); err != nil {
		cobra.CheckErr(fmt.Errorf("failed to mark flag required: %w", err))
	}
}

func runCloudValidate(_ *cobra.Command, _ []string) error {
	if cloudConfigFile == "" {
		return fmt.Errorf("cloud configuration file is required (use --cloud-config)")
	}

	log.Debug("loading cloud configuration", "file", cloudConfigFile)

	cloudCfg, err := loadCloudConfig(cloudConfigFile)
	if err != nil {
		return fmt.Errorf("failed to load cloud config: %w", err)
	}

	engine := policy.NewEngine()

	log.Debug("loading policies", "file", policyFile)

	if err := engine.LoadFromFile(policyFile); err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	policies := engine.GetPolicies()
	log.Debug("policies loaded", "count", len(policies))

	log.Info("connecting to cloud provider", "provider", cloudCfg.Provider, "region", cloudCfg.Region)
	integrator, err := cloud.NewIntegrator(cloudCfg)
	if err != nil {
		return fmt.Errorf("failed to create cloud integrator: %w", err)
	}
	defer integrator.Close()

	log.Info("validating cloud resources")
	report, err := integrator.Validate(policies)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	if outputFormat == "json" {
		return outputJSON(report)
	}

	return outputText(report)
}

func outputText(report *cloud.ValidationReport) error {
	if report.Compliant {
		log.Info("validation complete",
			"provider", report.Provider,
			"resources", report.Resources,
			"status", "compliant")
	} else {
		log.Warn("validation complete",
			"provider", report.Provider,
			"resources", report.Resources,
			"status", "non-compliant",
			"violations", len(report.Violations))
	}

	for i, v := range report.Violations {
		log.Error("violation found",
			"num", i+1,
			"resource", v.ResourceName,
			"resource_id", v.ResourceID,
			"severity", v.Severity,
			"policy", v.PolicyName,
			"issue", v.Description,
			"fix", v.Remediation)
	}

	for _, w := range report.Warnings {
		log.Warn("validation warning", "message", w)
	}

	if !report.Compliant {
		return fmt.Errorf("cloud resources are not compliant with PCI-DSS policies")
	}

	log.Info("all cloud resources are compliant")
	return nil
}

func outputJSON(report *cloud.ValidationReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}
