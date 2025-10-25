package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/msaadshabir/pci-segment/pkg/cloud"
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
	cloudValidateCmd.Flags().StringVarP(&cloudConfigFile, "config", "c", "", "cloud configuration file (required)")
	cloudValidateCmd.Flags().StringVar(&outputFormat, "format", "text", "output format (text, json)")
	if err := cloudValidateCmd.MarkFlagRequired("file"); err != nil {
		cobra.CheckErr(fmt.Errorf("failed to mark flag required: %w", err))
	}
	if err := cloudValidateCmd.MarkFlagRequired("config"); err != nil {
		cobra.CheckErr(fmt.Errorf("failed to mark flag required: %w", err))
	}
}

func runCloudValidate(_ *cobra.Command, _ []string) error {
	// Load cloud configuration
	if verbose {
		fmt.Printf("Loading cloud configuration from: %s\n", cloudConfigFile)
	}

	cloudCfg, err := loadCloudConfig(cloudConfigFile)
	if err != nil {
		return fmt.Errorf("failed to load cloud config: %w", err)
	}

	// Load policy engine
	engine := policy.NewEngine()

	if verbose {
		fmt.Printf("Loading policies from: %s\n", policyFile)
	}

	if err := engine.LoadFromFile(policyFile); err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	policies := engine.GetPolicies()
	if verbose {
		fmt.Printf("[OK] Loaded %d polic(ies)\n", len(policies))
	}

	// Create cloud integrator
	fmt.Printf("[CONNECTING] to %s %s...\n", cloudCfg.Provider, cloudCfg.Region)
	integrator, err := cloud.NewIntegrator(cloudCfg)
	if err != nil {
		return fmt.Errorf("failed to create cloud integrator: %w", err)
	}
	defer integrator.Close()

	// Validate cloud resources
	fmt.Println("\n[VALIDATING] Cloud resources...")
	report, err := integrator.Validate(policies)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Output results
	if outputFormat == "json" {
		return outputJSON(report)
	}

	return outputText(report)
}

func outputText(report *cloud.ValidationReport) error {
	fmt.Printf("\n[VALIDATION REPORT]\n")
	fmt.Printf("   Provider: %s\n", report.Provider)
	fmt.Printf("   Timestamp: %s\n", report.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("   Resources Checked: %d\n", report.Resources)

	if report.Compliant {
		fmt.Printf("   Status: [OK] COMPLIANT\n")
	} else {
		fmt.Printf("   Status: [!] NON-COMPLIANT\n")
	}

	if len(report.Violations) > 0 {
		fmt.Printf("\n   Violations (%d):\n", len(report.Violations))
		for i, v := range report.Violations {
			fmt.Printf("\n   %d. %s - %s\n", i+1, v.ResourceName, v.Severity)
			fmt.Printf("      Resource ID: %s\n", v.ResourceID)
			fmt.Printf("      Policy: %s\n", v.PolicyName)
			fmt.Printf("      Issue: %s\n", v.Description)
			fmt.Printf("      Fix: %s\n", v.Remediation)
		}
	}

	if len(report.Warnings) > 0 {
		fmt.Printf("\n   Warnings:\n")
		for _, w := range report.Warnings {
			fmt.Printf("   [!] %s\n", w)
		}
	}

	fmt.Println()
	if !report.Compliant {
		return fmt.Errorf("cloud resources are not compliant with PCI-DSS policies")
	}

	fmt.Println("[OK] All cloud resources are compliant")
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
