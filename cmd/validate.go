package cmd

import (
	"fmt"

	"github.com/saad-build/pci-segment/pkg/policy"
	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate policies against PCI-DSS requirements",
	Long:  `Validate network policies to ensure compliance with PCI-DSS v4.0 Requirements 1.2 and 1.3`,
	Example: `  pci-segment validate -f policies/cde-isolation.yaml
  pci-segment validate -f policies/*.yaml`,
	RunE: runValidate,
}

func init() {
	rootCmd.AddCommand(validateCmd)
	validateCmd.Flags().StringVarP(&policyFile, "file", "f", "", "policy file to validate (required)")
	validateCmd.MarkFlagRequired("file")
}

func runValidate(cmd *cobra.Command, args []string) error {
	// Create policy engine
	engine := policy.NewEngine()

	// Load policy file
	if verbose {
		fmt.Printf("Validating policy: %s\n", policyFile)
	}

	if err := engine.LoadFromFile(policyFile); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	policies := engine.GetPolicies()

	allValid := true
	for _, pol := range policies {
		result := engine.Validate(&pol)

		fmt.Printf("\n[POLICY] %s\n", pol.Metadata.Name)
		fmt.Printf("   API Version: %s\n", pol.APIVersion)
		fmt.Printf("   Kind: %s\n", pol.Kind)

		if len(result.PCIRequirements) > 0 {
			fmt.Printf("   PCI-DSS: %v\n", result.PCIRequirements)
		}

		if result.Valid {
			fmt.Println("   Status: [OK] VALID")
		} else {
			fmt.Println("   Status: [X] INVALID")
			allValid = false
		}

		if len(result.Errors) > 0 {
			fmt.Println("   Errors:")
			for _, err := range result.Errors {
				fmt.Printf("     - %s\n", err)
			}
		}

		if len(result.Warnings) > 0 {
			fmt.Println("   Warnings:")
			for _, warn := range result.Warnings {
				fmt.Printf("     [!] %s\n", warn)
			}
		}
	}

	fmt.Println()
	if allValid {
		fmt.Println("[OK] All policies are valid and PCI-DSS compliant")
		return nil
	}

	return fmt.Errorf("validation failed: one or more policies are invalid")
}
