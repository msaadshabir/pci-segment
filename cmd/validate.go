package cmd

import (
	"fmt"

	"github.com/msaadshabir/pci-segment/pkg/log"
	"github.com/msaadshabir/pci-segment/pkg/policy"
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
	if err := validateCmd.MarkFlagRequired("file"); err != nil {
		cobra.CheckErr(fmt.Errorf("failed to mark flag required: %w", err))
	}
}

func runValidate(_ *cobra.Command, _ []string) error {
	engine := policy.NewEngine()

	log.Debug("validating policy", "file", policyFile)

	if err := engine.LoadFromFile(policyFile); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	policies := engine.GetPolicies()

	allValid := true
	for _, pol := range policies {
		result := engine.Validate(&pol)

		if result.Valid {
			log.Info("policy valid",
				"policy", pol.Metadata.Name,
				"api_version", pol.APIVersion,
				"kind", pol.Kind,
				"pci_requirements", result.PCIRequirements)
		} else {
			log.Error("policy invalid",
				"policy", pol.Metadata.Name,
				"api_version", pol.APIVersion,
				"kind", pol.Kind,
				"errors", result.Errors)
			allValid = false
		}

		if len(result.Warnings) > 0 {
			log.Warn("policy has warnings", "policy", pol.Metadata.Name, "warnings", result.Warnings)
		}
	}

	if allValid {
		log.Info("all policies valid and PCI-DSS compliant")
		return nil
	}

	return fmt.Errorf("validation failed: one or more policies are invalid")
}
