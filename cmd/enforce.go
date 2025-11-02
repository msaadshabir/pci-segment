package cmd

import (
	"fmt"
	"os"
	"runtime"

	"github.com/msaadshabir/pci-segment/pkg/enforcer"
	"github.com/msaadshabir/pci-segment/pkg/policy"
	"github.com/msaadshabir/pci-segment/pkg/security/privilege"
	"github.com/spf13/cobra"
)

var enforceCmd = &cobra.Command{
	Use:   "enforce",
	Short: "Enforce PCI-DSS network policies",
	Long:  `Enforce network segmentation policies to comply with PCI-DSS Requirements 1.2 and 1.3`,
	Example: `  pci-segment enforce -f policies/cde-isolation.yaml
  pci-segment enforce -f policies/*.yaml --compliance=pci`,
	RunE: runEnforce,
}

var (
	complianceMode string
	allowRoot      bool
)

func init() {
	rootCmd.AddCommand(enforceCmd)
	enforceCmd.Flags().StringVarP(&policyFile, "file", "f", "", "policy file or glob pattern (required)")
	enforceCmd.Flags().StringVar(&complianceMode, "compliance", "pci", "compliance mode (pci, soc2)")
	enforceCmd.Flags().BoolVar(&allowRoot, "allow-root", false, "allow running enforcement as root (disables privilege drop)")
	if err := enforceCmd.MarkFlagRequired("file"); err != nil {
		cobra.CheckErr(fmt.Errorf("failed to mark flag required: %w", err))
	}
}

func runEnforce(cmd *cobra.Command, args []string) error {
	if runtime.GOOS == "linux" && !allowRoot {
		cfg := privilege.FromEnv()
		if err := privilege.Ensure(cfg); err != nil {
			return fmt.Errorf("privilege hardening failed: %w", err)
		}
	}

	// Create policy engine
	engine := policy.NewEngine()

	// Load policy file
	if verbose {
		fmt.Printf("Loading policy from: %s\n", policyFile)
	}

	if err := engine.LoadFromFile(policyFile); err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	policies := engine.GetPolicies()
	fmt.Printf("[OK] Loaded %d polic(ies)\n", len(policies))

	// Validate policies
	for _, pol := range policies {
		result := engine.Validate(&pol)
		if !result.Valid {
			return fmt.Errorf("policy validation failed for '%s': %v", pol.Metadata.Name, result.Errors)
		}
		if len(result.Warnings) > 0 && verbose {
			fmt.Printf("[WARN] Warnings for policy '%s': %v\n", pol.Metadata.Name, result.Warnings)
		}
		if len(result.PCIRequirements) > 0 {
			fmt.Printf("[OK] Policy '%s' covers: %v\n", pol.Metadata.Name, result.PCIRequirements)
		}
	}

	// Create enforcer
	enf, err := enforcer.NewEnforcer()
	if err != nil {
		return fmt.Errorf("failed to create enforcer: %w", err)
	}

	// Add policies to enforcer
	for i := range policies {
		if err := enf.AddPolicy(&policies[i]); err != nil {
			return fmt.Errorf("failed to add policy: %w", err)
		}
	}

	// Start enforcement
	fmt.Println("\n[STARTING] PCI-DSS enforcement...")
	if err := enf.Start(); err != nil {
		return fmt.Errorf("failed to start enforcer: %w", err)
	}

	fmt.Println("[OK] Enforcement active")
	fmt.Println("\nPress Ctrl+C to stop enforcement")

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	<-sigChan

	// Stop enforcement
	fmt.Println("\n\nStopping enforcement...")
	if err := enf.Stop(); err != nil {
		return fmt.Errorf("failed to stop enforcer: %w", err)
	}

	fmt.Println("[OK] Enforcement stopped")
	return nil
}
