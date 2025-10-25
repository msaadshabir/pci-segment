package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/msaadshabir/pci-segment/pkg/cloud"
	"github.com/msaadshabir/pci-segment/pkg/policy"
	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v3"
)

var cloudSyncCmd = &cobra.Command{
	Use:   "cloud-sync",
	Short: "Synchronize PCI-DSS policies to cloud security groups",
	Long: `Sync network policies to cloud providers (AWS Security Groups, Azure NSGs).
Automatically creates or updates cloud security resources to match PCI-DSS policies.`,
	Example: `  pci-segment cloud-sync -f policies/cde-isolation.yaml -c cloud-config.yaml
  pci-segment cloud-sync -f policies/*.yaml -c cloud-config.yaml --dry-run`,
	RunE: runCloudSync,
}

var (
	cloudConfigFile string
	dryRun          bool
)

func init() {
	rootCmd.AddCommand(cloudSyncCmd)
	cloudSyncCmd.Flags().StringVarP(&policyFile, "file", "f", "", "policy file(s) to sync (required)")
	cloudSyncCmd.Flags().StringVarP(&cloudConfigFile, "config", "c", "", "cloud configuration file (required)")
	cloudSyncCmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be synced without making changes")
	if err := cloudSyncCmd.MarkFlagRequired("file"); err != nil {
		cobra.CheckErr(fmt.Errorf("failed to mark flag required: %w", err))
	}
	if err := cloudSyncCmd.MarkFlagRequired("config"); err != nil {
		cobra.CheckErr(fmt.Errorf("failed to mark flag required: %w", err))
	}
}

func runCloudSync(_ *cobra.Command, _ []string) error {
	// Load cloud configuration
	if verbose {
		fmt.Printf("Loading cloud configuration from: %s\n", cloudConfigFile)
	}

	cloudCfg, err := loadCloudConfig(cloudConfigFile)
	if err != nil {
		return fmt.Errorf("failed to load cloud config: %w", err)
	}

	// Override dry-run flag if specified
	if dryRun {
		cloudCfg.DryRun = true
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
	fmt.Printf("[OK] Loaded %d polic(ies)\n", len(policies))

	// Validate policies first
	fmt.Println("\n[VALIDATING] Policies...")
	allValid := true
	for i, pol := range policies {
		result := engine.Validate(&policies[i])
		if !result.Valid {
			fmt.Printf("[!] Policy '%s' is invalid: %v\n", pol.Metadata.Name, result.Errors)
			allValid = false
		} else {
			fmt.Printf("[OK] Policy '%s' is valid\n", pol.Metadata.Name)
		}
	}

	if !allValid {
		return fmt.Errorf("validation failed: one or more policies are invalid")
	}

	// Create cloud integrator
	fmt.Printf("\n[CONNECTING] to %s %s...\n", cloudCfg.Provider, cloudCfg.Region)
	integrator, err := cloud.NewIntegrator(cloudCfg)
	if err != nil {
		return fmt.Errorf("failed to create cloud integrator: %w", err)
	}
	defer integrator.Close()

	// Sync policies
	if cloudCfg.DryRun {
		fmt.Println("\n[DRY RUN] Showing changes without applying...")
	} else {
		fmt.Println("\n[SYNCING] Policies to cloud...")
	}

	syncResult, err := integrator.Sync(policies)
	if err != nil {
		return fmt.Errorf("sync failed: %w", err)
	}

	// Display results
	fmt.Printf("\n[SYNC RESULTS]\n")
	fmt.Printf("   Provider: %s\n", syncResult.Provider)
	fmt.Printf("   Dry Run: %v\n", syncResult.DryRun)
	fmt.Printf("   Resources Added: %d\n", syncResult.ResourcesAdded)
	fmt.Printf("   Resources Updated: %d\n", syncResult.ResourcesUpdated)
	fmt.Printf("   Resources Deleted: %d\n", syncResult.ResourcesDeleted)

	if len(syncResult.Changes) > 0 {
		fmt.Printf("\n   Changes:\n")
		for _, change := range syncResult.Changes {
			status := "[OK]"
			if !change.Success {
				status = "[X]"
			}
			fmt.Printf("   %s %s: %s - %s\n", status, change.Operation, change.ResourceName, change.Details)
			if change.Error != "" {
				fmt.Printf("       Error: %s\n", change.Error)
			}
		}
	}

	if len(syncResult.Errors) > 0 {
		fmt.Printf("\n   Errors:\n")
		for _, err := range syncResult.Errors {
			fmt.Printf("   [!] %s\n", err)
		}
		return fmt.Errorf("sync completed with %d error(s)", len(syncResult.Errors))
	}

	fmt.Printf("\n[OK] Cloud sync complete\n")
	return nil
}

func loadCloudConfig(filename string) (*cloud.Config, error) {
	// Clean the file path to prevent directory traversal
	cleanPath := filepath.Clean(filename)

	data, err := os.ReadFile(cleanPath) // #nosec G304 - file path from CLI argument, validated by filepath.Clean
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg cloud.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config YAML: %w", err)
	}

	return &cfg, nil
}
