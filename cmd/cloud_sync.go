package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/msaadshabir/pci-segment/pkg/cloud"
	"github.com/msaadshabir/pci-segment/pkg/log"
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
	cloudSyncCmd.Flags().StringVarP(&cloudConfigFile, "cloud-config", "c", "", "cloud configuration file")
	cloudSyncCmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be synced without making changes")
	if err := cloudSyncCmd.MarkFlagRequired("file"); err != nil {
		cobra.CheckErr(fmt.Errorf("failed to mark flag required: %w", err))
	}
}

func runCloudSync(_ *cobra.Command, _ []string) error {
	if cloudConfigFile == "" {
		return fmt.Errorf("cloud configuration file is required (use --cloud-config)")
	}

	log.Debug("loading cloud configuration", "file", cloudConfigFile)

	cloudCfg, err := loadCloudConfig(cloudConfigFile)
	if err != nil {
		return fmt.Errorf("failed to load cloud config: %w", err)
	}

	if dryRun {
		cloudCfg.DryRun = true
	}

	engine := policy.NewEngine()

	log.Debug("loading policies", "file", policyFile)

	if err := engine.LoadFromFile(policyFile); err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	policies := engine.GetPolicies()
	log.Info("policies loaded", "count", len(policies))

	log.Info("validating policies")
	allValid := true
	for i, pol := range policies {
		result := engine.Validate(&policies[i])
		if !result.Valid {
			log.Error("policy invalid", "policy", pol.Metadata.Name, "errors", result.Errors)
			allValid = false
		} else {
			log.Info("policy valid", "policy", pol.Metadata.Name)
		}
	}

	if !allValid {
		return fmt.Errorf("validation failed: one or more policies are invalid")
	}

	log.Info("connecting to cloud provider", "provider", cloudCfg.Provider, "region", cloudCfg.Region)
	integrator, err := cloud.NewIntegrator(cloudCfg)
	if err != nil {
		return fmt.Errorf("failed to create cloud integrator: %w", err)
	}
	defer integrator.Close()

	if cloudCfg.DryRun {
		log.Info("dry run mode enabled")
	} else {
		log.Info("syncing policies to cloud")
	}

	syncResult, err := integrator.Sync(policies)
	if err != nil {
		return fmt.Errorf("sync failed: %w", err)
	}

	log.Info("sync complete",
		"provider", syncResult.Provider,
		"dry_run", syncResult.DryRun,
		"added", syncResult.ResourcesAdded,
		"updated", syncResult.ResourcesUpdated,
		"deleted", syncResult.ResourcesDeleted)

	for _, change := range syncResult.Changes {
		if change.Success {
			log.Info("change applied", "operation", change.Operation, "resource", change.ResourceName, "details", change.Details)
		} else {
			log.Error("change failed", "operation", change.Operation, "resource", change.ResourceName, "error", change.Error)
		}
	}

	if len(syncResult.Errors) > 0 {
		for _, e := range syncResult.Errors {
			log.Error("sync error", "error", e)
		}
		return fmt.Errorf("sync completed with %d error(s)", len(syncResult.Errors))
	}

	log.Info("cloud sync complete")
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
