package cmd

import (
	"fmt"
	"os"

	"github.com/msaadshabir/pci-segment/pkg/config"
	"github.com/msaadshabir/pci-segment/pkg/log"
	"github.com/msaadshabir/pci-segment/pkg/security/privilege"
	"github.com/spf13/cobra"
)

var (
	configFile string
	policyFile string
	outputFile string
	verbose    bool
	logLevel   string
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "pci-segment",
	Short: "PCI-DSS v4.0 compliant network segmentation enforcer",
	Long: `pci-segment: PCI-DSS v4.0 Compliant Network Segmentation Tool

A production-ready microsegmentation tool that enforces PCI-DSS Requirements
1.2 and 1.3 for network segmentation of the Cardholder Data Environment (CDE).

Features:
  * Policy validation against PCI-DSS Req 1.2/1.3
  * OS-native enforcement (eBPF, pf)
  * Compliance reporting (HTML/JSON)
  * Auditor-ready documentation`,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		if configFile != "" {
			cfg, err := config.LoadFromFile(configFile)
			if err != nil {
				return fmt.Errorf("loading config %s: %w", configFile, err)
			}
			applyConfig(cmd, cfg)
		}

		if verbose {
			logLevel = "debug"
		}
		if !log.SetLevel(logLevel) {
			return fmt.Errorf("invalid log level: %s (use debug, info, warn, error)", logLevel)
		}
		return nil
	},
}

func applyConfig(cmd *cobra.Command, cfg *config.Config) {
	if cfg == nil {
		return
	}

	if cfg.Log.Level != nil && !flagChanged(cmd, "log-level") {
		logLevel = *cfg.Log.Level
	}

	if cfg.Enforce.Compliance != nil && flagExists(cmd, "compliance") && !flagChanged(cmd, "compliance") {
		complianceMode = *cfg.Enforce.Compliance
	}
	if cfg.Enforce.AllowRoot != nil && flagExists(cmd, "allow-root") && !flagChanged(cmd, "allow-root") {
		allowRoot = *cfg.Enforce.AllowRoot
	}
	if cfg.Enforce.MetricsAddr != nil && flagExists(cmd, "metrics-addr") && !flagChanged(cmd, "metrics-addr") {
		metricsAddr = *cfg.Enforce.MetricsAddr
	}
	if cfg.Enforce.MetricsPath != nil && flagExists(cmd, "metrics-path") && !flagChanged(cmd, "metrics-path") {
		metricsPath = *cfg.Enforce.MetricsPath
	}
	if cfg.Enforce.Interface != nil && os.Getenv("PCI_SEGMENT_INTERFACE") == "" {
		os.Setenv("PCI_SEGMENT_INTERFACE", *cfg.Enforce.Interface)
	}

	if cfg.Cloud.ConfigFile != nil && flagExists(cmd, "cloud-config") && !flagChanged(cmd, "cloud-config") {
		cloudConfigFile = *cfg.Cloud.ConfigFile
	}
	if cfg.Cloud.DryRun != nil && flagExists(cmd, "dry-run") && !flagChanged(cmd, "dry-run") {
		dryRun = *cfg.Cloud.DryRun
	}

	if cfg.Privilege.User != nil && *cfg.Privilege.User != "" && os.Getenv(privilege.EnvTargetUser) == "" {
		os.Setenv(privilege.EnvTargetUser, *cfg.Privilege.User)
	}
	if cfg.Privilege.Group != nil && *cfg.Privilege.Group != "" && os.Getenv(privilege.EnvTargetGroup) == "" {
		os.Setenv(privilege.EnvTargetGroup, *cfg.Privilege.Group)
	}
	if cfg.Privilege.DisableSeccomp != nil && *cfg.Privilege.DisableSeccomp && os.Getenv(privilege.EnvDisableSeccomp) == "" {
		os.Setenv(privilege.EnvDisableSeccomp, "1")
	}
	if cfg.Privilege.SkipDrop != nil && *cfg.Privilege.SkipDrop && os.Getenv(privilege.EnvSkipDrop) == "" {
		os.Setenv(privilege.EnvSkipDrop, "1")
	}
	if cfg.Privilege.SELinuxProfile != nil && *cfg.Privilege.SELinuxProfile != "" && os.Getenv(privilege.EnvSELinuxProfile) == "" {
		os.Setenv(privilege.EnvSELinuxProfile, *cfg.Privilege.SELinuxProfile)
	}
	if cfg.Privilege.AppArmorProfile != nil && *cfg.Privilege.AppArmorProfile != "" && os.Getenv(privilege.EnvAppArmorProfile) == "" {
		os.Setenv(privilege.EnvAppArmorProfile, *cfg.Privilege.AppArmorProfile)
	}
	if cfg.Privilege.SkipMACVerify != nil && *cfg.Privilege.SkipMACVerify && os.Getenv(privilege.EnvSkipMACVerify) == "" {
		os.Setenv(privilege.EnvSkipMACVerify, "1")
	}
}

func flagExists(cmd *cobra.Command, name string) bool {
	return cmd.Flag(name) != nil
}

func flagChanged(cmd *cobra.Command, name string) bool {
	f := cmd.Flag(name)
	return f != nil && f.Changed
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "path to global config file (YAML)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output (alias for --log-level=debug)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level (debug, info, warn, error)")
}
