package cmd

import (
	"os"
	"testing"

	appconfig "github.com/msaadshabir/pci-segment/pkg/config"
	"github.com/spf13/cobra"
)

func TestApplyConfig_CloudDefaults(t *testing.T) {
	cloudConfigFile = ""
	dryRun = false

	cmd := &cobra.Command{Use: "cloud-sync"}
	cmd.Flags().StringVarP(&cloudConfigFile, "cloud-config", "c", "", "")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "")

	cfgPath := "from-config.yaml"
	trueVal := true
	cfg := &appconfig.Config{
		Cloud: appconfig.CloudConfig{
			ConfigFile: &cfgPath,
			DryRun:     &trueVal,
		},
	}

	applyConfig(cmd, cfg)

	if cloudConfigFile != "from-config.yaml" {
		t.Fatalf("expected cloudConfigFile to be set from config, got %q", cloudConfigFile)
	}
	if !dryRun {
		t.Fatalf("expected dryRun to be set from config")
	}
}

func TestApplyConfig_DoesNotOverrideChangedFlags(t *testing.T) {
	cloudConfigFile = ""

	cmd := &cobra.Command{Use: "cloud-sync"}
	cmd.Flags().StringVarP(&cloudConfigFile, "cloud-config", "c", "", "")
	if err := cmd.Flags().Set("cloud-config", "cli.yaml"); err != nil {
		t.Fatalf("set flag: %v", err)
	}

	cfgPath := "from-config.yaml"
	cfg := &appconfig.Config{
		Cloud: appconfig.CloudConfig{ConfigFile: &cfgPath},
	}

	applyConfig(cmd, cfg)

	if cloudConfigFile != "cli.yaml" {
		t.Fatalf("expected cloudConfigFile to keep CLI value, got %q", cloudConfigFile)
	}
}

func TestApplyConfig_DoesNotOverrideSetEnv(t *testing.T) {
	const key = "PCI_SEGMENT_INTERFACE"
	old := os.Getenv(key)
	t.Cleanup(func() {
		if old == "" {
			os.Unsetenv(key)
			return
		}
		os.Setenv(key, old)
	})

	os.Setenv(key, "from-env")

	cmd := &cobra.Command{Use: "enforce"}
	cmd.Flags().StringVarP(&policyFile, "file", "f", "", "")
	cmd.Flags().StringVar(&metricsAddr, "metrics-addr", "", "")

	iface := "from-config"
	cfg := &appconfig.Config{Enforce: appconfig.EnforceConfig{Interface: &iface}}
	applyConfig(cmd, cfg)

	if got := os.Getenv(key); got != "from-env" {
		t.Fatalf("expected env to win over config, got %q", got)
	}
}
