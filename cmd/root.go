package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	policyFile string
	outputFile string
	verbose    bool
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
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
}
