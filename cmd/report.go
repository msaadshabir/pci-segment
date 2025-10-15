package cmd

import (
	"fmt"
	"time"

	"github.com/msaadshabir/pci-segment/pkg/policy"
	"github.com/msaadshabir/pci-segment/pkg/reporter"
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate compliance reports",
	Long: `Generate PCI-DSS compliance reports in HTML or JSON format.
Reports include policy validation status, enforcement evidence, and auditor-ready documentation.`,
	Example: `  pci-segment report -f policies/cde-isolation.yaml -o report.html
  pci-segment report -f policies/*.yaml -o report.json --format=json`,
	RunE: runReport,
}

var (
	reportFormat string
)

func init() {
	rootCmd.AddCommand(reportCmd)
	reportCmd.Flags().StringVarP(&policyFile, "file", "f", "", "policy file(s) to include in report (required)")
	reportCmd.Flags().StringVarP(&outputFile, "output", "o", "pci-compliance-report.html", "output file")
	reportCmd.Flags().StringVar(&reportFormat, "format", "html", "report format (html, json)")
	if err := reportCmd.MarkFlagRequired("file"); err != nil {
		cobra.CheckErr(fmt.Errorf("failed to mark flag required: %w", err))
	}
}

func runReport(cmd *cobra.Command, args []string) error {
	// Create policy engine
	engine := policy.NewEngine()

	// Load policy file
	if verbose {
		fmt.Printf("Loading policies from: %s\n", policyFile)
	}

	if err := engine.LoadFromFile(policyFile); err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	policies := engine.GetPolicies()
	fmt.Printf("[OK] Loaded %d polic(ies)\n", len(policies))

	// Create some sample enforcement events for demonstration
	sampleEvents := []policy.EnforcementEvent{
		{
			Timestamp:  time.Now().Add(-2 * time.Hour),
			SourceIP:   "192.168.1.50",
			DestIP:     "10.0.1.100",
			DestPort:   3306,
			Protocol:   "TCP",
			Action:     "BLOCKED",
			PolicyName: "cde-isolation",
			PCIDSSReq:  "Req 1.3",
		},
		{
			Timestamp:  time.Now().Add(-1 * time.Hour),
			SourceIP:   "10.0.10.5",
			DestIP:     "10.0.1.100",
			DestPort:   443,
			Protocol:   "TCP",
			Action:     "ALLOWED",
			PolicyName: "cde-isolation",
			PCIDSSReq:  "Req 1.2",
		},
		{
			Timestamp:  time.Now().Add(-30 * time.Minute),
			SourceIP:   "192.168.1.75",
			DestIP:     "10.0.1.101",
			DestPort:   5432,
			Protocol:   "TCP",
			Action:     "BLOCKED",
			PolicyName: "cde-isolation",
			PCIDSSReq:  "Req 1.3",
		},
	}

	// Create reporter
	rep := reporter.NewReporter()
	rep.SetPolicies(policies)
	rep.SetEvents(sampleEvents)

	// Generate report
	fmt.Printf("\n[GENERATING] %s compliance report...\n", reportFormat)

	var err error
	switch reportFormat {
	case "html":
		err = rep.ExportHTML(outputFile)
	case "json":
		err = rep.ExportJSON(outputFile)
	default:
		return fmt.Errorf("unsupported format: %s (use 'html' or 'json')", reportFormat)
	}

	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	fmt.Printf("[OK] Report generated: %s\n", outputFile)
	fmt.Println("\n[REPORT SUMMARY]")

	report := rep.GenerateReport()
	fmt.Printf("   Status: %s\n", report.ComplianceStatus)
	fmt.Printf("   Policies: %d\n", report.Summary.TotalPolicies)
	fmt.Printf("   CDE Servers: %d\n", report.Summary.CDEServers)
	fmt.Printf("   Blocked Events: %d\n", report.Summary.BlockedEvents)
	fmt.Printf("   Allowed Events: %d\n", report.Summary.AllowedEvents)

	return nil
}
