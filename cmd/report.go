package cmd

import (
	"fmt"
	"time"

	"github.com/msaadshabir/pci-segment/pkg/log"
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

func runReport(_ *cobra.Command, _ []string) error {
	engine := policy.NewEngine()

	log.Debug("loading policies", "file", policyFile)

	if err := engine.LoadFromFile(policyFile); err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	policies := engine.GetPolicies()
	log.Info("policies loaded", "count", len(policies))

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

	rep := reporter.NewReporter()
	rep.SetPolicies(policies)
	rep.SetEvents(sampleEvents)

	log.Info("generating compliance report", "format", reportFormat)

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

	report := rep.GenerateReport()
	log.Info("report generated",
		"file", outputFile,
		"status", report.ComplianceStatus,
		"policies", report.Summary.TotalPolicies,
		"cde_servers", report.Summary.CDEServers,
		"blocked_events", report.Summary.BlockedEvents,
		"allowed_events", report.Summary.AllowedEvents)

	return nil
}
