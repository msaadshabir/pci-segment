package reporter

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"time"

	"github.com/saad-build/pci-segment/pkg/policy"
)

// Report represents a compliance report
type Report struct {
	GeneratedAt      time.Time                 `json:"generated_at"`
	Version          string                    `json:"version"`
	ComplianceStatus string                    `json:"compliance_status"`
	PCIRequirements  []string                  `json:"pci_requirements"`
	Policies         []policy.Policy           `json:"policies"`
	Events           []policy.EnforcementEvent `json:"events"`
	Summary          ReportSummary             `json:"summary"`
}

// ReportSummary contains executive summary data
type ReportSummary struct {
	TotalPolicies   int    `json:"total_policies"`
	CDEServers      int    `json:"cde_servers"`
	TotalServers    int    `json:"total_servers"`
	BlockedEvents   int    `json:"blocked_events"`
	AllowedEvents   int    `json:"allowed_events"`
	ComplianceLevel string `json:"compliance_level"`
}

// Reporter generates compliance reports
type Reporter struct {
	policies []policy.Policy
	events   []policy.EnforcementEvent
}

// NewReporter creates a new compliance reporter
func NewReporter() *Reporter {
	return &Reporter{
		policies: make([]policy.Policy, 0),
		events:   make([]policy.EnforcementEvent, 0),
	}
}

// SetPolicies sets the policies for reporting
func (r *Reporter) SetPolicies(policies []policy.Policy) {
	r.policies = policies
}

// SetEvents sets the enforcement events for reporting
func (r *Reporter) SetEvents(events []policy.EnforcementEvent) {
	r.events = events
}

// GenerateReport generates a compliance report
func (r *Reporter) GenerateReport() Report {
	summary := r.calculateSummary()
	pciReqs := r.extractPCIRequirements()

	return Report{
		GeneratedAt:      time.Now(),
		Version:          "1.0",
		ComplianceStatus: summary.ComplianceLevel,
		PCIRequirements:  pciReqs,
		Policies:         r.policies,
		Events:           r.events,
		Summary:          summary,
	}
}

// ExportJSON exports report as JSON
func (r *Reporter) ExportJSON(filename string) error {
	report := r.GenerateReport()

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	return nil
}

// ExportHTML exports report as HTML
func (r *Reporter) ExportHTML(filename string) error {
	report := r.GenerateReport()

	tmpl := template.Must(template.New("report").Parse(htmlTemplate))

	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create HTML file: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, report); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}

// calculateSummary calculates report summary statistics
func (r *Reporter) calculateSummary() ReportSummary {
	summary := ReportSummary{
		TotalPolicies: len(r.policies),
		CDEServers:    0,
		TotalServers:  100, // Mock data
		BlockedEvents: 0,
		AllowedEvents: 0,
	}

	// Count CDE policies
	for _, pol := range r.policies {
		if env, ok := pol.Spec.PodSelector.MatchLabels["pci-env"]; ok && env == "cde" {
			summary.CDEServers++
		}
	}

	// Count blocked/allowed events
	for _, event := range r.events {
		if event.Action == "BLOCKED" {
			summary.BlockedEvents++
		} else if event.Action == "ALLOWED" {
			summary.AllowedEvents++
		}
	}

	// Determine compliance level
	if summary.TotalPolicies > 0 && summary.CDEServers > 0 {
		summary.ComplianceLevel = "COMPLIANT"
	} else {
		summary.ComplianceLevel = "NON-COMPLIANT"
	}

	return summary
}

// extractPCIRequirements extracts all PCI-DSS requirements from policies
func (r *Reporter) extractPCIRequirements() []string {
	reqMap := make(map[string]bool)

	for _, pol := range r.policies {
		if pciReq, ok := pol.Metadata.Annotations["pci-dss"]; ok {
			reqMap[pciReq] = true
		}
	}

	reqs := make([]string, 0, len(reqMap))
	for req := range reqMap {
		reqs = append(reqs, req)
	}

	return reqs
}

// HTML template for compliance report
const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>pci-segment Compliance Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        .section {
            background: white;
            padding: 30px;
            margin-bottom: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .section h2 {
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-top: 0;
        }
        .status-badge {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 1.1em;
        }
        .status-compliant {
            background: #10b981;
            color: white;
        }
        .status-non-compliant {
            background: #ef4444;
            color: white;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }
        .stat-label {
            color: #6b7280;
            margin-top: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }
        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #374151;
        }
        .action-allowed {
            color: #10b981;
            font-weight: bold;
        }
        .action-blocked {
            color: #ef4444;
            font-weight: bold;
        }
        .footer {
            text-align: center;
            color: #6b7280;
            margin-top: 40px;
            padding: 20px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>[pci-segment] Compliance Report</h1>
        <p>PCI-DSS v4.0 Network Segmentation Assessment</p>
        <p>Generated: {{.GeneratedAt.Format "January 2, 2006 at 3:04 PM"}}</p>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <p><strong>Compliance Status:</strong> 
            <span class="status-badge {{if eq .ComplianceStatus "COMPLIANT"}}status-compliant{{else}}status-non-compliant{{end}}">
                {{.ComplianceStatus}}
            </span>
        </p>
        <p><strong>PCI-DSS Requirements Covered:</strong> {{range .PCIRequirements}}{{.}} {{end}}</p>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{{.Summary.CDEServers}}</div>
                <div class="stat-label">CDE Servers</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{.Summary.TotalPolicies}}</div>
                <div class="stat-label">Active Policies</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{.Summary.BlockedEvents}}</div>
                <div class="stat-label">Blocked Events</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{.Summary.AllowedEvents}}</div>
                <div class="stat-label">Allowed Events</div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Policy Details</h2>
        <table>
            <tr>
                <th>Policy Name</th>
                <th>Environment</th>
                <th>PCI-DSS Requirement</th>
            </tr>
            {{range .Policies}}
            <tr>
                <td>{{.Metadata.Name}}</td>
                <td>{{index .Spec.PodSelector.MatchLabels "pci-env"}}</td>
                <td>{{index .Metadata.Annotations "pci-dss"}}</td>
            </tr>
            {{end}}
        </table>
    </div>

    <div class="section">
        <h2>Enforcement Proof</h2>
        {{if .Events}}
        <table>
            <tr>
                <th>Timestamp</th>
                <th>Source IP</th>
                <th>Destination</th>
                <th>Port</th>
                <th>Action</th>
            </tr>
            {{range .Events}}
            <tr>
                <td>{{.Timestamp.Format "15:04:05"}}</td>
                <td>{{.SourceIP}}</td>
                <td>{{.DestIP}}</td>
                <td>{{.DestPort}}</td>
                <td class="{{if eq .Action "ALLOWED"}}action-allowed{{else}}action-blocked{{end}}">{{.Action}}</td>
            </tr>
            {{end}}
        </table>
        {{else}}
        <p>No enforcement events recorded yet.</p>
        {{end}}
    </div>

    <div class="section">
        <h2>Attestation</h2>
        <p>This report was generated by <strong>pci-segment v{{.Version}}</strong> on {{.GeneratedAt.Format "January 2, 2006"}}.</p>
        <p>pci-segment is an open-source, policy-driven microsegmentation tool designed to enforce PCI-DSS v4.0 Requirements 1.2 and 1.3 for network segmentation of the Cardholder Data Environment (CDE).</p>
    </div>

    <div class="footer">
        <p>pci-segment - Open Source PCI-DSS Microsegmentation</p>
        <p>© 2025 · Licensed under MIT</p>
    </div>
</body>
</html>
`
