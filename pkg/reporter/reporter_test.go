package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/msaadshabir/pci-segment/pkg/policy"
)

func TestNewReporter(t *testing.T) {
	r := NewReporter()
	if r == nil {
		t.Fatal("NewReporter() returned nil")
	}
	if r.policies == nil {
		t.Error("policies slice not initialized")
	}
	if r.events == nil {
		t.Error("events slice not initialized")
	}
}

func TestReporter_SetPolicies(t *testing.T) {
	r := NewReporter()

	policies := []policy.Policy{
		{
			APIVersion: "pci-segment/v1",
			Kind:       "NetworkPolicy",
			Metadata: policy.Metadata{
				Name: "test-policy",
				Annotations: map[string]string{
					"pci-dss": "Req 1.2",
				},
			},
			Spec: policy.Spec{
				PodSelector: policy.PodSelector{
					MatchLabels: map[string]string{
						"pci-env": "cde",
					},
				},
			},
		},
	}

	r.SetPolicies(policies)

	if len(r.policies) != 1 {
		t.Errorf("SetPolicies() did not set policies correctly, got %d policies", len(r.policies))
	}
	if r.policies[0].Metadata.Name != "test-policy" {
		t.Errorf("Policy name = %s, want test-policy", r.policies[0].Metadata.Name)
	}
}

func TestReporter_SetEvents(t *testing.T) {
	r := NewReporter()

	events := []policy.EnforcementEvent{
		{
			Timestamp:  time.Now(),
			SourceIP:   "10.0.1.100",
			DestIP:     "10.0.2.200",
			DestPort:   443,
			Protocol:   "TCP",
			Action:     "BLOCKED",
			PolicyName: "test-policy",
			PCIDSSReq:  "Req 1.2",
		},
	}

	r.SetEvents(events)

	if len(r.events) != 1 {
		t.Errorf("SetEvents() did not set events correctly, got %d events", len(r.events))
	}
	if r.events[0].SourceIP != "10.0.1.100" {
		t.Errorf("Event SourceIP = %s, want 10.0.1.100", r.events[0].SourceIP)
	}
}

func TestReporter_GenerateReport(t *testing.T) {
	r := NewReporter()

	policies := []policy.Policy{
		{
			APIVersion: "pci-segment/v1",
			Kind:       "NetworkPolicy",
			Metadata: policy.Metadata{
				Name: "cde-isolation",
				Annotations: map[string]string{
					"pci-dss": "Req 1.2",
				},
			},
			Spec: policy.Spec{
				PodSelector: policy.PodSelector{
					MatchLabels: map[string]string{
						"pci-env": "cde",
					},
				},
			},
		},
		{
			APIVersion: "pci-segment/v1",
			Kind:       "NetworkPolicy",
			Metadata: policy.Metadata{
				Name: "db-isolation",
				Annotations: map[string]string{
					"pci-dss": "Req 1.3",
				},
			},
			Spec: policy.Spec{
				PodSelector: policy.PodSelector{
					MatchLabels: map[string]string{
						"pci-env": "cde",
					},
				},
			},
		},
	}

	events := []policy.EnforcementEvent{
		{
			Timestamp:  time.Now(),
			SourceIP:   "10.0.1.100",
			DestIP:     "10.0.2.200",
			DestPort:   443,
			Protocol:   "TCP",
			Action:     "BLOCKED",
			PolicyName: "cde-isolation",
		},
		{
			Timestamp:  time.Now(),
			SourceIP:   "10.0.1.50",
			DestIP:     "10.0.2.100",
			DestPort:   443,
			Protocol:   "TCP",
			Action:     "ALLOWED",
			PolicyName: "cde-isolation",
		},
		{
			Timestamp:  time.Now(),
			SourceIP:   "192.168.1.50",
			DestIP:     "10.0.3.100",
			DestPort:   3306,
			Protocol:   "TCP",
			Action:     "BLOCKED",
			PolicyName: "db-isolation",
		},
	}

	r.SetPolicies(policies)
	r.SetEvents(events)

	report := r.GenerateReport()

	if report.Version != "1.0" {
		t.Errorf("Version = %s, want 1.0", report.Version)
	}

	if report.GeneratedAt.IsZero() {
		t.Error("GeneratedAt is zero")
	}

	if report.Summary.TotalPolicies != 2 {
		t.Errorf("TotalPolicies = %d, want 2", report.Summary.TotalPolicies)
	}

	if report.Summary.CDEServers != 2 {
		t.Errorf("CDEServers = %d, want 2", report.Summary.CDEServers)
	}

	if report.Summary.BlockedEvents != 2 {
		t.Errorf("BlockedEvents = %d, want 2", report.Summary.BlockedEvents)
	}

	if report.Summary.AllowedEvents != 1 {
		t.Errorf("AllowedEvents = %d, want 1", report.Summary.AllowedEvents)
	}

	if report.ComplianceStatus != "COMPLIANT" {
		t.Errorf("ComplianceStatus = %s, want COMPLIANT", report.ComplianceStatus)
	}

	if len(report.PCIRequirements) != 2 {
		t.Errorf("PCIRequirements count = %d, want 2", len(report.PCIRequirements))
	}
}

func TestReporter_GenerateReport_NonCompliant(t *testing.T) {
	r := NewReporter()

	report := r.GenerateReport()

	if report.ComplianceStatus != "NON-COMPLIANT" {
		t.Errorf("ComplianceStatus = %s, want NON-COMPLIANT", report.ComplianceStatus)
	}
	if report.Summary.ComplianceLevel != "NON-COMPLIANT" {
		t.Errorf("Summary.ComplianceLevel = %s, want NON-COMPLIANT", report.Summary.ComplianceLevel)
	}
}

func TestReporter_GenerateReport_NoCDEPolicies(t *testing.T) {
	r := NewReporter()

	policies := []policy.Policy{
		{
			APIVersion: "pci-segment/v1",
			Kind:       "NetworkPolicy",
			Metadata: policy.Metadata{
				Name: "non-cde-policy",
			},
			Spec: policy.Spec{
				PodSelector: policy.PodSelector{
					MatchLabels: map[string]string{
						"app": "web",
					},
				},
			},
		},
	}

	r.SetPolicies(policies)
	report := r.GenerateReport()

	if report.ComplianceStatus != "NON-COMPLIANT" {
		t.Errorf("ComplianceStatus = %s, want NON-COMPLIANT (no CDE policies)", report.ComplianceStatus)
	}
	if report.Summary.CDEServers != 0 {
		t.Errorf("CDEServers = %d, want 0", report.Summary.CDEServers)
	}
}

func TestReporter_ExportJSON(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")

	r := NewReporter()

	policies := []policy.Policy{
		{
			APIVersion: "pci-segment/v1",
			Kind:       "NetworkPolicy",
			Metadata: policy.Metadata{
				Name: "test-policy",
				Annotations: map[string]string{
					"pci-dss": "Req 1.2",
				},
			},
			Spec: policy.Spec{
				PodSelector: policy.PodSelector{
					MatchLabels: map[string]string{
						"pci-env": "cde",
					},
				},
			},
		},
	}

	r.SetPolicies(policies)

	if err := r.ExportJSON(outputPath); err != nil {
		t.Fatalf("ExportJSON() failed: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read JSON file: %v", err)
	}

	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if report.Version != "1.0" {
		t.Errorf("JSON Version = %s, want 1.0", report.Version)
	}
	if len(report.Policies) != 1 {
		t.Errorf("JSON Policies count = %d, want 1", len(report.Policies))
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("Failed to stat JSON file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("JSON file permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestReporter_ExportJSON_InvalidPath(t *testing.T) {
	r := NewReporter()

	invalidPath := "/nonexistent/directory/report.json"

	err := r.ExportJSON(invalidPath)
	if err == nil {
		t.Error("ExportJSON() should fail with invalid path")
	}
}

func TestReporter_ExportHTML(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.html")

	r := NewReporter()

	policies := []policy.Policy{
		{
			APIVersion: "pci-segment/v1",
			Kind:       "NetworkPolicy",
			Metadata: policy.Metadata{
				Name: "cde-isolation",
				Annotations: map[string]string{
					"pci-dss": "Req 1.2",
				},
			},
			Spec: policy.Spec{
				PodSelector: policy.PodSelector{
					MatchLabels: map[string]string{
						"pci-env": "cde",
					},
				},
			},
		},
	}

	events := []policy.EnforcementEvent{
		{
			Timestamp:  time.Now(),
			SourceIP:   "10.0.1.100",
			DestIP:     "10.0.2.200",
			DestPort:   443,
			Protocol:   "TCP",
			Action:     "BLOCKED",
			PolicyName: "cde-isolation",
		},
	}

	r.SetPolicies(policies)
	r.SetEvents(events)

	if err := r.ExportHTML(outputPath); err != nil {
		t.Fatalf("ExportHTML() failed: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read HTML file: %v", err)
	}

	content := string(data)

	if !strings.Contains(content, "<!DOCTYPE html>") {
		t.Error("HTML missing DOCTYPE")
	}
	if !strings.Contains(content, "pci-segment") {
		t.Error("HTML missing pci-segment branding")
	}
	if !strings.Contains(content, "PCI-DSS") {
		t.Error("HTML missing PCI-DSS reference")
	}
	if !strings.Contains(content, "cde-isolation") {
		t.Error("HTML missing policy name")
	}
	if !strings.Contains(content, "10.0.1.100") {
		t.Error("HTML missing event source IP")
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("Failed to stat HTML file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("HTML file permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestReporter_ExportHTML_InvalidPath(t *testing.T) {
	r := NewReporter()

	invalidPath := "/nonexistent/directory/report.html"

	err := r.ExportHTML(invalidPath)
	if err == nil {
		t.Error("ExportHTML() should fail with invalid path")
	}
}

func TestReporter_ExportHTML_NoEvents(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.html")

	r := NewReporter()

	policies := []policy.Policy{
		{
			APIVersion: "pci-segment/v1",
			Kind:       "NetworkPolicy",
			Metadata: policy.Metadata{
				Name: "test-policy",
			},
		},
	}

	r.SetPolicies(policies)

	if err := r.ExportHTML(outputPath); err != nil {
		t.Fatalf("ExportHTML() failed: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read HTML file: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "No enforcement events recorded yet") {
		t.Error("HTML should show 'no events' message when events list is empty")
	}
}

func TestReporter_calculateSummary(t *testing.T) {
	tests := []struct {
		name     string
		policies []policy.Policy
		events   []policy.EnforcementEvent
		want     ReportSummary
	}{
		{
			name:     "empty reporter",
			policies: []policy.Policy{},
			events:   []policy.EnforcementEvent{},
			want: ReportSummary{
				TotalPolicies:   0,
				CDEServers:      0,
				BlockedEvents:   0,
				AllowedEvents:   0,
				ComplianceLevel: "NON-COMPLIANT",
			},
		},
		{
			name: "mixed events",
			policies: []policy.Policy{
				{
					Metadata: policy.Metadata{Name: "p1"},
					Spec: policy.Spec{
						PodSelector: policy.PodSelector{
							MatchLabels: map[string]string{"pci-env": "cde"},
						},
					},
				},
			},
			events: []policy.EnforcementEvent{
				{Action: "BLOCKED"},
				{Action: "BLOCKED"},
				{Action: "ALLOWED"},
				{Action: "ALLOWED"},
				{Action: "ALLOWED"},
			},
			want: ReportSummary{
				TotalPolicies:   1,
				CDEServers:      1,
				BlockedEvents:   2,
				AllowedEvents:   3,
				ComplianceLevel: "COMPLIANT",
			},
		},
		{
			name: "non-cde policies only",
			policies: []policy.Policy{
				{
					Metadata: policy.Metadata{Name: "p1"},
					Spec: policy.Spec{
						PodSelector: policy.PodSelector{
							MatchLabels: map[string]string{"app": "web"},
						},
					},
				},
			},
			events: []policy.EnforcementEvent{},
			want: ReportSummary{
				TotalPolicies:   1,
				CDEServers:      0,
				BlockedEvents:   0,
				AllowedEvents:   0,
				ComplianceLevel: "NON-COMPLIANT",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReporter()
			r.SetPolicies(tt.policies)
			r.SetEvents(tt.events)

			report := r.GenerateReport()
			summary := report.Summary

			if summary.TotalPolicies != tt.want.TotalPolicies {
				t.Errorf("TotalPolicies = %d, want %d", summary.TotalPolicies, tt.want.TotalPolicies)
			}
			if summary.CDEServers != tt.want.CDEServers {
				t.Errorf("CDEServers = %d, want %d", summary.CDEServers, tt.want.CDEServers)
			}
			if summary.BlockedEvents != tt.want.BlockedEvents {
				t.Errorf("BlockedEvents = %d, want %d", summary.BlockedEvents, tt.want.BlockedEvents)
			}
			if summary.AllowedEvents != tt.want.AllowedEvents {
				t.Errorf("AllowedEvents = %d, want %d", summary.AllowedEvents, tt.want.AllowedEvents)
			}
			if summary.ComplianceLevel != tt.want.ComplianceLevel {
				t.Errorf("ComplianceLevel = %s, want %s", summary.ComplianceLevel, tt.want.ComplianceLevel)
			}
		})
	}
}

func TestReporter_extractPCIRequirements(t *testing.T) {
	tests := []struct {
		name     string
		policies []policy.Policy
		wantLen  int
	}{
		{
			name:     "no policies",
			policies: []policy.Policy{},
			wantLen:  0,
		},
		{
			name: "policies without pci-dss annotation",
			policies: []policy.Policy{
				{Metadata: policy.Metadata{Name: "p1", Annotations: map[string]string{}}},
				{Metadata: policy.Metadata{Name: "p2", Annotations: nil}},
			},
			wantLen: 0,
		},
		{
			name: "policies with unique pci-dss annotations",
			policies: []policy.Policy{
				{Metadata: policy.Metadata{Name: "p1", Annotations: map[string]string{"pci-dss": "Req 1.2"}}},
				{Metadata: policy.Metadata{Name: "p2", Annotations: map[string]string{"pci-dss": "Req 1.3"}}},
			},
			wantLen: 2,
		},
		{
			name: "policies with duplicate pci-dss annotations",
			policies: []policy.Policy{
				{Metadata: policy.Metadata{Name: "p1", Annotations: map[string]string{"pci-dss": "Req 1.2"}}},
				{Metadata: policy.Metadata{Name: "p2", Annotations: map[string]string{"pci-dss": "Req 1.2"}}},
				{Metadata: policy.Metadata{Name: "p3", Annotations: map[string]string{"pci-dss": "Req 1.3"}}},
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReporter()
			r.SetPolicies(tt.policies)

			report := r.GenerateReport()

			if len(report.PCIRequirements) != tt.wantLen {
				t.Errorf("PCIRequirements count = %d, want %d", len(report.PCIRequirements), tt.wantLen)
			}
		})
	}
}

func TestReport_JSONSerialization(t *testing.T) {
	report := Report{
		GeneratedAt:      time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Version:          "1.0",
		ComplianceStatus: "COMPLIANT",
		PCIRequirements:  []string{"Req 1.2", "Req 1.3"},
		Policies: []policy.Policy{
			{
				APIVersion: "pci-segment/v1",
				Kind:       "NetworkPolicy",
				Metadata:   policy.Metadata{Name: "test"},
			},
		},
		Events: []policy.EnforcementEvent{
			{
				Timestamp:  time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
				SourceIP:   "10.0.1.1",
				DestIP:     "10.0.2.2",
				DestPort:   443,
				Protocol:   "TCP",
				Action:     "BLOCKED",
				PolicyName: "test",
			},
		},
		Summary: ReportSummary{
			TotalPolicies:   1,
			CDEServers:      1,
			TotalServers:    10,
			BlockedEvents:   1,
			AllowedEvents:   0,
			ComplianceLevel: "COMPLIANT",
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Failed to marshal report: %v", err)
	}

	var unmarshaled Report
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal report: %v", err)
	}

	if unmarshaled.Version != report.Version {
		t.Errorf("Version = %s, want %s", unmarshaled.Version, report.Version)
	}
	if unmarshaled.ComplianceStatus != report.ComplianceStatus {
		t.Errorf("ComplianceStatus = %s, want %s", unmarshaled.ComplianceStatus, report.ComplianceStatus)
	}
	if len(unmarshaled.PCIRequirements) != len(report.PCIRequirements) {
		t.Errorf("PCIRequirements length = %d, want %d", len(unmarshaled.PCIRequirements), len(report.PCIRequirements))
	}
	if unmarshaled.Summary.TotalPolicies != report.Summary.TotalPolicies {
		t.Errorf("Summary.TotalPolicies = %d, want %d", unmarshaled.Summary.TotalPolicies, report.Summary.TotalPolicies)
	}
}

func TestReportSummary_JSONTags(t *testing.T) {
	summary := ReportSummary{
		TotalPolicies:   5,
		CDEServers:      3,
		TotalServers:    10,
		BlockedEvents:   100,
		AllowedEvents:   50,
		ComplianceLevel: "COMPLIANT",
	}

	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("Failed to marshal summary: %v", err)
	}

	jsonStr := string(data)

	expectedFields := []string{
		`"total_policies"`,
		`"cde_servers"`,
		`"total_servers"`,
		`"blocked_events"`,
		`"allowed_events"`,
		`"compliance_level"`,
	}

	for _, field := range expectedFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("JSON missing expected field: %s", field)
		}
	}
}
