package metrics

import (
	"github.com/msaadshabir/pci-segment/pkg/audit"
	"github.com/msaadshabir/pci-segment/pkg/enforcer"
	"github.com/msaadshabir/pci-segment/pkg/policy"
	"github.com/prometheus/client_golang/prometheus"
)

// EnforcerCollector collects metrics from an Enforcer
type EnforcerCollector struct {
	enforcer enforcer.Enforcer

	// Descriptors for custom metrics
	packetsAllowed *prometheus.Desc
	packetsBlocked *prometheus.Desc
	packetsTotal   *prometheus.Desc
	running        *prometheus.Desc
	policies       *prometheus.Desc
}

// NewEnforcerCollector creates a new EnforcerCollector
func NewEnforcerCollector(enf enforcer.Enforcer) *EnforcerCollector {
	return &EnforcerCollector{
		enforcer: enf,
		packetsAllowed: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "enforcer", "packets_allowed_total"),
			"Total packets allowed by enforcer",
			nil, nil,
		),
		packetsBlocked: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "enforcer", "packets_blocked_total"),
			"Total packets blocked by enforcer",
			nil, nil,
		),
		packetsTotal: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "enforcer", "packets_processed_total"),
			"Total packets processed by enforcer",
			nil, nil,
		),
		running: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "enforcer", "running_status"),
			"1 if enforcer is running, 0 otherwise",
			nil, nil,
		),
		policies: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "enforcer", "loaded_policies"),
			"Number of policies loaded in enforcer",
			nil, nil,
		),
	}
}

// Describe implements prometheus.Collector
func (c *EnforcerCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.packetsAllowed
	ch <- c.packetsBlocked
	ch <- c.packetsTotal
	ch <- c.running
	ch <- c.policies
}

// Collect implements prometheus.Collector
func (c *EnforcerCollector) Collect(ch chan<- prometheus.Metric) {
	// Check if enforcer is running
	runningValue := 0.0
	if c.enforcer.IsRunning() {
		runningValue = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.running, prometheus.GaugeValue, runningValue)

	// Try to get stats if enforcer supports it
	if statsEnforcer, ok := c.enforcer.(interface {
		GetStats() (allowed, blocked, total uint64, err error)
	}); ok && c.enforcer.IsRunning() {
		allowed, blocked, total, err := statsEnforcer.GetStats()
		if err == nil {
			ch <- prometheus.MustNewConstMetric(c.packetsAllowed, prometheus.CounterValue, float64(allowed))
			ch <- prometheus.MustNewConstMetric(c.packetsBlocked, prometheus.CounterValue, float64(blocked))
			ch <- prometheus.MustNewConstMetric(c.packetsTotal, prometheus.CounterValue, float64(total))
		}
	}

	// Count events as proxy for policies
	events := c.enforcer.GetEvents()
	ch <- prometheus.MustNewConstMetric(c.policies, prometheus.GaugeValue, float64(len(events)))
}

// AuditCollector collects metrics from an audit Logger
type AuditCollector struct {
	logger audit.Logger

	// Descriptors
	totalEvents      *prometheus.Desc
	failedWrites     *prometheus.Desc
	checksumFailures *prometheus.Desc
	rotatedFiles     *prometheus.Desc
	currentFileSize  *prometheus.Desc
}

// NewAuditCollector creates a new AuditCollector
func NewAuditCollector(logger audit.Logger) *AuditCollector {
	return &AuditCollector{
		logger: logger,
		totalEvents: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "audit", "logged_events_total"),
			"Total audit events logged",
			nil, nil,
		),
		failedWrites: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "audit", "write_failures_total"),
			"Failed audit log writes",
			nil, nil,
		),
		checksumFailures: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "audit", "integrity_failures_total"),
			"Checksum integrity check failures",
			nil, nil,
		),
		rotatedFiles: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "audit", "rotated_files_total"),
			"Total rotated log files",
			nil, nil,
		),
		currentFileSize: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "audit", "current_file_size_bytes"),
			"Current audit log file size in bytes",
			nil, nil,
		),
	}
}

// Describe implements prometheus.Collector
func (c *AuditCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.totalEvents
	ch <- c.failedWrites
	ch <- c.checksumFailures
	ch <- c.rotatedFiles
	ch <- c.currentFileSize
}

// Collect implements prometheus.Collector
func (c *AuditCollector) Collect(ch chan<- prometheus.Metric) {
	stats := c.logger.GetStats()

	ch <- prometheus.MustNewConstMetric(c.totalEvents, prometheus.CounterValue, float64(stats.TotalEvents))
	ch <- prometheus.MustNewConstMetric(c.failedWrites, prometheus.CounterValue, float64(stats.FailedWrites))
	ch <- prometheus.MustNewConstMetric(c.checksumFailures, prometheus.CounterValue, float64(stats.ChecksumFailures))
	ch <- prometheus.MustNewConstMetric(c.rotatedFiles, prometheus.CounterValue, float64(stats.RotatedFiles))
	ch <- prometheus.MustNewConstMetric(c.currentFileSize, prometheus.GaugeValue, float64(stats.CurrentFileSize))
}

// PolicyCollector collects metrics from a policy Engine
type PolicyCollector struct {
	engine *policy.Engine

	// Descriptors
	policiesTotal    *prometheus.Desc
	cdePoliciesTotal *prometheus.Desc
}

// NewPolicyCollector creates a new PolicyCollector
func NewPolicyCollector(engine *policy.Engine) *PolicyCollector {
	return &PolicyCollector{
		engine: engine,
		policiesTotal: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "policy", "loaded_total"),
			"Total policies loaded in engine",
			nil, nil,
		),
		cdePoliciesTotal: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "policy", "cde_total"),
			"Number of CDE-labeled policies",
			nil, nil,
		),
	}
}

// Describe implements prometheus.Collector
func (c *PolicyCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.policiesTotal
	ch <- c.cdePoliciesTotal
}

// Collect implements prometheus.Collector
func (c *PolicyCollector) Collect(ch chan<- prometheus.Metric) {
	policies := c.engine.GetPolicies()

	totalPolicies := float64(len(policies))
	cdePolicies := 0.0

	for _, p := range policies {
		if p.Spec.PodSelector.MatchLabels != nil {
			if env, ok := p.Spec.PodSelector.MatchLabels["pci-env"]; ok && env == "cde" {
				cdePolicies++
			}
		}
	}

	ch <- prometheus.MustNewConstMetric(c.policiesTotal, prometheus.GaugeValue, totalPolicies)
	ch <- prometheus.MustNewConstMetric(c.cdePoliciesTotal, prometheus.GaugeValue, cdePolicies)
}
