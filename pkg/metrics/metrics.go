// Package metrics provides Prometheus metrics for PCI-DSS compliance monitoring
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	namespace = "pci_segment"
)

// Enforcer metrics
var (
	// EnforcerPacketsTotal counts packets processed by direction and action
	EnforcerPacketsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "enforcer",
			Name:      "packets_total",
			Help:      "Total packets processed by the enforcer",
		},
		[]string{"action"}, // allowed, blocked
	)

	// EnforcerRulesTotal tracks current active rules by direction
	EnforcerRulesTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "enforcer",
			Name:      "rules_total",
			Help:      "Current number of active enforcement rules",
		},
		[]string{"direction"}, // ingress, egress
	)

	// EnforcerPoliciesTotal tracks loaded policies
	EnforcerPoliciesTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "enforcer",
			Name:      "policies_total",
			Help:      "Number of loaded policies",
		},
	)

	// EnforcerRunning indicates if enforcer is active
	EnforcerRunning = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "enforcer",
			Name:      "running",
			Help:      "1 if enforcer is running, 0 otherwise",
		},
	)

	// EnforcerEventsTotal counts enforcement events logged
	EnforcerEventsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "enforcer",
			Name:      "events_total",
			Help:      "Total enforcement events logged",
		},
	)
)

// Policy metrics
var (
	// PolicyValidationsTotal counts validation attempts by result
	PolicyValidationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "policy",
			Name:      "validations_total",
			Help:      "Policy validation attempts",
		},
		[]string{"result"}, // valid, invalid
	)

	// PolicyLoadDuration tracks time to load policies
	PolicyLoadDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "policy",
			Name:      "load_duration_seconds",
			Help:      "Time to load and parse policies",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// PolicyCDETotal tracks CDE-labeled policies
	PolicyCDETotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "policy",
			Name:      "cde_policies_total",
			Help:      "Number of CDE-labeled policies",
		},
	)
)

// Audit metrics
var (
	// AuditEventsTotal counts audit events logged
	AuditEventsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "audit",
			Name:      "events_total",
			Help:      "Total audit events logged",
		},
	)

	// AuditFailedWritesTotal counts failed audit writes
	AuditFailedWritesTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "audit",
			Name:      "failed_writes_total",
			Help:      "Failed audit log writes",
		},
	)

	// AuditChecksumFailuresTotal counts integrity check failures
	AuditChecksumFailuresTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "audit",
			Name:      "checksum_failures_total",
			Help:      "Integrity check failures",
		},
	)

	// AuditRotationsTotal counts log rotations
	AuditRotationsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "audit",
			Name:      "rotations_total",
			Help:      "Log rotations performed",
		},
	)

	// AuditFileSizeBytes tracks current audit log size
	AuditFileSizeBytes = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "audit",
			Name:      "file_size_bytes",
			Help:      "Current audit log file size",
		},
	)
)

// Cloud sync metrics
var (
	// CloudSyncTotal counts sync operations by provider and result
	CloudSyncTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "cloud",
			Name:      "sync_total",
			Help:      "Cloud sync operations",
		},
		[]string{"provider", "result"}, // aws/azure, success/error
	)

	// CloudSyncDuration tracks sync operation duration
	CloudSyncDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "cloud",
			Name:      "sync_duration_seconds",
			Help:      "Time for cloud sync operations",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"provider"}, // aws, azure
	)

	// CloudResourcesTotal tracks managed cloud resources
	CloudResourcesTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "cloud",
			Name:      "resources_total",
			Help:      "Cloud resources managed",
		},
		[]string{"provider", "operation"}, // added, updated, deleted
	)

	// CloudViolationsTotal tracks policy violations in cloud
	CloudViolationsTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "cloud",
			Name:      "violations_total",
			Help:      "Policy violations detected in cloud",
		},
		[]string{"provider"},
	)
)

// Build info metric
var (
	// BuildInfo exposes build information
	BuildInfo = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "build_info",
			Help:      "Build information",
		},
		[]string{"version", "go_version"},
	)
)

// SetBuildInfo sets the build information metric
func SetBuildInfo(version, goVersion string) {
	BuildInfo.WithLabelValues(version, goVersion).Set(1)
}
