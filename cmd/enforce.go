package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/msaadshabir/pci-segment/pkg/enforcer"
	"github.com/msaadshabir/pci-segment/pkg/log"
	"github.com/msaadshabir/pci-segment/pkg/metrics"
	"github.com/msaadshabir/pci-segment/pkg/policy"
	"github.com/msaadshabir/pci-segment/pkg/security/privilege"
	"github.com/spf13/cobra"
)

var enforceCmd = &cobra.Command{
	Use:   "enforce",
	Short: "Enforce PCI-DSS network policies",
	Long:  `Enforce network segmentation policies to comply with PCI-DSS Requirements 1.2 and 1.3`,
	Example: `  pci-segment enforce -f policies/cde-isolation.yaml
  pci-segment enforce -f policies/*.yaml --compliance=pci
  pci-segment enforce -f policies/*.yaml --metrics-addr=:9090`,
	RunE: runEnforce,
}

var (
	complianceMode string
	allowRoot      bool
	metricsAddr    string
	metricsPath    string
)

func init() {
	rootCmd.AddCommand(enforceCmd)
	enforceCmd.Flags().StringVarP(&policyFile, "file", "f", "", "policy file or glob pattern (required)")
	enforceCmd.Flags().StringVar(&complianceMode, "compliance", "pci", "compliance mode (pci, soc2)")
	enforceCmd.Flags().BoolVar(&allowRoot, "allow-root", false, "allow running enforcement as root (disables privilege drop)")
	enforceCmd.Flags().StringVar(&metricsAddr, "metrics-addr", "", "address for Prometheus metrics endpoint (e.g., :9090)")
	enforceCmd.Flags().StringVar(&metricsPath, "metrics-path", "/metrics", "path for metrics endpoint")
	if err := enforceCmd.MarkFlagRequired("file"); err != nil {
		cobra.CheckErr(fmt.Errorf("failed to mark flag required: %w", err))
	}
}

func runEnforce(_ *cobra.Command, _ []string) error {
	if runtime.GOOS == "linux" && !allowRoot {
		cfg := privilege.FromEnv()
		if err := privilege.Ensure(cfg); err != nil {
			return fmt.Errorf("privilege hardening failed: %w", err)
		}
	}

	engine := policy.NewEngine()

	log.Debug("loading policy", "file", policyFile)

	loadStart := time.Now()
	if err := engine.LoadFromFile(policyFile); err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}
	loadDuration := time.Since(loadStart)

	policies := engine.GetPolicies()
	log.Info("policies loaded", "count", len(policies))

	// Update metrics for policy load
	if metricsAddr != "" {
		metrics.PolicyLoadDuration.Observe(loadDuration.Seconds())
		metrics.EnforcerPoliciesTotal.Set(float64(len(policies)))

		// Count CDE policies
		cdeCount := 0
		for _, p := range policies {
			if p.Spec.PodSelector.MatchLabels != nil {
				if env, ok := p.Spec.PodSelector.MatchLabels["pci-env"]; ok && env == "cde" {
					cdeCount++
				}
			}
		}
		metrics.PolicyCDETotal.Set(float64(cdeCount))
	}

	// Validate policies
	for _, pol := range policies {
		result := engine.Validate(&pol)
		if !result.Valid {
			if metricsAddr != "" {
				metrics.PolicyValidationsTotal.WithLabelValues("invalid").Inc()
			}
			return fmt.Errorf("policy validation failed for '%s': %v", pol.Metadata.Name, result.Errors)
		}
		if metricsAddr != "" {
			metrics.PolicyValidationsTotal.WithLabelValues("valid").Inc()
		}
		if len(result.Warnings) > 0 {
			log.Warn("policy has warnings", "policy", pol.Metadata.Name, "warnings", result.Warnings)
		}
		if len(result.PCIRequirements) > 0 {
			log.Info("policy validated", "policy", pol.Metadata.Name, "pci_requirements", result.PCIRequirements)
		}
	}

	// Create enforcer
	enf, err := enforcer.NewEnforcer()
	if err != nil {
		return fmt.Errorf("failed to create enforcer: %w", err)
	}

	// Add policies to enforcer
	for i := range policies {
		if err := enf.AddPolicy(&policies[i]); err != nil {
			return fmt.Errorf("failed to add policy: %w", err)
		}
	}

	log.Info("starting PCI-DSS enforcement")
	if err := enf.Start(); err != nil {
		return fmt.Errorf("failed to start enforcer: %w", err)
	}

	log.Info("enforcement active")

	// Update enforcer running metric
	if metricsAddr != "" {
		metrics.EnforcerRunning.Set(1)
	}

	// Start metrics server if configured
	var metricsServer *metrics.Server
	if metricsAddr != "" {
		// Set build info
		metrics.SetBuildInfo("0.1.0", runtime.Version())

		metricsServer = metrics.NewServer(metrics.ServerConfig{
			Addr: metricsAddr,
			Path: metricsPath,
		})

		// Register collectors
		enforcerCollector := metrics.NewEnforcerCollector(enf)
		if err := metricsServer.RegisterCollector(enforcerCollector); err != nil {
			log.Warn("failed to register enforcer collector", "error", err)
		}

		policyCollector := metrics.NewPolicyCollector(engine)
		if err := metricsServer.RegisterCollector(policyCollector); err != nil {
			log.Warn("failed to register policy collector", "error", err)
		}

		if err := metricsServer.Start(); err != nil {
			return fmt.Errorf("failed to start metrics server: %w", err)
		}
	}

	log.Info("press Ctrl+C to stop enforcement")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	if metricsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := metricsServer.Stop(ctx); err != nil {
			log.Warn("failed to stop metrics server", "error", err)
		}
	}

	// Update enforcer running metric
	if metricsAddr != "" {
		metrics.EnforcerRunning.Set(0)
	}

	log.Info("stopping enforcement")
	if err := enf.Stop(); err != nil {
		return fmt.Errorf("failed to stop enforcer: %w", err)
	}

	log.Info("enforcement stopped")
	return nil
}
