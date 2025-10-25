package cloud

import (
	"fmt"
)

// NewIntegrator creates a cloud integrator based on configuration
func NewIntegrator(cfg *Config) (Integrator, error) {
	switch cfg.Provider {
	case ProviderAWS:
		return NewAWSIntegrator(cfg)
	case ProviderAzure:
		return NewAzureIntegrator(cfg)
	default:
		return nil, fmt.Errorf("unsupported cloud provider: %s", cfg.Provider)
	}
}
