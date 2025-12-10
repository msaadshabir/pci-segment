package metrics

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/msaadshabir/pci-segment/pkg/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ServerConfig holds metrics server configuration
type ServerConfig struct {
	// Addr is the address to listen on (e.g., ":9090" or "127.0.0.1:9090")
	Addr string

	// Path is the metrics endpoint path (default: "/metrics")
	Path string

	// ReadTimeout is the maximum duration for reading the request
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration for writing the response
	WriteTimeout time.Duration
}

// DefaultServerConfig returns sensible defaults for the metrics server
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Addr:         ":9090",
		Path:         "/metrics",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
}

// Server wraps an HTTP server for Prometheus metrics
type Server struct {
	config   ServerConfig
	server   *http.Server
	registry *prometheus.Registry
}

// NewServer creates a new metrics server
func NewServer(cfg ServerConfig) *Server {
	if cfg.Path == "" {
		cfg.Path = "/metrics"
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 5 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 10 * time.Second
	}

	// Create custom registry to avoid default process/go metrics if desired
	// Using default registry to include standard Go runtime metrics
	registry := prometheus.DefaultRegisterer.(*prometheus.Registry)

	return &Server{
		config:   cfg,
		registry: registry,
	}
}

// RegisterCollector registers a Prometheus collector
func (s *Server) RegisterCollector(collector prometheus.Collector) error {
	return prometheus.Register(collector)
}

// Start starts the metrics HTTP server in a goroutine
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Metrics endpoint
	mux.Handle(s.config.Path, promhttp.Handler())

	// Health check endpoint (basic liveness)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Readiness check endpoint
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	s.server = &http.Server{
		Addr:         s.config.Addr,
		Handler:      mux,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
	}

	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("metrics server error", "error", err)
		}
	}()

	log.Info("metrics server started", "addr", s.config.Addr, "path", s.config.Path)
	return nil
}

// Stop gracefully shuts down the metrics server
func (s *Server) Stop(ctx context.Context) error {
	if s.server == nil {
		return nil
	}

	log.Info("shutting down metrics server")
	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("metrics server shutdown failed: %w", err)
	}

	log.Info("metrics server stopped")
	return nil
}

// Addr returns the configured address
func (s *Server) Addr() string {
	return s.config.Addr
}
