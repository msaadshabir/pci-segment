// Package audit provides persistent, tamper-proof audit logging for PCI-DSS compliance
package audit

import (
	"time"

	"github.com/msaadshabir/pci-segment/pkg/policy"
)

// EnforcementEvent is an alias for policy.EnforcementEvent for convenience
type EnforcementEvent = policy.EnforcementEvent

// Logger defines the interface for persistent audit logging
type Logger interface {
	// Log writes an enforcement event to persistent storage
	Log(event EnforcementEvent) error

	// LogBatch writes multiple events atomically
	LogBatch(events []EnforcementEvent) error

	// Verify checks log file integrity using checksums
	Verify() (bool, error)

	// Rotate triggers manual log rotation
	Rotate() error

	// Close closes the logger and flushes pending writes
	Close() error

	// GetStats returns logging statistics
	GetStats() Stats
}

// Stats holds audit logging statistics
type Stats struct {
	TotalEvents       uint64    `json:"total_events"`
	EventsLastRotate  uint64    `json:"events_last_rotate"`
	LastRotation      time.Time `json:"last_rotation"`
	CurrentFileSize   int64     `json:"current_file_size_bytes"`
	RotatedFiles      int       `json:"rotated_files"`
	FailedWrites      uint64    `json:"failed_writes"`
	ChecksumFailures  uint64    `json:"checksum_failures"`
	LastChecksumCheck time.Time `json:"last_checksum_check"`
}

// Config holds audit logger configuration
type Config struct {
	// LogFilePath is the path to the audit log file
	LogFilePath string `yaml:"log_file_path" json:"log_file_path"`

	// MaxFileSizeMB is the maximum size before rotation (default: 100MB per PCI-DSS)
	MaxFileSizeMB int `yaml:"max_file_size_mb" json:"max_file_size_mb"`

	// RotateDaily enables daily rotation regardless of size
	RotateDaily bool `yaml:"rotate_daily" json:"rotate_daily"`

	// RetentionDays is how many days to keep rotated logs (default: 90 per PCI-DSS)
	RetentionDays int `yaml:"retention_days" json:"retention_days"`

	// ChecksumDBPath is the path to the checksum database
	ChecksumDBPath string `yaml:"checksum_db_path" json:"checksum_db_path"`

	// FileMode is the permission mode for log files (default: 0600)
	FileMode uint32 `yaml:"file_mode" json:"file_mode"`

	// EnableCompression enables gzip compression for rotated logs
	EnableCompression bool `yaml:"enable_compression" json:"enable_compression"`

	// BufferSize is the size of the write buffer in bytes (default: 4KB)
	BufferSize int `yaml:"buffer_size" json:"buffer_size"`

	// RotateCheckInterval controls how frequently rotation checks run (defaults to 5s when unset)
	RotateCheckInterval time.Duration `yaml:"rotate_check_interval" json:"rotate_check_interval"`
}

// DefaultConfig returns PCI-DSS compliant default configuration
func DefaultConfig() Config {
	return Config{
		LogFilePath:         "/var/log/pci-segment/audit.log",
		MaxFileSizeMB:       100,
		RotateDaily:         true,
		RetentionDays:       90,
		ChecksumDBPath:      "/var/lib/pci-segment/checksums.db",
		FileMode:            0600,
		EnableCompression:   true,
		BufferSize:          4096,
		RotateCheckInterval: 5 * time.Second,
	}
}
