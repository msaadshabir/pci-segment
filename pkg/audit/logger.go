package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// minEventsForSizeCheck is the minimum number of events before checking file size for rotation
	minEventsForSizeCheck = 1000
)

// FileLogger implements persistent audit logging with tamper detection
type FileLogger struct {
	config Config
	mu     sync.Mutex

	// File handles
	file   *os.File
	writer *bufio.Writer

	// Statistics
	stats Stats

	// Rotation state
	lastRotateCheck time.Time

	// Integrity checker
	integrity *IntegrityChecker

	// Closed flag
	closed bool

	// Background task management
	bgTasks sync.WaitGroup
}

// NewLogger creates a new persistent audit logger
func NewLogger(cfg Config) (*FileLogger, error) {
	// Validate configuration
	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Create log directory if it doesn't exist
	logDir := filepath.Dir(cfg.LogFilePath)
	if err := os.MkdirAll(logDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create log directory %s: %w", logDir, err)
	}

	// Create checksum directory if it doesn't exist
	checksumDir := filepath.Dir(cfg.ChecksumDBPath)
	if err := os.MkdirAll(checksumDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create checksum directory %s: %w", checksumDir, err)
	}

	// Initialize integrity checker
	integrity, err := NewIntegrityChecker(cfg.ChecksumDBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize integrity checker: %w", err)
	}

	logger := &FileLogger{
		config:          cfg,
		lastRotateCheck: time.Now(),
		integrity:       integrity,
		stats: Stats{
			LastRotation: time.Now(),
		},
	}

	// Open log file
	if err := logger.openLogFile(); err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	// Verify existing log integrity on startup
	if err := logger.verifyExistingLogs(); err != nil {
		// Log warning but don't fail - allow startup
		fmt.Fprintf(os.Stderr, "WARNING: log integrity check failed: %v\n", err)
		logger.stats.ChecksumFailures++
	}

	return logger, nil
}

// Log writes a single enforcement event to persistent storage
func (l *FileLogger) Log(event EnforcementEvent) error {
	return l.LogBatch([]EnforcementEvent{event})
}

// LogBatch writes multiple events atomically with fsync
func (l *FileLogger) LogBatch(events []EnforcementEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return fmt.Errorf("logger is closed")
	}

	// Check if rotation is needed
	if err := l.checkRotation(); err != nil {
		l.stats.FailedWrites++
		return fmt.Errorf("rotation check failed: %w", err)
	}

	// Write events as JSON lines
	for _, event := range events {
		// Marshal to JSON
		data, err := json.Marshal(event)
		if err != nil {
			l.stats.FailedWrites++
			return fmt.Errorf("failed to marshal event: %w", err)
		}

		// Write with newline
		if _, err := l.writer.Write(data); err != nil {
			l.stats.FailedWrites++
			return fmt.Errorf("failed to write event: %w", err)
		}
		if _, err := l.writer.WriteString("\n"); err != nil {
			l.stats.FailedWrites++
			return fmt.Errorf("failed to write newline: %w", err)
		}

		l.stats.TotalEvents++
		l.stats.EventsLastRotate++
	}

	// Flush buffer to OS
	if err := l.writer.Flush(); err != nil {
		l.stats.FailedWrites++
		return fmt.Errorf("failed to flush buffer: %w", err)
	}

	// Fsync for durability (required for PCI-DSS)
	if err := l.file.Sync(); err != nil {
		l.stats.FailedWrites++
		return fmt.Errorf("failed to sync file: %w", err)
	}

	// Update file size stat
	if stat, err := l.file.Stat(); err == nil {
		l.stats.CurrentFileSize = stat.Size()
	}

	return nil
}

// Verify checks log file integrity using checksums
func (l *FileLogger) Verify() (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Close and reopen file for reading
	if err := l.closeLogFile(); err != nil {
		return false, err
	}
	defer func() {
		_ = l.openLogFile() // Reopen for writing (best effort)
	}()

	// Calculate current checksum
	checksum, err := calculateFileChecksum(l.config.LogFilePath)
	if err != nil {
		return false, fmt.Errorf("failed to calculate checksum: %w", err)
	}

	// Verify against stored checksum
	valid, err := l.integrity.Verify(l.config.LogFilePath, checksum)
	if err != nil {
		return false, err
	}

	if !valid {
		l.stats.ChecksumFailures++
	}

	l.stats.LastChecksumCheck = time.Now()
	return valid, nil
}

// Rotate triggers manual log rotation
func (l *FileLogger) Rotate() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.performRotation()
}

// Close closes the logger and flushes pending writes
func (l *FileLogger) Close() error {
	l.mu.Lock()
	
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	
	l.closed = true
	l.mu.Unlock()

	// Wait for all background tasks to complete (outside mutex to avoid deadlock)
	l.bgTasks.Wait()

	// Reacquire lock for cleanup operations
	l.mu.Lock()
	defer l.mu.Unlock()

	// Flush any pending writes
	if l.writer != nil {
		if err := l.writer.Flush(); err != nil {
			return fmt.Errorf("failed to flush on close: %w", err)
		}
	}

	// Sync file
	if l.file != nil {
		if err := l.file.Sync(); err != nil {
			return fmt.Errorf("failed to sync on close: %w", err)
		}
	}

	// Calculate and store final checksum
	if l.config.LogFilePath != "" {
		checksum, err := calculateFileChecksum(l.config.LogFilePath)
		if err == nil {
			_ = l.integrity.Store(l.config.LogFilePath, checksum)
		}
	}

	// Close file
	if err := l.closeLogFile(); err != nil {
		return err
	}

	// Close integrity checker
	if l.integrity != nil {
		if err := l.integrity.Close(); err != nil {
			return fmt.Errorf("failed to close integrity checker: %w", err)
		}
	}

	return nil
}

// GetStats returns current logging statistics
func (l *FileLogger) GetStats() Stats {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.stats
}

// openLogFile opens the log file with proper permissions
func (l *FileLogger) openLogFile() error {
	file, err := os.OpenFile(
		l.config.LogFilePath,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		os.FileMode(l.config.FileMode),
	)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	l.file = file
	l.writer = bufio.NewWriterSize(file, l.config.BufferSize)

	// Update file size stat
	if stat, err := file.Stat(); err == nil {
		l.stats.CurrentFileSize = stat.Size()
	}

	return nil
}

// closeLogFile closes the log file
func (l *FileLogger) closeLogFile() error {
	if l.writer != nil {
		if err := l.writer.Flush(); err != nil {
			return fmt.Errorf("failed to flush writer: %w", err)
		}
		l.writer = nil
	}

	if l.file != nil {
		if err := l.file.Close(); err != nil {
			return fmt.Errorf("failed to close file: %w", err)
		}
		l.file = nil
	}

	return nil
}

// checkRotation checks if rotation is needed and performs it
func (l *FileLogger) checkRotation() error {
	now := time.Now()

	// Don't check too frequently (every 30 seconds is enough for most use cases)
	if now.Sub(l.lastRotateCheck) < 30*time.Second {
		return nil
	}
	l.lastRotateCheck = now

	needsRotation := false

	// Check size-based rotation (only if we're close to the limit)
	// Skip stat check if we know we're not close yet
	if l.stats.EventsLastRotate > minEventsForSizeCheck {
		if l.stats.CurrentFileSize >= int64(l.config.MaxFileSizeMB)*1024*1024 {
			needsRotation = true
		}
	}

	// Check time-based rotation (daily) - this is fast
	if !needsRotation && l.config.RotateDaily {
		lastRotateDate := l.stats.LastRotation.Truncate(24 * time.Hour)
		currentDate := now.Truncate(24 * time.Hour)
		if currentDate.After(lastRotateDate) {
			needsRotation = true
		}
	}

	if needsRotation {
		return l.performRotation()
	}

	return nil
}

// performRotation performs the actual log rotation
func (l *FileLogger) performRotation() error {
	// Check if logger is closed (prevent race condition with Close())
	if l.closed {
		return fmt.Errorf("logger is closed")
	}

	// Flush and close current file
	if err := l.writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush before rotation: %w", err)
	}
	if err := l.file.Sync(); err != nil {
		return fmt.Errorf("failed to sync before rotation: %w", err)
	}

	// Calculate and store checksum of current file
	checksum, err := calculateFileChecksum(l.config.LogFilePath)
	if err == nil {
		_ = l.integrity.Store(l.config.LogFilePath, checksum)
	}

	// Close current file
	if err := l.closeLogFile(); err != nil {
		return fmt.Errorf("failed to close file for rotation: %w", err)
	}

	// Generate rotated filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	rotatedPath := fmt.Sprintf("%s.%s", l.config.LogFilePath, timestamp)

	// Rename current log file
	if err := os.Rename(l.config.LogFilePath, rotatedPath); err != nil {
		// Try to reopen original file on error
		_ = l.openLogFile()
		return fmt.Errorf("failed to rename log file: %w", err)
	}

	// Compress rotated file if enabled
	if l.config.EnableCompression && !l.closed {
		l.bgTasks.Add(1)
		go func() {
			defer l.bgTasks.Done()
			if err := compressFile(rotatedPath); err != nil {
				fmt.Fprintf(os.Stderr, "WARNING: failed to compress rotated log: %v\n", err)
			}
		}()
	}

	// Clean up old rotated files
	if !l.closed {
		l.bgTasks.Add(1)
		go func() {
			defer l.bgTasks.Done()
			if err := l.cleanupOldLogs(); err != nil {
				fmt.Fprintf(os.Stderr, "WARNING: failed to cleanup old logs: %v\n", err)
			}
		}()
	}

	// Open new log file
	if err := l.openLogFile(); err != nil {
		return fmt.Errorf("failed to open new log file after rotation: %w", err)
	}

	// Update stats
	l.stats.LastRotation = time.Now()
	l.stats.EventsLastRotate = 0
	l.stats.RotatedFiles++

	return nil
}

// verifyExistingLogs verifies integrity of existing log files on startup
func (l *FileLogger) verifyExistingLogs() error {
	// Check current log file
	if _, err := os.Stat(l.config.LogFilePath); err == nil {
		checksum, err := calculateFileChecksum(l.config.LogFilePath)
		if err != nil {
			return fmt.Errorf("failed to calculate checksum: %w", err)
		}

		valid, err := l.integrity.Verify(l.config.LogFilePath, checksum)
		if err != nil {
			return err
		}

		if !valid {
			return fmt.Errorf("log file %s failed integrity check", l.config.LogFilePath)
		}
	}

	return nil
}

// cleanupOldLogs removes log files older than retention period
func (l *FileLogger) cleanupOldLogs() error {
	logDir := filepath.Dir(l.config.LogFilePath)
	baseFilename := filepath.Base(l.config.LogFilePath)

	// Find all rotated log files
	pattern := fmt.Sprintf("%s.*", baseFilename)
	matches, err := filepath.Glob(filepath.Join(logDir, pattern))
	if err != nil {
		return fmt.Errorf("failed to glob log files: %w", err)
	}

	cutoff := time.Now().AddDate(0, 0, -l.config.RetentionDays)

	for _, match := range matches {
		// Skip current log file
		if match == l.config.LogFilePath {
			continue
		}

		// Check file modification time
		info, err := os.Stat(match)
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			// Remove old log file
			if err := os.Remove(match); err != nil {
				fmt.Fprintf(os.Stderr, "WARNING: failed to remove old log %s: %v\n", match, err)
			}

			// Also remove compressed version if exists
			compressedPath := match + ".gz"
			_ = os.Remove(compressedPath)

			// Remove checksum entry
			_ = l.integrity.Remove(match)
		}
	}

	return nil
}

// calculateFileChecksum calculates SHA-256 checksum of a file
func calculateFileChecksum(filepath string) (string, error) {
	// #nosec G304 -- filepath is from controlled audit log rotation, not user input
	file, err := os.Open(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to calculate hash: %w", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// validateConfig validates logger configuration
func validateConfig(cfg Config) error {
	if cfg.LogFilePath == "" {
		return fmt.Errorf("log_file_path is required")
	}
	if cfg.MaxFileSizeMB <= 0 {
		return fmt.Errorf("max_file_size_mb must be positive")
	}
	if cfg.RetentionDays <= 0 {
		return fmt.Errorf("retention_days must be positive")
	}
	if cfg.ChecksumDBPath == "" {
		return fmt.Errorf("checksum_db_path is required")
	}
	if cfg.BufferSize <= 0 {
		return fmt.Errorf("buffer_size must be positive")
	}
	return nil
}
