package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewLogger(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: Config{
				LogFilePath:       filepath.Join(tmpDir, "audit.log"),
				MaxFileSizeMB:     100,
				RotateDaily:       true,
				RetentionDays:     90,
				ChecksumDBPath:    filepath.Join(tmpDir, "checksums.db"),
				FileMode:          0600,
				EnableCompression: true,
				BufferSize:        4096,
			},
			wantErr: false,
		},
		{
			name: "missing log file path",
			config: Config{
				MaxFileSizeMB:  100,
				RetentionDays:  90,
				ChecksumDBPath: filepath.Join(tmpDir, "checksums.db"),
				FileMode:       0600,
				BufferSize:     4096,
			},
			wantErr: true,
		},
		{
			name: "invalid max size",
			config: Config{
				LogFilePath:    filepath.Join(tmpDir, "audit.log"),
				MaxFileSizeMB:  0,
				RetentionDays:  90,
				ChecksumDBPath: filepath.Join(tmpDir, "checksums.db"),
				FileMode:       0600,
				BufferSize:     4096,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := NewLogger(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewLogger() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if logger != nil {
				defer logger.Close()
			}
		})
	}
}

func TestFileLogger_Log(t *testing.T) {
	tmpDir := t.TempDir()

	config := Config{
		LogFilePath:       filepath.Join(tmpDir, "audit.log"),
		MaxFileSizeMB:     100,
		RotateDaily:       true,
		RetentionDays:     90,
		ChecksumDBPath:    filepath.Join(tmpDir, "checksums.db"),
		FileMode:          0600,
		EnableCompression: true,
		BufferSize:        4096,
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Fatalf("NewLogger() failed: %v", err)
	}
	defer logger.Close()

	// Create test event
	event := EnforcementEvent{
		Timestamp:  time.Now(),
		SourceIP:   "10.0.1.100",
		DestIP:     "10.0.2.200",
		DestPort:   443,
		Protocol:   "TCP",
		Action:     "BLOCKED",
		PolicyName: "cde-isolation",
		PCIDSSReq:  "Req 1.2",
	}

	// Log the event
	if err := logger.Log(event); err != nil {
		t.Fatalf("Log() failed: %v", err)
	}

	// Verify file was created and contains the event
	data, err := os.ReadFile(config.LogFilePath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	// Parse JSON line
	var loggedEvent EnforcementEvent
	if err := json.Unmarshal(data, &loggedEvent); err != nil {
		t.Fatalf("Failed to parse logged event: %v", err)
	}

	// Verify event data
	if loggedEvent.SourceIP != event.SourceIP {
		t.Errorf("SourceIP = %s, want %s", loggedEvent.SourceIP, event.SourceIP)
	}
	if loggedEvent.DestIP != event.DestIP {
		t.Errorf("DestIP = %s, want %s", loggedEvent.DestIP, event.DestIP)
	}
	if loggedEvent.Action != event.Action {
		t.Errorf("Action = %s, want %s", loggedEvent.Action, event.Action)
	}
}

func TestFileLogger_LogBatch(t *testing.T) {
	tmpDir := t.TempDir()

	config := Config{
		LogFilePath:       filepath.Join(tmpDir, "audit.log"),
		MaxFileSizeMB:     100,
		RotateDaily:       true,
		RetentionDays:     90,
		ChecksumDBPath:    filepath.Join(tmpDir, "checksums.db"),
		FileMode:          0600,
		EnableCompression: true,
		BufferSize:        4096,
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Fatalf("NewLogger() failed: %v", err)
	}
	defer logger.Close()

	// Create multiple events
	events := []EnforcementEvent{
		{
			Timestamp:  time.Now(),
			SourceIP:   "10.0.1.100",
			DestIP:     "10.0.2.200",
			DestPort:   443,
			Protocol:   "TCP",
			Action:     "ALLOWED",
			PolicyName: "web-access",
		},
		{
			Timestamp:  time.Now(),
			SourceIP:   "192.168.1.50",
			DestIP:     "10.0.3.100",
			DestPort:   3306,
			Protocol:   "TCP",
			Action:     "BLOCKED",
			PolicyName: "db-isolation",
			PCIDSSReq:  "Req 1.3",
		},
	}

	// Log batch
	if err := logger.LogBatch(events); err != nil {
		t.Fatalf("LogBatch() failed: %v", err)
	}

	// Verify stats
	stats := logger.GetStats()
	if stats.TotalEvents != 2 {
		t.Errorf("TotalEvents = %d, want 2", stats.TotalEvents)
	}
	if stats.FailedWrites != 0 {
		t.Errorf("FailedWrites = %d, want 0", stats.FailedWrites)
	}
}

func TestFileLogger_Rotation(t *testing.T) {
	tmpDir := t.TempDir()

	config := Config{
		LogFilePath:       filepath.Join(tmpDir, "audit.log"),
		MaxFileSizeMB:     1, // 1MB for testing
		RotateDaily:       false,
		RetentionDays:     90,
		ChecksumDBPath:    filepath.Join(tmpDir, "checksums.db"),
		FileMode:          0600,
		EnableCompression: false, // Disable for easier testing
		BufferSize:        4096,
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Fatalf("NewLogger() failed: %v", err)
	}
	defer logger.Close()

	// Create a large event to hit the size threshold quickly
	// The rotation check has a 5-second throttle, so we need to exceed
	// the threshold before the second check happens
	largePayload := strings.Repeat("X", 10000) // 10KB per event
	event := EnforcementEvent{
		Timestamp:  time.Now(),
		SourceIP:   "10.0.1.100",
		DestIP:     "10.0.2.200",
		DestPort:   443,
		Protocol:   "TCP",
		Action:     "ALLOWED",
		PolicyName: largePayload,
	}

	// Write enough events to exceed 1MB
	for i := 0; i < 150; i++ {
		if err := logger.Log(event); err != nil {
			t.Fatalf("Log() failed: %v", err)
		}
	}

	// Wait for rotation check throttle to expire
	time.Sleep(6 * time.Second)

	// Write one more event to trigger the rotation check
	if err := logger.Log(event); err != nil {
		t.Fatalf("Log() failed: %v", err)
	}

	stats := logger.GetStats()
	if stats.RotatedFiles == 0 {
		t.Errorf("Expected rotation to occur, current file size: %d bytes", stats.CurrentFileSize)
	}

	// Verify rotated file exists
	matches, err := filepath.Glob(config.LogFilePath + ".*")
	if err != nil {
		t.Fatalf("Failed to glob rotated files: %v", err)
	}
	if len(matches) == 0 {
		t.Error("Expected at least one rotated file")
	}
}

func TestFileLogger_Verify(t *testing.T) {
	tmpDir := t.TempDir()

	config := Config{
		LogFilePath:       filepath.Join(tmpDir, "audit.log"),
		MaxFileSizeMB:     100,
		RotateDaily:       true,
		RetentionDays:     90,
		ChecksumDBPath:    filepath.Join(tmpDir, "checksums.db"),
		FileMode:          0600,
		EnableCompression: true,
		BufferSize:        4096,
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Fatalf("NewLogger() failed: %v", err)
	}

	// Log an event
	event := EnforcementEvent{
		Timestamp:  time.Now(),
		SourceIP:   "10.0.1.100",
		DestIP:     "10.0.2.200",
		DestPort:   443,
		Protocol:   "TCP",
		Action:     "ALLOWED",
		PolicyName: "test",
	}

	if err := logger.Log(event); err != nil {
		t.Fatalf("Log() failed: %v", err)
	}

	// Close to finalize checksum
	if err := logger.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	// Reopen logger
	logger, err = NewLogger(config)
	if err != nil {
		t.Fatalf("NewLogger() (reopen) failed: %v", err)
	}
	defer logger.Close()

	// Verify integrity (should pass)
	valid, err := logger.Verify()
	if err != nil {
		t.Fatalf("Verify() failed: %v", err)
	}
	if !valid {
		t.Error("Verify() = false, want true")
	}

	// Close logger
	if err := logger.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	// Tamper with log file
	file, err := os.OpenFile(config.LogFilePath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("Failed to open log file for tampering: %v", err)
	}
	fmt.Fprintln(file, "TAMPERED DATA")
	file.Close()

	// Reopen logger and verify (should fail)
	logger, err = NewLogger(config)
	if err != nil {
		t.Fatalf("NewLogger() (reopen) failed: %v", err)
	}
	defer logger.Close()

	valid, err = logger.Verify()
	if err != nil {
		t.Fatalf("Verify() failed: %v", err)
	}
	if valid {
		t.Error("Verify() = true, want false (tampered file should fail)")
	}
}

func TestFileLogger_ConcurrentWrites(t *testing.T) {
	tmpDir := t.TempDir()

	config := Config{
		LogFilePath:       filepath.Join(tmpDir, "audit.log"),
		MaxFileSizeMB:     100,
		RotateDaily:       true,
		RetentionDays:     90,
		ChecksumDBPath:    filepath.Join(tmpDir, "checksums.db"),
		FileMode:          0600,
		EnableCompression: true,
		BufferSize:        4096,
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Fatalf("NewLogger() failed: %v", err)
	}
	defer logger.Close()

	// Write events concurrently
	const numGoroutines = 10
	const eventsPerGoroutine = 100

	errChan := make(chan error, numGoroutines)
	doneChan := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < eventsPerGoroutine; j++ {
				event := EnforcementEvent{
					Timestamp:  time.Now(),
					SourceIP:   fmt.Sprintf("10.0.%d.%d", id, j),
					DestIP:     "10.0.2.200",
					DestPort:   443,
					Protocol:   "TCP",
					Action:     "ALLOWED",
					PolicyName: fmt.Sprintf("policy-%d", id),
				}

				if err := logger.Log(event); err != nil {
					errChan <- err
					return
				}
			}
			doneChan <- true
		}(i)
	}

	// Wait for completion
	for i := 0; i < numGoroutines; i++ {
		select {
		case err := <-errChan:
			t.Fatalf("Concurrent write failed: %v", err)
		case <-doneChan:
			// Success
		case <-time.After(10 * time.Second):
			t.Fatal("Timeout waiting for concurrent writes")
		}
	}

	// Verify stats
	stats := logger.GetStats()
	expectedEvents := uint64(numGoroutines * eventsPerGoroutine)
	if stats.TotalEvents != expectedEvents {
		t.Errorf("TotalEvents = %d, want %d", stats.TotalEvents, expectedEvents)
	}
	if stats.FailedWrites != 0 {
		t.Errorf("FailedWrites = %d, want 0", stats.FailedWrites)
	}
}

func TestFileLogger_GetStats(t *testing.T) {
	tmpDir := t.TempDir()

	config := Config{
		LogFilePath:       filepath.Join(tmpDir, "audit.log"),
		MaxFileSizeMB:     100,
		RotateDaily:       true,
		RetentionDays:     90,
		ChecksumDBPath:    filepath.Join(tmpDir, "checksums.db"),
		FileMode:          0600,
		EnableCompression: true,
		BufferSize:        4096,
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Fatalf("NewLogger() failed: %v", err)
	}
	defer logger.Close()

	// Initial stats
	stats := logger.GetStats()
	if stats.TotalEvents != 0 {
		t.Errorf("Initial TotalEvents = %d, want 0", stats.TotalEvents)
	}

	// Log some events
	for i := 0; i < 5; i++ {
		event := EnforcementEvent{
			Timestamp:  time.Now(),
			SourceIP:   "10.0.1.100",
			DestIP:     "10.0.2.200",
			DestPort:   443,
			Protocol:   "TCP",
			Action:     "ALLOWED",
			PolicyName: "test",
		}
		if err := logger.Log(event); err != nil {
			t.Fatalf("Log() failed: %v", err)
		}
	}

	// Check stats
	stats = logger.GetStats()
	if stats.TotalEvents != 5 {
		t.Errorf("TotalEvents = %d, want 5", stats.TotalEvents)
	}
	if stats.CurrentFileSize <= 0 {
		t.Error("CurrentFileSize should be > 0")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.LogFilePath != "/var/log/pci-segment/audit.log" {
		t.Errorf("LogFilePath = %s, want /var/log/pci-segment/audit.log", cfg.LogFilePath)
	}
	if cfg.MaxFileSizeMB != 100 {
		t.Errorf("MaxFileSizeMB = %d, want 100", cfg.MaxFileSizeMB)
	}
	if cfg.RetentionDays != 90 {
		t.Errorf("RetentionDays = %d, want 90", cfg.RetentionDays)
	}
	if cfg.FileMode != 0600 {
		t.Errorf("FileMode = %o, want 0600", cfg.FileMode)
	}
	if !cfg.RotateDaily {
		t.Error("RotateDaily should be true")
	}
	if !cfg.EnableCompression {
		t.Error("EnableCompression should be true")
	}
}
