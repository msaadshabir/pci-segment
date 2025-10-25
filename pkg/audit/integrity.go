package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// IntegrityChecker manages SHA-256 checksums for tamper detection
type IntegrityChecker struct {
	dbPath string
	mu     sync.RWMutex

	// In-memory checksum database
	checksums map[string]ChecksumEntry

	// Dirty flag for persistence
	dirty bool
}

// ChecksumEntry represents a stored checksum with metadata
type ChecksumEntry struct {
	Checksum  string    `json:"checksum"`
	Timestamp time.Time `json:"timestamp"`
	FileSize  int64     `json:"file_size"`
}

// NewIntegrityChecker creates a new integrity checker
func NewIntegrityChecker(dbPath string) (*IntegrityChecker, error) {
	ic := &IntegrityChecker{
		dbPath:    dbPath,
		checksums: make(map[string]ChecksumEntry),
	}

	// Load existing checksums if database exists
	if _, err := os.Stat(dbPath); err == nil {
		if err := ic.load(); err != nil {
			return nil, fmt.Errorf("failed to load checksum database: %w", err)
		}
	}

	return ic, nil
}

// Store saves a checksum for a file
func (ic *IntegrityChecker) Store(filepath string, checksum string) error {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	// Get file size
	stat, err := os.Stat(filepath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	ic.checksums[filepath] = ChecksumEntry{
		Checksum:  checksum,
		Timestamp: time.Now(),
		FileSize:  stat.Size(),
	}

	ic.dirty = true

	// Persist to disk
	return ic.persist()
}

// Verify checks if a file's checksum matches the stored value
func (ic *IntegrityChecker) Verify(filepath string, currentChecksum string) (bool, error) {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	entry, exists := ic.checksums[filepath]
	if !exists {
		// No stored checksum - treat as valid (first time)
		return true, nil
	}

	// Compare checksums
	return entry.Checksum == currentChecksum, nil
}

// Remove removes a checksum entry (e.g., when file is deleted)
func (ic *IntegrityChecker) Remove(filepath string) error {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	delete(ic.checksums, filepath)
	ic.dirty = true

	return ic.persist()
}

// Close persists any pending changes and closes the checker
func (ic *IntegrityChecker) Close() error {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	if ic.dirty {
		return ic.persist()
	}

	return nil
}

// load reads checksums from disk
func (ic *IntegrityChecker) load() error {
	data, err := os.ReadFile(ic.dbPath)
	if err != nil {
		return fmt.Errorf("failed to read checksum database: %w", err)
	}

	if err := json.Unmarshal(data, &ic.checksums); err != nil {
		return fmt.Errorf("failed to unmarshal checksums: %w", err)
	}

	return nil
}

// persist writes checksums to disk (must be called with lock held)
func (ic *IntegrityChecker) persist() error {
	if !ic.dirty {
		return nil
	}

	data, err := json.MarshalIndent(ic.checksums, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal checksums: %w", err)
	}

	// Write atomically using temp file + rename
	tempPath := ic.dbPath + ".tmp"
	if err := os.WriteFile(tempPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write temp checksum file: %w", err)
	}

	if err := os.Rename(tempPath, ic.dbPath); err != nil {
		// Clean up temp file on error (best effort)
		_ = os.Remove(tempPath)
		return fmt.Errorf("failed to rename checksum file: %w", err)
	}

	ic.dirty = false
	return nil
}
