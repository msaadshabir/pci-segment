package audit

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
)

// compressFile compresses a file using gzip and removes the original
func compressFile(filepath string) error {
	// Open source file
	src, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer src.Close()

	// Create compressed file
	dstPath := filepath + ".gz"
	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create compressed file: %w", err)
	}
	defer dst.Close()

	// Create gzip writer
	gzWriter := gzip.NewWriter(dst)
	defer gzWriter.Close()

	// Copy and compress
	if _, err := io.Copy(gzWriter, src); err != nil {
		return fmt.Errorf("failed to compress file: %w", err)
	}

	// Ensure gzip footer is written
	if err := gzWriter.Close(); err != nil {
		return fmt.Errorf("failed to close gzip writer: %w", err)
	}

	// Sync to disk
	if err := dst.Sync(); err != nil {
		return fmt.Errorf("failed to sync compressed file: %w", err)
	}

	// Close destination file
	if err := dst.Close(); err != nil {
		return fmt.Errorf("failed to close compressed file: %w", err)
	}

	// Close source file before removal
	if err := src.Close(); err != nil {
		return fmt.Errorf("failed to close source file: %w", err)
	}

	// Remove original file
	if err := os.Remove(filepath); err != nil {
		return fmt.Errorf("failed to remove original file: %w", err)
	}

	return nil
}
