package log

import (
	"bytes"
	"strings"
	"testing"
)

func TestSetLevel(t *testing.T) {
	tests := []struct {
		name     string
		level    string
		valid    bool
		expected string
	}{
		{"debug lowercase", "debug", true, "debug"},
		{"debug uppercase", "DEBUG", true, "debug"},
		{"info lowercase", "info", true, "info"},
		{"info mixed case", "Info", true, "info"},
		{"warn lowercase", "warn", true, "warn"},
		{"warning alias", "warning", true, "warn"},
		{"error lowercase", "error", true, "error"},
		{"error uppercase", "ERROR", true, "error"},
		{"invalid level", "trace", false, "info"},
		{"empty string", "", false, "info"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetLevel("info")
			got := SetLevel(tt.level)
			if got != tt.valid {
				t.Errorf("SetLevel(%q) = %v, want %v", tt.level, got, tt.valid)
			}
			if tt.valid && Level() != tt.expected {
				t.Errorf("Level() = %q, want %q", Level(), tt.expected)
			}
		})
	}
}

func TestLevel(t *testing.T) {
	tests := []struct {
		name     string
		setLevel string
		want     string
	}{
		{"debug", "debug", "debug"},
		{"info", "info", "info"},
		{"warn", "warn", "warn"},
		{"error", "error", "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetLevel(tt.setLevel)
			if got := Level(); got != tt.want {
				t.Errorf("Level() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLogOutput(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	SetLevel("debug")

	Debug("debug message", "key", "value")
	Info("info message")
	Warn("warn message")
	Error("error message")

	output := buf.String()

	if !strings.Contains(output, "debug message") {
		t.Error("expected debug message in output")
	}
	if !strings.Contains(output, "info message") {
		t.Error("expected info message in output")
	}
	if !strings.Contains(output, "warn message") {
		t.Error("expected warn message in output")
	}
	if !strings.Contains(output, "error message") {
		t.Error("expected error message in output")
	}
	if !strings.Contains(output, "key=value") {
		t.Error("expected structured key=value in output")
	}
}

func TestLogLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	SetLevel("warn")

	Debug("debug message")
	Info("info message")
	Warn("warn message")
	Error("error message")

	output := buf.String()

	if strings.Contains(output, "debug message") {
		t.Error("debug message should be filtered at warn level")
	}
	if strings.Contains(output, "info message") {
		t.Error("info message should be filtered at warn level")
	}
	if !strings.Contains(output, "warn message") {
		t.Error("warn message should appear at warn level")
	}
	if !strings.Contains(output, "error message") {
		t.Error("error message should appear at warn level")
	}
}
