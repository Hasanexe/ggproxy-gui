package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// ReadConfigFile reads the raw config file and returns key-value pairs
// Multi-value keys like allowed_ip are returned as slices
func ReadConfigFile(path string) (map[string][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %v", err)
	}
	defer f.Close()

	result := make(map[string][]string)

	// Read file content
	var content strings.Builder
	buf := make([]byte, 1024)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			content.Write(buf[:n])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read config file: %v", err)
		}
	}

	// Parse lines
	lines := strings.Split(content.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse key=value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		// Append to result (handles multi-value keys like allowed_ip)
		result[key] = append(result[key], val)
	}

	return result, nil
}

// WriteConfigFile writes validated config back to disk
// Preserves comments and formatting where possible
// Filters out csrf_token and other non-config keys
// Merges new values with existing config to preserve unmodified keys
func WriteConfigFile(path string, values map[string][]string) error {
	// Filter out non-config keys
	delete(values, "csrf_token")
	
	// Read existing config to preserve keys not in the form
	existingValues, err := ReadConfigFile(path)
	if err != nil {
		// If we can't read existing config, just use what we have
		existingValues = make(map[string][]string)
	}
	
	// Merge: new values override existing, but preserve existing keys not in new values
	for key, val := range existingValues {
		if _, exists := values[key]; !exists {
			// Key not in new values, preserve it
			values[key] = val
		}
	}
	
	// Read original file to preserve comments and structure
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open config file for reading: %v", err)
	}

	var content strings.Builder
	buf := make([]byte, 1024)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			content.Write(buf[:n])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			f.Close()
			return fmt.Errorf("failed to read config file: %v", err)
		}
	}
	f.Close()

	// Track which keys we've written
	writtenKeys := make(map[string]bool)

	// Build output preserving comments and structure
	var output strings.Builder
	lines := strings.Split(content.String(), "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Preserve comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			output.WriteString(line)
			output.WriteString("\n")
			continue
		}

		// Parse key=value
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			output.WriteString(line)
			output.WriteString("\n")
			continue
		}

		key := strings.TrimSpace(parts[0])

		// If this key has new values, write them
		if newVals, exists := values[key]; exists && !writtenKeys[key] {
			for _, val := range newVals {
				output.WriteString(key)
				output.WriteString(" = ")
				output.WriteString(val)
				output.WriteString("\n")
			}
			writtenKeys[key] = true
		}
		// Otherwise skip the old line (it will be replaced)
	}

	// Add any new keys that weren't in the original file
	for key, vals := range values {
		if !writtenKeys[key] {
			for _, val := range vals {
				output.WriteString(key)
				output.WriteString(" = ")
				output.WriteString(val)
				output.WriteString("\n")
			}
		}
	}

	// Write to temporary file first
	tmpPath := path + ".tmp"
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("failed to create temporary config file: %v", err)
	}

	_, err = tmpFile.WriteString(output.String())
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write temporary config file: %v", err)
	}
	tmpFile.Close()

	// Atomic rename
	err = os.Rename(tmpPath, path)
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

// ConfigValues represents a single configuration value for validation
type ConfigValues struct {
	ProxyMode   string
	Port        int
	LogLevel    string
	AllowedIPs  []string
	IdleTimeout string
	BufferSize  int
	AuthUser    string
	AuthPass    string
	GUIEnabled  string
	GUIPort     int
	GUIUser     string
	GUIPass     string
	GUIBind     string
}

// ValidateConfigValues validates user input before saving
// Returns specific error messages for each validation failure
func ValidateConfigValues(values map[string][]string) error {
	// Helper to get single value
	getSingleValue := func(key string) string {
		if vals, ok := values[key]; ok && len(vals) > 0 {
			return vals[0]
		}
		return ""
	}

	// Validate proxy_mode
	if proxyMode := getSingleValue("proxy_mode"); proxyMode != "" {
		lowerMode := strings.ToLower(proxyMode)
		if lowerMode != "http" && lowerMode != "socks" {
			return fmt.Errorf("proxy_mode must be 'http' or 'socks', got '%s'", proxyMode)
		}
	}

	// Validate port
	if portStr := getSingleValue("port"); portStr != "" {
		var port int
		if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
			return fmt.Errorf("port must be a number, got '%s'", portStr)
		}
		if port < 1 || port > 65535 {
			return fmt.Errorf("port must be between 1 and 65535, got %d", port)
		}
	}

	// Validate log_level
	if logLevel := getSingleValue("log_level"); logLevel != "" {
		lowerLevel := strings.ToLower(logLevel)
		if lowerLevel != "debug" && lowerLevel != "basic" && lowerLevel != "off" {
			return fmt.Errorf("log_level must be 'debug', 'basic', or 'off', got '%s'", logLevel)
		}
	}

	// Validate allowed_ip (CIDR notation, IPv4 only)
	if allowedIPs, ok := values["allowed_ip"]; ok {
		for _, cidr := range allowedIPs {
			if cidr == "" {
				continue
			}
			// Basic CIDR validation
			if !strings.Contains(cidr, "/") {
				return fmt.Errorf("allowed_ip must be in CIDR notation (e.g., 192.168.1.0/24), got '%s'", cidr)
			}
			// Try to parse it
			parts := strings.Split(cidr, "/")
			if len(parts) != 2 {
				return fmt.Errorf("invalid CIDR notation '%s'", cidr)
			}
			// Check if it looks like IPv4
			ipParts := strings.Split(parts[0], ".")
			if len(ipParts) != 4 {
				return fmt.Errorf("allowed_ip must be IPv4 CIDR notation, got '%s'", cidr)
			}
		}
	}

	// Validate idle_timeout (duration string)
	if timeout := getSingleValue("idle_timeout"); timeout != "" {
		// Basic validation: should end with s, m, h, etc.
		if !strings.HasSuffix(timeout, "s") && !strings.HasSuffix(timeout, "m") && !strings.HasSuffix(timeout, "h") {
			return fmt.Errorf("idle_timeout must be a duration string (e.g., '30s', '5m'), got '%s'", timeout)
		}
	}

	// Validate buffer_size (positive integer)
	if bufferStr := getSingleValue("buffer_size"); bufferStr != "" {
		var size int
		if _, err := fmt.Sscanf(bufferStr, "%d", &size); err != nil {
			return fmt.Errorf("buffer_size must be a number, got '%s'", bufferStr)
		}
		if size <= 0 {
			return fmt.Errorf("buffer_size must be positive, got %d", size)
		}
	}

	// Validate gui_port
	if guiPortStr := getSingleValue("gui_port"); guiPortStr != "" {
		var port int
		if _, err := fmt.Sscanf(guiPortStr, "%d", &port); err != nil {
			return fmt.Errorf("gui_port must be a number, got '%s'", guiPortStr)
		}
		if port < 1 || port > 65535 {
			return fmt.Errorf("gui_port must be between 1 and 65535, got %d", port)
		}
	}

	// Validate gui_bind (IP address only, no CIDR)
	if guiBind := getSingleValue("gui_bind"); guiBind != "" {
		// Basic validation: should be a valid IP address
		if strings.Contains(guiBind, "/") {
			return fmt.Errorf("gui_bind must be an IP address (not CIDR), got '%s'", guiBind)
		}
	}

	// Validate gui_enabled (should be "true" or "false" or empty)
	if guiEnabled := getSingleValue("gui_enabled"); guiEnabled != "" {
		if guiEnabled != "true" && guiEnabled != "false" {
			return fmt.Errorf("gui_enabled must be 'true' or 'false', got '%s'", guiEnabled)
		}
	}

	return nil
}


// ReloadConfig sends SIGHUP signal to the main GGProxy process
func ReloadConfig() error {
	// Get the current process ID
	pid := os.Getpid()

	// Send SIGHUP signal to self
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process: %v", err)
	}

	// On Unix systems, send SIGHUP
	// On Windows, this will fail gracefully
	err = proc.Signal(os.Interrupt) // Use Interrupt as fallback for Windows
	if err != nil {
		return fmt.Errorf("failed to send signal: %v", err)
	}

	return nil
}
