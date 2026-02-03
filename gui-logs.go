package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// LogEntry represents a single log entry
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

// StreamRecentLogs streams logs from the in-memory circular buffer via Server-Sent Events
// Works on all platforms (Linux, Windows, macOS)
func StreamRecentLogs(w http.ResponseWriter, filter string) error {
	flusher, ok := w.(http.Flusher)
	
	// Send initial batch of recent logs
	logMutex.RLock()
	logs := make([]string, len(recentLogs))
	copy(logs, recentLogs)
	logMutex.RUnlock()
	
	for _, logLine := range logs {
		entry := parseLogLine(logLine)
		
		// Apply text filter if provided
		if filter != "" && !strings.Contains(strings.ToLower(entry.Message), strings.ToLower(filter)) {
			continue
		}
		
		// Format as SSE message
		data, _ := json.Marshal(entry)
		sseMsg := fmt.Sprintf("data: %s\n\n", string(data))
		
		if _, err := w.Write([]byte(sseMsg)); err != nil {
			return fmt.Errorf("failed to write SSE message: %w", err)
		}
		
		if ok {
			flusher.Flush()
		}
	}
	
	// Keep connection open and stream new logs as they arrive
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	
	lastIndex := len(logs)
	
	for range ticker.C {
		logMutex.RLock()
		currentLogs := recentLogs
		logMutex.RUnlock()
		
		// Send any new logs since last check
		for i := lastIndex; i < len(currentLogs); i++ {
			entry := parseLogLine(currentLogs[i])
			
			// Apply text filter if provided
			if filter != "" && !strings.Contains(strings.ToLower(entry.Message), strings.ToLower(filter)) {
				continue
			}
			
			// Format as SSE message
			data, _ := json.Marshal(entry)
			sseMsg := fmt.Sprintf("data: %s\n\n", string(data))
			
			if _, err := w.Write([]byte(sseMsg)); err != nil {
				return nil // Client disconnected
			}
			
			if ok {
				flusher.Flush()
			}
		}
		
		lastIndex = len(currentLogs)
	}
	
	return nil
}

// parseLogLine parses a log line into a LogEntry
// Format: "02.01.2006 15:04:05 MESSAGE"
func parseLogLine(logLine string) LogEntry {
	parts := strings.SplitN(logLine, " ", 3)
	
	timestamp := ""
	message := logLine
	level := "info"
	
	if len(parts) >= 3 {
		timestamp = parts[0] + " " + parts[1]
		message = parts[2]
		
		// Determine log level from message content
		if strings.Contains(message, "Error") || strings.Contains(message, "error") {
			level = "error"
		} else if strings.Contains(message, "Warning") || strings.Contains(message, "warning") {
			level = "warning"
		} else if strings.Contains(message, "Debug") || strings.Contains(message, "debug") {
			level = "debug"
		}
	}
	
	return LogEntry{
		Timestamp: timestamp,
		Level:     level,
		Message:   message,
	}
}
