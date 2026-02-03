package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// DashboardMetrics holds all dashboard data
type DashboardMetrics struct {
	ServiceStatus      string             `json:"service_status"`
	Uptime             string             `json:"uptime"`
	ActiveConns        int64              `json:"active_connections"`
	TotalConns         int64              `json:"total_connections"`
	Bandwidth          BandwidthMetrics   `json:"bandwidth"`
	CPUPercent         float64            `json:"cpu_percent"`
	Memory             MemoryMetrics      `json:"memory"`
	Goroutines         int                `json:"goroutines"`
	OpenSockets        int                `json:"open_sockets"`
}

// BandwidthMetrics holds bandwidth data
type BandwidthMetrics struct {
	BytesIn        int64   `json:"bytes_in"`
	BytesOut       int64   `json:"bytes_out"`
	CurrentInMbps  float64 `json:"current_in_mbps"`
	CurrentOutMbps float64 `json:"current_out_mbps"`
}

// MemoryMetrics holds memory usage data
type MemoryMetrics struct {
	RSSBytes int64   `json:"rss_bytes"`
	VMSBytes int64   `json:"vms_bytes"`
	Percent  float64 `json:"percent"`
}

// ProcessMetrics holds cached process metrics
type ProcessMetrics struct {
	StartTime      time.Time
	LastCPUTime    int64
	LastCheckTime  time.Time
	LastBytesIn    int64
	LastBytesOut   int64
	LastBandwidthTime time.Time
}

var processMetrics = &ProcessMetrics{
	StartTime:         time.Now(),
	LastCheckTime:     time.Now(),
	LastBandwidthTime: time.Now(),
}

// GetDashboardMetrics collects all metrics and returns JSON
func GetDashboardMetrics() (*DashboardMetrics, error) {
	metrics := &DashboardMetrics{
		ServiceStatus: getServiceStatus(),
		Uptime:        calculateUptime(),
		ActiveConns:   getActiveConnections(),
		TotalConns:    getTotalConnections(),
		Bandwidth:     getBandwidthMetrics(),
		CPUPercent:    getCPUUsage(),
		Memory:        getMemoryUsage(),
		Goroutines:    runtime.NumGoroutine(),
		OpenSockets:   countOpenSockets(),
	}

	return metrics, nil
}

// getServiceStatus checks if GGProxy listener is active
func getServiceStatus() string {
	// Check if process is running and listener is active
	// For now, we'll return "healthy" if the process is running
	// In a real scenario, we'd check if the listener socket is active
	
	pid := os.Getpid()
	if pid > 0 {
		return "healthy"
	}
	return "down"
}

// calculateUptime calculates uptime from process start time
func calculateUptime() string {
	elapsed := time.Since(processMetrics.StartTime)
	
	days := int(elapsed.Hours() / 24)
	hours := int(elapsed.Hours()) % 24
	minutes := int(elapsed.Minutes()) % 60
	seconds := int(elapsed.Seconds()) % 60
	
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// getCPUUsage reads CPU usage from /proc/[pid]/stat
func getCPUUsage() float64 {
	pid := os.Getpid()
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	
	data, err := os.ReadFile(statPath)
	if err != nil {
		return 0
	}
	
	// Parse /proc/[pid]/stat
	// Format: pid (comm) state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt utime stime ...
	// utime is at index 13 (0-based), stime is at index 14
	fields := strings.Fields(string(data))
	if len(fields) < 15 {
		return 0
	}
	
	utime, _ := strconv.ParseInt(fields[13], 10, 64)
	stime, _ := strconv.ParseInt(fields[14], 10, 64)
	totalTime := utime + stime
	
	// Calculate CPU percentage
	now := time.Now()
	timeDiff := now.Sub(processMetrics.LastCheckTime).Seconds()
	if timeDiff <= 0 {
		return 0
	}
	
	cpuDiff := float64(totalTime - processMetrics.LastCPUTime)
	cpuPercent := (cpuDiff / timeDiff) * 100
	
	// Update cached values
	processMetrics.LastCPUTime = totalTime
	processMetrics.LastCheckTime = now
	
	// Clamp to reasonable values
	if cpuPercent < 0 {
		cpuPercent = 0
	}
	if cpuPercent > 100 {
		cpuPercent = 100
	}
	
	return cpuPercent
}

// getMemoryUsage reads memory usage from /proc/[pid]/status
func getMemoryUsage() MemoryMetrics {
	pid := os.Getpid()
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return MemoryMetrics{}
	}
	
	var rssBytes, vmsBytes int64
	lines := strings.Split(string(data), "\n")
	
	for _, line := range lines {
		if strings.HasPrefix(line, "VmRSS:") {
			// VmRSS is in kB
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				kb, _ := strconv.ParseInt(parts[1], 10, 64)
				rssBytes = kb * 1024
			}
		}
		if strings.HasPrefix(line, "VmSize:") {
			// VmSize is in kB
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				kb, _ := strconv.ParseInt(parts[1], 10, 64)
				vmsBytes = kb * 1024
			}
		}
	}
	
	// Calculate memory percentage (rough estimate: RSS / total system memory)
	// For simplicity, we'll use a fixed estimate of 8GB system memory
	totalSystemMemory := int64(8 * 1024 * 1024 * 1024)
	memPercent := float64(rssBytes) / float64(totalSystemMemory) * 100
	
	return MemoryMetrics{
		RSSBytes: rssBytes,
		VMSBytes: vmsBytes,
		Percent:  memPercent,
	}
}

// countOpenSockets counts open sockets from /proc/[pid]/fd
func countOpenSockets() int {
	pid := os.Getpid()
	fdPath := fmt.Sprintf("/proc/%d/fd", pid)
	
	entries, err := os.ReadDir(fdPath)
	if err != nil {
		return 0
	}
	
	// Count socket file descriptors
	socketCount := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		
		// Check if it's a socket by reading the link target
		linkPath := fmt.Sprintf("%s/%s", fdPath, entry.Name())
		target, err := os.Readlink(linkPath)
		if err != nil {
			continue
		}
		
		if strings.HasPrefix(target, "socket:") {
			socketCount++
		}
	}
	
	return socketCount
}

// Placeholder functions for connection and bandwidth tracking
// These will be implemented in tasks 5.4 and 5.5

// getActiveConnections returns the current number of active connections
func getActiveConnections() int64 {
	// This will be populated by instrumentation in main.go (task 5.4)
	return atomic.LoadInt64(&activeConnectionsCounter)
}

// getTotalConnections returns the total number of connections since startup
func getTotalConnections() int64 {
	// This will be populated by instrumentation in main.go (task 5.4)
	return atomic.LoadInt64(&totalConnectionsCounter)
}

// getBandwidthMetrics returns bandwidth metrics
func getBandwidthMetrics() BandwidthMetrics {
	// This will be populated by instrumentation in utils.go (task 5.5)
	bytesIn := atomic.LoadInt64(&bytesInCounter)
	bytesOut := atomic.LoadInt64(&bytesOutCounter)
	
	// Calculate current Mbps using time-windowed samples
	now := time.Now()
	timeDiff := now.Sub(processMetrics.LastBandwidthTime).Seconds()
	
	var inMbps, outMbps float64
	if timeDiff > 0 {
		inDiff := float64(bytesIn - processMetrics.LastBytesIn)
		outDiff := float64(bytesOut - processMetrics.LastBytesOut)
		
		// Convert bytes/second to Mbps (1 Mbps = 1,000,000 bits/second = 125,000 bytes/second)
		inMbps = (inDiff / timeDiff) * 8 / 1_000_000
		outMbps = (outDiff / timeDiff) * 8 / 1_000_000
	}
	
	// Update cached values
	processMetrics.LastBytesIn = bytesIn
	processMetrics.LastBytesOut = bytesOut
	processMetrics.LastBandwidthTime = now
	
	return BandwidthMetrics{
		BytesIn:        bytesIn,
		BytesOut:       bytesOut,
		CurrentInMbps:  inMbps,
		CurrentOutMbps: outMbps,
	}
}

// handleMetricsAPI returns dashboard metrics as JSON
func (gs *GUIServer) handleMetricsAPI(w http.ResponseWriter, r *http.Request) {
	metrics, err := GetDashboardMetrics()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"Failed to collect metrics: %s"}`, err.Error())
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(metrics)
}
