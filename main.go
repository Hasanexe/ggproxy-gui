package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// -----------------------------------------------------
// Setup
// -----------------------------------------------------

// Logging
var (
	cfg     *Config
	logChan chan string
	reloadChan chan bool
	configMutex sync.RWMutex
)

// Connection tracking (for dashboard metrics)
var (
	activeConnectionsCounter int64
	totalConnectionsCounter  int64
)

const logChanBufferSize = 1024
const maxRecentLogs = 500

// Circular buffer for recent logs (for GUI display)
var (
	recentLogs []string
	logMutex   sync.RWMutex
)

// -----------------------------------------------------
// Main
// -----------------------------------------------------

func main() {
	configPath := flag.String("config", "/etc/ggproxy.conf", "Path to ggproxy config file")
	flag.Parse()

	// Load config
	var err error
	cfg, err = loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Setup async logging (stdout only; journald can capture stdout via systemd)
	logChan = make(chan string, logChanBufferSize)
	recentLogs = make([]string, 0, maxRecentLogs)
	go func() {
		for msg := range logChan {
			timestamp := time.Now().Format("02.01.2006 15:04:05")
			fullMsg := timestamp + " " + msg
			fmt.Fprintln(os.Stdout, fullMsg)
			
			// Store in circular buffer for GUI
			logMutex.Lock()
			recentLogs = append(recentLogs, fullMsg)
			if len(recentLogs) > maxRecentLogs {
				recentLogs = recentLogs[1:] // Remove oldest log
			}
			logMutex.Unlock()
		}
	}()

	// Setup reload channel
	reloadChan = make(chan bool, 1)

	// Setup signal handling for SIGHUP (config reload)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	go func() {
		for range sigChan {
			logChan <- "Received SIGHUP, reloading configuration..."
			reloadChan <- true
		}
	}()

	// Parse allowed CIDRs
	var networks []*net.IPNet
	for _, cidrStr := range cfg.AllowedIPs {
		ip, ipNet, e := net.ParseCIDR(cidrStr)
		if e != nil {
			logChan <- fmt.Sprintf("Invalid CIDR %q (skipped): %v", cidrStr, e)
			continue
		}
		// skip IPv6
		if ip.To4() == nil {
			logChan <- fmt.Sprintf("Skipping IPv6 CIDR %q", cidrStr)
			continue
		}
		networks = append(networks, ipNet)
	}

	// ListenConfig with global keep-alive
	lc := &net.ListenConfig{
		KeepAlive: 15 * time.Second,
	}

	addr := fmt.Sprintf("0.0.0.0:%d", cfg.Port)
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		logChan <- fmt.Sprintf("Failed to listen on %s: %v", addr, err)
		os.Exit(1)
	}
	defer ln.Close()

	modeStr := "HTTP"
	if cfg.isSocks {
		modeStr = "SOCKS"
	}
	logChan <- fmt.Sprintf("%s: listening on %s", modeStr, addr)

	// Start GUI server if enabled
	if cfg.GUIEnabled {
		go func() {
			if err := startGUIServer(cfg); err != nil {
				logChan <- fmt.Sprintf("GUI: Failed to start GUI server: %v", err)
			}
		}()
	}

	// Start config reload handler
	go func() {
		for range reloadChan {
			newCfg, err := loadConfig(*configPath)
			if err != nil {
				logChan <- fmt.Sprintf("Failed to reload config: %v", err)
				continue
			}
			configMutex.Lock()
			cfg = newCfg
			configMutex.Unlock()
			logChan <- "Configuration reloaded successfully"
		}
	}()

	// Accept loop
	for {
		conn, err := ln.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				os.Exit(0)
			}
			if !cfg.isLogOff {
				logChan <- fmt.Sprintf("%s: Accept error: %v", modeStr, err)
			}
			continue
		}

		go handleConnection(conn, networks)
	}
}

// handleConnection handles incoming connections
func handleConnection(c net.Conn, networks []*net.IPNet) {
	defer c.Close()

	// Increment total connections counter
	atomic.AddInt64(&totalConnectionsCounter, 1)
	atomic.AddInt64(&activeConnectionsCounter, 1)
	defer atomic.AddInt64(&activeConnectionsCounter, -1)

	remoteAddr, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		configMutex.RLock()
		isLogOff := cfg.isLogOff
		configMutex.RUnlock()
		if !isLogOff {
			modeStr := "HTTP"
			configMutex.RLock()
			if cfg.isSocks {
				modeStr = "SOCKS"
			}
			configMutex.RUnlock()
			logChan <- fmt.Sprintf("%s: Could not parse remote address: %v", modeStr, c.RemoteAddr())
		}
		return
	}

	if !isAllowed(remoteAddr.IP, networks) {
		configMutex.RLock()
		isLogOff := cfg.isLogOff
		isSocks := cfg.isSocks
		configMutex.RUnlock()
		if !isLogOff {
			modeStr := "HTTP"
			if isSocks {
				modeStr = "SOCKS"
			}
			logChan <- fmt.Sprintf("%s: Denying client %s (not in allowed ranges)", modeStr, remoteAddr.IP)
		}
		return
	}

	c.SetReadDeadline(time.Now().Add(10 * time.Second))

	configMutex.RLock()
	isSocks := cfg.isSocks
	isDebug := cfg.isDebug
	configMutex.RUnlock()

	if isSocks {
		if isDebug {
			handleSocksDebug(c)
		} else {
			handleSocks(c)
		}
	} else {
		if isDebug {
			handleHTTPDebug(c)
		} else {
			handleHTTP(c)
		}
	}
}

// startGUIServer starts the GUI web server
// This is implemented in gui-server.go

