package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Config holds all configuration options
type Config struct {
	Port         int
	isSocks      bool
	isDebug      bool
	isLogOff     bool
	AllowedIPs   []string
	IdleTimeout  time.Duration
	BufferSize   int
	AuthUsername string
	AuthPassword string
	AuthRequired bool   // Computed flag to avoid repeated string comparisons
	AuthBasicToken []byte // Pre-computed Basic Auth token (bytes)
	
	// GUI configuration
	GUIEnabled  bool
	GUIPort     int
	GUIUser     string
	GUIPass     string
	GUIBind     string
	
	// Config file path (for GUI to read/write)
	ConfigPath  string
}

// loadConfig loads configuration from the specified file path
func loadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Default config with mode=http, port=3128
	cfg := &Config{
		isSocks:      false,            //proxy_mode   = http
		isDebug:      false,            //log_level    = debug
		isLogOff:     false,            //log_level    = off || none
		Port:         3128,             //port             = 3128
		AllowedIPs:   []string{},       //allowed_ip   = 0.0.0.0/0 (cidr)
		IdleTimeout:  30 * time.Second, //idle_timeout
		BufferSize:   32 * 1024,        //buffer_size
		AuthUsername: "",               //auth_username
		AuthPassword: "",               //auth_password
		
		// GUI defaults
		GUIEnabled:   false,            //gui_enabled  = false
		GUIPort:      8080,             //gui_port     = 8080
		GUIUser:      "",               //gui_user     = ""
		GUIPass:      "",               //gui_pass     = ""
		GUIBind:      "127.0.0.1",      //gui_bind     = 127.0.0.1
		
		// Store config path for GUI
		ConfigPath:   path,
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
			return nil, err
		}
	}

	lines := strings.Split(content.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "proxy_mode":
			cfg.isSocks = strings.HasPrefix(strings.ToLower(val), "socks")
		case "port":
			var p int
			fmt.Sscanf(val, "%d", &p)
			if p > 0 && p < 65536 {
				cfg.Port = p
			}
		case "log_file":
			// deprecated (stdout-only logging); intentionally ignored
		case "log_level":
			logLevel := strings.ToLower(val)
			cfg.isDebug = logLevel == "debug"
			cfg.isLogOff = logLevel == "off" || logLevel == "none"
		case "allowed_ip":
			cfg.AllowedIPs = append(cfg.AllowedIPs, val)
		case "idle_timeout":
			dur, err := time.ParseDuration(val)
			if err != nil {
				return nil, fmt.Errorf("invalid idle_timeout: %v", err)
			}
			if dur <= 0 {
				return nil, fmt.Errorf("idle_timeout must be > 0")
			}
			cfg.IdleTimeout = dur
		case "buffer_size":
			var size int
			if _, err := fmt.Sscanf(val, "%d", &size); err != nil {
				return nil, fmt.Errorf("invalid buffer_size: %v", err)
			}
			if size <= 0 {
				return nil, fmt.Errorf("buffer_size must be > 0")
			}
			cfg.BufferSize = size
		case "auth_user":
			cfg.AuthUsername = val
		case "auth_pass":
			cfg.AuthPassword = val
		case "gui_enabled":
			lowerVal := strings.ToLower(val)
			cfg.GUIEnabled = (lowerVal == "true" || lowerVal == "1" || lowerVal == "yes")
		case "gui_port":
			var p int
			fmt.Sscanf(val, "%d", &p)
			if p > 0 && p < 65536 {
				cfg.GUIPort = p
			}
		case "gui_user":
			cfg.GUIUser = val
		case "gui_pass":
			cfg.GUIPass = val
		case "gui_bind":
			cfg.GUIBind = val
		case "log_buffer_size":
			// deprecated (stdout-only logging); intentionally ignored
		}
	}

	// Compute AuthRequired flag once at startup to avoid repeated string comparisons
	cfg.AuthRequired = (cfg.AuthUsername != "" && cfg.AuthPassword != "")

	// Pre-compute AuthBasicToken
	if cfg.AuthRequired {
		auth := cfg.AuthUsername + ":" + cfg.AuthPassword
		// "Basic " + base64(user:pass)
		// We store the full header value "Basic <token>" as bytes for direct comparison
		// Wait, the plan says: "Pre-compute the Auth Token: ... generate the exact expected HTTP header value: Basic <base64(user:pass)>."
		encoded := base64.StdEncoding.EncodeToString([]byte(auth))
		cfg.AuthBasicToken = []byte("Basic " + encoded)
	}

	return cfg, nil
}
