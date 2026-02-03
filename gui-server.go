package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Session represents an authenticated user session
type Session struct {
	ID        string
	Username  string
	Token     string
	CSRFToken string
}

// GUIServer holds the GUI server state
type GUIServer struct {
	cfg      *Config
	sessions map[string]*Session
	mu       sync.RWMutex
}

var guiServer *GUIServer

// startGUIServer initializes and starts the web server
func startGUIServer(cfg *Config) error {
	guiServer = &GUIServer{
		cfg:      cfg,
		sessions: make(map[string]*Session),
	}

	addr := fmt.Sprintf("%s:%d", cfg.GUIBind, cfg.GUIPort)
	logChan <- fmt.Sprintf("GUI: Starting web server on %s", addr)

	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/", guiServer.handleRoot)
	mux.HandleFunc("/login", guiServer.handleLogin)

	// Protected routes
	mux.HandleFunc("/dashboard", guiServer.authMiddleware(guiServer.handleDashboard))
	mux.HandleFunc("/config", guiServer.authMiddleware(guiServer.handleConfig))
	mux.HandleFunc("/logs", guiServer.authMiddleware(guiServer.handleLogs))
	mux.HandleFunc("/logout", guiServer.authMiddleware(guiServer.handleLogout))

	// API endpoints
	mux.HandleFunc("/api/dashboard/metrics", guiServer.authMiddleware(guiServer.handleMetricsAPI))
	mux.HandleFunc("/api/logs/stream", guiServer.authMiddleware(guiServer.handleLogsStreamAPI))
	mux.HandleFunc("/api/config/save", guiServer.authMiddleware(guiServer.csrfMiddleware(guiServer.handleConfigSaveAPI)))
	mux.HandleFunc("/api/config/reload", guiServer.authMiddleware(guiServer.csrfMiddleware(guiServer.handleConfigReloadAPI)))

	// Static files
	mux.HandleFunc("/static/logs.js", guiServer.handleStaticFile("logs.js", "application/javascript"))
	mux.HandleFunc("/static/dashboard.js", guiServer.handleStaticFile("dashboard.js", "application/javascript"))
	mux.HandleFunc("/static/styles.css", guiServer.handleStaticFile("styles.css", "text/css"))

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("GUI server error: %v", err)
	}

	return nil
}

// generateSessionToken generates a random session token
func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// generateCSRFToken generates a random CSRF token
func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// authMiddleware wraps handlers with authentication check
func (gs *GUIServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check for session cookie
		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Validate session
		gs.mu.RLock()
		session, exists := gs.sessions[cookie.Value]
		gs.mu.RUnlock()

		if !exists || session == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Session is valid, call the next handler
		next(w, r)
	}
}

// csrfMiddleware wraps handlers with CSRF token validation for POST requests
func (gs *GUIServer) csrfMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only validate CSRF for POST requests
		if r.Method == http.MethodPost {
			// Get session
			cookie, err := r.Cookie("session_token")
			if err != nil {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			gs.mu.RLock()
			session, exists := gs.sessions[cookie.Value]
			gs.mu.RUnlock()

			if !exists || session == nil {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			// Parse form to get CSRF token (handles both application/x-www-form-urlencoded and multipart/form-data)
			if err := r.ParseMultipartForm(10 * 1024 * 1024); err != nil {
				// If multipart fails, try regular form parsing
				if err := r.ParseForm(); err != nil {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}

			// Validate CSRF token
			csrfToken := r.FormValue("csrf_token")
			if csrfToken == "" || csrfToken != session.CSRFToken {
				http.Error(w, "Forbidden: Invalid CSRF token", http.StatusForbidden)
				return
			}
		}

		// CSRF validation passed or not a POST request, call the next handler
		next(w, r)
	}
}

// handleRoot redirects to dashboard or login
func (gs *GUIServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Check if user has valid session
	cookie, err := r.Cookie("session_token")
	if err == nil {
		gs.mu.RLock()
		_, exists := gs.sessions[cookie.Value]
		gs.mu.RUnlock()

		if exists {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
	}

	// No valid session, redirect to login
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// handleLogin handles login page and authentication
func (gs *GUIServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Serve login page
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, loginPageHTML)
		return
	}

	if r.Method == http.MethodPost {
		// Handle login form submission
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Validate credentials against config
		if username != gs.cfg.GUIUser || password != gs.cfg.GUIPass {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			// Show error message with red styling
			fmt.Fprint(w, loginPageErrorHTML)
			return
		}

		// Create session
		token, err := generateSessionToken()
		if err != nil {
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}

		// Generate CSRF token
		csrfToken, err := generateCSRFToken()
		if err != nil {
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}

		session := &Session{
			ID:        token,
			Username:  username,
			Token:     token,
			CSRFToken: csrfToken,
		}

		gs.mu.Lock()
		gs.sessions[token] = session
		gs.mu.Unlock()

		// Set HTTP-only cookie (no expiration)
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			SameSite: 2, // http.SameSiteLax
		})

		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// handleDashboard serves the dashboard page
func (gs *GUIServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, dashboardPageHTML)
}

// handleConfig serves the configuration editor page
func (gs *GUIServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	// Get session to retrieve CSRF token
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	gs.mu.RLock()
	session, exists := gs.sessions[cookie.Value]
	gs.mu.RUnlock()

	if !exists || session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Read current config values from the config file path
	configValues, err := ReadConfigFile(gs.cfg.ConfigPath)
	if err != nil {
		logChan <- fmt.Sprintf("GUI: Failed to read config: %v", err)
		configValues = make(map[string][]string)
	}

	// Helper to get single value with default
	getSingleValue := func(key, defaultVal string) string {
		if vals, ok := configValues[key]; ok && len(vals) > 0 {
			return vals[0]
		}
		return defaultVal
	}

	// Prepare values for template
	proxyMode := getSingleValue("proxy_mode", "http")
	port := getSingleValue("port", "3128")
	logLevel := getSingleValue("log_level", "basic")
	idleTimeout := getSingleValue("idle_timeout", "30s")
	bufferSize := getSingleValue("buffer_size", "32768")
	
	// Auth config values
	authUser := getSingleValue("auth_user", "")
	authPass := getSingleValue("auth_pass", "")
	
	// Allowed IPs (multiple values)
	var allowedIPs string
	if vals, ok := configValues["allowed_ip"]; ok && len(vals) > 0 {
		allowedIPs = fmt.Sprintf("%v", vals) // Join all IPs with newlines
		allowedIPs = ""
		for _, ip := range vals {
			allowedIPs += ip + "\n"
		}
	}
	
	// GUI config values
	guiEnabled := getSingleValue("gui_enabled", "false")
	guiPort := getSingleValue("gui_port", "8080")
	guiUser := getSingleValue("gui_user", "")
	guiPass := getSingleValue("gui_pass", "")
	guiBind := getSingleValue("gui_bind", "127.0.0.1")

	// Build selected attributes
	httpSelected := map[bool]string{true: "selected", false: ""}[proxyMode == "http"]
	socksSelected := map[bool]string{true: "selected", false: ""}[proxyMode == "socks"]
	debugSelected := map[bool]string{true: "selected", false: ""}[logLevel == "debug"]
	basicSelected := map[bool]string{true: "selected", false: ""}[logLevel == "basic"]
	offSelected := map[bool]string{true: "selected", false: ""}[logLevel == "off"]
	guiEnabledChecked := map[bool]string{true: "checked", false: ""}[guiEnabled == "true"]

	// Inject values into template
	html := fmt.Sprintf(configPageHTML, session.CSRFToken, httpSelected, socksSelected, port, debugSelected, basicSelected, offSelected, idleTimeout, bufferSize, authUser, authPass, allowedIPs, guiEnabledChecked, guiPort, guiUser, guiPass, guiBind, session.CSRFToken)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, html)
}

// handleLogs serves the logs viewer page
func (gs *GUIServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, logsPageHTML)
}

// handleLogout invalidates the session
func (gs *GUIServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err == nil {
		gs.mu.Lock()
		delete(gs.sessions, cookie.Value)
		gs.mu.Unlock()
	}

	// Clear the cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// handleLogsStreamAPI streams logs via Server-Sent Events
func (gs *GUIServer) handleLogsStreamAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	// Get filter parameters
	filter := r.URL.Query().Get("filter")

	// Stream logs
	err := StreamRecentLogs(w, filter)
	if err != nil {
		logChan <- fmt.Sprintf("GUI: Error streaming logs: %v", err)
	}
}

// handleStaticFile serves static files with proper content type
func (gs *GUIServer) handleStaticFile(filename string, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, getStaticFile(filename))
	}
}

// getStaticFile returns the content of a static file
func getStaticFile(filename string) string {
	switch filename {
	case "logs.js":
		return logsJSContent
	case "dashboard.js":
		return dashboardJSContent
	case "styles.css":
		return stylesCSS
	default:
		return ""
	}
}

// handleConfigSaveAPI saves configuration
func (gs *GUIServer) handleConfigSaveAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Parse form data
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"status":"error","message":"Failed to parse form: %v"}`, err)
		return
	}

	// Convert form values to map[string][]string
	values := make(map[string][]string)
	for key, vals := range r.Form {
		// Special handling for allowed_ip: split by newlines
		if key == "allowed_ip" && len(vals) > 0 {
			var ips []string
			for _, val := range vals {
				// Manual split by newlines without strings package
				var currentLine []byte
				for i := 0; i < len(val); i++ {
					if val[i] == '\n' {
						// Trim and add line if not empty
						line := string(currentLine)
						// Manual trim
						start := 0
						end := len(line)
						for start < end && (line[start] == ' ' || line[start] == '\t' || line[start] == '\r') {
							start++
						}
						for end > start && (line[end-1] == ' ' || line[end-1] == '\t' || line[end-1] == '\r') {
							end--
						}
						trimmed := line[start:end]
						if trimmed != "" {
							ips = append(ips, trimmed)
						}
						currentLine = nil
					} else {
						currentLine = append(currentLine, val[i])
					}
				}
				// Handle last line
				line := string(currentLine)
				start := 0
				end := len(line)
				for start < end && (line[start] == ' ' || line[start] == '\t' || line[start] == '\r') {
					start++
				}
				for end > start && (line[end-1] == ' ' || line[end-1] == '\t' || line[end-1] == '\r') {
					end--
				}
				trimmed := line[start:end]
				if trimmed != "" {
					ips = append(ips, trimmed)
				}
			}
			values[key] = ips
		} else {
			values[key] = vals
		}
	}

	// Validate configuration values
	err = ValidateConfigValues(values)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		errMsg := err.Error()
		// Escape quotes manually
		var escaped []byte
		for i := 0; i < len(errMsg); i++ {
			if errMsg[i] == '"' {
				escaped = append(escaped, '\\')
			}
			escaped = append(escaped, errMsg[i])
		}
		fmt.Fprintf(w, `{"status":"error","message":"%s"}`, string(escaped))
		return
	}

	// Write configuration to file using the config path from cfg
	err = WriteConfigFile(gs.cfg.ConfigPath, values)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errMsg := err.Error()
		// Escape quotes manually
		var escaped []byte
		for i := 0; i < len(errMsg); i++ {
			if errMsg[i] == '"' {
				escaped = append(escaped, '\\')
			}
			escaped = append(escaped, errMsg[i])
		}
		fmt.Fprintf(w, `{"status":"error","message":"%s"}`, string(escaped))
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok","message":"Configuration saved successfully"}`)
}

// handleConfigReloadAPI triggers configuration reload
func (gs *GUIServer) handleConfigReloadAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Trigger reload
	err := ReloadConfig()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"status":"error","message":"Failed to reload config: %s"}`, err.Error())
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok","message":"Configuration reload signal sent"}`)
}


// buildConfigPageHTML builds the config page HTML with current values populated
// HTML Templates

const configPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GGProxy Admin - Configuration</title>
    <link rel="stylesheet" href="/static/styles.css">
</head>
<body>
    <header>
        <div class="header-title">GGProxy Admin</div>
        <nav>
            <a href="/dashboard" class="nav-link">Dashboard</a>
            <a href="/config" class="nav-link active">Config</a>
            <a href="/logs" class="nav-link">Logs</a>
            <a href="/logout">Logout</a>
        </nav>
    </header>
    <main>
        <div class="container">
            <h1>Configuration</h1>
            <form id="configForm">
                <input type="hidden" name="csrf_token" value="%s">
                
                <h2 style="margin-top: 0; margin-bottom: 15px; color: var(--text-secondary); font-size: 16px; text-transform: uppercase; letter-spacing: 0.5px;">Proxy Settings</h2>
                
                <div class="form-group">
                    <label for="proxy_mode">Proxy Mode <span style="color: var(--text-muted); font-size: 12px;">(e.g., proxy_mode = http)</span></label>
                    <select id="proxy_mode" name="proxy_mode">
                        <option value="http" %s>HTTP</option>
                        <option value="socks" %s>SOCKS5</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="port">Port <span style="color: var(--text-muted); font-size: 12px;">(e.g., port = 3128)</span></label>
                    <input type="number" id="port" name="port" min="1" max="65535" value="%s">
                </div>
                <div class="form-group">
                    <label for="log_level">Log Level <span style="color: var(--text-muted); font-size: 12px;">(e.g., log_level = basic)</span></label>
                    <select id="log_level" name="log_level">
                        <option value="debug" %s>Debug</option>
                        <option value="basic" %s>Basic</option>
                        <option value="off" %s>Off</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="idle_timeout">Idle Timeout <span style="color: var(--text-muted); font-size: 12px;">(e.g., idle_timeout = 30s)</span></label>
                    <input type="text" id="idle_timeout" name="idle_timeout" placeholder="e.g., 30s, 5m" value="%s">
                </div>
                <div class="form-group">
                    <label for="buffer_size">Buffer Size (bytes) <span style="color: var(--text-muted); font-size: 12px;">(e.g., buffer_size = 32768)</span></label>
                    <input type="number" id="buffer_size" name="buffer_size" min="1" value="%s">
                </div>
                
                <h2 style="margin-top: 30px; margin-bottom: 15px; color: var(--text-secondary); font-size: 16px; text-transform: uppercase; letter-spacing: 0.5px;">Authentication</h2>
                
                <div class="form-group">
                    <label for="auth_user">Auth Username <span style="color: var(--text-muted); font-size: 12px;">(e.g., auth_user = hasan)</span></label>
                    <input type="text" id="auth_user" name="auth_user" placeholder="Leave empty to disable" value="%s">
                </div>
                <div class="form-group">
                    <label for="auth_pass">Auth Password <span style="color: var(--text-muted); font-size: 12px;">(e.g., auth_pass = mypassword)</span></label>
                    <input type="password" id="auth_pass" name="auth_pass" placeholder="Leave empty to disable" value="%s">
                </div>
                
                <div class="form-group">
                    <label for="allowed_ip">Allowed IPs (CIDR) <span style="color: var(--text-muted); font-size: 12px;">One per line (e.g., allowed_ip = 192.168.1.0/24)</span></label>
                    <textarea id="allowed_ip" name="allowed_ip" style="font-family: monospace; min-height: 100px;">%s</textarea>
                </div>
                
                <h2 style="margin-top: 30px; margin-bottom: 15px; color: var(--text-secondary); font-size: 16px; text-transform: uppercase; letter-spacing: 0.5px;">GUI Settings</h2>
                
                <div class="form-group">
                    <label for="gui_enabled">
                        <input type="checkbox" id="gui_enabled" name="gui_enabled" value="true" %s>
                        Enable Web GUI
                    </label>
                </div>
                <div class="form-group">
                    <label for="gui_port">GUI Port <span style="color: var(--text-muted); font-size: 12px;">(e.g., gui_port = 8080)</span></label>
                    <input type="number" id="gui_port" name="gui_port" min="1" max="65535" value="%s">
                </div>
                <div class="form-group">
                    <label for="gui_user">GUI Username <span style="color: var(--text-muted); font-size: 12px;">(e.g., gui_user = admin)</span></label>
                    <input type="text" id="gui_user" name="gui_user" value="%s">
                </div>
                <div class="form-group">
                    <label for="gui_pass">GUI Password <span style="color: var(--text-muted); font-size: 12px;">(e.g., gui_pass = secret)</span></label>
                    <input type="password" id="gui_pass" name="gui_pass" value="%s">
                </div>
                <div class="form-group">
                    <label for="gui_bind">GUI Bind Address <span style="color: var(--text-muted); font-size: 12px;">(e.g., gui_bind = 127.0.0.1)</span></label>
                    <input type="text" id="gui_bind" name="gui_bind" placeholder="e.g., 127.0.0.1 or 0.0.0.0" value="%s">
                </div>
                
                <div class="button-group">
                    <button type="button" onclick="saveConfig()">Save Configuration</button>
                    <button type="button" class="secondary" onclick="reloadConfig()">Reload Configuration</button>
                </div>
            </form>
        </div>
    </main>
    <script>
        const csrfToken = '%s';
        
        function saveConfig() {
            const formData = new FormData(document.getElementById('configForm'));
            
            fetch('/api/config/save', { 
                method: 'POST',
                body: formData
            })
                .then(r => r.json())
                .then(data => {
                    if (data.status === 'ok') {
                        alert(data.message || 'Configuration saved successfully');
                    } else {
                        alert('Error: ' + (data.message || 'Unknown error'));
                    }
                })
                .catch(err => alert('Failed to save configuration: ' + err));
        }
        
        function reloadConfig() {
            const formData = new FormData();
            formData.append('csrf_token', csrfToken);
            
            fetch('/api/config/reload', { 
                method: 'POST',
                body: formData
            })
                .then(r => r.json())
                .then(data => alert(data.message || 'Configuration reloaded'))
                .catch(err => alert('Failed to reload configuration: ' + err));
        }
    </script>
</body>
</html>`

const loginPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GGProxy Admin - Login</title>
    <link rel="stylesheet" href="/static/styles.css">
</head>
<body class="login-page">
    <div class="login-container">
        <h1>GGProxy Admin</h1>
        <form method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>`

const loginPageErrorHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GGProxy Admin - Login</title>
    <link rel="stylesheet" href="/static/styles.css">
</head>
<body class="login-page">
    <div class="login-container">
        <h1>GGProxy Admin</h1>
        <div style="color: var(--error); background: rgba(244, 67, 54, 0.2); border: 1px solid var(--error); padding: 10px; border-radius: 4px; margin-bottom: 15px; font-size: 14px;">Invalid username or password</div>
        <form method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>`

const baseLayoutHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GGProxy Admin - %s</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #1e1e1e;
            color: #e0e0e0;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }
        header {
            background: #2d2d2d;
            border-bottom: 1px solid #404040;
            padding: 0 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            height: 60px;
        }
        .header-title {
            font-size: 20px;
            font-weight: 600;
            color: #4a9eff;
        }
        nav {
            display: flex;
            gap: 20px;
        }
        nav a {
            color: #b0b0b0;
            text-decoration: none;
            padding: 8px 12px;
            border-radius: 4px;
            transition: all 0.2s;
        }
        nav a:hover {
            background: #404040;
            color: #4a9eff;
        }
        nav a.active {
            background: #4a9eff;
            color: white;
        }
        main {
            flex: 1;
            padding: 20px;
            max-width: 1200px;
            margin: 0 auto;
            width: 100%;
        }
        .container {
            background: #2d2d2d;
            border: 1px solid #404040;
            border-radius: 8px;
            padding: 20px;
        }
        h1 {
            margin-bottom: 20px;
            font-size: 28px;
            color: #4a9eff;
        }
        @media (max-width: 768px) {
            header {
                flex-direction: column;
                height: auto;
                padding: 10px 20px;
                gap: 10px;
            }
            nav {
                width: 100%;
                flex-wrap: wrap;
            }
            main {
                padding: 10px;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="header-title">GGProxy Admin</div>
        <nav>
            <a href="/dashboard" class="nav-link">Dashboard</a>
            <a href="/config" class="nav-link">Config</a>
            <a href="/logs" class="nav-link">Logs</a>
            <a href="/logout">Logout</a>
        </nav>
    </header>
    <main>
        <div class="container">
            %s
        </div>
    </main>
</body>
</html>`

const dashboardPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GGProxy Admin - Dashboard</title>
    <link rel="stylesheet" href="/static/styles.css">
</head>
<body>
    <header>
        <div class="header-title">GGProxy Admin</div>
        <nav>
            <a href="/dashboard" class="nav-link active">Dashboard</a>
            <a href="/config" class="nav-link">Config</a>
            <a href="/logs" class="nav-link">Logs</a>
            <a href="/logout">Logout</a>
        </nav>
    </header>
    <main>
        <div class="container">
            <h1>Dashboard</h1>
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-label">Service Status</div>
                    <div class="status-badge status-healthy">Healthy</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Uptime</div>
                    <div class="metric-value" id="uptime">0s</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Active Connections</div>
                    <div class="metric-value" id="active-conns">0</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Total Connections</div>
                    <div class="metric-value" id="total-conns">0</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Bandwidth In</div>
                    <div class="metric-value" id="bandwidth-in">0 Mbps</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Bandwidth Out</div>
                    <div class="metric-value" id="bandwidth-out">0 Mbps</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">CPU Usage</div>
                    <div class="metric-value" id="cpu-usage">0%</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Memory Usage</div>
                    <div class="metric-value" id="memory-usage">0 MB</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Goroutines</div>
                    <div class="metric-value" id="goroutines">0</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Open Sockets</div>
                    <div class="metric-value" id="open-sockets">0</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Total Bytes In</div>
                    <div class="metric-value" id="bytes-in">0 B</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Total Bytes Out</div>
                    <div class="metric-value" id="bytes-out">0 B</div>
                </div>
            </div>
        </div>
    </main>
    <script src="/static/dashboard.js"></script>
</body>
</html>`

const logsPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GGProxy Admin - Logs</title>
    <link rel="stylesheet" href="/static/styles.css">
</head>
<body>
    <header>
        <div class="header-title">GGProxy Admin</div>
        <nav>
            <a href="/dashboard" class="nav-link">Dashboard</a>
            <a href="/config" class="nav-link">Config</a>
            <a href="/logs" class="nav-link active">Logs</a>
            <a href="/logout">Logout</a>
        </nav>
    </header>
    <main>
        <div class="container">
            <h1>Logs</h1>
            <p style="color: var(--text-secondary); font-size: 13px; margin-bottom: 15px;">
                Showing current session logs (last 500 entries). Logs are stored in memory and will be cleared on application restart. For persistent logs on Linux, please use journald.
            </p>
            <div class="filter-bar">
                <input type="text" id="logFilter" placeholder="Search logs...">
                <select id="logLevel">
                    <option value="">All Levels</option>
                    <option value="debug">Debug</option>
                    <option value="info">Info</option>
                    <option value="error">Error</option>
                </select>
                <button onclick="pauseLogs()">Pause</button>
            </div>
            <div class="logs-container" id="logsContainer"></div>
        </div>
    </main>
    <script src="/static/logs.js"></script>
</body>
</html>`

const logsJSContent = `
// Log viewer state
let isPaused = false;
let eventSource = null;
let autoScroll = true;

// Initialize log viewer
function initLogs() {
    const filterInput = document.getElementById('logFilter');
    const levelSelect = document.getElementById('logLevel');
    
    // Start streaming logs
    startLogStream();
    
    // Add event listeners for filters
    filterInput.addEventListener('input', debounce(applyFilters, 300));
    levelSelect.addEventListener('change', applyFilters);
}

// Start streaming logs from server
function startLogStream() {
    const filter = document.getElementById('logFilter').value;
    const level = document.getElementById('logLevel').value;
    
    let url = '/api/logs/stream';
    const params = new URLSearchParams();
    if (filter) params.append('filter', filter);
    if (level) params.append('level', level);
    
    if (params.toString()) {
        url += '?' + params.toString();
    }
    
    eventSource = new EventSource(url);
    
    eventSource.onmessage = function(event) {
        if (!isPaused) {
            try {
                const logEntry = JSON.parse(event.data);
                appendLogEntry(logEntry);
            } catch (e) {
                console.error('Failed to parse log entry:', e);
            }
        }
    };
    
    eventSource.onerror = function() {
        console.error('Log stream error');
        eventSource.close();
        // Attempt to reconnect after 3 seconds
        setTimeout(startLogStream, 3000);
    };
}

// Append a log entry to the container
function appendLogEntry(entry) {
    const container = document.getElementById('logsContainer');
    const logDiv = document.createElement('div');
    logDiv.className = 'log-entry log-' + (entry.level || 'info').toLowerCase();
    
    const timestamp = new Date(entry.timestamp).toLocaleTimeString();
    const level = (entry.level || 'INFO').toUpperCase();
    const message = entry.message || '';
    
    logDiv.textContent = '[' + timestamp + '] [' + level + '] ' + message;
    container.appendChild(logDiv);
    
    // Auto-scroll to bottom if enabled
    if (autoScroll) {
        container.scrollTop = container.scrollHeight;
    }
}

// Pause/resume log streaming
function pauseLogs() {
    isPaused = !isPaused;
    const btn = event.target;
    btn.textContent = isPaused ? 'Resume' : 'Pause';
    
    if (!isPaused) {
        // Resume scrolling
        autoScroll = true;
        const container = document.getElementById('logsContainer');
        container.scrollTop = container.scrollHeight;
    }
}

// Apply filters and restart stream
function applyFilters() {
    if (eventSource) {
        eventSource.close();
    }
    
    const container = document.getElementById('logsContainer');
    container.innerHTML = '';
    
    startLogStream();
}

// Debounce utility function
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Track auto-scroll state
document.addEventListener('DOMContentLoaded', function() {
    const container = document.getElementById('logsContainer');
    
    // Disable auto-scroll when user scrolls up
    container.addEventListener('scroll', function() {
        const isAtBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 10;
        autoScroll = isAtBottom;
    });
    
    initLogs();
});
`

const dashboardJSContent = `
// Dashboard metrics polling and rendering

// Update metrics every 2 seconds
function updateMetrics() {
    fetch('/api/dashboard/metrics')
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to fetch metrics');
            }
            return response.json();
        })
        .then(data => renderMetrics(data))
        .catch(error => {
            console.error('Error fetching metrics:', error);
            displayMetricsError();
        });
}

// Render metrics on the dashboard
function renderMetrics(data) {
    // Service status badge
    const statusBadge = document.querySelector('.status-badge');
    if (statusBadge) {
        statusBadge.textContent = data.service_status || 'unknown';
        statusBadge.className = 'status-badge status-' + (data.service_status || 'down');
    }

    // Uptime
    const uptimeElement = document.getElementById('uptime');
    if (uptimeElement) {
        uptimeElement.textContent = data.uptime || 'N/A';
    }

    // Active connections
    const activeConnsElement = document.getElementById('active-conns');
    if (activeConnsElement) {
        activeConnsElement.textContent = formatNumber(data.active_connections || 0);
    }

    // Total connections
    const totalConnsElement = document.getElementById('total-conns');
    if (totalConnsElement) {
        totalConnsElement.textContent = formatNumber(data.total_connections || 0);
    }

    // Bandwidth in
    const bandwidthInElement = document.getElementById('bandwidth-in');
    if (bandwidthInElement) {
        const mbps = data.bandwidth?.current_in_mbps || 0;
        bandwidthInElement.textContent = mbps.toFixed(2) + ' Mbps';
    }

    // Bandwidth out
    const bandwidthOutElement = document.getElementById('bandwidth-out');
    if (bandwidthOutElement) {
        const mbps = data.bandwidth?.current_out_mbps || 0;
        bandwidthOutElement.textContent = mbps.toFixed(2) + ' Mbps';
    }

    // CPU usage
    const cpuElement = document.getElementById('cpu-usage');
    if (cpuElement) {
        const cpu = data.cpu_percent || 0;
        cpuElement.textContent = cpu.toFixed(1) + '%';
    }

    // Memory usage
    const memoryElement = document.getElementById('memory-usage');
    if (memoryElement) {
        const bytes = data.memory?.rss_bytes || 0;
        const mb = bytes / 1024 / 1024;
        memoryElement.textContent = mb.toFixed(1) + ' MB';
    }

    // Goroutines
    const goroutinesElement = document.getElementById('goroutines');
    if (goroutinesElement) {
        goroutinesElement.textContent = formatNumber(data.goroutines || 0);
    }

    // Open sockets
    const socketsElement = document.getElementById('open-sockets');
    if (socketsElement) {
        socketsElement.textContent = formatNumber(data.open_sockets || 0);
    }

    // Bytes in/out (for reference)
    const bytesInElement = document.getElementById('bytes-in');
    if (bytesInElement) {
        const bytes = data.bandwidth?.bytes_in || 0;
        bytesInElement.textContent = formatBytes(bytes);
    }

    const bytesOutElement = document.getElementById('bytes-out');
    if (bytesOutElement) {
        const bytes = data.bandwidth?.bytes_out || 0;
        bytesOutElement.textContent = formatBytes(bytes);
    }
}

// Display error message when metrics are unavailable
function displayMetricsError() {
    const elements = [
        'active-conns', 'total-conns', 'bandwidth-in', 'bandwidth-out',
        'cpu-usage', 'memory-usage', 'goroutines', 'open-sockets',
        'bytes-in', 'bytes-out', 'uptime'
    ];

    elements.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = 'N/A';
        }
    });

    const statusBadge = document.querySelector('.status-badge');
    if (statusBadge) {
        statusBadge.textContent = 'down';
        statusBadge.className = 'status-badge status-down';
    }
}

// Format number with thousands separator
function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

// Format bytes to human-readable format
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
}

// Initialize dashboard on page load
document.addEventListener('DOMContentLoaded', function() {
    // Initial update
    updateMetrics();
    
    // Set up polling interval (2 seconds)
    setInterval(updateMetrics, 2000);
});
`

const stylesCSS = `/* GGProxy Admin GUI Styles */
/* Minimal, clean dark theme with responsive design */

/* ============================================
   CSS Variables - Color Palette
   ============================================ */
:root {
    /* Background colors */
    --bg-primary: #1e1e1e;
    --bg-secondary: #2d2d2d;
    --bg-tertiary: #404040;
    
    /* Text colors */
    --text-primary: #e0e0e0;
    --text-secondary: #b0b0b0;
    --text-muted: #888;
    
    /* Accent colors */
    --accent-primary: #4a9eff;
    --accent-hover: #3a8eef;
    
    /* Status colors */
    --success: #4caf50;
    --warning: #ff9800;
    --error: #f44336;
    
    /* Border colors */
    --border-primary: #404040;
    --border-focus: #4a9eff;
    
    /* Spacing */
    --spacing-xs: 8px;
    --spacing-sm: 10px;
    --spacing-md: 20px;
    --spacing-lg: 30px;
    --spacing-xl: 40px;
    
    /* Border radius */
    --radius-sm: 4px;
    --radius-md: 8px;
    
    /* Transitions */
    --transition-fast: 0.2s;
    --transition-medium: 0.3s;
}

/* ============================================
   Base Styles & Reset
   ============================================ */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    display: flex;
    flex-direction: column;
    min-height: 100vh;
    line-height: 1.6;
}

body.login-page {
    display: flex;
    justify-content: center;
    align-items: center;
    flex-direction: column;
}

/* ============================================
   Header & Navigation
   ============================================ */
header {
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border-primary);
    padding: 0 var(--spacing-md);
    display: flex;
    justify-content: space-between;
    align-items: center;
    height: 60px;
    flex-shrink: 0;
}

.header-title {
    font-size: 20px;
    font-weight: 600;
    color: var(--accent-primary);
}

nav {
    display: flex;
    gap: var(--spacing-md);
    align-items: center;
}

nav a {
    color: var(--text-secondary);
    text-decoration: none;
    padding: var(--spacing-xs) 12px;
    border-radius: var(--radius-sm);
    transition: all var(--transition-fast);
    font-weight: 500;
}

nav a:hover {
    background: var(--bg-tertiary);
    color: var(--accent-primary);
}

nav a.active {
    background: var(--accent-primary);
    color: white;
}

/* ============================================
   Main Content Layout
   ============================================ */
main {
    flex: 1;
    padding: var(--spacing-md);
    max-width: 1200px;
    margin: 0 auto;
    width: 100%;
}

.container {
    background: var(--bg-secondary);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius-md);
    padding: var(--spacing-md);
}

h1 {
    margin-bottom: var(--spacing-md);
    font-size: 28px;
    color: var(--accent-primary);
    font-weight: 600;
}

h2 {
    margin-bottom: var(--spacing-sm);
    font-size: 20px;
    color: var(--text-primary);
    font-weight: 600;
}

/* ============================================
   Login Page Styles
   ============================================ */
.login-container {
    background: var(--bg-secondary);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius-md);
    padding: var(--spacing-xl);
    width: 100%;
    max-width: 400px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
}

.login-container h1 {
    text-align: center;
    margin-bottom: var(--spacing-lg);
    font-size: 24px;
}

/* ============================================
   Form Elements
   ============================================ */
.form-group {
    margin-bottom: var(--spacing-md);
}

.form-section {
    margin-bottom: var(--spacing-lg);
    padding-bottom: var(--spacing-md);
    border-bottom: 1px solid var(--border-primary);
}

.form-section:last-child {
    border-bottom: none;
}

.form-section h2 {
    margin-bottom: var(--spacing-md);
    color: var(--text-secondary);
    font-size: 16px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

label {
    display: block;
    margin-bottom: var(--spacing-xs);
    font-weight: 500;
    color: var(--text-secondary);
    font-size: 14px;
}

input[type="text"],
input[type="password"],
input[type="number"],
select,
textarea {
    width: 100%;
    padding: var(--spacing-sm) 12px;
    background: var(--bg-primary);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font-size: 14px;
    font-family: inherit;
    transition: border-color var(--transition-fast);
}

input[type="text"]:focus,
input[type="password"]:focus,
input[type="number"]:focus,
select:focus,
textarea:focus {
    outline: none;
    border-color: var(--border-focus);
}

input[type="text"]::placeholder,
textarea::placeholder {
    color: var(--text-muted);
}

textarea {
    resize: vertical;
    min-height: 100px;
}

/* ============================================
   Buttons
   ============================================ */
button,
.button {
    padding: var(--spacing-sm) var(--spacing-md);
    background: var(--accent-primary);
    border: none;
    border-radius: var(--radius-sm);
    color: white;
    font-weight: 600;
    font-size: 14px;
    cursor: pointer;
    transition: background var(--transition-fast);
    font-family: inherit;
}

button:hover,
.button:hover {
    background: var(--accent-hover);
}

button:disabled,
.button:disabled {
    background: var(--bg-tertiary);
    cursor: not-allowed;
    opacity: 0.6;
}

button.secondary {
    background: var(--bg-tertiary);
    color: var(--text-primary);
}

button.secondary:hover {
    background: #505050;
}

button.success {
    background: var(--success);
}

button.success:hover {
    background: #45a049;
}

button.danger {
    background: var(--error);
}

button.danger:hover {
    background: #d32f2f;
}

.button-group {
    display: flex;
    gap: var(--spacing-sm);
    margin-top: var(--spacing-lg);
}

/* ============================================
   Dashboard Metrics Grid
   ============================================ */
.metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: var(--spacing-md);
    margin-top: var(--spacing-md);
}

.metric-card {
    background: var(--bg-primary);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius-md);
    padding: var(--spacing-md);
    text-align: center;
    transition: transform var(--transition-fast), box-shadow var(--transition-fast);
}

.metric-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
}

.metric-label {
    color: var(--text-secondary);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: var(--spacing-sm);
    font-weight: 600;
}

.metric-value {
    font-size: 32px;
    font-weight: 600;
    color: var(--accent-primary);
    line-height: 1.2;
}

.metric-value.large {
    font-size: 40px;
}

.metric-value.small {
    font-size: 24px;
}

/* ============================================
   Status Badges
   ============================================ */
.status-badge {
    display: inline-block;
    padding: 6px 12px;
    border-radius: var(--radius-sm);
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-top: var(--spacing-sm);
}

.status-healthy {
    background: var(--success);
    color: white;
}

.status-degraded {
    background: var(--warning);
    color: white;
}

.status-down {
    background: var(--error);
    color: white;
}

/* ============================================
   Logs Viewer
   ============================================ */
.filter-bar {
    display: flex;
    gap: var(--spacing-sm);
    margin-bottom: var(--spacing-md);
    flex-wrap: wrap;
    align-items: center;
}

.filter-bar input,
.filter-bar select {
    padding: var(--spacing-xs) 12px;
    background: var(--bg-primary);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font-size: 14px;
    flex: 1;
    min-width: 150px;
}

.filter-bar button {
    padding: var(--spacing-xs) 16px;
    flex-shrink: 0;
}

.logs-container {
    background: var(--bg-primary);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius-sm);
    padding: var(--spacing-sm);
    overflow-y: auto;
    max-height: 600px;
    font-family: 'Courier New', 'Consolas', 'Monaco', monospace;
    font-size: 12px;
    line-height: 1.5;
}

.log-entry {
    padding: var(--spacing-xs);
    border-bottom: 1px solid var(--border-primary);
    word-wrap: break-word;
}

.log-entry:last-child {
    border-bottom: none;
}

.log-entry:hover {
    background: var(--bg-secondary);
}

.log-debug {
    color: var(--text-muted);
}

.log-info {
    color: var(--accent-primary);
}

.log-error {
    color: var(--error);
}

.log-warning {
    color: var(--warning);
}

/* ============================================
   Notifications & Alerts
   ============================================ */
.notification {
    padding: 12px 16px;
    border-radius: var(--radius-sm);
    margin-bottom: var(--spacing-md);
    display: flex;
    align-items: center;
    gap: var(--spacing-sm);
}

.notification.success {
    background: rgba(76, 175, 80, 0.2);
    border: 1px solid var(--success);
    color: var(--success);
}

.notification.error {
    background: rgba(244, 67, 54, 0.2);
    border: 1px solid var(--error);
    color: var(--error);
}

.notification.warning {
    background: rgba(255, 152, 0, 0.2);
    border: 1px solid var(--warning);
    color: var(--warning);
}

.notification.info {
    background: rgba(74, 158, 255, 0.2);
    border: 1px solid var(--accent-primary);
    color: var(--accent-primary);
}

/* ============================================
   Utility Classes
   ============================================ */
.text-center {
    text-align: center;
}

.text-right {
    text-align: right;
}

.text-muted {
    color: var(--text-muted);
}

.text-success {
    color: var(--success);
}

.text-error {
    color: var(--error);
}

.text-warning {
    color: var(--warning);
}

.mt-sm { margin-top: var(--spacing-sm); }
.mt-md { margin-top: var(--spacing-md); }
.mt-lg { margin-top: var(--spacing-lg); }

.mb-sm { margin-bottom: var(--spacing-sm); }
.mb-md { margin-bottom: var(--spacing-md); }
.mb-lg { margin-bottom: var(--spacing-lg); }

.hidden {
    display: none;
}

/* ============================================
   Responsive Design - Tablet (768px)
   ============================================ */
@media (max-width: 768px) {
    header {
        flex-direction: column;
        height: auto;
        padding: var(--spacing-sm) var(--spacing-md);
        gap: var(--spacing-sm);
    }
    
    nav {
        width: 100%;
        flex-wrap: wrap;
        justify-content: center;
    }
    
    nav a {
        flex: 1;
        text-align: center;
        min-width: 80px;
    }
    
    main {
        padding: var(--spacing-sm);
    }
    
    .container {
        padding: var(--spacing-sm);
    }
    
    h1 {
        font-size: 24px;
    }
    
    .metrics-grid {
        grid-template-columns: 1fr;
    }
    
    .button-group {
        flex-direction: column;
    }
    
    .button-group button {
        width: 100%;
    }
    
    .filter-bar {
        flex-direction: column;
    }
    
    .filter-bar input,
    .filter-bar select,
    .filter-bar button {
        width: 100%;
        min-width: auto;
    }
    
    .metric-value {
        font-size: 28px;
    }
    
    .login-container {
        padding: var(--spacing-md);
    }
}

/* ============================================
   Responsive Design - Desktop (1024px+)
   ============================================ */
@media (min-width: 1024px) {
    .metrics-grid {
        grid-template-columns: repeat(3, 1fr);
    }
    
    .logs-container {
        max-height: 700px;
    }
    
    main {
        padding: var(--spacing-lg);
    }
}

/* ============================================
   Smooth Transitions & Animations
   ============================================ */
a,
button,
input,
select,
textarea,
.metric-card {
    transition: all var(--transition-fast) ease-in-out;
}

/* Fade in animation for page load */
@keyframes fadeIn {
    from {
        opacity: 0;
        transform: translateY(10px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.container {
    animation: fadeIn 0.3s ease-in-out;
}

/* Pulse animation for status badges */
@keyframes pulse {
    0%, 100% {
        opacity: 1;
    }
    50% {
        opacity: 0.7;
    }
}

.status-badge.pulse {
    animation: pulse 2s infinite;
}

/* ============================================
   Scrollbar Styling
   ============================================ */
::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}

::-webkit-scrollbar-track {
    background: var(--bg-primary);
}

::-webkit-scrollbar-thumb {
    background: var(--bg-tertiary);
    border-radius: var(--radius-sm);
}

::-webkit-scrollbar-thumb:hover {
    background: #505050;
}

/* ============================================
   Print Styles
   ============================================ */
@media print {
    header,
    nav,
    .button-group,
    .filter-bar {
        display: none;
    }
    
    body {
        background: white;
        color: black;
    }
    
    .container {
        border: none;
        box-shadow: none;
    }
}
`
