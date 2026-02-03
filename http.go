package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// trimCRLF efficiently removes trailing \r\n without allocation using string slicing
func trimCRLF(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	if len(s) > 0 && s[len(s)-1] == '\r' {
		s = s[:len(s)-1]
	}
	return s
}

// parseRequestLine parses HTTP request line into method, URI, and version
func parseRequestLine(line string) (method, uri, version string, err error) {
	line = trimCRLF(line)
	// Use IndexByte to avoid allocating a slice
	idx1 := strings.IndexByte(line, ' ')
	if idx1 == -1 {
		return "", "", "", fmt.Errorf("malformed request line")
	}
	method = line[:idx1]

	remaining := line[idx1+1:]
	idx2 := strings.IndexByte(remaining, ' ')
	if idx2 == -1 {
		return "", "", "", fmt.Errorf("malformed request line")
	}
	uri = remaining[:idx2]
	version = remaining[idx2+1:]

	if method == "" || uri == "" || version == "" {
		return "", "", "", fmt.Errorf("malformed request line")
	}
	return method, uri, version, nil
}

// readHeaders reads all HTTP headers until blank line
// Returns headers slice, auth header, and host header
func readHeaders(reader *bufio.Reader) (headers []string, authHeader string, hostHeader string, err error) {
	headers = make([]string, 0, 16)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return headers, "", "", err
		}

		cleanLine := trimCRLF(line)

		if cleanLine == "" {
			break
		}

		// Check for Proxy-Authorization
		if len(cleanLine) > 20 {
			if strings.EqualFold(cleanLine[:20], "Proxy-Authorization:") {
				authHeader = strings.TrimSpace(cleanLine[20:])
				continue
			}
		}

		// Check for Host
		if len(cleanLine) > 5 {
			if strings.EqualFold(cleanLine[:5], "Host:") {
				hostHeader = strings.TrimSpace(cleanLine[5:])
			}
		}

		headers = append(headers, cleanLine)
	}

	return headers, authHeader, hostHeader, nil
}

// handleHTTP handles HTTP proxy requests without debug logging
func handleHTTP(client net.Conn) {
	defer client.Close()

	client.SetDeadline(time.Now().Add(cfg.IdleTimeout))
	defer client.SetDeadline(time.Time{})

	reader := bufio.NewReader(client)

	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	method, requestURI, version, err := parseRequestLine(line)
	if err != nil {
		io.WriteString(client, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}

	headers, authHeader, hostHeader, err := readHeaders(reader)
	if err != nil {
		io.WriteString(client, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}

	if cfg.AuthRequired {
		if !validateAuth(authHeader) {
			io.WriteString(client, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"GGProxy\"\r\n\r\n")
			if !cfg.isLogOff {
				logChan <- fmt.Sprintf("HTTP: authentication failed from %s", client.RemoteAddr())
			}
			return
		}
	}

	if method == "CONNECT" || method == "connect" {
		handleHTTPConnect(client, reader, requestURI, version)
		return
	}

	hostPort, newFirstLine, e := parseHostPortFromAbsoluteURI(method, requestURI, version)
	// If absolute URI parsing fails or returns empty host, use Host header
	if e != nil || hostPort == "" || strings.HasPrefix(hostPort, ":") {
		if hostHeader != "" {
			if !strings.Contains(hostHeader, ":") {
				hostPort = hostHeader + ":80"
			} else {
				hostPort = hostHeader
			}
			newFirstLine = "" 
		} else {
			io.WriteString(client, "HTTP/1.1 400 Bad Request\r\n\r\n")
			return
		}
	}

	remote, err := net.Dial("tcp", hostPort)
	if err != nil {
		io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer remote.Close()
	remote.SetDeadline(time.Now().Add(cfg.IdleTimeout))
	defer remote.SetDeadline(time.Time{})

	if newFirstLine != "" {
		remote.Write([]byte(newFirstLine + "\r\n"))
	} else {
		remote.Write([]byte(line))
	}

	for _, h := range headers {
		remote.Write([]byte(h + "\r\n"))
	}

	remote.Write([]byte("\r\n"))

	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Remote
	go func() {
		defer wg.Done()
		buf := make([]byte, cfg.BufferSize)
		copyBuffer(remote, reader, buf, true)
		if tcpConn, ok := remote.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	// Remote -> Client
	go func() {
		defer wg.Done()
		buf := make([]byte, cfg.BufferSize)
		copyBuffer(client, remote, buf, false)
		if tcpConn, ok := client.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()

	if !cfg.isLogOff {
		logChan <- fmt.Sprintf("HTTP: forward done for %s", client.RemoteAddr())
	}
}

// handleHTTPConnect handles HTTP CONNECT tunneling without debug logging
func handleHTTPConnect(client net.Conn, reader *bufio.Reader, hostPort, httpVersion string) {
	remote, err := net.Dial("tcp", hostPort)
	if err != nil {
		io.WriteString(client, httpVersion+" 502 Bad Gateway\r\n\r\n")
		return
	}
	// Send 200 response
	io.WriteString(client, httpVersion+" 200 Connection Established\r\n\r\n")

	if !cfg.isLogOff {
		logChan <- fmt.Sprintf("HTTP: tunnel established %s <-> %s", client.RemoteAddr(), hostPort)
	}

	defer remote.Close()
	remote.SetDeadline(time.Now().Add(cfg.IdleTimeout))
	defer remote.SetDeadline(time.Time{})

	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Remote
	go func() {
		defer wg.Done()
		buf := make([]byte, cfg.BufferSize)
		copyBuffer(remote, reader, buf, true)
		if tcpConn, ok := remote.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	// Remote -> Client
	go func() {
		defer wg.Done()
		buf := make([]byte, cfg.BufferSize)
		copyBuffer(client, remote, buf, false)
		if tcpConn, ok := client.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
}

// parseHostPortFromAbsoluteURI parses host and port from absolute URI
func parseHostPortFromAbsoluteURI(method, requestURI, httpVersion string) (hostPort, newFirstLine string, err error) {
	u, e := url.Parse(requestURI)
	if e != nil {
		return "", "", fmt.Errorf("url parse error: %v", e)
	}
	host := u.Hostname()
	port := u.Port()
	scheme := strings.ToLower(u.Scheme)
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	hostPort = net.JoinHostPort(host, port)

	// If you want minimal rewriting so the server sees "GET /path HTTP/1.1" instead of absolute
	// If you want total pass-thru, set newFirstLine = "" so caller uses the original line
	newFirstLine = fmt.Sprintf("%s %s %s", method, u.RequestURI(), httpVersion)

	return hostPort, newFirstLine, nil
}
