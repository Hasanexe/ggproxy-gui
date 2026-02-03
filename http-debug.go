package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// handleHTTPDebug handles HTTP proxy requests with debug logging
func handleHTTPDebug(client net.Conn) {
	defer client.Close()
	logChan <- fmt.Sprintf("%s: New connection", "HTTP")

	// Set idle timeout
	client.SetDeadline(time.Now().Add(cfg.IdleTimeout))
	defer client.SetDeadline(time.Time{})

	reader := bufio.NewReader(client)

	// Read request line
	line, err := reader.ReadString('\n')
	if err != nil {
		logChan <- fmt.Sprintf("HTTP: request line read error from %s: %v", client.RemoteAddr(), err)
		return
	}

	// Parse request line
	method, requestURI, version, err := parseRequestLine(line)
	if err != nil {
		io.WriteString(client, "HTTP/1.1 400 Bad Request\r\n\r\n")
		logChan <- fmt.Sprintf("HTTP: malformed request from %s => 400", client.RemoteAddr())
		return
	}
	logChan <- fmt.Sprintf("HTTP: request line from %s: %q", client.RemoteAddr(), line)

	// Read all headers
	headers, authHeader, hostHeader, err := readHeaders(reader)
	if err != nil {
		io.WriteString(client, "HTTP/1.1 400 Bad Request\r\n\r\n")
		logChan <- fmt.Sprintf("HTTP: header read error from %s: %v", client.RemoteAddr(), err)
		return
	}

	// Validate authentication if required using pre-computed flag
	if cfg.AuthRequired {
		if !validateAuth(authHeader) {
			io.WriteString(client, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"GGProxy\"\r\n\r\n")
			logChan <- fmt.Sprintf("HTTP: auth failed for %s => 407", client.RemoteAddr())
			return
		}
	}

	// Route based on method (case-insensitive)
	if method == "CONNECT" || method == "connect" {
		logChan <- fmt.Sprintf("HTTP: CONNECT request => tunnel for %s", client.RemoteAddr())
		handleHTTPConnectDebug(client, reader, requestURI, version)
		return
	}

	// Normal forward-proxy for HTTP method=GET/POST/PUT/DELETE...
	logChan <- fmt.Sprintf("HTTP: forward proxy for method=%s from %s, URI=%s", method, client.RemoteAddr(), requestURI)

	hostPort, newFirstLine, e := parseHostPortFromAbsoluteURI(method, requestURI, version)
	// If absolute URI parsing fails or returns empty host (e.g. origin-form), try using the Host header
	if e != nil || hostPort == "" || strings.HasPrefix(hostPort, ":") {
		if hostHeader != "" {
			// If we have a Host header, use it. Default port 80 if not specified.
			if !strings.Contains(hostHeader, ":") {
				hostPort = hostHeader + ":80"
			} else {
				hostPort = hostHeader
			}
			// For origin-form, we don't rewrite the first line usually, or we keep it as is.
			newFirstLine = "" 
		} else {
			io.WriteString(client, "HTTP/1.1 400 Bad Request\r\n\r\n")
			logChan <- fmt.Sprintf("HTTP: parseHostPort error for %s: %v", client.RemoteAddr(), e)
			return
		}
	}

	remote, err := net.Dial("tcp", hostPort)
	if err != nil {
		logChan <- fmt.Sprintf("HTTP: dial fail %s => %v", hostPort, err)
		io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer remote.Close()
	remote.SetDeadline(time.Now().Add(cfg.IdleTimeout))
	defer remote.SetDeadline(time.Time{})

	// Send modified request line to remote
	if newFirstLine != "" {
		remote.Write([]byte(newFirstLine + "\r\n"))
	} else {
		remote.Write([]byte(line))
	}

	// Forward headers to remote
	for _, h := range headers {
		remote.Write([]byte(h + "\r\n"))
	}

	// Send blank line to complete HTTP request
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
	logChan <- fmt.Sprintf("HTTP: forward done for %s", client.RemoteAddr())
}


// handleHTTPConnectDebug handles HTTP CONNECT tunneling with debug logging
func handleHTTPConnectDebug(client net.Conn, reader *bufio.Reader, hostPort, httpVersion string) {
	logChan <- fmt.Sprintf("HTTP: Attempting to tunnel to %s for %s", hostPort, client.RemoteAddr())

	remote, err := net.Dial("tcp", hostPort)
	if err != nil {
		logChan <- fmt.Sprintf("HTTP: Failed to connect to %s for %s: %v", hostPort, client.RemoteAddr(), err)
		io.WriteString(client, httpVersion+" 502 Bad Gateway\r\n\r\n")
		return
	}
	// Send 200 response
	io.WriteString(client, httpVersion+" 200 Connection Established\r\n\r\n")

	logChan <- fmt.Sprintf("HTTP: tunnel established %s <-> %s", client.RemoteAddr(), hostPort)

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
	logChan <- fmt.Sprintf("HTTP: tunnel closed %s <-> %s", client.RemoteAddr(), hostPort)
}
