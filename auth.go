package main

import (
	"crypto/subtle"
	"io"
	"net"
)

// validateAuth validates HTTP Basic Authentication header value
func validateAuth(authHeader string) bool {
	if !cfg.AuthRequired {
		return true
	}

	// Direct byte comparison with pre-computed token
	if subtle.ConstantTimeCompare([]byte(authHeader), cfg.AuthBasicToken) == 1 {
		return true
	}

	return false
}

// authenticateSocks performs SOCKS5 username/password authentication (RFC 1929)
func authenticateSocks(client net.Conn) bool {
	var buf [256]byte

	// Read version, username length
	if _, err := io.ReadFull(client, buf[:2]); err != nil {
		return false
	}
	version, ulen := buf[0], buf[1]

	if version != 0x01 || ulen > 255 {
		return false
	}

	// Read username
	if _, err := io.ReadFull(client, buf[:ulen]); err != nil {
		return false
	}
	username := string(buf[:ulen])

	// Read password length
	if _, err := io.ReadFull(client, buf[:1]); err != nil {
		return false
	}
	plen := buf[0]

	if plen > 255 {
		return false
	}

	// Read password
	if _, err := io.ReadFull(client, buf[:plen]); err != nil {
		return false
	}
	password := string(buf[:plen])

	// Verify credentials using constant-time comparison
	if subtle.ConstantTimeCompare([]byte(username), []byte(cfg.AuthUsername)) == 1 &&
		subtle.ConstantTimeCompare([]byte(password), []byte(cfg.AuthPassword)) == 1 {
		// Success
		client.Write([]byte{0x01, 0x00})
		return true
	}

	// Failure
	client.Write([]byte{0x01, 0x01})
	return false
}
