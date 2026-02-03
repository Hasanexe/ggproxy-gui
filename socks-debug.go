package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// handleSocksDebug handles SOCKS5 proxy requests with debug logging
func handleSocksDebug(client net.Conn) {
	logChan <- fmt.Sprintf("%s: New connection", "SOCKS")

	defer client.Close()

	// Set idle timeout
	client.SetDeadline(time.Now().Add(cfg.IdleTimeout))
	defer client.SetDeadline(time.Time{})

	remoteAddr := client.RemoteAddr()
	logChan <- fmt.Sprintf("SOCKS: Starting handshake with %s", remoteAddr)

	var buf [256]byte
	// read (VER, NMETHODS, METHODS...)
	n, err := io.ReadAtLeast(client, buf[:], 2)
	if err != nil {
		logChan <- fmt.Sprintf("SOCKS: handshake error from %s: %v", remoteAddr, err)
		return
	}
	ver := buf[0]
	if ver != 0x05 {
		logChan <- fmt.Sprintf("SOCKS: Invalid version %d from %s", ver, remoteAddr)
		return
	}
	methodsCount := int(buf[1])
	logChan <- fmt.Sprintf("SOCKS: ver=5, methodsCount=%d from %s", methodsCount, remoteAddr)

	need := 2 + methodsCount
	if n < need {
		if _, err := io.ReadFull(client, buf[n:need]); err != nil {
			logChan <- fmt.Sprintf("SOCKS: reading methods error from %s: %v", remoteAddr, err)
			return
		}
	}

	// Check if auth is required
	var selectedMethod byte = 0x00 // no auth
	if cfg.AuthUsername != "" && cfg.AuthPassword != "" {
		selectedMethod = 0x02 // username/password auth
	}

	// respond with selected method
	_, err = client.Write([]byte{0x05, selectedMethod})
	if err != nil {
		logChan <- fmt.Sprintf("SOCKS: handshake write error to %s: %v", remoteAddr, err)
		return
	}
	logChan <- fmt.Sprintf("SOCKS: handshake done with %s, method=%d", remoteAddr, selectedMethod)

	// If username/password auth is required, handle subnegotiation
	if selectedMethod == 0x02 {
		if !authenticateSocks(client) {
			logChan <- fmt.Sprintf("SOCKS: authentication failed from %s", remoteAddr)
			return
		}
		logChan <- fmt.Sprintf("SOCKS: authentication successful from %s", remoteAddr)
	}

	// read (VER,CMD,RSV,ATYP)
	if _, err := io.ReadFull(client, buf[:4]); err != nil {
		logChan <- fmt.Sprintf("SOCKS: request header error from %s: %v", remoteAddr, err)
		return
	}
	version, cmd, rsv, addrType := buf[0], buf[1], buf[2], buf[3]
	logChan <- fmt.Sprintf("SOCKS: request version=%d, cmd=%d, rsv=%d, addrType=%d from %s", version, cmd, rsv, addrType, remoteAddr)

	if version != 0x05 || cmd != 0x01 {
		logChan <- fmt.Sprintf("SOCKS: unsupported request (ver=%d, cmd=%d) from %s", version, cmd, remoteAddr)
		client.Write([]byte{0x05, 0x07, 0x00, 0x01})
		return
	}

	// parse destination
	var dstIP net.IP
	var dstStr string

	switch addrType {
	case 0x01: // IPv4
		if _, err := io.ReadFull(client, buf[:4]); err != nil {
			logChan <- fmt.Sprintf("SOCKS: IPv4 read error from %s: %v", remoteAddr, err)
			return
		}
		dstIP = net.IPv4(buf[0], buf[1], buf[2], buf[3])
		dstStr = dstIP.String()
	case 0x03: // Domain
		if _, err := io.ReadFull(client, buf[:1]); err != nil {
			logChan <- fmt.Sprintf("SOCKS: domain length error from %s: %v", remoteAddr, err)
			return
		}
		domainLen := buf[0]
		if _, err := io.ReadFull(client, buf[:domainLen]); err != nil {
			logChan <- fmt.Sprintf("SOCKS: domain read error from %s: %v", remoteAddr, err)
			return
		}
		domain := string(buf[:domainLen])
		addrs, e := net.LookupIP(domain)
		if e != nil || len(addrs) == 0 {
			logChan <- fmt.Sprintf("SOCKS: domain resolve fail %s from %s: %v", domain, remoteAddr, e)
			client.Write([]byte{0x05, 0x04, 0x00, 0x01})
			return
		}
		found := false
		for _, a := range addrs {
			if v4 := a.To4(); v4 != nil {
				dstIP = v4
				dstStr = domain
				found = true
				break
			}
		}
		if !found {
			logChan <- fmt.Sprintf("SOCKS: no IPv4 found for domain=%s from %s", domain, remoteAddr)
			client.Write([]byte{0x05, 0x08, 0x00, 0x01})
			return
		}
	case 0x04:
		logChan <- fmt.Sprintf("SOCKS: IPv6 not supported from %s", remoteAddr)
		client.Write([]byte{0x05, 0x08, 0x00, 0x01})
		return
	default:
		logChan <- fmt.Sprintf("SOCKS: unknown addrType=%d from %s", addrType, remoteAddr)
		client.Write([]byte{0x05, 0x08, 0x00, 0x01})
		return
	}

	// read port
	if _, err := io.ReadFull(client, buf[:2]); err != nil {
		logChan <- fmt.Sprintf("SOCKS: port read error from %s: %v", remoteAddr, err)
		return
	}
	dstPort := binary.BigEndian.Uint16(buf[:2])

	logChan <- fmt.Sprintf("SOCKS: CONNECT to %s:%d from %s", dstStr, dstPort, remoteAddr)

	// dial
	targetAddr := net.JoinHostPort(dstIP.String(), fmt.Sprintf("%d", dstPort))
	remote, err := net.Dial("tcp", targetAddr)
	if err != nil {
		logChan <- fmt.Sprintf("SOCKS: fail connect %s for %s: %v", targetAddr, remoteAddr, err)
		client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	// success
	_, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		logChan <- fmt.Sprintf("SOCKS: fail sending success to %s: %v", remoteAddr, err)
		return
	}
	logChan <- fmt.Sprintf("SOCKS: tunnel established %s <-> %s:%d", remoteAddr, dstStr, dstPort)

	defer remote.Close()
	remote.SetDeadline(time.Now().Add(cfg.IdleTimeout))
	defer remote.SetDeadline(time.Time{})

	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Remote
	go func() {
		defer wg.Done()
		buf := make([]byte, cfg.BufferSize)
		copyBuffer(remote, client, buf, true)
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

	logChan <- fmt.Sprintf("SOCKS: tunnel closed %s <-> %s:%d", remoteAddr, dstStr, dstPort)
}
