package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// Pre-allocated SOCKS5 response constants to avoid repeated allocations
var (
	socksResponseSuccess          = []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	socksResponseCmdNotSupported  = []byte{0x05, 0x07, 0x00, 0x01}
	socksResponseHostUnreachable  = []byte{0x05, 0x04, 0x00, 0x01}
	socksResponseAddrNotSupported = []byte{0x05, 0x08, 0x00, 0x01}
	socksResponseConnRefused      = []byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
)

// handleSocks handles SOCKS5 proxy requests without debug logging
func handleSocks(client net.Conn) {
	defer client.Close()

	// Set idle timeout
	client.SetDeadline(time.Now().Add(cfg.IdleTimeout))
	defer client.SetDeadline(time.Time{})

	var buf [256]byte
	// read (VER, NMETHODS, METHODS...)
	n, err := io.ReadAtLeast(client, buf[:], 2)
	if err != nil {
		return
	}
	ver := buf[0]
	if ver != 0x05 {
		if !cfg.isLogOff {
			logChan <- fmt.Sprintf("SOCKS: Invalid version %d from %s", ver, client.RemoteAddr())
		}
		return
	}
	methodsCount := int(buf[1])

	need := 2 + methodsCount
	if n < need {
		if _, err := io.ReadFull(client, buf[n:need]); err != nil {
			return
		}
	}

	// Check if auth is required using pre-computed flag
	var selectedMethod byte = 0x00 // no auth
	if cfg.AuthRequired {
		selectedMethod = 0x02 // username/password auth
	}

	// respond with selected method
	_, err = client.Write([]byte{0x05, selectedMethod})
	if err != nil {
		return
	}

	// If username/password auth is required, handle subnegotiation
	if selectedMethod == 0x02 {
		if !authenticateSocks(client) {
			if !cfg.isLogOff {
				logChan <- fmt.Sprintf("SOCKS: authentication failed from %s", client.RemoteAddr())
			}
			return
		}
	}

	// read (VER,CMD,RSV,ATYP)
	if _, err := io.ReadFull(client, buf[:4]); err != nil {
		if !cfg.isLogOff {
			logChan <- fmt.Sprintf("SOCKS: request header error from %s: %v", client.RemoteAddr(), err)
		}
		return
	}
	version, cmd, _, addrType := buf[0], buf[1], buf[2], buf[3]

	if version != 0x05 || cmd != 0x01 {
		client.Write(socksResponseCmdNotSupported)
		return
	}

	// parse destination
	var dstIP net.IP
	var dstStr string

	switch addrType {
	case 0x01: // IPv4
		if _, err := io.ReadFull(client, buf[:4]); err != nil {
			return
		}
		dstIP = net.IPv4(buf[0], buf[1], buf[2], buf[3])
		dstStr = dstIP.String()
	case 0x03: // Domain
		if _, err := io.ReadFull(client, buf[:1]); err != nil {
			return
		}
		domainLen := buf[0]
		if _, err := io.ReadFull(client, buf[:domainLen]); err != nil {
			return
		}
		domain := string(buf[:domainLen])
		addrs, e := net.LookupIP(domain)
		if e != nil || len(addrs) == 0 {
			if !cfg.isLogOff {
				logChan <- fmt.Sprintf("SOCKS: domain resolve fail %s from %s: %v", domain, client.RemoteAddr(), e)
			}
			client.Write(socksResponseHostUnreachable)
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
			if !cfg.isLogOff {
				logChan <- fmt.Sprintf("SOCKS: no IPv4 found for domain=%s from %s", domain, client.RemoteAddr())
			}
			client.Write(socksResponseAddrNotSupported)
			return
		}
	case 0x04:
		client.Write(socksResponseAddrNotSupported)
		return
	default:
		if !cfg.isLogOff {
			logChan <- fmt.Sprintf("SOCKS: unknown addrType=%d from %s", addrType, client.RemoteAddr())
		}
		client.Write(socksResponseAddrNotSupported)
		return
	}

	// read port
	if _, err := io.ReadFull(client, buf[:2]); err != nil {
		if !cfg.isLogOff {
			logChan <- fmt.Sprintf("SOCKS: port read error from %s: %v", client.RemoteAddr(), err)
		}
		return
	}
	dstPort := binary.BigEndian.Uint16(buf[:2])

	// dial - use strconv.Itoa instead of fmt.Sprintf for better performance
	targetAddr := net.JoinHostPort(dstIP.String(), strconv.Itoa(int(dstPort)))
	remote, err := net.Dial("tcp", targetAddr)
	if err != nil {
		client.Write(socksResponseConnRefused)
		return
	}
	// success
	_, err = client.Write(socksResponseSuccess)
	if err != nil {
		return
	}
	if !cfg.isLogOff {
		logChan <- fmt.Sprintf("SOCKS: tunnel established %s <-> %s:%d", client.RemoteAddr(), dstStr, dstPort)
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
}
