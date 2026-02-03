package main

import (
	"io"
	"net"
	"sync/atomic"
)

// Bandwidth tracking (for dashboard metrics)
var (
	bytesInCounter  int64
	bytesOutCounter int64
)

// copyBuffer copies data between connections and tracks bandwidth
func copyBuffer(dst io.Writer, src io.Reader, buf []byte, isInbound bool) (written int64, err error) {
	for {
		nr, err := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
				// Track bandwidth
				if isInbound {
					atomic.AddInt64(&bytesInCounter, int64(nw))
				} else {
					atomic.AddInt64(&bytesOutCounter, int64(nw))
				}
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			break
		}
	}
	return written, err
}

// isAllowed checks if an IP address is allowed based on the configured networks
func isAllowed(ip net.IP, networks []*net.IPNet) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	for _, n := range networks {
		if n.Contains(ip4) {
			return true
		}
	}
	return false
}
