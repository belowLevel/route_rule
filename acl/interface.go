package acl

import (
	"net"
	"strconv"
)

type UDPConn interface {
	ReadFrom(b []byte) (int, *AddrEx, error)
	WriteTo(b []byte, addr *AddrEx) (int, error)
	Close() error
}

// AddrEx keeps both the original string representation of the address and
// the resolved IP addresses from the resolver, if any.
// The actual outbound implementations can choose to use either the string
// representation or the resolved IP addresses, depending on their capabilities.
// A SOCKS5 outbound, for example, should prefer the string representation
// because SOCKS5 protocol supports sending the hostname to the proxy server
// and let the proxy server do the DNS resolution.
type AddrEx struct {
	Host     string // String representation of the host, can be an IP or a domain name
	Port     uint16
	HostInfo *HostInfo // Only set if there's a resolver in the pipeline
	Txt      string
	Proto    Protocol
	ObName   string
	Err      error
	Geo      string
	ConnIp   string
}

func (a *AddrEx) String() string {
	return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port)))
}

// ResolveInfo contains the resolved IP addresses from the resolver, and any
// error that occurred during the resolution.
// Note that there could be no error but also no resolved IP addresses,
// or there could be an error but also some resolved IP addresses.
// It's up to the actual outbound implementation to decide how to handle
// these cases.
type ResolveInfo struct {
	IPv4 net.IP
	IPv6 net.IP
	Err  error
}

// Outbound provides the implementation of how the server should connect to remote servers.
// Although UDP includes a reqAddr, the implementation does not necessarily have to use it
// to make a "connected" UDP connection that does not accept packets from other addresses.
// In fact, the default implementation simply uses net.ListenUDP for a "full-cone" behavior.
type Outbound interface {
	TCP(reqAddr *AddrEx) (net.Conn, error)
	UDP(reqAddr *AddrEx) (UDPConn, error)
	GetName() string
}
