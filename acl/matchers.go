package acl

import (
	"net"
	"strings"

	"golang.org/x/net/idna"
)

const (
	domainMatchExact = uint8(iota)
	domainMatchWildcard
	domainMatchSuffix
)

type hostMatcher interface {
	Match(*AddrEx) bool
}

type ipMatcher struct {
	IP net.IP
}

func (m *ipMatcher) Match(reqAddr *AddrEx) bool {

	return m.IP.Equal(reqAddr.HostInfo.IPv4) || m.IP.Equal(reqAddr.HostInfo.IPv6)
}

type cidrMatcher struct {
	IPNet *net.IPNet
}

func (m *cidrMatcher) Match(reqAddr *AddrEx) bool {
	return m.IPNet.Contains(reqAddr.HostInfo.IPv4) || m.IPNet.Contains(reqAddr.HostInfo.IPv6)
}

type domainMatcher struct {
	Pattern string
	Mode    uint8
}

func (m *domainMatcher) Match(reqAddr *AddrEx) bool {
	name, err := idna.ToUnicode(reqAddr.Host)
	if err != nil {
		name = reqAddr.Host
	}
	switch m.Mode {
	case domainMatchExact:
		return name == m.Pattern
	case domainMatchWildcard:
		return deepMatchRune([]rune(name), []rune(m.Pattern))
	case domainMatchSuffix:
		return name == m.Pattern || strings.HasSuffix(name, "."+m.Pattern)
	default:
		return false // Invalid mode
	}
}

func deepMatchRune(str, pattern []rune) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		default:
			if len(str) == 0 || str[0] != pattern[0] {
				return false
			}
		case '*':
			return deepMatchRune(str, pattern[1:]) ||
				(len(str) > 0 && deepMatchRune(str[1:], pattern))
		}
		str = str[1:]
		pattern = pattern[1:]
	}
	return len(str) == 0 && len(pattern) == 0
}

type allMatcher struct{}

func (m *allMatcher) Match(reqAddr *AddrEx) bool {
	return true
}
