package acl

import (
	"errors"
	"github.com/belowLevel/route_rule/acl/v2geo"
	"net"
	"regexp"
	"strings"
)

var _ hostMatcher = (*geoipMatcher)(nil)

type geoipMatcher struct {
	country  string
	ipReader *IPReader
}

func (m *geoipMatcher) matchIP(ip net.IP) bool {
	if m.ipReader == nil {
		return false
	}
	isos := m.ipReader.LookupCode(ip)
	if len(isos) == 0 {
		return false
	}
	iso := isos[0]
	if iso == m.country {
		return true
	}
	return false
}

func (m *geoipMatcher) Match(reqAddr *AddrEx) bool {
	if reqAddr.Err != nil {
		return false
	}
	if reqAddr.HostInfo.IPv4 == nil {
		localResolve(reqAddr)
	}
	if reqAddr.HostInfo.IPv4 != nil {
		return m.matchIP(reqAddr.HostInfo.IPv4)
	}
	if reqAddr.HostInfo.IPv6 != nil {
		return m.matchIP(reqAddr.HostInfo.IPv6)
	}
	return false
}

func newGeoIPMatcher(country string, ipReader *IPReader) (*geoipMatcher, error) {
	return &geoipMatcher{
		country:  country,
		ipReader: ipReader,
	}, nil
}

var _ hostMatcher = (*geositeMatcher)(nil)

type geositeDomainType int

const (
	geositeDomainPlain geositeDomainType = iota
	geositeDomainRegex
	geositeDomainRoot
	geositeDomainFull
)

type geositeDomain struct {
	Type  geositeDomainType
	Value string
	Regex *regexp.Regexp
	Attrs map[string]bool
}

type geositeMatcher struct {
	Domains []geositeDomain
	// Attributes are matched using "and" logic - if you have multiple attributes here,
	// a domain must have all of those attributes to be considered a match.
	Attrs []string
}

func (m *geositeMatcher) matchDomain(domain geositeDomain, reqAddr *AddrEx) bool {
	// Match attributes first
	if len(m.Attrs) > 0 {
		if len(domain.Attrs) == 0 {
			return false
		}
		for _, attr := range m.Attrs {
			if !domain.Attrs[attr] {
				return false
			}
		}
	}

	switch domain.Type {
	case geositeDomainPlain:
		return strings.Contains(reqAddr.Host, domain.Value)
	case geositeDomainRegex:
		if domain.Regex != nil {
			return domain.Regex.MatchString(reqAddr.Host)
		}
	case geositeDomainFull:
		return reqAddr.Host == domain.Value
	case geositeDomainRoot:
		if reqAddr.Host == domain.Value {
			return true
		}
		return strings.HasSuffix(reqAddr.Host, "."+domain.Value)
	default:
		return false
	}
	return false
}

func (m *geositeMatcher) Match(reqAddr *AddrEx) bool {
	for _, domain := range m.Domains {
		if m.matchDomain(domain, reqAddr) {
			return true
		}
	}
	return false
}

func newGeositeMatcher(list *v2geo.GeoSite, attrs []string) (*geositeMatcher, error) {
	domains := make([]geositeDomain, len(list.Domain))
	for i, domain := range list.Domain {
		switch domain.Type {
		case v2geo.Domain_Plain:
			domains[i] = geositeDomain{
				Type:  geositeDomainPlain,
				Value: domain.Value,
				Attrs: domainAttributeToMap(domain.Attribute),
			}
		case v2geo.Domain_Regex:
			regex, err := regexp.Compile(domain.Value)
			if err != nil {
				return nil, err
			}
			domains[i] = geositeDomain{
				Type:  geositeDomainRegex,
				Regex: regex,
				Attrs: domainAttributeToMap(domain.Attribute),
			}
		case v2geo.Domain_Full:
			domains[i] = geositeDomain{
				Type:  geositeDomainFull,
				Value: domain.Value,
				Attrs: domainAttributeToMap(domain.Attribute),
			}
		case v2geo.Domain_RootDomain:
			domains[i] = geositeDomain{
				Type:  geositeDomainRoot,
				Value: domain.Value,
				Attrs: domainAttributeToMap(domain.Attribute),
			}
		default:
			return nil, errors.New("unsupported domain type")
		}
	}
	return &geositeMatcher{
		Domains: domains,
		Attrs:   attrs,
	}, nil
}

func domainAttributeToMap(attrs []*v2geo.Domain_Attribute) map[string]bool {
	m := make(map[string]bool)
	for _, attr := range attrs {
		// Supposedly there are also int attributes,
		// but nobody seems to use them, so we treat everything as boolean for now.
		m[attr.Key] = true
	}
	return m
}

func localResolve(reqAddr *AddrEx) {
	ips, err := net.LookupIP(reqAddr.Host)
	if err != nil {
		reqAddr.Err = err
		return
	}
	reqAddr.HostInfo.IPv4, reqAddr.HostInfo.IPv6 = splitIPv4IPv6(ips)
}

func splitIPv4IPv6(ips []net.IP) (ipv4, ipv6 net.IP) {
	for _, ip := range ips {
		if ip.To4() != nil {
			if ipv4 == nil {
				ipv4 = ip
			}
		} else {
			if ipv6 == nil {
				ipv6 = ip
			}
		}
		if ipv4 != nil && ipv6 != nil {
			// We have everything we need.
			break
		}
	}
	return ipv4, ipv6
}
