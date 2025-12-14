package acl

import (
	"github.com/oschwald/maxminddb-golang/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
)

type geoip2Country struct {
	Country struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type IPReader struct {
	*maxminddb.Reader
	lock  sync.Mutex
	close bool
}

type ASNReader struct {
	*maxminddb.Reader
}

type GeoLite2 struct {
	AutonomousSystemNumber       uint32 `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

func (r *IPReader) LookupCode(ipAddress net.IP) []string {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.close {
		return []string{}
	}
	var country geoip2Country
	netAddr, ok := netip.AddrFromSlice(ipAddress)
	if !ok {
		return []string{}
	}
	_ = r.Lookup(netAddr).Decode(&country)
	if country.Country.IsoCode == "" {
		return []string{}
	}
	return []string{strings.ToLower(country.Country.IsoCode)}
}
