package acl

import (
	"github.com/belowLevel/route_rule/acl/v2geo"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_geoipMatcher_Match(t *testing.T) {
	geoipMap, err := NewIPInstance("v2geo/country.mmdb")
	assert.NoError(t, err)
	m, err := newGeoIPMatcher("us", geoipMap)
	assert.NoError(t, err)

	tests := []struct {
		name string
		AddrEx
		want bool
	}{
		{
			name: "IPv4 match",
			AddrEx: AddrEx{
				Host: "",
				Port: 0,
				HostInfo: &HostInfo{
					IPv4: net.ParseIP("73.222.1.100"),
				},
				Txt:   "",
				Proto: 0,
				Err:   nil,
			},
			want: true,
		},
		{
			name: "IPv4 no match",
			AddrEx: AddrEx{
				Host: "",
				Port: 0,
				HostInfo: &HostInfo{
					IPv4: net.ParseIP("123.123.123.123"),
				},
				Txt:   "",
				Proto: 0,
				Err:   nil,
			},
			want: false,
		},
		{
			name: "IPv6 match",
			AddrEx: AddrEx{
				HostInfo: &HostInfo{
					IPv6: net.ParseIP("2607:f8b0:4005:80c::2004"),
				},
			},
			want: true,
		},
		{
			name: "IPv6 no match",
			AddrEx: AddrEx{HostInfo: &HostInfo{
				IPv6: net.ParseIP("240e:947:6001::1f8"),
			}},
			want: false,
		},
		{
			name: "both nil",
			AddrEx: AddrEx{HostInfo: &HostInfo{
				IPv4: nil,
				IPv6: nil,
			}},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, m.Match(&tt.AddrEx), "Match(%v)", tt.Host)
		})
	}
}

func Test_geositeMatcher_Match(t *testing.T) {
	geositeMap, err := v2geo.LoadGeoSite("v2geo/geosite.dat")
	assert.NoError(t, err)
	m, err := newGeositeMatcher(geositeMap["apple"], nil)
	assert.NoError(t, err)

	tests := []struct {
		name  string
		attrs []string
		AddrEx
		want bool
	}{
		{
			name:   "subdomain",
			attrs:  nil,
			AddrEx: AddrEx{Host: "poop.i-book.com"},
			want:   true,
		},
		{
			name:   "subdomain root",
			attrs:  nil,
			AddrEx: AddrEx{Host: "applepaycash.net"},
			want:   true,
		},
		{
			name:   "full",
			attrs:  nil,
			AddrEx: AddrEx{Host: "courier-push-apple.com.akadns.net"},
			want:   true,
		},
		{
			name:   "regexp",
			attrs:  nil,
			AddrEx: AddrEx{Host: "cdn4.apple-mapkit.com"},
			want:   true,
		},
		{
			name:   "attr match",
			attrs:  []string{"cn"},
			AddrEx: AddrEx{Host: "bag.itunes.apple.com"},
			want:   true,
		},
		{
			name:   "attr multi no match",
			attrs:  []string{"cn", "haha"},
			AddrEx: AddrEx{Host: "bag.itunes.apple.com"},
			want:   false,
		},
		{
			name:   "attr no match",
			attrs:  []string{"cn"},
			AddrEx: AddrEx{Host: "mr-apple.com.tw"},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.Attrs = tt.attrs
			assert.Equalf(t, tt.want, m.Match(&tt.AddrEx), "Match(%v)", tt.Host)
		})
	}
}
func BenchmarkIpMatcher(b *testing.B) {
	ipReader, err := NewIPInstance("v2geo/country.mmdb")
	assert.NoError(b, err)
	m, err := newGeoIPMatcher("us", ipReader)
	assert.NoError(b, err)
	ip := net.ParseIP("73.222.1.100")
	for i := 0; i < b.N; i++ {
		m.matchIP(ip)
	}
}

func BenchmarkDomainMatcher(b *testing.B) {

	geositeMap, err := v2geo.LoadGeoSite("v2geo/geosite.dat")
	assert.NoError(b, err)
	m, err := newGeositeMatcher(geositeMap["cn"], nil)
	assert.NoError(b, err)
	reqAddr := AddrEx{Host: "baidu.com"}
	for i := 0; i < b.N; i++ {
		m.Match(&reqAddr)
	}
}
func TestDomainMatcher(t *testing.T) {
	geositeMap, err := v2geo.LoadGeoSite("v2geo/geosite.dat")
	assert.NoError(t, err)
	for k, _ := range geositeMap {
		m, err := newGeositeMatcher(geositeMap[k], nil)
		assert.NoError(t, err)
		for _, domain := range m.Domains {
			if domain.Type == geositeDomainRegex {
				t.Log(k, "|", domain.Type, "|", domain.Regex)
			}
		}
	}

}

type OutboundTest struct {
}

func (o *OutboundTest) TCP(reqAddr string) (net.Conn, error) {
	return nil, nil
}
func (o *OutboundTest) UDP(reqAddr string) (UDPConn, error) {
	return nil, nil
}
func (o *OutboundTest) GetName() string {
	return "test"
}
