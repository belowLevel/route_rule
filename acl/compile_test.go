package acl

import (
	"github.com/belowLevel/route_rule/acl/v2geo"
	"github.com/stretchr/testify/assert"
	"testing"
)

var _ GeoLoader = (*testGeoLoader)(nil)

type testGeoLoader struct{}

func (l *testGeoLoader) LoadGeoIP() (map[string]*v2geo.GeoIP, error) {
	return v2geo.LoadGeoIP("v2geo/geoip.dat")
}

func (l *testGeoLoader) LoadGeoSite() (map[string]*v2geo.GeoSite, error) {
	return v2geo.LoadGeoSite("v2geo/geosite.dat")
}

func (l *testGeoLoader) LoadGeoSiteSSKV() (map[string]*v2geo.Set, error) {
	return v2geo.LoadGeoSiteSSKV("v2geo/geosite.dat")
}

func (l *testGeoLoader) LoadGeoMMDB() (*IPReader, error) {
	return NewIPInstance("v2geo/country.mmdb")
}

func Test_parseGeoSiteName(t *testing.T) {
	tests := []struct {
		name  string
		s     string
		want  string
		want1 []string
	}{
		{
			name:  "no attrs",
			s:     "pornhub",
			want:  "pornhub",
			want1: []string{},
		},
		{
			name:  "one attr 1",
			s:     "xiaomi@cn",
			want:  "xiaomi",
			want1: []string{"cn"},
		},
		{
			name:  "one attr 2",
			s:     " google @jp ",
			want:  "google",
			want1: []string{"jp"},
		},
		{
			name:  "two attrs 1",
			s:     "netflix@jp@kr",
			want:  "netflix",
			want1: []string{"jp", "kr"},
		},
		{
			name:  "two attrs 2",
			s:     "netflix @xixi    @haha ",
			want:  "netflix",
			want1: []string{"xixi", "haha"},
		},
		{
			name:  "empty",
			s:     "",
			want:  "",
			want1: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := parseGeoSiteName(tt.s)
			assert.Equalf(t, tt.want, got, "parseGeoSiteName(%v)", tt.s)
			assert.Equalf(t, tt.want1, got1, "parseGeoSiteName(%v)", tt.s)
		})
	}
}
