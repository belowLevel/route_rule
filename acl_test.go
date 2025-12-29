package route_rule

import (
	"context"
	"github.com/belowLevel/route_rule/acl"
	"github.com/belowLevel/route_rule/acl/outbound"
	"log"
	"net/url"
	"strings"
	"testing"
)

func TestACL(t *testing.T) {
	var urls = map[string]string{
		"p1":     "socks5://alice:secret123@203.0.113.5:1080",
		"reject": "reject://",
	}
	var obs = buildOutbounds(urls)
	Inline := []string{
		//"v6_only(suffix:gstatic.com)",
		"reject(geoip:cn)",
		"default(geoip:private)",
		"v6_only(geosite:youtube)",
		"v4_only(all)",
		"v4_only(geoip:cn)",
		"v4_only(all)",
	}
	gLoader := &acl.GeoLoaderT{
		DownloadFunc: func(filename, url string) {
			t.Logf("%s %s", filename, url)
		},
		DownloadErrFunc: func(err error) {
			t.Errorf("%v", err)
		},
		AutoDL: true,
	}
	aclO, err := NewACLEngineFromString(strings.Join(Inline, "\n"), obs, gLoader)
	if err != nil {
		t.Errorf("%v", err)
	}
	//uOb = outbounds.NewSystemResolver(uOb)
	//conn, err := ob.TCP("baidu.com:80")
	reqAddr := acl.AddrEx{
		Host: "xxee.com",
		Port: 80,
	}
	conn, err := aclO.TCP(context.Background(), &reqAddr)

	if err != nil {
		t.Errorf("%v", err)
	} else {
		defer conn.Close()
	}
}
func buildOutbounds(urls map[string]string) []OutboundEntry {
	var obs []OutboundEntry
	for k, v := range urls {
		upstreamURL, err := url.Parse(v)
		if err != nil {
			continue
		}
		switch upstreamURL.Scheme {
		case "socks":
			fallthrough
		case "socks5":
			fallthrough
		case "socks5h":
			{
				password, _ := upstreamURL.User.Password()
				obs = append(obs, OutboundEntry{
					Name:     k,
					Outbound: outbound.NewSOCKS5Outbound(upstreamURL.Host, upstreamURL.User.Username(), password, k),
				})
			}
		case "http":
			fallthrough
		case "https":
			{
				ob, err := outbound.NewHTTPOutbound(v, true, k)
				if err != nil {
					log.Fatalln(err)
				} else {
					obs = append(obs, OutboundEntry{
						Name:     k,
						Outbound: ob,
					})
				}
			}
		case "reject":
			obs = append(obs, OutboundEntry{
				Name:     k,
				Outbound: outbound.NewRejectOutbound(k),
			})
		default:
			log.Fatalln("unknown Scheme", v)

		}
	}
	obs = append(obs, OutboundEntry{
		Name:     "default",
		Outbound: outbound.NewDirectOutboundSimple(outbound.DirectOutboundModeAuto, "direct"),
	})
	obs = append(obs, OutboundEntry{
		Name:     "v6_only",
		Outbound: outbound.NewDirectOutboundSimple(outbound.DirectOutboundMode6, "v6_only"),
	})
	obs = append(obs, OutboundEntry{
		Name:     "v4_only",
		Outbound: outbound.NewDirectOutboundSimple(outbound.DirectOutboundMode4, "v4_only"),
	})
	return obs
}
