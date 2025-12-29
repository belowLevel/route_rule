package route_rule

import (
	"context"
	"github.com/belowLevel/route_rule/acl"
	"net"
	"os"
)

const (
	aclCacheSize = 1024
)

// aclEngine is a PluggableOutbound that dispatches connections to different
// outbounds based on ACL rules.
// There are 3 built-in outbounds:
// - direct: directOutbound, auto mode
// - reject: reject the connection
// - default: first outbound in the list, or if the list is empty, equal to direct
// If the user-defined outbounds contain any of the above names, they will
// override the built-in outbounds.
type aclEngine struct {
	RuleSet acl.CompiledRuleSet[acl.Outbound]
	Default acl.Outbound
	Name    string
}

type OutboundEntry struct {
	Name     string
	Outbound acl.Outbound
}

func NewACLEngineFromString(rules string, outbounds []OutboundEntry, geoLoader acl.GeoLoader) (acl.Outbound, error) {
	trs, err := acl.ParseTextRules(rules)
	if err != nil {
		return nil, err
	}
	obMap := outboundsToMap(outbounds)
	rs, err := acl.Compile[acl.Outbound](trs, obMap, aclCacheSize, geoLoader)
	if err != nil {
		return nil, err
	}
	return &aclEngine{rs, obMap["default"], "aclEngine"}, nil
}

func NewACLEngineFromFile(filename string, outbounds []OutboundEntry, geoLoader acl.GeoLoader) (acl.Outbound, error) {
	bs, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return NewACLEngineFromString(string(bs), outbounds, geoLoader)
}

func outboundsToMap(outbounds []OutboundEntry) map[string]acl.Outbound {
	obMap := make(map[string]acl.Outbound)
	for _, ob := range outbounds {
		obMap[ob.Name] = ob.Outbound
	}
	return obMap
}

func (a *aclEngine) handle(reqAddr *acl.AddrEx) acl.Outbound {
	if reqAddr.HostInfo == nil {
		reqAddr.HostInfo = &acl.HostInfo{}
	}
	ob := a.RuleSet.Match(reqAddr)
	if ob == nil {
		// No match, use default outbound
		return a.Default
	}
	return ob
}

func (a *aclEngine) TCP(ctx context.Context, reqAddr *acl.AddrEx) (net.Conn, error) {
	reqAddr.Proto = acl.ProtocolTCP
	ob := a.handle(reqAddr)
	if reqAddr.Err != nil {
		return nil, reqAddr.Err
	}
	reqAddr.ObName = ob.GetName()
	return ob.TCP(ctx, reqAddr)
}

func (a *aclEngine) UDP(reqAddr *acl.AddrEx) (acl.UDPConn, error) {
	reqAddr.Proto = acl.ProtocolUDP
	ob := a.handle(reqAddr)
	if reqAddr.Err != nil {
		return nil, reqAddr.Err
	}
	return ob.UDP(reqAddr)
}
func (a *aclEngine) GetName() string {
	return a.Name
}
