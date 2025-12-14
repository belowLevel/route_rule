package acl

import "github.com/belowLevel/route_rule/acl/v2geo"

type DomainSet struct {
	Set *v2geo.Set
}

func (d *DomainSet) Match(reqAddr *AddrEx) bool {
	if d.Set == nil {
		return false
	}
	return d.Set.Has(reqAddr.Host)
}

func (d *DomainSet) Size() int {
	if d.Set == nil {
		return 0
	}
	return d.Set.Size()
}

func newSSKVMatcher(set *v2geo.Set, attrs []string) (*DomainSet, error) {
	ds := &DomainSet{
		Set: set,
	}
	return ds, nil
}
