package acl

import "route_rule/acl/v2geo"

type DomainSet struct {
	Set *v2geo.Set
}

func (d *DomainSet) Match(host *HostInfo) bool {
	if d.Set == nil {
		return false
	}
	return d.Set.Has(host.Name)
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
