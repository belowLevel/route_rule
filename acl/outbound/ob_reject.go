package outbound

import (
	"context"
	"errors"
	"github.com/belowLevel/route_rule/acl"
	"net"
)

var errRejected = errors.New("rejected")

func NewRejectOutbound(name string) acl.Outbound {
	return &aclRejectOutbound{
		Name: name,
	}
}

type aclRejectOutbound struct {
	Name string
}

func (a *aclRejectOutbound) GetName() string {
	return a.Name
}

func (a *aclRejectOutbound) TCP(ctx context.Context, reqAddr *acl.AddrEx) (net.Conn, error) {
	return nil, errRejected
}

func (a *aclRejectOutbound) UDP(reqAddr *acl.AddrEx) (acl.UDPConn, error) {
	return nil, errRejected
}
