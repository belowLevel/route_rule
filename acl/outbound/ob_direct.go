package outbound

import (
	"context"
	"errors"
	"github.com/belowLevel/route_rule/acl"
	"net"
	"strconv"
	"time"
)

type DirectOutboundMode int

type udpConnState int

const (
	DirectOutboundModeAuto DirectOutboundMode = iota // Dual-stack "happy eyeballs"-like mode
	DirectOutboundMode64                             // Use IPv6 address when available, otherwise IPv4
	DirectOutboundMode46                             // Use IPv4 address when available, otherwise IPv6
	DirectOutboundMode6                              // Use IPv6 only, fail if not available
	DirectOutboundMode4                              // Use IPv4 only, fail if not available

	defaultDialerTimeout = 10 * time.Second
)

const (
	udpConnStateDualStack udpConnState = iota
	udpConnStateIPv4
	udpConnStateIPv6
)

// directOutbound is a PluggableOutbound that connects directly to the target
// using the local network (as opposed to using a proxy, for example).
// It prefers to use ResolveInfo in AddrEx if available. But if it's nil,
// it will fall back to resolving Host using Go's built-in DNS resolver.
type directOutbound struct {
	Mode DirectOutboundMode

	// Dialer4 and Dialer6 are used for IPv4 and IPv6 TCP connections respectively.
	DialFunc4 func(ctx context.Context, network, address string) (net.Conn, error)
	DialFunc6 func(ctx context.Context, network, address string) (net.Conn, error)

	// DeviceName & BindIPs are for UDP connections. They don't use dialers, so we
	// need to bind them when creating the connection.
	DeviceName string
	BindIP4    net.IP
	BindIP6    net.IP
	Name       string
}

type DirectOutboundOptions struct {
	Mode DirectOutboundMode

	DeviceName string
	BindIP4    net.IP
	BindIP6    net.IP

	FastOpen bool
}

type noAddressError struct {
	IPv4 bool
	IPv6 bool
}

func (e noAddressError) Error() string {
	if e.IPv4 && e.IPv6 {
		return "no IPv4 or IPv6 address available"
	} else if e.IPv4 {
		return "no IPv4 address available"
	} else if e.IPv6 {
		return "no IPv6 address available"
	} else {
		return "no address available"
	}
}

type invalidOutboundModeError struct{}

func (e invalidOutboundModeError) Error() string {
	return "invalid outbound mode"
}

type resolveError struct {
	Err error
}

func (e resolveError) Error() string {
	if e.Err == nil {
		return "resolve error"
	} else {
		return "resolve error: " + e.Err.Error()
	}
}

func (e resolveError) Unwrap() error {
	return e.Err
}

func NewDirectOutboundWithOptions(opts DirectOutboundOptions) (acl.Outbound, error) {
	dialer4 := &net.Dialer{
		Timeout: defaultDialerTimeout,
	}
	if opts.BindIP4 != nil {
		if opts.BindIP4.To4() == nil {
			return nil, errors.New("BindIP4 must be an IPv4 address")
		}
		dialer4.LocalAddr = &net.TCPAddr{
			IP: opts.BindIP4,
		}
	}
	dialer6 := &net.Dialer{
		Timeout: defaultDialerTimeout,
	}
	if opts.BindIP6 != nil {
		if opts.BindIP6.To4() != nil {
			return nil, errors.New("BindIP6 must be an IPv6 address")
		}
		dialer6.LocalAddr = &net.TCPAddr{
			IP: opts.BindIP6,
		}
	}
	if opts.DeviceName != "" {
		err := dialerBindToDevice(dialer4, opts.DeviceName)
		if err != nil {
			return nil, err
		}
		err = dialerBindToDevice(dialer6, opts.DeviceName)
		if err != nil {
			return nil, err
		}
	}
	dialFunc4 := dialer4.DialContext
	dialFunc6 := dialer6.DialContext
	return &directOutbound{
		Mode:       opts.Mode,
		DialFunc4:  dialFunc4,
		DialFunc6:  dialFunc6,
		DeviceName: opts.DeviceName,
		BindIP4:    opts.BindIP4,
		BindIP6:    opts.BindIP6,
	}, nil
}

// NewDirectOutboundSimple creates a new directOutbound with the given mode,
// without binding to a specific device. Works on all platforms.
func NewDirectOutboundSimple(mode DirectOutboundMode, name string) acl.Outbound {
	d := &net.Dialer{
		Timeout: defaultDialerTimeout,
	}
	return &directOutbound{
		Mode:      mode,
		DialFunc4: d.DialContext,
		DialFunc6: d.DialContext,
		Name:      name,
	}
}

// NewDirectOutboundBindToIPs creates a new directOutbound with the given mode,
// and binds to the given IPv4 and IPv6 addresses. Either or both of the addresses
// can be nil, in which case the directOutbound will not bind to a specific address
// for that family.
func NewDirectOutboundBindToIPs(mode DirectOutboundMode, bindIP4, bindIP6 net.IP) (acl.Outbound, error) {
	return NewDirectOutboundWithOptions(DirectOutboundOptions{
		Mode:    mode,
		BindIP4: bindIP4,
		BindIP6: bindIP6,
	})
}

// NewDirectOutboundBindToDevice creates a new directOutbound with the given mode,
// and binds to the given device. Only works on Linux.
func NewDirectOutboundBindToDevice(mode DirectOutboundMode, deviceName string) (acl.Outbound, error) {
	return NewDirectOutboundWithOptions(DirectOutboundOptions{
		Mode:       mode,
		DeviceName: deviceName,
	})
}

// resolve is our built-in DNS resolver for handling the case when
// AddrEx.ResolveInfo is nil.
func (d *directOutbound) resolve(reqAddr *acl.AddrEx) {
	ips, err := net.LookupIP(reqAddr.Host)
	if err != nil {
		reqAddr.Err = err
		return
	}
	reqAddr.HostInfo.IPv4, reqAddr.HostInfo.IPv4 = splitIPv4IPv6(ips)
	if reqAddr.HostInfo.IPv4 == nil && reqAddr.HostInfo.IPv6 == nil {
		reqAddr.Err = noAddressError{IPv4: true, IPv6: true}
	}
}

func (d *directOutbound) TCP(ctx context.Context, reqAddr *acl.AddrEx) (conn net.Conn, err error) {
	defer func() {
		if err == nil {
			remoteIp, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			reqAddr.ConnIp = remoteIp
		}
	}()
	hostPort := net.JoinHostPort(reqAddr.Host, strconv.Itoa(int(reqAddr.Port)))
	switch d.Mode {
	case DirectOutboundModeAuto:
		fallthrough
	case DirectOutboundMode64:
		fallthrough
	case DirectOutboundMode46:
		return d.DialFunc4(ctx, "tcp", hostPort)
	case DirectOutboundMode6:
		return d.DialFunc4(ctx, "tcp6", hostPort)
	case DirectOutboundMode4:
		return d.DialFunc4(ctx, "tcp4", hostPort)
	default:
		return nil, invalidOutboundModeError{}
	}
}

func (d *directOutbound) dialTCP(ctx context.Context, ip net.IP, port uint16) (net.Conn, error) {
	if ip.To4() != nil {
		return d.DialFunc4(ctx, "tcp4", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
	} else {
		return d.DialFunc6(ctx, "tcp6", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
	}
}

func (d *directOutbound) GetName() string {
	return d.Name
}

type dialResult struct {
	Conn net.Conn
	Err  error
}

// dualStackDialTCP dials the target using both IPv4 and IPv6 addresses simultaneously.
// It returns the first successful connection and drops the other one.
// If both connections fail, it returns the last error.
func (d *directOutbound) dualStackDialTCP(ctx context.Context, ipv4, ipv6 net.IP, port uint16) (net.Conn, error) {
	ch := make(chan dialResult, 2)
	go func() {
		conn, err := d.dialTCP(ctx, ipv4, port)
		ch <- dialResult{Conn: conn, Err: err}
	}()
	go func() {
		conn, err := d.dialTCP(ctx, ipv6, port)
		ch <- dialResult{Conn: conn, Err: err}
	}()
	// Get the first result, check if it's successful
	if r := <-ch; r.Err == nil {
		// Yes. Return this and close the other connection when it's done
		go func() {
			r2 := <-ch
			if r2.Conn != nil {
				_ = r2.Conn.Close()
			}
		}()
		return r.Conn, nil
	} else {
		// No. Return the other result, which may or may not be successful
		r2 := <-ch
		return r2.Conn, r2.Err
	}
}

type directOutboundUDPConn struct {
	*directOutbound
	*net.UDPConn
	State udpConnState
}

func (u *directOutboundUDPConn) ReadFrom(b []byte) (int, *acl.AddrEx, error) {
	n, addr, err := u.UDPConn.ReadFromUDP(b)
	if addr != nil {
		return n, &acl.AddrEx{
			Host: addr.IP.String(),
			Port: uint16(addr.Port),
		}, err
	} else {
		return n, nil, err
	}
}

func (u *directOutboundUDPConn) WriteTo(b []byte, addr *acl.AddrEx) (int, error) {
	if addr.HostInfo.IPv4 == nil {
		u.directOutbound.resolve(addr)
	}
	if addr.HostInfo.IPv4 == nil && addr.HostInfo.IPv6 == nil {
		return 0, resolveError{Err: addr.Err}
	}
	if u.State == udpConnStateIPv4 {
		if addr.HostInfo.IPv4 != nil {
			return u.UDPConn.WriteToUDP(b, &net.UDPAddr{
				IP:   addr.HostInfo.IPv4,
				Port: int(addr.Port),
			})
		} else {
			return 0, noAddressError{IPv4: true}
		}
	} else if u.State == udpConnStateIPv6 {
		if addr.HostInfo.IPv6 != nil {
			return u.UDPConn.WriteToUDP(b, &net.UDPAddr{
				IP:   addr.HostInfo.IPv6,
				Port: int(addr.Port),
			})
		} else {
			return 0, noAddressError{IPv6: true}
		}
	} else {
		// Dual stack
		switch u.directOutbound.Mode {
		case DirectOutboundModeAuto:
			// This is a special case.
			// We must make a decision here, so we prefer IPv4 for maximum compatibility.
			if addr.HostInfo.IPv4 != nil {
				return u.UDPConn.WriteToUDP(b, &net.UDPAddr{
					IP:   addr.HostInfo.IPv4,
					Port: int(addr.Port),
				})
			} else {
				return u.UDPConn.WriteToUDP(b, &net.UDPAddr{
					IP:   addr.HostInfo.IPv6,
					Port: int(addr.Port),
				})
			}
		case DirectOutboundMode64:
			if addr.HostInfo.IPv6 != nil {
				return u.UDPConn.WriteToUDP(b, &net.UDPAddr{
					IP:   addr.HostInfo.IPv6,
					Port: int(addr.Port),
				})
			} else {
				return u.UDPConn.WriteToUDP(b, &net.UDPAddr{
					IP:   addr.HostInfo.IPv4,
					Port: int(addr.Port),
				})
			}
		case DirectOutboundMode46:
			if addr.HostInfo.IPv4 != nil {
				return u.UDPConn.WriteToUDP(b, &net.UDPAddr{
					IP:   addr.HostInfo.IPv4,
					Port: int(addr.Port),
				})
			} else {
				return u.UDPConn.WriteToUDP(b, &net.UDPAddr{
					IP:   addr.HostInfo.IPv6,
					Port: int(addr.Port),
				})
			}
		case DirectOutboundMode6:
			if addr.HostInfo.IPv6 != nil {
				return u.UDPConn.WriteToUDP(b, &net.UDPAddr{
					IP:   addr.HostInfo.IPv6,
					Port: int(addr.Port),
				})
			} else {
				return 0, noAddressError{IPv6: true}
			}
		case DirectOutboundMode4:
			if addr.HostInfo.IPv4 != nil {
				return u.UDPConn.WriteToUDP(b, &net.UDPAddr{
					IP:   addr.HostInfo.IPv4,
					Port: int(addr.Port),
				})
			} else {
				return 0, noAddressError{IPv4: true}
			}
		default:
			return 0, invalidOutboundModeError{}
		}
	}
}

func (u *directOutboundUDPConn) Close() error {
	return u.UDPConn.Close()
}

func (d *directOutbound) UDP(reqAddr *acl.AddrEx) (acl.UDPConn, error) {
	if d.BindIP4 == nil && d.BindIP6 == nil {
		// No bind address specified, use default dual stack implementation
		c, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, err
		}
		if d.DeviceName != "" {
			if err := udpConnBindToDevice(c, d.DeviceName); err != nil {
				// Don't forget to close the UDPConn if binding fails
				_ = c.Close()
				return nil, err
			}
		}
		return &directOutboundUDPConn{
			directOutbound: d,
			UDPConn:        c,
			State:          udpConnStateDualStack,
		}, nil
	} else {
		// Bind address specified,
		// need to check what kind of address is in reqAddr
		// to determine which address family to bind to
		if reqAddr.HostInfo.IPv4 == nil {
			d.resolve(reqAddr)
		}
		if reqAddr.HostInfo.IPv4 == nil && reqAddr.HostInfo.IPv6 == nil {
			return nil, resolveError{Err: reqAddr.Err}
		}
		var bindIP net.IP      // can be nil, in which case we still lock the address family but don't bind to any address
		var state udpConnState // either IPv4 or IPv6
		switch d.Mode {
		case DirectOutboundModeAuto:
			// This is a special case.
			// We must make a decision here, so we prefer IPv4 for maximum compatibility.
			if reqAddr.HostInfo.IPv4 != nil {
				bindIP = d.BindIP4
				state = udpConnStateIPv4
			} else {
				bindIP = d.BindIP6
				state = udpConnStateIPv6
			}
		case DirectOutboundMode64:
			if reqAddr.HostInfo.IPv6 != nil {
				bindIP = d.BindIP6
				state = udpConnStateIPv6
			} else {
				bindIP = d.BindIP4
				state = udpConnStateIPv4
			}
		case DirectOutboundMode46:
			if reqAddr.HostInfo.IPv4 != nil {
				bindIP = d.BindIP4
				state = udpConnStateIPv4
			} else {
				bindIP = d.BindIP6
				state = udpConnStateIPv6
			}
		case DirectOutboundMode6:
			if reqAddr.HostInfo.IPv6 != nil {
				bindIP = d.BindIP6
				state = udpConnStateIPv6
			} else {
				return nil, noAddressError{IPv6: true}
			}
		case DirectOutboundMode4:
			if reqAddr.HostInfo.IPv4 != nil {
				bindIP = d.BindIP4
				state = udpConnStateIPv4
			} else {
				return nil, noAddressError{IPv4: true}
			}
		default:
			return nil, invalidOutboundModeError{}
		}
		var network string
		var c *net.UDPConn
		var err error
		if state == udpConnStateIPv4 {
			network = "udp4"
		} else {
			network = "udp6"
		}
		if bindIP != nil {
			c, err = net.ListenUDP(network, &net.UDPAddr{
				IP: bindIP,
			})
		} else {
			c, err = net.ListenUDP(network, nil)
		}
		if err != nil {
			return nil, err
		}
		// We don't support binding to both device & address at the same time,
		// so d.DeviceName is ignored in this case.
		return &directOutboundUDPConn{
			directOutbound: d,
			UDPConn:        c,
			State:          state,
		}, nil
	}
}
