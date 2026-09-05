package ldapclient

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (function resolverFunc) LookupNetIP(
	ctx context.Context,
	network string,
	host string,
) ([]netip.Addr, error) {
	return function(ctx, network, host)
}

type dialerFunc func(context.Context, string, string) (net.Conn, error)

func (function dialerFunc) DialContext(
	ctx context.Context,
	network string,
	address string,
) (net.Conn, error) {
	return function(ctx, network, address)
}

type recordingDialer struct {
	mu        sync.Mutex
	addresses []string
	dial      dialerFunc
}

func (dialer *recordingDialer) DialContext(
	ctx context.Context,
	network string,
	address string,
) (net.Conn, error) {
	dialer.mu.Lock()
	dialer.addresses = append(dialer.addresses, address)
	dialer.mu.Unlock()
	if dialer.dial == nil {
		return nil, errors.New("dial failed")
	}
	return dialer.dial(ctx, network, address)
}

func (dialer *recordingDialer) targets() []string {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	return append([]string(nil), dialer.addresses...)
}

func testConfiguration() Configuration {
	return Configuration{
		Endpoints: []Endpoint{{
			Priority:      1,
			Enabled:       true,
			Host:          "ldap.example.com",
			Port:          636,
			Transport:     TransportLDAPS,
			TLSServerName: "ldap.example.com",
		}},
		ConnectTimeout:   200 * time.Millisecond,
		OperationTimeout: time.Second,
	}
}

func testOptions(resolver Resolver, dialer Dialer) Options {
	return Options{Resolver: resolver, Dialer: dialer, MaxConcurrent: 4}
}

func publicResolver(addresses ...string) Resolver {
	parsed := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		parsed = append(parsed, netip.MustParseAddr(address))
	}
	return resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return append([]netip.Addr(nil), parsed...), nil
	})
}
