package ldapclient

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestUnsafeDestinationsAreBlockedBeforeDial(t *testing.T) {
	t.Parallel()

	for _, address := range []string{
		"0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254",
		"168.63.129.16", "172.16.0.1", "192.0.2.1", "192.168.0.1", "198.18.0.1", "198.51.100.1",
		"203.0.113.1", "224.0.0.1", "240.0.0.1", "::", "::1", "fc00::1",
		"fe80::1", "ff02::1", "2001:db8::1", "2620:4f:8000::1", "3fff::1", "64:ff9b::1",
		"fd00:ec2::254", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
	} {
		address := address
		t.Run(address, func(t *testing.T) {
			t.Parallel()
			dialer := &recordingDialer{}
			client, err := New(testOptions(publicResolver(address), dialer))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			diagnostic, err := client.TestConnection(context.Background(), testConfiguration())
			if err != nil {
				t.Fatalf("TestConnection() error = %v", err)
			}
			if diagnostic.Category != CategoryDestinationBlocked || diagnostic.Outcome != OutcomeFailure {
				t.Fatalf("diagnostic = %#v", diagnostic)
			}
			if targets := dialer.targets(); len(targets) != 0 {
				t.Fatalf("blocked destination was dialed: %v", targets)
			}
		})
	}
}

func TestEveryResolvedAddressMustPassPolicyBeforeAnyDial(t *testing.T) {
	t.Parallel()

	dialer := &recordingDialer{}
	resolver := publicResolver("93.184.216.34", "127.0.0.1")
	client, err := New(testOptions(resolver, dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	diagnostic, err := client.TestConnection(context.Background(), testConfiguration())
	if err != nil {
		t.Fatalf("TestConnection() error = %v", err)
	}
	if diagnostic.Category != CategoryDestinationBlocked || len(dialer.targets()) != 0 {
		t.Fatalf("diagnostic = %#v, dial targets = %v", diagnostic, dialer.targets())
	}
}

func TestPrivateDestinationsRequireExactDeploymentAllowlist(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		address  string
		allow    string
		category Category
		wantDial bool
	}{
		{name: "IPv4 inside", address: "10.20.1.2", allow: "10.20.0.0/16", category: CategoryConnectFailed, wantDial: true},
		{name: "IPv4 outside", address: "10.21.1.2", allow: "10.20.0.0/16", category: CategoryDestinationBlocked},
		{name: "IPv6 inside", address: "fd12:3456::1", allow: "fd12:3456::/32", category: CategoryConnectFailed, wantDial: true},
		{name: "IPv6 outside", address: "fd12:9999::1", allow: "fd12:3456::/32", category: CategoryDestinationBlocked},
		{name: "IPv6 metadata cannot be allowlisted", address: "fd00:ec2::254", allow: "fd00::/8", category: CategoryDestinationBlocked},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dialer := &recordingDialer{}
			options := testOptions(publicResolver(test.address), dialer)
			options.PrivateEgressCIDRs = []netip.Prefix{netip.MustParsePrefix(test.allow)}
			client, err := New(options)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			diagnostic, err := client.TestConnection(context.Background(), testConfiguration())
			if err != nil {
				t.Fatalf("TestConnection() error = %v", err)
			}
			if diagnostic.Category != test.category || (len(dialer.targets()) == 1) != test.wantDial {
				t.Fatalf("diagnostic = %#v, dial targets = %v", diagnostic, dialer.targets())
			}
		})
	}
}

func TestDNSRebindingIsRevalidatedAndOnlyLiteralIPIsDialed(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	lookup := 0
	resolver := resolverFunc(func(_ context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip" || host != "ldap.example.com" {
			t.Fatalf("LookupNetIP(%q, %q)", network, host)
		}
		mu.Lock()
		defer mu.Unlock()
		lookup++
		if lookup == 1 {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	})
	dialer := &recordingDialer{}
	client, err := New(testOptions(resolver, dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	first, err := client.TestConnection(context.Background(), testConfiguration())
	if err != nil || first.Category != CategoryConnectFailed {
		t.Fatalf("first diagnostic = %#v, %v", first, err)
	}
	second, err := client.TestConnection(context.Background(), testConfiguration())
	if err != nil || second.Category != CategoryDestinationBlocked {
		t.Fatalf("second diagnostic = %#v, %v", second, err)
	}
	if targets := dialer.targets(); len(targets) != 1 || targets[0] != "93.184.216.34:636" {
		t.Fatalf("dial targets = %v", targets)
	}
}

func TestResolutionBoundsAndFailuresAreSanitized(t *testing.T) {
	t.Parallel()

	tooMany := make([]netip.Addr, maximumResolvedAddresses+1)
	for index := range tooMany {
		tooMany[index] = netip.AddrFrom4([4]byte{93, 184, 216, byte(index + 1)})
	}
	for _, test := range []struct {
		name     string
		resolver Resolver
		category Category
	}{
		{name: "resolver error", resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, errors.New("upstream secret detail")
		}), category: CategoryDNSFailed},
		{name: "empty", resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) { return nil, nil }), category: CategoryDNSFailed},
		{name: "too many", resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) { return tooMany, nil }), category: CategoryDestinationBlocked},
		{name: "invalid", resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) { return []netip.Addr{{}}, nil }), category: CategoryDestinationBlocked},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client, err := New(testOptions(test.resolver, &recordingDialer{}))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			diagnostic, err := client.TestConnection(context.Background(), testConfiguration())
			if err != nil || diagnostic.Category != test.category {
				t.Fatalf("diagnostic = %#v, %v", diagnostic, err)
			}
		})
	}
}

func TestLiteralAddressSkipsResolverButStillUsesPolicy(t *testing.T) {
	t.Parallel()

	resolverCalls := 0
	resolver := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		resolverCalls++
		return nil, errors.New("must not be called")
	})
	dialer := &recordingDialer{}
	client, err := New(testOptions(resolver, dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	configuration := testConfiguration()
	configuration.Endpoints[0].Host = "93.184.216.34"
	diagnostic, err := client.TestConnection(context.Background(), configuration)
	if err != nil || diagnostic.Category != CategoryConnectFailed || resolverCalls != 0 {
		t.Fatalf("diagnostic = %#v, error = %v, resolver calls = %d", diagnostic, err, resolverCalls)
	}
	if targets := dialer.targets(); len(targets) != 1 || targets[0] != "93.184.216.34:636" {
		t.Fatalf("dial targets = %v", targets)
	}
}

func TestConcurrencyBudgetFailsClosedWithoutQueueing(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{})
	release := make(chan struct{})
	resolver := resolverFunc(func(ctx context.Context, _ string, _ string) ([]netip.Addr, error) {
		close(entered)
		select {
		case <-release:
			return nil, errors.New("released")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	client, err := New(Options{Resolver: resolver, Dialer: &recordingDialer{}, MaxConcurrent: 1})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		_, _ = client.TestConnection(context.Background(), testConfiguration())
	}()
	<-entered
	if _, err := client.TestConnection(context.Background(), testConfiguration()); !errors.Is(err, ErrBusy) {
		t.Fatalf("second TestConnection() error = %v", err)
	}
	secret := []byte("must-be-cleared")
	if _, err := client.TestBind(context.Background(), testConfiguration(), "cn=svc,dc=example,dc=com", secret); !errors.Is(err, ErrBusy) {
		t.Fatalf("busy TestBind() error = %v", err)
	}
	if !allZeroBytes(secret) {
		t.Fatal("busy TestBind() did not clear secret")
	}
	close(release)
	<-firstDone
}

func TestResolutionCancellationMatchesDatabaseFailureABI(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{})
	resolver := resolverFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	client, err := New(testOptions(resolver, &recordingDialer{}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan Diagnostic, 1)
	go func() {
		diagnostic, _ := client.TestConnection(ctx, testConfiguration())
		result <- diagnostic
	}()
	<-entered
	cancel()
	select {
	case diagnostic := <-result:
		if diagnostic.Category != CategoryCancelled || diagnostic.Outcome != OutcomeFailure {
			t.Fatalf("diagnostic = %#v", diagnostic)
		}
	case <-time.After(time.Second):
		t.Fatal("resolution did not stop on cancellation")
	}
}

func TestDialTimeoutIsBoundedAndSanitized(t *testing.T) {
	t.Parallel()

	dialer := dialerFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, errors.New("sensitive dial failure")
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	configuration := testConfiguration()
	configuration.ConnectTimeout = minimumConnectTimeout
	startedAt := time.Now()
	diagnostic, err := client.TestConnection(context.Background(), configuration)
	if err != nil || diagnostic.Category != CategoryConnectTimeout || diagnostic.Outcome != OutcomeFailure {
		t.Fatalf("diagnostic = %#v, error = %v", diagnostic, err)
	}
	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("connect timeout took %v", elapsed)
	}
}

func TestNilConnectionFromDialerFailsClosed(t *testing.T) {
	t.Parallel()

	dialer := dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, nil
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	diagnostic, err := client.TestConnection(context.Background(), testConfiguration())
	if err != nil || diagnostic.Category != CategoryConnectFailed {
		t.Fatalf("diagnostic = %#v, error = %v", diagnostic, err)
	}
}

func TestConnectionReturnedWithDialErrorIsClosed(t *testing.T) {
	t.Parallel()

	clientConnection, serverConnection := net.Pipe()
	defer serverConnection.Close()
	if err := serverConnection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	dialer := dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return clientConnection, errors.New("dial failed after allocating a connection")
	})
	client, err := New(testOptions(publicResolver("93.184.216.34"), dialer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	diagnostic, err := client.TestConnection(context.Background(), testConfiguration())
	if err != nil || diagnostic.Category != CategoryConnectFailed {
		t.Fatalf("diagnostic = %#v, error = %v", diagnostic, err)
	}
	buffer := make([]byte, 1)
	if read, err := serverConnection.Read(buffer); read != 0 || err == nil {
		t.Fatalf("leaked dial connection: read = %d, error = %v", read, err)
	}
}
