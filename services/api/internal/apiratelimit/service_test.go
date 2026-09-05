package apiratelimit

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/google/uuid"
)

type repositoryStub struct {
	rules    []Rule
	decision Decision
	err      error
}

func (r *repositoryStub) Admit(_ context.Context, rules []Rule) (Decision, error) {
	r.rules = make([]Rule, len(rules))
	for index, rule := range rules {
		r.rules[index] = rule
		r.rules[index].Digest = append([]byte(nil), rule.Digest...)
	}
	return r.decision, r.err
}

func TestServiceBuildsPurposeSeparatedBoundedRules(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	repository := &repositoryStub{decision: Decision{Admitted: true}}
	service := newTestService(t, repository)
	defer service.Close()

	request := Request{
		ClientNetwork: netip.MustParsePrefix("2001:db8:abcd:42::/64"),
		Credential:    "a-high-entropy-opaque-session-token",
		TenantID:      &tenantID,
	}
	decision, err := service.Admit(context.Background(), request)
	if err != nil || !decision.Admitted || len(repository.rules) != 3 {
		t.Fatalf("Admit() = %#v, %v; rules = %#v", decision, err, repository.rules)
	}
	wantScopes := []string{ScopeNetwork, ScopeCredential, ScopeTenantSubject}
	wantLimits := []int32{100, 60, 40}
	for index, rule := range repository.rules {
		if rule.Scope != wantScopes[index] || rule.Limit != wantLimits[index] || len(rule.Digest) != 32 {
			t.Fatalf("rule[%d] = %#v", index, rule)
		}
		if bytes.Contains(rule.Digest, []byte(request.Credential)) ||
			bytes.Contains(rule.Digest, []byte(tenantID.String())) ||
			bytes.Contains(rule.Digest, []byte(request.ClientNetwork.String())) {
			t.Fatalf("rule[%d] retained raw identity material", index)
		}
	}
	if bytes.Equal(repository.rules[0].Digest, repository.rules[1].Digest) ||
		bytes.Equal(repository.rules[1].Digest, repository.rules[2].Digest) {
		t.Fatal("purpose-separated rule digests collided")
	}
}

func TestTenantSubjectIsCredentialScopedAndAnonymousFallbackIsNetworkScoped(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	otherTenantID := uuid.Must(uuid.NewV7())
	repository := &repositoryStub{decision: Decision{Admitted: true}}
	service := newTestService(t, repository)
	defer service.Close()

	digest := func(request Request) []byte {
		t.Helper()
		if _, err := service.Admit(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		return append([]byte(nil), repository.rules[len(repository.rules)-1].Digest...)
	}
	networkA := netip.MustParsePrefix("198.51.100.10/32")
	networkB := netip.MustParsePrefix("198.51.100.11/32")
	credentialA := digest(Request{ClientNetwork: networkA, Credential: "credential-a", TenantID: &tenantID})
	credentialAOtherNetwork := digest(Request{ClientNetwork: networkB, Credential: "credential-a", TenantID: &tenantID})
	credentialB := digest(Request{ClientNetwork: networkA, Credential: "credential-b", TenantID: &tenantID})
	otherTenant := digest(Request{ClientNetwork: networkA, Credential: "credential-a", TenantID: &otherTenantID})
	anonymousA := digest(Request{ClientNetwork: networkA, TenantID: &tenantID})
	anonymousB := digest(Request{ClientNetwork: networkB, TenantID: &tenantID})

	if !bytes.Equal(credentialA, credentialAOtherNetwork) {
		t.Fatal("credential-scoped tenant rule changed with client network")
	}
	for name, candidate := range map[string][]byte{
		"other credential": credentialB,
		"other tenant":     otherTenant,
		"anonymous":        anonymousA,
		"other network":    anonymousB,
	} {
		if bytes.Equal(credentialA, candidate) {
			t.Fatalf("tenant subject collided with %s", name)
		}
	}
}

func TestServiceDerivesStableReplicaKeysAndSeparatesMasterKeys(t *testing.T) {
	request := Request{
		ClientNetwork: netip.MustParsePrefix("203.0.113.45/32"),
		Credential:    "stable-credential",
	}
	repositories := []*repositoryStub{
		{decision: Decision{Admitted: true}},
		{decision: Decision{Admitted: true}},
		{decision: Decision{Admitted: true}},
	}
	first := newTestService(t, repositories[0])
	defer first.Close()
	second := newTestService(t, repositories[1])
	defer second.Close()
	other, err := New(
		repositories[2],
		[]byte("abcdef0123456789abcdef0123456789"),
		Policy{100, 60, 40},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()

	for _, service := range []*Service{first, second, other} {
		if _, err := service.Admit(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	for index := range repositories[0].rules {
		if !bytes.Equal(repositories[0].rules[index].Digest, repositories[1].rules[index].Digest) {
			t.Fatalf("replica digest[%d] is not stable", index)
		}
		if bytes.Equal(repositories[0].rules[index].Digest, repositories[2].rules[index].Digest) {
			t.Fatalf("digest[%d] did not separate master keys", index)
		}
	}
}

func TestServiceFailsClosedOnRepositoryOrContradictoryDecision(t *testing.T) {
	for name, repository := range map[string]*repositoryStub{
		"repository failure":   {err: errors.New("database unavailable")},
		"denied without retry": {decision: Decision{Admitted: false}},
		"admitted with retry":  {decision: Decision{Admitted: true, RetryAfterSeconds: 1}},
		"admitted negative retry": {
			decision: Decision{Admitted: true, RetryAfterSeconds: -1},
		},
	} {
		t.Run(name, func(t *testing.T) {
			service := newTestService(t, repository)
			defer service.Close()
			_, err := service.Admit(context.Background(), Request{
				ClientNetwork: netip.MustParsePrefix("192.0.2.44/32"),
			})
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("Admit() error = %v", err)
			}
		})
	}
}

func TestServicePreservesCancellationWithoutWeakeningAdmission(t *testing.T) {
	request := Request{ClientNetwork: netip.MustParsePrefix("192.0.2.44/32")}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	repository := &repositoryStub{decision: Decision{Admitted: true}}
	service := newTestService(t, repository)
	defer service.Close()
	if _, err := service.Admit(canceled, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("Admit(canceled) error = %v", err)
	}
	if len(repository.rules) != 0 {
		t.Fatalf("canceled admission reached persistence: %#v", repository.rules)
	}

	repository.err = context.DeadlineExceeded
	if _, err := service.Admit(context.Background(), request); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Admit(repository deadline) error = %v", err)
	}
}

func TestServiceRejectsUnsafeConstructionAndUseAfterClose(t *testing.T) {
	validPolicy := Policy{100, 60, 40}
	for name, configure := range map[string]func() (Repository, []byte, Policy){
		"missing repository": func() (Repository, []byte, Policy) { return nil, make([]byte, 32), validPolicy },
		"short key":          func() (Repository, []byte, Policy) { return &repositoryStub{}, make([]byte, 31), validPolicy },
		"zero limit": func() (Repository, []byte, Policy) {
			return &repositoryStub{}, make([]byte, 32), Policy{}
		},
		"oversized limit": func() (Repository, []byte, Policy) {
			return &repositoryStub{}, make([]byte, 32), Policy{101, 60, 40}
		},
	} {
		t.Run(name, func(t *testing.T) {
			repository, key, policy := configure()
			if _, err := New(repository, key, policy); err == nil {
				t.Fatal("New() accepted unsafe configuration")
			}
		})
	}

	service := newTestService(t, &repositoryStub{decision: Decision{Admitted: true}})
	service.Close()
	_, err := service.Admit(context.Background(), Request{ClientNetwork: netip.MustParsePrefix("192.0.2.1/32")})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Admit() after Close error = %v", err)
	}
}

func TestServiceRejectsInvalidAdmissionIdentity(t *testing.T) {
	tenantV4 := uuid.New()
	for name, test := range map[string]struct {
		ctx     context.Context
		request Request
	}{
		"nil context": {
			request: Request{ClientNetwork: netip.MustParsePrefix("192.0.2.1/32")},
		},
		"missing network": {ctx: context.Background()},
		"unmasked network": {
			ctx: context.Background(), request: Request{ClientNetwork: netip.MustParsePrefix("192.0.2.1/24")},
		},
		"broad IPv4 network": {
			ctx: context.Background(), request: Request{ClientNetwork: netip.MustParsePrefix("192.0.2.0/24")},
		},
		"narrow IPv6 network": {
			ctx: context.Background(), request: Request{ClientNetwork: netip.MustParsePrefix("2001:db8::1/128")},
		},
		"oversized credential": {
			ctx: context.Background(), request: Request{
				ClientNetwork: netip.MustParsePrefix("192.0.2.1/32"), Credential: string(make([]byte, 257)),
			},
		},
		"non-v7 tenant": {
			ctx: context.Background(), request: Request{
				ClientNetwork: netip.MustParsePrefix("192.0.2.1/32"), TenantID: &tenantV4,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			repository := &repositoryStub{decision: Decision{Admitted: true}}
			service := newTestService(t, repository)
			defer service.Close()
			if _, err := service.Admit(test.ctx, test.request); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("Admit() error = %v", err)
			}
			if len(repository.rules) != 0 {
				t.Fatalf("invalid identity reached persistence: %#v", repository.rules)
			}
		})
	}
}

func newTestService(t *testing.T, repository Repository) *Service {
	t.Helper()
	service, err := New(repository, []byte("0123456789abcdef0123456789abcdef"), Policy{
		NetworkRequestsPerSecond: 100, CredentialRequestsPerSecond: 60,
		TenantSubjectRequestsPerSecond: 40,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}
