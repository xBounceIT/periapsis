// Package apiratelimit provides shared, purpose-separated admission for the
// complete HTTP API surface.
package apiratelimit

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net/netip"
	"sync"

	"github.com/google/uuid"
)

const (
	ScopeNetwork       = "api_network"
	ScopeCredential    = "api_credential"
	ScopeTenantSubject = "api_tenant_subject"

	// MaximumRequestsPerSecond matches the bounded admission ABI enforced by PostgreSQL.
	MaximumRequestsPerSecond int32 = 100

	derivedKeyInfo = "periapsis/api-rate-limit/key/v1"
)

var ErrUnavailable = errors.New("API rate-limit admission unavailable")

// Policy is a one-second request budget for each independently keyed scope.
// The database owns the window clock and serializes concurrent replicas.
type Policy struct {
	NetworkRequestsPerSecond       int32
	CredentialRequestsPerSecond    int32
	TenantSubjectRequestsPerSecond int32
}

// Request contains only the bounded identity material required to construct
// one-way admission keys. Credential is never returned to a caller or sent to
// persistence.
type Request struct {
	ClientNetwork netip.Prefix
	Credential    string
	TenantID      *uuid.UUID
}

// Decision is the database-authoritative admission result. RetryAfterSeconds
// is positive exactly when Admitted is false.
type Decision struct {
	Admitted          bool
	RetryAfterSeconds int
}

// Valid reports whether retry guidance agrees exactly with the admission bit.
func (d Decision) Valid() bool {
	if d.Admitted {
		return d.RetryAfterSeconds == 0
	}
	return d.RetryAfterSeconds > 0
}

// Rule is a purpose-separated, one-way database admission meter.
type Rule struct {
	Scope  string
	Digest []byte
	Limit  int32
}

// Repository serializes all supplied rules in one PostgreSQL transaction.
type Repository interface {
	Admit(context.Context, []Rule) (Decision, error)
}

// Service derives one-way meter keys before invoking shared persistence.
type Service struct {
	repository Repository
	policy     Policy
	mu         sync.RWMutex
	key        []byte
}

// New returns a rate limiter backed by the supplied shared repository.
func New(repository Repository, keyMaterial []byte, policy Policy) (*Service, error) {
	if repository == nil || len(keyMaterial) < sha256.Size || !validPolicy(policy) {
		return nil, errors.New("valid API rate-limit repository, key material, and policy are required")
	}
	derived, err := hkdf.Key(sha256.New, keyMaterial, nil, derivedKeyInfo, sha256.Size)
	if err != nil {
		return nil, errors.New("derive API rate-limit key")
	}
	return &Service{repository: repository, policy: policy, key: derived}, nil
}

// Close destroys the derived key after the HTTP server has stopped.
func (s *Service) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.key)
	s.key = nil
}

// Admit constructs network, optional credential, and optional bounded tenant
// tuple rules, then asks PostgreSQL for one aggregate decision.
func (s *Service) Admit(ctx context.Context, request Request) (Decision, error) {
	if s == nil || ctx == nil || !validRequest(request) {
		return Decision{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}

	s.mu.RLock()
	if len(s.key) != sha256.Size {
		s.mu.RUnlock()
		return Decision{}, ErrUnavailable
	}
	rules := s.rules(request)
	s.mu.RUnlock()
	defer func() {
		for index := range rules {
			clear(rules[index].Digest)
		}
	}()

	decision, err := s.repository.Admit(ctx, rules)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return Decision{}, err
	}
	if err != nil || !decision.Valid() {
		return Decision{}, ErrUnavailable
	}
	return decision, nil
}

func (s *Service) rules(request Request) []Rule {
	rules := make([]Rule, 0, 3)
	networkIdentity := request.ClientNetwork.String()
	rules = append(rules, Rule{
		Scope: ScopeNetwork, Digest: s.digest(ScopeNetwork, networkIdentity),
		Limit: s.policy.NetworkRequestsPerSecond,
	})

	var tenantSubject string
	if request.Credential != "" {
		credentialDigest := s.digest(ScopeCredential, request.Credential)
		rules = append(rules, Rule{
			Scope: ScopeCredential, Digest: credentialDigest,
			Limit: s.policy.CredentialRequestsPerSecond,
		})
		tenantSubject = "credential:" + string(credentialDigest)
	} else {
		tenantSubject = "network:" + networkIdentity
	}
	if request.TenantID != nil {
		rules = append(rules, Rule{
			Scope: ScopeTenantSubject,
			Digest: s.digest(
				ScopeTenantSubject,
				request.TenantID.String()+"\x00"+tenantSubject,
			),
			Limit: s.policy.TenantSubjectRequestsPerSecond,
		})
	}
	return rules
}

func (s *Service) digest(domain, value string) []byte {
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func validPolicy(policy Policy) bool {
	return validLimit(policy.NetworkRequestsPerSecond) &&
		validLimit(policy.CredentialRequestsPerSecond) &&
		validLimit(policy.TenantSubjectRequestsPerSecond)
}

func validLimit(value int32) bool {
	return value >= 1 && value <= MaximumRequestsPerSecond
}

func validRequest(request Request) bool {
	if !request.ClientNetwork.IsValid() || request.ClientNetwork != request.ClientNetwork.Masked() {
		return false
	}
	if request.ClientNetwork.Addr().Is4() && request.ClientNetwork.Bits() != 32 ||
		request.ClientNetwork.Addr().Is6() && request.ClientNetwork.Bits() != 64 {
		return false
	}
	if len(request.Credential) > 256 {
		return false
	}
	return request.TenantID == nil ||
		*request.TenantID != uuid.Nil && request.TenantID.Version() == 7 && request.TenantID.Variant() == uuid.RFC4122
}
