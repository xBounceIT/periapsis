package webhookurlpolicy

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var policyTestNow = time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)

func TestGoldenDigestsMatchNotifierCanonicalABI(t *testing.T) {
	policy, err := NewPolicy(PolicyInput{
		ID: testUUID(101), VersionID: testUUID(102), TenantID: testUUID(103), Version: 7,
		Rules: []RuleInput{
			{Effect: RuleDeny, Match: RuleSubdomains, Hostname: "EXAMPLE.com", Port: 8443},
			{Effect: RuleAllow, Match: RuleExact, Hostname: "BÜCHER.Example"},
		},
		PublishedByMembershipID: testUUID(104), PublishedAt: policyTestNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	defaultPort, err := CanonicalEndpoint("HTTPS://BÜCHER.Example:443/hook?mode=alert")
	if err != nil {
		t.Fatal(err)
	}
	nonDefaultPort, err := CanonicalEndpoint("https://BÜCHER.Example:8443/hook?mode=alert")
	if err != nil {
		t.Fatal(err)
	}
	rules := policy.Rules()
	got := map[string]any{
		"semantic":      fmt.Sprintf("%x", policy.SemanticDigest()),
		"version":       fmt.Sprintf("%x", policy.Digest()),
		"rule_0":        fmt.Sprintf("%x", rules[0].Digest()),
		"rule_1":        fmt.Sprintf("%x", rules[1].Digest()),
		"endpoint_443":  fmt.Sprintf("%x", defaultPort.Digest()),
		"endpoint_8443": fmt.Sprintf("%x", nonDefaultPort.Digest()),
	}
	want := map[string]any{
		"semantic":      "631a59fd46573840e7983d766c47f351e0de5cc9adc10000051a9cf929d5c0c7",
		"version":       "528df0fcdf6344273fec78a1d8462d5df471cad0bc7520a5e07f4d9181da9d5c",
		"rule_0":        "73bb7cccfe289491dd46280f555ab2d141604a43c7ad6fc69d2239a12d47e3df",
		"rule_1":        "7fc135421d7cae719a12ba544ded088eb2635213ebc5372eb27c8a58be8bd5bb",
		"endpoint_443":  "2196681bacef4a3a792566dd0213a7337dd63cd93e7c4031d1b954d45bbb3b7c",
		"endpoint_8443": "81c3853826acdde5d51307e419018ecdd2b84c0f1977335d4e40ce198a120117",
	}
	for key, expected := range want {
		if got[key] != expected {
			t.Errorf("%s = %v, want %v", key, got[key], expected)
		}
	}
	if defaultPort.URL() != "https://xn--bcher-kva.example/hook?mode=alert" ||
		nonDefaultPort.URL() != "https://xn--bcher-kva.example:8443/hook?mode=alert" {
		t.Fatalf("canonical endpoints = %q, %q", defaultPort.URL(), nonDefaultPort.URL())
	}
}

func TestPolicyIsCanonicalAppendOnlyAndDoesNotExposeMutableRules(t *testing.T) {
	current := testPolicy(t, testUUID(1), 1, []RuleInput{
		{Effect: RuleDeny, Match: RuleExact, Hostname: "Admin.Example.com"},
		{Effect: RuleAllow, Match: RuleSubdomains, Hostname: "Example.COM"},
	})
	rules := current.Rules()
	if len(rules) != 2 || rules[0].Effect() != RuleAllow || rules[0].Hostname() != "example.com" {
		t.Fatalf("rules = %#v", rules)
	}
	rules[0] = Rule{}
	if current.Rules()[0].Hostname() != "example.com" {
		t.Fatal("Rules exposed mutable policy state")
	}

	nextInput := PolicyInput{
		ID: current.ID(), VersionID: testUUID(20), TenantID: current.TenantID(), Version: 2,
		Rules:                   []RuleInput{{Effect: RuleAllow, Match: RuleExact, Hostname: "example.com"}},
		PublishedByMembershipID: testUUID(4), PublishedAt: policyTestNow.Add(time.Millisecond),
	}
	plan, err := PlanPolicyReplacement(current, 1, nextInput)
	if err != nil || plan.ExpectedVersion() != 1 || plan.Next().Version() != 2 || plan.Next().ID() != current.ID() {
		t.Fatalf("plan = %#v, error = %v", plan, err)
	}
	if _, err := PlanPolicyReplacement(current, 2, nextInput); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale CAS error = %v", err)
	}
	nextInput.VersionID = testUUID(21)
	nextInput.Rules = ruleInputs(current.Rules())
	if _, err := PlanPolicyReplacement(current, 1, nextInput); !errors.Is(err, ErrNoChange) {
		t.Fatalf("no-change error = %v", err)
	}
	nextInput.Rules = []RuleInput{{Effect: RuleAllow, Match: RuleExact, Hostname: "new.example"}}
	nextInput.PublishedAt = current.PublishedAt().Add(-time.Millisecond)
	if _, err := PlanPolicyReplacement(current, 1, nextInput); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("backdated error = %v", err)
	}
}

func TestPolicyRejectsAmbiguousRulesAndBoundaries(t *testing.T) {
	invalidRules := [][]RuleInput{
		{{Effect: RuleAllow, Match: RuleExact, Hostname: "127.0.0.1"}},
		{{Effect: RuleAllow, Match: RuleExact, Hostname: "[2001:db8::1]"}},
		{{Effect: RuleAllow, Match: RuleExact, Hostname: "10.0.0.0/8"}},
		{{Effect: RuleAllow, Match: RuleExact, Hostname: "tenant.localhost"}},
		{{Effect: RuleAllow, Match: RuleExact, Hostname: "hooks.example."}},
		{{Effect: RuleAllow, Match: RuleExact, Hostname: "hooks%2eexample"}},
		{{Effect: RuleAllow, Match: RuleExact, Hostname: "*.example.com"}},
		{{Effect: RuleAllow, Match: RuleExact, Hostname: "singlelabel"}},
		{{Effect: RuleAllow, Match: RuleExact, Hostname: "hooks.example", Port: 65_536}},
		{
			{Effect: RuleAllow, Match: RuleExact, Hostname: "hooks.example"},
			{Effect: RuleAllow, Match: RuleExact, Hostname: "HOOKS.EXAMPLE", Port: 443},
		},
	}
	for _, rules := range invalidRules {
		input := PolicyInput{
			ID: testUUID(50), VersionID: testUUID(51), TenantID: testUUID(52), Version: 1,
			Rules: rules, PublishedByMembershipID: testUUID(53), PublishedAt: policyTestNow,
		}
		if policy, err := NewPolicy(input); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("NewPolicy(%v) = %#v, %v", rules, policy, err)
		}
	}
	tooMany := make([]RuleInput, MaximumPolicyRules+1)
	for index := range tooMany {
		tooMany[index] = RuleInput{
			Effect: RuleAllow, Match: RuleExact, Hostname: fmt.Sprintf("hooks-%d.example", index),
		}
	}
	if _, err := NewPolicy(PolicyInput{
		ID: testUUID(54), VersionID: testUUID(55), TenantID: testUUID(56), Version: 1,
		Rules: tooMany, PublishedByMembershipID: testUUID(57), PublishedAt: policyTestNow,
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversized rules error = %v", err)
	}
	if _, err := NewPolicy(PolicyInput{
		ID: testUUID(54), VersionID: testUUID(55), TenantID: testUUID(56), Version: 1,
		PublishedByMembershipID: testUUID(57), PublishedAt: time.Date(1999, 12, 31, 23, 59, 59, 0, time.UTC),
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("out-of-range instant error = %v", err)
	}
}

func TestCanonicalEndpointRejectsAmbiguousAuthorityAndPathForms(t *testing.T) {
	valid := map[string]string{
		"https://Hooks.Example":                            "https://hooks.example/",
		"HTTPS://BÜCHER.Example:8443/hooks/v1?event=alert": "https://xn--bcher-kva.example:8443/hooks/v1?event=alert",
	}
	for input, expected := range valid {
		endpoint, err := CanonicalEndpoint(input)
		if err != nil || endpoint.URL() != expected {
			t.Errorf("CanonicalEndpoint(%q) = %q, %v", input, endpoint.URL(), err)
		}
	}
	invalid := []string{
		"http://hooks.example/", "https://hooks.example./", "https://hooks.example.:443/",
		"https://@hooks.example/", "https://user:password@hooks.example/",
		"https://127.0.0.1/", "https://127.1/", "https://0x7f000001/", "https://2130706433/",
		"https://[2001:db8::1]/", "https://hooks%2eexample/", "https://hooks.example/%2e%2e/admin",
		"https://hooks.example/a/../admin", "https://hooks.example\\@attacker.example/",
		"https://hooks.example/#fragment", "https://hooks.example:0443/", "https://hooks.example:/",
		"https://localhost/", "https://tenant.localhost/", "https://example.09/", "https://1.2.3.4.5/",
		" https://hooks.example/", "https://hooks.example/\nattacker",
		"https://hooks.\u202eexample/", "https://hooks.example/秘密",
	}
	for _, input := range invalid {
		if endpoint, err := CanonicalEndpoint(input); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("CanonicalEndpoint(%q) = %v, %v", input, endpoint, err)
		}
	}
}

func TestDenyPrecedenceSubdomainApexAndDefaultDeny(t *testing.T) {
	policy := testPolicy(t, testUUID(1), 1, []RuleInput{
		{Effect: RuleAllow, Match: RuleExact, Hostname: "example.com"},
		{Effect: RuleAllow, Match: RuleSubdomains, Hostname: "example.com"},
		{Effect: RuleDeny, Match: RuleExact, Hostname: "blocked.example.com"},
		{Effect: RuleDeny, Match: RuleSubdomains, Hostname: "private.example.com"},
	})
	for endpointURL, expected := range map[string]DecisionReason{
		"https://example.com/":           DecisionAllowedByRule,
		"https://child.example.com/":     DecisionAllowedByRule,
		"https://blocked.example.com/":   DecisionDeniedByRule,
		"https://x.private.example.com/": DecisionDeniedByRule,
		"https://private.example.com/":   DecisionAllowedByRule,
		"https://unrelated.example.net/": DecisionDefaultDeny,
	} {
		endpoint, err := CanonicalEndpoint(endpointURL)
		if err != nil {
			t.Fatal(err)
		}
		decision, err := Evaluate(policy, endpoint)
		if err != nil || decision.Reason != expected || decision.Allowed != (expected == DecisionAllowedByRule) {
			t.Errorf("Evaluate(%q) = %#v, %v", endpointURL, decision, err)
		}
		serialized := fmt.Sprintf("%#v", decision)
		if stringsContainAny(serialized, endpoint.Hostname(), endpoint.URL()) {
			t.Fatalf("decision evidence leaked endpoint: %s", serialized)
		}
	}

	subdomainOnly := testPolicy(t, testUUID(30), 1, []RuleInput{
		{Effect: RuleAllow, Match: RuleSubdomains, Hostname: "vendor.example"},
	})
	apex, _ := CanonicalEndpoint("https://vendor.example/")
	decision, _ := Evaluate(subdomainOnly, apex)
	if decision.Allowed || decision.Reason != DecisionDefaultDeny {
		t.Fatalf("subdomain rule unexpectedly included apex: %#v", decision)
	}
}

func TestConfigurationAndDeliveryPinsAreExactAndTenantScoped(t *testing.T) {
	policy := testPolicy(t, testUUID(1), 1, []RuleInput{
		{Effect: RuleAllow, Match: RuleExact, Hostname: "hooks.example"},
	})
	configuration, err := NewConfigurationPin(
		policy, testUUID(40), 3, policy.TenantID(), "https://HOOKS.example/path?tenant=opaque",
	)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := NewDeliveryPin(
		configuration, testUUID(41), configuration.ConfigurationID(), configuration.ConfigurationVersion(),
		configuration.TenantID(), configuration.Endpoint().URL(),
	)
	if err != nil || delivery.PolicyDigest() != policy.Digest() || delivery.Endpoint().Digest() != configuration.Endpoint().Digest() {
		t.Fatalf("delivery pin = %#v, error = %v", delivery, err)
	}
	if _, err := NewConfigurationPin(policy, testUUID(42), 1, testUUID(999), "https://hooks.example/"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("cross-tenant config pin error = %v", err)
	}
	if _, err := NewDeliveryPin(
		configuration, testUUID(43), configuration.ConfigurationID(), configuration.ConfigurationVersion(),
		configuration.TenantID(), "https://attacker.example/",
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("substituted endpoint error = %v", err)
	}
}

func testPolicy(t *testing.T, versionID uuid.UUID, version int64, rules []RuleInput) Policy {
	t.Helper()
	policy, err := NewPolicy(PolicyInput{
		ID: testUUID(2), VersionID: versionID, TenantID: testUUID(3), Version: version,
		Rules: rules, PublishedByMembershipID: testUUID(4),
		PublishedAt: policyTestNow.Add(time.Duration(version-1) * time.Millisecond),
	})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func testUUID(value uint32) uuid.UUID {
	return uuid.MustParse(fmt.Sprintf("019d0000-0000-7000-8000-%012d", value))
}

func stringsContainAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if candidate != "" && strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}

func FuzzCanonicalEndpointRoundTripsWithoutParserDrift(f *testing.F) {
	for _, seed := range []string{
		"https://hooks.example/", "HTTPS://BÜCHER.Example:443/hook?mode=alert",
		"https://127.1/", "https://user@hooks.example/", "https://hooks%2eexample/",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		endpoint, err := CanonicalEndpoint(input)
		if err != nil {
			return
		}
		restored, err := CanonicalEndpoint(endpoint.URL())
		if err != nil || restored != endpoint || endpoint.Port() < 1 || endpoint.Port() > 65_535 ||
			stringsContainAny(endpoint.URL(), "#", "%", "\\") || looksLikeIPLiteral(endpoint.Hostname()) {
			t.Fatalf("non-idempotent canonical endpoint: %#v, %#v, %v", endpoint, restored, err)
		}
	})
}
