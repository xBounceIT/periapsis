package ldapclient

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestDirectoryReferralURLMustCanonicallyMatchAllowedEndpoint(t *testing.T) {
	t.Parallel()

	ldaps := Endpoint{
		Priority: 2, Enabled: true, ReferralAllowed: true,
		Host: "referral.example.com", Port: 636, Transport: TransportLDAPS,
		TLSServerName: "referral.example.com",
	}
	startTLS := Endpoint{
		Priority: 3, Enabled: true, ReferralAllowed: true,
		Host: "starttls.example.com", Port: 389, Transport: TransportStartTLS,
		TLSServerName: "starttls.example.com",
	}
	allowed := map[directoryEndpointOrigin]Endpoint{
		directoryOriginForEndpoint(ldaps):    ldaps,
		directoryOriginForEndpoint(startTLS): startTLS,
	}
	for _, referralURL := range []string{
		"ldaps://referral.example.com",
		"ldaps://referral.example.com:636",
		"ldap://starttls.example.com",
		"ldap://starttls.example.com:389",
	} {
		endpoint, err := directoryReferralEndpoint(referralURL, allowed)
		if err != nil || !endpoint.ReferralAllowed {
			t.Fatalf("directoryReferralEndpoint(%q) = %s, %v", referralURL, endpoint, err)
		}
	}

	for _, referralURL := range []string{
		"ldap://referral.example.com:636",
		"ldaps://referral.example.com:389",
		"ldaps://other.example.com:636",
		"ldaps://user@referral.example.com:636",
		"ldaps://referral.example.com:0636",
		"ldaps://REFERRAL.example.com:636",
		"ldaps://referral.example.com:636/",
		"ldaps://referral.example.com:636/ou=people",
		"ldaps://referral.example.com:636?scope=sub",
		"ldaps://referral.example.com:636#fragment",
		"ldaps://127.1:636",
		"ldaps://0x7f000001:636",
		"http://referral.example.com:636",
	} {
		if _, err := directoryReferralEndpoint(referralURL, allowed); !errors.Is(err, errDirectoryReferral) {
			t.Fatalf("directoryReferralEndpoint(%q) error = %v", referralURL, err)
		}
	}
}

func TestDirectoryReferralTraversalRejectsLoopsAndHopOverflowBeforeNetwork(t *testing.T) {
	t.Parallel()

	endpointA := Endpoint{
		Priority: 1, Enabled: true, ReferralAllowed: true,
		Host: "a.example.com", Port: 636, Transport: TransportLDAPS, TLSServerName: "a.example.com",
	}
	endpointB := Endpoint{
		Priority: 2, Enabled: true, ReferralAllowed: true,
		Host: "b.example.com", Port: 636, Transport: TransportLDAPS, TLSServerName: "b.example.com",
	}
	state := &directorySearchState{limits: testDirectoryLimits(), referrals: &directoryReferralPolicy{
		configuration: validatedDirectoryReferrals{
			enabled: true,
			maxHops: 1,
			endpoints: map[directoryEndpointOrigin]Endpoint{
				directoryOriginForEndpoint(endpointA): endpointA,
				directoryOriginForEndpoint(endpointB): endpointB,
			},
		},
	}}
	path := map[directoryEndpointOrigin]struct{}{directoryOriginForEndpoint(endpointA): {}}
	if _, err := state.validatedReferralTargets([]string{"ldaps://a.example.com:636"}, 0, path); !errors.Is(err, errDirectoryReferral) {
		t.Fatalf("loop error = %v", err)
	}
	if _, err := state.validatedReferralTargets([]string{"ldaps://b.example.com:636"}, 1, path); !errors.Is(err, errDirectoryReferral) {
		t.Fatalf("hop overflow error = %v", err)
	}
	if targets, err := state.validatedReferralTargets([]string{"ldaps://b.example.com:636"}, 0, path); err != nil || len(targets) != 1 {
		t.Fatalf("allowed target = %v, %v", targets, err)
	}
}

func TestDirectoryReferralConfigurationIsClosedAndRedacted(t *testing.T) {
	t.Parallel()

	client := newValidationOnlyDirectoryClient(t)
	configured := validDirectoryRequest(t)
	configured.ReferralMode = DirectoryReferralModeConfiguredEndpoints
	configured.ReferralMaxHops = 2
	configured.Configuration.Endpoints[0].ReferralAllowed = true
	validated, err := client.validateDirectoryRequest(configured)
	if err != nil || !validated.referrals.enabled || validated.referrals.maxHops != 2 ||
		len(validated.referrals.endpoints) != 1 {
		t.Fatalf("configured referral validation = %#v, %v", validated.referrals, err)
	}

	for name, mutate := range map[string]func(*DirectoryRequest){
		"disabled latent allow": func(value *DirectoryRequest) {
			value.Configuration.Endpoints[0].ReferralAllowed = true
		},
		"configured no allow": func(value *DirectoryRequest) {
			value.ReferralMode = DirectoryReferralModeConfiguredEndpoints
			value.ReferralMaxHops = 1
		},
		"configured zero hops": func(value *DirectoryRequest) {
			value.ReferralMode = DirectoryReferralModeConfiguredEndpoints
			value.Configuration.Endpoints[0].ReferralAllowed = true
		},
		"configured excessive hops": func(value *DirectoryRequest) {
			value.ReferralMode = DirectoryReferralModeConfiguredEndpoints
			value.ReferralMaxHops = maximumDirectoryReferralHops + 1
			value.Configuration.Endpoints[0].ReferralAllowed = true
		},
		"disabled endpoint allowed": func(value *DirectoryRequest) {
			value.ReferralMode = DirectoryReferralModeConfiguredEndpoints
			value.ReferralMaxHops = 1
			value.Configuration.Endpoints[0].Enabled = false
			value.Configuration.Endpoints[0].ReferralAllowed = true
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := validDirectoryRequest(t)
			mutate(&candidate)
			if _, err := client.validateDirectoryRequest(candidate); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("validateDirectoryRequest() error = %v", err)
			}
		})
	}

	canary := DirectoryReferralMode("private-referral-mode")
	formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x", canary, canary, canary, canary, canary, canary)
	if strings.Contains(formatted, string(canary)) ||
		strings.Contains(strings.ToLower(formatted), fmt.Sprintf("%x", []byte(canary))) {
		t.Fatalf("referral mode formatting exposed raw value: %s", formatted)
	}
	secretCanary := "private-referral-bind-secret"
	hostCanary := "private-referral-host.example.com"
	endpoint := Endpoint{
		Priority: 1, Enabled: true, ReferralAllowed: true,
		Host: hostCanary, Port: 636, Transport: TransportLDAPS, TLSServerName: hostCanary,
	}
	policy := directoryReferralPolicy{
		configuration: validatedDirectoryReferrals{
			enabled: true, maxHops: 2,
			endpoints: map[directoryEndpointOrigin]Endpoint{directoryOriginForEndpoint(endpoint): endpoint},
		},
		bindDN:     "cn=private-referral-bind,dc=example,dc=com",
		bindSecret: []byte(secretCanary),
	}
	formatted = fmt.Sprintf("%v|%+v|%#v|%s|%q|%x", policy, policy, policy, policy, policy, policy)
	for _, privateValue := range []string{secretCanary, hostCanary, policy.bindDN} {
		if strings.Contains(strings.ToLower(formatted), strings.ToLower(privateValue)) ||
			strings.Contains(strings.ToLower(formatted), fmt.Sprintf("%x", []byte(privateValue))) {
			t.Fatalf("referral policy formatting exposed %q: %s", privateValue, formatted)
		}
	}
}
