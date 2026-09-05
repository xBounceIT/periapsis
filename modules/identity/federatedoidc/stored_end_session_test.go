package federatedoidc

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

type storedLogoutConfirmationFixture struct {
	provider              identity.ProviderContext
	admission             identity.TenantAdmissionContext
	material              identity.EntityID
	session               identity.EntityID
	postLogoutRedirectURI string
	revokedAt             time.Time
}

func (value storedLogoutConfirmationFixture) OIDCProvider() identity.ProviderContext {
	return value.provider
}
func (value storedLogoutConfirmationFixture) OIDCAdmission() identity.TenantAdmissionContext {
	return value.admission
}
func (value storedLogoutConfirmationFixture) OIDCMaterialID() identity.EntityID {
	return value.material
}
func (value storedLogoutConfirmationFixture) OIDCPostLogoutRedirectURI() string {
	return value.postLogoutRedirectURI
}
func (value storedLogoutConfirmationFixture) LocalSessionID() identity.EntityID {
	return value.session
}
func (value storedLogoutConfirmationFixture) LocalSessionRevokedAt() time.Time {
	return value.revokedAt
}

type observedStoredLogoutConfirmation struct {
	storedLogoutConfirmationFixture
	observedAt time.Time
}

func (value observedStoredLogoutConfirmation) LocalLogoutObservedAt() time.Time {
	return value.observedAt
}

func TestStoredEndSessionBuilderRequiresExactCommittedOwnerAndDeploymentRedirect(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	tenantID := testAuthorizationBegin(2).OperationRunID
	providerID := testAuthorizationBegin(3).OperationRunID
	bindingID := testAuthorizationBegin(4).OperationRunID
	materialID := testAuthorizationBegin(5).OperationRunID
	sessionID := testAuthorizationBegin(6).OperationRunID
	provider := identity.ProviderContext{
		Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: providerID,
	}
	admission := identity.TenantAdmissionContext{TenantID: tenantID, BindingID: bindingID}
	confirmation := storedLogoutConfirmationFixture{
		provider: provider, admission: admission, material: materialID,
		session: sessionID, postLogoutRedirectURI: "https://app.example/signed-out",
		revokedAt: flowTestNow,
	}
	builder, err := newStoredEndSessionBuilder(
		fixture.flow.trust,
		"https://app.example/signed-out",
		&deterministicFlowReader{},
		func() time.Time { return flowTestNow },
	)
	if err != nil {
		t.Fatal(err)
	}
	request := StoredEndSessionBuildRequest{
		Provider: provider, Admission: admission, MaterialID: materialID, SessionID: sessionID,
		EndpointURL: testEndSession, PostLogoutRedirectURI: "https://app.example/signed-out",
		IDTokenHint:  []byte("header.payload.signature"),
		Confirmation: confirmation,
	}
	artifact, err := builder.Build(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := url.Parse(artifact.RedirectURL())
	if err != nil {
		t.Fatal(err)
	}
	if redirect.Scheme != "https" || redirect.Host != "provider.example" ||
		redirect.Query().Get("id_token_hint") != "header.payload.signature" ||
		redirect.Query().Get("post_logout_redirect_uri") != "https://app.example/signed-out" ||
		!validOpaque([]byte(redirect.Query().Get("state"))) {
		t.Fatalf("unexpected end-session redirect: %q", artifact.RedirectURL())
	}
	if strings.Contains(artifact.String(), "header.payload.signature") ||
		strings.Contains(request.String(), "header.payload.signature") {
		t.Fatal("stored logout formatting exposed token material")
	}
	artifact.Destroy()
	if artifact.RedirectURL() != "" || len(artifact.IDTokenHint()) != 0 {
		t.Fatal("Destroy retained browser redirect material")
	}

	wrongOwner := request
	wrongOwner.Confirmation = storedLogoutConfirmationFixture{
		provider: provider, admission: admission, material: testAuthorizationBegin(7).OperationRunID,
		session: sessionID, postLogoutRedirectURI: request.PostLogoutRedirectURI, revokedAt: flowTestNow,
	}
	if _, err = builder.Build(context.Background(), wrongOwner); !errors.Is(err, ErrUpstreamArtifactRejected) {
		t.Fatalf("cross-material confirmation accepted: %v", err)
	}
	expired := request
	expired.Confirmation = storedLogoutConfirmationFixture{
		provider: provider, admission: admission, material: materialID,
		session: sessionID, postLogoutRedirectURI: request.PostLogoutRedirectURI,
		revokedAt: flowTestNow.Add(-storedLogoutConfirmationLifetime - time.Millisecond),
	}
	if _, err = builder.Build(context.Background(), expired); !errors.Is(err, ErrUpstreamArtifactRejected) {
		t.Fatalf("expired local confirmation accepted: %v", err)
	}
}

func TestStoredEndSessionBuilderRejectsNonCanonicalDeploymentRedirect(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	for _, redirect := range []string{
		"https://app.example/logout/callback",
		"https://app.example/signed-out?next=/admin",
		"https://app.example/signed-out#fragment",
		"http://app.example/signed-out",
		"https://attacker.example/signed-out/../signed-out",
	} {
		if _, err := newStoredEndSessionBuilder(
			fixture.flow.trust, redirect, &deterministicFlowReader{}, func() time.Time { return flowTestNow },
		); !errors.Is(err, ErrInvalidFlowOptions) {
			t.Fatalf("non-canonical redirect %q accepted: %v", redirect, err)
		}
	}
}

func TestStoredEndSessionBuilderUsesDatabaseObservedLogoutTimeAcrossClockSkew(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	provider := identity.ProviderContext{
		Scope: identity.PlatformProviderScope, ProviderID: testAuthorizationBegin(20).OperationRunID,
	}
	materialID := testAuthorizationBegin(21).OperationRunID
	sessionID := testAuthorizationBegin(22).OperationRunID
	builder, err := newStoredEndSessionBuilder(
		fixture.flow.trust, "https://app.example/signed-out", &deterministicFlowReader{},
		func() time.Time { return flowTestNow },
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []time.Duration{-299 * time.Second, 299 * time.Second} {
		confirmation := observedStoredLogoutConfirmation{
			storedLogoutConfirmationFixture: storedLogoutConfirmationFixture{
				provider: provider, material: materialID, session: sessionID,
				postLogoutRedirectURI: "https://historical.example/signed-out",
				revokedAt:             flowTestNow.Add(offset),
			},
			observedAt: flowTestNow.Add(offset),
		}
		artifact, buildErr := builder.Build(context.Background(), StoredEndSessionBuildRequest{
			Provider: provider, MaterialID: materialID, SessionID: sessionID,
			EndpointURL: testEndSession, PostLogoutRedirectURI: "https://historical.example/signed-out",
			IDTokenHint:  []byte("header.payload.signature"),
			Confirmation: confirmation,
		})
		if buildErr != nil {
			t.Fatalf("DB offset %s rejected: %v", offset, buildErr)
		}
		redirect, parseErr := url.Parse(artifact.RedirectURL())
		if parseErr != nil || redirect.Query().Get("post_logout_redirect_uri") != "https://historical.example/signed-out" {
			t.Fatalf("historical redirect at DB offset %s = %q, %v", offset, artifact.RedirectURL(), parseErr)
		}
		artifact.Destroy()
	}
}
