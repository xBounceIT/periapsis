package federatedoidc

import (
	"context"
	"crypto/rand"
	"io"
	"net/url"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

const storedLogoutConfirmationLifetime = 15 * time.Minute

type storedLocalLogoutObservation interface {
	LocalLogoutObservedAt() time.Time
}

// StoredLocalLogoutConfirmation is implemented by the application only from
// the result of the atomic local-revocation transaction. Matching every owner
// field prevents a confirmation for one session from authorizing another
// session's ID-token hint.
type StoredLocalLogoutConfirmation interface {
	OIDCProvider() identity.ProviderContext
	OIDCAdmission() identity.TenantAdmissionContext
	OIDCMaterialID() identity.EntityID
	OIDCPostLogoutRedirectURI() string
	LocalSessionID() identity.EntityID
	LocalSessionRevokedAt() time.Time
}

// StoredEndSessionBuildRequest contains material opened from one immutable
// session-material row only after local revocation committed. EndpointURL and
// IDTokenHint are deliberately excluded from routine formatting.
type StoredEndSessionBuildRequest struct {
	Provider              identity.ProviderContext
	Admission             identity.TenantAdmissionContext
	MaterialID            identity.EntityID
	SessionID             identity.EntityID
	EndpointURL           string `json:"-"`
	PostLogoutRedirectURI string `json:"-"`
	IDTokenHint           []byte `json:"-"`
	Confirmation          StoredLocalLogoutConfirmation
}

func (request StoredEndSessionBuildRequest) String() string {
	return "federatedoidc.StoredEndSessionBuildRequest{material:[REDACTED]}"
}

func (request StoredEndSessionBuildRequest) GoString() string { return request.String() }

// StoredEndSessionBuilder revalidates a persisted discovery endpoint through
// the deployment-owned federated HTTP policy and pins the post-logout target
// at construction. It never consults request Host or forwarded headers.
type StoredEndSessionBuilder struct {
	trust  *Client
	random io.Reader
	now    func() time.Time
}

func NewStoredEndSessionBuilder(
	trust *Client,
	postLogoutRedirectURI string,
) (*StoredEndSessionBuilder, error) {
	return newStoredEndSessionBuilder(trust, postLogoutRedirectURI, rand.Reader, func() time.Time {
		return time.Now().UTC().Truncate(time.Millisecond)
	})
}

func newStoredEndSessionBuilder(
	trust *Client,
	postLogoutRedirectURI string,
	random io.Reader,
	now func() time.Time,
) (*StoredEndSessionBuilder, error) {
	if trust == nil || trust.http == nil || random == nil || now == nil ||
		!validStoredPostLogoutRedirect(trust, postLogoutRedirectURI) {
		return nil, ErrInvalidFlowOptions
	}
	return &StoredEndSessionBuilder{
		trust: trust, random: random, now: now,
	}, nil
}

func (builder *StoredEndSessionBuilder) Build(
	ctx context.Context,
	request StoredEndSessionBuildRequest,
) (*EndSessionRequest, error) {
	if builder == nil || builder.trust == nil || builder.trust.http == nil ||
		ctx == nil || ctx.Err() != nil || !validStoredEndSessionRequest(request) ||
		!validStoredPostLogoutRedirect(builder.trust, request.PostLogoutRedirectURI) ||
		!builder.confirmedLocalLogout(request) {
		return nil, ErrUpstreamArtifactRejected
	}
	target, err := builder.trust.http.CompileTarget(
		federatedhttp.DocumentOIDCDiscovery,
		request.EndpointURL,
	)
	if err != nil {
		return nil, ErrUpstreamArtifactRejected
	}
	endpoint := newPinnedEndpoint(EndpointEndSession, request.EndpointURL, target)
	if !endpoint.validEndpoint(EndpointEndSession) {
		return nil, ErrUpstreamArtifactRejected
	}
	state, err := generateOpaque(builder.random)
	if err != nil {
		return nil, ErrUpstreamArtifactRejected
	}
	defer clear(state)
	now := builder.now()
	if !validFlowInstant(now) {
		return nil, ErrUpstreamArtifactRejected
	}
	parsed, err := url.Parse(endpoint.URL())
	if err != nil {
		return nil, ErrUpstreamArtifactRejected
	}
	query := parsed.Query()
	query.Set("id_token_hint", string(request.IDTokenHint))
	query.Set("post_logout_redirect_uri", request.PostLogoutRedirectURI)
	query.Set("state", string(state))
	parsed.RawQuery = query.Encode()
	redirectURL := parsed.String()
	if len(redirectURL) > maximumAuthorizationURLBytes {
		return nil, ErrUpstreamArtifactRejected
	}
	return &EndSessionRequest{
		endpoint: endpoint, idTokenHint: append([]byte(nil), request.IDTokenHint...),
		postLogoutRedirectURI: request.PostLogoutRedirectURI,
		state:                 append([]byte(nil), state...), createdAt: now, valid: true,
		redirectURL: redirectURL,
	}, nil
}

func (builder *StoredEndSessionBuilder) confirmedLocalLogout(
	request StoredEndSessionBuildRequest,
) bool {
	confirmation := request.Confirmation
	if confirmation == nil || confirmation.OIDCProvider() != request.Provider ||
		confirmation.OIDCAdmission() != request.Admission ||
		confirmation.OIDCMaterialID() != request.MaterialID ||
		confirmation.OIDCPostLogoutRedirectURI() != request.PostLogoutRedirectURI ||
		confirmation.LocalSessionID() != request.SessionID {
		return false
	}
	revokedAt := confirmation.LocalSessionRevokedAt()
	now := builder.now()
	observedAt := now
	if observation, ok := confirmation.(storedLocalLogoutObservation); ok {
		observedAt = observation.LocalLogoutObservedAt()
		if !validFlowInstant(observedAt) || observedAt.Before(now.Add(-5*time.Minute)) ||
			observedAt.After(now.Add(5*time.Minute)) {
			return false
		}
	}
	return validFlowInstant(revokedAt) && validFlowInstant(now) && validFlowInstant(observedAt) &&
		!revokedAt.After(observedAt) && observedAt.Sub(revokedAt) <= storedLogoutConfirmationLifetime
}

func validStoredPostLogoutRedirect(client *Client, raw string) bool {
	if raw == "" {
		return false
	}
	if _, err := client.http.CompileTarget(federatedhttp.DocumentOIDCDiscovery, raw); err != nil {
		return false
	}
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Path == "/signed-out" &&
		parsed.RawPath == "" && parsed.RawQuery == "" && !parsed.ForceQuery && parsed.Fragment == "" &&
		parsed.User == nil
}

func validStoredEndSessionRequest(request StoredEndSessionBuildRequest) bool {
	if request.EndpointURL == "" || len(request.IDTokenHint) == 0 ||
		!validTokenBytes(request.IDTokenHint, maximumCompactTokenBytes) ||
		request.MaterialID == (identity.EntityID{}) || request.SessionID == (identity.EntityID{}) ||
		request.Provider.ProviderID == (identity.EntityID{}) {
		return false
	}
	switch request.Provider.Scope {
	case identity.TenantProviderScope:
		return request.Provider.TenantID != (identity.EntityID{}) &&
			request.Admission.TenantID == request.Provider.TenantID &&
			request.Admission.BindingID != (identity.EntityID{})
	case identity.PlatformProviderScope:
		return request.Provider.TenantID == (identity.EntityID{}) &&
			(request.Admission == (identity.TenantAdmissionContext{}) ||
				request.Admission.TenantID != (identity.EntityID{}) &&
					request.Admission.BindingID != (identity.EntityID{}))
	default:
		return false
	}
}
