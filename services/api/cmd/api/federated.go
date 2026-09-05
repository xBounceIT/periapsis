package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/config"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/httpserver"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres"
	"github.com/periapsis-im/periapsis/services/api/internal/sessionlogout"
)

const (
	oidcCallbackPath                 = "/api/v1/auth/federated/oidc/callback"
	oidcPostLogoutRedirectPath       = "/signed-out"
	defaultSAMLTransactionTTL        = 5 * time.Minute
	defaultOIDCUserInfoResponseBytes = 64 * 1024
	defaultOIDCTokenResponseBytes    = 64 * 1024
	defaultLogoutContinuationTTL     = 2 * time.Minute
)

func configuredOIDCFlowPolicy(operationTimeout, clockSkew time.Duration) federatedoidc.FlowPolicy {
	policy := federatedoidc.DefaultFlowPolicy()
	policy.OperationTimeout = operationTimeout
	policy.ClockSkew = clockSkew
	return policy
}

func configuredTenantOIDCRedirects(publicOrigin string) (string, string) {
	return publicOrigin + oidcCallbackPath, publicOrigin + oidcPostLogoutRedirectPath
}

type federatedReadinessVerifier interface {
	Ready(context.Context) error
}

type federatedSessionRevalidator interface {
	RevalidateSession(context.Context, federatedauth.SessionLookup) (federatedauth.SessionResult, error)
}

type runtimeFederatedSessionAuthority struct {
	revalidator federatedSessionRevalidator
}

var _ authentication.FederatedSessionAuthority = (*runtimeFederatedSessionAuthority)(nil)

func (authority *runtimeFederatedSessionAuthority) RevalidateFederatedSession(
	ctx context.Context,
	lookup authentication.FederatedSessionAuthorityLookup,
) (authentication.FederatedSessionAuthorityResult, error) {
	if authority == nil || runtimeDependencyIsNil(authority.revalidator) || ctx == nil || ctx.Err() != nil ||
		!validRuntimeFederatedID(lookup.SessionID) || !validRuntimeFederatedID(lookup.TenantID) ||
		!validRuntimeFederatedID(lookup.UserID) ||
		(lookup.AuthenticationMethod != string(federatedauth.AuthenticationMethodOIDC) &&
			lookup.AuthenticationMethod != string(federatedauth.AuthenticationMethodSAML) &&
			lookup.AuthenticationMethod != string(federatedauth.AuthenticationMethodPasskey) &&
			lookup.AuthenticationMethod != string(federatedauth.AuthenticationMethodLDAP)) ||
		lookup.Audience != "api" {
		return authentication.FederatedSessionAuthorityResult{}, errors.New("federated session authority is unavailable")
	}
	result, err := authority.revalidator.RevalidateSession(ctx, federatedauth.SessionLookup{
		SessionID: identity.EntityID(lookup.SessionID), TenantID: identity.EntityID(lookup.TenantID),
		Audience: lookup.Audience, AuthenticationMethod: federatedauth.AuthenticationMethod(lookup.AuthenticationMethod),
	})
	if result.Credential != nil {
		defer result.Credential.Destroy()
	}
	if err != nil || ctx.Err() != nil || result.SessionID != identity.EntityID(lookup.SessionID) ||
		result.TenantID != identity.EntityID(lookup.TenantID) || result.UserID != identity.EntityID(lookup.UserID) ||
		string(result.AuthenticationMethod) != lookup.AuthenticationMethod {
		return authentication.FederatedSessionAuthorityResult{}, errors.New("federated session authority was rejected")
	}
	mapped := authentication.FederatedSessionAuthorityResult{
		SessionID: lookup.SessionID, TenantID: lookup.TenantID, UserID: lookup.UserID,
	}
	zero := identity.EntityID{}
	switch result.Decision {
	case mfa.SessionUsable:
		if result.Reason != mfa.SessionReasonCurrent || !result.AllowAuthority || !result.AllowIdleTouch ||
			result.NewSessionID != zero || result.ContinuationID != zero || !result.AbsoluteExpiresAt.IsZero() ||
			result.Credential != nil {
			return authentication.FederatedSessionAuthorityResult{}, errors.New("federated usable session result was malformed")
		}
		mapped.AllowAuthority = true
		mapped.AllowIdleTouch = true
		return mapped, nil
	case mfa.SessionRotate:
		if result.Reason != mfa.SessionReasonPolicyRefresh || result.AllowAuthority || result.AllowIdleTouch ||
			!validRuntimeFederatedID(uuid.UUID(result.NewSessionID)) ||
			uuid.UUID(result.NewSessionID) == lookup.SessionID || result.ContinuationID != zero ||
			result.AbsoluteExpiresAt.IsZero() || result.AbsoluteExpiresAt.Location() != time.UTC ||
			result.Credential == nil {
			return authentication.FederatedSessionAuthorityResult{}, errors.New("federated rotation result was malformed")
		}
		material, consumed := result.Credential.Consume()
		if !consumed {
			return authentication.FederatedSessionAuthorityResult{}, errors.New("federated rotation credential was unavailable")
		}
		defer material.Destroy()
		if material.Kind != federatedauth.BrowserCredentialSession ||
			material.SessionID != result.NewSessionID || material.ContinuationID != zero ||
			material.Authority != federatedauth.ContinuationAuthorityTenant ||
			!material.ExpiresAt.IsZero() || len(material.Receipt) != 0 {
			return authentication.FederatedSessionAuthorityResult{}, errors.New("federated rotation credential was malformed")
		}
		transition, transitionErr := authentication.NewFederatedSessionRotationTransition(
			lookup, uuid.UUID(result.NewSessionID), result.AbsoluteExpiresAt,
			material.SessionToken, material.CSRFToken,
		)
		if transitionErr != nil {
			return authentication.FederatedSessionAuthorityResult{}, errors.New("federated rotation credential was rejected")
		}
		mapped.Transition = transition
		return mapped, nil
	case mfa.SessionStepUp:
		if (result.Reason != mfa.SessionReasonAssuranceInsufficient &&
			result.Reason != mfa.SessionReasonRecoveryRestricted) ||
			result.AllowAuthority || result.AllowIdleTouch || result.NewSessionID != zero ||
			!validRuntimeFederatedID(uuid.UUID(result.ContinuationID)) ||
			uuid.UUID(result.ContinuationID) == lookup.SessionID || !result.AbsoluteExpiresAt.IsZero() ||
			result.Credential == nil {
			return authentication.FederatedSessionAuthorityResult{}, errors.New("federated step-up result was malformed")
		}
		material, consumed := result.Credential.Consume()
		if !consumed {
			return authentication.FederatedSessionAuthorityResult{}, errors.New("federated step-up credential was unavailable")
		}
		defer material.Destroy()
		if material.Kind != federatedauth.BrowserCredentialContinuation || material.SessionID != zero ||
			material.ContinuationID != result.ContinuationID || len(material.SessionToken) != 0 ||
			len(material.CSRFToken) != 0 ||
			material.Authority != federatedauth.ContinuationAuthorityTenant {
			return authentication.FederatedSessionAuthorityResult{}, errors.New("federated step-up credential was malformed")
		}
		transition, transitionErr := authentication.NewFederatedSessionStepUpTransition(
			lookup, uuid.UUID(result.ContinuationID), material.ExpiresAt, material.Receipt,
		)
		if transitionErr != nil {
			return authentication.FederatedSessionAuthorityResult{}, errors.New("federated step-up credential was rejected")
		}
		mapped.Transition = transition
		return mapped, nil
	case mfa.SessionRevoke:
		if !validRuntimeFederatedRevocationReason(result.Reason) || result.AllowAuthority || result.AllowIdleTouch ||
			result.NewSessionID != zero || result.ContinuationID != zero || !result.AbsoluteExpiresAt.IsZero() ||
			result.Credential != nil {
			return authentication.FederatedSessionAuthorityResult{}, errors.New("federated revocation result was malformed")
		}
		return mapped, nil
	case mfa.SessionDeny:
		if result.Reason != mfa.SessionReasonMalformed || result.AllowAuthority || result.AllowIdleTouch ||
			result.NewSessionID != zero || result.ContinuationID != zero || !result.AbsoluteExpiresAt.IsZero() ||
			result.Credential != nil {
			return authentication.FederatedSessionAuthorityResult{}, errors.New("federated denial result was malformed")
		}
		return mapped, nil
	default:
		return authentication.FederatedSessionAuthorityResult{}, errors.New("federated session decision was unsupported")
	}
}

func validRuntimeFederatedID(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validRuntimeFederatedRevocationReason(reason mfa.SessionReason) bool {
	switch reason {
	case mfa.SessionReasonLifecycle, mfa.SessionReasonIdentityEpoch, mfa.SessionReasonPrimaryDrift,
		mfa.SessionReasonFactorDrift, mfa.SessionReasonTrustDrift, mfa.SessionReasonExpired:
		return true
	default:
		return false
	}
}

type directPlatformOIDCSessionRevalidator interface {
	RevalidateDirectPlatformSession(
		context.Context,
		platformoidcauth.DirectSessionAuthorityLookup,
	) (platformoidcauth.DirectSessionAuthorityResult, error)
}

type directPlatformSAMLSessionRevalidator interface {
	RevalidateDirectPlatformSession(
		context.Context,
		platformsamlauth.DirectSAMLSessionAuthorityLookup,
	) (platformsamlauth.DirectSAMLSessionAuthorityOutcome, error)
}

type directPlatformLDAPSessionRevalidator interface {
	RevalidatePlatformLDAPSession(
		context.Context,
		uuid.UUID,
		uuid.UUID,
		string,
	) (postgres.PlatformLDAPSessionAuthorityResult, error)
}

// runtimeDirectPlatformSessionAuthority is the deny-by-default protocol
// dispatcher between the authentication-owned tenantless session boundary and
// each direct provider authority. A protocol implementation cannot receive or
// authorize another protocol's session lookup by structural coincidence.
type runtimeDirectPlatformSessionAuthority struct {
	oidc directPlatformOIDCSessionRevalidator
	saml directPlatformSAMLSessionRevalidator
	ldap directPlatformLDAPSessionRevalidator
}

var _ authentication.DirectPlatformSessionAuthority = (*runtimeDirectPlatformSessionAuthority)(nil)

func (authority *runtimeDirectPlatformSessionAuthority) RevalidateDirectPlatformSession(
	ctx context.Context,
	lookup authentication.DirectPlatformSessionAuthorityLookup,
) (authentication.DirectPlatformSessionAuthorityResult, error) {
	if authority == nil || ctx == nil || ctx.Err() != nil ||
		!validRuntimeFederatedID(lookup.SessionID) || !validRuntimeFederatedID(lookup.UserID) ||
		lookup.SessionID == lookup.UserID || lookup.Audience != "api" {
		return authentication.DirectPlatformSessionAuthorityResult{},
			errors.New("direct platform session authority is unavailable")
	}
	switch lookup.AuthenticationMethod {
	case "oidc":
		if runtimeDependencyIsNil(authority.oidc) {
			break
		}
		result, err := authority.oidc.RevalidateDirectPlatformSession(
			ctx,
			platformoidcauth.DirectSessionAuthorityLookup{
				SessionID: lookup.SessionID, UserID: lookup.UserID,
				AuthenticationMethod: lookup.AuthenticationMethod, Audience: lookup.Audience,
			},
		)
		if err != nil || ctx.Err() != nil || result.SessionID != lookup.SessionID || result.UserID != lookup.UserID {
			break
		}
		return authentication.DirectPlatformSessionAuthorityResult{
			SessionID: result.SessionID, UserID: result.UserID,
			AllowAuthority: result.AllowAuthority, AllowIdleTouch: result.AllowIdleTouch,
		}, nil
	case "saml":
		if runtimeDependencyIsNil(authority.saml) {
			break
		}
		return authority.revalidateDirectPlatformSAMLSession(ctx, lookup)
	case "ldap":
		if runtimeDependencyIsNil(authority.ldap) {
			break
		}
		result, err := authority.ldap.RevalidatePlatformLDAPSession(
			ctx, lookup.SessionID, lookup.UserID, "platform",
		)
		if err != nil || ctx.Err() != nil || result.SessionID != lookup.SessionID ||
			result.UserID != lookup.UserID {
			break
		}
		return authentication.DirectPlatformSessionAuthorityResult{
			SessionID: result.SessionID, UserID: result.UserID,
			AllowAuthority: result.Allowed, AllowIdleTouch: result.IdleTouchAllowed,
		}, nil
	default:
	}
	return authentication.DirectPlatformSessionAuthorityResult{},
		errors.New("direct platform session authority was rejected")
}

func (authority *runtimeDirectPlatformSessionAuthority) revalidateDirectPlatformSAMLSession(
	ctx context.Context,
	lookup authentication.DirectPlatformSessionAuthorityLookup,
) (authentication.DirectPlatformSessionAuthorityResult, error) {
	event, ok := authentication.EventContextFromContext(ctx)
	if !ok {
		return authentication.DirectPlatformSessionAuthorityResult{},
			errors.New("direct platform SAML session audit attribution is unavailable")
	}
	outcome, err := authority.saml.RevalidateDirectPlatformSession(
		ctx,
		platformsamlauth.DirectSAMLSessionAuthorityLookup{
			SessionID: identity.EntityID(lookup.SessionID), UserID: identity.EntityID(lookup.UserID),
			AuthenticationMethod: lookup.AuthenticationMethod, Audience: lookup.Audience,
			Audit: platformsamlauth.AuditContext{
				RequestID: identity.EntityID(event.RequestID), CorrelationID: identity.EntityID(event.CorrelationID),
				RemoteAddress: event.RemoteAddress, UserAgent: event.UserAgent,
			},
		},
	)
	if outcome.Credential != nil {
		defer outcome.Credential.Destroy()
	}
	if err != nil || ctx.Err() != nil || outcome.SessionID != identity.EntityID(lookup.SessionID) ||
		outcome.UserID != identity.EntityID(lookup.UserID) {
		compensateDirectPlatformSAMLDelivery(ctx, outcome.Delivery)
		return authentication.DirectPlatformSessionAuthorityResult{},
			errors.New("direct platform SAML session authority was rejected")
	}
	mapped := authentication.DirectPlatformSessionAuthorityResult{
		SessionID: lookup.SessionID, UserID: lookup.UserID,
	}
	zero := identity.EntityID{}
	switch outcome.Decision {
	case mfa.SessionUsable:
		if outcome.Reason != mfa.SessionReasonCurrent || !outcome.AllowAuthority || !outcome.AllowIdleTouch ||
			outcome.NewSessionID != zero || outcome.ContinuationID != zero || !outcome.ExpiresAt.IsZero() ||
			outcome.Credential != nil || outcome.Delivery != nil {
			compensateDirectPlatformSAMLDelivery(ctx, outcome.Delivery)
			return authentication.DirectPlatformSessionAuthorityResult{},
				errors.New("direct platform SAML usable outcome was malformed")
		}
		mapped.AllowAuthority = true
		mapped.AllowIdleTouch = true
		return mapped, nil
	case mfa.SessionRotate:
		if outcome.Reason != mfa.SessionReasonPolicyRefresh || outcome.AllowAuthority || outcome.AllowIdleTouch ||
			!validRuntimeFederatedID(uuid.UUID(outcome.NewSessionID)) ||
			uuid.UUID(outcome.NewSessionID) == lookup.SessionID || outcome.ContinuationID != zero ||
			outcome.ExpiresAt.IsZero() || outcome.ExpiresAt.Location() != time.UTC ||
			outcome.Credential == nil || outcome.Delivery == nil {
			compensateDirectPlatformSAMLDelivery(ctx, outcome.Delivery)
			return authentication.DirectPlatformSessionAuthorityResult{},
				errors.New("direct platform SAML rotation outcome was malformed")
		}
		material, consumed := outcome.Credential.Consume()
		if !consumed {
			compensateDirectPlatformSAMLDelivery(ctx, outcome.Delivery)
			return authentication.DirectPlatformSessionAuthorityResult{},
				errors.New("direct platform SAML rotation credential was unavailable")
		}
		defer material.Destroy()
		if material.Kind != platformsamlauth.BrowserSessionCredential ||
			material.SessionID != outcome.NewSessionID || material.ContinuationID != zero ||
			!material.ExpiresAt.IsZero() || len(material.Receipt) != 0 {
			compensateDirectPlatformSAMLDelivery(ctx, outcome.Delivery)
			return authentication.DirectPlatformSessionAuthorityResult{},
				errors.New("direct platform SAML rotation credential was malformed")
		}
		transition, transitionErr := authentication.NewDirectPlatformSessionRotationTransition(
			lookup, uuid.UUID(outcome.NewSessionID), outcome.ExpiresAt,
			material.SessionToken, material.CSRFToken, outcome.Delivery,
		)
		if transitionErr != nil {
			compensateDirectPlatformSAMLDelivery(ctx, outcome.Delivery)
			return authentication.DirectPlatformSessionAuthorityResult{},
				errors.New("direct platform SAML rotation credential was rejected")
		}
		mapped.Transition = transition
		return mapped, nil
	case mfa.SessionStepUp:
		if (outcome.Reason != mfa.SessionReasonAssuranceInsufficient &&
			outcome.Reason != mfa.SessionReasonRecoveryRestricted) ||
			outcome.AllowAuthority || outcome.AllowIdleTouch || outcome.NewSessionID != zero ||
			!validRuntimeFederatedID(uuid.UUID(outcome.ContinuationID)) ||
			uuid.UUID(outcome.ContinuationID) == lookup.SessionID || outcome.ExpiresAt.IsZero() ||
			outcome.ExpiresAt.Location() != time.UTC || outcome.Credential == nil || outcome.Delivery == nil {
			compensateDirectPlatformSAMLDelivery(ctx, outcome.Delivery)
			return authentication.DirectPlatformSessionAuthorityResult{},
				errors.New("direct platform SAML step-up outcome was malformed")
		}
		material, consumed := outcome.Credential.Consume()
		if !consumed {
			compensateDirectPlatformSAMLDelivery(ctx, outcome.Delivery)
			return authentication.DirectPlatformSessionAuthorityResult{},
				errors.New("direct platform SAML step-up credential was unavailable")
		}
		defer material.Destroy()
		if material.Kind != platformsamlauth.BrowserContinuationCredential || material.SessionID != zero ||
			material.ContinuationID != outcome.ContinuationID || !material.ExpiresAt.Equal(outcome.ExpiresAt) ||
			len(material.SessionToken) != 0 || len(material.CSRFToken) != 0 {
			compensateDirectPlatformSAMLDelivery(ctx, outcome.Delivery)
			return authentication.DirectPlatformSessionAuthorityResult{},
				errors.New("direct platform SAML step-up credential was malformed")
		}
		transition, transitionErr := authentication.NewDirectPlatformSessionStepUpTransition(
			lookup, uuid.UUID(outcome.ContinuationID), outcome.ExpiresAt, material.Receipt, outcome.Delivery,
		)
		if transitionErr != nil {
			compensateDirectPlatformSAMLDelivery(ctx, outcome.Delivery)
			return authentication.DirectPlatformSessionAuthorityResult{},
				errors.New("direct platform SAML step-up credential was rejected")
		}
		mapped.Transition = transition
		return mapped, nil
	case mfa.SessionRevoke, mfa.SessionDeny:
		// The application returns these decisions together with a non-oracular
		// denial error, so reaching this branch means its contract drifted.
		compensateDirectPlatformSAMLDelivery(ctx, outcome.Delivery)
		return authentication.DirectPlatformSessionAuthorityResult{},
			errors.New("direct platform SAML denial outcome was malformed")
	default:
		compensateDirectPlatformSAMLDelivery(ctx, outcome.Delivery)
		return authentication.DirectPlatformSessionAuthorityResult{},
			errors.New("direct platform SAML session decision was unsupported")
	}
}

func compensateDirectPlatformSAMLDelivery(
	ctx context.Context,
	delivery *platformsamlauth.DirectSAMLSessionDeliveryFinalizer,
) {
	if delivery != nil {
		_ = delivery.CompensateBrowserDelivery(ctx)
	}
}

type federatedRuntimeComposition struct {
	browser                  *httpserver.FederatedBrowserOptions
	platformOIDCBrowser      httpserver.PlatformOIDCBrowserAuthentication
	platformSAMLBrowser      httpserver.PlatformSAMLBrowserAuthentication
	platformSAMLContinuation httpserver.PlatformSAMLContinuationService
	sessionLogout            httpserver.SessionLogoutService
	httpClient               *federatedhttp.Client
	oidcTrust                *federatedoidc.Client
	readiness                federatedReadinessVerifier
	enabled                  bool
}

type federatedRuntimeReadiness struct {
	tenant     federatedReadinessVerifier
	directOIDC federatedReadinessVerifier
	directSAML federatedReadinessVerifier
}

func (readiness *federatedRuntimeReadiness) Ready(ctx context.Context) error {
	if readiness == nil || runtimeDependencyIsNil(readiness.tenant) ||
		runtimeDependencyIsNil(readiness.directOIDC) || runtimeDependencyIsNil(readiness.directSAML) ||
		ctx == nil || ctx.Err() != nil {
		return errors.New("federated runtime readiness is unavailable")
	}
	if err := readiness.tenant.Ready(ctx); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return errors.New("federated runtime readiness is unavailable")
	}
	if err := readiness.directOIDC.Ready(ctx); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return errors.New("federated runtime readiness is unavailable")
	}
	if err := readiness.directSAML.Ready(ctx); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return errors.New("federated runtime readiness is unavailable")
	}
	return nil
}

// newFederatedRuntimeComposition constructs one all-or-nothing federation
// graph. Development and test origins may intentionally remain HTTP; those
// deployments keep the routes fail-closed instead of weakening the hardened
// HTTPS callback and outbound-network boundary. Production configuration is
// always HTTPS and must compose successfully.
func newFederatedRuntimeComposition(
	pool *pgxpool.Pool,
	cfg *config.Config,
	authenticationService *authentication.Service,
) (federatedRuntimeComposition, error) {
	if cfg == nil {
		return federatedRuntimeComposition{}, errors.New("federated runtime configuration is required")
	}
	if !strings.HasPrefix(cfg.PublicOrigin, "https://") {
		if cfg.Environment == "production" {
			return federatedRuntimeComposition{}, errors.New("federated browser authentication requires an HTTPS public origin")
		}
		if pool == nil {
			return federatedRuntimeComposition{}, nil
		}
		localLogout, err := sessionlogout.New(sessionlogout.Options{
			Store: postgres.NewFederatedAuthRepository(pool), OperationTimeout: cfg.FederatedOperationTimeout,
			ContinuationTTL: defaultLogoutContinuationTTL,
		})
		if err != nil {
			return federatedRuntimeComposition{}, errors.New("initialize local session logout")
		}
		return federatedRuntimeComposition{sessionLogout: localLogout}, nil
	}
	if pool == nil || authenticationService == nil {
		return federatedRuntimeComposition{}, errors.New("federated runtime dependencies are required")
	}

	roots, err := federatedauth.LoadFederatedRootCAs(cfg.FederatedCABundleFile)
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("load federated root certificates")
	}
	httpClient, err := federatedauth.NewDeploymentHTTPClient(federatedauth.DeploymentHTTPOptions{
		Resolver:           net.DefaultResolver,
		Dialer:             &net.Dialer{},
		PrivateEgressCIDRs: cfg.FederatedPrivateEgressCIDRs,
		AllowedHTTPSPorts:  cfg.FederatedAllowedHTTPSPorts,
		RootCAs:            roots,
		OperationTimeout:   cfg.FederatedOperationTimeout,
		MaxConcurrent:      cfg.FederatedMaxConcurrent,
	})
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize federated HTTP boundary")
	}
	oidcLimits := federatedoidc.DefaultLimits()
	oidcTrust, err := federatedoidc.New(federatedoidc.Options{HTTP: httpClient, Limits: oidcLimits})
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize OIDC trust client")
	}
	oidcUpstream, err := federatedoidc.NewUpstreamHTTP(federatedoidc.UpstreamOptions{
		HTTP: httpClient, JSONLimits: oidcLimits,
		MaxUserInfoBytes: defaultOIDCUserInfoResponseBytes,
		MaxRefreshBytes:  defaultOIDCTokenResponseBytes,
	})
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize OIDC upstream client")
	}

	sessionProtector, err := federatedauth.NewIdentitySAMLSessionMaterialProtector(cfg.IdentityKeyring)
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize SAML session material protection")
	}
	repository := postgres.NewFederatedAuthRepositoryWithRuntimeDependencies(
		pool,
		sessionProtector,
		oidcTrust,
	)
	pkceProtector, err := federatedauth.NewIdentityPKCEVerifierProtector(cfg.IdentityKeyring)
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize OIDC PKCE protection")
	}
	interactiveClientSecrets, err := federatedauth.NewKeyringOIDCClientSecretSource(repository, cfg.IdentityKeyring)
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize OIDC client-secret source")
	}
	oidcPlanner, err := federatedauth.NewSharedFederatedPlanner(federatedauth.SharedFederatedPlannerOptions{
		Source: repository, Keyring: cfg.IdentityKeyring,
	})
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize OIDC mapping planner")
	}
	oidcAssurance, err := federatedauth.NewPinnedOIDCTrustResolver(repository)
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize OIDC assurance resolver")
	}
	oidcSessionProtector, err := federatedauth.NewIdentityOIDCSessionTokenProtector(cfg.IdentityKeyring)
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize OIDC session material protection")
	}
	oidcApplication, err := federatedauth.New(federatedauth.Options{
		Planner: oidcPlanner, OIDCTrust: oidcAssurance, Applier: repository,
		OIDCApplier: repository, OIDCSessionSealer: oidcSessionProtector,
		Credentials: authenticationService, Sessions: repository,
		OperationTimeout: cfg.FederatedOperationTimeout,
	})
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize OIDC authentication application")
	}

	samlKeyOpener, err := federatedauth.NewIdentitySAMLSPKeyEnvelopeOpener(cfg.IdentityKeyring)
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize SAML key protection")
	}
	samlKeySource, err := federatedauth.NewProtectedSAMLSPKeySource(repository, samlKeyOpener)
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize SAML key source")
	}
	samlCrypto, err := federatedsaml.NewLibraryCryptoAdapter(samlKeySource)
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize SAML cryptographic adapter")
	}
	samlPlanner, err := federatedauth.NewSAMLSharedFederatedPlanner(
		federatedauth.SAMLSharedFederatedPlannerOptions{Source: repository, Keyring: cfg.IdentityKeyring},
	)
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize SAML mapping planner")
	}
	samlApplication, err := federatedauth.NewSAMLApplication(federatedauth.SAMLApplicationOptions{
		Planner: samlPlanner, Applier: repository, Credentials: authenticationService,
		OperationTimeout: cfg.FederatedOperationTimeout,
	})
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize SAML authentication application")
	}

	oidcPolicy := configuredOIDCFlowPolicy(cfg.FederatedOperationTimeout, cfg.FederatedOIDCClockSkew)
	oidcRedirectURI, oidcPostLogoutRedirectURI := configuredTenantOIDCRedirects(cfg.PublicOrigin)
	runtime, err := federatedauth.NewRuntime(federatedauth.RuntimeOptions{
		Readiness: repository, Transactions: repository, Configurations: repository,
		OIDCTrust: oidcTrust, OIDCVerifierProtector: pkceProtector,
		OIDCTokenEndpoint:         oidcUpstream,
		OIDCRedirectURI:           oidcRedirectURI,
		OIDCPostLogoutRedirectURI: oidcPostLogoutRedirectURI,
		OIDCPolicy:                oidcPolicy, OIDCApplication: oidcApplication,
		OIDCClientSecrets: interactiveClientSecrets, OIDCUserInfo: oidcUpstream,
		SAMLRedirectSigner: samlCrypto, SAMLSignatureVerifier: samlCrypto,
		SAMLAssertionDecrypter: samlCrypto, SAMLSessionProtector: sessionProtector,
		SAMLApplication: samlApplication, SAMLLimits: federatedsaml.DefaultLimits(),
		SAMLTransactionTTL: defaultSAMLTransactionTTL,
		OperationTimeout:   cfg.FederatedOperationTimeout,
	})
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize federated authentication runtime")
	}
	browserAuthentication, err := httpserver.NewRuntimeFederatedAuthentication(runtime)
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize federated browser adapter")
	}
	oidcStartDigest, err := federatedauth.NewOIDCStartDigester(cfg.MasterKey)
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize OIDC start digester")
	}
	samlStartDigest, err := federatedauth.NewSAMLStartDigester(cfg.MasterKey)
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize SAML start digester")
	}
	tenantSAMLMetadata, err := httpserver.NewRuntimeTenantSAMLMetadata(repository, cfg.PublicOrigin)
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize tenant SAML public metadata")
	}
	directRuntime, err := newDirectPlatformOIDCRuntime(directPlatformOIDCRuntimeOptions{
		Repository: repository, Trust: oidcTrust, VerifierProtector: pkceProtector,
		TokenEndpoint: oidcUpstream, IdentityKeyring: cfg.IdentityKeyring,
		StartKey: cfg.MasterKey, Credentials: authenticationService,
		SessionSealer: oidcSessionProtector,
		TOTPVerifier:  authenticationService, PublicOrigin: cfg.PublicOrigin,
		Policy: oidcPolicy, OperationTimeout: cfg.FederatedOperationTimeout,
		ChallengeTTL: cfg.MFAChallengeTimeout, Now: time.Now,
	})
	if err != nil {
		return federatedRuntimeComposition{}, err
	}
	platformSAMLRepository, err := postgres.NewPlatformSAMLRepository(pool, cfg.PublicOrigin)
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize direct platform SAML public repository")
	}
	directSAMLRuntime, err := newDirectPlatformSAMLRuntime(directPlatformSAMLRuntimeOptions{
		Repository: repository, PublicRepository: platformSAMLRepository,
		SessionProtector: sessionProtector, IdentityKeyring: cfg.IdentityKeyring,
		StartKey: cfg.MasterKey, Credentials: authenticationService, TOTPVerifier: authenticationService,
		OperationTimeout: cfg.FederatedOperationTimeout, TransactionTTL: defaultSAMLTransactionTTL,
		ChallengeTTL: cfg.MFAChallengeTimeout, Now: time.Now,
	})
	if err != nil {
		return federatedRuntimeComposition{}, err
	}
	storedEndSession, err := federatedoidc.NewStoredEndSessionBuilder(oidcTrust, oidcPostLogoutRedirectURI)
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize OIDC end-session builder")
	}
	endSessionBuilder, err := sessionlogout.NewKernelEndSessionBuilder(storedEndSession)
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize OIDC logout adapter")
	}
	samlLogoutBuilder, err := sessionlogout.NewAuthoritySAMLLogoutBuilder(
		runtime.SAMLLogoutFlow(), directSAMLRuntime.logoutFlow,
	)
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize SAML logout adapter")
	}
	sessionLogoutService, err := sessionlogout.New(sessionlogout.Options{
		Store: repository, IDTokenOpener: oidcSessionProtector, EndSessionBuilder: endSessionBuilder,
		SAMLBuilder: samlLogoutBuilder, OperationTimeout: cfg.FederatedOperationTimeout,
		ContinuationTTL: defaultLogoutContinuationTTL,
	})
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize session logout")
	}
	directSessionAuthority, err := platformoidcauth.NewDirectPlatformSessionAuthority(
		platformoidcauth.DirectPlatformSessionAuthorityOptions{
			Store: repository, OperationTimeout: cfg.FederatedOperationTimeout,
		},
	)
	if err != nil {
		return federatedRuntimeComposition{}, errors.New("initialize direct platform OIDC session authority")
	}
	if err = authenticationService.BindDirectPlatformSessionAuthority(&runtimeDirectPlatformSessionAuthority{
		oidc: directSessionAuthority, saml: directSAMLRuntime.sessionAuthority, ldap: repository,
	}); err != nil {
		return federatedRuntimeComposition{}, errors.New("bind direct platform session authority")
	}
	if err = authenticationService.BindDirectPlatformTenantSwitcher(repository); err != nil {
		return federatedRuntimeComposition{}, errors.New("bind direct platform tenant switcher")
	}
	return federatedRuntimeComposition{
		browser: &httpserver.FederatedBrowserOptions{
			Authentication:  browserAuthentication,
			SAMLMetadata:    tenantSAMLMetadata,
			OIDCStartDigest: oidcStartDigest,
			SAMLStartDigest: samlStartDigest,
		},
		platformOIDCBrowser:      directRuntime,
		platformSAMLBrowser:      directSAMLRuntime.browser,
		platformSAMLContinuation: directSAMLRuntime.continuation,
		sessionLogout:            sessionLogoutService,
		httpClient:               httpClient,
		oidcTrust:                oidcTrust,
		readiness: &federatedRuntimeReadiness{
			tenant: browserAuthentication, directOIDC: directRuntime, directSAML: directSAMLRuntime.browser,
		},
		enabled: true,
	}, nil
}
