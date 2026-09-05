package sessionlogout

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

const (
	minimumOperationTimeout   = 100 * time.Millisecond
	maximumOperationTimeout   = 2 * time.Minute
	opaqueCredentialBytes     = 32
	minimumProtectedBytes     = 1 + 12 + 16
	maximumProtectedBytes     = 256*1024 + 12 + 16
	maximumContinuationTTL    = 2 * time.Minute
	minimumContinuationTTL    = 10 * time.Second
	maximumPersistentRevision = uint64(9_000_000_000_000_000)
)

var (
	ErrInvalidInput          = errors.New("session logout input is invalid")
	ErrInvalidAuthentication = errors.New("session logout authentication failed")
	ErrForbidden             = errors.New("session logout forbidden")
	ErrUnavailable           = errors.New("session logout unavailable")
	ErrNotFound              = errors.New("session logout credential not found")
)

type EventContext struct {
	RequestID     identity.EntityID
	CorrelationID identity.EntityID
	RemoteAddress netip.Addr
	UserAgent     string
}

type Credential struct {
	SessionID   identity.EntityID
	UserID      identity.EntityID
	TenantID    identity.EntityID
	TokenDigest [sha256.Size]byte
	CSRFDigest  [sha256.Size]byte
}

func (credential Credential) String() string {
	return fmt.Sprintf(
		"sessionlogout.Credential{session:%t,user:%t,tenant:%t,material:[REDACTED]}",
		credential.SessionID != (identity.EntityID{}), credential.UserID != (identity.EntityID{}),
		credential.TenantID != (identity.EntityID{}),
	)
}

func (credential Credential) GoString() string { return credential.String() }

type CredentialResolver interface {
	ResolveSessionForLogout(context.Context, [sha256.Size]byte) (Credential, error)
}

type LocalRevokeCommand struct {
	OperationRunID        identity.EntityID
	Credential            Credential
	RequestUpstream       bool
	RequestDigest         [sha256.Size]byte
	ContinuationID        identity.EntityID
	ContinuationDigest    [sha256.Size]byte
	ContinuationExpiresAt time.Time
	RequestedAt           time.Time
	Audit                 EventContext
}

func (command LocalRevokeCommand) String() string {
	return fmt.Sprintf(
		"sessionlogout.LocalRevokeCommand{operation:%t,credential:%q,upstream:%t,continuation:%t,digests:[REDACTED],requested:%t,audit:[REDACTED]}",
		command.OperationRunID != (identity.EntityID{}), command.Credential.String(), command.RequestUpstream,
		command.ContinuationID != (identity.EntityID{}), !command.RequestedAt.IsZero(),
	)
}

func (command LocalRevokeCommand) GoString() string { return command.String() }

type LocalRevokeCategory string

const (
	LocalOnly          LocalRevokeCategory = "revoked_local_only"
	LogoutContinuation LocalRevokeCategory = "logout_continuation"
)

// LocalRevokeSnapshot never contains an upstream URL or protected protocol
// material. Persistence creates the digest-only continuation atomically with
// local revocation and returns only this safe receipt.
type LocalRevokeSnapshot struct {
	Category              LocalRevokeCategory
	OperationRunID        identity.EntityID
	SessionID             identity.EntityID
	UserID                identity.EntityID
	TenantID              identity.EntityID
	PreviousVersion       uint64
	RequestedAt           time.Time
	ObservedAt            time.Time
	ContinuationID        identity.EntityID
	ContinuationExpiresAt time.Time
	RevokedAt             time.Time
}

func (snapshot LocalRevokeSnapshot) String() string {
	return fmt.Sprintf(
		"sessionlogout.LocalRevokeSnapshot{category:%s,operation:%t,session:%t,user:%t,tenant:%t,version:%t,requested:%t,observed:%t,continuation:%t,expires:%t,revoked:%t,material:[REDACTED]}",
		safeLocalCategory(snapshot.Category), snapshot.OperationRunID != (identity.EntityID{}),
		snapshot.SessionID != (identity.EntityID{}), snapshot.UserID != (identity.EntityID{}),
		snapshot.TenantID != (identity.EntityID{}), snapshot.PreviousVersion > 0,
		!snapshot.RequestedAt.IsZero(), !snapshot.ObservedAt.IsZero(),
		snapshot.ContinuationID != (identity.EntityID{}), !snapshot.ContinuationExpiresAt.IsZero(),
		!snapshot.RevokedAt.IsZero(),
	)
}

func (snapshot LocalRevokeSnapshot) GoString() string { return snapshot.String() }

type ContinuationClaim struct {
	ContinuationID     identity.EntityID
	ContinuationDigest [sha256.Size]byte
	ClaimedAt          time.Time
}

func (claim ContinuationClaim) String() string {
	return fmt.Sprintf(
		"sessionlogout.ContinuationClaim{continuation:%t,digest:[REDACTED],claimed:%t}",
		claim.ContinuationID != (identity.EntityID{}), !claim.ClaimedAt.IsZero(),
	)
}

func (claim ContinuationClaim) GoString() string { return claim.String() }

type ClaimCategory string

const (
	ClaimGone ClaimCategory = "gone"
	ClaimOIDC ClaimCategory = "oidc_end_session"
	ClaimSAML ClaimCategory = "saml_logout"
)

// ContinuationSnapshot is a one-use server-side claim. Protected material is
// returned only after the digest is consumed and is cleared by the service.
// It is never copied into the DELETE response, JavaScript, audit, or ledger.
type ContinuationSnapshot struct {
	Category           ClaimCategory
	RequestedClaimedAt time.Time
	ObservedAt         time.Time
	ContinuationID     identity.EntityID
	OperationRunID     identity.EntityID
	SessionID          identity.EntityID
	UserID             identity.EntityID
	TenantID           identity.EntityID
	PreviousVersion    uint64
	Provider           identity.ProviderContext
	Admission          identity.TenantAdmissionContext
	BindingID          identity.EntityID
	MaterialID         identity.EntityID
	RevokedAt          time.Time
	ExpiresAt          time.Time

	EndSessionEndpoint    string
	ProtectedIDToken      federatedauth.ProtectedToken
	IDTokenDigest         [sha256.Size]byte
	MaterialExpiresAt     time.Time
	PostLogoutRedirectURI string

	SAMLConfiguration federatedsaml.StoredLogoutConfiguration
	ProtectedSAML     federatedsaml.ProtectedSessionMaterial
}

func (snapshot ContinuationSnapshot) String() string {
	return fmt.Sprintf(
		"sessionlogout.ContinuationSnapshot{category:%s,continuation:%t,operation:%t,session:%t,user:%t,tenant:%t,version:%t,provider:%t,binding:%t,material:%t,revoked:%t,expires:%t,oidc:%t,saml:%t,material:[REDACTED]}",
		safeClaimCategory(snapshot.Category), snapshot.ContinuationID != (identity.EntityID{}),
		snapshot.OperationRunID != (identity.EntityID{}),
		snapshot.SessionID != (identity.EntityID{}), snapshot.UserID != (identity.EntityID{}),
		snapshot.TenantID != (identity.EntityID{}), snapshot.PreviousVersion > 0,
		snapshot.Provider.ProviderID != (identity.EntityID{}),
		snapshot.BindingID != (identity.EntityID{}), snapshot.MaterialID != (identity.EntityID{}),
		!snapshot.RevokedAt.IsZero(), !snapshot.ExpiresAt.IsZero(),
		len(snapshot.ProtectedIDToken.Ciphertext) != 0, len(snapshot.ProtectedSAML.Ciphertext) != 0,
	)
}

func (snapshot ContinuationSnapshot) GoString() string { return snapshot.String() }

type Store interface {
	CredentialResolver
	RevokeLocalSession(context.Context, LocalRevokeCommand) (LocalRevokeSnapshot, error)
	ClaimLogoutContinuation(context.Context, ContinuationClaim) (ContinuationSnapshot, error)
}

type EndSessionBuilder interface {
	BuildEndSession(context.Context, federatedoidc.StoredEndSessionBuildRequest) (string, error)
}

type SAMLLogoutFlow interface {
	BuildStoredLogoutRequest(context.Context, federatedsaml.StoredLogoutBuildRequest) (federatedsaml.LogoutRequest, error)
}

type SAMLLogoutBuilder interface {
	BuildSAMLLogout(context.Context, federatedsaml.StoredLogoutBuildRequest) (string, error)
}

type KernelSAMLLogoutBuilder struct{ flow SAMLLogoutFlow }

func NewKernelSAMLLogoutBuilder(flow SAMLLogoutFlow) (*KernelSAMLLogoutBuilder, error) {
	if flow == nil {
		return nil, ErrInvalidInput
	}
	return &KernelSAMLLogoutBuilder{flow: flow}, nil
}

func (builder *KernelSAMLLogoutBuilder) BuildSAMLLogout(
	ctx context.Context,
	request federatedsaml.StoredLogoutBuildRequest,
) (string, error) {
	if builder == nil || builder.flow == nil {
		return "", ErrUnavailable
	}
	artifact, err := builder.flow.BuildStoredLogoutRequest(ctx, request)
	if err != nil {
		return "", err
	}
	if artifact.RedirectURL() == "" {
		return "", ErrUnavailable
	}
	return artifact.RedirectURL(), nil
}

// AuthoritySAMLLogoutBuilder preserves the hard separation between tenant
// and direct-platform SAML key sources while presenting one protocol-neutral
// continuation capability to the HTTP logout service.
type AuthoritySAMLLogoutBuilder struct {
	tenant SAMLLogoutFlow
	direct SAMLLogoutFlow
}

func NewAuthoritySAMLLogoutBuilder(
	tenant SAMLLogoutFlow,
	direct SAMLLogoutFlow,
) (*AuthoritySAMLLogoutBuilder, error) {
	if tenant == nil || direct == nil {
		return nil, ErrInvalidInput
	}
	return &AuthoritySAMLLogoutBuilder{tenant: tenant, direct: direct}, nil
}

func (builder *AuthoritySAMLLogoutBuilder) BuildSAMLLogout(
	ctx context.Context,
	request federatedsaml.StoredLogoutBuildRequest,
) (string, error) {
	if builder == nil || builder.tenant == nil || builder.direct == nil || ctx == nil || ctx.Err() != nil {
		return "", ErrUnavailable
	}
	var flow SAMLLogoutFlow
	switch request.Configuration.Authority {
	case federatedsaml.TenantCeremonyAuthority:
		flow = builder.tenant
	case federatedsaml.DirectPlatformCeremonyAuthority:
		flow = builder.direct
	default:
		return "", ErrUnavailable
	}
	artifact, err := flow.BuildStoredLogoutRequest(ctx, request)
	if err != nil || artifact.RedirectURL() == "" {
		return "", ErrUnavailable
	}
	return artifact.RedirectURL(), nil
}

type KernelEndSessionBuilder struct {
	builder *federatedoidc.StoredEndSessionBuilder
}

func NewKernelEndSessionBuilder(builder *federatedoidc.StoredEndSessionBuilder) (*KernelEndSessionBuilder, error) {
	if builder == nil {
		return nil, ErrInvalidInput
	}
	return &KernelEndSessionBuilder{builder: builder}, nil
}

func (builder *KernelEndSessionBuilder) BuildEndSession(
	ctx context.Context,
	request federatedoidc.StoredEndSessionBuildRequest,
) (string, error) {
	if builder == nil || builder.builder == nil {
		return "", ErrUnavailable
	}
	artifact, err := builder.builder.Build(ctx, request)
	if err != nil || artifact == nil {
		return "", ErrUnavailable
	}
	defer artifact.Destroy()
	redirect := artifact.RedirectURL()
	if redirect == "" {
		return "", ErrUnavailable
	}
	return redirect, nil
}

type browserContinuationState struct {
	mu         sync.Mutex
	id         identity.EntityID
	credential []byte
	expiresAt  time.Time
	lifetime   time.Duration
	consumed   bool
}

// BrowserContinuation is a shared, one-use owner for the HttpOnly cookie
// credential. The response URL contains only ID; JavaScript never sees the
// credential used by Continue.
type BrowserContinuation struct{ state *browserContinuationState }

// NewBrowserContinuation copies a validated browser credential into a one-use
// owner. It is exported so transports and contract tests can restore the safe
// receipt without exposing mutable state or serializing the credential.
func NewBrowserContinuation(
	id identity.EntityID,
	credential []byte,
	expiresAt time.Time,
) (*BrowserContinuation, error) {
	if !validEntityID(id) || !validOpaqueBytes(credential) || !validInstant(expiresAt) {
		return nil, ErrInvalidInput
	}
	owned := append([]byte(nil), credential...)
	return &BrowserContinuation{state: &browserContinuationState{
		id: id, credential: owned, expiresAt: expiresAt,
	}}, nil
}

// NewBrowserContinuationAt preserves the database-authoritative lifetime
// separately from its absolute timestamps. The HTTP transport can therefore
// issue a bounded cookie even when the application and database clocks differ.
func NewBrowserContinuationAt(
	id identity.EntityID,
	credential []byte,
	observedAt time.Time,
	expiresAt time.Time,
) (*BrowserContinuation, error) {
	lifetime := expiresAt.Sub(observedAt)
	if !validInstant(observedAt) || !validInstant(expiresAt) ||
		lifetime < minimumContinuationTTL || lifetime > maximumContinuationTTL {
		return nil, ErrInvalidInput
	}
	continuation, err := NewBrowserContinuation(id, credential, expiresAt)
	if err != nil {
		return nil, err
	}
	continuation.state.lifetime = lifetime
	return continuation, nil
}

func (continuation *BrowserContinuation) Take() (identity.EntityID, []byte, time.Time, bool) {
	id, credential, expiresAt, _, ok := continuation.TakeWithLifetime()
	return id, credential, expiresAt, ok
}

// TakeWithLifetime transfers the one-use credential together with the
// database-authoritative lifetime. A zero lifetime is returned only for the
// compatibility constructor, whose caller must apply its own strict bound.
func (continuation *BrowserContinuation) TakeWithLifetime() (
	identity.EntityID,
	[]byte,
	time.Time,
	time.Duration,
	bool,
) {
	if continuation == nil || continuation.state == nil {
		return identity.EntityID{}, nil, time.Time{}, 0, false
	}
	continuation.state.mu.Lock()
	defer continuation.state.mu.Unlock()
	if continuation.state.consumed || !validEntityID(continuation.state.id) ||
		!validOpaqueBytes(continuation.state.credential) || !validInstant(continuation.state.expiresAt) {
		continuation.destroyLocked()
		return identity.EntityID{}, nil, time.Time{}, 0, false
	}
	id := continuation.state.id
	credential := continuation.state.credential
	expiresAt := continuation.state.expiresAt
	lifetime := continuation.state.lifetime
	continuation.state.credential = nil
	continuation.state.consumed = true
	return id, credential, expiresAt, lifetime, true
}

func (continuation *BrowserContinuation) Destroy() {
	if continuation == nil || continuation.state == nil {
		return
	}
	continuation.state.mu.Lock()
	defer continuation.state.mu.Unlock()
	continuation.destroyLocked()
}

func (continuation *BrowserContinuation) destroyLocked() {
	clear(continuation.state.credential)
	continuation.state.credential = nil
	continuation.state.consumed = true
}

func (continuation BrowserContinuation) String() string {
	return "sessionlogout.BrowserContinuation{material:[REDACTED]}"
}

func (continuation BrowserContinuation) GoString() string { return continuation.String() }

type Result struct {
	LocalRevoked bool
	Continuation *BrowserContinuation `json:"-"`
}

func (result Result) String() string {
	return fmt.Sprintf(
		"sessionlogout.Result{local_revoked:%t,continuation:%t,material:[REDACTED]}",
		result.LocalRevoked, result.Continuation != nil,
	)
}

func (result Result) GoString() string { return result.String() }

type Options struct {
	Store             Store
	IDTokenOpener     federatedauth.OIDCSessionTokenOpener
	EndSessionBuilder EndSessionBuilder
	SAMLBuilder       SAMLLogoutBuilder
	OperationTimeout  time.Duration
	ContinuationTTL   time.Duration
	Now               func() time.Time
	NewID             func() (identity.EntityID, error)
	Random            io.Reader
}

type Service struct {
	store             Store
	idTokenOpener     federatedauth.OIDCSessionTokenOpener
	endSessionBuilder EndSessionBuilder
	samlBuilder       SAMLLogoutBuilder
	operationTimeout  time.Duration
	continuationTTL   time.Duration
	now               func() time.Time
	newID             func() (identity.EntityID, error)
	random            io.Reader
}

func New(options Options) (*Service, error) {
	if options.Store == nil || options.OperationTimeout < minimumOperationTimeout ||
		options.OperationTimeout > maximumOperationTimeout || options.OperationTimeout%time.Microsecond != 0 ||
		options.ContinuationTTL < minimumContinuationTTL || options.ContinuationTTL > maximumContinuationTTL ||
		(options.IDTokenOpener == nil) != (options.EndSessionBuilder == nil) {
		return nil, ErrInvalidInput
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.NewID == nil {
		options.NewID = func() (identity.EntityID, error) {
			value, err := uuid.NewV7()
			return identity.EntityID(value), err
		}
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	return &Service{
		store: options.Store, idTokenOpener: options.IDTokenOpener,
		endSessionBuilder: options.EndSessionBuilder, samlBuilder: options.SAMLBuilder,
		operationTimeout: options.OperationTimeout, continuationTTL: options.ContinuationTTL,
		now: options.Now, newID: options.NewID, random: options.Random,
	}, nil
}

// Logout proves possession directly against the immutable session credential,
// without resolving live user, tenant, membership, provider, or expiry
// authority. Local revocation and a digest-only continuation are one commit.
func (service *Service) Logout(
	ctx context.Context,
	sessionToken string,
	csrfToken string,
	event EventContext,
) (Result, error) {
	if service == nil || service.store == nil || !validOpaque(sessionToken) || !validOpaque(csrfToken) ||
		!validEvent(event) || ctx == nil || ctx.Err() != nil {
		return Result{}, ErrInvalidAuthentication
	}
	operation, cancel := context.WithTimeout(ctx, service.operationTimeout)
	defer cancel()
	tokenDigest := sha256.Sum256([]byte(sessionToken))
	defer clear(tokenDigest[:])
	credential, err := service.store.ResolveSessionForLogout(operation, tokenDigest)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Result{}, ErrInvalidAuthentication
		}
		return Result{}, ErrUnavailable
	}
	if !validCredential(credential) ||
		subtle.ConstantTimeCompare(credential.TokenDigest[:], tokenDigest[:]) != 1 {
		return Result{}, ErrUnavailable
	}
	csrfDigest := sha256.Sum256([]byte(csrfToken))
	defer clear(csrfDigest[:])
	if subtle.ConstantTimeCompare(credential.CSRFDigest[:], csrfDigest[:]) != 1 {
		return Result{}, ErrForbidden
	}
	operationID, err := service.newID()
	if err != nil || !validEntityID(operationID) {
		return Result{}, ErrUnavailable
	}
	continuationID, err := service.newID()
	if err != nil || !validEntityID(continuationID) || continuationID == operationID {
		return Result{}, ErrUnavailable
	}
	continuationCredential, err := newOpaque(service.random)
	if err != nil {
		return Result{}, ErrUnavailable
	}
	defer clear(continuationCredential)
	now := service.currentTime()
	if !validInstant(now) {
		return Result{}, ErrUnavailable
	}
	expiresAt := now.Add(service.continuationTTL)
	command := LocalRevokeCommand{
		OperationRunID: operationID, Credential: credential, RequestUpstream: true,
		ContinuationID:     continuationID,
		ContinuationDigest: sha256.Sum256(continuationCredential), ContinuationExpiresAt: expiresAt,
		RequestedAt: now, Audit: event,
	}
	command.RequestDigest = localRevokeDigest(command)
	snapshot, err := service.store.RevokeLocalSession(operation, command)
	if err != nil || !validLocalSnapshot(snapshot, command, now) {
		return Result{}, ErrUnavailable
	}
	result := Result{LocalRevoked: true}
	if snapshot.Category == LocalOnly {
		return result, nil
	}
	result.Continuation, err = NewBrowserContinuationAt(
		snapshot.ContinuationID,
		continuationCredential,
		snapshot.ObservedAt,
		snapshot.ContinuationExpiresAt,
	)
	if err != nil {
		return Result{}, ErrUnavailable
	}
	return result, nil
}

// Continue consumes the cookie proof before opening any protocol material.
// The returned URL is for a server-side 303 Location only and must never be
// serialized into a response body or exposed to JavaScript.
func (service *Service) Continue(
	ctx context.Context,
	continuationID identity.EntityID,
	credential []byte,
) (string, error) {
	if service == nil || service.store == nil || ctx == nil || ctx.Err() != nil ||
		!validEntityID(continuationID) || !validOpaqueBytes(credential) {
		return "", ErrInvalidAuthentication
	}
	operation, cancel := context.WithTimeout(ctx, service.operationTimeout)
	defer cancel()
	now := service.currentTime()
	claim := ContinuationClaim{
		ContinuationID: continuationID, ContinuationDigest: sha256.Sum256(credential), ClaimedAt: now,
	}
	snapshot, err := service.store.ClaimLogoutContinuation(operation, claim)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return "", nil
		}
		return "", ErrUnavailable
	}
	defer clearContinuationSnapshot(&snapshot)
	if snapshot.Category == ClaimGone {
		return "", nil
	}
	if !validClaimSnapshot(snapshot, claim, now) {
		return "", ErrUnavailable
	}
	switch snapshot.Category {
	case ClaimOIDC:
		return service.buildOIDCRedirect(operation, snapshot)
	case ClaimSAML:
		return service.buildSAMLRedirect(operation, snapshot)
	default:
		return "", ErrUnavailable
	}
}

func (service *Service) buildOIDCRedirect(
	ctx context.Context,
	snapshot ContinuationSnapshot,
) (string, error) {
	if service.idTokenOpener == nil || service.endSessionBuilder == nil {
		return "", nil
	}
	protection := federatedauth.OIDCSessionMaterialSealContext{
		Provider: snapshot.Provider, Admission: snapshot.Admission,
		MaterialID: snapshot.MaterialID, KeepIDToken: true,
	}
	idToken, err := service.idTokenOpener.OpenOIDCIDToken(ctx, protection, snapshot.ProtectedIDToken)
	if err != nil || len(idToken) == 0 {
		clear(idToken)
		return "", nil
	}
	defer clear(idToken)
	digest := sha256.Sum256(idToken)
	defer clear(digest[:])
	if subtle.ConstantTimeCompare(digest[:], snapshot.IDTokenDigest[:]) != 1 {
		return "", nil
	}
	request := federatedoidc.StoredEndSessionBuildRequest{
		Provider: snapshot.Provider, Admission: snapshot.Admission, MaterialID: snapshot.MaterialID,
		SessionID: snapshot.SessionID, EndpointURL: snapshot.EndSessionEndpoint,
		PostLogoutRedirectURI: snapshot.PostLogoutRedirectURI,
		IDTokenHint:           append([]byte(nil), idToken...), Confirmation: oidcLocalConfirmation{snapshot: snapshot},
	}
	defer clear(request.IDTokenHint)
	redirect, err := service.endSessionBuilder.BuildEndSession(ctx, request)
	if err != nil {
		return "", nil
	}
	return redirect, nil
}

func (service *Service) buildSAMLRedirect(
	ctx context.Context,
	snapshot ContinuationSnapshot,
) (string, error) {
	if service.samlBuilder == nil {
		return "", nil
	}
	request := federatedsaml.StoredLogoutBuildRequest{
		Configuration: snapshot.SAMLConfiguration, SessionID: snapshot.SessionID,
		MaterialID: snapshot.MaterialID,
		ProtectedMaterial: federatedsaml.ProtectedSessionMaterial{
			KeyVersion: snapshot.ProtectedSAML.KeyVersion,
			Ciphertext: append([]byte(nil), snapshot.ProtectedSAML.Ciphertext...),
		},
		Confirmation: samlLocalConfirmation{snapshot: snapshot},
	}
	defer clear(request.ProtectedMaterial.Ciphertext)
	redirect, err := service.samlBuilder.BuildSAMLLogout(ctx, request)
	if err != nil {
		return "", nil
	}
	if redirect == "" {
		return "", nil
	}
	return redirect, nil
}

type oidcLocalConfirmation struct{ snapshot ContinuationSnapshot }

func (confirmation oidcLocalConfirmation) OIDCProvider() identity.ProviderContext {
	return confirmation.snapshot.Provider
}
func (confirmation oidcLocalConfirmation) OIDCAdmission() identity.TenantAdmissionContext {
	return confirmation.snapshot.Admission
}
func (confirmation oidcLocalConfirmation) OIDCMaterialID() identity.EntityID {
	return confirmation.snapshot.MaterialID
}
func (confirmation oidcLocalConfirmation) OIDCPostLogoutRedirectURI() string {
	return confirmation.snapshot.PostLogoutRedirectURI
}
func (confirmation oidcLocalConfirmation) LocalSessionID() identity.EntityID {
	return confirmation.snapshot.SessionID
}
func (confirmation oidcLocalConfirmation) LocalSessionRevokedAt() time.Time {
	return confirmation.snapshot.RevokedAt
}
func (confirmation oidcLocalConfirmation) LocalLogoutObservedAt() time.Time {
	return confirmation.snapshot.ObservedAt
}

type samlLocalConfirmation struct{ snapshot ContinuationSnapshot }

func (confirmation samlLocalConfirmation) SAMLProvider() identity.ProviderContext {
	return confirmation.snapshot.Provider
}
func (confirmation samlLocalConfirmation) SAMLBindingID() identity.EntityID {
	return confirmation.snapshot.BindingID
}
func (confirmation samlLocalConfirmation) LocalSessionID() identity.EntityID {
	return confirmation.snapshot.SessionID
}
func (confirmation samlLocalConfirmation) LocalSessionRevokedAt() time.Time {
	return confirmation.snapshot.RevokedAt
}
func (confirmation samlLocalConfirmation) LocalLogoutObservedAt() time.Time {
	return confirmation.snapshot.ObservedAt
}

func (service *Service) currentTime() time.Time {
	return service.now().UTC().Truncate(time.Microsecond)
}

func localRevokeDigest(command LocalRevokeCommand) [sha256.Size]byte {
	document := make([]byte, 0, 256)
	document = append(document, "periapsis/session-logout/v2"...)
	document = append(document, command.OperationRunID[:]...)
	document = append(document, command.Credential.SessionID[:]...)
	document = append(document, command.Credential.UserID[:]...)
	document = append(document, command.Credential.TenantID[:]...)
	document = append(document, command.Credential.TokenDigest[:]...)
	document = append(document, command.ContinuationID[:]...)
	document = append(document, command.ContinuationDigest[:]...)
	document = append(document, []byte(command.ContinuationExpiresAt.Format(time.RFC3339Nano))...)
	if command.RequestUpstream {
		document = append(document, 1)
	} else {
		document = append(document, 0)
	}
	document = append(document, command.Audit.RequestID[:]...)
	document = append(document, command.Audit.CorrelationID[:]...)
	digest := sha256.Sum256(document)
	clear(document)
	return digest
}

func validCredential(value Credential) bool {
	return validEntityID(value.SessionID) && validEntityID(value.UserID) &&
		(value.TenantID == (identity.EntityID{}) || validEntityID(value.TenantID)) &&
		value.TokenDigest != ([sha256.Size]byte{}) && value.CSRFDigest != ([sha256.Size]byte{}) &&
		value.SessionID != value.UserID && value.SessionID != value.TenantID && value.UserID != value.TenantID
}

func validLocalSnapshot(value LocalRevokeSnapshot, command LocalRevokeCommand, now time.Time) bool {
	continuationTTL := command.ContinuationExpiresAt.Sub(command.RequestedAt)
	if value.OperationRunID != command.OperationRunID || value.SessionID != command.Credential.SessionID ||
		value.UserID != command.Credential.UserID || value.TenantID != command.Credential.TenantID ||
		value.PreviousVersion == 0 || value.PreviousVersion > maximumPersistentRevision ||
		!validInstant(value.RequestedAt) || !value.RequestedAt.Equal(command.RequestedAt) ||
		!validInstant(value.ObservedAt) || value.ObservedAt.Before(command.RequestedAt.Add(-5*time.Minute)) ||
		value.ObservedAt.After(command.RequestedAt.Add(5*time.Minute)) ||
		!validInstant(value.RevokedAt) || value.RevokedAt.After(value.ObservedAt) ||
		continuationTTL < minimumContinuationTTL || continuationTTL > maximumContinuationTTL {
		return false
	}
	switch value.Category {
	case LocalOnly:
		return value.ContinuationID == (identity.EntityID{}) && value.ContinuationExpiresAt.IsZero()
	case LogoutContinuation:
		return value.ContinuationID == command.ContinuationID &&
			value.ContinuationExpiresAt.Equal(value.ObservedAt.Add(continuationTTL)) &&
			value.ContinuationExpiresAt.After(value.ObservedAt) &&
			!value.ContinuationExpiresAt.After(value.ObservedAt.Add(maximumContinuationTTL))
	default:
		return false
	}
}

func validClaimSnapshot(value ContinuationSnapshot, claim ContinuationClaim, now time.Time) bool {
	if value.ContinuationID != claim.ContinuationID || !validEntityID(value.OperationRunID) ||
		!validEntityID(value.SessionID) ||
		!validEntityID(value.UserID) || (value.TenantID != (identity.EntityID{}) && !validEntityID(value.TenantID)) ||
		value.PreviousVersion == 0 || value.PreviousVersion > maximumPersistentRevision ||
		!validInstant(value.RequestedClaimedAt) || !value.RequestedClaimedAt.Equal(claim.ClaimedAt) ||
		!validInstant(value.ObservedAt) || value.ObservedAt.Before(claim.ClaimedAt.Add(-5*time.Minute)) ||
		value.ObservedAt.After(claim.ClaimedAt.Add(5*time.Minute)) ||
		!validInstant(value.RevokedAt) || value.RevokedAt.After(value.ObservedAt) || !validInstant(value.ExpiresAt) ||
		!value.ExpiresAt.After(value.ObservedAt) || value.ExpiresAt.After(value.ObservedAt.Add(maximumContinuationTTL)) ||
		!validEntityID(value.Provider.ProviderID) || !validEntityID(value.MaterialID) {
		return false
	}
	switch value.Category {
	case ClaimOIDC:
		return validOIDCClaim(value, value.ObservedAt)
	case ClaimSAML:
		return validSAMLClaim(value)
	default:
		return false
	}
}

func validOIDCClaim(value ContinuationSnapshot, now time.Time) bool {
	if value.BindingID != (identity.EntityID{}) || value.EndSessionEndpoint == "" ||
		value.PostLogoutRedirectURI == "" ||
		value.ProtectedIDToken.KeyVersion == 0 ||
		len(value.ProtectedIDToken.Ciphertext) < minimumProtectedBytes ||
		len(value.ProtectedIDToken.Ciphertext) > maximumProtectedBytes ||
		value.IDTokenDigest == ([sha256.Size]byte{}) || !validInstant(value.MaterialExpiresAt) ||
		!value.MaterialExpiresAt.After(now) || value.ProtectedSAML.KeyVersion != 0 ||
		len(value.ProtectedSAML.Ciphertext) != 0 {
		return false
	}
	return validOIDCScope(value)
}

func validOIDCScope(value ContinuationSnapshot) bool {
	switch value.Provider.Scope {
	case identity.TenantProviderScope:
		return value.TenantID != (identity.EntityID{}) && value.Provider.TenantID == value.TenantID &&
			value.Admission.TenantID == value.TenantID && validEntityID(value.Admission.BindingID)
	case identity.PlatformProviderScope:
		if value.Provider.TenantID != (identity.EntityID{}) {
			return false
		}
		if value.Admission == (identity.TenantAdmissionContext{}) {
			// Direct-platform OIDC material keeps its original AAD after an
			// authenticated tenant switch; TenantID then names only the locally
			// revoked target session and must not be injected into token AAD.
			return true
		}
		return value.Admission.TenantID == value.TenantID && validEntityID(value.Admission.BindingID)
	default:
		return false
	}
}

func validSAMLClaim(value ContinuationSnapshot) bool {
	if value.ProtectedSAML.KeyVersion == 0 || len(value.ProtectedSAML.Ciphertext) < minimumProtectedBytes ||
		len(value.ProtectedSAML.Ciphertext) > 16*1024 ||
		value.ProtectedIDToken.KeyVersion != 0 || len(value.ProtectedIDToken.Ciphertext) != 0 ||
		value.IDTokenDigest != ([sha256.Size]byte{}) || value.EndSessionEndpoint != "" ||
		value.PostLogoutRedirectURI != "" ||
		!value.MaterialExpiresAt.IsZero() {
		return false
	}
	configuration := value.SAMLConfiguration
	if configuration.Provider != value.Provider || configuration.MaterialBindingID != value.BindingID ||
		configuration.SPEntityID == "" || configuration.SLORedirectURL == "" ||
		configuration.SPKeyRevision == 0 || configuration.SPKeyRevision > maximumPersistentRevision ||
		configuration.RedirectSignatureAlgorithm == "" {
		return false
	}
	switch value.Provider.Scope {
	case identity.TenantProviderScope:
		return value.TenantID != (identity.EntityID{}) && value.Provider.TenantID == value.TenantID &&
			validEntityID(value.BindingID) && value.Admission == (identity.TenantAdmissionContext{}) &&
			configuration.Authority == federatedsaml.TenantCeremonyAuthority &&
			configuration.PlatformLoginRevision == 0
	case identity.PlatformProviderScope:
		if value.Provider.TenantID != (identity.EntityID{}) || value.BindingID != (identity.EntityID{}) ||
			configuration.Authority != federatedsaml.DirectPlatformCeremonyAuthority ||
			configuration.PlatformLoginRevision == 0 ||
			configuration.PlatformLoginRevision > maximumPersistentRevision {
			return false
		}
		if value.TenantID == (identity.EntityID{}) {
			return value.Admission == (identity.TenantAdmissionContext{})
		}
		return value.Admission.TenantID == value.TenantID && validEntityID(value.Admission.BindingID)
	default:
		return false
	}
}

func clearContinuationSnapshot(value *ContinuationSnapshot) {
	if value == nil {
		return
	}
	clear(value.ProtectedIDToken.Ciphertext)
	clear(value.ProtectedSAML.Ciphertext)
	*value = ContinuationSnapshot{}
}

func newOpaque(source io.Reader) ([]byte, error) {
	raw := make([]byte, opaqueCredentialBytes)
	if _, err := io.ReadFull(source, raw); err != nil {
		clear(raw)
		return nil, err
	}
	var combined byte
	for _, item := range raw {
		combined |= item
	}
	if combined == 0 {
		clear(raw)
		return nil, ErrUnavailable
	}
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
	base64.RawURLEncoding.Encode(encoded, raw)
	clear(raw)
	return encoded, nil
}

func validOpaque(value string) bool { return validOpaqueBytes([]byte(value)) }

func validOpaqueBytes(value []byte) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(opaqueCredentialBytes) {
		return false
	}
	var decoded [opaqueCredentialBytes]byte
	written, err := base64.RawURLEncoding.Strict().Decode(decoded[:], value)
	var combined byte
	for _, item := range decoded {
		combined |= item
	}
	clear(decoded[:])
	return err == nil && written == opaqueCredentialBytes && combined != 0
}

func validEvent(value EventContext) bool {
	if !validEntityID(value.RequestID) || !validEntityID(value.CorrelationID) ||
		value.RequestID == value.CorrelationID || !value.RemoteAddress.IsValid() ||
		value.UserAgent == "" || len(value.UserAgent) > 512 || !utf8.ValidString(value.UserAgent) {
		return false
	}
	for _, character := range value.UserAgent {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validEntityID(value identity.EntityID) bool {
	return value != (identity.EntityID{}) && value[6]>>4 == 7 && value[8]&0xc0 == 0x80
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%1_000 == 0
}

func safeLocalCategory(value LocalRevokeCategory) string {
	if value == LocalOnly || value == LogoutContinuation {
		return string(value)
	}
	return "unknown"
}

func safeClaimCategory(value ClaimCategory) string {
	if value == ClaimGone || value == ClaimOIDC || value == ClaimSAML {
		return string(value)
	}
	return "unknown"
}
