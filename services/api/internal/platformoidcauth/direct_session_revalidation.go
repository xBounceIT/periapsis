package platformoidcauth

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

const (
	directSessionAudience                   = "api"
	directSessionAuthenticationMethod       = "oidc"
	directSessionPrimaryKind                = "platform_provider"
	directSessionProviderKind               = "oidc"
	directSessionPlatformFloorScope         = "platform_floor"
	maximumDirectSessionVersion       int64 = 2_147_483_647
	maximumDirectSessionEvidence            = 2
	directSessionRequestDigestDomain        = "periapsis/platform-oidc-auth/session-revalidation/v1"
)

var ErrDirectSessionRejected = errors.New("direct platform OIDC session rejected")

type DirectSessionEvidenceKind string

const (
	DirectSessionEvidencePlatformProvider DirectSessionEvidenceKind = "platform_provider"
	DirectSessionEvidenceTOTP             DirectSessionEvidenceKind = "totp"
)

type DirectSessionPolicyKind string

const (
	DirectSessionPolicyAssurance     DirectSessionPolicyKind = "assurance"
	DirectSessionPolicyLogin         DirectSessionPolicyKind = "login"
	DirectSessionPolicyPlatformFloor DirectSessionPolicyKind = "platform_floor"
)

type DirectSessionRevalidationDecision string

const (
	DirectSessionRevalidationUsable DirectSessionRevalidationDecision = "usable"
	DirectSessionRevalidationRevoke DirectSessionRevalidationDecision = "revoke"
)

type DirectSessionRevalidationReason string

const (
	DirectSessionReasonCurrent      DirectSessionRevalidationReason = "current"
	DirectSessionReasonExpired      DirectSessionRevalidationReason = "expired"
	DirectSessionReasonLifecycle    DirectSessionRevalidationReason = "lifecycle"
	DirectSessionReasonPrimaryDrift DirectSessionRevalidationReason = "primary_drift"
	DirectSessionReasonFactorDrift  DirectSessionRevalidationReason = "factor_drift"
	DirectSessionReasonTrustDrift   DirectSessionRevalidationReason = "trust_drift"
)

// DirectSessionRevalidationLookup is the narrow read key. ObservedAt is part
// of the database snapshot boundary, so lifecycle and evidence freshness are
// evaluated against the same instant in both layers.
type DirectSessionRevalidationLookup struct {
	SessionID  uuid.UUID
	ObservedAt time.Time
}

func (lookup DirectSessionRevalidationLookup) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectSessionRevalidationLookup{session:%t,observed:%t}",
		validUUIDv7(lookup.SessionID), validInstant(lookup.ObservedAt),
	)
}

func (lookup DirectSessionRevalidationLookup) GoString() string { return lookup.String() }

// DirectSessionState contains the complete shape of the tenantless session
// and its physically separate direct-primary rows. Counts remain explicit so
// an adapter cannot hide an ambiguous or mixed provenance graph behind a
// synthesized live flag.
type DirectSessionState struct {
	SessionID                  uuid.UUID
	RotationFamilyID           uuid.UUID
	UserID                     uuid.UUID
	ActiveTenantID             *uuid.UUID
	AuthenticationMethod       string
	Audience                   string
	PrimaryKind                string
	DirectStateCount           int
	DirectProvenanceCount      int
	TenantProvenanceCount      int
	ProviderEvidenceCount      int
	TOTPEvidenceCount          int
	CurrentVersion             int64
	UserAuthenticationRevision int64
	RecoveryRestricted         bool
	IssuedAt                   time.Time
	IdleExpiresAt              time.Time
	AbsoluteExpiresAt          time.Time
	Active                     bool
	RotationFamilyLive         bool
}

type DirectSessionAuthorityRevisions struct {
	Provider           ExactRevision
	Security           ExactRevision
	LoginPolicy        ExactRevision
	UserAuthentication ExactRevision
	ExternalIdentity   ExactRevision
	SubjectAliasKey    ExactRevision
	AssurancePolicy    ExactRevision
}

// DirectSessionPlatformFloor contains both the provenance pin and the raw
// current platform-floor row. CurrentCount makes absence and ambiguity
// observable without asking the adapter to choose one row.
type DirectSessionPlatformFloor struct {
	PinnedID           uuid.UUID
	PinnedRevision     int64
	CurrentID          uuid.UUID
	CurrentRevision    int64
	CurrentCount       int
	CurrentScope       string
	CurrentTenantID    *uuid.UUID
	CurrentRetiredAt   *time.Time
	Level              identity.AssuranceLevel
	LocalRequired      bool
	Freshness          time.Duration
	EnrollmentDeadline *time.Time
}

// DirectSessionAuthorityFacts are raw current rows and exact provenance pins.
// Aggregate compatibility booleans from persistence are intentionally absent.
type DirectSessionAuthorityFacts struct {
	ProviderID                 uuid.UUID
	ExternalIdentityID         uuid.UUID
	ProviderKind               string
	ProviderEnabled            bool
	RuntimePolicyEnabled       bool
	LegacyPlatformLoginEnabled bool
	LoginPolicyEnabled         bool
	AccountMode                AccountMode
	UserActive                 bool
	IdentityCurrentProviderID  uuid.UUID
	IdentityCurrentUserID      uuid.UUID
	IdentityProviderKind       string
	IdentityRetiredAt          *time.Time
	AliasCurrentProviderID     uuid.UUID
	AliasCurrentIdentityID     uuid.UUID
	AliasRetiredAt             *time.Time
	Revisions                  DirectSessionAuthorityRevisions
	PlatformFloor              DirectSessionPlatformFloor
	TrustRuleID                *uuid.UUID
	TrustRuleRevision          *int64
}

type DirectSessionEvidence struct {
	ID                 uuid.UUID
	UserID             uuid.UUID
	Kind               DirectSessionEvidenceKind
	Level              identity.AssuranceLevel
	PlatformProviderID *uuid.UUID
	ExternalIdentityID *uuid.UUID
	TOTPCredentialID   *uuid.UUID
	FactorRevision     *int64
	TrustRuleID        *uuid.UUID
	TrustRuleRevision  *int64
	AuthenticatedAt    time.Time
	ExpiresAt          *time.Time
}

// DirectSessionFactorAuthority is the current row for one immutable TOTP
// evidence reference. EvidenceID makes the join cardinality independently
// checkable by the application.
type DirectSessionFactorAuthority struct {
	EvidenceID              uuid.UUID
	EvidenceUserID          uuid.UUID
	TOTPCredentialID        uuid.UUID
	PinnedSecurityRevision  int64
	CurrentUserID           uuid.UUID
	CurrentSecurityRevision int64
	ConfirmedAt             *time.Time
	DisabledAt              *time.Time
}

// DirectSessionTrustAuthority is the current trust-rule row for one elevated
// provider evidence item. Primary provider evidence has no trust authority.
type DirectSessionTrustAuthority struct {
	EvidenceID          uuid.UUID
	TrustRuleID         uuid.UUID
	PinnedRevision      int64
	CurrentProviderID   uuid.UUID
	CurrentProviderKind string
	CurrentRevision     int64
	CurrentLevel        identity.AssuranceLevel
	Enabled             bool
	RetiredAt           *time.Time
}

type DirectSessionPolicyPin struct {
	Kind     DirectSessionPolicyKind
	ID       uuid.UUID
	Revision int64
}

type DirectSessionRevalidationSnapshot struct {
	Session           DirectSessionState
	Authority         DirectSessionAuthorityFacts
	Evidence          []DirectSessionEvidence
	FactorAuthorities []DirectSessionFactorAuthority
	TrustAuthorities  []DirectSessionTrustAuthority
	PolicyPins        []DirectSessionPolicyPin
}

func (snapshot DirectSessionRevalidationSnapshot) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectSessionRevalidationSnapshot{session:%t,user:%t,provider:%t,identity:%t,version:%t,evidence:%d,factors:%d,trust:%d,policies:%d,material:[REDACTED]}",
		validUUIDv7(snapshot.Session.SessionID), validUUIDv7(snapshot.Session.UserID),
		validUUIDv7(snapshot.Authority.ProviderID), validUUIDv7(snapshot.Authority.ExternalIdentityID),
		snapshot.Session.CurrentVersion > 0, len(snapshot.Evidence), len(snapshot.FactorAuthorities),
		len(snapshot.TrustAuthorities), len(snapshot.PolicyPins),
	)
}

func (snapshot DirectSessionRevalidationSnapshot) GoString() string { return snapshot.String() }

type DirectSessionRevalidationRequestDigest [sha256.Size]byte

type DirectSessionRevalidationMutation struct {
	SessionID       uuid.UUID
	ExpectedVersion int64
	RequestDigest   DirectSessionRevalidationRequestDigest
	Decision        DirectSessionRevalidationDecision
	Reason          DirectSessionRevalidationReason
	ObservedAt      time.Time
}

func (mutation DirectSessionRevalidationMutation) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectSessionRevalidationMutation{session:%t,expectedVersion:%t,decision:%q,reason:%q,observed:%t,material:[REDACTED]}",
		validUUIDv7(mutation.SessionID), mutation.ExpectedVersion > 0,
		mutation.Decision, mutation.Reason, validInstant(mutation.ObservedAt),
	)
}

func (mutation DirectSessionRevalidationMutation) GoString() string { return mutation.String() }

type DirectSessionRevalidationMutationResult struct {
	Applied         bool
	SessionID       uuid.UUID
	UserID          uuid.UUID
	ExpectedVersion int64
	NewVersion      int64
	Decision        DirectSessionRevalidationDecision
}

type DirectSessionRevalidationStore interface {
	LoadDirectPlatformSessionForRevalidation(
		context.Context,
		DirectSessionRevalidationLookup,
	) (DirectSessionRevalidationSnapshot, error)
	ApplyDirectPlatformSessionRevalidation(
		context.Context,
		DirectSessionRevalidationMutation,
	) (DirectSessionRevalidationMutationResult, error)
}

type DirectPlatformSessionAuthorityOptions struct {
	Store            DirectSessionRevalidationStore
	OperationTimeout time.Duration
	Now              func() time.Time
}

// DirectPlatformSessionAuthorityService is the request-time authority gate
// for tenantless direct OIDC sessions. It deliberately cannot emit a session
// transition: only an atomically committed usable decision grants authority.
type DirectPlatformSessionAuthorityService struct {
	store            DirectSessionRevalidationStore
	operationTimeout time.Duration
	now              func() time.Time
}

// DirectSessionAuthorityLookup is the already-resolved local identity from
// the session-cookie boundary. It contains no provider claim or browser
// credential.
type DirectSessionAuthorityLookup struct {
	SessionID            uuid.UUID
	UserID               uuid.UUID
	AuthenticationMethod string
	Audience             string
}

func (lookup DirectSessionAuthorityLookup) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectSessionAuthorityLookup{session:%t,user:%t,method:%q,audience:%q,material:[REDACTED]}",
		validUUIDv7(lookup.SessionID), validUUIDv7(lookup.UserID),
		lookup.AuthenticationMethod, lookup.Audience,
	)
}

func (lookup DirectSessionAuthorityLookup) GoString() string { return lookup.String() }

// DirectSessionAuthorityResult grants current authority and the later idle
// touch only as one indivisible outcome.
type DirectSessionAuthorityResult struct {
	SessionID      uuid.UUID
	UserID         uuid.UUID
	AllowAuthority bool
	AllowIdleTouch bool
}

func (result DirectSessionAuthorityResult) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectSessionAuthorityResult{session:%t,user:%t,authority:%t,idleTouch:%t,material:[REDACTED]}",
		validUUIDv7(result.SessionID), validUUIDv7(result.UserID), result.AllowAuthority, result.AllowIdleTouch,
	)
}

func (result DirectSessionAuthorityResult) GoString() string { return result.String() }

func NewDirectPlatformSessionAuthority(
	options DirectPlatformSessionAuthorityOptions,
) (*DirectPlatformSessionAuthorityService, error) {
	if options.Store == nil || options.OperationTimeout < minimumDirectOIDCOperationTimeout ||
		options.OperationTimeout > maximumDirectOIDCOperationTimeout ||
		options.OperationTimeout%time.Microsecond != 0 {
		return nil, ErrDirectSessionRejected
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &DirectPlatformSessionAuthorityService{
		store: options.Store, operationTimeout: options.OperationTimeout, now: options.Now,
	}, nil
}

func (service *DirectPlatformSessionAuthorityService) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectPlatformSessionAuthorityService{configured:%t}",
		service != nil && service.store != nil && service.now != nil &&
			service.operationTimeout >= minimumDirectOIDCOperationTimeout,
	)
}

func (service *DirectPlatformSessionAuthorityService) GoString() string { return service.String() }

func (service *DirectPlatformSessionAuthorityService) RevalidateDirectPlatformSession(
	ctx context.Context,
	lookup DirectSessionAuthorityLookup,
) (DirectSessionAuthorityResult, error) {
	if service == nil || service.store == nil || service.now == nil || ctx == nil ||
		!validDirectSessionAuthorityLookup(lookup) || ctx.Err() != nil {
		return DirectSessionAuthorityResult{}, ErrDirectSessionRejected
	}
	observedAt := service.now().UTC().Truncate(time.Microsecond)
	if !validInstant(observedAt) {
		return DirectSessionAuthorityResult{}, ErrDirectSessionRejected
	}
	operation, cancel := context.WithTimeout(ctx, service.operationTimeout)
	defer cancel()
	persistenceLookup := DirectSessionRevalidationLookup{
		SessionID: lookup.SessionID, ObservedAt: observedAt,
	}
	snapshot, err := service.load(operation, persistenceLookup)
	if err != nil || operation.Err() != nil ||
		!validDirectSessionSnapshotShape(snapshot, lookup, observedAt) {
		return DirectSessionAuthorityResult{}, ErrDirectSessionRejected
	}
	decision, reason, apply := evaluateDirectSession(snapshot, observedAt)
	if !apply {
		return DirectSessionAuthorityResult{}, ErrDirectSessionRejected
	}
	mutation, ok := newDirectSessionMutation(snapshot, observedAt, decision, reason)
	if !ok {
		return DirectSessionAuthorityResult{}, ErrDirectSessionRejected
	}
	result, err := service.apply(operation, mutation)
	if err != nil || operation.Err() != nil ||
		!validDirectSessionMutationResult(result, mutation, snapshot.Session.UserID) ||
		decision != DirectSessionRevalidationUsable {
		return DirectSessionAuthorityResult{}, ErrDirectSessionRejected
	}
	return DirectSessionAuthorityResult{
		SessionID: lookup.SessionID, UserID: lookup.UserID,
		AllowAuthority: true, AllowIdleTouch: true,
	}, nil
}

func (service *DirectPlatformSessionAuthorityService) load(
	ctx context.Context,
	lookup DirectSessionRevalidationLookup,
) (DirectSessionRevalidationSnapshot, error) {
	var lastErr error
	for range 2 {
		returned, err := service.store.LoadDirectPlatformSessionForRevalidation(ctx, lookup)
		if err == nil {
			return cloneDirectSessionSnapshot(returned), nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return DirectSessionRevalidationSnapshot{}, lastErr
}

func (service *DirectPlatformSessionAuthorityService) apply(
	ctx context.Context,
	mutation DirectSessionRevalidationMutation,
) (DirectSessionRevalidationMutationResult, error) {
	var result DirectSessionRevalidationMutationResult
	var lastErr error
	for range 2 {
		result, lastErr = service.store.ApplyDirectPlatformSessionRevalidation(ctx, mutation)
		if lastErr == nil || ctx.Err() != nil {
			break
		}
	}
	return result, lastErr
}

func validDirectSessionAuthorityLookup(lookup DirectSessionAuthorityLookup) bool {
	return validUUIDv7(lookup.SessionID) && validUUIDv7(lookup.UserID) &&
		lookup.SessionID != lookup.UserID && lookup.AuthenticationMethod == directSessionAuthenticationMethod &&
		lookup.Audience == directSessionAudience
}

func validDirectSessionSnapshotShape(
	snapshot DirectSessionRevalidationSnapshot,
	lookup DirectSessionAuthorityLookup,
	observedAt time.Time,
) bool {
	session := snapshot.Session
	authority := snapshot.Authority
	if session.SessionID != lookup.SessionID || session.UserID != lookup.UserID ||
		!validUUIDv7(session.SessionID) || !validUUIDv7(session.RotationFamilyID) ||
		session.SessionID == session.RotationFamilyID || !validUUIDv7(session.UserID) ||
		session.ActiveTenantID != nil || session.AuthenticationMethod != lookup.AuthenticationMethod ||
		session.Audience != lookup.Audience || session.PrimaryKind != directSessionPrimaryKind ||
		session.DirectStateCount != 1 || session.DirectProvenanceCount != 1 || session.TenantProvenanceCount != 0 ||
		session.ProviderEvidenceCount != 1 || session.TOTPEvidenceCount < 0 || session.TOTPEvidenceCount > 1 ||
		session.CurrentVersion < 1 || session.CurrentVersion > maximumDirectSessionVersion ||
		!validRevision(session.UserAuthenticationRevision) || session.RecoveryRestricted ||
		!validInstant(session.IssuedAt) || !validInstant(session.IdleExpiresAt) ||
		!validInstant(session.AbsoluteExpiresAt) || session.IssuedAt.After(observedAt) ||
		!session.IdleExpiresAt.After(session.IssuedAt) || !session.AbsoluteExpiresAt.After(session.IssuedAt) ||
		session.IdleExpiresAt.After(session.AbsoluteExpiresAt) {
		return false
	}
	if !validUUIDv7(authority.ProviderID) || !validUUIDv7(authority.ExternalIdentityID) ||
		authority.ProviderID == authority.ExternalIdentityID || authority.ProviderKind == "" ||
		!validDirectSessionAccountModeShape(authority.AccountMode) ||
		!validUUIDv7(authority.IdentityCurrentProviderID) || !validUUIDv7(authority.IdentityCurrentUserID) ||
		authority.IdentityProviderKind == "" || !validUUIDv7(authority.AliasCurrentProviderID) ||
		!validUUIDv7(authority.AliasCurrentIdentityID) ||
		!validOptionalDirectSessionInstant(authority.IdentityRetiredAt) ||
		!validOptionalDirectSessionInstant(authority.AliasRetiredAt) ||
		!validDirectSessionRevisionsShape(authority.Revisions) ||
		session.UserAuthenticationRevision != authority.Revisions.UserAuthentication.Pinned ||
		!validDirectSessionPlatformFloorShape(authority.PlatformFloor) ||
		!validDirectSessionTrustPinShape(authority.TrustRuleID, authority.TrustRuleRevision) {
		return false
	}
	return validDirectSessionEvidenceShape(snapshot, observedAt) &&
		validDirectSessionPolicyPinShape(snapshot.PolicyPins)
}

func validDirectSessionRevisionsShape(revisions DirectSessionAuthorityRevisions) bool {
	return validRevisionPair(revisions.Provider) && validRevisionPair(revisions.Security) &&
		validRevisionPair(revisions.LoginPolicy) && validRevisionPair(revisions.UserAuthentication) &&
		validRevisionPair(revisions.ExternalIdentity) && validRevisionPair(revisions.SubjectAliasKey) &&
		validRevisionPair(revisions.AssurancePolicy) &&
		revisions.Provider.Pinned <= maximumDirectSessionVersion &&
		revisions.Provider.Current <= maximumDirectSessionVersion &&
		revisions.ExternalIdentity.Pinned <= maximumDirectSessionVersion &&
		revisions.ExternalIdentity.Current <= maximumDirectSessionVersion &&
		revisions.SubjectAliasKey.Pinned <= 32_767 && revisions.SubjectAliasKey.Current <= 32_767
}

func validRevisionPair(revision ExactRevision) bool {
	return validRevision(revision.Pinned) && validRevision(revision.Current)
}

func validDirectSessionPlatformFloorShape(floor DirectSessionPlatformFloor) bool {
	if !validUUIDv7(floor.PinnedID) || !validRevision(floor.PinnedRevision) ||
		floor.CurrentCount < 0 || floor.CurrentCount > 1_024 ||
		floor.Freshness < 0 || floor.Freshness > 365*24*time.Hour ||
		!validOptionalDirectSessionInstant(floor.EnrollmentDeadline) ||
		!validOptionalDirectSessionInstant(floor.CurrentRetiredAt) {
		return false
	}
	if floor.CurrentCount != 1 {
		return floor.CurrentID == uuid.Nil && floor.CurrentRevision == 0 && floor.CurrentScope == "" &&
			floor.CurrentTenantID == nil && floor.CurrentRetiredAt == nil && floor.Level == 0 &&
			!floor.LocalRequired && floor.Freshness == 0 && floor.EnrollmentDeadline == nil
	}
	return validUUIDv7(floor.CurrentID) && validRevision(floor.CurrentRevision) &&
		floor.CurrentScope != "" && floor.Level >= identity.AssurancePrimary &&
		floor.Level <= identity.AssurancePhishingResistant
}

func validDirectSessionTrustPinShape(ruleID *uuid.UUID, revision *int64) bool {
	if ruleID == nil || revision == nil {
		return ruleID == nil && revision == nil
	}
	return validUUIDv7(*ruleID) && validRevision(*revision)
}

func validDirectSessionEvidenceShape(
	snapshot DirectSessionRevalidationSnapshot,
	observedAt time.Time,
) bool {
	if len(snapshot.Evidence) < 1 || len(snapshot.Evidence) > maximumDirectSessionEvidence ||
		len(snapshot.FactorAuthorities) > 1 || len(snapshot.TrustAuthorities) > 1 {
		return false
	}
	providerCount, factorCount := 0, 0
	seen := make(map[uuid.UUID]struct{}, len(snapshot.Evidence))
	for index, evidence := range snapshot.Evidence {
		if !validUUIDv7(evidence.ID) || !validUUIDv7(evidence.UserID) ||
			evidence.UserID != snapshot.Session.UserID || !validDirectSessionEvidenceLevel(evidence.Level) ||
			!validInstant(evidence.AuthenticatedAt) || !validOptionalDirectSessionInstant(evidence.ExpiresAt) ||
			evidence.AuthenticatedAt.After(snapshot.Session.IssuedAt) ||
			evidence.ExpiresAt != nil && !evidence.ExpiresAt.After(evidence.AuthenticatedAt) ||
			index > 0 && !directSessionEvidenceLess(snapshot.Evidence[index-1], evidence) {
			return false
		}
		if _, duplicate := seen[evidence.ID]; duplicate {
			return false
		}
		seen[evidence.ID] = struct{}{}
		switch evidence.Kind {
		case DirectSessionEvidencePlatformProvider:
			providerCount++
			if evidence.PlatformProviderID == nil || evidence.ExternalIdentityID == nil ||
				*evidence.PlatformProviderID != snapshot.Authority.ProviderID ||
				*evidence.ExternalIdentityID != snapshot.Authority.ExternalIdentityID ||
				evidence.TOTPCredentialID != nil || evidence.FactorRevision != nil {
				return false
			}
			trusted := evidence.Level != identity.AssurancePrimary
			if trusted != (evidence.TrustRuleID != nil && evidence.TrustRuleRevision != nil) ||
				evidence.TrustRuleID == nil != (evidence.TrustRuleRevision == nil) {
				return false
			}
			if trusted && (evidence.ExpiresAt == nil || !validUUIDv7(*evidence.TrustRuleID) ||
				!validRevision(*evidence.TrustRuleRevision)) {
				return false
			}
		case DirectSessionEvidenceTOTP:
			factorCount++
			if evidence.Level != identity.AssuranceMFA || evidence.PlatformProviderID != nil ||
				evidence.ExternalIdentityID != nil || evidence.TOTPCredentialID == nil ||
				evidence.FactorRevision == nil || !validUUIDv7(*evidence.TOTPCredentialID) ||
				!validRevision(*evidence.FactorRevision) || evidence.TrustRuleID != nil ||
				evidence.TrustRuleRevision != nil {
				return false
			}
		default:
			return false
		}
	}
	if providerCount != 1 || factorCount > 1 || providerCount != snapshot.Session.ProviderEvidenceCount ||
		factorCount != snapshot.Session.TOTPEvidenceCount || factorCount != len(snapshot.FactorAuthorities) {
		return false
	}
	providerEvidence := directSessionProviderEvidence(snapshot.Evidence)
	if providerEvidence == nil {
		return false
	}
	wantTrust := 0
	if providerEvidence.Level != identity.AssurancePrimary {
		wantTrust = 1
	}
	if len(snapshot.TrustAuthorities) != wantTrust ||
		!validDirectSessionFactorAuthorityShape(snapshot.FactorAuthorities, snapshot.Evidence, observedAt) ||
		!validDirectSessionTrustAuthorityShape(snapshot.TrustAuthorities, *providerEvidence) {
		return false
	}
	return true
}

func validDirectSessionFactorAuthorityShape(
	authorities []DirectSessionFactorAuthority,
	evidence []DirectSessionEvidence,
	observedAt time.Time,
) bool {
	for _, authority := range authorities {
		if !validUUIDv7(authority.EvidenceID) || !validUUIDv7(authority.EvidenceUserID) ||
			!validUUIDv7(authority.TOTPCredentialID) || !validRevision(authority.PinnedSecurityRevision) ||
			!validUUIDv7(authority.CurrentUserID) || !validRevision(authority.CurrentSecurityRevision) ||
			authority.ConfirmedAt == nil || !validInstant(*authority.ConfirmedAt) ||
			authority.ConfirmedAt.After(observedAt) || !validOptionalDirectSessionInstant(authority.DisabledAt) ||
			authority.DisabledAt != nil && authority.DisabledAt.Before(*authority.ConfirmedAt) {
			return false
		}
		matching := 0
		for _, proof := range evidence {
			if proof.Kind == DirectSessionEvidenceTOTP && proof.ID == authority.EvidenceID &&
				proof.UserID == authority.EvidenceUserID && proof.TOTPCredentialID != nil &&
				*proof.TOTPCredentialID == authority.TOTPCredentialID && proof.FactorRevision != nil &&
				*proof.FactorRevision == authority.PinnedSecurityRevision {
				matching++
			}
		}
		if matching != 1 {
			return false
		}
	}
	return true
}

func validDirectSessionTrustAuthorityShape(
	authorities []DirectSessionTrustAuthority,
	evidence DirectSessionEvidence,
) bool {
	for _, authority := range authorities {
		if !validUUIDv7(authority.EvidenceID) || !validUUIDv7(authority.TrustRuleID) ||
			!validRevision(authority.PinnedRevision) || !validUUIDv7(authority.CurrentProviderID) ||
			authority.CurrentProviderKind == "" || !validRevision(authority.CurrentRevision) ||
			!validDirectSessionEvidenceLevel(authority.CurrentLevel) ||
			!validOptionalDirectSessionInstant(authority.RetiredAt) || evidence.TrustRuleID == nil ||
			evidence.TrustRuleRevision == nil || authority.EvidenceID != evidence.ID ||
			authority.TrustRuleID != *evidence.TrustRuleID ||
			authority.PinnedRevision != *evidence.TrustRuleRevision {
			return false
		}
	}
	return true
}

func validDirectSessionPolicyPinShape(pins []DirectSessionPolicyPin) bool {
	if len(pins) != 3 {
		return false
	}
	for index, pin := range pins {
		if !validUUIDv7(pin.ID) || !validRevision(pin.Revision) ||
			index > 0 && !directSessionPolicyPinLess(pins[index-1], pin) {
			return false
		}
		switch pin.Kind {
		case DirectSessionPolicyAssurance, DirectSessionPolicyLogin, DirectSessionPolicyPlatformFloor:
		default:
			return false
		}
	}
	return true
}

func evaluateDirectSession(
	snapshot DirectSessionRevalidationSnapshot,
	observedAt time.Time,
) (DirectSessionRevalidationDecision, DirectSessionRevalidationReason, bool) {
	session := snapshot.Session
	authority := snapshot.Authority
	if !observedAt.Before(session.IdleExpiresAt) || !observedAt.Before(session.AbsoluteExpiresAt) {
		return DirectSessionRevalidationRevoke, DirectSessionReasonExpired, true
	}
	if !session.Active || !session.RotationFamilyLive || !authority.UserActive || !authority.ProviderEnabled ||
		!authority.RuntimePolicyEnabled || authority.LegacyPlatformLoginEnabled || !authority.LoginPolicyEnabled ||
		authority.AccountMode != AccountModeExistingIdentity || authority.IdentityRetiredAt != nil ||
		authority.AliasRetiredAt != nil {
		return DirectSessionRevalidationRevoke, DirectSessionReasonLifecycle, true
	}
	if authority.ProviderKind != directSessionProviderKind ||
		authority.IdentityProviderKind != directSessionProviderKind ||
		authority.IdentityCurrentProviderID != authority.ProviderID ||
		authority.IdentityCurrentUserID != session.UserID ||
		authority.AliasCurrentProviderID != authority.ProviderID ||
		authority.AliasCurrentIdentityID != authority.ExternalIdentityID ||
		!exactDirectSessionPrimaryRevisions(authority.Revisions) {
		return DirectSessionRevalidationRevoke, DirectSessionReasonPrimaryDrift, true
	}
	if authority.Revisions.AssurancePolicy.Pinned != authority.Revisions.AssurancePolicy.Current ||
		!currentDirectSessionPlatformFloor(authority.PlatformFloor) ||
		!exactDirectSessionPolicyPins(snapshot.PolicyPins, authority) {
		// A policy refresh may require rotation or step-up, neither of which this
		// authority-only boundary can represent. Deny without a terminal write.
		return "", "", false
	}
	if !currentDirectSessionFactorAuthorities(snapshot) {
		return DirectSessionRevalidationRevoke, DirectSessionReasonFactorDrift, true
	}
	if !currentDirectSessionTrustAuthorities(snapshot) {
		return DirectSessionRevalidationRevoke, DirectSessionReasonTrustDrift, true
	}
	if !directSessionEvidenceSatisfiesFloor(snapshot, observedAt) {
		// A fresh factor or a newly evaluated policy could legitimately recover
		// this case. With no transition in this boundary, deny without turning a
		// potentially recoverable assurance decision into a family revocation.
		return "", "", false
	}
	return DirectSessionRevalidationUsable, DirectSessionReasonCurrent, true
}

func exactDirectSessionPrimaryRevisions(revisions DirectSessionAuthorityRevisions) bool {
	return revisions.Provider.Pinned == revisions.Provider.Current &&
		revisions.Security.Pinned == revisions.Security.Current &&
		revisions.LoginPolicy.Pinned == revisions.LoginPolicy.Current &&
		revisions.UserAuthentication.Pinned == revisions.UserAuthentication.Current &&
		revisions.ExternalIdentity.Pinned == revisions.ExternalIdentity.Current &&
		revisions.SubjectAliasKey.Pinned == revisions.SubjectAliasKey.Current
}

func currentDirectSessionPlatformFloor(floor DirectSessionPlatformFloor) bool {
	return floor.CurrentCount == 1 && floor.CurrentID == floor.PinnedID &&
		floor.CurrentRevision == floor.PinnedRevision && floor.CurrentScope == directSessionPlatformFloorScope &&
		floor.CurrentTenantID == nil && floor.CurrentRetiredAt == nil
}

func exactDirectSessionPolicyPins(
	pins []DirectSessionPolicyPin,
	authority DirectSessionAuthorityFacts,
) bool {
	wanted := map[DirectSessionPolicyKind]DirectSessionPolicyPin{
		DirectSessionPolicyAssurance: {
			Kind: DirectSessionPolicyAssurance, ID: authority.ProviderID,
			Revision: authority.Revisions.AssurancePolicy.Current,
		},
		DirectSessionPolicyLogin: {
			Kind: DirectSessionPolicyLogin, ID: authority.ProviderID,
			Revision: authority.Revisions.LoginPolicy.Current,
		},
		DirectSessionPolicyPlatformFloor: {
			Kind: DirectSessionPolicyPlatformFloor, ID: authority.PlatformFloor.CurrentID,
			Revision: authority.PlatformFloor.CurrentRevision,
		},
	}
	for _, pin := range pins {
		if expected, ok := wanted[pin.Kind]; !ok || expected != pin {
			return false
		}
		delete(wanted, pin.Kind)
	}
	return len(wanted) == 0
}

func currentDirectSessionFactorAuthorities(snapshot DirectSessionRevalidationSnapshot) bool {
	for _, authority := range snapshot.FactorAuthorities {
		if authority.EvidenceUserID != snapshot.Session.UserID ||
			authority.CurrentUserID != snapshot.Session.UserID ||
			authority.PinnedSecurityRevision != authority.CurrentSecurityRevision ||
			authority.DisabledAt != nil {
			return false
		}
		matched := false
		for _, evidence := range snapshot.Evidence {
			if evidence.ID == authority.EvidenceID && evidence.Kind == DirectSessionEvidenceTOTP {
				matched = authority.ConfirmedAt != nil &&
					!authority.ConfirmedAt.After(evidence.AuthenticatedAt)
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func currentDirectSessionTrustAuthorities(snapshot DirectSessionRevalidationSnapshot) bool {
	providerEvidence := directSessionProviderEvidence(snapshot.Evidence)
	if providerEvidence == nil {
		return false
	}
	if providerEvidence.Level == identity.AssurancePrimary {
		return len(snapshot.TrustAuthorities) == 0 && snapshot.Authority.TrustRuleID == nil &&
			snapshot.Authority.TrustRuleRevision == nil
	}
	if len(snapshot.TrustAuthorities) != 1 || snapshot.Authority.TrustRuleID == nil ||
		snapshot.Authority.TrustRuleRevision == nil {
		return false
	}
	current := snapshot.TrustAuthorities[0]
	return current.TrustRuleID == *snapshot.Authority.TrustRuleID &&
		current.PinnedRevision == *snapshot.Authority.TrustRuleRevision &&
		current.CurrentProviderID == snapshot.Authority.ProviderID &&
		current.CurrentProviderKind == directSessionProviderKind &&
		current.PinnedRevision == current.CurrentRevision && current.CurrentLevel == providerEvidence.Level &&
		current.Enabled && current.RetiredAt == nil
}

func directSessionEvidenceSatisfiesFloor(
	snapshot DirectSessionRevalidationSnapshot,
	observedAt time.Time,
) bool {
	floor := snapshot.Authority.PlatformFloor
	for _, evidence := range snapshot.Evidence {
		if evidence.AuthenticatedAt.After(observedAt) || evidence.ExpiresAt != nil && !evidence.ExpiresAt.After(observedAt) ||
			floor.Freshness > 0 && observedAt.Sub(evidence.AuthenticatedAt) > floor.Freshness ||
			floor.LocalRequired && evidence.Kind != DirectSessionEvidenceTOTP {
			continue
		}
		if evidence.Level >= floor.Level {
			return true
		}
	}
	return false
}

func newDirectSessionMutation(
	snapshot DirectSessionRevalidationSnapshot,
	observedAt time.Time,
	decision DirectSessionRevalidationDecision,
	reason DirectSessionRevalidationReason,
) (DirectSessionRevalidationMutation, bool) {
	mutation := DirectSessionRevalidationMutation{
		SessionID: snapshot.Session.SessionID, ExpectedVersion: snapshot.Session.CurrentVersion,
		Decision: decision, Reason: reason, ObservedAt: observedAt,
	}
	mutation.RequestDigest = directSessionMutationDigest(mutation)
	return mutation, validDirectSessionMutation(mutation)
}

func validDirectSessionMutation(mutation DirectSessionRevalidationMutation) bool {
	if !validUUIDv7(mutation.SessionID) || mutation.ExpectedVersion < 1 ||
		mutation.ExpectedVersion >= maximumDirectSessionVersion || !validInstant(mutation.ObservedAt) ||
		mutation.RequestDigest == (DirectSessionRevalidationRequestDigest{}) {
		return false
	}
	return mutation.Decision == DirectSessionRevalidationUsable && mutation.Reason == DirectSessionReasonCurrent ||
		mutation.Decision == DirectSessionRevalidationRevoke &&
			(mutation.Reason == DirectSessionReasonExpired || mutation.Reason == DirectSessionReasonLifecycle ||
				mutation.Reason == DirectSessionReasonPrimaryDrift || mutation.Reason == DirectSessionReasonFactorDrift ||
				mutation.Reason == DirectSessionReasonTrustDrift)
}

func validDirectSessionMutationResult(
	result DirectSessionRevalidationMutationResult,
	mutation DirectSessionRevalidationMutation,
	expectedUserID uuid.UUID,
) bool {
	if !result.Applied || result.SessionID != mutation.SessionID || result.UserID != expectedUserID ||
		result.ExpectedVersion != mutation.ExpectedVersion || result.Decision != mutation.Decision {
		return false
	}
	if mutation.Decision == DirectSessionRevalidationUsable {
		return result.NewVersion == mutation.ExpectedVersion+1
	}
	return result.NewVersion == 0
}

func directSessionMutationDigest(
	mutation DirectSessionRevalidationMutation,
) DirectSessionRevalidationRequestDigest {
	digest := sha256.New()
	writeDirectDigestField(digest, []byte(directSessionRequestDigestDomain))
	writeDirectDigestField(digest, mutation.SessionID[:])
	writeDirectDigestField(digest, []byte(mutation.Decision))
	writeDirectDigestField(digest, []byte(mutation.Reason))
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], uint64(mutation.ExpectedVersion))
	writeDirectDigestField(digest, number[:])
	binary.BigEndian.PutUint64(number[:], uint64(mutation.ObservedAt.UnixMicro()))
	writeDirectDigestField(digest, number[:])
	var result DirectSessionRevalidationRequestDigest
	copy(result[:], digest.Sum(nil))
	return result
}

func directSessionEvidenceLess(left, right DirectSessionEvidence) bool {
	if left.Kind != right.Kind {
		return left.Kind < right.Kind
	}
	return slices.Compare(left.ID[:], right.ID[:]) < 0
}

func directSessionPolicyPinLess(left, right DirectSessionPolicyPin) bool {
	if left.Kind != right.Kind {
		return left.Kind < right.Kind
	}
	return slices.Compare(left.ID[:], right.ID[:]) < 0
}

func directSessionProviderEvidence(values []DirectSessionEvidence) *DirectSessionEvidence {
	for index := range values {
		if values[index].Kind == DirectSessionEvidencePlatformProvider {
			return &values[index]
		}
	}
	return nil
}

func validDirectSessionEvidenceLevel(level identity.AssuranceLevel) bool {
	return level >= identity.AssurancePrimary && level <= identity.AssurancePhishingResistant
}

func validDirectSessionAccountModeShape(mode AccountMode) bool {
	return mode == AccountModeExistingIdentity || mode == "disabled"
}

func validOptionalDirectSessionInstant(value *time.Time) bool {
	return value == nil || validInstant(*value)
}

func cloneDirectSessionSnapshot(value DirectSessionRevalidationSnapshot) DirectSessionRevalidationSnapshot {
	value.Session.ActiveTenantID = cloneDirectSessionUUID(value.Session.ActiveTenantID)
	value.Authority.IdentityRetiredAt = cloneDirectSessionTime(value.Authority.IdentityRetiredAt)
	value.Authority.AliasRetiredAt = cloneDirectSessionTime(value.Authority.AliasRetiredAt)
	value.Authority.TrustRuleID = cloneDirectSessionUUID(value.Authority.TrustRuleID)
	value.Authority.TrustRuleRevision = cloneDirectSessionInt64(value.Authority.TrustRuleRevision)
	floor := &value.Authority.PlatformFloor
	floor.CurrentTenantID = cloneDirectSessionUUID(floor.CurrentTenantID)
	floor.CurrentRetiredAt = cloneDirectSessionTime(floor.CurrentRetiredAt)
	floor.EnrollmentDeadline = cloneDirectSessionTime(floor.EnrollmentDeadline)
	value.Evidence = append([]DirectSessionEvidence(nil), value.Evidence...)
	for index := range value.Evidence {
		evidence := &value.Evidence[index]
		evidence.PlatformProviderID = cloneDirectSessionUUID(evidence.PlatformProviderID)
		evidence.ExternalIdentityID = cloneDirectSessionUUID(evidence.ExternalIdentityID)
		evidence.TOTPCredentialID = cloneDirectSessionUUID(evidence.TOTPCredentialID)
		evidence.FactorRevision = cloneDirectSessionInt64(evidence.FactorRevision)
		evidence.TrustRuleID = cloneDirectSessionUUID(evidence.TrustRuleID)
		evidence.TrustRuleRevision = cloneDirectSessionInt64(evidence.TrustRuleRevision)
		evidence.ExpiresAt = cloneDirectSessionTime(evidence.ExpiresAt)
	}
	value.FactorAuthorities = append([]DirectSessionFactorAuthority(nil), value.FactorAuthorities...)
	for index := range value.FactorAuthorities {
		value.FactorAuthorities[index].ConfirmedAt = cloneDirectSessionTime(value.FactorAuthorities[index].ConfirmedAt)
		value.FactorAuthorities[index].DisabledAt = cloneDirectSessionTime(value.FactorAuthorities[index].DisabledAt)
	}
	value.TrustAuthorities = append([]DirectSessionTrustAuthority(nil), value.TrustAuthorities...)
	for index := range value.TrustAuthorities {
		value.TrustAuthorities[index].RetiredAt = cloneDirectSessionTime(value.TrustAuthorities[index].RetiredAt)
	}
	value.PolicyPins = append([]DirectSessionPolicyPin(nil), value.PolicyPins...)
	return value
}

func cloneDirectSessionUUID(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func cloneDirectSessionInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func cloneDirectSessionTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}
