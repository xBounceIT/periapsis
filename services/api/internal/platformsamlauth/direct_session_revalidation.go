package platformsamlauth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

const (
	DirectSAMLSessionAuthority       = "direct_platform_saml"
	DirectSAMLSessionMethod          = "saml"
	DirectSAMLSessionAudience        = "api"
	DirectSAMLSessionPrimaryKind     = "platform_provider"
	DirectSAMLSessionProviderKind    = "saml"
	DirectSAMLSessionAccountExisting = DirectSAMLSessionAccountMode("existing_identity")
	DirectSAMLSessionAccountDisabled = DirectSAMLSessionAccountMode("disabled")
	DirectSAMLSessionMaximumEvidence = 2
	DirectSAMLSessionMaximumPolicies = 3
	DirectSAMLSessionMaximumVersion  = uint64(2_147_483_647)
	DirectSAMLSessionMaximumRevision = uint64(9_007_199_254_740_991)
	DirectSAMLSessionRequestDigestV1 = "periapsis/platform-saml/session-revalidation/v1"
)

type DirectSAMLSessionAccountMode string

type DirectSAMLSessionEvidenceKind string

const (
	DirectSAMLSessionEvidenceProvider DirectSAMLSessionEvidenceKind = "platform_provider"
	DirectSAMLSessionEvidenceTOTP     DirectSAMLSessionEvidenceKind = "totp"
)

type DirectSAMLSessionPolicyKind string

const (
	DirectSAMLSessionPolicyLogin         DirectSAMLSessionPolicyKind = "login"
	DirectSAMLSessionPolicyAssurance     DirectSAMLSessionPolicyKind = "assurance"
	DirectSAMLSessionPolicyPlatformFloor DirectSAMLSessionPolicyKind = "platform_floor"
)

type DirectSAMLSessionRevalidationLookup struct {
	SessionID  identity.EntityID
	ObservedAt time.Time
}

func (lookup DirectSAMLSessionRevalidationLookup) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLSessionRevalidationLookup{session:%t,observed:%t,authority:direct_platform_saml}",
		lookup.SessionID != (identity.EntityID{}), !lookup.ObservedAt.IsZero(),
	)
}

func (lookup DirectSAMLSessionRevalidationLookup) GoString() string { return lookup.String() }

// DirectSAMLSessionState exposes every cardinality needed to reject a mixed
// OIDC, tenant, or ambiguous provenance graph. Persistence must not collapse
// those counts into a synthesized live flag.
type DirectSAMLSessionState struct {
	SessionID                  identity.EntityID
	RotationFamilyID           identity.EntityID
	UserID                     identity.EntityID
	ActiveTenantID             *identity.EntityID
	Authority                  string
	AuthenticationMethod       string
	Audience                   string
	PrimaryKind                string
	SAMLStateCount             int
	SAMLProvenanceCount        int
	OIDCStateCount             int
	TenantProvenanceCount      int
	ProviderEvidenceCount      int
	TOTPEvidenceCount          int
	CurrentVersion             uint64
	UserAuthenticationRevision uint64
	RecoveryRestricted         bool
	IssuedAt                   time.Time
	IdleExpiresAt              time.Time
	AbsoluteExpiresAt          time.Time
	Active                     bool
	RotationFamilyLive         bool
}

// DirectSAMLSessionAuthorityFacts carries raw pins and current rows. The
// application validates every pair and digest; adapter-produced aggregate
// booleans are additional fail-closed lifecycle evidence, never substitutes
// for the exact values.
type DirectSAMLSessionAuthorityFacts struct {
	ProviderID         identity.EntityID
	ExternalIdentityID identity.EntityID
	ProviderKind       string
	AccountMode        DirectSAMLSessionAccountMode

	PinnedProviderRevision            uint64
	CurrentProviderRevision           uint64
	PinnedLoginPolicyRevision         uint64
	CurrentLoginPolicyRevision        uint64
	PinnedConfigurationRevision       uint64
	CurrentConfigurationRevision      uint64
	PinnedSecurityRevision            uint64
	CurrentSecurityRevision           uint64
	PinnedPlanRevision                uint64
	CurrentPlanRevision               uint64
	PinnedAssurancePolicyRevision     uint64
	CurrentAssurancePolicyRevision    uint64
	PinnedMetadataRevision            uint64
	CurrentMetadataRevision           uint64
	PinnedSPKeyRevision               uint64
	CurrentSPKeyRevision              uint64
	PinnedUserAuthenticationRevision  uint64
	CurrentUserAuthenticationRevision uint64
	PinnedIdentityRevision            uint64
	CurrentIdentityRevision           uint64
	PinnedAliasKeyVersion             int16
	CurrentAliasKeyVersion            int16

	PinnedMetadataDigest       [sha256.Size]byte
	CurrentMetadataDigest      [sha256.Size]byte
	PinnedConfigurationDigest  [sha256.Size]byte
	CurrentConfigurationDigest [sha256.Size]byte

	IdentityCurrentProviderID identity.EntityID
	IdentityCurrentUserID     identity.EntityID
	AliasCurrentProviderID    identity.EntityID
	AliasCurrentIdentityID    identity.EntityID

	PinnedPlatformAuthorityID        identity.EntityID
	CurrentPlatformAuthorityID       identity.EntityID
	PinnedPlatformAuthorityRevision  uint64
	CurrentPlatformAuthorityRevision uint64
	PinnedPlatformFloorID            identity.EntityID
	CurrentPlatformFloorID           identity.EntityID
	PinnedPlatformFloorRevision      uint64
	CurrentPlatformFloorRevision     uint64

	ProviderEnabled       bool
	PlatformLoginLive     bool
	UserActive            bool
	IdentityLive          bool
	SubjectAliasLive      bool
	FactorEvidenceLive    bool
	EvidenceFresh         bool
	PolicyPinsExact       bool
	TrustEvidenceLive     bool
	ConfigurationLive     bool
	MetadataLive          bool
	SPKeyLive             bool
	PlatformAuthorityLive bool
	PlatformFloorLive     bool

	PlatformFloor identity.EffectiveAssuranceRequirement
	StepUpTOTP    *TOTPSelection
}

type DirectSAMLSessionEvidence struct {
	ID                 identity.EntityID
	UserID             identity.EntityID
	Kind               DirectSAMLSessionEvidenceKind
	Level              identity.AssuranceLevel
	PlatformProviderID *identity.EntityID
	ExternalIdentityID *identity.EntityID
	TOTPCredentialID   *identity.EntityID
	FactorRevision     *uint64
	TrustRuleID        *identity.EntityID
	TrustRuleRevision  *uint64
	AuthenticatedAt    time.Time
	ExpiresAt          *time.Time
}

type DirectSAMLSessionFactorAuthority struct {
	EvidenceID              identity.EntityID
	EvidenceUserID          identity.EntityID
	TOTPCredentialID        identity.EntityID
	PinnedSecurityRevision  uint64
	CurrentUserID           identity.EntityID
	CurrentSecurityRevision uint64
	ConfirmedAt             *time.Time
	DisabledAt              *time.Time
}

type DirectSAMLSessionTrustAuthority struct {
	EvidenceID          identity.EntityID
	TrustRuleID         identity.EntityID
	PinnedRevision      uint64
	CurrentProviderID   identity.EntityID
	CurrentProviderKind string
	CurrentRevision     uint64
	CurrentLevel        identity.AssuranceLevel
	Enabled             bool
	RetiredAt           *time.Time
}

type DirectSAMLSessionPolicyPin struct {
	Kind     DirectSAMLSessionPolicyKind
	ID       identity.EntityID
	Revision uint64
}

type DirectSAMLSessionRevalidationSnapshot struct {
	Session           DirectSAMLSessionState
	Authority         DirectSAMLSessionAuthorityFacts
	Evidence          []DirectSAMLSessionEvidence
	FactorAuthorities []DirectSAMLSessionFactorAuthority
	TrustAuthorities  []DirectSAMLSessionTrustAuthority
	PolicyPins        []DirectSAMLSessionPolicyPin
}

func (snapshot DirectSAMLSessionRevalidationSnapshot) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLSessionRevalidationSnapshot{session:%t,user:%t,provider:%t,identity:%t,version:%t,evidence:%d,factors:%d,trust:%d,policies:%d,authority:direct_platform_saml,material:[REDACTED]}",
		snapshot.Session.SessionID != (identity.EntityID{}), snapshot.Session.UserID != (identity.EntityID{}),
		snapshot.Authority.ProviderID != (identity.EntityID{}), snapshot.Authority.ExternalIdentityID != (identity.EntityID{}),
		snapshot.Session.CurrentVersion != 0, len(snapshot.Evidence), len(snapshot.FactorAuthorities),
		len(snapshot.TrustAuthorities), len(snapshot.PolicyPins),
	)
}

func (snapshot DirectSAMLSessionRevalidationSnapshot) GoString() string { return snapshot.String() }

type DirectSAMLSessionRevalidationRequestDigest [sha256.Size]byte

type DirectSAMLSessionRevalidationCommand struct {
	SessionID       identity.EntityID
	ExpectedVersion uint64
	RequestDigest   DirectSAMLSessionRevalidationRequestDigest
	Decision        mfa.SessionDecision
	Reason          mfa.SessionReason
	ObservedAt      time.Time
	Session         mfa.SessionReservation
	Continuation    ContinuationReservation
	Audit           AuditContext
}

func (command DirectSAMLSessionRevalidationCommand) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLSessionRevalidationCommand{session:%t,expectedVersion:%t,decision:%q,reason:%q,observed:%t,audit:%q,authority:direct_platform_saml,material:[REDACTED]}",
		command.SessionID != (identity.EntityID{}), command.ExpectedVersion != 0,
		command.Decision, command.Reason, !command.ObservedAt.IsZero(), command.Audit.String(),
	)
}

func (command DirectSAMLSessionRevalidationCommand) GoString() string { return command.String() }

type DirectSAMLSessionRevalidationCategory string

const (
	DirectSAMLSessionRevalidationSuccess        DirectSAMLSessionRevalidationCategory = "success"
	DirectSAMLSessionRevalidationAlreadyApplied DirectSAMLSessionRevalidationCategory = "already_applied"
	DirectSAMLSessionRevalidationStale          DirectSAMLSessionRevalidationCategory = "stale"
	DirectSAMLSessionRevalidationReplay         DirectSAMLSessionRevalidationCategory = "replay"
)

type DirectSAMLSessionRevalidationResult struct {
	Applied         bool
	Category        DirectSAMLSessionRevalidationCategory
	Decision        mfa.SessionDecision
	SessionID       identity.EntityID
	UserID          identity.EntityID
	ExpectedVersion uint64
	NewVersion      uint64
	NewSessionID    identity.EntityID
	ContinuationID  identity.EntityID
	AppliedAt       time.Time
}

func (result DirectSAMLSessionRevalidationResult) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLSessionRevalidationResult{applied:%t,category:%q,decision:%q,session:%t,user:%t,expectedVersion:%t,newVersion:%t,newSession:%t,continuation:%t,appliedAt:%t,authority:direct_platform_saml}",
		result.Applied, result.Category, result.Decision,
		result.SessionID != (identity.EntityID{}), result.UserID != (identity.EntityID{}),
		result.ExpectedVersion != 0, result.NewVersion != 0,
		result.NewSessionID != (identity.EntityID{}), result.ContinuationID != (identity.EntityID{}),
		!result.AppliedAt.IsZero(),
	)
}

func (result DirectSAMLSessionRevalidationResult) GoString() string { return result.String() }

type DirectSAMLSessionRevalidationRecoveryLookup struct {
	Command DirectSAMLSessionRevalidationCommand
}

type DirectSAMLSessionRevalidationRecoveryResult struct {
	Matched bool
	Result  DirectSAMLSessionRevalidationResult
}

type DirectSAMLSessionRevalidationCleanup struct {
	Command     DirectSAMLSessionRevalidationCommand
	Result      DirectSAMLSessionRevalidationResult
	Reason      CleanupReason
	CleanedUpAt time.Time
	Audit       AuditContext
}

func (cleanup DirectSAMLSessionRevalidationCleanup) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLSessionRevalidationCleanup{command:%q,result:%q,reason:%q,cleaned:%t,audit:%q,authority:direct_platform_saml,material:[REDACTED]}",
		cleanup.Command.String(), cleanup.Result.String(), cleanup.Reason,
		!cleanup.CleanedUpAt.IsZero(), cleanup.Audit.String(),
	)
}

func (cleanup DirectSAMLSessionRevalidationCleanup) GoString() string { return cleanup.String() }

// DirectSAMLSessionRevalidationStore is physically and semantically separate
// from direct OIDC and tenant federation. Recovery is read-only over the exact
// command; cleanup can revoke only the exact successor represented by Result.
type DirectSAMLSessionRevalidationStore interface {
	LoadDirectSAMLSessionForRevalidation(
		context.Context,
		DirectSAMLSessionRevalidationLookup,
	) (DirectSAMLSessionRevalidationSnapshot, error)
	ApplyDirectSAMLSessionRevalidation(
		context.Context,
		DirectSAMLSessionRevalidationCommand,
	) (DirectSAMLSessionRevalidationResult, error)
	RecoverDirectSAMLSessionRevalidationApply(
		context.Context,
		DirectSAMLSessionRevalidationRecoveryLookup,
	) (DirectSAMLSessionRevalidationRecoveryResult, error)
	CleanupDirectSAMLSessionRevalidationDelivery(
		context.Context,
		DirectSAMLSessionRevalidationCleanup,
	) error
}
