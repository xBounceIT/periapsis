// Package platformoidcauth contains the deny-by-default application model for
// direct authentication through a platform-owned OIDC provider. Persistence,
// protocol verification, HTTP, and credential issuance remain adapter concerns.
package platformoidcauth

import (
	"errors"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

const maximumExactRevision int64 = 9_007_199_254_740_991

var ErrTenantSwitchDenied = errors.New("platform OIDC tenant switch denied")

type AccountMode string

const (
	AccountModeExistingIdentity AccountMode = "existing_identity"
)

// ExactRevision couples a revision pinned by the source session to the row
// revision observed while the switch transaction holds its authority locks.
type ExactRevision struct {
	Pinned  int64
	Current int64
}

// PlatformSessionAuthority is the complete primary-authority gate for a direct
// platform-provider session. ActiveTenantID must be nil: tenant-scoped sessions
// use a different provenance family and cannot enter this switch path.
type PlatformSessionAuthority struct {
	SessionID             uuid.UUID
	RotationFamilyID      uuid.UUID
	UserID                uuid.UUID
	ProviderID            uuid.UUID
	ExternalIdentityID    uuid.UUID
	ActiveTenantID        *uuid.UUID
	AuthenticationMethod  string
	PrimaryKind           string
	DirectStateCount      int
	DirectProvenanceCount int
	TenantProvenanceCount int
	ExpectedVersion       int64
	CurrentVersion        int64
	IdleExpiresAt         time.Time
	AbsoluteExpiresAt     time.Time
	SessionActive         bool
	RotationFamilyLive    bool
	UserActive            bool
	ProviderEnabled       bool
	PlatformLoginLive     bool
	AccountMode           AccountMode
	IdentityLive          bool
	SubjectAliasLive      bool
	Revisions             PlatformSessionRevisions
}

// PlatformSessionRevisions are the primary facts whose drift invalidates a
// direct platform-provider session before any target-tenant authority is read.
type PlatformSessionRevisions struct {
	Provider         ExactRevision
	Security         ExactRevision
	PlatformLogin    ExactRevision
	ExternalIdentity ExactRevision
	SubjectAliasKey  ExactRevision
}

type LiveTenant struct {
	ID      uuid.UUID
	Version int64
	Active  bool
}

type LiveMembership struct {
	ID       uuid.UUID
	TenantID uuid.UUID
	UserID   uuid.UUID
	Active   bool
}

type LivePlatformBinding struct {
	ID                    uuid.UUID
	TenantID              uuid.UUID
	ProviderID            uuid.UUID
	Version               int64
	MappingRevision       int64
	AuthorizationRevision int64
	CurrentAccessEpochID  uuid.UUID
	Enabled               bool
}

type LiveAccessEpoch struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	BindingID  uuid.UUID
	ProviderID uuid.UUID
	SourceID   uuid.UUID
	Version    int64
	Live       bool
}

type LiveAccessSource struct {
	ID               uuid.UUID
	TenantID         uuid.UUID
	PlatformProvider bool
	Authoritative    bool
	Live             bool
}

type LiveExternalIdentity struct {
	ID         uuid.UUID
	ProviderID uuid.UUID
	UserID     uuid.UUID
	Version    int64
	Live       bool
}

type LiveSubjectAlias struct {
	ExternalIdentityID uuid.UUID
	KeyVersion         int64
	Live               bool
}

type LiveAccessGrant struct {
	ID                 uuid.UUID
	TenantID           uuid.UUID
	ProviderID         uuid.UUID
	BindingID          uuid.UUID
	AccessEpochID      uuid.UUID
	AccessSourceID     uuid.UUID
	ExternalIdentityID uuid.UUID
	MembershipID       uuid.UUID
	UserID             uuid.UUID
	Version            int64
	Live               bool
}

// TargetTenantAuthority is a transactionally loaded, tenant-qualified graph.
// The planner verifies every edge instead of trusting a permissive or partial
// join assembled by an adapter.
type TargetTenantAuthority struct {
	TenantExecutionLive bool
	Tenant              LiveTenant
	Membership          LiveMembership
	Binding             LivePlatformBinding
	AccessEpoch         LiveAccessEpoch
	AccessSource        LiveAccessSource
	ExternalIdentity    LiveExternalIdentity
	SubjectAlias        LiveSubjectAlias
	AccessGrant         LiveAccessGrant
}

type TenantSwitchSnapshot struct {
	Source PlatformSessionAuthority
	Target TargetTenantAuthority
}

// TenantSwitchAdmission is safe to pass to assurance evaluation and the
// atomic session-rotation adapter. It contains only exact IDs and revisions;
// it grants no authority by itself.
type TenantSwitchAdmission struct {
	SourceSessionID        uuid.UUID
	RotationFamilyID       uuid.UUID
	ExpectedSessionVersion int64
	UserID                 uuid.UUID
	ProviderID             uuid.UUID
	ExternalIdentityID     uuid.UUID
	TargetTenantID         uuid.UUID
	MembershipID           uuid.UUID
	BindingID              uuid.UUID
	AccessEpochID          uuid.UUID
	AccessSourceID         uuid.UUID
	AccessGrantID          uuid.UUID
	AbsoluteExpiresAt      time.Time
	ProviderRevision       int64
	SecurityRevision       int64
	PlatformLoginRevision  int64
	IdentityRevision       int64
	SubjectAliasKeyVersion int64
	TenantVersion          int64
	BindingVersion         int64
	MappingRevision        int64
	AuthorizationRevision  int64
	AccessEpochVersion     int64
	AccessGrantVersion     int64
}

// PlanTenantSwitchAdmission validates the source CAS and the complete live
// provider/binding/identity/grant graph. MFA and trusted-IdP evidence must be
// evaluated after this gate and before consuming the returned admission.
func PlanTenantSwitchAdmission(
	now time.Time,
	snapshot TenantSwitchSnapshot,
) (TenantSwitchAdmission, error) {
	if !validInstant(now) || !validSource(now, snapshot.Source) ||
		!validTarget(snapshot.Source, snapshot.Target) {
		return TenantSwitchAdmission{}, ErrTenantSwitchDenied
	}

	return TenantSwitchAdmission{
		SourceSessionID:        snapshot.Source.SessionID,
		RotationFamilyID:       snapshot.Source.RotationFamilyID,
		ExpectedSessionVersion: snapshot.Source.ExpectedVersion,
		UserID:                 snapshot.Source.UserID,
		ProviderID:             snapshot.Source.ProviderID,
		ExternalIdentityID:     snapshot.Source.ExternalIdentityID,
		TargetTenantID:         snapshot.Target.Tenant.ID,
		MembershipID:           snapshot.Target.Membership.ID,
		BindingID:              snapshot.Target.Binding.ID,
		AccessEpochID:          snapshot.Target.AccessEpoch.ID,
		AccessSourceID:         snapshot.Target.AccessSource.ID,
		AccessGrantID:          snapshot.Target.AccessGrant.ID,
		AbsoluteExpiresAt:      snapshot.Source.AbsoluteExpiresAt,
		ProviderRevision:       snapshot.Source.Revisions.Provider.Current,
		SecurityRevision:       snapshot.Source.Revisions.Security.Current,
		PlatformLoginRevision:  snapshot.Source.Revisions.PlatformLogin.Current,
		IdentityRevision:       snapshot.Target.ExternalIdentity.Version,
		SubjectAliasKeyVersion: snapshot.Target.SubjectAlias.KeyVersion,
		TenantVersion:          snapshot.Target.Tenant.Version,
		BindingVersion:         snapshot.Target.Binding.Version,
		MappingRevision:        snapshot.Target.Binding.MappingRevision,
		AuthorizationRevision:  snapshot.Target.Binding.AuthorizationRevision,
		AccessEpochVersion:     snapshot.Target.AccessEpoch.Version,
		AccessGrantVersion:     snapshot.Target.AccessGrant.Version,
	}, nil
}

// TenantSwitchAssuranceSatisfied evaluates the exact direct provider proof
// against the target tenant's pinned policy. A platform-account TOTP is not a
// tenant-owned factor and cannot be copied into tenant session provenance, so
// local-required policies fail closed until the tenant-local step-up flow is
// completed. This also prevents a stronger local TOTP from being relabeled as
// provider assurance during the switch.
func TenantSwitchAssuranceSatisfied(
	now time.Time,
	admission TenantSwitchAdmission,
	evidence []DirectSessionEvidence,
	requirement identity.EffectiveAssuranceRequirement,
) bool {
	if !validInstant(now) || requirement.LocalRequired ||
		!validTenantSwitchAdmission(admission, now) ||
		len(evidence) < 1 || len(evidence) > 2 {
		return false
	}

	normalized := make([]identity.AssuranceEvidence, 0, 1)
	providerCount, localCount := 0, 0
	seen := make(map[uuid.UUID]struct{}, len(evidence))
	for index, proof := range evidence {
		if !validUUIDv7(proof.ID) || !validUUIDv7(proof.UserID) || proof.UserID != admission.UserID ||
			!validDirectSessionEvidenceLevel(proof.Level) || !validInstant(proof.AuthenticatedAt) ||
			!validOptionalDirectSessionInstant(proof.ExpiresAt) ||
			proof.ExpiresAt != nil && !proof.ExpiresAt.After(proof.AuthenticatedAt) ||
			index > 0 && !directSessionEvidenceLess(evidence[index-1], proof) {
			return false
		}
		if _, duplicate := seen[proof.ID]; duplicate {
			return false
		}
		seen[proof.ID] = struct{}{}

		candidate := identity.AssuranceEvidence{
			Level: proof.Level, Kind: identity.AssuranceEvidenceFactor,
			AuthenticatedAt: proof.AuthenticatedAt,
			ExpiresAt:       cloneDirectSessionTime(proof.ExpiresAt),
		}
		switch proof.Kind {
		case DirectSessionEvidencePlatformProvider:
			providerCount++
			if proof.PlatformProviderID == nil || proof.ExternalIdentityID == nil ||
				*proof.PlatformProviderID != admission.ProviderID ||
				*proof.ExternalIdentityID != admission.ExternalIdentityID ||
				proof.TOTPCredentialID != nil || proof.FactorRevision != nil {
				return false
			}
			trusted := proof.Level != identity.AssurancePrimary
			if trusted != (proof.TrustRuleID != nil && proof.TrustRuleRevision != nil) ||
				trusted && (!validUUIDv7(*proof.TrustRuleID) || !validRevision(*proof.TrustRuleRevision)) {
				return false
			}
			candidate.Source = identity.AssuranceSource{
				DirectPlatform: true,
				ProviderID:     identity.EntityID(admission.ProviderID),
			}
			if trusted {
				candidate.TrustRuleRevision = cloneDirectSessionInt64(proof.TrustRuleRevision)
			} else {
				// The persisted primary row has no selected elevated trust rule;
				// its baseline provider authority is the exact security revision.
				revision := admission.SecurityRevision
				candidate.TrustRuleRevision = &revision
			}
			normalized = append(normalized, candidate)
		case DirectSessionEvidenceTOTP:
			localCount++
			if proof.Level != identity.AssuranceMFA || proof.PlatformProviderID != nil ||
				proof.ExternalIdentityID != nil || proof.TOTPCredentialID == nil ||
				proof.FactorRevision == nil || !validUUIDv7(*proof.TOTPCredentialID) ||
				!validRevision(*proof.FactorRevision) || proof.TrustRuleID != nil ||
				proof.TrustRuleRevision != nil {
				return false
			}
		default:
			return false
		}
	}
	if providerCount != 1 || localCount > 1 {
		return false
	}
	return identity.EvaluateAssurance(now, requirement, normalized, false) ==
		identity.AssuranceSatisfied
}

func validTenantSwitchAdmission(value TenantSwitchAdmission, now time.Time) bool {
	identifiers := [...]uuid.UUID{
		value.SourceSessionID, value.RotationFamilyID, value.UserID,
		value.ProviderID, value.ExternalIdentityID, value.TargetTenantID,
		value.MembershipID, value.BindingID, value.AccessEpochID,
		value.AccessSourceID, value.AccessGrantID,
	}
	seen := make(map[uuid.UUID]struct{}, len(identifiers))
	for _, identifier := range identifiers {
		if !validUUIDv7(identifier) {
			return false
		}
		if _, duplicate := seen[identifier]; duplicate {
			return false
		}
		seen[identifier] = struct{}{}
	}
	revisions := [...]int64{
		value.ExpectedSessionVersion, value.ProviderRevision,
		value.SecurityRevision, value.PlatformLoginRevision,
		value.IdentityRevision, value.SubjectAliasKeyVersion,
		value.TenantVersion, value.BindingVersion, value.MappingRevision,
		value.AuthorizationRevision, value.AccessEpochVersion,
		value.AccessGrantVersion,
	}
	for _, revision := range revisions {
		if !validRevision(revision) {
			return false
		}
	}
	return validInstant(value.AbsoluteExpiresAt) && now.Before(value.AbsoluteExpiresAt)
}

func validSource(now time.Time, value PlatformSessionAuthority) bool {
	return validUUIDv7(value.SessionID) && validUUIDv7(value.RotationFamilyID) &&
		value.SessionID != value.RotationFamilyID && validUUIDv7(value.UserID) &&
		validUUIDv7(value.ProviderID) && validUUIDv7(value.ExternalIdentityID) &&
		value.ActiveTenantID == nil && value.AuthenticationMethod == "oidc" &&
		value.PrimaryKind == "platform_provider" && value.DirectStateCount == 1 &&
		value.DirectProvenanceCount == 1 && value.TenantProvenanceCount == 0 &&
		validRevision(value.ExpectedVersion) &&
		value.ExpectedVersion == value.CurrentVersion &&
		validInstant(value.IdleExpiresAt) && validInstant(value.AbsoluteExpiresAt) &&
		now.Before(value.IdleExpiresAt) && now.Before(value.AbsoluteExpiresAt) &&
		!value.IdleExpiresAt.After(value.AbsoluteExpiresAt) && value.SessionActive &&
		value.RotationFamilyLive && value.UserActive && value.ProviderEnabled &&
		value.PlatformLoginLive && validAccountMode(value.AccountMode) &&
		value.IdentityLive && value.SubjectAliasLive &&
		validExactRevision(value.Revisions.Provider) &&
		validExactRevision(value.Revisions.Security) &&
		validExactRevision(value.Revisions.PlatformLogin) &&
		validExactRevision(value.Revisions.ExternalIdentity) &&
		validExactRevision(value.Revisions.SubjectAliasKey)
}

func validTarget(source PlatformSessionAuthority, value TargetTenantAuthority) bool {
	if !value.TenantExecutionLive || !validUUIDv7(value.Tenant.ID) ||
		!validRevision(value.Tenant.Version) || !value.Tenant.Active ||
		!validUUIDv7(value.Membership.ID) || !value.Membership.Active ||
		value.Membership.TenantID != value.Tenant.ID || value.Membership.UserID != source.UserID ||
		!validUUIDv7(value.Binding.ID) || !validRevision(value.Binding.Version) || !value.Binding.Enabled ||
		value.Binding.TenantID != value.Tenant.ID || value.Binding.ProviderID != source.ProviderID ||
		!validRevision(value.Binding.MappingRevision) ||
		!validRevision(value.Binding.AuthorizationRevision) ||
		!validUUIDv7(value.Binding.CurrentAccessEpochID) {
		return false
	}
	if !validUUIDv7(value.AccessEpoch.ID) || !validRevision(value.AccessEpoch.Version) ||
		!value.AccessEpoch.Live || value.AccessEpoch.TenantID != value.Tenant.ID ||
		value.AccessEpoch.BindingID != value.Binding.ID || value.AccessEpoch.ID != value.Binding.CurrentAccessEpochID ||
		value.AccessEpoch.ProviderID != source.ProviderID ||
		!validUUIDv7(value.AccessEpoch.SourceID) {
		return false
	}
	if value.AccessSource.ID != value.AccessEpoch.SourceID || !value.AccessSource.Live ||
		value.AccessSource.TenantID != value.Tenant.ID || !value.AccessSource.PlatformProvider ||
		!value.AccessSource.Authoritative {
		return false
	}
	if value.ExternalIdentity.ID != source.ExternalIdentityID ||
		value.ExternalIdentity.ProviderID != source.ProviderID ||
		value.ExternalIdentity.UserID != source.UserID || !value.ExternalIdentity.Live ||
		!validRevision(value.ExternalIdentity.Version) ||
		value.ExternalIdentity.Version != source.Revisions.ExternalIdentity.Current {
		return false
	}
	if value.SubjectAlias.ExternalIdentityID != source.ExternalIdentityID ||
		!value.SubjectAlias.Live || !validRevision(value.SubjectAlias.KeyVersion) ||
		value.SubjectAlias.KeyVersion != source.Revisions.SubjectAliasKey.Current {
		return false
	}
	grant := value.AccessGrant
	return validUUIDv7(grant.ID) && validRevision(grant.Version) && grant.Live &&
		grant.TenantID == value.Tenant.ID && grant.ProviderID == source.ProviderID &&
		grant.BindingID == value.Binding.ID && grant.AccessEpochID == value.AccessEpoch.ID &&
		grant.AccessSourceID == value.AccessSource.ID &&
		grant.ExternalIdentityID == source.ExternalIdentityID &&
		grant.MembershipID == value.Membership.ID && grant.UserID == source.UserID
}

func validExactRevision(value ExactRevision) bool {
	return validRevision(value.Pinned) && value.Pinned == value.Current
}

func validAccountMode(value AccountMode) bool {
	return value == AccountModeExistingIdentity
}

func validRevision(value int64) bool {
	return value > 0 && value <= maximumExactRevision
}

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC &&
		value.Year() >= 1970 && value.Year() <= 9999 &&
		value.Nanosecond()%int(time.Microsecond) == 0
}
