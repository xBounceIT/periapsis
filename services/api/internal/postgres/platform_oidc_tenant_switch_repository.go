package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

const (
	loadPlatformOIDCTenantSwitchSQL         = `select app.load_platform_oidc_tenant_switch_v1($1::jsonb)`
	applyPlatformOIDCTenantSwitchSQL        = `select app.apply_platform_oidc_tenant_switch_v1($1::jsonb)`
	lookupPlatformOIDCTenantSwitchReplaySQL = `select app.lookup_platform_oidc_tenant_switch_replay_v1($1::jsonb)`
	loadPlatformSAMLTenantSwitchSQL         = `select app.load_platform_saml_tenant_switch_v1($1::jsonb)`
	applyPlatformSAMLTenantSwitchSQL        = `select app.apply_platform_saml_tenant_switch_v1($1::jsonb)`
	lookupPlatformSAMLTenantSwitchReplaySQL = `select app.lookup_platform_saml_tenant_switch_replay_v1($1::jsonb)`

	platformOIDCTenantSwitchAuditAction = "tenant_switch.apply"
	platformSAMLTenantSwitchAuditAction = "tenant_switch.saml.apply"

	maximumPlatformOIDCTenantSwitchLookupBytes   = 8 * 1024
	maximumPlatformOIDCTenantSwitchReplayBytes   = 32 * 1024
	maximumPlatformOIDCTenantSwitchCommandBytes  = 256 * 1024
	maximumPlatformOIDCTenantSwitchResponseBytes = 64 * 1024
	maximumPlatformOIDCTenantSwitchDatabaseCount = int64(2_147_483_647)
	platformOIDCTenantSwitchRecoveryTimeout      = 2 * time.Second
)

type platformOIDCTenantSwitchLookupWire struct {
	SourceSessionID string    `json:"sourceSessionId"`
	TargetTenantID  string    `json:"targetTenantId"`
	ObservedAt      time.Time `json:"observedAt"`
}

type platformOIDCTenantSwitchSourceRevisionsWire struct {
	Provider         platformOIDCDirectExactRevisionWire `json:"provider"`
	Security         platformOIDCDirectExactRevisionWire `json:"security"`
	PlatformLogin    platformOIDCDirectExactRevisionWire `json:"platformLogin"`
	ExternalIdentity platformOIDCDirectExactRevisionWire `json:"externalIdentity"`
	SubjectAliasKey  platformOIDCDirectExactRevisionWire `json:"subjectAliasKey"`
}

type platformOIDCTenantSwitchSourceWire struct {
	SessionID             string                                      `json:"sessionId"`
	RotationFamilyID      string                                      `json:"rotationFamilyId"`
	UserID                string                                      `json:"userId"`
	ProviderID            string                                      `json:"providerId"`
	ExternalIdentityID    string                                      `json:"externalIdentityId"`
	ActiveTenantID        json.RawMessage                             `json:"activeTenantId"`
	AuthenticationMethod  string                                      `json:"authenticationMethod"`
	PrimaryKind           string                                      `json:"primaryKind"`
	DirectStateCount      int                                         `json:"directStateCount"`
	DirectProvenanceCount int                                         `json:"directProvenanceCount"`
	TenantProvenanceCount int                                         `json:"tenantProvenanceCount"`
	ExpectedVersion       int64                                       `json:"expectedVersion"`
	CurrentVersion        int64                                       `json:"currentVersion"`
	IdleExpiresAt         time.Time                                   `json:"idleExpiresAt"`
	AbsoluteExpiresAt     time.Time                                   `json:"absoluteExpiresAt"`
	SessionActive         *bool                                       `json:"sessionActive"`
	RotationFamilyLive    *bool                                       `json:"rotationFamilyLive"`
	UserActive            *bool                                       `json:"userActive"`
	ProviderEnabled       *bool                                       `json:"providerEnabled"`
	PlatformLoginLive     *bool                                       `json:"platformLoginLive"`
	AccountMode           string                                      `json:"accountMode"`
	IdentityLive          *bool                                       `json:"identityLive"`
	SubjectAliasLive      *bool                                       `json:"subjectAliasLive"`
	Revisions             platformOIDCTenantSwitchSourceRevisionsWire `json:"revisions"`
}

type platformOIDCTenantSwitchAssuranceWire struct {
	Level           string                                  `json:"level"`
	AuthenticatedAt time.Time                               `json:"authenticatedAt"`
	ExpiresAt       json.RawMessage                         `json:"expiresAt"`
	LocalSatisfied  *bool                                   `json:"localSatisfied"`
	Evidence        []platformOIDCDirectSessionEvidenceWire `json:"evidence"`
}

type platformOIDCTenantSwitchTenantWire struct {
	ID      string `json:"id"`
	Version int64  `json:"version"`
	Active  *bool  `json:"active"`
}

type platformOIDCTenantSwitchMembershipWire struct {
	ID       string `json:"id"`
	TenantID string `json:"tenantId"`
	UserID   string `json:"userId"`
	Active   *bool  `json:"active"`
}

type platformOIDCTenantSwitchBindingWire struct {
	ID                    string `json:"id"`
	TenantID              string `json:"tenantId"`
	ProviderID            string `json:"providerId"`
	Version               int64  `json:"version"`
	MappingRevision       int64  `json:"mappingRevision"`
	AuthorizationRevision int64  `json:"authorizationRevision"`
	CurrentAccessEpochID  string `json:"currentAccessEpochId"`
	Enabled               *bool  `json:"enabled"`
}

type platformOIDCTenantSwitchAccessEpochWire struct {
	ID         string `json:"id"`
	TenantID   string `json:"tenantId"`
	BindingID  string `json:"bindingId"`
	ProviderID string `json:"providerId"`
	SourceID   string `json:"sourceId"`
	Version    int64  `json:"version"`
	Live       *bool  `json:"live"`
}

type platformOIDCTenantSwitchAccessSourceWire struct {
	ID               string `json:"id"`
	TenantID         string `json:"tenantId"`
	PlatformProvider *bool  `json:"platformProvider"`
	Authoritative    *bool  `json:"authoritative"`
	Live             *bool  `json:"live"`
}

type platformOIDCTenantSwitchExternalIdentityWire struct {
	ID         string `json:"id"`
	ProviderID string `json:"providerId"`
	UserID     string `json:"userId"`
	Version    int64  `json:"version"`
	Live       *bool  `json:"live"`
}

type platformOIDCTenantSwitchSubjectAliasWire struct {
	ExternalIdentityID string `json:"externalIdentityId"`
	KeyVersion         int64  `json:"keyVersion"`
	Live               *bool  `json:"live"`
}

type platformOIDCTenantSwitchAccessGrantWire struct {
	ID                 string `json:"id"`
	TenantID           string `json:"tenantId"`
	ProviderID         string `json:"providerId"`
	BindingID          string `json:"bindingId"`
	AccessEpochID      string `json:"accessEpochId"`
	AccessSourceID     string `json:"accessSourceId"`
	ExternalIdentityID string `json:"externalIdentityId"`
	MembershipID       string `json:"membershipId"`
	UserID             string `json:"userId"`
	Version            int64  `json:"version"`
	Live               *bool  `json:"live"`
}

type platformOIDCTenantSwitchMFASubjectWire struct {
	Version                  int64 `json:"version"`
	IdentityEpoch            int64 `json:"identityEpoch"`
	SessionInvalidationEpoch int64 `json:"sessionInvalidationEpoch"`
}

type platformOIDCTenantSwitchTargetWire struct {
	TenantExecutionLive *bool                                        `json:"tenantExecutionLive"`
	Tenant              platformOIDCTenantSwitchTenantWire           `json:"tenant"`
	Membership          platformOIDCTenantSwitchMembershipWire       `json:"membership"`
	Binding             platformOIDCTenantSwitchBindingWire          `json:"binding"`
	AccessEpoch         platformOIDCTenantSwitchAccessEpochWire      `json:"accessEpoch"`
	AccessSource        platformOIDCTenantSwitchAccessSourceWire     `json:"accessSource"`
	ExternalIdentity    platformOIDCTenantSwitchExternalIdentityWire `json:"externalIdentity"`
	SubjectAlias        platformOIDCTenantSwitchSubjectAliasWire     `json:"subjectAlias"`
	AccessGrant         platformOIDCTenantSwitchAccessGrantWire      `json:"accessGrant"`
	MFASubject          platformOIDCTenantSwitchMFASubjectWire       `json:"mfaSubject"`
}

type platformOIDCTenantSwitchLoadWire struct {
	Source      platformOIDCTenantSwitchSourceWire     `json:"source"`
	Assurance   *platformOIDCTenantSwitchAssuranceWire `json:"assurance"`
	Target      platformOIDCTenantSwitchTargetWire     `json:"target"`
	CommandPins json.RawMessage                        `json:"commandPins"`
}

type platformOIDCTenantSwitchCommandPinsWire struct {
	TenantID                 string          `json:"tenantId"`
	TenantVersion            int64           `json:"tenantVersion"`
	MembershipID             string          `json:"membershipId"`
	MFASubjectVersion        int64           `json:"mfaSubjectVersion"`
	IdentityEpoch            int64           `json:"identityEpoch"`
	SessionInvalidationEpoch int64           `json:"sessionInvalidationEpoch"`
	BindingID                string          `json:"bindingId"`
	BindingVersion           int64           `json:"bindingVersion"`
	MappingRevision          int64           `json:"mappingRevision"`
	AuthorizationRevision    int64           `json:"authorizationRevision"`
	AccessEpochID            string          `json:"accessEpochId"`
	AccessEpochVersion       int64           `json:"accessEpochVersion"`
	AccessSourceID           string          `json:"accessSourceId"`
	AccessGrantID            string          `json:"accessGrantId"`
	AccessGrantVersion       int64           `json:"accessGrantVersion"`
	PlatformProviderID       string          `json:"platformProviderId"`
	ProviderRevision         int64           `json:"providerRevision"`
	SecurityRevision         int64           `json:"securityRevision"`
	ExternalIdentityID       string          `json:"externalIdentityId"`
	IdentityVersion          int64           `json:"identityVersion"`
	AliasKeyVersion          int64           `json:"aliasKeyVersion"`
	PolicySnapshot           json.RawMessage `json:"policySnapshot"`
}

type platformOIDCTenantSwitchPolicySnapshotWire struct {
	PolicyContext policyContextWire        `json:"policyContext"`
	Policies      []scopedPolicyWire       `json:"policies"`
	Requirement   assuranceRequirementWire `json:"requirement"`
}

type platformOIDCTenantSwitchSessionWire struct {
	ID                 string    `json:"id"`
	RotationFamilyID   string    `json:"rotationFamilyId"`
	TokenDigest        []byte    `json:"tokenDigest"`
	CSRFSecretDigest   []byte    `json:"csrfSecretDigest"`
	Audience           string    `json:"audience"`
	IdleExpiresAt      time.Time `json:"idleExpiresAt"`
	AbsoluteExpiresAt  time.Time `json:"absoluteExpiresAt"`
	SessionVersion     int64     `json:"sessionVersion"`
	RecoveryRestricted bool      `json:"recoveryRestricted"`
}

type platformOIDCTenantSwitchReplayLookupWire struct {
	SourceSessionID   string                      `json:"sourceSessionId"`
	TargetTenantID    string                      `json:"targetTenantId"`
	NewSessionID      string                      `json:"newSessionId"`
	RotationFamilyID  string                      `json:"rotationFamilyId"`
	SourceTokenDigest []byte                      `json:"sourceTokenDigest"`
	NewTokenDigest    []byte                      `json:"newTokenDigest"`
	CSRFSecretDigest  []byte                      `json:"csrfSecretDigest"`
	OccurredAt        time.Time                   `json:"occurredAt"`
	IdleExpiresAt     time.Time                   `json:"idleExpiresAt"`
	AbsoluteExpiresAt time.Time                   `json:"absoluteExpiresAt"`
	Audit             platformOIDCDirectAuditWire `json:"audit"`
}

type platformOIDCTenantSwitchApplyWire struct {
	SourceSessionID      string                                  `json:"sourceSessionId"`
	ExpectedVersion      int64                                   `json:"expectedVersion"`
	AuthenticationMethod string                                  `json:"authenticationMethod,omitempty"`
	Target               platformOIDCTenantSwitchCommandPinsWire `json:"target"`
	RequestDigest        []byte                                  `json:"requestDigest,omitempty"`
	Decision             string                                  `json:"decision"`
	Session              platformOIDCTenantSwitchSessionWire     `json:"session"`
	ObservedAt           time.Time                               `json:"observedAt"`
	Audit                platformOIDCDirectAuditWire             `json:"audit"`
}

type platformOIDCTenantSwitchApplyResultWire struct {
	Applied         *bool  `json:"applied"`
	Category        string `json:"category,omitempty"`
	Decision        string `json:"decision,omitempty"`
	SourceSessionID string `json:"sourceSessionId,omitempty"`
	SessionID       string `json:"sessionId,omitempty"`
	TargetTenantID  string `json:"targetTenantId,omitempty"`
	SessionVersion  int64  `json:"sessionVersion,omitempty"`
}

type platformOIDCTenantSwitchReplayResultWire struct {
	Matched *bool                                    `json:"matched"`
	Result  *platformOIDCTenantSwitchApplyResultWire `json:"result,omitempty"`
}

func (value *platformOIDCTenantSwitchReplayResultWire) UnmarshalJSON(encoded []byte) error {
	if value == nil {
		return errFederatedAuthPersistence
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return errFederatedAuthPersistence
	}
	var matched *bool
	if raw, present := fields["matched"]; !present || json.Unmarshal(raw, &matched) != nil || matched == nil {
		return errFederatedAuthPersistence
	}
	if !*matched {
		if len(fields) != 1 {
			return errFederatedAuthPersistence
		}
		*value = platformOIDCTenantSwitchReplayResultWire{Matched: tenantSwitchBool(false)}
		return nil
	}
	if len(fields) != 2 {
		return errFederatedAuthPersistence
	}
	var result *platformOIDCTenantSwitchApplyResultWire
	if raw, present := fields["result"]; !present || json.Unmarshal(raw, &result) != nil || result == nil {
		return errFederatedAuthPersistence
	}
	*value = platformOIDCTenantSwitchReplayResultWire{Matched: tenantSwitchBool(true), Result: result}
	return nil
}

func (value *platformOIDCTenantSwitchApplyResultWire) UnmarshalJSON(encoded []byte) error {
	if value == nil {
		return errFederatedAuthPersistence
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return errFederatedAuthPersistence
	}
	var applied *bool
	if raw, present := fields["applied"]; !present || json.Unmarshal(raw, &applied) != nil || applied == nil {
		return errFederatedAuthPersistence
	}
	if !*applied {
		if len(fields) != 2 {
			return errFederatedAuthPersistence
		}
		var category string
		if raw, present := fields["category"]; !present || json.Unmarshal(raw, &category) != nil ||
			(category != "stale" && category != "denied") {
			return errFederatedAuthPersistence
		}
		*value = platformOIDCTenantSwitchApplyResultWire{Applied: tenantSwitchBool(false), Category: category}
		return nil
	}
	if len(fields) != 6 {
		return errFederatedAuthPersistence
	}
	decoded := platformOIDCTenantSwitchApplyResultWire{Applied: tenantSwitchBool(true)}
	for name, destination := range map[string]any{
		"decision": &decoded.Decision, "sourceSessionId": &decoded.SourceSessionID,
		"sessionId": &decoded.SessionID, "targetTenantId": &decoded.TargetTenantID,
		"sessionVersion": &decoded.SessionVersion,
	} {
		raw, present := fields[name]
		if !present || json.Unmarshal(raw, destination) != nil {
			return errFederatedAuthPersistence
		}
	}
	*value = decoded
	return nil
}

func tenantSwitchBool(value bool) *bool { return &value }

type platformOIDCTenantSwitchOutcome struct {
	session   authentication.Session
	publicErr error
}

var _ authentication.DirectPlatformTenantSwitcher = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) SwitchDirectPlatformTenant(
	ctx context.Context,
	request authentication.DirectPlatformTenantSwitchRequest,
) (authentication.Session, error) {
	prepared, err := preparePlatformOIDCTenantSwitch(request)
	defer clearPlatformOIDCTenantSwitchRequest(&request)
	if err != nil || repository == nil || repository.begin == nil || ctx == nil || ctx.Err() != nil {
		clearPlatformOIDCTenantSwitchPrepared(&prepared)
		return authentication.Session{}, errFederatedAuthPersistence
	}
	defer clearPlatformOIDCTenantSwitchPrepared(&prepared)
	recoveryRequest := request
	defer clearPlatformOIDCTenantSwitchRequest(&recoveryRequest)
	recoveryAudit := prepared.audit

	outcome, err := withinTransaction(ctx, repository.begin, func(tx databaseTransaction) (platformOIDCTenantSwitchOutcome, error) {
		return repository.switchDirectPlatformTenantInTransaction(ctx, tx, request, &prepared)
	})
	if err != nil {
		clear(outcome.session.CSRFDigest)
		if recovered, ok := repository.recoverDirectPlatformTenantSwitch(
			ctx, recoveryRequest, recoveryAudit,
		); ok {
			return recovered, nil
		}
		return authentication.Session{}, err
	}
	if outcome.publicErr != nil {
		return authentication.Session{}, outcome.publicErr
	}
	return outcome.session, nil
}

func (repository *FederatedAuthRepository) recoverDirectPlatformTenantSwitch(
	ctx context.Context,
	request authentication.DirectPlatformTenantSwitchRequest,
	audit platformOIDCDirectAuditWire,
) (authentication.Session, bool) {
	defer clearPlatformOIDCTenantSwitchRequest(&request)
	if repository == nil || repository.begin == nil || ctx == nil {
		return authentication.Session{}, false
	}
	recoveryContext, cancel := context.WithTimeout(
		context.WithoutCancel(ctx),
		platformOIDCTenantSwitchRecoveryTimeout,
	)
	defer cancel()
	outcome, err := withinTransactionWithOptions(
		recoveryContext,
		repository.begin,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly},
		func(tx databaseTransaction) (platformOIDCTenantSwitchOutcome, error) {
			queries := dbsql.New(tx)
			return repository.replayDirectPlatformTenantSwitchInTransaction(
				recoveryContext, tx, queries, request, audit,
			)
		},
	)
	if err != nil || outcome.publicErr != nil ||
		!validPlatformOIDCTenantSwitchResult(outcome.session, request) {
		clear(outcome.session.CSRFDigest)
		return authentication.Session{}, false
	}
	return outcome.session, true
}

type platformOIDCTenantSwitchPrepared struct {
	rates  databaseRateRules
	lookup platformOIDCTenantSwitchLookupWire
	audit  platformOIDCDirectAuditWire
}

func preparePlatformOIDCTenantSwitch(
	request authentication.DirectPlatformTenantSwitchRequest,
) (platformOIDCTenantSwitchPrepared, error) {
	defer clearPlatformOIDCTenantSwitchRequest(&request)
	if request.AuthenticationMethod != "oidc" && request.AuthenticationMethod != "saml" {
		return platformOIDCTenantSwitchPrepared{}, errFederatedAuthPersistence
	}
	identifiers := [...]uuid.UUID{
		request.SourceSessionID, request.RotationFamilyID, request.NewSessionID,
		request.UserID, request.TargetTenantID,
	}
	seen := make(map[uuid.UUID]struct{}, len(identifiers))
	for _, identifier := range identifiers {
		if !platformOIDCDirectUUIDv7(identifier) {
			return platformOIDCTenantSwitchPrepared{}, errFederatedAuthPersistence
		}
		if _, duplicate := seen[identifier]; duplicate {
			return platformOIDCTenantSwitchPrepared{}, errFederatedAuthPersistence
		}
		seen[identifier] = struct{}{}
	}
	if !validPlatformOIDCDigest(request.SourceTokenDigest[:]) ||
		!validPlatformOIDCDigest(request.NewTokenDigest[:]) ||
		!validPlatformOIDCDigest(request.NewCSRFDigest[:]) ||
		request.SourceTokenDigest == request.NewTokenDigest ||
		request.SourceTokenDigest == request.NewCSRFDigest ||
		request.NewTokenDigest == request.NewCSRFDigest ||
		!validFederatedDatabaseTime(request.OccurredAt) ||
		!validFederatedDatabaseTime(request.IdleExpiresAt) ||
		!validFederatedDatabaseTime(request.AbsoluteExpiresAt) ||
		!request.IdleExpiresAt.After(request.OccurredAt) ||
		request.IdleExpiresAt.After(request.AbsoluteExpiresAt) ||
		!request.AbsoluteExpiresAt.After(request.OccurredAt) ||
		request.AbsoluteExpiresAt.After(request.OccurredAt.Add(maximumPlatformOIDCDirectSessionAge)) ||
		len(request.AdmissionRules) != 1 || request.AdmissionRules[0].Key.Scope != "tenant_switch" {
		return platformOIDCTenantSwitchPrepared{}, errFederatedAuthPersistence
	}
	rates, err := mapRateRules(request.AdmissionRules)
	if err != nil {
		return platformOIDCTenantSwitchPrepared{}, errFederatedAuthPersistence
	}
	audit := platformoidcauth.DirectAuditContext{
		RequestID: identity.EntityID(request.Event.RequestID), CorrelationID: identity.EntityID(request.Event.CorrelationID),
		RemoteAddress: request.Event.RemoteAddress, UserAgent: request.Event.UserAgent,
	}
	auditAction := platformOIDCTenantSwitchAuditAction
	if request.AuthenticationMethod == "saml" {
		auditAction = platformSAMLTenantSwitchAuditAction
	}
	eventID, err := platformOIDCDirectStableAuditEventID(
		audit, auditAction,
		request.SourceSessionID[:], request.TargetTenantID[:], request.NewSessionID[:],
	)
	if err != nil {
		clearPlatformOIDCTenantSwitchRates(&rates)
		return platformOIDCTenantSwitchPrepared{}, errFederatedAuthPersistence
	}
	auditWire, err := platformOIDCDirectAuditToWire(audit, eventID)
	if err != nil {
		clearPlatformOIDCTenantSwitchRates(&rates)
		return platformOIDCTenantSwitchPrepared{}, errFederatedAuthPersistence
	}
	auditWire.AuthenticationMethod = request.AuthenticationMethod
	return platformOIDCTenantSwitchPrepared{
		rates: rates,
		lookup: platformOIDCTenantSwitchLookupWire{
			SourceSessionID: request.SourceSessionID.String(), TargetTenantID: request.TargetTenantID.String(),
			ObservedAt: request.OccurredAt,
		},
		audit: auditWire,
	}, nil
}

func (repository *FederatedAuthRepository) switchDirectPlatformTenantInTransaction(
	ctx context.Context,
	tx databaseTransaction,
	request authentication.DirectPlatformTenantSwitchRequest,
	prepared *platformOIDCTenantSwitchPrepared,
) (platformOIDCTenantSwitchOutcome, error) {
	defer clearPlatformOIDCTenantSwitchRequest(&request)
	if tx == nil || prepared == nil || ctx.Err() != nil {
		return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
	}
	queries := dbsql.New(tx)
	admission, err := queries.AdmitAuthAttempts(ctx, dbsql.AdmitAuthAttemptsParams{
		Scopes: prepared.rates.scopes, KeyDigests: prepared.rates.keyDigests,
		WindowSeconds: prepared.rates.windowSeconds, MaxAttempts: prepared.rates.maxAttempts,
		BlockSeconds: prepared.rates.blockSeconds,
	})
	if err != nil || ctx.Err() != nil {
		return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
	}
	if admission == nil || admission.MaximumAttemptCount < 1 {
		return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
	}
	if !admission.Admitted {
		publicErr := retryAfter(admission.BlockedUntil, request.OccurredAt)
		if publicErr == nil {
			return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
		}
		return platformOIDCTenantSwitchOutcome{publicErr: publicErr}, nil
	}

	source, err := resolveSession(ctx, queries, request.SourceTokenDigest[:])
	if ctx.Err() != nil {
		return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
	}
	if errors.Is(err, authentication.ErrNotFound) {
		return repository.replayDirectPlatformTenantSwitchInTransaction(ctx, tx, queries, request, prepared.audit)
	}
	if err != nil {
		return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
	}
	defer clear(source.CSRFDigest)
	if !validPlatformOIDCTenantSwitchSourceSession(source, request) {
		return platformOIDCTenantSwitchOutcome{publicErr: authentication.ErrForbidden}, nil
	}

	txRepository := &FederatedAuthRepository{queryer: tx}
	var loaded platformOIDCTenantSwitchLoadWire
	loadSQL, applySQL, _, ok := platformTenantSwitchSQL(request.AuthenticationMethod)
	if !ok {
		return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
	}
	if err = txRepository.queryJSONWithLimits(
		ctx, loadSQL, prepared.lookup, &loaded,
		maximumPlatformOIDCTenantSwitchLookupBytes,
		maximumFederatedAuthenticationWireBytes,
	); err != nil || ctx.Err() != nil {
		return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
	}
	if len(loaded.CommandPins) == 0 {
		return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
	}
	if bytes.Equal(bytes.TrimSpace(loaded.CommandPins), []byte("null")) {
		return platformOIDCTenantSwitchOutcome{publicErr: authentication.ErrForbidden}, nil
	}

	if loaded.Source.AuthenticationMethod != request.AuthenticationMethod {
		return platformOIDCTenantSwitchOutcome{publicErr: authentication.ErrForbidden}, nil
	}
	// The admission planner predates the protocol-neutral switch port. The DB
	// projection above has already proved the physically separate SAML state;
	// normalize only this in-memory planner discriminator until that planner is
	// generalized, never the SQL authority or command proof.
	planningSource := loaded.Source
	planningSource.AuthenticationMethod = "oidc"
	snapshot, err := platformOIDCTenantSwitchSnapshotFromWire(planningSource, loaded.Target)
	if err != nil || loaded.Assurance == nil {
		return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
	}
	evidence, err := platformOIDCTenantSwitchEvidenceFromWire(*loaded.Assurance)
	if err != nil {
		return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
	}
	var pins platformOIDCTenantSwitchCommandPinsWire
	if err = unmarshalMFAWire(loaded.CommandPins, &pins); err != nil {
		return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
	}
	admitted, err := platformoidcauth.PlanTenantSwitchAdmission(request.OccurredAt, snapshot)
	if err != nil {
		return platformOIDCTenantSwitchOutcome{publicErr: authentication.ErrForbidden}, nil
	}
	if !platformOIDCTenantSwitchRequestMatchesAdmission(request, admitted) ||
		!platformOIDCTenantSwitchPinsMatchAdmission(pins, loaded.Target.MFASubject, admitted) {
		return platformOIDCTenantSwitchOutcome{publicErr: authentication.ErrForbidden}, nil
	}
	requirement, err := platformOIDCTenantSwitchRequirement(pins.PolicySnapshot, admitted.TargetTenantID)
	if err != nil {
		return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
	}
	if !platformoidcauth.TenantSwitchAssuranceSatisfied(request.OccurredAt, admitted, evidence, requirement) {
		return platformOIDCTenantSwitchOutcome{publicErr: authentication.ErrForbidden}, nil
	}

	command, err := platformOIDCTenantSwitchApplyCommand(request, admitted, pins, prepared.audit)
	if err != nil {
		return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
	}
	defer clearPlatformOIDCTenantSwitchApplyWire(&command)
	var applied platformOIDCTenantSwitchApplyResultWire
	if err = txRepository.queryJSONWithLimits(
		ctx, applySQL, command, &applied,
		maximumPlatformOIDCTenantSwitchCommandBytes,
		maximumPlatformOIDCTenantSwitchResponseBytes,
	); err != nil || ctx.Err() != nil {
		return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
	}
	if publicErr, resultErr := platformOIDCTenantSwitchApplyResult(applied, command); resultErr != nil {
		return platformOIDCTenantSwitchOutcome{}, resultErr
	} else if publicErr != nil {
		return platformOIDCTenantSwitchOutcome{publicErr: publicErr}, nil
	}

	result, err := resolveSession(ctx, queries, request.NewTokenDigest[:])
	if err != nil || ctx.Err() != nil || !validPlatformOIDCTenantSwitchResult(result, request) {
		clear(result.CSRFDigest)
		return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
	}
	return platformOIDCTenantSwitchOutcome{session: result}, nil
}

func (repository *FederatedAuthRepository) replayDirectPlatformTenantSwitchInTransaction(
	ctx context.Context,
	tx databaseTransaction,
	queries *dbsql.Queries,
	request authentication.DirectPlatformTenantSwitchRequest,
	audit platformOIDCDirectAuditWire,
) (platformOIDCTenantSwitchOutcome, error) {
	defer clearPlatformOIDCTenantSwitchRequest(&request)
	lookup := platformOIDCTenantSwitchReplayLookupWire{
		SourceSessionID: request.SourceSessionID.String(), TargetTenantID: request.TargetTenantID.String(),
		NewSessionID: request.NewSessionID.String(), RotationFamilyID: request.RotationFamilyID.String(),
		SourceTokenDigest: append([]byte(nil), request.SourceTokenDigest[:]...),
		NewTokenDigest:    append([]byte(nil), request.NewTokenDigest[:]...),
		CSRFSecretDigest:  append([]byte(nil), request.NewCSRFDigest[:]...),
		OccurredAt:        request.OccurredAt, IdleExpiresAt: request.IdleExpiresAt,
		AbsoluteExpiresAt: request.AbsoluteExpiresAt, Audit: audit,
	}
	defer clearPlatformOIDCTenantSwitchReplayLookupWire(&lookup)
	txRepository := &FederatedAuthRepository{queryer: tx}
	_, _, replaySQL, ok := platformTenantSwitchSQL(request.AuthenticationMethod)
	if !ok {
		return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
	}
	var replay platformOIDCTenantSwitchReplayResultWire
	if err := txRepository.queryJSONWithLimits(
		ctx, replaySQL, lookup, &replay,
		maximumPlatformOIDCTenantSwitchReplayBytes,
		maximumPlatformOIDCTenantSwitchResponseBytes,
	); err != nil || ctx.Err() != nil {
		return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
	}
	if replay.Matched == nil {
		return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
	}
	if !*replay.Matched {
		return platformOIDCTenantSwitchOutcome{publicErr: authentication.ErrForbidden}, nil
	}
	if replay.Result == nil || replay.Result.Applied == nil || !*replay.Result.Applied ||
		replay.Result.Category != "" || replay.Result.Decision != "rotated" ||
		replay.Result.SourceSessionID != request.SourceSessionID.String() ||
		replay.Result.SessionID != request.NewSessionID.String() ||
		replay.Result.TargetTenantID != request.TargetTenantID.String() ||
		replay.Result.SessionVersion < 2 ||
		replay.Result.SessionVersion > maximumMFAJSONSafeInteger {
		return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
	}
	result, err := resolveSession(ctx, queries, request.NewTokenDigest[:])
	if ctx.Err() != nil {
		clear(result.CSRFDigest)
		return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
	}
	if errors.Is(err, authentication.ErrNotFound) {
		return platformOIDCTenantSwitchOutcome{publicErr: authentication.ErrForbidden}, nil
	}
	if err != nil || !validPlatformOIDCTenantSwitchResult(result, request) {
		clear(result.CSRFDigest)
		return platformOIDCTenantSwitchOutcome{}, errFederatedAuthPersistence
	}
	return platformOIDCTenantSwitchOutcome{session: result}, nil
}

func validPlatformOIDCTenantSwitchSourceSession(
	value authentication.Session,
	request authentication.DirectPlatformTenantSwitchRequest,
) bool {
	defer clearPlatformOIDCTenantSwitchRequest(&request)
	return value.ID == request.SourceSessionID && value.RotationFamilyID == request.RotationFamilyID &&
		value.User.ID == request.UserID && value.ActiveTenantID == nil && value.RevokedAt == nil &&
		value.AuthenticationMethod == request.AuthenticationMethod && len(value.CSRFDigest) == sha256.Size &&
		!allZeroFederatedBytes(value.CSRFDigest) &&
		!bytes.Equal(value.CSRFDigest, request.SourceTokenDigest[:]) &&
		!bytes.Equal(value.CSRFDigest, request.NewTokenDigest[:]) &&
		!bytes.Equal(value.CSRFDigest, request.NewCSRFDigest[:]) &&
		validFederatedDatabaseTime(value.CreatedAt) && validFederatedDatabaseTime(value.LastSeenAt) &&
		validFederatedDatabaseTime(value.IdleExpiresAt) && validFederatedDatabaseTime(value.AbsoluteExpiresAt) &&
		!value.CreatedAt.After(request.OccurredAt) && !value.LastSeenAt.After(request.OccurredAt) &&
		value.IdleExpiresAt.After(request.OccurredAt) && value.AbsoluteExpiresAt.Equal(request.AbsoluteExpiresAt)
}

func platformOIDCTenantSwitchSnapshotFromWire(
	source platformOIDCTenantSwitchSourceWire,
	target platformOIDCTenantSwitchTargetWire,
) (platformoidcauth.TenantSwitchSnapshot, error) {
	sourceValue, err := platformOIDCTenantSwitchSourceFromWire(source)
	if err != nil {
		return platformoidcauth.TenantSwitchSnapshot{}, err
	}
	targetValue, err := platformOIDCTenantSwitchTargetFromWire(target)
	if err != nil {
		return platformoidcauth.TenantSwitchSnapshot{}, err
	}
	return platformoidcauth.TenantSwitchSnapshot{Source: sourceValue, Target: targetValue}, nil
}

func platformOIDCTenantSwitchSourceFromWire(
	value platformOIDCTenantSwitchSourceWire,
) (platformoidcauth.PlatformSessionAuthority, error) {
	sessionID, sessionErr := platformOIDCDirectSessionUUID(value.SessionID)
	familyID, familyErr := platformOIDCDirectSessionUUID(value.RotationFamilyID)
	userID, userErr := platformOIDCDirectSessionUUID(value.UserID)
	providerID, providerErr := platformOIDCDirectSessionUUID(value.ProviderID)
	externalID, externalErr := platformOIDCDirectSessionUUID(value.ExternalIdentityID)
	activeTenantID, activeTenantErr := platformOIDCDirectNullableUUID(value.ActiveTenantID)
	idleExpiresAt, validIdle := canonicalFederatedDatabaseTimeFromWire(value.IdleExpiresAt)
	absoluteExpiresAt, validAbsolute := canonicalFederatedDatabaseTimeFromWire(value.AbsoluteExpiresAt)
	if sessionErr != nil || familyErr != nil || userErr != nil || providerErr != nil || externalErr != nil ||
		activeTenantErr != nil || !validIdle || !validAbsolute || value.SessionActive == nil ||
		value.RotationFamilyLive == nil || value.UserActive == nil || value.ProviderEnabled == nil ||
		value.PlatformLoginLive == nil || value.IdentityLive == nil || value.SubjectAliasLive == nil ||
		!platformOIDCDirectExactRevisionWireValid(value.Revisions.Provider) ||
		!platformOIDCDirectExactRevisionWireValid(value.Revisions.Security) ||
		!platformOIDCDirectExactRevisionWireValid(value.Revisions.PlatformLogin) ||
		!platformOIDCDirectExactRevisionWireValid(value.Revisions.ExternalIdentity) ||
		!platformOIDCDirectExactRevisionWireValid(value.Revisions.SubjectAliasKey) ||
		value.ExpectedVersion < 1 || value.ExpectedVersion > maximumPlatformOIDCTenantSwitchDatabaseCount ||
		value.CurrentVersion < 1 || value.CurrentVersion > maximumPlatformOIDCTenantSwitchDatabaseCount {
		return platformoidcauth.PlatformSessionAuthority{}, errFederatedAuthPersistence
	}
	return platformoidcauth.PlatformSessionAuthority{
		SessionID: sessionID, RotationFamilyID: familyID, UserID: userID,
		ProviderID: providerID, ExternalIdentityID: externalID, ActiveTenantID: activeTenantID,
		AuthenticationMethod: value.AuthenticationMethod, PrimaryKind: value.PrimaryKind,
		DirectStateCount: value.DirectStateCount, DirectProvenanceCount: value.DirectProvenanceCount,
		TenantProvenanceCount: value.TenantProvenanceCount, ExpectedVersion: value.ExpectedVersion,
		CurrentVersion: value.CurrentVersion, IdleExpiresAt: idleExpiresAt, AbsoluteExpiresAt: absoluteExpiresAt,
		SessionActive: *value.SessionActive, RotationFamilyLive: *value.RotationFamilyLive,
		UserActive: *value.UserActive, ProviderEnabled: *value.ProviderEnabled,
		PlatformLoginLive: *value.PlatformLoginLive, AccountMode: platformoidcauth.AccountMode(value.AccountMode),
		IdentityLive: *value.IdentityLive, SubjectAliasLive: *value.SubjectAliasLive,
		Revisions: platformoidcauth.PlatformSessionRevisions{
			Provider:         platformOIDCDirectExactRevisionFromWire(value.Revisions.Provider),
			Security:         platformOIDCDirectExactRevisionFromWire(value.Revisions.Security),
			PlatformLogin:    platformOIDCDirectExactRevisionFromWire(value.Revisions.PlatformLogin),
			ExternalIdentity: platformOIDCDirectExactRevisionFromWire(value.Revisions.ExternalIdentity),
			SubjectAliasKey:  platformOIDCDirectExactRevisionFromWire(value.Revisions.SubjectAliasKey),
		},
	}, nil
}

func platformOIDCTenantSwitchTargetFromWire(
	value platformOIDCTenantSwitchTargetWire,
) (platformoidcauth.TargetTenantAuthority, error) {
	tenantID, tenantErr := platformOIDCDirectSessionUUID(value.Tenant.ID)
	membershipID, membershipErr := platformOIDCDirectSessionUUID(value.Membership.ID)
	membershipTenantID, membershipTenantErr := platformOIDCDirectSessionUUID(value.Membership.TenantID)
	membershipUserID, membershipUserErr := platformOIDCDirectSessionUUID(value.Membership.UserID)
	bindingID, bindingErr := platformOIDCDirectSessionUUID(value.Binding.ID)
	bindingTenantID, bindingTenantErr := platformOIDCDirectSessionUUID(value.Binding.TenantID)
	bindingProviderID, bindingProviderErr := platformOIDCDirectSessionUUID(value.Binding.ProviderID)
	currentEpochID, currentEpochErr := platformOIDCDirectSessionUUID(value.Binding.CurrentAccessEpochID)
	epochID, epochErr := platformOIDCDirectSessionUUID(value.AccessEpoch.ID)
	epochTenantID, epochTenantErr := platformOIDCDirectSessionUUID(value.AccessEpoch.TenantID)
	epochBindingID, epochBindingErr := platformOIDCDirectSessionUUID(value.AccessEpoch.BindingID)
	epochProviderID, epochProviderErr := platformOIDCDirectSessionUUID(value.AccessEpoch.ProviderID)
	epochSourceID, epochSourceErr := platformOIDCDirectSessionUUID(value.AccessEpoch.SourceID)
	sourceID, sourceErr := platformOIDCDirectSessionUUID(value.AccessSource.ID)
	sourceTenantID, sourceTenantErr := platformOIDCDirectSessionUUID(value.AccessSource.TenantID)
	externalID, externalErr := platformOIDCDirectSessionUUID(value.ExternalIdentity.ID)
	externalProviderID, externalProviderErr := platformOIDCDirectSessionUUID(value.ExternalIdentity.ProviderID)
	externalUserID, externalUserErr := platformOIDCDirectSessionUUID(value.ExternalIdentity.UserID)
	aliasExternalID, aliasErr := platformOIDCDirectSessionUUID(value.SubjectAlias.ExternalIdentityID)
	grantID, grantErr := platformOIDCDirectSessionUUID(value.AccessGrant.ID)
	grantTenantID, grantTenantErr := platformOIDCDirectSessionUUID(value.AccessGrant.TenantID)
	grantProviderID, grantProviderErr := platformOIDCDirectSessionUUID(value.AccessGrant.ProviderID)
	grantBindingID, grantBindingErr := platformOIDCDirectSessionUUID(value.AccessGrant.BindingID)
	grantEpochID, grantEpochErr := platformOIDCDirectSessionUUID(value.AccessGrant.AccessEpochID)
	grantSourceID, grantSourceErr := platformOIDCDirectSessionUUID(value.AccessGrant.AccessSourceID)
	grantExternalID, grantExternalErr := platformOIDCDirectSessionUUID(value.AccessGrant.ExternalIdentityID)
	grantMembershipID, grantMembershipErr := platformOIDCDirectSessionUUID(value.AccessGrant.MembershipID)
	grantUserID, grantUserErr := platformOIDCDirectSessionUUID(value.AccessGrant.UserID)
	if tenantErr != nil || membershipErr != nil || membershipTenantErr != nil || membershipUserErr != nil ||
		bindingErr != nil || bindingTenantErr != nil || bindingProviderErr != nil || currentEpochErr != nil ||
		epochErr != nil || epochTenantErr != nil || epochBindingErr != nil || epochProviderErr != nil || epochSourceErr != nil ||
		sourceErr != nil || sourceTenantErr != nil || externalErr != nil || externalProviderErr != nil ||
		externalUserErr != nil || aliasErr != nil || grantErr != nil || grantTenantErr != nil ||
		grantProviderErr != nil || grantBindingErr != nil || grantEpochErr != nil || grantSourceErr != nil ||
		grantExternalErr != nil || grantMembershipErr != nil || grantUserErr != nil || value.TenantExecutionLive == nil ||
		value.Tenant.Active == nil || value.Membership.Active == nil || value.Binding.Enabled == nil ||
		value.AccessEpoch.Live == nil || value.AccessSource.PlatformProvider == nil ||
		value.AccessSource.Authoritative == nil || value.AccessSource.Live == nil ||
		value.ExternalIdentity.Live == nil || value.SubjectAlias.Live == nil || value.AccessGrant.Live == nil ||
		!platformOIDCDirectSessionRevision(value.MFASubject.Version) ||
		!platformOIDCDirectSessionRevision(value.MFASubject.IdentityEpoch) ||
		!platformOIDCDirectSessionRevision(value.MFASubject.SessionInvalidationEpoch) {
		return platformoidcauth.TargetTenantAuthority{}, errFederatedAuthPersistence
	}
	return platformoidcauth.TargetTenantAuthority{
		TenantExecutionLive: *value.TenantExecutionLive,
		Tenant:              platformoidcauth.LiveTenant{ID: tenantID, Version: value.Tenant.Version, Active: *value.Tenant.Active},
		Membership: platformoidcauth.LiveMembership{
			ID: membershipID, TenantID: membershipTenantID, UserID: membershipUserID, Active: *value.Membership.Active,
		},
		Binding: platformoidcauth.LivePlatformBinding{
			ID: bindingID, TenantID: bindingTenantID, ProviderID: bindingProviderID, Version: value.Binding.Version,
			MappingRevision: value.Binding.MappingRevision, AuthorizationRevision: value.Binding.AuthorizationRevision,
			CurrentAccessEpochID: currentEpochID, Enabled: *value.Binding.Enabled,
		},
		AccessEpoch: platformoidcauth.LiveAccessEpoch{
			ID: epochID, TenantID: epochTenantID, BindingID: epochBindingID, ProviderID: epochProviderID,
			SourceID: epochSourceID, Version: value.AccessEpoch.Version, Live: *value.AccessEpoch.Live,
		},
		AccessSource: platformoidcauth.LiveAccessSource{
			ID: sourceID, TenantID: sourceTenantID, PlatformProvider: *value.AccessSource.PlatformProvider,
			Authoritative: *value.AccessSource.Authoritative, Live: *value.AccessSource.Live,
		},
		ExternalIdentity: platformoidcauth.LiveExternalIdentity{
			ID: externalID, ProviderID: externalProviderID, UserID: externalUserID,
			Version: value.ExternalIdentity.Version, Live: *value.ExternalIdentity.Live,
		},
		SubjectAlias: platformoidcauth.LiveSubjectAlias{
			ExternalIdentityID: aliasExternalID, KeyVersion: value.SubjectAlias.KeyVersion,
			Live: *value.SubjectAlias.Live,
		},
		AccessGrant: platformoidcauth.LiveAccessGrant{
			ID: grantID, TenantID: grantTenantID, ProviderID: grantProviderID, BindingID: grantBindingID,
			AccessEpochID: grantEpochID, AccessSourceID: grantSourceID, ExternalIdentityID: grantExternalID,
			MembershipID: grantMembershipID, UserID: grantUserID, Version: value.AccessGrant.Version,
			Live: *value.AccessGrant.Live,
		},
	}, nil
}

func platformOIDCTenantSwitchEvidenceFromWire(
	value platformOIDCTenantSwitchAssuranceWire,
) ([]platformoidcauth.DirectSessionEvidence, error) {
	_, levelErr := assuranceLevelFromWire(value.Level)
	authenticatedAt, validAuthenticatedAt := canonicalFederatedDatabaseTimeFromWire(value.AuthenticatedAt)
	expiresAt, expiresErr := platformOIDCDirectNullableTime(value.ExpiresAt)
	if levelErr != nil || !validAuthenticatedAt || expiresErr != nil || value.LocalSatisfied == nil ||
		expiresAt != nil && !expiresAt.After(authenticatedAt) || len(value.Evidence) < 1 || len(value.Evidence) > 2 {
		return nil, errFederatedAuthPersistence
	}
	result := make([]platformoidcauth.DirectSessionEvidence, len(value.Evidence))
	for index := range value.Evidence {
		proof, err := platformOIDCDirectSessionEvidenceFromWire(value.Evidence[index])
		if err != nil {
			return nil, errFederatedAuthPersistence
		}
		result[index] = proof
	}
	return result, nil
}

func platformOIDCTenantSwitchRequirement(
	raw json.RawMessage,
	tenantID uuid.UUID,
) (identity.EffectiveAssuranceRequirement, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return identity.EffectiveAssuranceRequirement{}, errFederatedAuthPersistence
	}
	var snapshot platformOIDCTenantSwitchPolicySnapshotWire
	if err := unmarshalMFAWire(raw, &snapshot); err != nil {
		return identity.EffectiveAssuranceRequirement{}, errFederatedAuthPersistence
	}
	contextValue, err := policyContextFromWire(snapshot.PolicyContext)
	if err != nil || uuid.UUID(contextValue.TenantID) != tenantID || contextValue.Action != "session.create" {
		return identity.EffectiveAssuranceRequirement{}, errFederatedAuthPersistence
	}
	policies, err := scopedPoliciesFromWire(snapshot.Policies)
	if err != nil {
		return identity.EffectiveAssuranceRequirement{}, errFederatedAuthPersistence
	}
	parsed, err := requirementFromWire(snapshot.Requirement)
	if err != nil {
		return identity.EffectiveAssuranceRequirement{}, errFederatedAuthPersistence
	}
	resolved, err := mfa.ResolvePolicy(contextValue, policies)
	if err != nil || !platformOIDCTenantSwitchRequirementsEqual(resolved.Requirement, parsed) {
		return identity.EffectiveAssuranceRequirement{}, errFederatedAuthPersistence
	}
	return parsed, nil
}

func platformOIDCTenantSwitchRequirementsEqual(
	left identity.EffectiveAssuranceRequirement,
	right identity.EffectiveAssuranceRequirement,
) bool {
	if left.Level != right.Level || left.LocalRequired != right.LocalRequired || left.Freshness != right.Freshness ||
		(left.EnrollmentDeadline == nil) != (right.EnrollmentDeadline == nil) ||
		len(left.PolicyRevisions) != len(right.PolicyRevisions) {
		return false
	}
	if left.EnrollmentDeadline != nil && !left.EnrollmentDeadline.Equal(*right.EnrollmentDeadline) {
		return false
	}
	for index := range left.PolicyRevisions {
		if left.PolicyRevisions[index] != right.PolicyRevisions[index] {
			return false
		}
	}
	return true
}

func platformOIDCTenantSwitchRequestMatchesAdmission(
	request authentication.DirectPlatformTenantSwitchRequest,
	value platformoidcauth.TenantSwitchAdmission,
) bool {
	defer clearPlatformOIDCTenantSwitchRequest(&request)
	return value.SourceSessionID == request.SourceSessionID && value.RotationFamilyID == request.RotationFamilyID &&
		value.UserID == request.UserID && value.TargetTenantID == request.TargetTenantID &&
		value.AbsoluteExpiresAt.Equal(request.AbsoluteExpiresAt) && value.ExpectedSessionVersion > 0 &&
		value.ExpectedSessionVersion < maximumMFAJSONSafeInteger &&
		request.NewSessionID != value.ProviderID && request.NewSessionID != value.ExternalIdentityID &&
		request.NewSessionID != value.MembershipID && request.NewSessionID != value.BindingID &&
		request.NewSessionID != value.AccessEpochID && request.NewSessionID != value.AccessSourceID &&
		request.NewSessionID != value.AccessGrantID
}

func platformOIDCTenantSwitchPinsMatchAdmission(
	value platformOIDCTenantSwitchCommandPinsWire,
	subject platformOIDCTenantSwitchMFASubjectWire,
	admission platformoidcauth.TenantSwitchAdmission,
) bool {
	tenantID, tenantErr := platformOIDCDirectSessionUUID(value.TenantID)
	membershipID, membershipErr := platformOIDCDirectSessionUUID(value.MembershipID)
	bindingID, bindingErr := platformOIDCDirectSessionUUID(value.BindingID)
	epochID, epochErr := platformOIDCDirectSessionUUID(value.AccessEpochID)
	sourceID, sourceErr := platformOIDCDirectSessionUUID(value.AccessSourceID)
	grantID, grantErr := platformOIDCDirectSessionUUID(value.AccessGrantID)
	providerID, providerErr := platformOIDCDirectSessionUUID(value.PlatformProviderID)
	externalID, externalErr := platformOIDCDirectSessionUUID(value.ExternalIdentityID)
	return tenantErr == nil && membershipErr == nil && bindingErr == nil && epochErr == nil && sourceErr == nil &&
		grantErr == nil && providerErr == nil && externalErr == nil && tenantID == admission.TargetTenantID &&
		value.TenantVersion == admission.TenantVersion && membershipID == admission.MembershipID &&
		value.MFASubjectVersion == subject.Version && value.IdentityEpoch == subject.IdentityEpoch &&
		value.SessionInvalidationEpoch == subject.SessionInvalidationEpoch && bindingID == admission.BindingID &&
		value.BindingVersion == admission.BindingVersion && value.MappingRevision == admission.MappingRevision &&
		value.AuthorizationRevision == admission.AuthorizationRevision && epochID == admission.AccessEpochID &&
		value.AccessEpochVersion == admission.AccessEpochVersion && sourceID == admission.AccessSourceID &&
		grantID == admission.AccessGrantID && value.AccessGrantVersion == admission.AccessGrantVersion &&
		providerID == admission.ProviderID && value.ProviderRevision == admission.ProviderRevision &&
		value.SecurityRevision == admission.SecurityRevision && externalID == admission.ExternalIdentityID &&
		value.IdentityVersion == admission.IdentityRevision && value.AliasKeyVersion == admission.SubjectAliasKeyVersion &&
		value.TenantVersion <= maximumPlatformOIDCTenantSwitchDatabaseCount &&
		value.BindingVersion <= maximumPlatformOIDCTenantSwitchDatabaseCount &&
		value.AccessEpochVersion <= maximumPlatformOIDCTenantSwitchDatabaseCount &&
		value.AccessGrantVersion <= maximumPlatformOIDCTenantSwitchDatabaseCount &&
		platformOIDCDirectSessionRevision(value.MFASubjectVersion) &&
		platformOIDCDirectSessionRevision(value.IdentityEpoch) &&
		platformOIDCDirectSessionRevision(value.SessionInvalidationEpoch) && len(value.PolicySnapshot) > 0
}

func platformOIDCTenantSwitchApplyCommand(
	request authentication.DirectPlatformTenantSwitchRequest,
	admission platformoidcauth.TenantSwitchAdmission,
	target platformOIDCTenantSwitchCommandPinsWire,
	audit platformOIDCDirectAuditWire,
) (platformOIDCTenantSwitchApplyWire, error) {
	defer clearPlatformOIDCTenantSwitchRequest(&request)
	command := platformOIDCTenantSwitchApplyWire{
		SourceSessionID: request.SourceSessionID.String(), ExpectedVersion: admission.ExpectedSessionVersion,
		Target: target, Decision: "rotate", ObservedAt: request.OccurredAt, Audit: audit,
		Session: platformOIDCTenantSwitchSessionWire{
			ID: request.NewSessionID.String(), RotationFamilyID: request.RotationFamilyID.String(),
			TokenDigest:      append([]byte(nil), request.NewTokenDigest[:]...),
			CSRFSecretDigest: append([]byte(nil), request.NewCSRFDigest[:]...),
			Audience:         "api", IdleExpiresAt: request.IdleExpiresAt, AbsoluteExpiresAt: request.AbsoluteExpiresAt,
			SessionVersion: admission.ExpectedSessionVersion + 1, RecoveryRestricted: false,
		},
	}
	if request.AuthenticationMethod == "saml" {
		command.AuthenticationMethod = "saml"
	}
	encoded, err := json.Marshal(command)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumPlatformOIDCTenantSwitchCommandBytes {
		clear(encoded)
		clearPlatformOIDCTenantSwitchApplyWire(&command)
		return platformOIDCTenantSwitchApplyWire{}, errFederatedAuthPersistence
	}
	digest := sha256.Sum256(encoded)
	clear(encoded)
	if !validPlatformOIDCDigest(digest[:]) {
		clearPlatformOIDCTenantSwitchApplyWire(&command)
		return platformOIDCTenantSwitchApplyWire{}, errFederatedAuthPersistence
	}
	command.RequestDigest = append([]byte(nil), digest[:]...)
	clear(digest[:])
	return command, nil
}

func platformOIDCTenantSwitchApplyResult(
	value platformOIDCTenantSwitchApplyResultWire,
	wanted platformOIDCTenantSwitchApplyWire,
) (error, error) {
	if value.Applied == nil {
		return nil, errFederatedAuthPersistence
	}
	if !*value.Applied {
		if (value.Category != "stale" && value.Category != "denied") || value.Decision != "" ||
			value.SourceSessionID != "" || value.SessionID != "" || value.TargetTenantID != "" ||
			value.SessionVersion != 0 {
			return nil, errFederatedAuthPersistence
		}
		return authentication.ErrForbidden, nil
	}
	if value.Category != "" || value.Decision != "rotated" ||
		value.SourceSessionID != wanted.SourceSessionID || value.SessionID != wanted.Session.ID ||
		value.TargetTenantID != wanted.Target.TenantID || value.SessionVersion != wanted.Session.SessionVersion {
		return nil, errFederatedAuthPersistence
	}
	if _, err := platformOIDCDirectSessionUUID(value.SourceSessionID); err != nil {
		return nil, errFederatedAuthPersistence
	}
	if _, err := platformOIDCDirectSessionUUID(value.SessionID); err != nil {
		return nil, errFederatedAuthPersistence
	}
	if _, err := platformOIDCDirectSessionUUID(value.TargetTenantID); err != nil {
		return nil, errFederatedAuthPersistence
	}
	return nil, nil
}

func validPlatformOIDCTenantSwitchResult(
	value authentication.Session,
	request authentication.DirectPlatformTenantSwitchRequest,
) bool {
	defer clearPlatformOIDCTenantSwitchRequest(&request)
	return value.ID == request.NewSessionID && value.RotationFamilyID == request.RotationFamilyID &&
		value.User.ID == request.UserID && value.ActiveTenantID != nil && *value.ActiveTenantID == request.TargetTenantID &&
		value.RevokedAt == nil && value.AuthenticationMethod == request.AuthenticationMethod && value.CreatedAt.Equal(request.OccurredAt) &&
		value.LastSeenAt.Equal(request.OccurredAt) && value.IdleExpiresAt.Equal(request.IdleExpiresAt) &&
		value.AbsoluteExpiresAt.Equal(request.AbsoluteExpiresAt) && len(value.CSRFDigest) == sha256.Size &&
		bytes.Equal(value.CSRFDigest, request.NewCSRFDigest[:])
}

func platformTenantSwitchSQL(authenticationMethod string) (load, apply, replay string, ok bool) {
	switch authenticationMethod {
	case "oidc":
		return loadPlatformOIDCTenantSwitchSQL, applyPlatformOIDCTenantSwitchSQL,
			lookupPlatformOIDCTenantSwitchReplaySQL, true
	case "saml":
		return loadPlatformSAMLTenantSwitchSQL, applyPlatformSAMLTenantSwitchSQL,
			lookupPlatformSAMLTenantSwitchReplaySQL, true
	default:
		return "", "", "", false
	}
}

func clearPlatformOIDCTenantSwitchApplyWire(value *platformOIDCTenantSwitchApplyWire) {
	if value == nil {
		return
	}
	clear(value.RequestDigest)
	clear(value.Session.TokenDigest)
	clear(value.Session.CSRFSecretDigest)
	*value = platformOIDCTenantSwitchApplyWire{}
}

func clearPlatformOIDCTenantSwitchReplayLookupWire(value *platformOIDCTenantSwitchReplayLookupWire) {
	if value == nil {
		return
	}
	clear(value.SourceTokenDigest)
	clear(value.NewTokenDigest)
	clear(value.CSRFSecretDigest)
	*value = platformOIDCTenantSwitchReplayLookupWire{}
}

func clearPlatformOIDCTenantSwitchRates(value *databaseRateRules) {
	if value == nil {
		return
	}
	for index := range value.keyDigests {
		clear(value.keyDigests[index])
	}
	*value = databaseRateRules{}
}

func clearPlatformOIDCTenantSwitchPrepared(value *platformOIDCTenantSwitchPrepared) {
	if value == nil {
		return
	}
	clearPlatformOIDCTenantSwitchRates(&value.rates)
	*value = platformOIDCTenantSwitchPrepared{}
}

func clearPlatformOIDCTenantSwitchRequest(value *authentication.DirectPlatformTenantSwitchRequest) {
	if value == nil {
		return
	}
	clear(value.SourceTokenDigest[:])
	clear(value.NewTokenDigest[:])
	clear(value.NewCSRFDigest[:])
}
