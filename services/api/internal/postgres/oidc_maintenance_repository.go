package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

const (
	claimOIDCRefreshRotationSQL    = `select app.claim_tenant_oidc_refresh_rotation_v1($1::jsonb)`
	completeOIDCRefreshRotationSQL = `select app.complete_tenant_oidc_refresh_rotation_v1($1::jsonb)`
	revokeOIDCSessionFamilySQL     = `select app.revoke_tenant_oidc_session_family_v1($1::jsonb)`
	claimOIDCLogoutRetrySQL        = `select app.claim_tenant_oidc_logout_retry_v1($1::jsonb)`
	completeOIDCLogoutRetrySQL     = `select app.complete_tenant_oidc_logout_retry_v1($1::jsonb)`

	maximumOIDCMaintenanceWireBytes = 1024 * 1024
	maximumOIDCMaintenanceCounter   = uint64(9_000_000_000_000_000)
	maximumOIDCKeyVersion           = uint32(32767)
)

type oidcRefreshClaimRequestWire struct {
	SessionFamilyID    string    `json:"sessionFamilyId"`
	ExpectedGeneration uint64    `json:"expectedGeneration"`
	ExpectedDigest     []byte    `json:"expectedDigest"`
	ClaimedAt          time.Time `json:"claimedAt"`
}

type oidcMaintenanceProtectedTokenWire struct {
	KeyVersion uint32 `json:"keyVersion"`
	Ciphertext []byte `json:"ciphertext"`
}

func (value oidcMaintenanceProtectedTokenWire) String() string {
	return "postgres.oidcMaintenanceProtectedTokenWire{material:[REDACTED]}"
}

func (value oidcMaintenanceProtectedTokenWire) GoString() string { return value.String() }

type oidcRefreshClaimSnapshotWire struct {
	Category              string                                 `json:"category"`
	TenantID              *string                                `json:"tenantId,omitempty"`
	EffectiveTenantID     *string                                `json:"effectiveTenantId,omitempty"`
	ObservedAt            *time.Time                             `json:"observedAt,omitempty"`
	MaterialID            string                                 `json:"materialId,omitempty"`
	SessionFamilyID       string                                 `json:"sessionFamilyId"`
	Generation            uint64                                 `json:"generation,omitempty"`
	Version               uint64                                 `json:"version,omitempty"`
	LeaseExpiresAt        *time.Time                             `json:"leaseExpiresAt,omitempty"`
	Provider              *federatedProviderBindingWire          `json:"provider,omitempty"`
	Admission             *federatedTenantAdmissionWire          `json:"admission,omitempty"`
	BindingID             *string                                `json:"bindingId,omitempty"`
	ClientSecretRevision  uint64                                 `json:"clientSecretRevision,omitempty"`
	Endpoint              string                                 `json:"endpoint,omitempty"`
	ClientAuthentication  federatedoidc.ClientAuthenticationMode `json:"clientAuthentication,omitempty"`
	ClientID              string                                 `json:"clientId,omitempty"`
	Token                 *oidcMaintenanceProtectedTokenWire     `json:"token,omitempty"`
	TokenDigest           []byte                                 `json:"tokenDigest,omitempty"`
	MaterialExpiresAt     *time.Time                             `json:"materialExpiresAt,omitempty"`
	AbsoluteSessionExpiry *time.Time                             `json:"absoluteSessionExpiry,omitempty"`
}

func (value oidcRefreshClaimSnapshotWire) String() string {
	return fmt.Sprintf("postgres.oidcRefreshClaimSnapshotWire{category:%s,material:[REDACTED]}", value.Category)
}

func (value oidcRefreshClaimSnapshotWire) GoString() string { return value.String() }

type oidcRefreshCompletionWire struct {
	TenantID            *string                                `json:"tenantId"`
	EffectiveTenantID   *string                                `json:"effectiveTenantId"`
	MaterialID          string                                 `json:"materialId"`
	SessionFamilyID     string                                 `json:"sessionFamilyId"`
	ExpectedVersion     uint64                                 `json:"expectedVersion"`
	ExpectedGeneration  uint64                                 `json:"expectedGeneration"`
	Outcome             federatedauth.RefreshCompletionOutcome `json:"outcome"`
	SuccessorGeneration *uint64                                `json:"successorGeneration,omitempty"`
	SuccessorDigest     []byte                                 `json:"successorDigest,omitempty"`
	SuccessorToken      *oidcMaintenanceProtectedTokenWire     `json:"successorToken,omitempty"`
	AccessExpiresAt     *time.Time                             `json:"accessExpiresAt,omitempty"`
	CompletedAt         time.Time                              `json:"completedAt"`
}

func (value oidcRefreshCompletionWire) String() string {
	return "postgres.oidcRefreshCompletionWire{material:[REDACTED]}"
}

func (value oidcRefreshCompletionWire) GoString() string { return value.String() }

type oidcSessionFamilyRevokeWire struct {
	SessionFamilyID string                         `json:"sessionFamilyId"`
	Reason          federatedauth.RevocationReason `json:"reason"`
	RevokedAt       time.Time                      `json:"revokedAt"`
}

type oidcLogoutRetryClaimWire struct {
	JobID      string    `json:"jobId"`
	ObservedAt time.Time `json:"observedAt"`
}

type oidcLogoutRetrySnapshotWire struct {
	JobID                string                                 `json:"jobId"`
	TenantID             *string                                `json:"tenantId"`
	MaterialID           string                                 `json:"materialId"`
	SessionFamilyID      string                                 `json:"sessionFamilyId"`
	Attempt              int                                    `json:"attempt"`
	MaximumAttempts      int                                    `json:"maximumAttempts"`
	ClaimVersion         uint64                                 `json:"claimVersion"`
	LeaseExpiresAt       time.Time                              `json:"leaseExpiresAt"`
	NotBefore            time.Time                              `json:"notBefore"`
	Provider             federatedProviderBindingWire           `json:"provider"`
	Admission            *federatedTenantAdmissionWire          `json:"admission,omitempty"`
	ClientSecretRevision uint64                                 `json:"clientSecretRevision"`
	ClientAuthentication federatedoidc.ClientAuthenticationMode `json:"clientAuthentication"`
	ClientID             string                                 `json:"clientId"`
	Endpoint             string                                 `json:"endpoint"`
	RefreshGeneration    uint64                                 `json:"refreshGeneration"`
	TokenDigest          []byte                                 `json:"tokenDigest"`
	MaterialExpiresAt    time.Time                              `json:"materialExpiresAt"`
	OpaqueReference      oidcMaintenanceProtectedTokenWire      `json:"opaqueReference"`
}

func (value oidcLogoutRetrySnapshotWire) String() string {
	return fmt.Sprintf("postgres.oidcLogoutRetrySnapshotWire{attempt:%d,material:[REDACTED]}", value.Attempt)
}

func (value oidcLogoutRetrySnapshotWire) GoString() string { return value.String() }

type oidcLogoutRetryCompletionWire struct {
	JobID           string                               `json:"jobId"`
	Attempt         int                                  `json:"attempt"`
	ExpectedVersion uint64                               `json:"expectedVersion"`
	Outcome         federatedauth.LogoutRetryDisposition `json:"outcome"`
	CompletedAt     time.Time                            `json:"completedAt"`
	NextTryAt       *time.Time                           `json:"nextTryAt,omitempty"`
}

var (
	_ federatedauth.RefreshStore     = (*FederatedAuthRepository)(nil)
	_ federatedauth.LogoutRetryStore = (*FederatedAuthRepository)(nil)
)

func (repository *FederatedAuthRepository) ClaimRefreshRotation(
	ctx context.Context,
	command federatedauth.RefreshCommand,
	claimedAt time.Time,
) (federatedauth.RefreshSnapshot, error) {
	familyID, err := requiredFederatedEntityIDWire(command.SessionFamilyID)
	if err != nil || command.ExpectedGeneration == 0 ||
		command.ExpectedGeneration >= maximumOIDCMaintenanceCounter ||
		!validDigestWire(command.ExpectedDigest[:]) || !validFederatedDatabaseTime(claimedAt) {
		return federatedauth.RefreshSnapshot{}, errFederatedAuthPersistence
	}
	request := oidcRefreshClaimRequestWire{
		SessionFamilyID: familyID, ExpectedGeneration: command.ExpectedGeneration,
		ExpectedDigest: append([]byte(nil), command.ExpectedDigest[:]...), ClaimedAt: claimedAt,
	}
	defer clear(request.ExpectedDigest)
	var wire oidcRefreshClaimSnapshotWire
	defer clearOIDCRefreshClaimSnapshotWire(&wire)
	if err := repository.queryJSONWithResponseLimit(
		ctx, claimOIDCRefreshRotationSQL, request, &wire, maximumOIDCMaintenanceWireBytes,
	); err != nil {
		return federatedauth.RefreshSnapshot{}, errFederatedAuthPersistence
	}
	return oidcRefreshSnapshotFromWire(wire, command, claimedAt)
}

func (repository *FederatedAuthRepository) CompleteRefreshRotation(
	ctx context.Context,
	completion federatedauth.RefreshCompletion,
) error {
	wire, err := oidcRefreshCompletionToWire(completion)
	if err != nil {
		return errFederatedAuthPersistence
	}
	defer clearOIDCRefreshCompletionWire(&wire)
	ok, err := repository.executeOIDCMaintenanceBoolean(ctx, completeOIDCRefreshRotationSQL, wire)
	if err != nil || !ok {
		return errFederatedAuthPersistence
	}
	return nil
}

func (repository *FederatedAuthRepository) RevokeSessionFamily(
	ctx context.Context,
	familyID identity.EntityID,
	reason federatedauth.RevocationReason,
	revokedAt time.Time,
) error {
	encodedFamilyID, err := requiredFederatedEntityIDWire(familyID)
	if err != nil || !validOIDCRevocationReason(reason) || !validFederatedDatabaseTime(revokedAt) {
		return errFederatedAuthPersistence
	}
	ok, err := repository.executeOIDCMaintenanceBoolean(ctx, revokeOIDCSessionFamilySQL, oidcSessionFamilyRevokeWire{
		SessionFamilyID: encodedFamilyID, Reason: reason, RevokedAt: revokedAt,
	})
	if err != nil || !ok {
		return errFederatedAuthPersistence
	}
	return nil
}

func (repository *FederatedAuthRepository) ClaimLogoutRetry(
	ctx context.Context,
	jobID identity.EntityID,
	observedAt time.Time,
) (federatedauth.LogoutRetryJob, error) {
	encodedJobID, err := requiredFederatedEntityIDWire(jobID)
	if err != nil || !validFederatedDatabaseTime(observedAt) {
		return federatedauth.LogoutRetryJob{}, errFederatedAuthPersistence
	}
	var wire *oidcLogoutRetrySnapshotWire
	if err := repository.queryJSONWithResponseLimit(
		ctx, claimOIDCLogoutRetrySQL,
		oidcLogoutRetryClaimWire{JobID: encodedJobID, ObservedAt: observedAt},
		&wire, maximumOIDCMaintenanceWireBytes,
	); err != nil || wire == nil {
		return federatedauth.LogoutRetryJob{}, errFederatedAuthPersistence
	}
	defer clearOIDCLogoutRetrySnapshotWire(wire)
	return oidcLogoutRetryJobFromWire(*wire, jobID, observedAt)
}

func (repository *FederatedAuthRepository) CompleteLogoutRetry(
	ctx context.Context,
	update federatedauth.LogoutRetryUpdate,
) error {
	wire, err := oidcLogoutRetryCompletionToWire(update)
	if err != nil {
		return errFederatedAuthPersistence
	}
	ok, err := repository.executeOIDCMaintenanceBoolean(ctx, completeOIDCLogoutRetrySQL, wire)
	if err != nil || !ok {
		return errFederatedAuthPersistence
	}
	return nil
}

func (repository *FederatedAuthRepository) executeOIDCMaintenanceBoolean(
	ctx context.Context,
	query string,
	request any,
) (bool, error) {
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil {
		return false, errFederatedAuthPersistence
	}
	payload, err := json.Marshal(request)
	if err != nil || len(payload) == 0 || len(payload) > maximumOIDCMaintenanceWireBytes {
		clear(payload)
		return false, errFederatedAuthPersistence
	}
	defer clear(payload)
	var applied bool
	if err := repository.queryer.QueryRow(ctx, query, payload).Scan(&applied); err != nil || ctx.Err() != nil {
		return false, errFederatedAuthPersistence
	}
	return applied, nil
}

func oidcRefreshSnapshotFromWire(
	wire oidcRefreshClaimSnapshotWire,
	command federatedauth.RefreshCommand,
	claimedAt time.Time,
) (federatedauth.RefreshSnapshot, error) {
	familyID, err := parseFederatedEntityIDWire(wire.SessionFamilyID, false)
	if err != nil || familyID != command.SessionFamilyID {
		return federatedauth.RefreshSnapshot{}, errFederatedAuthPersistence
	}
	snapshot := federatedauth.RefreshSnapshot{
		Category: federatedauth.RefreshClaimCategory(wire.Category), SessionFamilyID: familyID,
	}
	switch snapshot.Category {
	case federatedauth.RefreshStale, federatedauth.RefreshBusy:
		if !emptyOIDCRefreshClaimPayload(wire) {
			return federatedauth.RefreshSnapshot{}, errFederatedAuthPersistence
		}
		return snapshot, nil
	case federatedauth.RefreshReuse:
		tenantID, tenantErr := optionalSessionLogoutEntityID(wire.TenantID)
		effectiveTenantID, effectiveTenantErr := optionalSessionLogoutEntityID(wire.EffectiveTenantID)
		materialID, materialErr := parseFederatedEntityIDWire(wire.MaterialID, false)
		if tenantErr != nil || effectiveTenantErr != nil || materialErr != nil ||
			(tenantID != (identity.EntityID{}) && effectiveTenantID != tenantID) ||
			!emptyOIDCRefreshClaimedFields(wire) {
			return federatedauth.RefreshSnapshot{}, errFederatedAuthPersistence
		}
		snapshot.TenantID, snapshot.EffectiveTenantID, snapshot.MaterialID = tenantID, effectiveTenantID, materialID
		return snapshot, nil
	case federatedauth.RefreshClaimed:
	default:
		return federatedauth.RefreshSnapshot{}, errFederatedAuthPersistence
	}
	if wire.Provider == nil || wire.Token == nil || wire.ObservedAt == nil || wire.LeaseExpiresAt == nil ||
		wire.MaterialExpiresAt == nil || wire.AbsoluteSessionExpiry == nil ||
		wire.Generation != command.ExpectedGeneration || wire.Generation == 0 ||
		wire.Generation >= maximumOIDCMaintenanceCounter || wire.Version == 0 ||
		wire.Version >= maximumOIDCMaintenanceCounter || wire.ClientSecretRevision == 0 ||
		wire.ClientSecretRevision > maximumOIDCMaintenanceCounter ||
		!validOIDCMaintenanceClientAuthentication(wire.ClientAuthentication) ||
		!validOIDCMaintenanceClientID(wire.ClientID) || !validOIDCMaintenanceEndpoint(wire.Endpoint) ||
		wire.Token.KeyVersion == 0 || wire.Token.KeyVersion > maximumOIDCKeyVersion ||
		len(wire.Token.Ciphertext) < minimumOIDCProtectedTokenBytes ||
		len(wire.Token.Ciphertext) > maximumOIDCProtectedTokenBytes || !validDigestWire(wire.TokenDigest) {
		return federatedauth.RefreshSnapshot{}, errFederatedAuthPersistence
	}
	tenantID, tenantErr := optionalSessionLogoutEntityID(wire.TenantID)
	effectiveTenantID, effectiveTenantErr := optionalSessionLogoutEntityID(wire.EffectiveTenantID)
	materialID, materialErr := parseFederatedEntityIDWire(wire.MaterialID, false)
	bindingID, bindingErr := optionalSessionLogoutEntityID(wire.BindingID)
	provider, admission, providerErr := sessionLogoutProviderFromWire(*wire.Provider, wire.Admission, tenantID)
	observedAt, validObservedAt := canonicalFederatedDatabaseTimeFromWire(*wire.ObservedAt)
	lease, validLease := canonicalFederatedDatabaseTimeFromWire(*wire.LeaseExpiresAt)
	materialExpiry, validMaterialExpiry := canonicalFederatedDatabaseTimeFromWire(*wire.MaterialExpiresAt)
	absoluteExpiry, validAbsoluteExpiry := canonicalFederatedDatabaseTimeFromWire(*wire.AbsoluteSessionExpiry)
	if tenantErr != nil || effectiveTenantErr != nil || materialErr != nil || bindingErr != nil || providerErr != nil ||
		!validObservedAt || observedAt.Before(claimedAt.Add(-5*time.Minute)) ||
		observedAt.After(claimedAt.Add(5*time.Minute)) ||
		!validLease || !validMaterialExpiry || !validAbsoluteExpiry || !lease.After(observedAt) ||
		lease.After(materialExpiry) || !materialExpiry.After(observedAt) ||
		materialExpiry.After(absoluteExpiry) ||
		!validOIDCMaintenanceEffectiveScope(tenantID, effectiveTenantID, provider, admission, bindingID) {
		return federatedauth.RefreshSnapshot{}, errFederatedAuthPersistence
	}
	snapshot.TenantID, snapshot.EffectiveTenantID, snapshot.MaterialID = tenantID, effectiveTenantID, materialID
	snapshot.Generation, snapshot.Version = wire.Generation, wire.Version
	snapshot.Provider, snapshot.Admission, snapshot.BindingID = provider, admission, bindingID
	snapshot.ClientSecretRevision = wire.ClientSecretRevision
	snapshot.Endpoint, snapshot.ClientAuthentication, snapshot.ClientID = wire.Endpoint, wire.ClientAuthentication, wire.ClientID
	snapshot.Token = federatedauth.ProtectedToken{
		KeyVersion: wire.Token.KeyVersion, Ciphertext: append([]byte(nil), wire.Token.Ciphertext...),
	}
	copy(snapshot.TokenDigest[:], wire.TokenDigest)
	snapshot.ObservedAt, snapshot.LeaseExpiresAt = observedAt, lease
	snapshot.MaterialExpiresAt, snapshot.AbsoluteSessionExpiry = materialExpiry, absoluteExpiry
	return snapshot, nil
}

func oidcRefreshCompletionToWire(
	completion federatedauth.RefreshCompletion,
) (oidcRefreshCompletionWire, error) {
	tenantID, err := optionalSessionLogoutEntityIDWire(completion.TenantID)
	effectiveTenantID, effectiveTenantErr := optionalSessionLogoutEntityIDWire(completion.EffectiveTenantID)
	materialID, materialErr := requiredFederatedEntityIDWire(completion.MaterialID)
	familyID, familyErr := requiredFederatedEntityIDWire(completion.SessionFamilyID)
	if err != nil || effectiveTenantErr != nil || materialErr != nil || familyErr != nil ||
		(completion.TenantID != (identity.EntityID{}) && completion.EffectiveTenantID != completion.TenantID) ||
		completion.ExpectedVersion == 0 ||
		completion.ExpectedVersion >= maximumOIDCMaintenanceCounter || completion.ExpectedGeneration == 0 ||
		completion.ExpectedGeneration >= maximumOIDCMaintenanceCounter || !validFederatedDatabaseTime(completion.CompletedAt) {
		return oidcRefreshCompletionWire{}, errFederatedAuthPersistence
	}
	wire := oidcRefreshCompletionWire{
		TenantID: tenantID, EffectiveTenantID: effectiveTenantID,
		MaterialID: materialID, SessionFamilyID: familyID,
		ExpectedVersion: completion.ExpectedVersion, ExpectedGeneration: completion.ExpectedGeneration,
		Outcome: completion.Outcome, CompletedAt: completion.CompletedAt,
	}
	switch completion.Outcome {
	case federatedauth.RefreshRotated:
		if completion.SuccessorGeneration != completion.ExpectedGeneration+1 ||
			completion.SuccessorGeneration >= maximumOIDCMaintenanceCounter ||
			!validDigestWire(completion.SuccessorDigest[:]) || completion.SuccessorToken.KeyVersion == 0 ||
			completion.SuccessorToken.KeyVersion > maximumOIDCKeyVersion ||
			len(completion.SuccessorToken.Ciphertext) < minimumOIDCProtectedTokenBytes ||
			len(completion.SuccessorToken.Ciphertext) > maximumOIDCProtectedTokenBytes ||
			!validFederatedDatabaseTime(completion.AccessExpiresAt) ||
			!completion.AccessExpiresAt.After(completion.CompletedAt) {
			return oidcRefreshCompletionWire{}, errFederatedAuthPersistence
		}
		successorGeneration := completion.SuccessorGeneration
		accessExpiresAt := completion.AccessExpiresAt
		wire.SuccessorGeneration = &successorGeneration
		wire.SuccessorDigest = append([]byte(nil), completion.SuccessorDigest[:]...)
		wire.SuccessorToken = &oidcMaintenanceProtectedTokenWire{
			KeyVersion: completion.SuccessorToken.KeyVersion,
			Ciphertext: append([]byte(nil), completion.SuccessorToken.Ciphertext...),
		}
		wire.AccessExpiresAt = &accessExpiresAt
	case federatedauth.RefreshSafeToRetry, federatedauth.RefreshAmbiguous, federatedauth.RefreshRejected:
		if completion.SuccessorGeneration != 0 || completion.SuccessorDigest != ([sha256.Size]byte{}) ||
			completion.SuccessorToken.KeyVersion != 0 || len(completion.SuccessorToken.Ciphertext) != 0 ||
			!completion.AccessExpiresAt.IsZero() {
			return oidcRefreshCompletionWire{}, errFederatedAuthPersistence
		}
	default:
		return oidcRefreshCompletionWire{}, errFederatedAuthPersistence
	}
	return wire, nil
}

func oidcLogoutRetryJobFromWire(
	wire oidcLogoutRetrySnapshotWire,
	expectedJobID identity.EntityID,
	observedAt time.Time,
) (federatedauth.LogoutRetryJob, error) {
	jobID, jobErr := parseFederatedEntityIDWire(wire.JobID, false)
	tenantID, tenantErr := optionalSessionLogoutEntityID(wire.TenantID)
	materialID, materialErr := parseFederatedEntityIDWire(wire.MaterialID, false)
	familyID, familyErr := parseFederatedEntityIDWire(wire.SessionFamilyID, false)
	provider, admission, providerErr := sessionLogoutProviderFromWire(wire.Provider, wire.Admission, tenantID)
	lease, validLease := canonicalFederatedDatabaseTimeFromWire(wire.LeaseExpiresAt)
	notBefore, validNotBefore := canonicalFederatedDatabaseTimeFromWire(wire.NotBefore)
	materialExpiry, validMaterialExpiry := canonicalFederatedDatabaseTimeFromWire(wire.MaterialExpiresAt)
	if jobErr != nil || tenantErr != nil || materialErr != nil || familyErr != nil || providerErr != nil ||
		jobID != expectedJobID || wire.Attempt < 1 || wire.MaximumAttempts < 1 ||
		wire.MaximumAttempts > 16 || wire.Attempt > wire.MaximumAttempts || wire.ClaimVersion == 0 ||
		wire.ClaimVersion >= maximumOIDCMaintenanceCounter || !validLease || !lease.After(observedAt) ||
		!validNotBefore || notBefore.After(observedAt) || !validMaterialExpiry ||
		!materialExpiry.After(observedAt) || lease.After(materialExpiry) ||
		wire.ClientSecretRevision == 0 || wire.ClientSecretRevision > maximumOIDCMaintenanceCounter ||
		!validOIDCMaintenanceClientAuthentication(wire.ClientAuthentication) ||
		!validOIDCMaintenanceClientID(wire.ClientID) || !validOIDCMaintenanceEndpoint(wire.Endpoint) ||
		wire.RefreshGeneration == 0 || wire.RefreshGeneration >= maximumOIDCMaintenanceCounter ||
		!validDigestWire(wire.TokenDigest) || wire.OpaqueReference.KeyVersion == 0 ||
		wire.OpaqueReference.KeyVersion > maximumOIDCKeyVersion ||
		len(wire.OpaqueReference.Ciphertext) < minimumOIDCProtectedTokenBytes ||
		len(wire.OpaqueReference.Ciphertext) > maximumOIDCProtectedTokenBytes {
		return federatedauth.LogoutRetryJob{}, errFederatedAuthPersistence
	}
	bindingID := admission.BindingID
	if provider.Scope == identity.TenantProviderScope {
		_, providerBinding, err := providerBindingFromWire(wire.Provider, false)
		if err != nil {
			return federatedauth.LogoutRetryJob{}, errFederatedAuthPersistence
		}
		bindingID = providerBinding
	}
	if !validOIDCMaintenanceBinding(tenantID, provider, admission, bindingID) {
		return federatedauth.LogoutRetryJob{}, errFederatedAuthPersistence
	}
	job := federatedauth.LogoutRetryJob{
		JobID: jobID, TenantID: tenantID, MaterialID: materialID, SessionFamilyID: familyID,
		Attempt: wire.Attempt, MaximumAttempts: wire.MaximumAttempts, ClaimVersion: wire.ClaimVersion,
		LeaseExpiresAt: lease, NotBefore: notBefore, Provider: provider, Admission: admission, BindingID: bindingID,
		ClientSecretRevision: wire.ClientSecretRevision, ClientAuthentication: wire.ClientAuthentication,
		ClientID: wire.ClientID, Endpoint: wire.Endpoint, RefreshGeneration: wire.RefreshGeneration,
		MaterialExpiresAt: materialExpiry,
		OpaqueReference: federatedauth.ProtectedToken{
			KeyVersion: wire.OpaqueReference.KeyVersion,
			Ciphertext: append([]byte(nil), wire.OpaqueReference.Ciphertext...),
		},
	}
	copy(job.TokenDigest[:], wire.TokenDigest)
	return job, nil
}

func oidcLogoutRetryCompletionToWire(
	update federatedauth.LogoutRetryUpdate,
) (oidcLogoutRetryCompletionWire, error) {
	jobID, err := requiredFederatedEntityIDWire(update.JobID)
	if err != nil || update.Attempt < 1 || update.ExpectedVersion == 0 ||
		update.ExpectedVersion >= maximumOIDCMaintenanceCounter || !validFederatedDatabaseTime(update.ObservedAt) {
		return oidcLogoutRetryCompletionWire{}, errFederatedAuthPersistence
	}
	wire := oidcLogoutRetryCompletionWire{
		JobID: jobID, Attempt: update.Attempt, ExpectedVersion: update.ExpectedVersion,
		Outcome: update.Disposition, CompletedAt: update.ObservedAt,
	}
	switch update.Disposition {
	case federatedauth.LogoutRetryReschedule:
		if !validFederatedDatabaseTime(update.NextTryAt) || !update.NextTryAt.After(update.ObservedAt) ||
			update.NextTryAt.After(update.ObservedAt.Add(15*time.Minute)) {
			return oidcLogoutRetryCompletionWire{}, errFederatedAuthPersistence
		}
		nextTryAt := update.NextTryAt
		wire.NextTryAt = &nextTryAt
	case federatedauth.LogoutRetryComplete, federatedauth.LogoutRetryAmbiguous, federatedauth.LogoutRetryRejected:
		if !update.NextTryAt.IsZero() {
			return oidcLogoutRetryCompletionWire{}, errFederatedAuthPersistence
		}
	default:
		return oidcLogoutRetryCompletionWire{}, errFederatedAuthPersistence
	}
	return wire, nil
}

func validOIDCMaintenanceBinding(
	tenantID identity.EntityID,
	provider identity.ProviderContext,
	admission identity.TenantAdmissionContext,
	bindingID identity.EntityID,
) bool {
	zero := identity.EntityID{}
	switch provider.Scope {
	case identity.TenantProviderScope:
		return tenantID != zero && provider.TenantID == tenantID && bindingID != zero &&
			admission == (identity.TenantAdmissionContext{TenantID: tenantID, BindingID: bindingID})
	case identity.PlatformProviderScope:
		if provider.TenantID != zero {
			return false
		}
		if tenantID == zero {
			return bindingID == zero && admission == (identity.TenantAdmissionContext{})
		}
		return bindingID != zero && admission == (identity.TenantAdmissionContext{TenantID: tenantID, BindingID: bindingID})
	default:
		return false
	}
}

func validOIDCMaintenanceClientAuthentication(value federatedoidc.ClientAuthenticationMode) bool {
	return value == federatedoidc.ClientSecretBasic || value == federatedoidc.ClientSecretPost
}

func validOIDCMaintenanceClientID(value string) bool {
	if len(value) == 0 || len(value) > 512 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func validOIDCMaintenanceEndpoint(value string) bool {
	if len(value) < 9 || len(value) > 4096 || !utf8.ValidString(value) ||
		!strings.HasPrefix(value, "https://") || strings.ContainsAny(value, "# \t\r\n") {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func validOIDCRevocationReason(value federatedauth.RevocationReason) bool {
	return value == federatedauth.RevokeRefreshReuse || value == federatedauth.RevokeRefreshFailure ||
		value == federatedauth.RevokeRefreshKeyFailure || value == federatedauth.RevokeSessionDrift
}

func emptyOIDCRefreshClaimPayload(wire oidcRefreshClaimSnapshotWire) bool {
	return wire.TenantID == nil && wire.EffectiveTenantID == nil && wire.MaterialID == "" &&
		emptyOIDCRefreshClaimedFields(wire)
}

func emptyOIDCRefreshClaimedFields(wire oidcRefreshClaimSnapshotWire) bool {
	return wire.ObservedAt == nil && wire.Generation == 0 && wire.Version == 0 && wire.LeaseExpiresAt == nil && wire.Provider == nil &&
		wire.Admission == nil && wire.BindingID == nil && wire.ClientSecretRevision == 0 && wire.Endpoint == "" &&
		wire.ClientAuthentication == "" && wire.ClientID == "" && wire.Token == nil && len(wire.TokenDigest) == 0 &&
		wire.MaterialExpiresAt == nil && wire.AbsoluteSessionExpiry == nil
}

func validOIDCMaintenanceEffectiveScope(
	originTenantID identity.EntityID,
	effectiveTenantID identity.EntityID,
	provider identity.ProviderContext,
	admission identity.TenantAdmissionContext,
	bindingID identity.EntityID,
) bool {
	if !validOIDCMaintenanceBinding(originTenantID, provider, admission, bindingID) {
		return false
	}
	if originTenantID != (identity.EntityID{}) {
		return effectiveTenantID == originTenantID
	}
	return provider.Scope == identity.PlatformProviderScope && bindingID == (identity.EntityID{}) &&
		admission == (identity.TenantAdmissionContext{})
}

func clearOIDCRefreshClaimSnapshotWire(value *oidcRefreshClaimSnapshotWire) {
	if value == nil {
		return
	}
	if value.Token != nil {
		clear(value.Token.Ciphertext)
	}
	clear(value.TokenDigest)
	*value = oidcRefreshClaimSnapshotWire{}
}

func clearOIDCRefreshCompletionWire(value *oidcRefreshCompletionWire) {
	if value == nil {
		return
	}
	clear(value.SuccessorDigest)
	if value.SuccessorToken != nil {
		clear(value.SuccessorToken.Ciphertext)
	}
	*value = oidcRefreshCompletionWire{}
}

func clearOIDCLogoutRetrySnapshotWire(value *oidcLogoutRetrySnapshotWire) {
	if value == nil {
		return
	}
	clear(value.TokenDigest)
	clear(value.OpaqueReference.Ciphertext)
	*value = oidcLogoutRetrySnapshotWire{}
}
