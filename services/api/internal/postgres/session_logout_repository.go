package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/sessionlogout"
)

const (
	resolveSessionForLogoutSQL          = `select app.resolve_session_for_logout_v1($1::bytea)`
	revokeLocalSessionForLogoutSQL      = `select app.revoke_local_session_for_logout_v1($1::jsonb)`
	claimLogoutContinuationSQL          = `select app.claim_session_logout_continuation_v1($1::jsonb)`
	installSessionLogoutActorContextSQL = `select
  set_config('app.tenant_id', coalesce($1::uuid::text, ''), true),
  set_config('app.user_id', $2::uuid::text, true)`
	maximumSessionLogoutWire = 4 * 1024 * 1024

	minimumOIDCProtectedTokenBytes = 1 + 12 + 16
	maximumOIDCProtectedTokenBytes = 256*1024 + 12 + 16
	minimumSAMLProtectedTokenBytes = 1 + 12 + 16
	maximumSAMLProtectedTokenBytes = 16 * 1024
	maximumSessionLogoutRevision   = uint64(9_000_000_000_000_000)
)

type sessionLogoutCredentialWire struct {
	SessionID   string  `json:"sessionId"`
	UserID      string  `json:"userId"`
	TenantID    *string `json:"tenantId"`
	TokenDigest []byte  `json:"tokenDigest"`
	CSRFDigest  []byte  `json:"csrfDigest"`
}

type sessionLogoutAuditWire struct {
	RequestID     string `json:"requestId"`
	CorrelationID string `json:"correlationId"`
	RemoteAddress string `json:"remoteAddress"`
	UserAgent     string `json:"userAgent"`
}

type sessionLogoutCommandWire struct {
	OperationRunID        string                 `json:"operationRunId"`
	SessionID             string                 `json:"sessionId"`
	UserID                string                 `json:"userId"`
	TenantID              *string                `json:"tenantId"`
	TokenDigest           []byte                 `json:"tokenDigest"`
	RequestDigest         []byte                 `json:"requestDigest"`
	RequestUpstream       bool                   `json:"requestUpstream"`
	RequestedAt           time.Time              `json:"requestedAt"`
	ContinuationID        string                 `json:"continuationId"`
	ContinuationDigest    []byte                 `json:"continuationDigest"`
	ContinuationExpiresAt time.Time              `json:"continuationExpiresAt"`
	Audit                 sessionLogoutAuditWire `json:"audit"`
}

type sessionLogoutRevokeSnapshotWire struct {
	Category              string     `json:"category"`
	OperationRunID        string     `json:"operationRunId"`
	SessionID             string     `json:"sessionId"`
	UserID                string     `json:"userId"`
	TenantID              *string    `json:"tenantId"`
	PreviousVersion       uint64     `json:"previousVersion"`
	RequestedAt           time.Time  `json:"requestedAt"`
	ObservedAt            time.Time  `json:"observedAt"`
	ContinuationID        *string    `json:"continuationId,omitempty"`
	ContinuationExpiresAt *time.Time `json:"continuationExpiresAt,omitempty"`
	RevokedAt             time.Time  `json:"revokedAt"`
}

type sessionLogoutClaimWire struct {
	ContinuationID string    `json:"continuationId"`
	TokenDigest    []byte    `json:"tokenDigest"`
	ClaimedAt      time.Time `json:"claimedAt"`
}

type sessionLogoutProtectedTokenWire struct {
	KeyVersion uint32 `json:"keyVersion"`
	Ciphertext []byte `json:"ciphertext"`
}

type sessionLogoutProtectedSAMLWire struct {
	KeyVersion uint32 `json:"keyVersion"`
	Ciphertext []byte `json:"ciphertext"`
}

type sessionLogoutClaimSnapshotWire struct {
	Category              string                           `json:"category"`
	RequestedClaimedAt    time.Time                        `json:"requestedClaimedAt"`
	ObservedAt            time.Time                        `json:"observedAt"`
	ContinuationID        string                           `json:"continuationId"`
	OperationRunID        string                           `json:"operationRunId"`
	SessionID             string                           `json:"sessionId"`
	UserID                string                           `json:"userId"`
	TenantID              *string                          `json:"tenantId"`
	PreviousVersion       uint64                           `json:"previousVersion"`
	Provider              *federatedProviderBindingWire    `json:"provider"`
	Admission             *federatedTenantAdmissionWire    `json:"admission,omitempty"`
	BindingID             *string                          `json:"bindingId,omitempty"`
	MaterialID            string                           `json:"materialId"`
	RevokedAt             time.Time                        `json:"revokedAt"`
	ExpiresAt             time.Time                        `json:"expiresAt"`
	EndSessionEndpoint    *string                          `json:"endSessionEndpoint,omitempty"`
	PostLogoutRedirectURI *string                          `json:"postLogoutRedirectUri,omitempty"`
	ProtectedIDToken      *sessionLogoutProtectedTokenWire `json:"protectedIdToken,omitempty"`
	IDTokenDigest         []byte                           `json:"idTokenDigest,omitempty"`
	MaterialExpiresAt     *time.Time                       `json:"materialExpiresAt,omitempty"`
	LogoutRetryJobID      *string                          `json:"logoutRetryJobId,omitempty"`
	Configuration         json.RawMessage                  `json:"configuration,omitempty"`
	ProtectedMaterial     *sessionLogoutProtectedSAMLWire  `json:"protectedMaterial,omitempty"`
}

var _ sessionlogout.Store = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) ResolveSessionForLogout(
	ctx context.Context,
	tokenDigest [sha256.Size]byte,
) (sessionlogout.Credential, error) {
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil ||
		tokenDigest == ([sha256.Size]byte{}) {
		return sessionlogout.Credential{}, sessionlogout.ErrInvalidAuthentication
	}
	var raw []byte
	err := repository.queryer.QueryRow(ctx, resolveSessionForLogoutSQL, tokenDigest[:]).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && sessionLogoutJSONIsNull(raw) {
		clear(raw)
		return sessionlogout.Credential{}, sessionlogout.ErrNotFound
	}
	if err != nil || ctx.Err() != nil || len(raw) > maximumSessionLogoutWire {
		clear(raw)
		return sessionlogout.Credential{}, sessionlogout.ErrUnavailable
	}
	defer clear(raw)
	var wire sessionLogoutCredentialWire
	if !decodeSessionLogoutJSON(raw, &wire) {
		clearSessionLogoutCredentialWire(&wire)
		return sessionlogout.Credential{}, sessionlogout.ErrUnavailable
	}
	defer clearSessionLogoutCredentialWire(&wire)
	credential, err := sessionLogoutCredentialFromWire(wire)
	if err != nil || credential.TokenDigest != tokenDigest {
		return sessionlogout.Credential{}, sessionlogout.ErrUnavailable
	}
	return credential, nil
}

func (repository *FederatedAuthRepository) RevokeLocalSession(
	ctx context.Context,
	command sessionlogout.LocalRevokeCommand,
) (sessionlogout.LocalRevokeSnapshot, error) {
	if repository == nil || repository.begin == nil || ctx == nil || ctx.Err() != nil {
		return sessionlogout.LocalRevokeSnapshot{}, sessionlogout.ErrUnavailable
	}
	wire, err := sessionLogoutCommandToWire(command)
	if err != nil {
		return sessionlogout.LocalRevokeSnapshot{}, sessionlogout.ErrInvalidInput
	}
	defer clearSessionLogoutCommandWire(&wire)
	snapshot, err := withinTransactionWithOptions(
		ctx, repository.begin,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite},
		func(tx databaseTransaction) (sessionlogout.LocalRevokeSnapshot, error) {
			expectedTenantID := ""
			if wire.TenantID != nil {
				expectedTenantID = *wire.TenantID
			}
			var tenantID, userID string
			if err := tx.QueryRow(
				ctx, installSessionLogoutActorContextSQL, wire.TenantID, wire.UserID,
			).Scan(&tenantID, &userID); err != nil || ctx.Err() != nil ||
				tenantID != expectedTenantID || userID != wire.UserID {
				return sessionlogout.LocalRevokeSnapshot{}, sessionlogout.ErrUnavailable
			}
			var response *sessionLogoutRevokeSnapshotWire
			scoped := &FederatedAuthRepository{queryer: tx}
			if err := scoped.queryBoundedJSON(
				ctx, revokeLocalSessionForLogoutSQL, wire, &response, maximumSessionLogoutWire,
			); err != nil || ctx.Err() != nil || response == nil {
				return sessionlogout.LocalRevokeSnapshot{}, sessionlogout.ErrUnavailable
			}
			snapshot, err := sessionLogoutRevokeSnapshotFromWire(*response, command)
			if err != nil || ctx.Err() != nil {
				return sessionlogout.LocalRevokeSnapshot{}, sessionlogout.ErrUnavailable
			}
			return snapshot, nil
		},
	)
	if err != nil {
		return sessionlogout.LocalRevokeSnapshot{}, sessionlogout.ErrUnavailable
	}
	return snapshot, nil
}

func (repository *FederatedAuthRepository) ClaimLogoutContinuation(
	ctx context.Context,
	claim sessionlogout.ContinuationClaim,
) (sessionlogout.ContinuationSnapshot, error) {
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil {
		return sessionlogout.ContinuationSnapshot{}, sessionlogout.ErrUnavailable
	}
	wire, err := sessionLogoutClaimToWire(claim)
	if err != nil {
		return sessionlogout.ContinuationSnapshot{}, sessionlogout.ErrInvalidInput
	}
	defer clear(wire.TokenDigest)
	var response *sessionLogoutClaimSnapshotWire
	if err := repository.queryBoundedJSON(
		ctx, claimLogoutContinuationSQL, wire, &response, maximumSessionLogoutWire,
	); err != nil || ctx.Err() != nil {
		return sessionlogout.ContinuationSnapshot{}, sessionlogout.ErrUnavailable
	}
	if response == nil {
		return sessionlogout.ContinuationSnapshot{}, sessionlogout.ErrNotFound
	}
	defer clearSessionLogoutClaimSnapshotWire(response)
	snapshot, err := sessionLogoutClaimSnapshotFromWire(*response, claim)
	if err != nil {
		return sessionlogout.ContinuationSnapshot{}, sessionlogout.ErrUnavailable
	}
	return snapshot, nil
}

func sessionLogoutCredentialFromWire(wire sessionLogoutCredentialWire) (sessionlogout.Credential, error) {
	sessionID, sessionErr := parseFederatedEntityIDWire(wire.SessionID, false)
	userID, userErr := parseFederatedEntityIDWire(wire.UserID, false)
	tenantID, tenantErr := optionalSessionLogoutEntityID(wire.TenantID)
	if sessionErr != nil || userErr != nil || tenantErr != nil || !validDigestWire(wire.TokenDigest) ||
		!validDigestWire(wire.CSRFDigest) || sessionID == userID || sessionID == tenantID || userID == tenantID {
		return sessionlogout.Credential{}, errFederatedAuthPersistence
	}
	var tokenDigest, csrfDigest [sha256.Size]byte
	copy(tokenDigest[:], wire.TokenDigest)
	copy(csrfDigest[:], wire.CSRFDigest)
	return sessionlogout.Credential{
		SessionID: sessionID, UserID: userID, TenantID: tenantID,
		TokenDigest: tokenDigest, CSRFDigest: csrfDigest,
	}, nil
}

func sessionLogoutCommandToWire(command sessionlogout.LocalRevokeCommand) (sessionLogoutCommandWire, error) {
	operationID, operationErr := requiredFederatedEntityIDWire(command.OperationRunID)
	sessionID, sessionErr := requiredFederatedEntityIDWire(command.Credential.SessionID)
	userID, userErr := requiredFederatedEntityIDWire(command.Credential.UserID)
	tenantID, tenantErr := optionalSessionLogoutEntityIDWire(command.Credential.TenantID)
	continuationID, continuationErr := requiredFederatedEntityIDWire(command.ContinuationID)
	requestID, requestErr := requiredFederatedEntityIDWire(command.Audit.RequestID)
	correlationID, correlationErr := requiredFederatedEntityIDWire(command.Audit.CorrelationID)
	if operationErr != nil || sessionErr != nil || userErr != nil || tenantErr != nil || continuationErr != nil ||
		requestErr != nil || correlationErr != nil || command.OperationRunID == command.Credential.SessionID ||
		command.OperationRunID == command.Credential.UserID || command.OperationRunID == command.ContinuationID ||
		command.Credential.SessionID == command.Credential.UserID ||
		!validDigestWire(command.Credential.TokenDigest[:]) || !validDigestWire(command.RequestDigest[:]) ||
		!validDigestWire(command.ContinuationDigest[:]) || !command.RequestUpstream ||
		!validFederatedDatabaseTime(command.RequestedAt) ||
		!validFederatedDatabaseTime(command.ContinuationExpiresAt) ||
		!command.ContinuationExpiresAt.After(command.RequestedAt) ||
		command.ContinuationExpiresAt.After(command.RequestedAt.Add(2*time.Minute)) ||
		!validSessionLogoutAudit(command.Audit.RemoteAddress, command.Audit.UserAgent) {
		return sessionLogoutCommandWire{}, errFederatedAuthPersistence
	}
	return sessionLogoutCommandWire{
		OperationRunID: operationID, SessionID: sessionID, UserID: userID, TenantID: tenantID,
		TokenDigest:   append([]byte(nil), command.Credential.TokenDigest[:]...),
		RequestDigest: append([]byte(nil), command.RequestDigest[:]...), RequestUpstream: true,
		RequestedAt: command.RequestedAt, ContinuationID: continuationID,
		ContinuationDigest:    append([]byte(nil), command.ContinuationDigest[:]...),
		ContinuationExpiresAt: command.ContinuationExpiresAt,
		Audit: sessionLogoutAuditWire{
			RequestID: requestID, CorrelationID: correlationID,
			RemoteAddress: command.Audit.RemoteAddress.String(), UserAgent: command.Audit.UserAgent,
		},
	}, nil
}

func sessionLogoutRevokeSnapshotFromWire(
	wire sessionLogoutRevokeSnapshotWire,
	command sessionlogout.LocalRevokeCommand,
) (sessionlogout.LocalRevokeSnapshot, error) {
	operationID, operationErr := parseFederatedEntityIDWire(wire.OperationRunID, false)
	sessionID, sessionErr := parseFederatedEntityIDWire(wire.SessionID, false)
	userID, userErr := parseFederatedEntityIDWire(wire.UserID, false)
	tenantID, tenantErr := optionalSessionLogoutEntityID(wire.TenantID)
	requestedAt, validRequestedAt := canonicalFederatedDatabaseTimeFromWire(wire.RequestedAt)
	observedAt, validObservedAt := canonicalFederatedDatabaseTimeFromWire(wire.ObservedAt)
	revokedAt, validRevokedAt := canonicalFederatedDatabaseTimeFromWire(wire.RevokedAt)
	if operationErr != nil || sessionErr != nil || userErr != nil || tenantErr != nil ||
		!validRequestedAt || !validObservedAt || !validRevokedAt ||
		operationID != command.OperationRunID || sessionID != command.Credential.SessionID ||
		userID != command.Credential.UserID || tenantID != command.Credential.TenantID ||
		!requestedAt.Equal(command.RequestedAt) ||
		observedAt.Before(command.RequestedAt.Add(-5*time.Minute)) ||
		observedAt.After(command.RequestedAt.Add(5*time.Minute)) || revokedAt.After(observedAt) ||
		wire.PreviousVersion == 0 || wire.PreviousVersion > maximumSessionLogoutRevision {
		return sessionlogout.LocalRevokeSnapshot{}, errFederatedAuthPersistence
	}
	snapshot := sessionlogout.LocalRevokeSnapshot{
		Category: sessionlogout.LocalRevokeCategory(wire.Category), OperationRunID: operationID,
		SessionID: sessionID, UserID: userID, TenantID: tenantID,
		PreviousVersion: wire.PreviousVersion, RequestedAt: requestedAt,
		ObservedAt: observedAt, RevokedAt: revokedAt,
	}
	switch snapshot.Category {
	case sessionlogout.LocalOnly:
		if wire.ContinuationID != nil || wire.ContinuationExpiresAt != nil {
			return sessionlogout.LocalRevokeSnapshot{}, errFederatedAuthPersistence
		}
	case sessionlogout.LogoutContinuation:
		if wire.ContinuationID == nil || wire.ContinuationExpiresAt == nil {
			return sessionlogout.LocalRevokeSnapshot{}, errFederatedAuthPersistence
		}
		continuationID, err := parseFederatedEntityIDWire(*wire.ContinuationID, false)
		expiresAt, validExpiry := canonicalFederatedDatabaseTimeFromWire(*wire.ContinuationExpiresAt)
		continuationTTL := command.ContinuationExpiresAt.Sub(command.RequestedAt)
		if err != nil || !validExpiry || continuationID != command.ContinuationID ||
			continuationTTL <= 0 || continuationTTL > 2*time.Minute ||
			!expiresAt.Equal(observedAt.Add(continuationTTL)) {
			return sessionlogout.LocalRevokeSnapshot{}, errFederatedAuthPersistence
		}
		snapshot.ContinuationID = continuationID
		snapshot.ContinuationExpiresAt = expiresAt
	default:
		return sessionlogout.LocalRevokeSnapshot{}, errFederatedAuthPersistence
	}
	return snapshot, nil
}

func sessionLogoutClaimToWire(claim sessionlogout.ContinuationClaim) (sessionLogoutClaimWire, error) {
	continuationID, err := requiredFederatedEntityIDWire(claim.ContinuationID)
	if err != nil || !validDigestWire(claim.ContinuationDigest[:]) ||
		!validFederatedDatabaseTime(claim.ClaimedAt) {
		return sessionLogoutClaimWire{}, errFederatedAuthPersistence
	}
	return sessionLogoutClaimWire{
		ContinuationID: continuationID,
		TokenDigest:    append([]byte(nil), claim.ContinuationDigest[:]...),
		ClaimedAt:      claim.ClaimedAt,
	}, nil
}

func sessionLogoutClaimSnapshotFromWire(
	wire sessionLogoutClaimSnapshotWire,
	claim sessionlogout.ContinuationClaim,
) (sessionlogout.ContinuationSnapshot, error) {
	continuationID, continuationErr := parseFederatedEntityIDWire(wire.ContinuationID, false)
	operationID, operationErr := parseFederatedEntityIDWire(wire.OperationRunID, false)
	sessionID, sessionErr := parseFederatedEntityIDWire(wire.SessionID, false)
	userID, userErr := parseFederatedEntityIDWire(wire.UserID, false)
	tenantID, tenantErr := optionalSessionLogoutEntityID(wire.TenantID)
	materialID, materialErr := parseFederatedEntityIDWire(wire.MaterialID, false)
	requestedClaimedAt, validRequestedClaimedAt := canonicalFederatedDatabaseTimeFromWire(wire.RequestedClaimedAt)
	observedAt, validObservedAt := canonicalFederatedDatabaseTimeFromWire(wire.ObservedAt)
	revokedAt, validRevokedAt := canonicalFederatedDatabaseTimeFromWire(wire.RevokedAt)
	expiresAt, validExpiresAt := canonicalFederatedDatabaseTimeFromWire(wire.ExpiresAt)
	if continuationErr != nil || operationErr != nil || sessionErr != nil || userErr != nil || tenantErr != nil ||
		materialErr != nil || !validRequestedClaimedAt || !validObservedAt || !validRevokedAt || !validExpiresAt ||
		!requestedClaimedAt.Equal(claim.ClaimedAt) || observedAt.Before(claim.ClaimedAt.Add(-5*time.Minute)) ||
		observedAt.After(claim.ClaimedAt.Add(5*time.Minute)) || revokedAt.After(observedAt) ||
		!expiresAt.After(observedAt) || expiresAt.After(observedAt.Add(2*time.Minute)) ||
		continuationID != claim.ContinuationID ||
		wire.PreviousVersion == 0 || wire.PreviousVersion > maximumSessionLogoutRevision || wire.Provider == nil {
		return sessionlogout.ContinuationSnapshot{}, errFederatedAuthPersistence
	}
	snapshot := sessionlogout.ContinuationSnapshot{
		Category: sessionlogout.ClaimCategory(wire.Category), RequestedClaimedAt: requestedClaimedAt,
		ObservedAt: observedAt, ContinuationID: continuationID,
		OperationRunID: operationID, SessionID: sessionID, UserID: userID, TenantID: tenantID,
		PreviousVersion: wire.PreviousVersion, MaterialID: materialID, RevokedAt: revokedAt, ExpiresAt: expiresAt,
	}
	switch snapshot.Category {
	case sessionlogout.ClaimOIDC:
		return oidcLogoutClaimSnapshotFromWire(snapshot, wire)
	case sessionlogout.ClaimSAML:
		return samlLogoutClaimSnapshotFromWire(snapshot, wire)
	default:
		return sessionlogout.ContinuationSnapshot{}, errFederatedAuthPersistence
	}
}

func oidcLogoutClaimSnapshotFromWire(
	snapshot sessionlogout.ContinuationSnapshot,
	wire sessionLogoutClaimSnapshotWire,
) (sessionlogout.ContinuationSnapshot, error) {
	if wire.EndSessionEndpoint == nil || wire.PostLogoutRedirectURI == nil ||
		wire.ProtectedIDToken == nil || wire.MaterialExpiresAt == nil ||
		!validDigestWire(wire.IDTokenDigest) || wire.BindingID != nil || len(wire.Configuration) != 0 ||
		wire.ProtectedMaterial != nil {
		return sessionlogout.ContinuationSnapshot{}, errFederatedAuthPersistence
	}
	provider, admission, err := sessionLogoutOIDCMaterialProviderFromWire(
		*wire.Provider, wire.Admission, snapshot.TenantID,
	)
	expiresAt, validExpiry := canonicalFederatedDatabaseTimeFromWire(*wire.MaterialExpiresAt)
	if err != nil || !validExpiry || *wire.EndSessionEndpoint == "" ||
		!validSessionLogoutPostLogoutRedirect(*wire.PostLogoutRedirectURI) ||
		wire.ProtectedIDToken.KeyVersion == 0 ||
		len(wire.ProtectedIDToken.Ciphertext) < minimumOIDCProtectedTokenBytes ||
		len(wire.ProtectedIDToken.Ciphertext) > maximumOIDCProtectedTokenBytes {
		return sessionlogout.ContinuationSnapshot{}, errFederatedAuthPersistence
	}
	if wire.LogoutRetryJobID != nil {
		if _, err := parseFederatedEntityIDWire(*wire.LogoutRetryJobID, false); err != nil {
			return sessionlogout.ContinuationSnapshot{}, errFederatedAuthPersistence
		}
	}
	snapshot.Provider = provider
	snapshot.Admission = admission
	snapshot.EndSessionEndpoint = *wire.EndSessionEndpoint
	snapshot.PostLogoutRedirectURI = *wire.PostLogoutRedirectURI
	snapshot.ProtectedIDToken = federatedauth.ProtectedToken{
		KeyVersion: wire.ProtectedIDToken.KeyVersion,
		Ciphertext: append([]byte(nil), wire.ProtectedIDToken.Ciphertext...),
	}
	copy(snapshot.IDTokenDigest[:], wire.IDTokenDigest)
	snapshot.MaterialExpiresAt = expiresAt
	return snapshot, nil
}

// sessionLogoutOIDCMaterialProviderFromWire separates the current local
// session's tenant from the immutable authority used to seal OIDC material.
// A direct-platform session may be rotated into a tenant session without
// resealing its tokens; in that case the database-proven switch bridge returns
// a tenant-owned local session together with the original platform/no-
// admission cryptographic context.
func sessionLogoutOIDCMaterialProviderFromWire(
	providerWire federatedProviderBindingWire,
	admissionWire *federatedTenantAdmissionWire,
	tenantID identity.EntityID,
) (identity.ProviderContext, identity.TenantAdmissionContext, error) {
	if providerWire.Scope != federatedPlatformProviderScopeWire || admissionWire != nil {
		return sessionLogoutProviderFromWire(providerWire, admissionWire, tenantID)
	}
	provider, bindingID, err := providerBindingFromWire(providerWire, true)
	if err != nil || bindingID != (identity.EntityID{}) {
		return identity.ProviderContext{}, identity.TenantAdmissionContext{}, errFederatedAuthPersistence
	}
	return provider, identity.TenantAdmissionContext{}, nil
}

func samlLogoutClaimSnapshotFromWire(
	snapshot sessionlogout.ContinuationSnapshot,
	wire sessionLogoutClaimSnapshotWire,
) (sessionlogout.ContinuationSnapshot, error) {
	if wire.EndSessionEndpoint != nil || wire.PostLogoutRedirectURI != nil || wire.ProtectedIDToken != nil ||
		len(wire.IDTokenDigest) != 0 || wire.MaterialExpiresAt != nil || wire.LogoutRetryJobID != nil ||
		len(wire.Configuration) == 0 || sessionLogoutJSONIsNull(wire.Configuration) || wire.ProtectedMaterial == nil {
		return sessionlogout.ContinuationSnapshot{}, errFederatedAuthPersistence
	}
	provider, providerBindingID, err := providerBindingFromWire(*wire.Provider, true)
	if err != nil {
		return sessionlogout.ContinuationSnapshot{}, errFederatedAuthPersistence
	}
	bindingID, bindingErr := optionalSessionLogoutEntityID(wire.BindingID)
	if bindingErr != nil {
		return sessionlogout.ContinuationSnapshot{}, errFederatedAuthPersistence
	}
	protected := wire.ProtectedMaterial
	if protected.KeyVersion == 0 || len(protected.Ciphertext) < minimumSAMLProtectedTokenBytes ||
		len(protected.Ciphertext) > maximumSAMLProtectedTokenBytes {
		return sessionlogout.ContinuationSnapshot{}, errFederatedAuthPersistence
	}
	var configuration federatedsaml.StoredLogoutConfiguration
	switch provider.Scope {
	case identity.TenantProviderScope:
		if snapshot.TenantID == (identity.EntityID{}) || provider.TenantID != snapshot.TenantID ||
			providerBindingID == (identity.EntityID{}) || bindingID != providerBindingID || wire.Admission != nil {
			return sessionlogout.ContinuationSnapshot{}, errFederatedAuthPersistence
		}
		var record tenantSAMLConfigurationRecordWire
		if !decodeSessionLogoutJSON(wire.Configuration, &record) {
			clearTenantSAMLConfigurationRecordWire(&record)
			return sessionlogout.ContinuationSnapshot{}, errFederatedAuthPersistence
		}
		defer clearTenantSAMLConfigurationRecordWire(&record)
		compiled, compileErr := tenantSAMLConfigurationRecordFromWire(record)
		if compileErr != nil {
			return sessionlogout.ContinuationSnapshot{}, errFederatedAuthPersistence
		}
		logoutConfiguration, compileErr := compileSAMLLogoutConfiguration(compiled)
		if compileErr != nil {
			return sessionlogout.ContinuationSnapshot{}, errFederatedAuthPersistence
		}
		configuration = storedSAMLLogoutConfiguration(logoutConfiguration.Authentication)
	case identity.PlatformProviderScope:
		if providerBindingID != (identity.EntityID{}) || bindingID != (identity.EntityID{}) {
			return sessionlogout.ContinuationSnapshot{}, errFederatedAuthPersistence
		}
		admission, admissionErr := sessionLogoutPlatformAdmissionFromWire(wire.Admission, snapshot.TenantID)
		if admissionErr != nil {
			return sessionlogout.ContinuationSnapshot{}, errFederatedAuthPersistence
		}
		var direct directPlatformSAMLConfigurationWire
		if !decodeSessionLogoutJSON(wire.Configuration, &direct) {
			clearPlatformSAMLConfigurationWire(&direct)
			return sessionlogout.ContinuationSnapshot{}, errFederatedAuthPersistence
		}
		defer clearPlatformSAMLConfigurationWire(&direct)
		compiled, _, compileErr := platformSAMLConfigurationFromWire(direct)
		if compileErr != nil {
			return sessionlogout.ContinuationSnapshot{}, errFederatedAuthPersistence
		}
		configuration = storedSAMLLogoutConfiguration(compiled.Authentication)
		snapshot.Admission = admission
	default:
		return sessionlogout.ContinuationSnapshot{}, errFederatedAuthPersistence
	}
	if configuration.Provider != provider || configuration.MaterialBindingID != bindingID {
		return sessionlogout.ContinuationSnapshot{}, errFederatedAuthPersistence
	}
	snapshot.Provider = provider
	snapshot.BindingID = bindingID
	snapshot.SAMLConfiguration = configuration
	snapshot.ProtectedSAML = federatedsaml.ProtectedSessionMaterial{
		KeyVersion: protected.KeyVersion, Ciphertext: append([]byte(nil), protected.Ciphertext...),
	}
	return snapshot, nil
}

func validSessionLogoutPostLogoutRedirect(value string) bool {
	if len(value) < len("https://a/signed-out") || len(value) > 4096 || !utf8.ValidString(value) {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "/signed-out" ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.User != nil || parsed.String() != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func storedSAMLLogoutConfiguration(configuration federatedsaml.Configuration) federatedsaml.StoredLogoutConfiguration {
	return federatedsaml.StoredLogoutConfiguration{
		Authority: configuration.Authority, Provider: configuration.Provider,
		MaterialBindingID: configuration.BindingID, PlatformLoginRevision: configuration.PlatformLoginRevision,
		SPEntityID: configuration.SPEntityID, SLORedirectURL: configuration.Metadata.SLORedirectURL(),
		SPKeyRevision:              configuration.SPKeyRevision,
		RedirectSignatureAlgorithm: configuration.RedirectSignatureAlgorithm,
	}
}

func sessionLogoutPlatformAdmissionFromWire(
	wire *federatedTenantAdmissionWire,
	tenantID identity.EntityID,
) (identity.TenantAdmissionContext, error) {
	if wire == nil {
		if tenantID != (identity.EntityID{}) {
			return identity.TenantAdmissionContext{}, errFederatedAuthPersistence
		}
		return identity.TenantAdmissionContext{}, nil
	}
	admission, err := tenantAdmissionFromWire(*wire)
	if err != nil || tenantID == (identity.EntityID{}) || admission.TenantID != tenantID {
		return identity.TenantAdmissionContext{}, errFederatedAuthPersistence
	}
	return admission, nil
}

func sessionLogoutProviderFromWire(
	providerWire federatedProviderBindingWire,
	admissionWire *federatedTenantAdmissionWire,
	tenantID identity.EntityID,
) (identity.ProviderContext, identity.TenantAdmissionContext, error) {
	switch providerWire.Scope {
	case federatedTenantProviderScopeWire:
		if admissionWire != nil || tenantID == (identity.EntityID{}) {
			return identity.ProviderContext{}, identity.TenantAdmissionContext{}, errFederatedAuthPersistence
		}
		provider, bindingID, err := providerBindingFromWire(providerWire, false)
		if err != nil || provider.TenantID != tenantID {
			return identity.ProviderContext{}, identity.TenantAdmissionContext{}, errFederatedAuthPersistence
		}
		return provider, identity.TenantAdmissionContext{TenantID: tenantID, BindingID: bindingID}, nil
	case federatedPlatformProviderScopeWire:
		provider, bindingID, err := providerBindingFromWire(providerWire, true)
		if err != nil || bindingID != (identity.EntityID{}) {
			return identity.ProviderContext{}, identity.TenantAdmissionContext{}, errFederatedAuthPersistence
		}
		if admissionWire == nil {
			if tenantID != (identity.EntityID{}) {
				return identity.ProviderContext{}, identity.TenantAdmissionContext{}, errFederatedAuthPersistence
			}
			return provider, identity.TenantAdmissionContext{}, nil
		}
		admission, err := tenantAdmissionFromWire(*admissionWire)
		if err != nil || admission.TenantID != tenantID || tenantID == (identity.EntityID{}) {
			return identity.ProviderContext{}, identity.TenantAdmissionContext{}, errFederatedAuthPersistence
		}
		return provider, admission, nil
	default:
		return identity.ProviderContext{}, identity.TenantAdmissionContext{}, errFederatedAuthPersistence
	}
}

func optionalSessionLogoutEntityID(value *string) (identity.EntityID, error) {
	if value == nil {
		return identity.EntityID{}, nil
	}
	return parseFederatedEntityIDWire(*value, false)
}

func optionalSessionLogoutEntityIDWire(value identity.EntityID) (*string, error) {
	if value == (identity.EntityID{}) {
		return nil, nil
	}
	encoded, err := requiredFederatedEntityIDWire(value)
	if err != nil {
		return nil, err
	}
	return &encoded, nil
}

func validSessionLogoutAudit(address netip.Addr, userAgent string) bool {
	if !address.IsValid() || userAgent == "" || len(userAgent) > 512 || !utf8.ValidString(userAgent) {
		return false
	}
	for _, character := range userAgent {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func sessionLogoutJSONIsNull(raw []byte) bool {
	return len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func decodeSessionLogoutJSON(raw []byte, destination any) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

func clearSessionLogoutCredentialWire(value *sessionLogoutCredentialWire) {
	if value == nil {
		return
	}
	clear(value.TokenDigest)
	clear(value.CSRFDigest)
	*value = sessionLogoutCredentialWire{}
}

func clearSessionLogoutCommandWire(value *sessionLogoutCommandWire) {
	if value == nil {
		return
	}
	clear(value.TokenDigest)
	clear(value.RequestDigest)
	clear(value.ContinuationDigest)
	*value = sessionLogoutCommandWire{}
}

func clearSessionLogoutClaimSnapshotWire(value *sessionLogoutClaimSnapshotWire) {
	if value == nil {
		return
	}
	if value.ProtectedIDToken != nil {
		clear(value.ProtectedIDToken.Ciphertext)
	}
	clear(value.IDTokenDigest)
	clear(value.Configuration)
	if value.ProtectedMaterial != nil {
		clear(value.ProtectedMaterial.Ciphertext)
	}
	*value = sessionLogoutClaimSnapshotWire{}
}
