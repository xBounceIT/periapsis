package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

const (
	installSAMLLogoutActorContextSQL = `select
  set_config('app.tenant_id', $1::uuid::text, true),
  set_config('app.user_id', $2::uuid::text, true)`
	revokeLocalSAMLSessionSQL = `select app.revoke_local_saml_session_v1(
  ($1::jsonb ->> 'authenticatedUserId')::uuid,
  $1::jsonb
)`
)

type samlLogoutRequestWire struct {
	OperationRunID      string `json:"operationRunId"`
	TenantID            string `json:"tenantId"`
	AuthenticatedUserID string `json:"authenticatedUserId"`
	SessionID           string `json:"sessionId"`
	ExpectedVersion     uint64 `json:"expectedVersion"`
	RequestUpstream     bool   `json:"requestUpstream"`
}

type samlLogoutCommandWire struct {
	OperationRunID      string `json:"operationRunId"`
	TenantID            string `json:"tenantId"`
	AuthenticatedUserID string `json:"authenticatedUserId"`
	SessionID           string `json:"sessionId"`
	ExpectedVersion     uint64 `json:"expectedVersion"`
	RequestUpstream     bool   `json:"requestUpstream"`
	RequestDigest       []byte `json:"requestDigest"`
}

type samlLogoutProtectedMaterialWire struct {
	KeyVersion uint32 `json:"keyVersion"`
	Ciphertext []byte `json:"ciphertext"`
}

type samlLogoutSnapshotWire struct {
	OperationRunID      string                             `json:"operationRunId"`
	TenantID            string                             `json:"tenantId"`
	AuthenticatedUserID string                             `json:"authenticatedUserId"`
	SessionID           string                             `json:"sessionId"`
	PreviousVersion     uint64                             `json:"previousVersion"`
	Provider            federatedProviderBindingWire       `json:"provider"`
	BindingID           string                             `json:"bindingId"`
	MaterialID          string                             `json:"materialId"`
	Configuration       *tenantSAMLConfigurationRecordWire `json:"configuration"`
	ProtectedMaterial   *samlLogoutProtectedMaterialWire   `json:"protectedMaterial"`
	RevokedAt           time.Time                          `json:"revokedAt"`
}

var _ federatedauth.SAMLLogoutStore = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) RevokeLocalSAMLSession(
	ctx context.Context,
	command federatedauth.SAMLLogoutCommand,
) (federatedauth.SAMLLogoutSnapshot, error) {
	if repository == nil || repository.begin == nil || ctx == nil || ctx.Err() != nil {
		return federatedauth.SAMLLogoutSnapshot{}, errFederatedAuthPersistence
	}
	wire, err := samlLogoutCommandToWire(command)
	if err != nil {
		return federatedauth.SAMLLogoutSnapshot{}, errFederatedAuthPersistence
	}
	defer clear(wire.RequestDigest)
	snapshot, err := withinTransactionWithOptions(
		ctx,
		repository.begin,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite},
		func(tx databaseTransaction) (federatedauth.SAMLLogoutSnapshot, error) {
			var installedTenantID string
			var installedUserID string
			if err := tx.QueryRow(
				ctx, installSAMLLogoutActorContextSQL, wire.TenantID, wire.AuthenticatedUserID,
			).Scan(&installedTenantID, &installedUserID); err != nil ||
				installedTenantID != wire.TenantID || installedUserID != wire.AuthenticatedUserID {
				return federatedauth.SAMLLogoutSnapshot{}, errFederatedAuthPersistence
			}
			var response samlLogoutSnapshotWire
			defer clearSAMLLogoutSnapshotWire(&response)
			scoped := &FederatedAuthRepository{queryer: tx}
			if err := scoped.queryJSONWithResponseLimit(
				ctx, revokeLocalSAMLSessionSQL, wire, &response,
				maximumFederatedConfigurationResponseBytes+64*1024,
			); err != nil {
				return federatedauth.SAMLLogoutSnapshot{}, err
			}
			return samlLogoutSnapshotFromWire(response, command)
		},
	)
	if err != nil {
		return federatedauth.SAMLLogoutSnapshot{}, errFederatedAuthPersistence
	}
	return snapshot, nil
}

func samlLogoutCommandToWire(
	command federatedauth.SAMLLogoutCommand,
) (samlLogoutCommandWire, error) {
	operationID, operationErr := requiredFederatedEntityIDWire(command.OperationRunID)
	tenantID, tenantErr := requiredFederatedEntityIDWire(command.TenantID)
	userID, userErr := requiredFederatedEntityIDWire(command.AuthenticatedUserID)
	sessionID, sessionErr := requiredFederatedEntityIDWire(command.SessionID)
	if operationErr != nil || tenantErr != nil || userErr != nil || sessionErr != nil ||
		!validFederatedSuccessorRevision(command.ExpectedVersion) ||
		command.OperationRunID == command.TenantID || command.OperationRunID == command.SessionID ||
		command.OperationRunID == command.AuthenticatedUserID ||
		command.TenantID == command.AuthenticatedUserID || command.TenantID == command.SessionID ||
		command.AuthenticatedUserID == command.SessionID {
		return samlLogoutCommandWire{}, errFederatedAuthPersistence
	}
	request := samlLogoutRequestWire{
		OperationRunID: operationID, TenantID: tenantID, AuthenticatedUserID: userID,
		SessionID:       sessionID,
		ExpectedVersion: command.ExpectedVersion, RequestUpstream: command.RequestUpstream,
	}
	document, err := json.Marshal(request)
	if err != nil || len(document) == 0 || len(document) > 16*1024 {
		clear(document)
		return samlLogoutCommandWire{}, errFederatedAuthPersistence
	}
	digest := sha256.Sum256(document)
	clear(document)
	return samlLogoutCommandWire{
		OperationRunID: request.OperationRunID, TenantID: request.TenantID,
		AuthenticatedUserID: request.AuthenticatedUserID, SessionID: request.SessionID,
		ExpectedVersion: request.ExpectedVersion,
		RequestUpstream: request.RequestUpstream,
		RequestDigest:   append([]byte(nil), digest[:]...),
	}, nil
}

func samlLogoutSnapshotFromWire(
	wire samlLogoutSnapshotWire,
	command federatedauth.SAMLLogoutCommand,
) (federatedauth.SAMLLogoutSnapshot, error) {
	operationID, operationErr := parseFederatedEntityIDWire(wire.OperationRunID, false)
	tenantID, tenantErr := parseFederatedEntityIDWire(wire.TenantID, false)
	userID, userErr := parseFederatedEntityIDWire(wire.AuthenticatedUserID, false)
	sessionID, sessionErr := parseFederatedEntityIDWire(wire.SessionID, false)
	materialID, materialErr := parseFederatedEntityIDWire(wire.MaterialID, false)
	provider, bindingID, providerErr := providerBindingFromWire(wire.Provider, false)
	wireBindingID, wireBindingErr := parseFederatedEntityIDWire(wire.BindingID, false)
	revokedAt, validRevokedAt := canonicalFederatedDatabaseTimeFromWire(wire.RevokedAt)
	var configuration federatedauth.TenantSAMLConfiguration
	if wire.Configuration != nil {
		configurationRecord, configurationErr := tenantSAMLConfigurationRecordFromWire(*wire.Configuration)
		if configurationErr == nil {
			compiled, compileErr := compileSAMLLogoutConfiguration(configurationRecord)
			if compileErr == nil && provider == compiled.Authentication.Provider &&
				bindingID == compiled.Authentication.BindingID {
				configuration = compiled
			}
		}
	}
	var protectedMaterial federatedsaml.ProtectedSessionMaterial
	if wire.ProtectedMaterial != nil && wire.ProtectedMaterial.KeyVersion > 0 &&
		len(wire.ProtectedMaterial.Ciphertext) >= 16 &&
		len(wire.ProtectedMaterial.Ciphertext) <= 16*1024 {
		protectedMaterial = federatedsaml.ProtectedSessionMaterial{
			KeyVersion: wire.ProtectedMaterial.KeyVersion,
			Ciphertext: append([]byte(nil), wire.ProtectedMaterial.Ciphertext...),
		}
	}
	if operationErr != nil || tenantErr != nil || userErr != nil || sessionErr != nil || materialErr != nil ||
		providerErr != nil || wireBindingErr != nil ||
		operationID != command.OperationRunID || tenantID != command.TenantID ||
		userID != command.AuthenticatedUserID || sessionID != command.SessionID ||
		wire.PreviousVersion != command.ExpectedVersion ||
		provider.Scope != identity.TenantProviderScope || provider.TenantID != tenantID ||
		bindingID != wireBindingID || materialID == operationID || materialID == tenantID ||
		materialID == userID || materialID == sessionID ||
		!validRevokedAt {
		clear(protectedMaterial.Ciphertext)
		return federatedauth.SAMLLogoutSnapshot{}, errFederatedAuthPersistence
	}
	return federatedauth.SAMLLogoutSnapshot{
		OperationRunID: operationID, TenantID: tenantID, AuthenticatedUserID: userID,
		SessionID:       sessionID,
		PreviousVersion: wire.PreviousVersion, Provider: provider, BindingID: bindingID,
		MaterialID: materialID, Configuration: configuration,
		ProtectedMaterial: protectedMaterial,
		RevokedAt:         revokedAt,
	}, nil
}

func compileSAMLLogoutConfiguration(
	record federatedauth.TenantSAMLConfigurationRecord,
) (federatedauth.TenantSAMLConfiguration, error) {
	document := append([]byte(nil), record.MetadataDocument...)
	defer clear(document)
	metadata, err := federatedsaml.CompileMetadata(federatedsaml.MetadataCompilationRequest{
		Document: document, ExpectedEntityID: record.ExpectedEntityID,
		Revision: record.MetadataRevision, RetrievedAt: record.MetadataRetrievedAt,
		MaximumValidUntil: record.MetadataMaximumValidUntil,
	}, federatedsaml.DefaultLimits())
	if err != nil || metadata.Digest() != record.MetadataDigest {
		return federatedauth.TenantSAMLConfiguration{}, errFederatedAuthPersistence
	}
	authentication := record.Authentication
	authentication.Metadata = metadata
	return federatedauth.TenantSAMLConfiguration{Authentication: authentication}, nil
}

func clearSAMLLogoutSnapshotWire(value *samlLogoutSnapshotWire) {
	if value == nil {
		return
	}
	if value.Configuration != nil {
		clearTenantSAMLConfigurationRecordWire(value.Configuration)
	}
	if value.ProtectedMaterial != nil {
		clear(value.ProtectedMaterial.Ciphertext)
	}
	*value = samlLogoutSnapshotWire{}
}
