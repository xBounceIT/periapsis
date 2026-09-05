package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

const (
	maximumPlatformIdentityProviderProjectionBytes  = 64 * 1024
	platformIdentityProviderRevisionConflictMessage = "platform identity provider revision conflict"
)

// PlatformIdentityProviderRepository is the PostgreSQL adapter for the
// platform-owned OIDC/SAML administration boundary. It deliberately calls
// only the security-definer ABI and installs the exact actor in every
// transaction; runtime roles have no direct table privileges.
type PlatformIdentityProviderRepository struct {
	begin transactionBeginner
	newID func() (uuid.UUID, error)
}

var _ platformidentityprovider.Repository = (*PlatformIdentityProviderRepository)(nil)

func NewPlatformIdentityProviderRepository(pool *pgxpool.Pool) *PlatformIdentityProviderRepository {
	return &PlatformIdentityProviderRepository{
		begin: poolTransactionBeginner(pool),
		newID: uuid.NewV7,
	}
}

func (repository *PlatformIdentityProviderRepository) List(
	ctx context.Context,
	params platformidentityprovider.ListParams,
) ([]platformidentityprovider.ProviderSummary, error) {
	if params.Limit < 1 || params.Limit > 200 ||
		params.After != nil && !platformIdentityProviderUUIDv7(*params.After) {
		return nil, authentication.ErrInvalidInput
	}
	return withPlatformIdentityProviderTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) ([]platformidentityprovider.ProviderSummary, error) {
			documents, err := queries.ListPlatformAuthProviders(ctx, dbsql.ListPlatformAuthProvidersParams{
				SessionID:            toDatabaseUUID(params.SessionID),
				AuthenticationMethod: params.AuthenticationMethod,
				AfterProviderID:      optionalDatabaseUUID(params.After),
				PageSize:             params.Limit,
				IncludeArchived:      params.IncludeArchived,
			})
			if err != nil {
				return nil, err
			}
			providers := make([]platformidentityprovider.ProviderSummary, 0, len(documents))
			for _, document := range documents {
				provider, decodeErr := decodePlatformIdentityProviderSummary(document)
				if decodeErr != nil {
					return nil, decodeErr
				}
				providers = append(providers, provider)
			}
			return providers, nil
		},
	)
}

func (repository *PlatformIdentityProviderRepository) Get(
	ctx context.Context,
	params platformidentityprovider.GetParams,
) (platformidentityprovider.Provider, error) {
	if !platformIdentityProviderUUIDv7(params.ProviderID) {
		return platformidentityprovider.Provider{}, authentication.ErrInvalidInput
	}
	return withPlatformIdentityProviderTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityprovider.Provider, error) {
			document, err := queries.GetPlatformAuthProvider(ctx, dbsql.GetPlatformAuthProviderParams{
				SessionID:            toDatabaseUUID(params.SessionID),
				ProviderID:           toDatabaseUUID(params.ProviderID),
				AuthenticationMethod: params.AuthenticationMethod,
			})
			if err != nil {
				return platformidentityprovider.Provider{}, err
			}
			return decodePlatformIdentityProvider(document)
		},
	)
}

func (repository *PlatformIdentityProviderRepository) Create(
	ctx context.Context,
	params platformidentityprovider.CreateParams,
) (platformidentityprovider.CreateResult, error) {
	documents, err := buildPlatformIdentityProviderCreateDocuments(
		params.Kind,
		params.Configuration,
	)
	if err != nil || !platformIdentityProviderUUIDv7(params.CommandID) ||
		!platformIdentityProviderUUIDv7(params.ProviderID) || params.Key == "" ||
		params.DisplayName == "" || params.Reason == "" || params.ValidateResult == nil {
		return platformidentityprovider.CreateResult{}, authentication.ErrInvalidInput
	}
	event, err := eventArguments(params.Event)
	if err != nil {
		return platformidentityprovider.CreateResult{}, authentication.ErrInvalidInput
	}
	auditID, err := platformIdentityProviderAuditID(repository)
	if err != nil {
		return platformidentityprovider.CreateResult{}, err
	}
	keyDigest := append([]byte(nil), params.KeyDigest[:]...)
	requestDigest := append([]byte(nil), params.RequestDigest[:]...)
	defer clear(keyDigest)
	defer clear(requestDigest)

	return withPlatformIdentityProviderTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityprovider.CreateResult, error) {
			row, queryErr := createPlatformIdentityProvider(
				ctx, queries, params, documents, keyDigest,
				requestDigest, auditID, event,
			)
			if queryErr != nil {
				return platformidentityprovider.CreateResult{}, queryErr
			}
			providerID, mapErr := domainUUID(row.ProviderID)
			if mapErr != nil {
				return platformidentityprovider.CreateResult{}, authentication.ErrUnavailable
			}
			provider, decodeErr := decodePlatformIdentityProvider(row.Document)
			if decodeErr != nil {
				return platformidentityprovider.CreateResult{}, authentication.ErrUnavailable
			}
			result, restoreErr := platformidentityprovider.RestoreCreateResult(
				platformidentityprovider.CreateResultInput{
					ProviderID: providerID,
					Version:    row.Version,
					Replayed:   row.Replayed,
					Provider:   provider,
				},
			)
			if restoreErr != nil {
				return platformidentityprovider.CreateResult{}, authentication.ErrUnavailable
			}
			validated, validationErr := params.ValidateResult(result)
			if validationErr != nil {
				return platformidentityprovider.CreateResult{}, authentication.ErrUnavailable
			}
			return validated, nil
		},
	)
}

type platformIdentityProviderCreateRow struct {
	ProviderID pgtype.UUID
	Version    int64
	Replayed   bool
	Document   []byte
}

func createPlatformIdentityProvider(
	ctx context.Context,
	queries *dbsql.Queries,
	params platformidentityprovider.CreateParams,
	documents platformIdentityProviderCreateDocuments,
	keyDigest, requestDigest []byte,
	auditID uuid.UUID,
	event auditArguments,
) (*platformIdentityProviderCreateRow, error) {
	if queries == nil {
		return nil, authentication.ErrUnavailable
	}
	switch params.Kind {
	case platformidentityprovider.ProviderKindLDAP:
		audit := platformLDAPAuditDocument(
			auditID, params.SessionParams, params.Event, params.Reason,
		)
		request, err := json.Marshal(struct {
			SessionID            uuid.UUID       `json:"sessionId"`
			AuthenticationMethod string          `json:"authenticationMethod"`
			ProviderID           uuid.UUID       `json:"providerId"`
			CommandID            uuid.UUID       `json:"commandId"`
			KeyDigest            string          `json:"keyDigest"`
			RequestDigest        string          `json:"requestDigest"`
			Key                  string          `json:"key"`
			DisplayName          string          `json:"displayName"`
			Description          string          `json:"description"`
			Configuration        json.RawMessage `json:"configuration"`
			Endpoints            json.RawMessage `json:"endpoints"`
			Audit                json.RawMessage `json:"audit"`
		}{
			SessionID: params.SessionID, AuthenticationMethod: params.AuthenticationMethod,
			ProviderID: params.ProviderID, CommandID: params.CommandID,
			KeyDigest: fmt.Sprintf("%x", keyDigest), RequestDigest: fmt.Sprintf("%x", requestDigest),
			Key: params.Key, DisplayName: params.DisplayName, Description: params.Description,
			Configuration: documents.Configuration, Endpoints: documents.Endpoints, Audit: audit,
		})
		clear(audit)
		if err != nil {
			return nil, authentication.ErrInvalidInput
		}
		defer clear(request)
		resultDocument, err := queries.CreatePlatformLDAPAuthProvider(
			ctx,
			dbsql.CreatePlatformLDAPAuthProviderParams{Request: request},
		)
		if err != nil {
			return nil, err
		}
		var result struct {
			ProviderID uuid.UUID       `json:"providerId"`
			Version    int64           `json:"version"`
			Replayed   bool            `json:"replayed"`
			Document   json.RawMessage `json:"document"`
		}
		if err := json.Unmarshal(resultDocument, &result); err != nil {
			return nil, authentication.ErrUnavailable
		}
		return &platformIdentityProviderCreateRow{
			ProviderID: toDatabaseUUID(result.ProviderID), Version: result.Version,
			Replayed: result.Replayed, Document: append([]byte(nil), result.Document...),
		}, nil
	case platformidentityprovider.ProviderKindOIDC:
		row, err := queries.CreatePlatformOIDCAuthProvider(
			ctx,
			dbsql.CreatePlatformOIDCAuthProviderParams{
				SessionID:            toDatabaseUUID(params.SessionID),
				CommandID:            toDatabaseUUID(params.CommandID),
				ProviderID:           toDatabaseUUID(params.ProviderID),
				ProviderKey:          params.Key,
				DisplayName:          params.DisplayName,
				Description:          params.Description,
				Configuration:        documents.Configuration,
				TenantRedirectUri:    documents.TenantRedirectURI,
				KeyDigest:            keyDigest,
				RequestDigest:        requestDigest,
				AuditEventID:         toDatabaseUUID(auditID),
				RequestID:            event.requestID,
				CorrelationID:        event.correlationID,
				IpAddress:            params.Event.RemoteAddress,
				UserAgent:            params.Event.UserAgent,
				AuthenticationMethod: params.AuthenticationMethod,
				Reason:               params.Reason,
			},
		)
		if err != nil {
			return nil, err
		}
		return &platformIdentityProviderCreateRow{
			ProviderID: row.ProviderID,
			Version:    row.Version, Replayed: row.Replayed, Document: row.Document,
		}, nil
	case platformidentityprovider.ProviderKindSAML:
		row, err := queries.CreatePlatformSAMLAuthProvider(
			ctx,
			dbsql.CreatePlatformSAMLAuthProviderParams{
				SessionID:            toDatabaseUUID(params.SessionID),
				CommandID:            toDatabaseUUID(params.CommandID),
				ProviderID:           toDatabaseUUID(params.ProviderID),
				ProviderKey:          params.Key,
				DisplayName:          params.DisplayName,
				Description:          params.Description,
				Configuration:        documents.Configuration,
				KeyDigest:            keyDigest,
				RequestDigest:        requestDigest,
				AuditEventID:         toDatabaseUUID(auditID),
				RequestID:            event.requestID,
				CorrelationID:        event.correlationID,
				IpAddress:            params.Event.RemoteAddress,
				UserAgent:            params.Event.UserAgent,
				AuthenticationMethod: params.AuthenticationMethod,
				Reason:               params.Reason,
			},
		)
		if err != nil {
			return nil, err
		}
		return &platformIdentityProviderCreateRow{
			ProviderID: row.ProviderID,
			Version:    row.Version, Replayed: row.Replayed, Document: row.Document,
		}, nil
	default:
		return nil, authentication.ErrInvalidInput
	}
}

func (repository *PlatformIdentityProviderRepository) Update(
	ctx context.Context,
	params platformidentityprovider.UpdateParams,
) (platformidentityprovider.UpdateResult, error) {
	if !validPlatformIdentityProviderMutation(
		params.SessionParams, params.ProviderID, params.ExpectedVersion, params.Reason, params.Event,
	) || params.Key == "" || params.DisplayName == "" || params.ValidateResult == nil {
		return platformidentityprovider.UpdateResult{}, authentication.ErrInvalidInput
	}
	event, err := eventArguments(params.Event)
	if err != nil {
		return platformidentityprovider.UpdateResult{}, authentication.ErrInvalidInput
	}
	auditID, err := platformIdentityProviderAuditID(repository)
	if err != nil {
		return platformidentityprovider.UpdateResult{}, err
	}
	return withPlatformIdentityProviderTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityprovider.UpdateResult, error) {
			row, queryErr := queries.UpdatePlatformAuthProvider(ctx, dbsql.UpdatePlatformAuthProviderParams{
				SessionID:            toDatabaseUUID(params.SessionID),
				ProviderID:           toDatabaseUUID(params.ProviderID),
				ExpectedVersion:      params.ExpectedVersion,
				ProviderKey:          params.Key,
				DisplayName:          params.DisplayName,
				Description:          params.Description,
				AuditEventID:         toDatabaseUUID(auditID),
				RequestID:            event.requestID,
				CorrelationID:        event.correlationID,
				IpAddress:            params.Event.RemoteAddress,
				UserAgent:            params.Event.UserAgent,
				AuthenticationMethod: params.AuthenticationMethod,
				Reason:               params.Reason,
			})
			if queryErr != nil {
				return platformidentityprovider.UpdateResult{}, queryErr
			}
			provider, decodeErr := decodePlatformIdentityProvider(row.Document)
			if decodeErr != nil {
				return platformidentityprovider.UpdateResult{}, authentication.ErrUnavailable
			}
			result, restoreErr := platformidentityprovider.RestoreUpdateResult(
				platformidentityprovider.UpdateResultInput{
					ProviderID: params.ProviderID,
					Version:    row.Version,
					Provider:   provider,
				},
			)
			if restoreErr != nil {
				return platformidentityprovider.UpdateResult{}, authentication.ErrUnavailable
			}
			validated, validationErr := params.ValidateResult(result)
			if validationErr != nil {
				return platformidentityprovider.UpdateResult{}, authentication.ErrUnavailable
			}
			return validated, nil
		},
	)
}

func (repository *PlatformIdentityProviderRepository) Archive(
	ctx context.Context,
	params platformidentityprovider.ArchiveParams,
) (platformidentityprovider.MutationReceipt, error) {
	if !validPlatformIdentityProviderMutation(
		params.SessionParams, params.ProviderID, params.ExpectedVersion, params.Reason, params.Event,
	) {
		return platformidentityprovider.MutationReceipt{}, authentication.ErrInvalidInput
	}
	event, err := eventArguments(params.Event)
	if err != nil {
		return platformidentityprovider.MutationReceipt{}, authentication.ErrInvalidInput
	}
	auditID, err := platformIdentityProviderAuditID(repository)
	if err != nil {
		return platformidentityprovider.MutationReceipt{}, err
	}
	return withPlatformIdentityProviderTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityprovider.MutationReceipt, error) {
			version, queryErr := queries.ArchivePlatformAuthProvider(ctx, dbsql.ArchivePlatformAuthProviderParams{
				SessionID:            toDatabaseUUID(params.SessionID),
				ProviderID:           toDatabaseUUID(params.ProviderID),
				ExpectedVersion:      params.ExpectedVersion,
				AuditEventID:         toDatabaseUUID(auditID),
				RequestID:            event.requestID,
				CorrelationID:        event.correlationID,
				IpAddress:            params.Event.RemoteAddress,
				UserAgent:            params.Event.UserAgent,
				AuthenticationMethod: params.AuthenticationMethod,
				Reason:               params.Reason,
			})
			if queryErr != nil {
				return platformidentityprovider.MutationReceipt{}, queryErr
			}
			receipt, restoreErr := restorePlatformIdentityProviderMutationReceipt(params.ProviderID, version)
			if restoreErr != nil || receipt.Version() != params.ExpectedVersion+1 {
				return platformidentityprovider.MutationReceipt{}, authentication.ErrUnavailable
			}
			return receipt, nil
		},
	)
}

func (repository *PlatformIdentityProviderRepository) Activate(
	ctx context.Context,
	params platformidentityprovider.ActivationParams,
) (platformidentityprovider.UpdateResult, error) {
	if !validPlatformIdentityProviderMutation(
		params.SessionParams, params.ProviderID, params.ExpectedVersion, params.Reason, params.Event,
	) || (params.AccountMode != platformidentityprovider.AccountModeExistingIdentity &&
		params.AccountMode != platformidentityprovider.AccountModeCreate) || params.ValidateResult == nil {
		return platformidentityprovider.UpdateResult{}, authentication.ErrInvalidInput
	}
	event, err := eventArguments(params.Event)
	if err != nil {
		return platformidentityprovider.UpdateResult{}, authentication.ErrInvalidInput
	}
	auditID, err := platformIdentityProviderAuditID(repository)
	if err != nil {
		return platformidentityprovider.UpdateResult{}, err
	}
	return withPlatformIdentityProviderTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityprovider.UpdateResult, error) {
			row, queryErr := queries.ActivatePlatformAuthProviderTenantExecution(
				ctx,
				dbsql.ActivatePlatformAuthProviderTenantExecutionParams{
					SessionID:            toDatabaseUUID(params.SessionID),
					ProviderID:           toDatabaseUUID(params.ProviderID),
					ExpectedVersion:      params.ExpectedVersion,
					AccountMode:          string(params.AccountMode),
					AuditEventID:         toDatabaseUUID(auditID),
					RequestID:            event.requestID,
					CorrelationID:        event.correlationID,
					IpAddress:            params.Event.RemoteAddress,
					UserAgent:            params.Event.UserAgent,
					AuthenticationMethod: params.AuthenticationMethod,
					Reason:               params.Reason,
				},
			)
			if queryErr != nil {
				return platformidentityprovider.UpdateResult{}, queryErr
			}
			return restorePlatformIdentityProviderLifecycleResult(
				params.ProviderID, params.ExpectedVersion, params.ValidateResult,
				row.Version, row.Document,
			)
		},
	)
}

func (repository *PlatformIdentityProviderRepository) Deactivate(
	ctx context.Context,
	params platformidentityprovider.DeactivationParams,
) (platformidentityprovider.UpdateResult, error) {
	if !validPlatformIdentityProviderMutation(
		params.SessionParams, params.ProviderID, params.ExpectedVersion, params.Reason, params.Event,
	) || params.ValidateResult == nil {
		return platformidentityprovider.UpdateResult{}, authentication.ErrInvalidInput
	}
	event, err := eventArguments(params.Event)
	if err != nil {
		return platformidentityprovider.UpdateResult{}, authentication.ErrInvalidInput
	}
	auditID, err := platformIdentityProviderAuditID(repository)
	if err != nil {
		return platformidentityprovider.UpdateResult{}, err
	}
	return withPlatformIdentityProviderTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityprovider.UpdateResult, error) {
			row, queryErr := queries.DeactivatePlatformAuthProviderTenantExecution(
				ctx,
				dbsql.DeactivatePlatformAuthProviderTenantExecutionParams{
					SessionID:            toDatabaseUUID(params.SessionID),
					ProviderID:           toDatabaseUUID(params.ProviderID),
					ExpectedVersion:      params.ExpectedVersion,
					AuditEventID:         toDatabaseUUID(auditID),
					RequestID:            event.requestID,
					CorrelationID:        event.correlationID,
					IpAddress:            params.Event.RemoteAddress,
					UserAgent:            params.Event.UserAgent,
					AuthenticationMethod: params.AuthenticationMethod,
					Reason:               params.Reason,
				},
			)
			if queryErr != nil {
				return platformidentityprovider.UpdateResult{}, queryErr
			}
			return restorePlatformIdentityProviderLifecycleResult(
				params.ProviderID, params.ExpectedVersion, params.ValidateResult,
				row.Version, row.Document,
			)
		},
	)
}

func (repository *PlatformIdentityProviderRepository) ActivateDirectLogin(
	ctx context.Context,
	params platformidentityprovider.DirectLoginParams,
) (platformidentityprovider.UpdateResult, error) {
	if !validPlatformIdentityProviderMutation(
		params.SessionParams, params.ProviderID, params.ExpectedVersion, params.Reason, params.Event,
	) || params.ValidateResult == nil {
		return platformidentityprovider.UpdateResult{}, authentication.ErrInvalidInput
	}
	event, err := eventArguments(params.Event)
	if err != nil {
		return platformidentityprovider.UpdateResult{}, authentication.ErrInvalidInput
	}
	auditID, err := platformIdentityProviderAuditID(repository)
	if err != nil {
		return platformidentityprovider.UpdateResult{}, err
	}
	return withPlatformIdentityProviderTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityprovider.UpdateResult, error) {
			row, queryErr := queries.ActivatePlatformOIDCDirectLogin(
				ctx,
				dbsql.ActivatePlatformOIDCDirectLoginParams{
					SessionID:            toDatabaseUUID(params.SessionID),
					ProviderID:           toDatabaseUUID(params.ProviderID),
					ExpectedVersion:      params.ExpectedVersion,
					AuditEventID:         toDatabaseUUID(auditID),
					RequestID:            event.requestID,
					CorrelationID:        event.correlationID,
					IpAddress:            params.Event.RemoteAddress,
					UserAgent:            params.Event.UserAgent,
					AuthenticationMethod: params.AuthenticationMethod,
					Reason:               params.Reason,
				},
			)
			if queryErr != nil {
				return platformidentityprovider.UpdateResult{}, queryErr
			}
			return restorePlatformIdentityProviderLifecycleResult(
				params.ProviderID, params.ExpectedVersion, params.ValidateResult,
				row.Version, row.Document,
			)
		},
	)
}

func (repository *PlatformIdentityProviderRepository) DeactivateDirectLogin(
	ctx context.Context,
	params platformidentityprovider.DirectLoginParams,
) (platformidentityprovider.UpdateResult, error) {
	if !validPlatformIdentityProviderMutation(
		params.SessionParams, params.ProviderID, params.ExpectedVersion, params.Reason, params.Event,
	) || params.ValidateResult == nil {
		return platformidentityprovider.UpdateResult{}, authentication.ErrInvalidInput
	}
	event, err := eventArguments(params.Event)
	if err != nil {
		return platformidentityprovider.UpdateResult{}, authentication.ErrInvalidInput
	}
	auditID, err := platformIdentityProviderAuditID(repository)
	if err != nil {
		return platformidentityprovider.UpdateResult{}, err
	}
	return withPlatformIdentityProviderTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityprovider.UpdateResult, error) {
			row, queryErr := queries.DeactivatePlatformOIDCDirectLogin(
				ctx,
				dbsql.DeactivatePlatformOIDCDirectLoginParams{
					SessionID:            toDatabaseUUID(params.SessionID),
					ProviderID:           toDatabaseUUID(params.ProviderID),
					ExpectedVersion:      params.ExpectedVersion,
					AuditEventID:         toDatabaseUUID(auditID),
					RequestID:            event.requestID,
					CorrelationID:        event.correlationID,
					IpAddress:            params.Event.RemoteAddress,
					UserAgent:            params.Event.UserAgent,
					AuthenticationMethod: params.AuthenticationMethod,
					Reason:               params.Reason,
				},
			)
			if queryErr != nil {
				return platformidentityprovider.UpdateResult{}, queryErr
			}
			return restorePlatformIdentityProviderLifecycleResult(
				params.ProviderID, params.ExpectedVersion, params.ValidateResult,
				row.Version, row.Document,
			)
		},
	)
}

func restorePlatformIdentityProviderLifecycleResult(
	providerID uuid.UUID,
	expectedVersion int64,
	validate platformidentityprovider.UpdateResultValidator,
	version int64,
	document []byte,
) (platformidentityprovider.UpdateResult, error) {
	provider, err := decodePlatformIdentityProvider(document)
	if err != nil {
		return platformidentityprovider.UpdateResult{}, authentication.ErrUnavailable
	}
	result, err := platformidentityprovider.RestoreUpdateResult(
		platformidentityprovider.UpdateResultInput{
			ProviderID: providerID, Version: version, Provider: provider,
		},
	)
	if err != nil || result.Version() != expectedVersion+1 || validate == nil {
		return platformidentityprovider.UpdateResult{}, authentication.ErrUnavailable
	}
	validated, err := validate(result)
	if err != nil {
		return platformidentityprovider.UpdateResult{}, authentication.ErrUnavailable
	}
	return validated, nil
}

func (repository *PlatformIdentityProviderRepository) ReplaceOIDCClientSecret(
	ctx context.Context,
	params platformidentityprovider.ReplaceOIDCClientSecretParams,
) (platformidentityprovider.SecretMutationReceipt, error) {
	if !validPlatformIdentityProviderMutation(
		params.SessionParams, params.ProviderID, params.ExpectedVersion, params.Reason, params.Event,
	) || !platformIdentityProviderUUIDv7(params.Secret.SecretID) ||
		params.Secret.Envelope.KeyVersion < 1 || len(params.Secret.Envelope.Ciphertext) < 17 ||
		len(params.Secret.Envelope.Ciphertext) > 8208 {
		return platformidentityprovider.SecretMutationReceipt{}, authentication.ErrInvalidInput
	}
	event, err := eventArguments(params.Event)
	if err != nil {
		return platformidentityprovider.SecretMutationReceipt{}, authentication.ErrInvalidInput
	}
	auditID, err := platformIdentityProviderAuditID(repository)
	if err != nil {
		return platformidentityprovider.SecretMutationReceipt{}, err
	}
	nonce := append([]byte(nil), params.Secret.Envelope.Nonce[:]...)
	ciphertext := append([]byte(nil), params.Secret.Envelope.Ciphertext...)
	defer clear(nonce)
	defer clear(ciphertext)

	return withPlatformIdentityProviderTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityprovider.SecretMutationReceipt, error) {
			row, queryErr := queries.ReplacePlatformOIDCAuthProviderClientSecret(
				ctx,
				dbsql.ReplacePlatformOIDCAuthProviderClientSecretParams{
					SessionID:            toDatabaseUUID(params.SessionID),
					ProviderID:           toDatabaseUUID(params.ProviderID),
					SecretID:             toDatabaseUUID(params.Secret.SecretID),
					ExpectedVersion:      params.ExpectedVersion,
					KeyVersion:           int32(params.Secret.Envelope.KeyVersion),
					Nonce:                nonce,
					Ciphertext:           ciphertext,
					AuditEventID:         toDatabaseUUID(auditID),
					RequestID:            event.requestID,
					CorrelationID:        event.correlationID,
					IpAddress:            params.Event.RemoteAddress,
					UserAgent:            params.Event.UserAgent,
					AuthenticationMethod: params.AuthenticationMethod,
					Reason:               params.Reason,
				},
			)
			if queryErr != nil {
				return platformidentityprovider.SecretMutationReceipt{}, queryErr
			}
			receipt, restoreErr := platformidentityprovider.RestoreSecretMutationReceipt(
				platformidentityprovider.SecretMutationReceiptInput{
					ProviderID:     params.ProviderID,
					Version:        row.Version,
					SecretRevision: row.SecretRevision,
				},
			)
			if restoreErr != nil || receipt.Version() != params.ExpectedVersion+1 {
				return platformidentityprovider.SecretMutationReceipt{}, authentication.ErrUnavailable
			}
			return receipt, nil
		},
	)
}

func withPlatformIdentityProviderTransaction[T any](
	ctx context.Context,
	repository *PlatformIdentityProviderRepository,
	session platformidentityprovider.SessionParams,
	work func(*dbsql.Queries) (T, error),
) (T, error) {
	var zero T
	if ctx == nil || repository == nil || repository.begin == nil || work == nil {
		return zero, authentication.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if !validPlatformIdentityProviderSession(session) {
		return zero, authentication.ErrInvalidInput
	}
	result, err := withinTransaction(ctx, repository.begin, func(tx databaseTransaction) (T, error) {
		queries := dbsql.New(tx)
		if setErr := setUserContext(ctx, queries, session.ActorID); setErr != nil {
			return zero, setErr
		}
		return work(queries)
	})
	if err != nil {
		return zero, mapPlatformIdentityProviderDatabaseError(err)
	}
	return result, nil
}

func platformIdentityProviderAuditID(
	repository *PlatformIdentityProviderRepository,
) (uuid.UUID, error) {
	if repository == nil || repository.newID == nil {
		return uuid.Nil, authentication.ErrUnavailable
	}
	auditID, err := repository.newID()
	if err != nil || !platformIdentityProviderUUIDv7(auditID) {
		return uuid.Nil, authentication.ErrUnavailable
	}
	return auditID, nil
}

func validPlatformIdentityProviderSession(session platformidentityprovider.SessionParams) bool {
	return platformIdentityProviderUUIDv7(session.ActorID) &&
		platformIdentityProviderUUIDv7(session.SessionID) &&
		validPlatformIdentityProviderAuthenticationMethod(session.AuthenticationMethod)
}

func validPlatformIdentityProviderMutation(
	session platformidentityprovider.SessionParams,
	providerID uuid.UUID,
	expectedVersion int64,
	reason string,
	event authentication.EventContext,
) bool {
	return validPlatformIdentityProviderSession(session) &&
		platformIdentityProviderUUIDv7(providerID) && expectedVersion > 0 &&
		expectedVersion <= 2_147_483_646 &&
		reason != "" && event.RequestID != uuid.Nil && event.CorrelationID != uuid.Nil
}

func validPlatformIdentityProviderAuthenticationMethod(value string) bool {
	switch value {
	case "bootstrap_totp", "ldap", "oidc", "passkey", "recovery_code", "saml", "totp":
		return true
	default:
		return false
	}
}

func platformIdentityProviderUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

type platformIdentityProviderCreateDocuments struct {
	Configuration     []byte
	Endpoints         []byte
	TenantRedirectURI string
}

func buildPlatformIdentityProviderCreateDocuments(
	kind platformidentityprovider.ProviderKind,
	configuration platformidentityprovider.CreateConfiguration,
) (platformIdentityProviderCreateDocuments, error) {
	switch value := configuration.(type) {
	case platformidentityprovider.LDAPCreateConfiguration:
		if kind != platformidentityprovider.ProviderKindLDAP || value.ProviderKind() != kind {
			return platformIdentityProviderCreateDocuments{}, authentication.ErrInvalidInput
		}
		configurationDocument, err := json.Marshal(value.Configuration)
		if err != nil {
			return platformIdentityProviderCreateDocuments{}, authentication.ErrInvalidInput
		}
		endpointsDocument, err := json.Marshal(value.Endpoints)
		if err != nil {
			clear(configurationDocument)
			return platformIdentityProviderCreateDocuments{}, authentication.ErrInvalidInput
		}
		return platformIdentityProviderCreateDocuments{
			Configuration: configurationDocument, Endpoints: endpointsDocument,
		}, nil
	case platformidentityprovider.OIDCCreateConfiguration:
		if kind != platformidentityprovider.ProviderKindOIDC || value.ProviderKind() != kind {
			return platformIdentityProviderCreateDocuments{}, authentication.ErrInvalidInput
		}
		document, err := json.Marshal(struct {
			Issuer                string   `json:"issuer"`
			ClientID              string   `json:"clientId"`
			RedirectURI           string   `json:"redirectUri"`
			PostLogoutRedirectURI string   `json:"postLogoutRedirectUri"`
			ExtraScopes           []string `json:"extraScopes"`
			AllowRefreshToken     bool     `json:"allowRefreshToken"`
			UseUserInfo           bool     `json:"useUserInfo"`
		}{
			Issuer: value.Issuer, ClientID: value.ClientID, RedirectURI: value.RedirectURI,
			PostLogoutRedirectURI: value.PostLogoutRedirectURI,
			ExtraScopes:           value.ExtraScopes, AllowRefreshToken: value.AllowRefreshToken,
			UseUserInfo: value.UseUserInfo,
		})
		return platformIdentityProviderCreateDocuments{
			Configuration: document, TenantRedirectURI: value.TenantRedirectURI,
		}, err
	case platformidentityprovider.SAMLCreateConfiguration:
		if kind != platformidentityprovider.ProviderKindSAML || value.ProviderKind() != kind {
			return platformIdentityProviderCreateDocuments{}, authentication.ErrInvalidInput
		}
		document, err := json.Marshal(value)
		return platformIdentityProviderCreateDocuments{Configuration: document}, err
	default:
		return platformIdentityProviderCreateDocuments{}, authentication.ErrInvalidInput
	}
}

func platformLDAPAuditDocument(
	eventID uuid.UUID,
	session platformidentityprovider.SessionParams,
	event authentication.EventContext,
	reason string,
) []byte {
	document, _ := json.Marshal(struct {
		EventID              uuid.UUID `json:"eventId"`
		RequestID            uuid.UUID `json:"requestId"`
		CorrelationID        uuid.UUID `json:"correlationId"`
		IPAddress            string    `json:"ipAddress,omitempty"`
		UserAgent            string    `json:"userAgent,omitempty"`
		AuthenticationMethod string    `json:"authenticationMethod"`
		Reason               string    `json:"reason,omitempty"`
	}{
		EventID: eventID, RequestID: event.RequestID, CorrelationID: event.CorrelationID,
		IPAddress: event.RemoteAddress.String(), UserAgent: event.UserAgent,
		AuthenticationMethod: session.AuthenticationMethod, Reason: reason,
	})
	return document
}

func restorePlatformIdentityProviderMutationReceipt(
	providerID uuid.UUID,
	version int64,
) (platformidentityprovider.MutationReceipt, error) {
	receipt, err := platformidentityprovider.RestoreMutationReceipt(
		platformidentityprovider.MutationReceiptInput{ProviderID: providerID, Version: version},
	)
	if err != nil {
		return platformidentityprovider.MutationReceipt{}, authentication.ErrUnavailable
	}
	return receipt, nil
}

func mapPlatformIdentityProviderDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, authentication.ErrForbidden) || errors.Is(err, authentication.ErrNotFound) ||
		errors.Is(err, authentication.ErrConflict) || errors.Is(err, authentication.ErrInvalidInput) ||
		errors.Is(err, authentication.ErrUnavailable) ||
		errors.Is(err, platformidentityprovider.ErrPreconditionFailed) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return authentication.ErrNotFound
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) && databaseError.Code == "40001" &&
		databaseError.Message == platformIdentityProviderRevisionConflictMessage {
		return platformidentityprovider.ErrPreconditionFailed
	}
	switch postgresCode(err) {
	case "42501":
		return authentication.ErrForbidden
	case "P0002":
		return authentication.ErrNotFound
	case "55000", "23505":
		return authentication.ErrConflict
	case "22023", "23514":
		return authentication.ErrInvalidInput
	default:
		return authentication.ErrUnavailable
	}
}

type platformIdentityProviderSummaryWire struct {
	ID                               uuid.UUID                             `json:"id"`
	Key                              string                                `json:"key"`
	DisplayName                      string                                `json:"displayName"`
	Description                      string                                `json:"description"`
	Kind                             platformidentityprovider.ProviderKind `json:"kind"`
	Enabled                          bool                                  `json:"enabled"`
	PlatformLoginEnabled             bool                                  `json:"platformLoginEnabled"`
	PlatformLoginActivationAvailable bool                                  `json:"platformLoginActivationAvailable"`
	ActivationAvailable              bool                                  `json:"activationAvailable"`
	Configured                       bool                                  `json:"configured"`
	SecretPresent                    bool                                  `json:"secretPresent"`
	ArchivedAt                       *time.Time                            `json:"archivedAt"`
	Version                          int64                                 `json:"version"`
	CreatedAt                        time.Time                             `json:"createdAt"`
	UpdatedAt                        time.Time                             `json:"updatedAt"`
}

type platformIdentityProviderWire struct {
	ID                               uuid.UUID                             `json:"id"`
	Key                              string                                `json:"key"`
	DisplayName                      string                                `json:"displayName"`
	Description                      string                                `json:"description"`
	Kind                             platformidentityprovider.ProviderKind `json:"kind"`
	Enabled                          bool                                  `json:"enabled"`
	PlatformLoginEnabled             bool                                  `json:"platformLoginEnabled"`
	PlatformLoginActivationAvailable bool                                  `json:"platformLoginActivationAvailable"`
	ActivationAvailable              bool                                  `json:"activationAvailable"`
	Configured                       bool                                  `json:"configured"`
	SecretPresent                    bool                                  `json:"secretPresent"`
	ConfigurationRevision            int64                                 `json:"configurationRevision"`
	SecurityRevision                 int64                                 `json:"securityRevision"`
	PlanRevision                     int64                                 `json:"planRevision"`
	AssurancePolicyRevision          int64                                 `json:"assurancePolicyRevision"`
	AccountMode                      platformidentityprovider.AccountMode  `json:"accountMode"`
	Configuration                    json.RawMessage                       `json:"configuration"`
	Endpoints                        json.RawMessage                       `json:"endpoints"`
	Mappings                         json.RawMessage                       `json:"mappings"`
	ArchivedAt                       *time.Time                            `json:"archivedAt"`
	Version                          int64                                 `json:"version"`
	CreatedAt                        time.Time                             `json:"createdAt"`
	UpdatedAt                        time.Time                             `json:"updatedAt"`
}

type platformLDAPEndpointWire struct {
	ID              uuid.UUID `json:"id"`
	Priority        int       `json:"priority"`
	Host            string    `json:"host"`
	Port            uint16    `json:"port"`
	Transport       string    `json:"transport"`
	TLSServerName   string    `json:"tlsServerName"`
	ReferralAllowed bool      `json:"referralAllowed"`
	Enabled         bool      `json:"enabled"`
}

type platformLDAPMappingWire struct {
	ID                 uuid.UUID                           `json:"id"`
	MatcherType        identityprovider.MappingMatcherType `json:"matcherType"`
	MatcherValue       string                              `json:"matcherValue"`
	CaseSensitive      bool                                `json:"caseSensitive"`
	Priority           int                                 `json:"priority"`
	PlatformRoleID     uuid.UUID                           `json:"platformRoleId"`
	ReconciliationMode identityprovider.ReconciliationMode `json:"reconciliationMode"`
	Enabled            bool                                `json:"enabled"`
	Notes              string                              `json:"notes"`
	LastMatchedAt      *time.Time                          `json:"lastMatchedAt"`
	Version            int64                               `json:"version"`
	ArchivedAt         *time.Time                          `json:"archivedAt"`
}

type platformOIDCConfigurationWire struct {
	Issuer                string   `json:"issuer"`
	ClientID              string   `json:"clientId"`
	RedirectURI           string   `json:"redirectUri"`
	TenantRedirectURI     string   `json:"tenantRedirectUri"`
	PostLogoutRedirectURI string   `json:"postLogoutRedirectUri"`
	ExtraScopes           []string `json:"extraScopes"`
	AllowRefreshToken     bool     `json:"allowRefreshToken"`
	UseUserInfo           bool     `json:"useUserInfo"`
	ClientSecretRevision  int64    `json:"clientSecretRevision"`
	ClientSecretPresent   bool     `json:"clientSecretPresent"`
	DiscoveryRevision     int64    `json:"discoveryRevision"`
	JWKSRevision          int64    `json:"jwksRevision"`
}

type platformSAMLConfigurationWire struct {
	ExpectedEntityID           string                                   `json:"expectedEntityId"`
	SPEntityID                 string                                   `json:"spEntityId"`
	ACSURL                     string                                   `json:"acsUrl"`
	SPKeyRevision              int64                                    `json:"spKeyRevision"`
	SPKeyPresent               bool                                     `json:"spKeyPresent"`
	MetadataRevision           int64                                    `json:"metadataRevision"`
	RedirectSignatureAlgorithm federatedsaml.RedirectSignatureAlgorithm `json:"redirectSignatureAlgorithm"`
	SignaturePolicy            federatedsaml.SignaturePolicy            `json:"signaturePolicy"`
	EncryptionPolicy           federatedsaml.EncryptionPolicy           `json:"encryptionPolicy"`
	RequestedAuthnContexts     []string                                 `json:"requestedAuthnContexts"`
	SubjectSource              federatedsaml.SubjectSource              `json:"subjectSource"`
	SubjectAttributeName       *string                                  `json:"subjectAttributeName"`
	SubjectAttributeNameFormat *string                                  `json:"subjectAttributeNameFormat"`
	ClockSkew                  time.Duration                            `json:"clockSkewNanoseconds"`
	MaximumAuthenticationAge   time.Duration                            `json:"maxAuthenticationAgeNanoseconds"`
}

type platformIdentityProviderJSONKind uint8

const (
	platformIdentityProviderJSONString platformIdentityProviderJSONKind = iota
	platformIdentityProviderJSONBoolean
	platformIdentityProviderJSONInteger
	platformIdentityProviderJSONStringArray
	platformIdentityProviderJSONObject
)

type platformIdentityProviderJSONField struct {
	kind     platformIdentityProviderJSONKind
	nullable bool
}

func decodePlatformIdentityProviderSummary(
	document []byte,
) (platformidentityprovider.ProviderSummary, error) {
	if err := validatePlatformIdentityProviderDocumentShape(document, map[string]platformIdentityProviderJSONField{
		"id":                               {kind: platformIdentityProviderJSONString},
		"key":                              {kind: platformIdentityProviderJSONString},
		"displayName":                      {kind: platformIdentityProviderJSONString},
		"description":                      {kind: platformIdentityProviderJSONString},
		"kind":                             {kind: platformIdentityProviderJSONString},
		"enabled":                          {kind: platformIdentityProviderJSONBoolean},
		"platformLoginEnabled":             {kind: platformIdentityProviderJSONBoolean},
		"platformLoginActivationAvailable": {kind: platformIdentityProviderJSONBoolean},
		"activationAvailable":              {kind: platformIdentityProviderJSONBoolean},
		"configured":                       {kind: platformIdentityProviderJSONBoolean},
		"secretPresent":                    {kind: platformIdentityProviderJSONBoolean},
		"archivedAt":                       {kind: platformIdentityProviderJSONString, nullable: true},
		"version":                          {kind: platformIdentityProviderJSONInteger},
		"createdAt":                        {kind: platformIdentityProviderJSONString},
		"updatedAt":                        {kind: platformIdentityProviderJSONString},
	}, nil); err != nil {
		return platformidentityprovider.ProviderSummary{}, err
	}
	wire, err := decodePlatformIdentityProviderDocument[platformIdentityProviderSummaryWire](document)
	if err != nil {
		return platformidentityprovider.ProviderSummary{}, err
	}
	return platformidentityprovider.ProviderSummary{
		ID:                               wire.ID,
		Key:                              wire.Key,
		DisplayName:                      wire.DisplayName,
		Description:                      wire.Description,
		Kind:                             wire.Kind,
		Enabled:                          wire.Enabled,
		PlatformLoginEnabled:             wire.PlatformLoginEnabled,
		PlatformLoginActivationAvailable: wire.PlatformLoginActivationAvailable,
		ActivationAvailable:              wire.ActivationAvailable,
		Configured:                       wire.Configured,
		SecretPresent:                    wire.SecretPresent,
		ArchivedAt:                       platformIdentityProviderOptionalUTC(wire.ArchivedAt),
		Version:                          wire.Version,
		CreatedAt:                        wire.CreatedAt.UTC(),
		UpdatedAt:                        wire.UpdatedAt.UTC(),
	}, nil
}

func decodePlatformIdentityProvider(
	document []byte,
) (platformidentityprovider.Provider, error) {
	if err := validatePlatformIdentityProviderDocumentShape(document, map[string]platformIdentityProviderJSONField{
		"id":                               {kind: platformIdentityProviderJSONString},
		"key":                              {kind: platformIdentityProviderJSONString},
		"displayName":                      {kind: platformIdentityProviderJSONString},
		"description":                      {kind: platformIdentityProviderJSONString},
		"kind":                             {kind: platformIdentityProviderJSONString},
		"enabled":                          {kind: platformIdentityProviderJSONBoolean},
		"platformLoginEnabled":             {kind: platformIdentityProviderJSONBoolean},
		"platformLoginActivationAvailable": {kind: platformIdentityProviderJSONBoolean},
		"activationAvailable":              {kind: platformIdentityProviderJSONBoolean},
		"configurationRevision":            {kind: platformIdentityProviderJSONInteger},
		"securityRevision":                 {kind: platformIdentityProviderJSONInteger},
		"planRevision":                     {kind: platformIdentityProviderJSONInteger},
		"assurancePolicyRevision":          {kind: platformIdentityProviderJSONInteger},
		"accountMode":                      {kind: platformIdentityProviderJSONString},
		"configuration":                    {kind: platformIdentityProviderJSONObject},
		"archivedAt":                       {kind: platformIdentityProviderJSONString, nullable: true},
		"version":                          {kind: platformIdentityProviderJSONInteger},
		"createdAt":                        {kind: platformIdentityProviderJSONString},
		"updatedAt":                        {kind: platformIdentityProviderJSONString},
	}, nil); err != nil {
		return platformidentityprovider.Provider{}, err
	}
	wire, err := decodePlatformIdentityProviderDocument[platformIdentityProviderWire](document)
	if err != nil {
		return platformidentityprovider.Provider{}, err
	}
	provider := platformidentityprovider.Provider{
		ProviderSummary: platformidentityprovider.ProviderSummary{
			ID:                               wire.ID,
			Key:                              wire.Key,
			DisplayName:                      wire.DisplayName,
			Description:                      wire.Description,
			Kind:                             wire.Kind,
			Enabled:                          wire.Enabled,
			PlatformLoginEnabled:             wire.PlatformLoginEnabled,
			PlatformLoginActivationAvailable: wire.PlatformLoginActivationAvailable,
			ActivationAvailable:              wire.ActivationAvailable,
			Configured:                       wire.Configured || wire.Kind != platformidentityprovider.ProviderKindLDAP,
			ArchivedAt:                       platformIdentityProviderOptionalUTC(wire.ArchivedAt),
			Version:                          wire.Version,
			CreatedAt:                        wire.CreatedAt.UTC(),
			UpdatedAt:                        wire.UpdatedAt.UTC(),
		},
		ConfigurationRevision:   wire.ConfigurationRevision,
		SecurityRevision:        wire.SecurityRevision,
		PlanRevision:            wire.PlanRevision,
		AssurancePolicyRevision: wire.AssurancePolicyRevision,
		AccountMode:             wire.AccountMode,
	}
	switch wire.Kind {
	case platformidentityprovider.ProviderKindLDAP:
		configuration, decodeErr := decodePlatformIdentityProviderDocument[identityprovider.Configuration](
			wire.Configuration,
		)
		if decodeErr != nil {
			return platformidentityprovider.Provider{}, decodeErr
		}
		endpoints, decodeErr := decodePlatformIdentityProviderArray[platformLDAPEndpointWire](wire.Endpoints)
		if decodeErr != nil {
			return platformidentityprovider.Provider{}, decodeErr
		}
		mappings, decodeErr := decodePlatformIdentityProviderArray[platformLDAPMappingWire](wire.Mappings)
		if decodeErr != nil {
			return platformidentityprovider.Provider{}, decodeErr
		}
		provider.LDAP = &platformidentityprovider.LDAPConfiguration{
			Configuration: configuration,
			Endpoints:     make([]platformidentityprovider.LDAPEndpoint, len(endpoints)),
			Mappings:      make([]platformidentityprovider.LDAPMapping, len(mappings)),
		}
		for index, endpoint := range endpoints {
			provider.LDAP.Endpoints[index] = platformidentityprovider.LDAPEndpoint{
				ID: endpoint.ID, Priority: endpoint.Priority, Host: endpoint.Host, Port: endpoint.Port,
				Transport: endpoint.Transport, TLSServerName: endpoint.TLSServerName,
				ReferralAllowed: endpoint.ReferralAllowed, Enabled: endpoint.Enabled,
			}
		}
		for index, mapping := range mappings {
			provider.LDAP.Mappings[index] = platformidentityprovider.LDAPMapping{
				ID: mapping.ID, MatcherType: mapping.MatcherType, MatcherValue: mapping.MatcherValue,
				CaseSensitive: mapping.CaseSensitive, Priority: mapping.Priority,
				PlatformRoleID:     mapping.PlatformRoleID,
				ReconciliationMode: mapping.ReconciliationMode, Enabled: mapping.Enabled,
				Notes: mapping.Notes, LastMatchedAt: platformIdentityProviderOptionalUTC(mapping.LastMatchedAt),
				Version: mapping.Version, ArchivedAt: platformIdentityProviderOptionalUTC(mapping.ArchivedAt),
			}
		}
		provider.SecretPresent = wire.SecretPresent
	case platformidentityprovider.ProviderKindOIDC:
		if shapeErr := validatePlatformIdentityProviderDocumentShape(
			wire.Configuration,
			map[string]platformIdentityProviderJSONField{
				"issuer":                {kind: platformIdentityProviderJSONString},
				"clientId":              {kind: platformIdentityProviderJSONString},
				"redirectUri":           {kind: platformIdentityProviderJSONString},
				"tenantRedirectUri":     {kind: platformIdentityProviderJSONString},
				"postLogoutRedirectUri": {kind: platformIdentityProviderJSONString},
				"extraScopes":           {kind: platformIdentityProviderJSONStringArray},
				"allowRefreshToken":     {kind: platformIdentityProviderJSONBoolean},
				"useUserInfo":           {kind: platformIdentityProviderJSONBoolean},
				"clientSecretRevision":  {kind: platformIdentityProviderJSONInteger},
				"clientSecretPresent":   {kind: platformIdentityProviderJSONBoolean},
				"discoveryRevision":     {kind: platformIdentityProviderJSONInteger},
				"jwksRevision":          {kind: platformIdentityProviderJSONInteger},
			},
			nil,
		); shapeErr != nil {
			return platformidentityprovider.Provider{}, shapeErr
		}
		configuration, decodeErr := decodePlatformIdentityProviderDocument[platformOIDCConfigurationWire](
			wire.Configuration,
		)
		if decodeErr != nil {
			return platformidentityprovider.Provider{}, decodeErr
		}
		provider.OIDC = &platformidentityprovider.OIDCConfiguration{
			Issuer:                configuration.Issuer,
			ClientID:              configuration.ClientID,
			RedirectURI:           configuration.RedirectURI,
			TenantRedirectURI:     configuration.TenantRedirectURI,
			PostLogoutRedirectURI: configuration.PostLogoutRedirectURI,
			ExtraScopes:           clonePlatformIdentityProviderSlice(configuration.ExtraScopes),
			AllowRefreshToken:     configuration.AllowRefreshToken,
			UseUserInfo:           configuration.UseUserInfo,
			ClientSecretRevision:  configuration.ClientSecretRevision,
			ClientSecretPresent:   configuration.ClientSecretPresent,
			DiscoveryRevision:     configuration.DiscoveryRevision,
			JWKSRevision:          configuration.JWKSRevision,
		}
		provider.SecretPresent = configuration.ClientSecretPresent
	case platformidentityprovider.ProviderKindSAML:
		if shapeErr := validatePlatformIdentityProviderDocumentShape(
			wire.Configuration,
			map[string]platformIdentityProviderJSONField{
				"expectedEntityId":                {kind: platformIdentityProviderJSONString},
				"spEntityId":                      {kind: platformIdentityProviderJSONString},
				"acsUrl":                          {kind: platformIdentityProviderJSONString},
				"spKeyRevision":                   {kind: platformIdentityProviderJSONInteger},
				"spKeyPresent":                    {kind: platformIdentityProviderJSONBoolean},
				"metadataRevision":                {kind: platformIdentityProviderJSONInteger},
				"redirectSignatureAlgorithm":      {kind: platformIdentityProviderJSONString},
				"signaturePolicy":                 {kind: platformIdentityProviderJSONString},
				"encryptionPolicy":                {kind: platformIdentityProviderJSONString},
				"requestedAuthnContexts":          {kind: platformIdentityProviderJSONStringArray},
				"subjectSource":                   {kind: platformIdentityProviderJSONString},
				"clockSkewNanoseconds":            {kind: platformIdentityProviderJSONInteger},
				"maxAuthenticationAgeNanoseconds": {kind: platformIdentityProviderJSONInteger},
			},
			map[string]platformIdentityProviderJSONField{
				"subjectAttributeName":       {kind: platformIdentityProviderJSONString},
				"subjectAttributeNameFormat": {kind: platformIdentityProviderJSONString},
			},
		); shapeErr != nil {
			return platformidentityprovider.Provider{}, shapeErr
		}
		configuration, decodeErr := decodePlatformIdentityProviderDocument[platformSAMLConfigurationWire](
			wire.Configuration,
		)
		if decodeErr != nil {
			return platformidentityprovider.Provider{}, decodeErr
		}
		provider.SAML = &platformidentityprovider.SAMLConfiguration{
			ExpectedEntityID:           configuration.ExpectedEntityID,
			SPEntityID:                 configuration.SPEntityID,
			ACSURL:                     configuration.ACSURL,
			SPKeyRevision:              configuration.SPKeyRevision,
			SPKeyPresent:               configuration.SPKeyPresent,
			MetadataRevision:           configuration.MetadataRevision,
			RedirectSignatureAlgorithm: configuration.RedirectSignatureAlgorithm,
			SignaturePolicy:            configuration.SignaturePolicy,
			EncryptionPolicy:           configuration.EncryptionPolicy,
			RequestedAuthnContexts:     clonePlatformIdentityProviderSlice(configuration.RequestedAuthnContexts),
			SubjectSource:              configuration.SubjectSource,
			SubjectAttributeName:       clonePlatformIdentityProviderString(configuration.SubjectAttributeName),
			SubjectAttributeNameFormat: clonePlatformIdentityProviderString(configuration.SubjectAttributeNameFormat),
			ClockSkew:                  configuration.ClockSkew,
			MaximumAuthenticationAge:   configuration.MaximumAuthenticationAge,
		}
		provider.SecretPresent = configuration.SPKeyPresent
	default:
		return platformidentityprovider.Provider{}, authentication.ErrUnavailable
	}
	return provider, nil
}

func decodePlatformIdentityProviderArray[T any](document []byte) ([]T, error) {
	trimmed := bytes.TrimSpace(document)
	if len(trimmed) < 2 || len(trimmed) > maximumPlatformIdentityProviderProjectionBytes || trimmed[0] != '[' {
		return nil, authentication.ErrUnavailable
	}
	var values []T
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&values); err != nil || values == nil {
		return nil, authentication.ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, authentication.ErrUnavailable
	}
	return values, nil
}

func decodePlatformIdentityProviderDocument[T any](document []byte) (T, error) {
	var value T
	trimmed := bytes.TrimSpace(document)
	if len(trimmed) < 2 || len(trimmed) > maximumPlatformIdentityProviderProjectionBytes || trimmed[0] != '{' {
		return value, authentication.ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, authentication.ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return value, authentication.ErrUnavailable
	}
	return value, nil
}

func validatePlatformIdentityProviderDocumentShape(
	document []byte,
	required map[string]platformIdentityProviderJSONField,
	optional map[string]platformIdentityProviderJSONField,
) error {
	trimmed := bytes.TrimSpace(document)
	if len(trimmed) < 2 || len(trimmed) > maximumPlatformIdentityProviderProjectionBytes || trimmed[0] != '{' {
		return authentication.ErrUnavailable
	}
	var object map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	if err := decoder.Decode(&object); err != nil || object == nil {
		return authentication.ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return authentication.ErrUnavailable
	}
	for name, field := range required {
		raw, present := object[name]
		if !present || !validPlatformIdentityProviderJSONField(raw, field) {
			return authentication.ErrUnavailable
		}
	}
	for name, field := range optional {
		if raw, present := object[name]; present && !validPlatformIdentityProviderJSONField(raw, field) {
			return authentication.ErrUnavailable
		}
	}
	return nil
}

func validPlatformIdentityProviderJSONField(
	raw json.RawMessage,
	field platformIdentityProviderJSONField,
) bool {
	trimmed := bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("null")) {
		return field.nullable
	}
	switch field.kind {
	case platformIdentityProviderJSONString:
		var value string
		return json.Unmarshal(trimmed, &value) == nil
	case platformIdentityProviderJSONBoolean:
		return bytes.Equal(trimmed, []byte("true")) || bytes.Equal(trimmed, []byte("false"))
	case platformIdentityProviderJSONInteger:
		var value json.Number
		if json.Unmarshal(trimmed, &value) != nil {
			return false
		}
		_, err := strconv.ParseInt(value.String(), 10, 64)
		return err == nil
	case platformIdentityProviderJSONStringArray:
		var values []json.RawMessage
		if json.Unmarshal(trimmed, &values) != nil || values == nil {
			return false
		}
		for _, value := range values {
			if !validPlatformIdentityProviderJSONField(value, platformIdentityProviderJSONField{
				kind: platformIdentityProviderJSONString,
			}) {
				return false
			}
		}
		return true
	case platformIdentityProviderJSONObject:
		var value map[string]json.RawMessage
		return len(trimmed) >= 2 && trimmed[0] == '{' && json.Unmarshal(trimmed, &value) == nil && value != nil
	default:
		return false
	}
}

func platformIdentityProviderOptionalUTC(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	normalized := value.UTC()
	return &normalized
}

func clonePlatformIdentityProviderString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func clonePlatformIdentityProviderSlice[T any](value []T) []T {
	if value == nil {
		return nil
	}
	cloned := make([]T, len(value))
	copy(cloned, value)
	return cloned
}
