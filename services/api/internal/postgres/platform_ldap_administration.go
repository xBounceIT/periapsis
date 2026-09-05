package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

var _ platformidentityprovider.LDAPAdministrationRepository = (*PlatformIdentityProviderRepository)(nil)

func (repository *PlatformIdentityProviderRepository) UpdateLDAP(
	ctx context.Context,
	params platformidentityprovider.UpdateLDAPParams,
) (platformidentityprovider.UpdateResult, error) {
	if !validPlatformIdentityProviderMutation(
		params.SessionParams, params.ProviderID, params.ExpectedVersion, params.Reason, params.Event,
	) || params.ValidateResult == nil {
		return platformidentityprovider.UpdateResult{}, authentication.ErrInvalidInput
	}
	auditID, err := platformIdentityProviderAuditID(repository)
	if err != nil {
		return platformidentityprovider.UpdateResult{}, err
	}
	audit := platformLDAPAuditDocument(auditID, params.SessionParams, params.Event, params.Reason)
	request, err := json.Marshal(struct {
		SessionID            uuid.UUID                               `json:"sessionId"`
		AuthenticationMethod string                                  `json:"authenticationMethod"`
		ProviderID           uuid.UUID                               `json:"providerId"`
		ExpectedVersion      int64                                   `json:"expectedVersion"`
		Key                  string                                  `json:"key"`
		DisplayName          string                                  `json:"displayName"`
		Description          string                                  `json:"description"`
		Configuration        any                                     `json:"configuration"`
		Endpoints            []platformidentityprovider.LDAPEndpoint `json:"endpoints"`
		Audit                json.RawMessage                         `json:"audit"`
	}{
		SessionID: params.SessionID, AuthenticationMethod: params.AuthenticationMethod,
		ProviderID: params.ProviderID, ExpectedVersion: params.ExpectedVersion,
		Key: params.Key, DisplayName: params.DisplayName, Description: params.Description,
		Configuration: params.Configuration, Endpoints: params.Endpoints, Audit: audit,
	})
	clear(audit)
	if err != nil {
		return platformidentityprovider.UpdateResult{}, authentication.ErrInvalidInput
	}
	defer clear(request)
	return withPlatformIdentityProviderTransaction(ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityprovider.UpdateResult, error) {
			document, queryErr := queries.UpdatePlatformLDAPAuthProvider(
				ctx, dbsql.UpdatePlatformLDAPAuthProviderParams{Request: request},
			)
			if queryErr != nil {
				return platformidentityprovider.UpdateResult{}, queryErr
			}
			return restorePlatformLDAPUpdateResult(params.ProviderID, document, params.ValidateResult)
		},
	)
}

func (repository *PlatformIdentityProviderRepository) ReplaceLDAPBindSecret(
	ctx context.Context,
	params platformidentityprovider.ReplaceLDAPBindSecretParams,
) (platformidentityprovider.SecretMutationReceipt, error) {
	if !validPlatformIdentityProviderMutation(
		params.SessionParams, params.ProviderID, params.ExpectedVersion, params.Reason, params.Event,
	) || !platformIdentityProviderUUIDv7(params.Secret.SecretID) ||
		params.Secret.Envelope.KeyVersion < 1 || len(params.Secret.Envelope.Ciphertext) < 17 ||
		len(params.Secret.Envelope.Ciphertext) > 8192 {
		return platformidentityprovider.SecretMutationReceipt{}, authentication.ErrInvalidInput
	}
	auditID, err := platformIdentityProviderAuditID(repository)
	if err != nil {
		return platformidentityprovider.SecretMutationReceipt{}, err
	}
	audit := platformLDAPAuditDocument(auditID, params.SessionParams, params.Event, params.Reason)
	request, err := json.Marshal(struct {
		SessionID            uuid.UUID       `json:"sessionId"`
		AuthenticationMethod string          `json:"authenticationMethod"`
		ProviderID           uuid.UUID       `json:"providerId"`
		ExpectedVersion      int64           `json:"expectedVersion"`
		SecretID             uuid.UUID       `json:"secretId"`
		KeyVersion           int16           `json:"keyVersion"`
		Nonce                string          `json:"nonce"`
		Ciphertext           string          `json:"ciphertext"`
		Audit                json.RawMessage `json:"audit"`
	}{
		SessionID: params.SessionID, AuthenticationMethod: params.AuthenticationMethod,
		ProviderID: params.ProviderID, ExpectedVersion: params.ExpectedVersion,
		SecretID: params.Secret.SecretID, KeyVersion: params.Secret.Envelope.KeyVersion,
		Nonce:      fmt.Sprintf("%x", params.Secret.Envelope.Nonce[:]),
		Ciphertext: fmt.Sprintf("%x", params.Secret.Envelope.Ciphertext), Audit: audit,
	})
	clear(audit)
	if err != nil {
		return platformidentityprovider.SecretMutationReceipt{}, authentication.ErrInvalidInput
	}
	defer clear(request)
	return withPlatformIdentityProviderTransaction(ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityprovider.SecretMutationReceipt, error) {
			document, queryErr := queries.ReplacePlatformLDAPBindSecret(
				ctx, dbsql.ReplacePlatformLDAPBindSecretParams{Request: request},
			)
			if queryErr != nil {
				return platformidentityprovider.SecretMutationReceipt{}, queryErr
			}
			var result struct {
				ProviderID     uuid.UUID `json:"providerId"`
				Version        int64     `json:"version"`
				SecretRevision int64     `json:"secretRevision"`
			}
			if err := json.Unmarshal(document, &result); err != nil {
				return platformidentityprovider.SecretMutationReceipt{}, authentication.ErrUnavailable
			}
			return platformidentityprovider.RestoreSecretMutationReceipt(
				platformidentityprovider.SecretMutationReceiptInput{
					ProviderID: result.ProviderID, Version: result.Version,
					SecretRevision: result.SecretRevision,
				},
			)
		},
	)
}

func (repository *PlatformIdentityProviderRepository) PutLDAPMapping(
	ctx context.Context,
	params platformidentityprovider.PutLDAPMappingParams,
) (platformidentityprovider.UpdateResult, error) {
	if !validPlatformIdentityProviderSession(params.SessionParams) ||
		!platformIdentityProviderUUIDv7(params.ProviderID) || !platformIdentityProviderUUIDv7(params.MappingID) ||
		!platformIdentityProviderUUIDv7(params.PlatformRoleID) || params.ValidateResult == nil {
		return platformidentityprovider.UpdateResult{}, authentication.ErrInvalidInput
	}
	auditID, err := platformIdentityProviderAuditID(repository)
	if err != nil {
		return platformidentityprovider.UpdateResult{}, err
	}
	audit := platformLDAPAuditDocument(auditID, params.SessionParams, params.Event, params.Reason)
	request, err := json.Marshal(struct {
		SessionID            uuid.UUID       `json:"sessionId"`
		AuthenticationMethod string          `json:"authenticationMethod"`
		ProviderID           uuid.UUID       `json:"providerId"`
		MappingID            uuid.UUID       `json:"mappingId"`
		ExpectedVersion      *int64          `json:"expectedVersion,omitempty"`
		MatcherType          string          `json:"matcherType"`
		MatcherValue         string          `json:"matcherValue"`
		CaseSensitive        bool            `json:"caseSensitive"`
		Priority             int             `json:"priority"`
		PlatformRoleID       uuid.UUID       `json:"platformRoleId"`
		ReconciliationMode   string          `json:"reconciliationMode"`
		Enabled              bool            `json:"enabled"`
		Notes                string          `json:"notes"`
		Audit                json.RawMessage `json:"audit"`
	}{
		SessionID: params.SessionID, AuthenticationMethod: params.AuthenticationMethod,
		ProviderID: params.ProviderID, MappingID: params.MappingID,
		ExpectedVersion: params.ExpectedVersion, MatcherType: string(params.MatcherType),
		MatcherValue: params.MatcherValue, CaseSensitive: params.CaseSensitive, Priority: params.Priority,
		PlatformRoleID: params.PlatformRoleID, ReconciliationMode: string(params.ReconciliationMode),
		Enabled: params.Enabled, Notes: params.Notes, Audit: audit,
	})
	clear(audit)
	if err != nil {
		return platformidentityprovider.UpdateResult{}, authentication.ErrInvalidInput
	}
	defer clear(request)
	return withPlatformIdentityProviderTransaction(ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityprovider.UpdateResult, error) {
			document, queryErr := queries.PutPlatformLDAPMapping(
				ctx, dbsql.PutPlatformLDAPMappingParams{Request: request},
			)
			if queryErr != nil {
				return platformidentityprovider.UpdateResult{}, queryErr
			}
			return restorePlatformLDAPUpdateResult(params.ProviderID, document, params.ValidateResult)
		},
	)
}

func (repository *PlatformIdentityProviderRepository) SetLDAPLoginState(
	ctx context.Context,
	params platformidentityprovider.SetLDAPLoginStateParams,
) (platformidentityprovider.UpdateResult, error) {
	if !validPlatformIdentityProviderMutation(
		params.SessionParams, params.ProviderID, params.ExpectedVersion, params.Reason, params.Event,
	) || params.ValidateResult == nil {
		return platformidentityprovider.UpdateResult{}, authentication.ErrInvalidInput
	}
	auditID, err := platformIdentityProviderAuditID(repository)
	if err != nil {
		return platformidentityprovider.UpdateResult{}, err
	}
	audit := platformLDAPAuditDocument(auditID, params.SessionParams, params.Event, params.Reason)
	request, err := json.Marshal(struct {
		SessionID            uuid.UUID       `json:"sessionId"`
		AuthenticationMethod string          `json:"authenticationMethod"`
		ProviderID           uuid.UUID       `json:"providerId"`
		ExpectedVersion      int64           `json:"expectedVersion"`
		Enabled              bool            `json:"enabled"`
		Audit                json.RawMessage `json:"audit"`
	}{
		SessionID: params.SessionID, AuthenticationMethod: params.AuthenticationMethod,
		ProviderID: params.ProviderID, ExpectedVersion: params.ExpectedVersion,
		Enabled: params.Enabled, Audit: audit,
	})
	clear(audit)
	if err != nil {
		return platformidentityprovider.UpdateResult{}, authentication.ErrInvalidInput
	}
	defer clear(request)
	return withPlatformIdentityProviderTransaction(ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityprovider.UpdateResult, error) {
			document, queryErr := queries.SetPlatformLDAPLoginState(
				ctx, dbsql.SetPlatformLDAPLoginStateParams{Request: request},
			)
			if queryErr != nil {
				return platformidentityprovider.UpdateResult{}, queryErr
			}
			return restorePlatformLDAPUpdateResult(params.ProviderID, document, params.ValidateResult)
		},
	)
}

func restorePlatformLDAPUpdateResult(
	providerID uuid.UUID,
	document []byte,
	validate platformidentityprovider.UpdateResultValidator,
) (platformidentityprovider.UpdateResult, error) {
	provider, err := decodePlatformIdentityProvider(document)
	if err != nil || provider.ID != providerID || provider.Kind != platformidentityprovider.ProviderKindLDAP {
		return platformidentityprovider.UpdateResult{}, authentication.ErrUnavailable
	}
	result, err := platformidentityprovider.RestoreUpdateResult(
		platformidentityprovider.UpdateResultInput{
			ProviderID: providerID, Version: provider.Version, Provider: provider,
		},
	)
	if err != nil {
		return platformidentityprovider.UpdateResult{}, authentication.ErrUnavailable
	}
	validated, err := validate(result)
	if err != nil {
		return platformidentityprovider.UpdateResult{}, authentication.ErrUnavailable
	}
	return validated, nil
}
