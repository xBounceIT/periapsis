package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

var _ platformidentityprovider.LDAPTestRepository = (*PlatformIdentityProviderRepository)(nil)

type platformLDAPTestSecretWire struct {
	SecretID   uuid.UUID `json:"secretId"`
	Revision   int64     `json:"revision"`
	KeyVersion int16     `json:"keyVersion"`
	Nonce      string    `json:"nonce"`
	Ciphertext string    `json:"ciphertext"`
}

type platformLDAPTestSnapshotWire struct {
	TestID                uuid.UUID                               `json:"testId"`
	ProviderID            uuid.UUID                               `json:"providerId"`
	Kind                  platformidentityprovider.LDAPTestKind   `json:"kind"`
	ProviderVersion       int64                                   `json:"providerVersion"`
	ConfigurationRevision int64                                   `json:"configurationRevision"`
	MappingRevision       int64                                   `json:"mappingRevision"`
	Configuration         identityprovider.Configuration          `json:"configuration"`
	Endpoints             []platformidentityprovider.LDAPEndpoint `json:"endpoints"`
	Mappings              []platformidentityprovider.LDAPMapping  `json:"mappings"`
	BindSecret            *platformLDAPTestSecretWire             `json:"bindSecret"`
}

func (repository *PlatformIdentityProviderRepository) BeginLDAPTest(
	ctx context.Context,
	params platformidentityprovider.BeginLDAPTestParams,
) (platformidentityprovider.LDAPTestSnapshot, error) {
	if !validPlatformIdentityProviderSession(params.SessionParams) ||
		!platformIdentityProviderUUIDv7(params.ProviderID) || !platformIdentityProviderUUIDv7(params.TestID) ||
		!validPlatformLDAPTestKind(params.Kind) || params.Event.RequestID == uuid.Nil ||
		params.Event.CorrelationID == uuid.Nil {
		return platformidentityprovider.LDAPTestSnapshot{}, authentication.ErrInvalidInput
	}
	request, err := json.Marshal(struct {
		SessionID            uuid.UUID                             `json:"sessionId"`
		AuthenticationMethod string                                `json:"authenticationMethod"`
		ProviderID           uuid.UUID                             `json:"providerId"`
		TestID               uuid.UUID                             `json:"testId"`
		Kind                 platformidentityprovider.LDAPTestKind `json:"kind"`
		RequestID            uuid.UUID                             `json:"requestId"`
		CorrelationID        uuid.UUID                             `json:"correlationId"`
	}{
		SessionID: params.SessionID, AuthenticationMethod: params.AuthenticationMethod,
		ProviderID: params.ProviderID, TestID: params.TestID, Kind: params.Kind,
		RequestID: params.Event.RequestID, CorrelationID: params.Event.CorrelationID,
	})
	if err != nil {
		return platformidentityprovider.LDAPTestSnapshot{}, authentication.ErrInvalidInput
	}
	defer clear(request)
	return withPlatformIdentityProviderTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityprovider.LDAPTestSnapshot, error) {
			document, queryErr := queries.BeginPlatformLDAPTest(
				ctx, dbsql.BeginPlatformLDAPTestParams{Request: request},
			)
			if queryErr != nil {
				return platformidentityprovider.LDAPTestSnapshot{}, queryErr
			}
			defer clear(document)
			var wire platformLDAPTestSnapshotWire
			if err := json.Unmarshal(document, &wire); err != nil {
				return platformidentityprovider.LDAPTestSnapshot{}, authentication.ErrUnavailable
			}
			return restorePlatformLDAPTestSnapshot(wire)
		},
	)
}

func (repository *PlatformIdentityProviderRepository) CompleteLDAPTest(
	ctx context.Context,
	params platformidentityprovider.CompleteLDAPTestParams,
) (platformidentityprovider.LDAPDiagnostic, error) {
	if !validPlatformIdentityProviderSession(params.SessionParams) ||
		!platformIdentityProviderUUIDv7(params.TestID) || !validPlatformLDAPTestReport(params) {
		return platformidentityprovider.LDAPDiagnostic{}, authentication.ErrInvalidInput
	}
	auditID, err := platformIdentityProviderAuditID(repository)
	if err != nil {
		return platformidentityprovider.LDAPDiagnostic{}, err
	}
	audit := platformLDAPAuditDocument(auditID, params.SessionParams, params.Event, params.Reason)
	request, err := json.Marshal(struct {
		SessionID            uuid.UUID       `json:"sessionId"`
		AuthenticationMethod string          `json:"authenticationMethod"`
		TestID               uuid.UUID       `json:"testId"`
		Outcome              string          `json:"outcome"`
		Category             string          `json:"category"`
		EndpointPriority     *int            `json:"endpointPriority,omitempty"`
		DurationMS           int64           `json:"durationMs"`
		MatchedEntryCount    *int            `json:"matchedEntryCount,omitempty"`
		Attributes           []string        `json:"attributes"`
		CompletedAt          time.Time       `json:"completedAt"`
		Audit                json.RawMessage `json:"audit"`
	}{
		SessionID: params.SessionID, AuthenticationMethod: params.AuthenticationMethod,
		TestID: params.TestID, Outcome: params.Outcome, Category: params.Category,
		EndpointPriority: params.EndpointPriority, DurationMS: params.Duration.Milliseconds(),
		MatchedEntryCount: params.MatchedEntryCount, Attributes: params.Attributes,
		CompletedAt: params.CompletedAt.UTC(), Audit: audit,
	})
	clear(audit)
	if err != nil {
		return platformidentityprovider.LDAPDiagnostic{}, authentication.ErrInvalidInput
	}
	defer clear(request)
	return withPlatformIdentityProviderTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityprovider.LDAPDiagnostic, error) {
			document, queryErr := queries.CompletePlatformLDAPTest(
				ctx, dbsql.CompletePlatformLDAPTestParams{Request: request},
			)
			if queryErr != nil {
				return platformidentityprovider.LDAPDiagnostic{}, queryErr
			}
			defer clear(document)
			var result struct {
				TestID            uuid.UUID                             `json:"testId"`
				Kind              platformidentityprovider.LDAPTestKind `json:"kind"`
				Outcome           string                                `json:"outcome"`
				Category          string                                `json:"category"`
				EndpointPriority  *int                                  `json:"endpointPriority"`
				DurationMS        int                                   `json:"durationMs"`
				MatchedEntryCount *int                                  `json:"matchedEntryCount"`
				Attributes        []string                              `json:"attributes"`
			}
			if err := json.Unmarshal(document, &result); err != nil {
				return platformidentityprovider.LDAPDiagnostic{}, authentication.ErrUnavailable
			}
			return platformidentityprovider.LDAPDiagnostic{
				TestID: result.TestID, Kind: result.Kind, Outcome: result.Outcome,
				Category: result.Category, EndpointPriority: result.EndpointPriority,
				Duration:          time.Duration(result.DurationMS) * time.Millisecond,
				MatchedEntryCount: result.MatchedEntryCount, Attributes: result.Attributes,
			}, nil
		},
	)
}

func restorePlatformLDAPTestSnapshot(
	wire platformLDAPTestSnapshotWire,
) (platformidentityprovider.LDAPTestSnapshot, error) {
	result := platformidentityprovider.LDAPTestSnapshot{
		TestID: wire.TestID, ProviderID: wire.ProviderID, Kind: wire.Kind,
		ProviderVersion: wire.ProviderVersion, ConfigurationRevision: wire.ConfigurationRevision,
		MappingRevision: wire.MappingRevision, Configuration: wire.Configuration,
		Endpoints: wire.Endpoints, Mappings: wire.Mappings,
	}
	if wire.BindSecret == nil {
		return result, nil
	}
	nonce, err := hex.DecodeString(wire.BindSecret.Nonce)
	if err != nil || len(nonce) != len(identity.BindSecretEnvelope{}.Nonce) {
		clear(nonce)
		result.Destroy()
		return platformidentityprovider.LDAPTestSnapshot{}, authentication.ErrUnavailable
	}
	ciphertext, err := hex.DecodeString(wire.BindSecret.Ciphertext)
	if err != nil || len(ciphertext) < 17 || len(ciphertext) > 8192 {
		clear(nonce)
		clear(ciphertext)
		result.Destroy()
		return platformidentityprovider.LDAPTestSnapshot{}, authentication.ErrUnavailable
	}
	var envelope identity.BindSecretEnvelope
	envelope.KeyVersion = wire.BindSecret.KeyVersion
	copy(envelope.Nonce[:], nonce)
	clear(nonce)
	envelope.Ciphertext = ciphertext
	result.BindSecret = &platformidentityprovider.EncryptedLDAPBindSecret{
		SecretID: wire.BindSecret.SecretID, Envelope: envelope,
	}
	revision := wire.BindSecret.Revision
	result.SecretRevision = &revision
	return result, nil
}

func validPlatformLDAPTestKind(kind platformidentityprovider.LDAPTestKind) bool {
	switch kind {
	case platformidentityprovider.LDAPTestConnection, platformidentityprovider.LDAPTestBind,
		platformidentityprovider.LDAPTestSearchUser, platformidentityprovider.LDAPTestFilter,
		platformidentityprovider.LDAPTestMappingDryRun:
		return true
	default:
		return false
	}
}

func validPlatformLDAPTestReport(params platformidentityprovider.CompleteLDAPTestParams) bool {
	if params.Outcome != "success" && params.Outcome != "failure" && params.Outcome != "inconclusive" ||
		params.Category == "" || params.Duration < 0 || params.Duration > 120*time.Second ||
		params.CompletedAt.IsZero() || params.Reason == "" || params.Event.RequestID == uuid.Nil ||
		params.Event.CorrelationID == uuid.Nil || len(params.Attributes) > 128 {
		return false
	}
	if params.EndpointPriority != nil && (*params.EndpointPriority < 1 || *params.EndpointPriority > 8) {
		return false
	}
	if params.MatchedEntryCount != nil && (*params.MatchedEntryCount < 0 || *params.MatchedEntryCount > 1000) {
		return false
	}
	for _, attribute := range params.Attributes {
		if attribute == "" || len(attribute) > 128 {
			return false
		}
	}
	return true
}
