package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentityaccount"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

const (
	maximumPlatformIdentityAccountProjectionBytes  = 16 * 1024
	maximumPlatformIdentityAccountAliases          = 16
	maximumPlatformIdentityAccountCiphertextBytes  = 4*1024 + 16
	platformIdentityAccountRevisionConflictMessage = "platform identity account revision conflict"
	platformIdentityAccountAlreadyRetiredMessage   = "platform identity account is already retired"
)

// PlatformIdentityAccountRepository is the PostgreSQL adapter for protected
// provider-global account administration. It installs the exact actor in a
// transaction, then calls only the reviewed SECURITY DEFINER account ABI. The
// adapter never reads identity tables and never returns protected subject
// material.
type PlatformIdentityAccountRepository struct {
	begin transactionBeginner
	newID func() (uuid.UUID, error)
}

var _ platformidentityaccount.Repository = (*PlatformIdentityAccountRepository)(nil)

func NewPlatformIdentityAccountRepository(
	pool *pgxpool.Pool,
) (*PlatformIdentityAccountRepository, error) {
	if pool == nil {
		return nil, errors.New("platform identity account database is required")
	}
	return &PlatformIdentityAccountRepository{
		begin: poolTransactionBeginner(pool),
		newID: uuid.NewV7,
	}, nil
}

func (repository *PlatformIdentityAccountRepository) List(
	ctx context.Context,
	params platformidentityaccount.ListParams,
) ([]platformidentityaccount.Account, error) {
	if !validPlatformIdentityAccountSession(params.SessionParams) ||
		!platformIdentityAccountUUIDv7(params.ProviderID) || params.Limit < 1 || params.Limit > 101 ||
		params.After != nil && !platformIdentityAccountUUIDv7(*params.After) {
		return nil, authentication.ErrInvalidInput
	}
	return withPlatformIdentityAccountTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) ([]platformidentityaccount.Account, error) {
			documents, err := queries.ListPlatformIdentityAccounts(
				ctx,
				dbsql.ListPlatformIdentityAccountsParams{
					SessionID:            toDatabaseUUID(params.SessionID),
					AuthenticationMethod: params.AuthenticationMethod,
					PlatformProviderID:   toDatabaseUUID(params.ProviderID),
					AfterAccountID:       optionalDatabaseUUID(params.After),
					PageSize:             params.Limit,
					IncludeRetired:       params.IncludeRetired,
				},
			)
			if err != nil {
				return nil, err
			}
			accounts := make([]platformidentityaccount.Account, 0, len(documents))
			for _, document := range documents {
				account, decodeErr := decodePlatformIdentityAccount(document)
				if decodeErr != nil {
					return nil, decodeErr
				}
				accounts = append(accounts, account)
			}
			return accounts, nil
		},
	)
}

func (repository *PlatformIdentityAccountRepository) Get(
	ctx context.Context,
	params platformidentityaccount.GetParams,
) (platformidentityaccount.Account, error) {
	if !validPlatformIdentityAccountSession(params.SessionParams) ||
		!platformIdentityAccountUUIDv7(params.ProviderID) ||
		!platformIdentityAccountUUIDv7(params.AccountID) {
		return platformidentityaccount.Account{}, authentication.ErrInvalidInput
	}
	return withPlatformIdentityAccountTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityaccount.Account, error) {
			document, err := queries.GetPlatformIdentityAccount(
				ctx,
				dbsql.GetPlatformIdentityAccountParams{
					SessionID:            toDatabaseUUID(params.SessionID),
					PlatformProviderID:   toDatabaseUUID(params.ProviderID),
					AccountID:            toDatabaseUUID(params.AccountID),
					AuthenticationMethod: params.AuthenticationMethod,
				},
			)
			if err != nil {
				return platformidentityaccount.Account{}, err
			}
			return decodePlatformIdentityAccount(document)
		},
	)
}

func (repository *PlatformIdentityAccountRepository) Prelink(
	ctx context.Context,
	params platformidentityaccount.PrelinkParams,
) (platformidentityaccount.PrelinkResult, error) {
	if !validPlatformIdentityAccountPrelink(params) {
		return platformidentityaccount.PrelinkResult{}, authentication.ErrInvalidInput
	}
	event, err := eventArguments(params.Event)
	if err != nil {
		return platformidentityaccount.PrelinkResult{}, authentication.ErrInvalidInput
	}
	auditID, err := platformIdentityAccountAuditID(repository)
	if err != nil {
		return platformidentityaccount.PrelinkResult{}, err
	}

	aliasKeyVersions := make([]int32, len(params.Subject.Aliases))
	aliasSubjectDigests := make([][]byte, len(params.Subject.Aliases))
	for index, alias := range params.Subject.Aliases {
		aliasKeyVersions[index] = int32(alias.KeyVersion)
		aliasSubjectDigests[index] = append([]byte(nil), alias.Digest[:]...)
	}
	subjectCiphertext := append([]byte(nil), params.Subject.Envelope.Ciphertext...)
	subjectNonce := append([]byte(nil), params.Subject.Envelope.Nonce[:]...)
	keyDigest := append([]byte(nil), params.KeyDigest[:]...)
	publicRequestDigest := append([]byte(nil), params.PublicRequestDigest[:]...)
	defer func() {
		clear(subjectCiphertext)
		clear(subjectNonce)
		clear(keyDigest)
		clear(publicRequestDigest)
		clearPlatformIdentityAccountDigests(aliasSubjectDigests)
		clear(aliasKeyVersions)
	}()

	return withPlatformIdentityAccountTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityaccount.PrelinkResult, error) {
			row, queryErr := queries.PrelinkPlatformIdentityAccount(
				ctx,
				dbsql.PrelinkPlatformIdentityAccountParams{
					SessionID:            toDatabaseUUID(params.SessionID),
					CommandID:            toDatabaseUUID(params.CommandID),
					AccountID:            toDatabaseUUID(params.AccountID),
					PlatformProviderID:   toDatabaseUUID(params.ProviderID),
					UserID:               toDatabaseUUID(params.UserID),
					Issuer:               params.Issuer,
					SubjectFormat:        dbsql.IdentitySubjectFormatUtf8Exact,
					SubjectCiphertext:    subjectCiphertext,
					SubjectNonce:         subjectNonce,
					SubjectKeyVersion:    int32(params.Subject.Envelope.KeyVersion),
					AliasKeyVersions:     aliasKeyVersions,
					AliasSubjectDigests:  aliasSubjectDigests,
					KeyDigest:            keyDigest,
					PublicRequestDigest:  publicRequestDigest,
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
				return platformidentityaccount.PrelinkResult{}, queryErr
			}
			accountID, mapErr := domainUUID(row.AccountID)
			if mapErr != nil {
				return platformidentityaccount.PrelinkResult{}, authentication.ErrUnavailable
			}
			account, decodeErr := decodePlatformIdentityAccount(row.Document)
			if decodeErr != nil {
				return platformidentityaccount.PrelinkResult{}, authentication.ErrUnavailable
			}
			result, restoreErr := platformidentityaccount.RestorePrelinkResult(
				platformidentityaccount.PrelinkResultInput{
					AccountID: accountID,
					Version:   row.Version,
					Replayed:  row.Replayed,
					Account:   account,
				},
			)
			if restoreErr != nil {
				return platformidentityaccount.PrelinkResult{}, authentication.ErrUnavailable
			}
			validated, validationErr := params.ValidateResult(result)
			if validationErr != nil {
				return platformidentityaccount.PrelinkResult{}, authentication.ErrUnavailable
			}
			return validated, nil
		},
	)
}

func (repository *PlatformIdentityAccountRepository) Retire(
	ctx context.Context,
	params platformidentityaccount.RetireParams,
) (platformidentityaccount.RetireResult, error) {
	if !validPlatformIdentityAccountRetire(params) {
		return platformidentityaccount.RetireResult{}, authentication.ErrInvalidInput
	}
	event, err := eventArguments(params.Event)
	if err != nil {
		return platformidentityaccount.RetireResult{}, authentication.ErrInvalidInput
	}
	auditID, err := platformIdentityAccountAuditID(repository)
	if err != nil {
		return platformidentityaccount.RetireResult{}, err
	}
	return withPlatformIdentityAccountTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityaccount.RetireResult, error) {
			previousDocument, queryErr := queries.GetPlatformIdentityAccount(
				ctx,
				dbsql.GetPlatformIdentityAccountParams{
					SessionID:            toDatabaseUUID(params.SessionID),
					PlatformProviderID:   toDatabaseUUID(params.ProviderID),
					AccountID:            toDatabaseUUID(params.AccountID),
					AuthenticationMethod: params.AuthenticationMethod,
				},
			)
			if queryErr != nil {
				return platformidentityaccount.RetireResult{}, queryErr
			}
			previous, decodeErr := decodePlatformIdentityAccount(previousDocument)
			if decodeErr != nil {
				return platformidentityaccount.RetireResult{}, authentication.ErrUnavailable
			}
			if previous.ID != params.AccountID || previous.ProviderID != params.ProviderID ||
				previous.Version != params.ExpectedVersion ||
				previous.User.Version != params.ExpectedUserVersion {
				return platformidentityaccount.RetireResult{}, platformidentityaccount.ErrPreconditionFailed
			}
			row, queryErr := queries.RetirePlatformIdentityAccountV3(
				ctx,
				dbsql.RetirePlatformIdentityAccountV3Params{
					SessionID:            toDatabaseUUID(params.SessionID),
					PlatformProviderID:   toDatabaseUUID(params.ProviderID),
					AccountID:            toDatabaseUUID(params.AccountID),
					ExpectedVersion:      params.ExpectedVersion,
					ExpectedUserVersion:  params.ExpectedUserVersion,
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
				return platformidentityaccount.RetireResult{}, queryErr
			}
			accountID, mapErr := domainUUID(row.AccountID)
			if mapErr != nil {
				return platformidentityaccount.RetireResult{}, authentication.ErrUnavailable
			}
			account, decodeErr := decodePlatformIdentityAccount(row.Document)
			if decodeErr != nil {
				return platformidentityaccount.RetireResult{}, authentication.ErrUnavailable
			}
			result, restoreErr := platformidentityaccount.RestoreRetireResult(
				platformidentityaccount.RetireResultInput{
					AccountID: accountID,
					Version:   row.Version,
					Account:   account,
				},
			)
			if restoreErr != nil || result.Version() != params.ExpectedVersion+1 {
				return platformidentityaccount.RetireResult{}, authentication.ErrUnavailable
			}
			validated, validationErr := params.ValidateResult(previous, result)
			if validationErr != nil {
				return platformidentityaccount.RetireResult{}, authentication.ErrUnavailable
			}
			return validated, nil
		},
	)
}

func withPlatformIdentityAccountTransaction[T any](
	ctx context.Context,
	repository *PlatformIdentityAccountRepository,
	session platformidentityaccount.SessionParams,
	work func(*dbsql.Queries) (T, error),
) (T, error) {
	var zero T
	if ctx == nil || repository == nil || repository.begin == nil || work == nil {
		return zero, authentication.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if !validPlatformIdentityAccountSession(session) {
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
		return zero, mapPlatformIdentityAccountDatabaseError(err)
	}
	return result, nil
}

func platformIdentityAccountAuditID(
	repository *PlatformIdentityAccountRepository,
) (uuid.UUID, error) {
	if repository == nil || repository.newID == nil {
		return uuid.Nil, authentication.ErrUnavailable
	}
	auditID, err := repository.newID()
	if err != nil || !platformIdentityAccountUUIDv7(auditID) {
		return uuid.Nil, authentication.ErrUnavailable
	}
	return auditID, nil
}

func validPlatformIdentityAccountPrelink(params platformidentityaccount.PrelinkParams) bool {
	if !validPlatformIdentityAccountSession(params.SessionParams) ||
		!platformIdentityAccountUUIDv7(params.CommandID) ||
		!platformIdentityAccountUUIDv7(params.AccountID) ||
		!platformIdentityAccountUUIDv7(params.ProviderID) ||
		!platformIdentityAccountUUIDv7(params.UserID) || len(params.Issuer) > 2*1024 ||
		!validPlatformIdentityAccountText(params.Issuer, 1, 2*1024) ||
		!validPlatformIdentityAccountReasonAndEvent(params.Reason, params.Event) ||
		params.ValidateResult == nil || platformIdentityAccountAllZero(params.KeyDigest[:]) ||
		platformIdentityAccountAllZero(params.PublicRequestDigest[:]) ||
		len(params.Subject.Aliases) < 1 || len(params.Subject.Aliases) > maximumPlatformIdentityAccountAliases ||
		params.Subject.Envelope.Format != identity.UTF8ExactSubject ||
		params.Subject.Envelope.KeyVersion < 1 || len(params.Subject.Envelope.Ciphertext) < 17 ||
		len(params.Subject.Envelope.Ciphertext) > maximumPlatformIdentityAccountCiphertextBytes {
		return false
	}
	hasEnvelopeVersion := false
	for index, alias := range params.Subject.Aliases {
		if alias.KeyVersion < 1 || index > 0 && params.Subject.Aliases[index-1].KeyVersion >= alias.KeyVersion ||
			platformIdentityAccountAllZero(alias.Digest[:]) {
			return false
		}
		if alias.KeyVersion == params.Subject.Envelope.KeyVersion {
			hasEnvelopeVersion = true
		}
	}
	return hasEnvelopeVersion
}

func validPlatformIdentityAccountRetire(params platformidentityaccount.RetireParams) bool {
	return validPlatformIdentityAccountSession(params.SessionParams) &&
		platformIdentityAccountUUIDv7(params.ProviderID) && platformIdentityAccountUUIDv7(params.AccountID) &&
		params.ExpectedVersion > 0 && params.ExpectedVersion <= 2_147_483_646 &&
		params.ExpectedUserVersion > 0 && params.ExpectedUserVersion <= 2_147_483_647 &&
		validPlatformIdentityAccountReasonAndEvent(params.Reason, params.Event) && params.ValidateResult != nil
}

func validPlatformIdentityAccountSession(session platformidentityaccount.SessionParams) bool {
	return platformIdentityAccountUUIDv7(session.ActorID) &&
		platformIdentityAccountUUIDv7(session.SessionID) &&
		validPlatformIdentityProviderAuthenticationMethod(session.AuthenticationMethod)
}

func validPlatformIdentityAccountReasonAndEvent(
	reason string,
	event authentication.EventContext,
) bool {
	if reason == "" || len(reason) > 2*1024 || strings.TrimSpace(reason) != reason ||
		!utf8.ValidString(reason) || !platformIdentityAccountUUIDv7(event.RequestID) ||
		!platformIdentityAccountUUIDv7(event.CorrelationID) ||
		!event.RemoteAddress.IsValid() || event.RemoteAddress.Zone() != "" ||
		event.UserAgent == "" || len(event.UserAgent) > 512 || !utf8.ValidString(event.UserAgent) {
		return false
	}
	for _, value := range reason {
		if unicode.IsControl(value) || unicode.In(value, unicode.Cf) {
			return false
		}
	}
	for _, value := range event.UserAgent {
		if unicode.IsControl(value) || unicode.In(value, unicode.Cf) {
			return false
		}
	}
	return true
}

func platformIdentityAccountUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func platformIdentityAccountAllZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func clearPlatformIdentityAccountDigests(values [][]byte) {
	for _, value := range values {
		clear(value)
	}
	clear(values)
}

func mapPlatformIdentityAccountDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, authentication.ErrForbidden) || errors.Is(err, authentication.ErrNotFound) ||
		errors.Is(err, authentication.ErrConflict) || errors.Is(err, authentication.ErrInvalidInput) ||
		errors.Is(err, authentication.ErrUnavailable) ||
		errors.Is(err, platformidentityaccount.ErrPreconditionFailed) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return authentication.ErrNotFound
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) && databaseError.Code == "40001" &&
		databaseError.Message == platformIdentityAccountRevisionConflictMessage {
		return platformidentityaccount.ErrPreconditionFailed
	}
	if errors.As(err, &databaseError) && databaseError.Code == "55000" &&
		databaseError.Message == platformIdentityAccountAlreadyRetiredMessage {
		return authentication.ErrConflict
	}
	switch postgresCode(err) {
	case "42501":
		return authentication.ErrForbidden
	case "P0002":
		return authentication.ErrNotFound
	case "23505":
		return authentication.ErrConflict
	case "22023", "23514":
		return authentication.ErrInvalidInput
	default:
		return authentication.ErrUnavailable
	}
}

type platformIdentityAccountWire struct {
	ID                            uuid.UUID                                    `json:"id"`
	ProviderID                    uuid.UUID                                    `json:"providerId"`
	User                          platformIdentityAccountUserWire              `json:"user"`
	State                         platformidentityaccount.AccountState         `json:"state"`
	AdmittedConfigurationRevision int64                                        `json:"admittedConfigurationRevision"`
	AdmittedSecurityRevision      int64                                        `json:"admittedSecurityRevision"`
	LastObservationState          platformidentityaccount.LastObservationState `json:"lastObservationState"`
	LastObservedAt                *time.Time                                   `json:"lastObservedAt"`
	RetiredAt                     *time.Time                                   `json:"retiredAt"`
	Version                       int64                                        `json:"version"`
	CreatedAt                     time.Time                                    `json:"createdAt"`
	UpdatedAt                     time.Time                                    `json:"updatedAt"`
}

type platformIdentityAccountUserWire struct {
	ID          uuid.UUID `json:"id"`
	DisplayName string    `json:"displayName"`
	Email       *string   `json:"email"`
	Active      bool      `json:"active"`
	Version     int64     `json:"version"`
}

func decodePlatformIdentityAccount(document []byte) (platformidentityaccount.Account, error) {
	trimmed := bytes.TrimSpace(document)
	if len(trimmed) < 2 || len(trimmed) > maximumPlatformIdentityAccountProjectionBytes || trimmed[0] != '{' {
		return platformidentityaccount.Account{}, authentication.ErrUnavailable
	}
	if err := validatePlatformIdentityProviderDocumentShape(
		trimmed,
		map[string]platformIdentityProviderJSONField{
			"id":                            {kind: platformIdentityProviderJSONString},
			"providerId":                    {kind: platformIdentityProviderJSONString},
			"user":                          {kind: platformIdentityProviderJSONObject},
			"state":                         {kind: platformIdentityProviderJSONString},
			"admittedConfigurationRevision": {kind: platformIdentityProviderJSONInteger},
			"admittedSecurityRevision":      {kind: platformIdentityProviderJSONInteger},
			"lastObservationState":          {kind: platformIdentityProviderJSONString},
			"lastObservedAt":                {kind: platformIdentityProviderJSONString, nullable: true},
			"retiredAt":                     {kind: platformIdentityProviderJSONString, nullable: true},
			"version":                       {kind: platformIdentityProviderJSONInteger},
			"createdAt":                     {kind: platformIdentityProviderJSONString},
			"updatedAt":                     {kind: platformIdentityProviderJSONString},
		},
		nil,
	); err != nil {
		return platformidentityaccount.Account{}, authentication.ErrUnavailable
	}
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &outer); err != nil {
		return platformidentityaccount.Account{}, authentication.ErrUnavailable
	}
	if err := validatePlatformIdentityProviderDocumentShape(
		outer["user"],
		map[string]platformIdentityProviderJSONField{
			"id":          {kind: platformIdentityProviderJSONString},
			"displayName": {kind: platformIdentityProviderJSONString},
			"email":       {kind: platformIdentityProviderJSONString, nullable: true},
			"active":      {kind: platformIdentityProviderJSONBoolean},
			"version":     {kind: platformIdentityProviderJSONInteger},
		},
		nil,
	); err != nil {
		return platformidentityaccount.Account{}, authentication.ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	var wire platformIdentityAccountWire
	if err := decoder.Decode(&wire); err != nil {
		return platformidentityaccount.Account{}, authentication.ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return platformidentityaccount.Account{}, authentication.ErrUnavailable
	}
	account := platformidentityaccount.Account{
		ID:         wire.ID,
		ProviderID: wire.ProviderID,
		User: platformidentityaccount.UserSummary{
			ID: wire.User.ID, DisplayName: wire.User.DisplayName,
			Email: clonePlatformIdentityAccountString(wire.User.Email), Active: wire.User.Active,
			Version: wire.User.Version,
		},
		State:                         wire.State,
		AdmittedConfigurationRevision: wire.AdmittedConfigurationRevision,
		AdmittedSecurityRevision:      wire.AdmittedSecurityRevision,
		LastObservationState:          wire.LastObservationState,
		LastObservedAt:                platformIdentityAccountOptionalUTC(wire.LastObservedAt),
		RetiredAt:                     platformIdentityAccountOptionalUTC(wire.RetiredAt),
		Version:                       wire.Version,
		CreatedAt:                     wire.CreatedAt.UTC(),
		UpdatedAt:                     wire.UpdatedAt.UTC(),
	}
	if !validPlatformIdentityAccountProjection(account) {
		return platformidentityaccount.Account{}, authentication.ErrUnavailable
	}
	return account, nil
}

func validPlatformIdentityAccountProjection(value platformidentityaccount.Account) bool {
	if !platformIdentityAccountUUIDv7(value.ID) || !platformIdentityAccountUUIDv7(value.ProviderID) ||
		!platformIdentityAccountUUIDv7(value.User.ID) ||
		!validPlatformIdentityAccountText(value.User.DisplayName, 1, 160) ||
		value.User.Version < 1 || value.User.Version > 2_147_483_647 ||
		(value.State != platformidentityaccount.AccountStateActive &&
			value.State != platformidentityaccount.AccountStateRetired) ||
		(value.State == platformidentityaccount.AccountStateActive) != (value.RetiredAt == nil) ||
		value.AdmittedConfigurationRevision < 1 ||
		value.AdmittedConfigurationRevision > 9_007_199_254_740_991 ||
		value.AdmittedSecurityRevision < 1 || value.AdmittedSecurityRevision > 9_007_199_254_740_991 ||
		value.Version < 1 || value.Version > 2_147_483_647 ||
		!validPlatformIdentityAccountInstant(value.CreatedAt) ||
		!validPlatformIdentityAccountInstant(value.UpdatedAt) ||
		value.UpdatedAt.Before(value.CreatedAt) {
		return false
	}
	switch value.LastObservationState {
	case platformidentityaccount.LastObservationStateKnown:
		if value.LastObservedAt == nil || !validPlatformIdentityAccountInstant(*value.LastObservedAt) ||
			value.LastObservedAt.Before(value.CreatedAt) || value.LastObservedAt.After(value.UpdatedAt) {
			return false
		}
	case platformidentityaccount.LastObservationStateLegacyUnknown:
		if value.State != platformidentityaccount.AccountStateRetired || value.RetiredAt == nil ||
			value.LastObservedAt != nil || value.Version != 1 {
			return false
		}
	default:
		return false
	}
	if value.User.Email != nil {
		email := *value.User.Email
		if len(email) > 320 || strings.TrimSpace(email) != email || strings.ToLower(email) != email ||
			strings.IndexByte(email, '@') <= 0 || !validPlatformIdentityAccountText(email, 3, 320) {
			return false
		}
	}
	return value.RetiredAt == nil ||
		validPlatformIdentityAccountInstant(*value.RetiredAt) &&
			!value.RetiredAt.Before(value.CreatedAt) &&
			(value.LastObservedAt == nil || !value.RetiredAt.Before(*value.LastObservedAt)) &&
			!value.RetiredAt.After(value.UpdatedAt)
}

func validPlatformIdentityAccountText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) < minimum ||
		utf8.RuneCountInString(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func validPlatformIdentityAccountInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 1970 && value.Year() <= 9999 &&
		value.Nanosecond()%1_000 == 0
}

func platformIdentityAccountOptionalUTC(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	normalized := value.UTC()
	return &normalized
}

func clonePlatformIdentityAccountString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
