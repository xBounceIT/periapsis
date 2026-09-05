package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentitybinding"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

const (
	maximumPlatformIdentityBindingProjectionBytes  = 32 * 1024
	platformIdentityBindingRevisionConflictMessage = "tenant platform identity binding revision conflict"
	maximumPlatformIdentityBindingPriority         = 1_000_000
)

var platformIdentityBindingKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)

// PlatformIdentityBindingRepository persists explicit tenant bindings through
// only the protected cross-boundary ABI. Every call has its own transaction
// and reinstalls the exact human actor before the ABI revalidates the session.
type PlatformIdentityBindingRepository struct {
	begin transactionBeginner
	newID func() (uuid.UUID, error)
}

var _ platformidentitybinding.Repository = (*PlatformIdentityBindingRepository)(nil)

func NewPlatformIdentityBindingRepository(pool *pgxpool.Pool) *PlatformIdentityBindingRepository {
	return &PlatformIdentityBindingRepository{begin: poolTransactionBeginner(pool), newID: uuid.NewV7}
}

func (repository *PlatformIdentityBindingRepository) List(
	ctx context.Context,
	params platformidentitybinding.ListParams,
) ([]platformidentitybinding.Binding, error) {
	if !platformIdentityBindingUUIDv7(params.ProviderID) || params.Limit < 1 || params.Limit > 200 ||
		params.After != nil && !platformIdentityBindingUUIDv7(*params.After) {
		return nil, authentication.ErrInvalidInput
	}
	return withPlatformIdentityBindingTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) ([]platformidentitybinding.Binding, error) {
			documents, err := queries.ListTenantPlatformAuthProviderBindings(
				ctx,
				dbsql.ListTenantPlatformAuthProviderBindingsParams{
					SessionID:            toDatabaseUUID(params.SessionID),
					PlatformProviderID:   toDatabaseUUID(params.ProviderID),
					AuthenticationMethod: params.AuthenticationMethod,
					AfterBindingID:       optionalDatabaseUUID(params.After),
					PageSize:             params.Limit,
					IncludeArchived:      params.IncludeArchived,
				},
			)
			if err != nil {
				return nil, err
			}
			bindings := make([]platformidentitybinding.Binding, 0, len(documents))
			for _, document := range documents {
				binding, decodeErr := decodePlatformIdentityBinding(document)
				if decodeErr != nil {
					return nil, decodeErr
				}
				bindings = append(bindings, binding)
			}
			return bindings, nil
		},
	)
}

func (repository *PlatformIdentityBindingRepository) Get(
	ctx context.Context,
	params platformidentitybinding.GetParams,
) (platformidentitybinding.Binding, error) {
	if !platformIdentityBindingUUIDv7(params.ProviderID) || !platformIdentityBindingUUIDv7(params.BindingID) {
		return platformidentitybinding.Binding{}, authentication.ErrInvalidInput
	}
	return withPlatformIdentityBindingTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentitybinding.Binding, error) {
			document, err := queries.GetTenantPlatformAuthProviderBinding(
				ctx,
				dbsql.GetTenantPlatformAuthProviderBindingParams{
					SessionID:            toDatabaseUUID(params.SessionID),
					PlatformProviderID:   toDatabaseUUID(params.ProviderID),
					BindingID:            toDatabaseUUID(params.BindingID),
					AuthenticationMethod: params.AuthenticationMethod,
				},
			)
			if err != nil {
				return platformidentitybinding.Binding{}, err
			}
			return decodePlatformIdentityBinding(document)
		},
	)
}

func (repository *PlatformIdentityBindingRepository) Create(
	ctx context.Context,
	params platformidentitybinding.CreateParams,
) (platformidentitybinding.CreateResult, error) {
	if !validPlatformIdentityBindingCreate(params) {
		return platformidentitybinding.CreateResult{}, authentication.ErrInvalidInput
	}
	event, err := eventArguments(params.Event)
	if err != nil {
		return platformidentitybinding.CreateResult{}, authentication.ErrInvalidInput
	}
	tenantAuditID, platformAuditID, err := platformIdentityBindingAuditIDs(repository)
	if err != nil {
		return platformidentitybinding.CreateResult{}, err
	}
	keyDigest := append([]byte(nil), params.KeyDigest[:]...)
	requestDigest := append([]byte(nil), params.RequestDigest[:]...)
	defer clear(keyDigest)
	defer clear(requestDigest)

	return withPlatformIdentityBindingTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentitybinding.CreateResult, error) {
			row, queryErr := queries.CreateTenantPlatformAuthProviderBinding(
				ctx,
				dbsql.CreateTenantPlatformAuthProviderBindingParams{
					SessionID:            toDatabaseUUID(params.SessionID),
					CommandID:            toDatabaseUUID(params.CommandID),
					BindingID:            toDatabaseUUID(params.BindingID),
					PlatformProviderID:   toDatabaseUUID(params.ProviderID),
					TenantID:             toDatabaseUUID(params.TenantID),
					LoginKey:             params.LoginKey,
					ProfilePriority:      int32(params.ProfilePriority),
					KeyDigest:            keyDigest,
					RequestDigest:        requestDigest,
					TenantAuditEventID:   toDatabaseUUID(tenantAuditID),
					PlatformAuditEventID: toDatabaseUUID(platformAuditID),
					RequestID:            event.requestID,
					CorrelationID:        event.correlationID,
					IpAddress:            params.Event.RemoteAddress,
					UserAgent:            params.Event.UserAgent,
					AuthenticationMethod: params.AuthenticationMethod,
					Reason:               params.Reason,
				},
			)
			if queryErr != nil {
				return platformidentitybinding.CreateResult{}, queryErr
			}
			bindingID, mapErr := domainUUID(row.BindingID)
			if mapErr != nil {
				return platformidentitybinding.CreateResult{}, authentication.ErrUnavailable
			}
			binding, decodeErr := decodePlatformIdentityBinding(row.Document)
			if decodeErr != nil {
				return platformidentitybinding.CreateResult{}, authentication.ErrUnavailable
			}
			result, restoreErr := platformidentitybinding.RestoreCreateResult(
				platformidentitybinding.CreateResultInput{
					BindingID: bindingID, Version: row.Version, Replayed: row.Replayed, Binding: binding,
				},
			)
			if restoreErr != nil {
				return platformidentitybinding.CreateResult{}, authentication.ErrUnavailable
			}
			validated, validationErr := params.ValidateResult(result)
			if validationErr != nil {
				return platformidentitybinding.CreateResult{}, authentication.ErrUnavailable
			}
			return validated, nil
		},
	)
}

func (repository *PlatformIdentityBindingRepository) Update(
	ctx context.Context,
	params platformidentitybinding.UpdateParams,
) (platformidentitybinding.UpdateResult, error) {
	if !validPlatformIdentityBindingMutation(
		params.SessionParams, params.ProviderID, params.BindingID, params.ExpectedVersion,
		params.ExpectedTenantVersion,
		params.LoginKey, params.ProfilePriority, params.Reason, params.Event,
	) || params.ValidateResult == nil {
		return platformidentitybinding.UpdateResult{}, authentication.ErrInvalidInput
	}
	event, err := eventArguments(params.Event)
	if err != nil {
		return platformidentitybinding.UpdateResult{}, authentication.ErrInvalidInput
	}
	tenantAuditID, platformAuditID, err := platformIdentityBindingAuditIDs(repository)
	if err != nil {
		return platformidentitybinding.UpdateResult{}, err
	}

	return withPlatformIdentityBindingTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentitybinding.UpdateResult, error) {
			row, queryErr := queries.UpdateTenantPlatformAuthProviderBinding(
				ctx,
				dbsql.UpdateTenantPlatformAuthProviderBindingParams{
					SessionID:             toDatabaseUUID(params.SessionID),
					PlatformProviderID:    toDatabaseUUID(params.ProviderID),
					BindingID:             toDatabaseUUID(params.BindingID),
					ExpectedVersion:       params.ExpectedVersion,
					ExpectedTenantVersion: int32(params.ExpectedTenantVersion),
					LoginKey:              params.LoginKey,
					ProfilePriority:       int32(params.ProfilePriority),
					TenantAuditEventID:    toDatabaseUUID(tenantAuditID),
					PlatformAuditEventID:  toDatabaseUUID(platformAuditID),
					RequestID:             event.requestID,
					CorrelationID:         event.correlationID,
					IpAddress:             params.Event.RemoteAddress,
					UserAgent:             params.Event.UserAgent,
					AuthenticationMethod:  params.AuthenticationMethod,
					Reason:                params.Reason,
				},
			)
			if queryErr != nil {
				return platformidentitybinding.UpdateResult{}, queryErr
			}
			binding, decodeErr := decodePlatformIdentityBinding(row.Document)
			if decodeErr != nil {
				return platformidentitybinding.UpdateResult{}, authentication.ErrUnavailable
			}
			result, restoreErr := platformidentitybinding.RestoreUpdateResult(
				platformidentitybinding.UpdateResultInput{
					BindingID: params.BindingID, Version: row.Version, Binding: binding,
				},
			)
			if restoreErr != nil {
				return platformidentitybinding.UpdateResult{}, authentication.ErrUnavailable
			}
			validated, validationErr := params.ValidateResult(result)
			if validationErr != nil {
				return platformidentitybinding.UpdateResult{}, authentication.ErrUnavailable
			}
			return validated, nil
		},
	)
}

func (repository *PlatformIdentityBindingRepository) Archive(
	ctx context.Context,
	params platformidentitybinding.ArchiveParams,
) (platformidentitybinding.MutationReceipt, error) {
	if !validPlatformIdentityBindingArchive(params) {
		return platformidentitybinding.MutationReceipt{}, authentication.ErrInvalidInput
	}
	event, err := eventArguments(params.Event)
	if err != nil {
		return platformidentitybinding.MutationReceipt{}, authentication.ErrInvalidInput
	}
	tenantAuditID, platformAuditID, err := platformIdentityBindingAuditIDs(repository)
	if err != nil {
		return platformidentitybinding.MutationReceipt{}, err
	}

	return withPlatformIdentityBindingTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentitybinding.MutationReceipt, error) {
			row, queryErr := queries.ArchiveTenantPlatformAuthProviderBinding(
				ctx,
				dbsql.ArchiveTenantPlatformAuthProviderBindingParams{
					SessionID:             toDatabaseUUID(params.SessionID),
					PlatformProviderID:    toDatabaseUUID(params.ProviderID),
					BindingID:             toDatabaseUUID(params.BindingID),
					ExpectedVersion:       params.ExpectedVersion,
					ExpectedTenantVersion: int32(params.ExpectedTenantVersion),
					TenantAuditEventID:    toDatabaseUUID(tenantAuditID),
					PlatformAuditEventID:  toDatabaseUUID(platformAuditID),
					RequestID:             event.requestID,
					CorrelationID:         event.correlationID,
					IpAddress:             params.Event.RemoteAddress,
					UserAgent:             params.Event.UserAgent,
					AuthenticationMethod:  params.AuthenticationMethod,
					Reason:                params.Reason,
				},
			)
			if queryErr != nil {
				return platformidentitybinding.MutationReceipt{}, queryErr
			}
			receipt, restoreErr := platformidentitybinding.RestoreMutationReceipt(
				platformidentitybinding.MutationReceiptInput{
					BindingID: params.BindingID, Version: row.Version, TenantVersion: int64(row.TenantVersion),
				},
			)
			if restoreErr != nil || receipt.Version() != params.ExpectedVersion+1 ||
				receipt.TenantVersion() != params.ExpectedTenantVersion {
				return platformidentitybinding.MutationReceipt{}, authentication.ErrUnavailable
			}
			return receipt, nil
		},
	)
}

func (repository *PlatformIdentityBindingRepository) Activate(
	ctx context.Context,
	params platformidentitybinding.ActivationParams,
) (platformidentitybinding.UpdateResult, error) {
	if !validPlatformIdentityBindingLifecycleMutation(
		params.SessionParams, params.ProviderID, params.BindingID, params.ExpectedVersion,
		params.ExpectedTenantVersion, params.Reason, params.Event,
	) || (params.JITMode != platformidentitybinding.JITModeDisabled &&
		params.JITMode != platformidentitybinding.JITModeCreate) ||
		(params.NoMatchPolicy != platformidentitybinding.NoMatchPolicyDeny &&
			params.NoMatchPolicy != platformidentitybinding.NoMatchPolicyProviderAccessOnly) ||
		params.ValidateResult == nil {
		return platformidentitybinding.UpdateResult{}, authentication.ErrInvalidInput
	}
	event, err := eventArguments(params.Event)
	if err != nil {
		return platformidentitybinding.UpdateResult{}, authentication.ErrInvalidInput
	}
	tenantAuditID, platformAuditID, err := platformIdentityBindingAuditIDs(repository)
	if err != nil {
		return platformidentitybinding.UpdateResult{}, err
	}
	return withPlatformIdentityBindingTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentitybinding.UpdateResult, error) {
			row, queryErr := queries.ActivateTenantPlatformAuthProviderBinding(
				ctx,
				dbsql.ActivateTenantPlatformAuthProviderBindingParams{
					SessionID:             toDatabaseUUID(params.SessionID),
					PlatformProviderID:    toDatabaseUUID(params.ProviderID),
					BindingID:             toDatabaseUUID(params.BindingID),
					ExpectedVersion:       params.ExpectedVersion,
					ExpectedTenantVersion: int32(params.ExpectedTenantVersion),
					JitMode:               string(params.JITMode),
					NoMatchPolicy:         string(params.NoMatchPolicy),
					TenantAuditEventID:    toDatabaseUUID(tenantAuditID),
					PlatformAuditEventID:  toDatabaseUUID(platformAuditID),
					RequestID:             event.requestID,
					CorrelationID:         event.correlationID,
					IpAddress:             params.Event.RemoteAddress,
					UserAgent:             params.Event.UserAgent,
					AuthenticationMethod:  params.AuthenticationMethod,
					Reason:                params.Reason,
				},
			)
			if queryErr != nil {
				return platformidentitybinding.UpdateResult{}, queryErr
			}
			return restorePlatformIdentityBindingLifecycleResult(
				params.BindingID, params.ExpectedVersion, params.ExpectedTenantVersion,
				params.ValidateResult, row.Version, row.Document,
			)
		},
	)
}

func (repository *PlatformIdentityBindingRepository) Deactivate(
	ctx context.Context,
	params platformidentitybinding.DeactivationParams,
) (platformidentitybinding.UpdateResult, error) {
	if !validPlatformIdentityBindingLifecycleMutation(
		params.SessionParams, params.ProviderID, params.BindingID, params.ExpectedVersion,
		params.ExpectedTenantVersion, params.Reason, params.Event,
	) || params.ValidateResult == nil {
		return platformidentitybinding.UpdateResult{}, authentication.ErrInvalidInput
	}
	event, err := eventArguments(params.Event)
	if err != nil {
		return platformidentitybinding.UpdateResult{}, authentication.ErrInvalidInput
	}
	tenantAuditID, platformAuditID, err := platformIdentityBindingAuditIDs(repository)
	if err != nil {
		return platformidentitybinding.UpdateResult{}, err
	}
	return withPlatformIdentityBindingTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentitybinding.UpdateResult, error) {
			row, queryErr := queries.DeactivateTenantPlatformAuthProviderBinding(
				ctx,
				dbsql.DeactivateTenantPlatformAuthProviderBindingParams{
					SessionID:             toDatabaseUUID(params.SessionID),
					PlatformProviderID:    toDatabaseUUID(params.ProviderID),
					BindingID:             toDatabaseUUID(params.BindingID),
					ExpectedVersion:       params.ExpectedVersion,
					ExpectedTenantVersion: int32(params.ExpectedTenantVersion),
					TenantAuditEventID:    toDatabaseUUID(tenantAuditID),
					PlatformAuditEventID:  toDatabaseUUID(platformAuditID),
					RequestID:             event.requestID,
					CorrelationID:         event.correlationID,
					IpAddress:             params.Event.RemoteAddress,
					UserAgent:             params.Event.UserAgent,
					AuthenticationMethod:  params.AuthenticationMethod,
					Reason:                params.Reason,
				},
			)
			if queryErr != nil {
				return platformidentitybinding.UpdateResult{}, queryErr
			}
			return restorePlatformIdentityBindingLifecycleResult(
				params.BindingID, params.ExpectedVersion, params.ExpectedTenantVersion,
				params.ValidateResult, row.Version, row.Document,
			)
		},
	)
}

func validPlatformIdentityBindingLifecycleMutation(
	session platformidentitybinding.SessionParams,
	providerID, bindingID uuid.UUID,
	expectedVersion, expectedTenantVersion int64,
	reason string,
	event authentication.EventContext,
) bool {
	return validPlatformIdentityBindingSession(session) &&
		platformIdentityBindingUUIDv7(providerID) && platformIdentityBindingUUIDv7(bindingID) &&
		expectedVersion > 0 && expectedVersion <= 2_147_483_646 &&
		expectedTenantVersion > 0 && expectedTenantVersion <= 2_147_483_647 &&
		validPlatformIdentityBindingReasonAndEvent(reason, event)
}

func restorePlatformIdentityBindingLifecycleResult(
	bindingID uuid.UUID,
	expectedVersion, expectedTenantVersion int64,
	validate platformidentitybinding.UpdateResultValidator,
	version int64,
	document []byte,
) (platformidentitybinding.UpdateResult, error) {
	binding, err := decodePlatformIdentityBinding(document)
	if err != nil {
		return platformidentitybinding.UpdateResult{}, authentication.ErrUnavailable
	}
	result, err := platformidentitybinding.RestoreUpdateResult(
		platformidentitybinding.UpdateResultInput{
			BindingID: bindingID, Version: version, Binding: binding,
		},
	)
	if err != nil || result.Version() != expectedVersion+1 ||
		binding.Tenant.Version != expectedTenantVersion || validate == nil {
		return platformidentitybinding.UpdateResult{}, authentication.ErrUnavailable
	}
	validated, err := validate(result)
	if err != nil {
		return platformidentitybinding.UpdateResult{}, authentication.ErrUnavailable
	}
	return validated, nil
}

func withPlatformIdentityBindingTransaction[T any](
	ctx context.Context,
	repository *PlatformIdentityBindingRepository,
	session platformidentitybinding.SessionParams,
	work func(*dbsql.Queries) (T, error),
) (T, error) {
	var zero T
	if ctx == nil || repository == nil || repository.begin == nil || work == nil {
		return zero, authentication.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if !validPlatformIdentityBindingSession(session) {
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
		return zero, mapPlatformIdentityBindingDatabaseError(err)
	}
	return result, nil
}

func platformIdentityBindingAuditIDs(
	repository *PlatformIdentityBindingRepository,
) (uuid.UUID, uuid.UUID, error) {
	if repository == nil || repository.newID == nil {
		return uuid.Nil, uuid.Nil, authentication.ErrUnavailable
	}
	tenantAuditID, err := repository.newID()
	if err != nil || !platformIdentityBindingUUIDv7(tenantAuditID) {
		return uuid.Nil, uuid.Nil, authentication.ErrUnavailable
	}
	platformAuditID, err := repository.newID()
	if err != nil || !platformIdentityBindingUUIDv7(platformAuditID) || platformAuditID == tenantAuditID {
		return uuid.Nil, uuid.Nil, authentication.ErrUnavailable
	}
	return tenantAuditID, platformAuditID, nil
}

func validPlatformIdentityBindingCreate(params platformidentitybinding.CreateParams) bool {
	return validPlatformIdentityBindingSession(params.SessionParams) &&
		platformIdentityBindingUUIDv7(params.CommandID) && platformIdentityBindingUUIDv7(params.BindingID) &&
		platformIdentityBindingUUIDv7(params.ProviderID) && platformIdentityBindingUUIDv7(params.TenantID) &&
		validPlatformIdentityBindingWrite(params.LoginKey, params.ProfilePriority, params.Reason, params.Event) &&
		!platformIdentityBindingAllZero(params.KeyDigest[:]) &&
		!platformIdentityBindingAllZero(params.RequestDigest[:]) && params.ValidateResult != nil
}

func validPlatformIdentityBindingArchive(params platformidentitybinding.ArchiveParams) bool {
	return validPlatformIdentityBindingSession(params.SessionParams) &&
		platformIdentityBindingUUIDv7(params.ProviderID) && platformIdentityBindingUUIDv7(params.BindingID) &&
		params.ExpectedVersion > 0 && params.ExpectedVersion <= 2_147_483_646 &&
		params.ExpectedTenantVersion > 0 && params.ExpectedTenantVersion <= 2_147_483_647 &&
		validPlatformIdentityBindingReasonAndEvent(params.Reason, params.Event)
}

func validPlatformIdentityBindingMutation(
	session platformidentitybinding.SessionParams,
	providerID, bindingID uuid.UUID,
	expectedVersion int64,
	expectedTenantVersion int64,
	loginKey string,
	profilePriority int,
	reason string,
	event authentication.EventContext,
) bool {
	return validPlatformIdentityBindingSession(session) &&
		platformIdentityBindingUUIDv7(providerID) && platformIdentityBindingUUIDv7(bindingID) &&
		expectedVersion > 0 && expectedVersion <= 2_147_483_646 &&
		expectedTenantVersion > 0 && expectedTenantVersion <= 2_147_483_647 &&
		validPlatformIdentityBindingWrite(loginKey, profilePriority, reason, event)
}

func validPlatformIdentityBindingWrite(
	loginKey string,
	profilePriority int,
	reason string,
	event authentication.EventContext,
) bool {
	return platformIdentityBindingKeyPattern.MatchString(loginKey) &&
		profilePriority >= 0 && profilePriority <= maximumPlatformIdentityBindingPriority &&
		validPlatformIdentityBindingReasonAndEvent(reason, event)
}

func validPlatformIdentityBindingReasonAndEvent(
	reason string,
	event authentication.EventContext,
) bool {
	if reason == "" || len(reason) > 2*1024 || strings.TrimSpace(reason) != reason ||
		!utf8.ValidString(reason) || !platformIdentityBindingUUIDv7(event.RequestID) ||
		!platformIdentityBindingUUIDv7(event.CorrelationID) ||
		!event.RemoteAddress.IsValid() || event.RemoteAddress.Zone() != "" ||
		len(event.UserAgent) < 1 || len(event.UserAgent) > 512 || !utf8.ValidString(event.UserAgent) {
		return false
	}
	for _, character := range reason {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	for _, character := range event.UserAgent {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func validPlatformIdentityBindingSession(session platformidentitybinding.SessionParams) bool {
	return platformIdentityBindingUUIDv7(session.ActorID) &&
		platformIdentityBindingUUIDv7(session.SessionID) &&
		validPlatformIdentityBindingAuthenticationMethod(session.AuthenticationMethod)
}

func validPlatformIdentityBindingAuthenticationMethod(value string) bool {
	switch value {
	case "bootstrap_totp", "oidc", "passkey", "recovery_code", "saml", "totp":
		return true
	default:
		return false
	}
}

func platformIdentityBindingUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func platformIdentityBindingAllZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func mapPlatformIdentityBindingDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, authentication.ErrForbidden) || errors.Is(err, authentication.ErrNotFound) ||
		errors.Is(err, authentication.ErrConflict) || errors.Is(err, authentication.ErrInvalidInput) ||
		errors.Is(err, authentication.ErrUnavailable) ||
		errors.Is(err, platformidentitybinding.ErrPreconditionFailed) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return authentication.ErrNotFound
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) && databaseError.Code == "40001" &&
		databaseError.Message == platformIdentityBindingRevisionConflictMessage {
		return platformidentitybinding.ErrPreconditionFailed
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

type platformIdentityBindingTenantWire struct {
	ID      uuid.UUID                            `json:"id"`
	Slug    string                               `json:"slug"`
	Name    string                               `json:"name"`
	Status  platformidentitybinding.TenantStatus `json:"status"`
	Version int64                                `json:"version"`
}

type platformIdentityBindingWire struct {
	ID                   uuid.UUID                             `json:"id"`
	ProviderID           uuid.UUID                             `json:"providerId"`
	Tenant               platformIdentityBindingTenantWire     `json:"tenant"`
	Origin               string                                `json:"origin"`
	LoginKey             string                                `json:"loginKey"`
	ProfilePriority      int                                   `json:"profilePriority"`
	JITMode              platformidentitybinding.JITMode       `json:"jitMode"`
	NoMatchPolicy        platformidentitybinding.NoMatchPolicy `json:"noMatchPolicy"`
	Enabled              bool                                  `json:"enabled"`
	ActivationAvailable  bool                                  `json:"activationAvailable"`
	AuthRevision         int64                                 `json:"authRevision"`
	MappingRevision      int64                                 `json:"mappingRevision"`
	CurrentAccessEpochID *uuid.UUID                            `json:"currentAccessEpochId"`
	ArchivedAt           *time.Time                            `json:"archivedAt"`
	Version              int64                                 `json:"version"`
	CreatedAt            time.Time                             `json:"createdAt"`
	UpdatedAt            time.Time                             `json:"updatedAt"`
}

type platformIdentityBindingJSONKind uint8

const (
	platformIdentityBindingJSONString platformIdentityBindingJSONKind = iota
	platformIdentityBindingJSONBoolean
	platformIdentityBindingJSONInteger
	platformIdentityBindingJSONObject
)

type platformIdentityBindingJSONField struct {
	kind     platformIdentityBindingJSONKind
	nullable bool
}

func decodePlatformIdentityBinding(document []byte) (platformidentitybinding.Binding, error) {
	if err := validatePlatformIdentityBindingDocumentShape(document, map[string]platformIdentityBindingJSONField{
		"id":                   {kind: platformIdentityBindingJSONString},
		"providerId":           {kind: platformIdentityBindingJSONString},
		"tenant":               {kind: platformIdentityBindingJSONObject},
		"origin":               {kind: platformIdentityBindingJSONString},
		"loginKey":             {kind: platformIdentityBindingJSONString},
		"profilePriority":      {kind: platformIdentityBindingJSONInteger},
		"jitMode":              {kind: platformIdentityBindingJSONString},
		"noMatchPolicy":        {kind: platformIdentityBindingJSONString},
		"enabled":              {kind: platformIdentityBindingJSONBoolean},
		"activationAvailable":  {kind: platformIdentityBindingJSONBoolean},
		"authRevision":         {kind: platformIdentityBindingJSONInteger},
		"mappingRevision":      {kind: platformIdentityBindingJSONInteger},
		"currentAccessEpochId": {kind: platformIdentityBindingJSONString, nullable: true},
		"archivedAt":           {kind: platformIdentityBindingJSONString, nullable: true},
		"version":              {kind: platformIdentityBindingJSONInteger},
		"createdAt":            {kind: platformIdentityBindingJSONString},
		"updatedAt":            {kind: platformIdentityBindingJSONString},
	}); err != nil {
		return platformidentitybinding.Binding{}, err
	}
	wire, err := decodePlatformIdentityBindingDocument[platformIdentityBindingWire](document)
	if err != nil || wire.Origin != "platform" ||
		wire.Enabled != (wire.CurrentAccessEpochID != nil) ||
		wire.ActivationAvailable && (wire.Enabled || wire.ArchivedAt != nil) ||
		!platformIdentityBindingProjectionModesValid(wire.JITMode, wire.NoMatchPolicy) {
		return platformidentitybinding.Binding{}, authentication.ErrUnavailable
	}
	tenantDocument, err := platformIdentityBindingNestedDocument(document, "tenant")
	if err != nil || validatePlatformIdentityBindingDocumentShape(tenantDocument, map[string]platformIdentityBindingJSONField{
		"id": {kind: platformIdentityBindingJSONString}, "slug": {kind: platformIdentityBindingJSONString},
		"name": {kind: platformIdentityBindingJSONString}, "status": {kind: platformIdentityBindingJSONString},
		"version": {kind: platformIdentityBindingJSONInteger},
	}) != nil {
		return platformidentitybinding.Binding{}, authentication.ErrUnavailable
	}
	return platformidentitybinding.Binding{
		ID: wire.ID, ProviderID: wire.ProviderID,
		Tenant: platformidentitybinding.TenantSummary{
			ID: wire.Tenant.ID, Slug: wire.Tenant.Slug, Name: wire.Tenant.Name,
			Status: wire.Tenant.Status, Version: wire.Tenant.Version,
		},
		LoginKey: wire.LoginKey, ProfilePriority: wire.ProfilePriority,
		JITMode: wire.JITMode, NoMatchPolicy: wire.NoMatchPolicy,
		Enabled: wire.Enabled, ActivationAvailable: wire.ActivationAvailable,
		AuthRevision: wire.AuthRevision, MappingRevision: wire.MappingRevision,
		CurrentAccessEpochID: wire.CurrentAccessEpochID,
		ArchivedAt:           platformIdentityBindingOptionalUTC(wire.ArchivedAt), Version: wire.Version,
		CreatedAt: wire.CreatedAt.UTC(), UpdatedAt: wire.UpdatedAt.UTC(),
	}, nil
}

func platformIdentityBindingProjectionModesValid(
	jitMode platformidentitybinding.JITMode,
	noMatchPolicy platformidentitybinding.NoMatchPolicy,
) bool {
	return (jitMode == platformidentitybinding.JITModeDisabled ||
		jitMode == platformidentitybinding.JITModeCreate) &&
		(noMatchPolicy == platformidentitybinding.NoMatchPolicyDeny ||
			noMatchPolicy == platformidentitybinding.NoMatchPolicyProviderAccessOnly)
}

func decodePlatformIdentityBindingDocument[T any](document []byte) (T, error) {
	var value T
	trimmed := bytes.TrimSpace(document)
	if len(trimmed) < 2 || len(trimmed) > maximumPlatformIdentityBindingProjectionBytes || trimmed[0] != '{' {
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

func validatePlatformIdentityBindingDocumentShape(
	document []byte,
	required map[string]platformIdentityBindingJSONField,
) error {
	trimmed := bytes.TrimSpace(document)
	if len(trimmed) < 2 || len(trimmed) > maximumPlatformIdentityBindingProjectionBytes || trimmed[0] != '{' {
		return authentication.ErrUnavailable
	}
	var object map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	if err := decoder.Decode(&object); err != nil || object == nil || len(object) != len(required) {
		return authentication.ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return authentication.ErrUnavailable
	}
	for name, field := range required {
		raw, present := object[name]
		if !present || !validPlatformIdentityBindingJSONField(raw, field) {
			return authentication.ErrUnavailable
		}
	}
	return nil
}

func validPlatformIdentityBindingJSONField(
	raw json.RawMessage,
	field platformIdentityBindingJSONField,
) bool {
	trimmed := bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("null")) {
		return field.nullable
	}
	switch field.kind {
	case platformIdentityBindingJSONString:
		var value string
		return json.Unmarshal(trimmed, &value) == nil
	case platformIdentityBindingJSONBoolean:
		return bytes.Equal(trimmed, []byte("true")) || bytes.Equal(trimmed, []byte("false"))
	case platformIdentityBindingJSONInteger:
		var value json.Number
		if json.Unmarshal(trimmed, &value) != nil {
			return false
		}
		_, err := strconv.ParseInt(value.String(), 10, 64)
		return err == nil
	case platformIdentityBindingJSONObject:
		var value map[string]json.RawMessage
		return len(trimmed) >= 2 && trimmed[0] == '{' && json.Unmarshal(trimmed, &value) == nil && value != nil
	default:
		return false
	}
}

func platformIdentityBindingNestedDocument(document []byte, name string) ([]byte, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(document, &object); err != nil {
		return nil, authentication.ErrUnavailable
	}
	nested, present := object[name]
	if !present {
		return nil, authentication.ErrUnavailable
	}
	return nested, nil
}

func platformIdentityBindingOptionalUTC(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	normalized := value.UTC()
	return &normalized
}
