package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

const identityProviderPageLimit = int32(101)

type identityProviderQueries interface {
	SetTenantContext(context.Context, dbsql.SetTenantContextParams) (*dbsql.SetTenantContextRow, error)
	ListTenantLDAPProviders(context.Context, dbsql.ListTenantLDAPProvidersParams) ([]*dbsql.ListTenantLDAPProvidersRow, error)
	GetTenantLDAPProvider(context.Context, dbsql.GetTenantLDAPProviderParams) (*dbsql.GetTenantLDAPProviderRow, error)
	CreateTenantLDAPProvider(context.Context, dbsql.CreateTenantLDAPProviderParams) (*dbsql.CreateTenantLDAPProviderRow, error)
	UpdateTenantLDAPProvider(context.Context, dbsql.UpdateTenantLDAPProviderParams) (int32, error)
	ArchiveTenantLDAPProvider(context.Context, dbsql.ArchiveTenantLDAPProviderParams) (int32, error)
	GetTenantLDAPBindSecretID(context.Context, dbsql.GetTenantLDAPBindSecretIDParams) (pgtype.UUID, error)
	RotateTenantLDAPBindSecret(context.Context, dbsql.RotateTenantLDAPBindSecretParams) (int32, error)
	ClearTenantLDAPBindSecret(context.Context, dbsql.ClearTenantLDAPBindSecretParams) (int32, error)
	BeginTenantLDAPProviderTest(context.Context, dbsql.BeginTenantLDAPProviderTestParams) (*dbsql.BeginTenantLDAPProviderTestRow, error)
	CompleteTenantLDAPProviderTest(context.Context, dbsql.CompleteTenantLDAPProviderTestParams) (*dbsql.CompleteTenantLDAPProviderTestRow, error)
}

// IdentityProviderRepository keeps every tenant provider read and mutation on
// the bounded database ABI. Each call owns and commits its transaction before
// returning; in particular BeginTest never retains a transaction across LDAP
// DNS, TLS, or bind work.
type IdentityProviderRepository struct {
	begin                           transactionBeginner
	queryFactory                    func(databaseTransaction) identityProviderQueries
	administrationQueryFactory      func(databaseTransaction) ldapAdministrationQueries
	syncAdministrationQueryFactory  func(databaseTransaction) ldapSyncAdministrationQueries
	directoryInspectionQueryFactory func(databaseTransaction) ldapDirectoryInspectionQueries
	authority                       *AuthorizationRepository
}

func NewIdentityProviderRepository(pool *pgxpool.Pool) *IdentityProviderRepository {
	return &IdentityProviderRepository{
		begin: poolTransactionBeginner(pool),
		queryFactory: func(tx databaseTransaction) identityProviderQueries {
			return dbsql.New(tx)
		},
		administrationQueryFactory: func(tx databaseTransaction) ldapAdministrationQueries {
			return dbsql.New(tx)
		},
		syncAdministrationQueryFactory: func(tx databaseTransaction) ldapSyncAdministrationQueries {
			return dbsql.New(tx)
		},
		directoryInspectionQueryFactory: func(tx databaseTransaction) ldapDirectoryInspectionQueries {
			return dbsql.New(tx)
		},
		authority: NewAuthorizationRepository(pool),
	}
}

var _ identityprovider.Repository = (*IdentityProviderRepository)(nil)

func (r *IdentityProviderRepository) ResolveHumanAuthority(
	ctx context.Context,
	params authorization.ResolveAuthorityParams,
) (authorization.TenantAuthority, error) {
	if r == nil || r.authority == nil {
		return authorization.TenantAuthority{}, fmt.Errorf("%w: authorization repository is required", identityprovider.ErrUnavailable)
	}
	return r.authority.ResolveAuthority(ctx, params)
}

func (r *IdentityProviderRepository) List(
	ctx context.Context,
	params identityprovider.ListParams,
) ([]identityprovider.ProviderSummary, error) {
	if !validIdentityProviderHuman(params.HumanParams) || params.Limit < 1 || params.Limit > identityProviderPageLimit ||
		params.After != nil && !identityProviderUUIDv7(*params.After) {
		return nil, identityprovider.ErrInvalidInput
	}
	return withIdentityProviderTransaction(ctx, r, params.HumanParams,
		func(queries identityProviderQueries) ([]identityprovider.ProviderSummary, error) {
			rows, err := queries.ListTenantLDAPProviders(ctx, dbsql.ListTenantLDAPProvidersParams{
				AfterProviderID: optionalDatabaseUUID(params.After), IncludeArchived: params.IncludeArchived,
				PageSize: params.Limit,
			})
			if err != nil {
				return nil, mapIdentityProviderDatabaseError(err)
			}
			if len(rows) > int(params.Limit) {
				return nil, invalidIdentityProviderProjection("oversized provider page")
			}
			result := make([]identityprovider.ProviderSummary, 0, len(rows))
			var previous uuid.UUID
			if params.After != nil {
				previous = *params.After
			}
			for _, row := range rows {
				provider, mapErr := mapListedIdentityProvider(params.TenantID, row)
				if mapErr != nil || previous != uuid.Nil && compareUUID(provider.ID, previous) <= 0 {
					if mapErr != nil {
						return nil, mapErr
					}
					return nil, invalidIdentityProviderProjection("non-monotonic provider page")
				}
				if !params.IncludeArchived && provider.ArchivedAt != nil {
					return nil, invalidIdentityProviderProjection("archived provider in live-only page")
				}
				previous = provider.ID
				result = append(result, provider)
			}
			return result, nil
		},
	)
}

func (r *IdentityProviderRepository) Get(
	ctx context.Context,
	params identityprovider.GetParams,
) (identityprovider.Provider, error) {
	if !validIdentityProviderHuman(params.HumanParams) || !identityProviderUUIDv7(params.ProviderID) {
		return identityprovider.Provider{}, identityprovider.ErrInvalidInput
	}
	return withIdentityProviderTransaction(ctx, r, params.HumanParams,
		func(queries identityProviderQueries) (identityprovider.Provider, error) {
			return getIdentityProvider(ctx, queries, params.TenantID, params.ProviderID)
		},
	)
}

func (r *IdentityProviderRepository) Create(
	ctx context.Context,
	params identityprovider.CreateParams,
) (identityprovider.CreateResult, error) {
	configuration, endpoints, err := identityProviderDocuments(params.Configuration, params.Endpoints)
	if err != nil || !validIdentityProviderMutation(params.HumanParams, params.Audit, params.OccurredAt, params.ProviderID) ||
		allZero(params.IdempotencyKeyDigest[:]) {
		return identityprovider.CreateResult{}, identityprovider.ErrInvalidInput
	}
	audit, err := identityProviderAuditArgumentsFor(params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod)
	if err != nil {
		return identityprovider.CreateResult{}, err
	}
	return withIdentityProviderTransaction(ctx, r, params.HumanParams,
		func(queries identityProviderQueries) (identityprovider.CreateResult, error) {
			row, queryErr := queries.CreateTenantLDAPProvider(ctx, dbsql.CreateTenantLDAPProviderParams{
				ProviderID:           toDatabaseUUID(params.ProviderID),
				IdempotencyKeyDigest: append([]byte(nil), params.IdempotencyKeyDigest[:]...),
				ProviderKey:          params.Key, DisplayName: params.DisplayName, Description: params.Description,
				Configuration: configuration, Endpoints: endpoints,
				RequestID: audit.requestID, CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
				UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return identityprovider.CreateResult{}, mapIdentityProviderDatabaseError(queryErr)
			}
			if row == nil || row.ResultVersion < 1 {
				return identityprovider.CreateResult{}, invalidIdentityProviderProjection("invalid create result")
			}
			providerID, mapErr := domainUUID(row.ProviderID)
			if mapErr != nil || !identityProviderUUIDv7(providerID) {
				return identityprovider.CreateResult{}, invalidIdentityProviderProjection("invalid created provider ID")
			}
			return identityprovider.CreateResult{
				ProviderID: providerID, Version: int64(row.ResultVersion), Replayed: row.Replayed,
			}, nil
		},
	)
}

func (r *IdentityProviderRepository) Update(
	ctx context.Context,
	params identityprovider.UpdateParams,
) (int64, error) {
	version, err := identityProviderDatabaseVersion(params.ExpectedVersion)
	configuration, endpoints, documentErr := identityProviderDocuments(params.Configuration, params.Endpoints)
	if err != nil || documentErr != nil ||
		!validIdentityProviderMutation(params.HumanParams, params.Audit, params.OccurredAt, params.ProviderID) {
		return 0, identityprovider.ErrInvalidInput
	}
	audit, err := identityProviderAuditArgumentsFor(params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod)
	if err != nil {
		return 0, err
	}
	return withIdentityProviderTransaction(ctx, r, params.HumanParams,
		func(queries identityProviderQueries) (int64, error) {
			updated, queryErr := queries.UpdateTenantLDAPProvider(ctx, dbsql.UpdateTenantLDAPProviderParams{
				ProviderID: toDatabaseUUID(params.ProviderID), ExpectedVersion: version,
				ProviderKey: params.Key, DisplayName: params.DisplayName, Description: params.Description,
				Enabled: params.Enabled, Configuration: configuration, Endpoints: endpoints,
				RequestID: audit.requestID, CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
				UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return 0, mapIdentityProviderDatabaseError(queryErr)
			}
			return int64(updated), nil
		},
	)
}

func (r *IdentityProviderRepository) Archive(
	ctx context.Context,
	params identityprovider.ArchiveParams,
) (int64, error) {
	version, err := identityProviderDatabaseVersion(params.ExpectedVersion)
	if err != nil || !validIdentityProviderMutation(params.HumanParams, params.Audit, params.OccurredAt, params.ProviderID) {
		return 0, identityprovider.ErrInvalidInput
	}
	audit, err := identityProviderAuditArgumentsFor(params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod)
	if err != nil {
		return 0, err
	}
	return withIdentityProviderTransaction(ctx, r, params.HumanParams,
		func(queries identityProviderQueries) (int64, error) {
			updated, queryErr := queries.ArchiveTenantLDAPProvider(ctx, dbsql.ArchiveTenantLDAPProviderParams{
				ProviderID: toDatabaseUUID(params.ProviderID), ExpectedVersion: version, Reason: params.Reason,
				RequestID: audit.requestID, CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
				UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return 0, mapIdentityProviderDatabaseError(queryErr)
			}
			return int64(updated), nil
		},
	)
}

func (r *IdentityProviderRepository) GetBindSecretID(
	ctx context.Context,
	params identityprovider.GetBindSecretIDParams,
) (*uuid.UUID, error) {
	if !validIdentityProviderHuman(params.HumanParams) || !identityProviderUUIDv7(params.ProviderID) {
		return nil, identityprovider.ErrInvalidInput
	}
	return withIdentityProviderTransaction(ctx, r, params.HumanParams,
		func(queries identityProviderQueries) (*uuid.UUID, error) {
			value, queryErr := queries.GetTenantLDAPBindSecretID(ctx, dbsql.GetTenantLDAPBindSecretIDParams{
				ProviderID: toDatabaseUUID(params.ProviderID),
			})
			if queryErr != nil {
				return nil, mapIdentityProviderDatabaseError(queryErr)
			}
			if !value.Valid {
				return nil, nil
			}
			identifier, mapErr := domainUUID(value)
			if mapErr != nil || !identityProviderUUIDv7(identifier) {
				return nil, invalidIdentityProviderProjection("invalid bind-secret ID")
			}
			return &identifier, nil
		},
	)
}

func (r *IdentityProviderRepository) RotateBindSecret(
	ctx context.Context,
	params identityprovider.RotateBindSecretParams,
) (int64, error) {
	version, err := identityProviderDatabaseVersion(params.ExpectedVersion)
	if err != nil || !validIdentityProviderMutation(params.HumanParams, params.Audit, params.OccurredAt, params.ProviderID) ||
		!identityProviderUUIDv7(params.Secret.SecretID) || params.Secret.Envelope.KeyVersion < 1 ||
		len(params.Secret.Envelope.Ciphertext) < 17 || len(params.Secret.Envelope.Ciphertext) > 8192 {
		return 0, identityprovider.ErrInvalidInput
	}
	audit, err := identityProviderAuditArgumentsFor(params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod)
	if err != nil {
		return 0, err
	}
	ciphertext := append([]byte(nil), params.Secret.Envelope.Ciphertext...)
	nonce := append([]byte(nil), params.Secret.Envelope.Nonce[:]...)
	defer clear(ciphertext)
	defer clear(nonce)
	return withIdentityProviderTransaction(ctx, r, params.HumanParams,
		func(queries identityProviderQueries) (int64, error) {
			updated, queryErr := queries.RotateTenantLDAPBindSecret(ctx, dbsql.RotateTenantLDAPBindSecretParams{
				ProviderID: toDatabaseUUID(params.ProviderID), ExpectedVersion: version,
				SecretID:         toDatabaseUUID(params.Secret.SecretID),
				SecretCiphertext: ciphertext,
				SecretNonce:      nonce,
				KeyVersion:       int32(params.Secret.Envelope.KeyVersion),
				RequestID:        audit.requestID, CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
				UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return 0, mapIdentityProviderDatabaseError(queryErr)
			}
			return int64(updated), nil
		},
	)
}

func (r *IdentityProviderRepository) ClearBindSecret(
	ctx context.Context,
	params identityprovider.ClearBindSecretParams,
) (int64, error) {
	version, err := identityProviderDatabaseVersion(params.ExpectedVersion)
	if err != nil || !validIdentityProviderMutation(params.HumanParams, params.Audit, params.OccurredAt, params.ProviderID) {
		return 0, identityprovider.ErrInvalidInput
	}
	audit, err := identityProviderAuditArgumentsFor(params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod)
	if err != nil {
		return 0, err
	}
	return withIdentityProviderTransaction(ctx, r, params.HumanParams,
		func(queries identityProviderQueries) (int64, error) {
			updated, queryErr := queries.ClearTenantLDAPBindSecret(ctx, dbsql.ClearTenantLDAPBindSecretParams{
				ProviderID: toDatabaseUUID(params.ProviderID), ExpectedVersion: version, Reason: params.Reason,
				RequestID: audit.requestID, CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
				UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return 0, mapIdentityProviderDatabaseError(queryErr)
			}
			return int64(updated), nil
		},
	)
}

func (r *IdentityProviderRepository) BeginTest(
	ctx context.Context,
	params identityprovider.BeginTestParams,
) (identityprovider.TestSnapshot, error) {
	if !validIdentityProviderMutation(params.HumanParams, params.Audit, params.OccurredAt, params.ProviderID) ||
		!identityProviderUUIDv7(params.TestRunID) ||
		(params.Kind != identityprovider.TestKindConnection && params.Kind != identityprovider.TestKindBind) ||
		params.Audit.RequestID == uuid.Nil || params.Audit.CorrelationID == uuid.Nil {
		return identityprovider.TestSnapshot{}, identityprovider.ErrInvalidInput
	}
	audit, err := identityProviderAuditArgumentsFor(params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod)
	if err != nil {
		return identityprovider.TestSnapshot{}, err
	}
	return withIdentityProviderTransaction(ctx, r, params.HumanParams,
		func(queries identityProviderQueries) (identityprovider.TestSnapshot, error) {
			row, queryErr := queries.BeginTenantLDAPProviderTest(ctx, dbsql.BeginTenantLDAPProviderTestParams{
				TestRunID: toDatabaseUUID(params.TestRunID), ProviderID: toDatabaseUUID(params.ProviderID),
				TestKind: string(params.Kind), RequestID: audit.requestID, CorrelationID: audit.correlationID,
				IpAddress: audit.remoteAddress, UserAgent: audit.userAgent,
				AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return identityprovider.TestSnapshot{}, mapIdentityProviderDatabaseError(queryErr)
			}
			return mapIdentityProviderTestSnapshot(row, params.Kind)
		},
	)
}

func (r *IdentityProviderRepository) CompleteTest(
	ctx context.Context,
	params identityprovider.CompleteTestParams,
) (identityprovider.TestResult, error) {
	if !validIdentityProviderHuman(params.HumanParams) || !validIdentityProviderAudit(params.Audit) ||
		!validIdentityProviderOccurrence(params.OccurredAt) || !identityProviderUUIDv7(params.TestRunID) ||
		params.Audit.RequestID == uuid.Nil || params.Audit.CorrelationID == uuid.Nil ||
		params.Duration < 0 || params.Duration > 120*time.Second ||
		params.Duration%time.Millisecond != 0 {
		return identityprovider.TestResult{}, identityprovider.ErrInvalidInput
	}
	audit, err := identityProviderAuditArgumentsFor(params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod)
	if err != nil {
		return identityprovider.TestResult{}, err
	}
	var endpointPriority *int32
	if params.EndpointPriority != nil {
		if *params.EndpointPriority < 1 || *params.EndpointPriority > 8 {
			return identityprovider.TestResult{}, identityprovider.ErrInvalidInput
		}
		value := int32(*params.EndpointPriority)
		endpointPriority = &value
	}
	return withIdentityProviderTransaction(ctx, r, params.HumanParams,
		func(queries identityProviderQueries) (identityprovider.TestResult, error) {
			row, queryErr := queries.CompleteTenantLDAPProviderTest(ctx, dbsql.CompleteTenantLDAPProviderTestParams{
				TestRunID: toDatabaseUUID(params.TestRunID), ReportedOutcome: string(params.ReportedOutcome),
				ReportedCategory: string(params.ReportedCategory), EndpointPriority: endpointPriority,
				DurationMs: int32(params.Duration / time.Millisecond), RequestID: audit.requestID,
				CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
				UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return identityprovider.TestResult{}, mapIdentityProviderDatabaseError(queryErr)
			}
			return mapIdentityProviderTestResult(row)
		},
	)
}

func getIdentityProvider(
	ctx context.Context,
	queries identityProviderQueries,
	tenantID, providerID uuid.UUID,
) (identityprovider.Provider, error) {
	row, err := queries.GetTenantLDAPProvider(ctx, dbsql.GetTenantLDAPProviderParams{
		ProviderID: toDatabaseUUID(providerID),
	})
	if err != nil {
		return identityprovider.Provider{}, mapIdentityProviderDatabaseError(err)
	}
	provider, err := mapGotIdentityProvider(tenantID, row)
	if err != nil {
		return identityprovider.Provider{}, err
	}
	if provider.ID != providerID {
		return identityprovider.Provider{}, invalidIdentityProviderProjection("unexpected provider ID")
	}
	return provider, nil
}

func withIdentityProviderTransaction[T any](
	ctx context.Context,
	repository *IdentityProviderRepository,
	human identityprovider.HumanParams,
	work func(identityProviderQueries) (T, error),
) (T, error) {
	var zero T
	if !validIdentityProviderHuman(human) {
		return zero, identityprovider.ErrForbidden
	}
	if repository == nil || repository.begin == nil || repository.queryFactory == nil || work == nil {
		return zero, fmt.Errorf("%w: identity-provider repository dependencies are required", identityprovider.ErrUnavailable)
	}
	result, err := withinTransaction(ctx, repository.begin, func(tx databaseTransaction) (T, error) {
		queries := repository.queryFactory(tx)
		if queries == nil {
			return zero, invalidIdentityProviderProjection("identity-provider query surface is unavailable")
		}
		installed, installErr := queries.SetTenantContext(ctx, dbsql.SetTenantContextParams{
			TenantID: toDatabaseUUID(human.TenantID), UserID: toDatabaseUUID(human.Actor.UserID),
		})
		if installErr != nil {
			return zero, mapIdentityProviderDatabaseError(installErr)
		}
		if installed == nil || installed.TenantID != human.TenantID.String() || installed.UserID != human.Actor.UserID.String() {
			return zero, invalidIdentityProviderProjection("database installed an unexpected human context")
		}
		return work(queries)
	})
	if err != nil {
		return zero, mapIdentityProviderDatabaseError(err)
	}
	return result, nil
}

type identityProviderAuditArguments struct {
	requestID            pgtype.UUID
	correlationID        pgtype.UUID
	remoteAddress        netip.Addr
	userAgent            string
	authenticationMethod string
}

func identityProviderAuditArgumentsFor(
	audit authorization.AuditContext,
	occurredAt time.Time,
	authenticationMethod string,
) (identityProviderAuditArguments, error) {
	if !validIdentityProviderAudit(audit) || !validIdentityProviderOccurrence(occurredAt) ||
		audit.RequestID == uuid.Nil || audit.CorrelationID == uuid.Nil ||
		!identityProviderText(authenticationMethod, 1, 64) {
		return identityProviderAuditArguments{}, identityprovider.ErrInvalidInput
	}
	remote := audit.RemoteAddress
	if remote.IsValid() {
		remote = remote.Unmap()
	}
	return identityProviderAuditArguments{
		requestID: toDatabaseUUID(audit.RequestID), correlationID: toDatabaseUUID(audit.CorrelationID),
		remoteAddress: remote, userAgent: audit.UserAgent, authenticationMethod: authenticationMethod,
	}, nil
}

func identityProviderDocuments(
	configuration identityprovider.Configuration,
	endpoints []identityprovider.Endpoint,
) ([]byte, []byte, error) {
	configurationDocument, err := json.Marshal(configuration)
	if err != nil {
		return nil, nil, identityprovider.ErrInvalidInput
	}
	endpointDocument, err := json.Marshal(endpoints)
	if err != nil {
		return nil, nil, identityprovider.ErrInvalidInput
	}
	return configurationDocument, endpointDocument, nil
}

func decodeIdentityProviderJSON[T any](source []byte) (T, error) {
	var result T
	decoder := json.NewDecoder(strings.NewReader(string(source)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return result, invalidIdentityProviderProjection("malformed identity-provider JSON projection")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return result, invalidIdentityProviderProjection("identity-provider JSON projection has trailing data")
	}
	return result, nil
}

func validIdentityProviderHuman(params identityprovider.HumanParams) bool {
	return identityProviderUUIDv7(params.TenantID) && identityProviderUUIDv7(params.MembershipID) &&
		identityProviderUUIDv7(params.Actor.UserID) && identityProviderUUIDv7(params.Actor.SessionID) &&
		params.Actor.ActiveTenantID == params.TenantID && identityProviderText(params.Actor.AuthenticationMethod, 1, 64)
}

func validIdentityProviderMutation(
	human identityprovider.HumanParams,
	audit authorization.AuditContext,
	occurredAt time.Time,
	providerID uuid.UUID,
) bool {
	return validIdentityProviderHuman(human) && identityProviderUUIDv7(providerID) &&
		validIdentityProviderAudit(audit) && audit.RequestID != uuid.Nil && audit.CorrelationID != uuid.Nil &&
		validIdentityProviderOccurrence(occurredAt)
}

func validIdentityProviderAudit(audit authorization.AuditContext) bool {
	return (audit.RequestID == uuid.Nil || audit.RequestID.Variant() == uuid.RFC4122) &&
		(audit.CorrelationID == uuid.Nil || audit.CorrelationID.Variant() == uuid.RFC4122) &&
		(!audit.RemoteAddress.IsValid() || audit.RemoteAddress.Zone() == "" && !audit.RemoteAddress.Is4In6()) &&
		identityProviderText(audit.UserAgent, 0, 1024)
}

func validIdentityProviderOccurrence(value time.Time) bool {
	if value.IsZero() || value.Nanosecond()%int(time.Microsecond) != 0 {
		return false
	}
	_, err := value.UTC().MarshalJSON()
	return err == nil
}

func identityProviderText(value string, minimum, maximum int) bool {
	if strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	length := len([]rune(value))
	return length >= minimum && length <= maximum
}

func identityProviderDatabaseVersion(value int64) (int32, error) {
	if value < 1 || value > math.MaxInt32 {
		return 0, identityprovider.ErrInvalidInput
	}
	return int32(value), nil
}

func identityProviderUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func invalidIdentityProviderProjection(reason string) error {
	return fmt.Errorf("%w: %s", identityprovider.ErrUnavailable, reason)
}

func mapIdentityProviderDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, identityprovider.ErrInvalidInput) || errors.Is(err, identityprovider.ErrForbidden) ||
		errors.Is(err, identityprovider.ErrNotFound) || errors.Is(err, identityprovider.ErrConflict) ||
		errors.Is(err, identityprovider.ErrPreconditionRequired) || errors.Is(err, identityprovider.ErrPreconditionFailed) ||
		errors.Is(err, identityprovider.ErrRateLimited) || errors.Is(err, identityprovider.ErrUnavailable) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return identityprovider.ErrNotFound
	}
	switch postgresCode(err) {
	case "22023", "22P02":
		return identityprovider.ErrInvalidInput
	case "42501":
		return identityprovider.ErrForbidden
	case "P0002":
		return identityprovider.ErrNotFound
	case "40001":
		return identityprovider.ErrPreconditionFailed
	case "53300":
		return identityprovider.ErrRateLimited
	case "0A000", "23503", "23505", "23514", "55000":
		return identityprovider.ErrConflict
	default:
		return err
	}
}
