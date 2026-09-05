package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

const (
	savedViewDatabaseTimeout = 15 * time.Second

	savedViewResolveSpecABIQuery = `
		SELECT response
		FROM app.resolve_ticket_saved_view_spec_v1($1::jsonb)`
	savedViewListABIQuery = `
		SELECT response
		FROM app.list_ticket_saved_views_v1($1::jsonb)`
	savedViewGetABIQuery = `
		SELECT response
		FROM app.get_ticket_saved_view_v1($1::jsonb)`
	savedViewReplayABIQuery = `
		SELECT response
		FROM app.lookup_ticket_saved_view_replay_v1($1::jsonb)`
	savedViewCommitABIQuery = `
		SELECT response
		FROM app.commit_ticket_saved_view_v1($1::jsonb)`
)

var _ application.SavedViewRepository = (*TicketingRepository)(nil)

func (repository *TicketingRepository) ResolveSavedViewAccess(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	capability application.SavedViewCapability,
) (application.SavedViewAccess, error) {
	if err := savedViewContextError(ctx); err != nil {
		return application.SavedViewAccess{}, err
	}
	return withinSavedViewTransaction(
		ctx, repository, actor, tenantID, phase4ReadOptions(),
		func(ctx context.Context, tx databaseTransaction) (application.SavedViewAccess, error) {
			return resolveSavedViewAccessInTransaction(ctx, tx, actor, tenantID, kind, capability)
		},
	)
}

func (repository *TicketingRepository) ResolveSavedViewSpec(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	input application.SavedViewSpecInput,
	claimed application.SavedViewAccess,
) (kernel.SavedViewSpec, error) {
	if err := savedViewContextError(ctx); err != nil {
		return kernel.SavedViewSpec{}, err
	}
	validated, err := application.NormalizeSavedViewSpecInput(input)
	if err != nil {
		return kernel.SavedViewSpec{}, err
	}
	request, err := newSavedViewResolveSpecRequestFromValidated(
		tenantID, actor.UserID, claimed.Membership(), kind, validated,
	)
	if err != nil {
		return kernel.SavedViewSpec{}, err
	}
	payload, err := marshalSavedViewWire(request, maximumSavedViewResolveRequestBytes)
	if err != nil {
		return kernel.SavedViewSpec{}, err
	}
	return withinSavedViewTransaction(
		ctx, repository, actor, tenantID, phase4ReadOptions(),
		func(ctx context.Context, tx databaseTransaction) (kernel.SavedViewSpec, error) {
			if err := recheckSavedViewAccess(
				ctx, tx, actor, tenantID, kind, application.SavedViewCapabilityManage, claimed,
			); err != nil {
				return kernel.SavedViewSpec{}, err
			}
			var response []byte
			if err := tx.QueryRow(ctx, savedViewResolveSpecABIQuery, payload).Scan(&response); err != nil {
				return kernel.SavedViewSpec{}, mapSavedViewRequiredRowError(err)
			}
			return restoreSavedViewResolvedSpec(response, tenantID, kind, validated)
		},
	)
}

func (repository *TicketingRepository) ReserveSavedViewID(
	ctx context.Context,
	tenantID uuid.UUID,
) (kernel.EntityID, error) {
	if err := savedViewContextError(ctx); err != nil {
		return kernel.EntityID{}, err
	}
	if repository == nil || repository.newID == nil || !authorizationUUIDv7(tenantID) {
		return kernel.EntityID{}, application.ErrConflict
	}
	identifier, err := repository.newID()
	if err != nil || !authorizationUUIDv7(identifier) {
		return kernel.EntityID{}, application.ErrConflict
	}
	return ticketEntityID(identifier)
}

func (repository *TicketingRepository) ListSavedViews(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	input application.SavedViewListInput,
	claimed application.SavedViewAccess,
) (application.SavedViewPage, error) {
	if err := savedViewContextError(ctx); err != nil {
		return application.SavedViewPage{}, err
	}
	after, err := decodeSavedViewCursor(input.After)
	if err != nil || input.Limit < 1 || input.Limit > application.MaximumPageSize {
		return application.SavedViewPage{}, application.ErrInvalidInput
	}
	request := savedViewListRequestV1{
		SchemaVersion: 1, TenantID: tenantID.String(), ActorID: actor.UserID.String(),
		OwnerMembershipID: claimed.Membership().String(), AggregateKind: kind.String(),
		AfterID: savedViewOptionalUUID(after), Limit: input.Limit,
		IncludeArchived: input.IncludeArchived,
	}
	payload, err := marshalSavedViewWire(request, maximumSavedViewListRequestBytes)
	if err != nil {
		return application.SavedViewPage{}, err
	}
	return withinSavedViewTransaction(
		ctx, repository, actor, tenantID, phase4ReadOptions(),
		func(ctx context.Context, tx databaseTransaction) (application.SavedViewPage, error) {
			if err := recheckSavedViewAccess(
				ctx, tx, actor, tenantID, kind, application.SavedViewCapabilityRead, claimed,
			); err != nil {
				return application.SavedViewPage{}, err
			}
			var response []byte
			if err := tx.QueryRow(ctx, savedViewListABIQuery, payload).Scan(&response); err != nil {
				return application.SavedViewPage{}, mapSavedViewRequiredRowError(err)
			}
			return restoreSavedViewPage(
				response, tenantID, claimed.Membership(), kind, after, input.Limit, input.IncludeArchived,
			)
		},
	)
}

func (repository *TicketingRepository) GetSavedView(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	viewID uuid.UUID,
	claimed application.SavedViewAccess,
) (application.SavedViewRecord, error) {
	if err := savedViewContextError(ctx); err != nil {
		return application.SavedViewRecord{}, err
	}
	if !authorizationUUIDv7(viewID) {
		return application.SavedViewRecord{}, application.ErrInvalidInput
	}
	request := savedViewGetRequestV1{
		SchemaVersion: 1, TenantID: tenantID.String(), ActorID: actor.UserID.String(),
		OwnerMembershipID: claimed.Membership().String(), AggregateKind: claimed.Kind().String(),
		ViewID: viewID.String(),
	}
	payload, err := marshalSavedViewWire(request, maximumSavedViewGetRequestBytes)
	if err != nil {
		return application.SavedViewRecord{}, err
	}
	return withinSavedViewTransaction(
		ctx, repository, actor, tenantID, phase4ReadOptions(),
		func(ctx context.Context, tx databaseTransaction) (application.SavedViewRecord, error) {
			if err := recheckSavedViewAccess(
				ctx, tx, actor, tenantID, claimed.Kind(), application.SavedViewCapabilityRead, claimed,
			); err != nil {
				return application.SavedViewRecord{}, err
			}
			var response []byte
			if err := tx.QueryRow(ctx, savedViewGetABIQuery, payload).Scan(&response); err != nil {
				return application.SavedViewRecord{}, mapSavedViewDatabaseError(err)
			}
			record, err := restoreSavedViewGetResponse(
				response, tenantID, claimed.Membership(), claimed.Kind(),
			)
			if err != nil {
				return application.SavedViewRecord{}, err
			}
			if savedViewUUID(record.View.ID()) != viewID {
				return application.SavedViewRecord{}, application.ErrNotFound
			}
			return record, nil
		},
	)
}

func (repository *TicketingRepository) LookupSavedViewReplay(
	ctx context.Context,
	query application.SavedViewReplayQuery,
) (application.SavedViewMutationResult, bool, error) {
	if err := savedViewContextError(ctx); err != nil {
		return application.SavedViewMutationResult{}, false, err
	}
	request, err := newSavedViewReplayRequest(query)
	if err != nil {
		return application.SavedViewMutationResult{}, false, err
	}
	payload, err := marshalSavedViewWire(request, maximumSavedViewReplayRequestBytes)
	if err != nil {
		return application.SavedViewMutationResult{}, false, err
	}
	actor := application.Actor{UserID: query.ActorID, ActiveTenantID: query.TenantID}
	type replayResult struct {
		result application.SavedViewMutationResult
		found  bool
	}
	resolved, err := withinSavedViewTransaction(
		ctx, repository, actor, query.TenantID, phase4ReadOptions(),
		func(ctx context.Context, tx databaseTransaction) (replayResult, error) {
			var response []byte
			err := tx.QueryRow(ctx, savedViewReplayABIQuery, payload).Scan(&response)
			if errors.Is(err, pgx.ErrNoRows) {
				return replayResult{}, nil
			}
			if err != nil {
				return replayResult{}, mapSavedViewDatabaseError(err)
			}
			result, fingerprint, err := restoreSavedViewReplayResponse(
				response, query.TenantID, query.ActorID, query.OwnerMembershipID,
				query.Kind, query.Action,
			)
			if err != nil {
				return replayResult{}, err
			}
			if subtle.ConstantTimeCompare(fingerprint[:], query.Fingerprint[:]) != 1 {
				return replayResult{}, application.ErrConflict
			}
			result.Replayed = true
			return replayResult{result: result, found: true}, nil
		},
	)
	if err != nil {
		return application.SavedViewMutationResult{}, false, err
	}
	return resolved.result, resolved.found, nil
}

func (repository *TicketingRepository) CommitSavedView(
	ctx context.Context,
	write application.SavedViewWrite,
) (application.SavedViewMutationResult, error) {
	if err := savedViewContextError(ctx); err != nil {
		return application.SavedViewMutationResult{}, err
	}
	request, next, err := newSavedViewCommitRequest(repository, write)
	if err != nil {
		return application.SavedViewMutationResult{}, err
	}
	payload, err := marshalSavedViewWire(request, maximumSavedViewCommitRequestBytes)
	if err != nil {
		return application.SavedViewMutationResult{}, err
	}
	tenantID := savedViewUUID(next.Tenant())
	// READ COMMITTED is part of the command ABI. The database function locks
	// the actor/owner/action/key lineage before reading its immutable ledger, so
	// an exact create racing another generated ID observes the winner in a fresh
	// statement snapshot. The function also re-resolves membership, ticket-read
	// authority, and all non-archive dynamic pins before CAS and journaling.
	return withinSavedViewTransaction(
		ctx, repository, write.Actor, tenantID,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
		func(ctx context.Context, tx databaseTransaction) (application.SavedViewMutationResult, error) {
			access, err := resolveSavedViewAccessInTransaction(
				ctx, tx, write.Actor, tenantID, next.Kind(), application.SavedViewCapabilityManage,
			)
			if err != nil {
				return application.SavedViewMutationResult{}, err
			}
			if !access.Allowed() || access.Membership() != write.OwnerMembershipID {
				return application.SavedViewMutationResult{}, application.ErrForbidden
			}
			var response []byte
			if err := tx.QueryRow(ctx, savedViewCommitABIQuery, payload).Scan(&response); err != nil {
				return application.SavedViewMutationResult{}, mapSavedViewRequiredRowError(err)
			}
			return restoreSavedViewCommitResponse(
				response, tenantID, write.Actor.UserID, write.OwnerMembershipID,
				write.Command.Action, write.Command.Fingerprint, next,
			)
		},
	)
}

func resolveSavedViewAccessInTransaction(
	ctx context.Context,
	tx databaseTransaction,
	actor application.Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	capability application.SavedViewCapability,
) (application.SavedViewAccess, error) {
	if !validSavedViewRepositoryKind(kind) || !validSavedViewRepositoryCapability(capability) {
		return application.SavedViewAccess{}, application.ErrForbidden
	}
	authority, err := phase4Authority(ctx, tx, savedViewAuthorizationActor(actor), tenantID)
	if err != nil {
		return application.SavedViewAccess{}, mapSavedViewDatabaseError(err)
	}
	if authority.TenantID != tenantID || !authorizationUUIDv7(authority.MembershipID) ||
		!validPhase4Authority(authority, authority.MembershipID) || authority.Principal.ID != actor.UserID {
		return application.SavedViewAccess{}, application.ErrForbidden
	}
	allowed := savedViewHasTicketRead(authority, kind)
	access, err := application.NewSavedViewAccess(
		tenantID, actor.UserID, authority.MembershipID, kind, capability,
		kernel.PrincipalOperator, allowed,
	)
	if err != nil {
		return application.SavedViewAccess{}, application.ErrUnavailable
	}
	return access, nil
}

func recheckSavedViewAccess(
	ctx context.Context,
	tx databaseTransaction,
	actor application.Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	capability application.SavedViewCapability,
	claimed application.SavedViewAccess,
) error {
	current, err := resolveSavedViewAccessInTransaction(ctx, tx, actor, tenantID, kind, capability)
	if err != nil {
		return err
	}
	if current.Tenant() != claimed.Tenant() || current.Actor() != claimed.Actor() ||
		current.Membership() != claimed.Membership() || current.Kind() != claimed.Kind() ||
		current.Capability() != claimed.Capability() || current.Principal() != claimed.Principal() ||
		!current.Allowed() || !claimed.Allowed() {
		return application.ErrForbidden
	}
	return nil
}

func savedViewAuthorizationActor(actor application.Actor) authorization.Actor {
	return authorization.Actor{
		UserID: actor.UserID, SessionID: actor.SessionID, ActiveTenantID: actor.ActiveTenantID,
		AuthenticationMethod: actor.AuthenticationMethod,
	}
}

func savedViewHasTicketRead(
	authority authorization.TenantAuthority,
	kind kernel.AggregateKind,
) bool {
	var permission string
	switch kind {
	case kernel.AggregateAlert:
		permission = string(application.CapabilityAlertRead)
	case kernel.AggregateCase:
		permission = string(application.CapabilityCaseRead)
	default:
		return false
	}
	return slices.ContainsFunc(authority.Permissions, func(candidate authorization.ScopedPermission) bool {
		if string(candidate.Permission) != permission {
			return false
		}
		switch candidate.Scope {
		case authorization.ScopeOwn, authorization.ScopeAssigned,
			authorization.ScopeOperatorTeam, authorization.ScopeTenant:
			return true
		default:
			return false
		}
	})
}

func withinSavedViewTransaction[T any](
	ctx context.Context,
	repository *TicketingRepository,
	actor application.Actor,
	tenantID uuid.UUID,
	options pgx.TxOptions,
	work func(context.Context, databaseTransaction) (T, error),
) (T, error) {
	var zero T
	if ctx == nil || repository == nil || repository.begin == nil || work == nil ||
		!authorizationUUIDv7(actor.UserID) || !authorizationUUIDv7(tenantID) {
		return zero, application.ErrForbidden
	}
	operationContext, cancel := context.WithTimeout(ctx, savedViewDatabaseTimeout)
	defer cancel()
	if err := operationContext.Err(); err != nil {
		return zero, err
	}
	result, err := withinTransactionWithOptions(
		operationContext, repository.begin, options,
		func(tx databaseTransaction) (T, error) {
			installed, err := dbsql.New(tx).SetTenantContext(
				operationContext,
				dbsql.SetTenantContextParams{
					TenantID: toDatabaseUUID(tenantID), UserID: toDatabaseUUID(actor.UserID),
				},
			)
			if err != nil {
				return zero, mapSavedViewDatabaseError(err)
			}
			if installed == nil || installed.TenantID != tenantID.String() ||
				installed.UserID != actor.UserID.String() {
				return zero, application.ErrUnavailable
			}
			if err := installPersistedTraceContext(operationContext, tx); err != nil {
				return zero, mapSavedViewDatabaseError(err)
			}
			return work(operationContext, tx)
		},
	)
	if err != nil {
		return zero, mapSavedViewDatabaseError(err)
	}
	return result, nil
}

func encodeSavedViewCursor(identifier uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString(identifier[:])
}

func decodeSavedViewCursor(value string) (uuid.UUID, error) {
	if value == "" {
		return uuid.Nil, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != 16 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return uuid.Nil, application.ErrInvalidInput
	}
	identifier, err := uuid.FromBytes(decoded)
	if err != nil || !authorizationUUIDv7(identifier) {
		return uuid.Nil, application.ErrInvalidInput
	}
	return identifier, nil
}

func savedViewOptionalUUID(value uuid.UUID) string {
	if value == uuid.Nil {
		return ""
	}
	return value.String()
}

func savedViewUUID(value kernel.EntityID) uuid.UUID {
	identifier, _ := uuid.Parse(value.String())
	return identifier
}

func validSavedViewRepositoryKind(kind kernel.AggregateKind) bool {
	return kind == kernel.AggregateAlert || kind == kernel.AggregateCase
}

func validSavedViewRepositoryCapability(capability application.SavedViewCapability) bool {
	return capability == application.SavedViewCapabilityRead ||
		capability == application.SavedViewCapabilityManage
}

func validSavedViewRepositoryAction(action kernel.SavedViewAction) bool {
	switch action {
	case kernel.SavedViewCreate, kernel.SavedViewReplace,
		kernel.SavedViewArchive, kernel.SavedViewRestore:
		return true
	default:
		return false
	}
}

func mapSavedViewDatabaseError(err error) error {
	switch {
	case errors.Is(err, authorization.ErrInvalidInput):
		return application.ErrInvalidInput
	case errors.Is(err, authorization.ErrDenied), errors.Is(err, authorization.ErrForbidden),
		errors.Is(err, authorization.ErrNotFound):
		return application.ErrForbidden
	case errors.Is(err, authorization.ErrConflict):
		return application.ErrConflict
	case errors.Is(err, authorization.ErrPreconditionFailed):
		return application.ErrPreconditionFailed
	case errors.Is(err, authorization.ErrUnavailable):
		return application.ErrUnavailable
	}
	if err == nil || errors.Is(err, application.ErrInvalidInput) ||
		errors.Is(err, application.ErrForbidden) || errors.Is(err, application.ErrNotFound) ||
		errors.Is(err, application.ErrConflict) || errors.Is(err, application.ErrPreconditionFailed) ||
		errors.Is(err, application.ErrUnavailable) || errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return application.ErrNotFound
	}
	switch postgresCode(err) {
	case "22023", "22P02", "22007":
		return application.ErrInvalidInput
	case "42501":
		return application.ErrForbidden
	case "P0002":
		return application.ErrNotFound
	case "40001":
		return application.ErrPreconditionFailed
	case "23503", "23505", "23514", "40P01", "55000":
		return application.ErrConflict
	default:
		return application.ErrUnavailable
	}
}

func mapSavedViewRequiredRowError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return application.ErrUnavailable
	}
	return mapSavedViewDatabaseError(err)
}

func nonzeroSavedViewDigest(value [sha256.Size]byte) bool {
	return value != ([sha256.Size]byte{})
}

func validSavedViewRevision(value uint64) bool {
	return value > 0 && value <= maximumSavedViewRevision
}

func savedViewContextError(ctx context.Context) error {
	if ctx == nil {
		return application.ErrUnavailable
	}
	return ctx.Err()
}
