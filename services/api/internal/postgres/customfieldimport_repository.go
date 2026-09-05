package postgres

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	kernel "github.com/periapsis-im/periapsis/modules/customfields"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/customfieldimport"
	customapp "github.com/periapsis-im/periapsis/services/api/internal/customfields"
)

const customFieldImportMaximumDocumentBytes = kernel.ImportMaximumPayloadBytes + 2*1024*1024

type CustomFieldImportRepository struct {
	begin transactionBeginner
	newID func() (uuid.UUID, error)
}

func NewCustomFieldImportRepository(pool *pgxpool.Pool) *CustomFieldImportRepository {
	if pool == nil {
		return nil
	}
	return &CustomFieldImportRepository{begin: poolTransactionBeginner(pool), newID: uuid.NewV7}
}

func (repository *CustomFieldImportRepository) ResolveAccess(
	ctx context.Context,
	actor application.Actor,
	tenant uuid.UUID,
	objectType kernel.ObjectType,
	capability application.Capability,
) (application.Access, error) {
	if repository == nil || repository.begin == nil {
		return application.Access{}, errors.New("custom-field import repository is not configured")
	}
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.Access, error) {
			authority, resolveErr := phase4Authority(ctx, tx, customAuthorizationActor(actor), tenant)
			if resolveErr != nil {
				return application.Access{}, resolveErr
			}
			return customFieldImportAccess(authority, actor, tenant, objectType, capability)
		},
	)
	return result, mapCustomFieldImportDatabaseError(err)
}

func (repository *CustomFieldImportRepository) LoadDefinitions(
	ctx context.Context,
	actor application.Actor,
	tenant uuid.UUID,
	objectType kernel.ObjectType,
	claimed application.Access,
) ([]kernel.Definition, error) {
	if repository == nil || repository.begin == nil {
		return nil, errors.New("custom-field import repository is not configured")
	}
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) ([]kernel.Definition, error) {
			authority, resolveErr := phase4Authority(ctx, tx, customAuthorizationActor(actor), tenant)
			if resolveErr != nil {
				return nil, resolveErr
			}
			access, accessErr := customFieldImportAccess(
				authority, actor, tenant, objectType, application.CapabilityRequest,
			)
			if accessErr != nil || !sameCustomFieldImportAccess(access, claimed) {
				if accessErr != nil {
					return nil, accessErr
				}
				return nil, authorization.ErrForbidden
			}
			return loadCustomObjectDefinitions(ctx, tx, tenant, objectType)
		},
	)
	return result, mapCustomFieldImportDatabaseError(err)
}

func (repository *CustomFieldImportRepository) ReserveImportID(
	_ context.Context,
	_ uuid.UUID,
) (kernel.EntityID, error) {
	if repository == nil || repository.newID == nil {
		return kernel.EntityID{}, errors.New("custom-field import repository is not configured")
	}
	id, err := repository.newID()
	if err != nil {
		return kernel.EntityID{}, err
	}
	return kernel.ParseEntityID(id.String())
}

func (repository *CustomFieldImportRepository) LookupReplay(
	ctx context.Context,
	query application.ReplayQuery,
) (application.Result, bool, error) {
	request := customFieldImportReplayRequest{
		SchemaVersion: 1, TenantID: query.Tenant.String(), ActorID: query.Actor.UserID.String(),
		MembershipID: query.Actor.MembershipID.String(), ObjectType: string(query.ObjectType),
		Action: query.Command.Action.String(), KeySHA256: hex.EncodeToString(query.Command.KeyHash[:]),
		FingerprintSHA256: hex.EncodeToString(query.Command.Fingerprint[:]),
	}
	document, err := repository.callActorFunction(
		ctx, query.Actor, query.Tenant, "app.lookup_custom_field_import_replay_v1", request,
	)
	if err != nil {
		return application.Result{}, false, err
	}
	if bytes.Equal(bytes.TrimSpace(document), []byte("null")) {
		return application.Result{}, false, nil
	}
	result, err := decodeCustomFieldImportResult(document)
	return result, err == nil, err
}

func (repository *CustomFieldImportRepository) CommitRequest(
	ctx context.Context,
	write application.RequestWrite,
) (application.Result, error) {
	job, err := kernel.NewImportJobDocument(write.Job)
	if err != nil {
		return application.Result{}, application.ErrRepositoryConflict
	}
	request := customFieldImportCommitRequest{
		SchemaVersion: 1, Job: job, Scope: string(write.Access.Scope()),
		Command: customFieldImportCommandDocument{
			Action: write.Command.Action.String(), KeySHA256: hex.EncodeToString(write.Command.KeyHash[:]),
			FingerprintSHA256: hex.EncodeToString(write.Command.Fingerprint[:]),
		},
		Audit: customFieldImportAuditDocumentFromApplication(write.Audit),
	}
	document, err := repository.callActorFunction(
		ctx, write.Actor, write.Access.Tenant(), "app.commit_custom_field_import_request_v1", request,
	)
	if err != nil {
		return application.Result{}, err
	}
	return decodeCustomFieldImportResult(document)
}

func (repository *CustomFieldImportRepository) Get(
	ctx context.Context,
	actor application.Actor,
	tenant uuid.UUID,
	jobID uuid.UUID,
	access application.Access,
) (application.Record, error) {
	request := struct {
		SchemaVersion uint64 `json:"schemaVersion"`
		TenantID      string `json:"tenantId"`
		ActorID       string `json:"actorId"`
		MembershipID  string `json:"membershipId"`
		ObjectType    string `json:"objectType"`
		Capability    string `json:"capability"`
		Scope         string `json:"scope"`
		JobID         string `json:"jobId"`
	}{
		SchemaVersion: 1, TenantID: tenant.String(), ActorID: actor.UserID.String(),
		MembershipID: actor.MembershipID.String(), ObjectType: string(access.ObjectType()),
		Capability: access.Capability().String(), Scope: string(access.Scope()), JobID: jobID.String(),
	}
	document, err := repository.callActorFunction(
		ctx, actor, tenant, "app.get_custom_field_import_v1", request,
	)
	if err != nil {
		return application.Record{}, err
	}
	return decodeCustomFieldImportRecord(document)
}

func (repository *CustomFieldImportRepository) ListResults(
	ctx context.Context,
	actor application.Actor,
	tenant uuid.UUID,
	jobID uuid.UUID,
	access application.Access,
	after uint32,
	pageSize int,
) (application.ResultPage, error) {
	request := struct {
		SchemaVersion uint64 `json:"schemaVersion"`
		TenantID      string `json:"tenantId"`
		ActorID       string `json:"actorId"`
		MembershipID  string `json:"membershipId"`
		ObjectType    string `json:"objectType"`
		Capability    string `json:"capability"`
		Scope         string `json:"scope"`
		JobID         string `json:"jobId"`
		After         uint32 `json:"after"`
		PageSize      int    `json:"pageSize"`
	}{
		SchemaVersion: 1, TenantID: tenant.String(), ActorID: actor.UserID.String(),
		MembershipID: actor.MembershipID.String(), ObjectType: string(access.ObjectType()),
		Capability: access.Capability().String(), Scope: string(access.Scope()), JobID: jobID.String(),
		After: after, PageSize: pageSize,
	}
	document, err := repository.callActorFunction(
		ctx, actor, tenant, "app.list_custom_field_import_results_v1", request,
	)
	if err != nil {
		return application.ResultPage{}, err
	}
	return decodeCustomFieldImportResultPage(document)
}

func (repository *CustomFieldImportRepository) CommitCancellation(
	ctx context.Context,
	write application.CancellationWrite,
) (application.Result, error) {
	current, err := kernel.NewImportJobDocument(write.Current)
	if err != nil {
		return application.Result{}, application.ErrRepositoryPrecondition
	}
	next, err := kernel.NewImportJobDocument(write.Next)
	if err != nil {
		return application.Result{}, application.ErrRepositoryConflict
	}
	request := struct {
		SchemaVersion uint64                           `json:"schemaVersion"`
		Current       kernel.ImportJobDocument         `json:"current"`
		Next          kernel.ImportJobDocument         `json:"next"`
		Scope         string                           `json:"scope"`
		Command       customFieldImportCommandDocument `json:"command"`
		Audit         customFieldImportAuditDocument   `json:"audit"`
	}{
		SchemaVersion: 1, Current: current, Next: next, Scope: string(write.Access.Scope()),
		Command: customFieldImportCommandDocument{
			Action: write.Command.Action.String(), KeySHA256: hex.EncodeToString(write.Command.KeyHash[:]),
			FingerprintSHA256: hex.EncodeToString(write.Command.Fingerprint[:]),
		},
		Audit: customFieldImportAuditDocumentFromApplication(write.Audit),
	}
	document, err := repository.callActorFunction(
		ctx, write.Actor, write.Access.Tenant(), "app.commit_custom_field_import_cancellation_v1", request,
	)
	if err != nil {
		return application.Result{}, err
	}
	return decodeCustomFieldImportResult(document)
}

func (repository *CustomFieldImportRepository) callActorFunction(
	ctx context.Context,
	actor application.Actor,
	tenant uuid.UUID,
	function string,
	request any,
) ([]byte, error) {
	if repository == nil || repository.begin == nil || !slices.Contains([]string{
		"app.lookup_custom_field_import_replay_v1",
		"app.commit_custom_field_import_request_v1",
		"app.get_custom_field_import_v1",
		"app.list_custom_field_import_results_v1",
		"app.commit_custom_field_import_cancellation_v1",
	}, function) {
		return nil, errors.New("custom-field import repository function is invalid")
	}
	encoded, err := json.Marshal(request)
	if err != nil || len(encoded) == 0 || len(encoded) > customFieldImportMaximumDocumentBytes {
		return nil, application.ErrRepositoryConflict
	}
	result, err := withinTransaction(
		ctx, repository.begin,
		func(tx databaseTransaction) ([]byte, error) {
			if _, resolveErr := phase4Authority(ctx, tx, customAuthorizationActor(actor), tenant); resolveErr != nil {
				return nil, resolveErr
			}
			var document []byte
			if queryErr := tx.QueryRow(ctx, "SELECT "+function+"($1::jsonb)", encoded).Scan(&document); queryErr != nil {
				return nil, queryErr
			}
			if len(document) == 0 || len(document) > customFieldImportMaximumDocumentBytes {
				return nil, errors.New("database returned invalid custom-field import document size")
			}
			return document, nil
		},
	)
	return result, mapCustomFieldImportDatabaseError(err)
}

func customFieldImportAccess(
	authority authorization.TenantAuthority,
	actor application.Actor,
	tenant uuid.UUID,
	objectType kernel.ObjectType,
	capability application.Capability,
) (application.Access, error) {
	if !validPhase4Authority(authority, actor.MembershipID) || authority.TenantID != tenant ||
		authority.Principal.ID != actor.UserID || actor.Kind != customapp.PrincipalHuman ||
		!phase4HasPermission(authority, "custom_field.read", authorization.ScopeTenant) {
		return application.Access{}, authorization.ErrForbidden
	}
	permission := "alert.update"
	if objectType == kernel.ObjectCase {
		permission = "case.update"
	} else if objectType != kernel.ObjectAlert {
		return application.Access{}, application.ErrInvalidInput
	}
	scope := customapp.Scope("")
	for _, candidate := range []struct {
		authorization authorization.Scope
		application   customapp.Scope
	}{
		{authorization.ScopeTenant, customapp.ScopeTenant},
		{authorization.ScopeOperatorTeam, customapp.ScopeOperatorTeam},
		{authorization.ScopeAssigned, customapp.ScopeAssigned},
	} {
		if phase4HasPermission(authority, permission, candidate.authorization) {
			scope = candidate.application
			break
		}
	}
	if scope == "" {
		return application.Access{}, authorization.ErrForbidden
	}
	return application.NewAccess(
		tenant, actor.UserID, actor.MembershipID, objectType, capability, scope, true,
	)
}

func sameCustomFieldImportAccess(left, right application.Access) bool {
	return left.Tenant() == right.Tenant() && left.Actor() == right.Actor() &&
		left.Membership() == right.Membership() && left.ObjectType() == right.ObjectType() &&
		left.Capability() == right.Capability() && left.Scope() == right.Scope() &&
		left.Allowed() == right.Allowed()
}

type customFieldImportCommandDocument struct {
	Action            string `json:"action"`
	KeySHA256         string `json:"keySha256"`
	FingerprintSHA256 string `json:"fingerprintSha256"`
}

type customFieldImportAuditDocument struct {
	RequestID            string `json:"requestId"`
	CorrelationID        string `json:"correlationId"`
	IPAddress            string `json:"ipAddress"`
	UserAgent            string `json:"userAgent"`
	AuthenticationMethod string `json:"authenticationMethod"`
}

type customFieldImportRecordDocument struct {
	Job   kernel.ImportJobDocument       `json:"job"`
	Audit customFieldImportAuditDocument `json:"audit"`
}

type customFieldImportResultDocument struct {
	SchemaVersion uint64                          `json:"schemaVersion"`
	Record        customFieldImportRecordDocument `json:"record"`
	Replayed      bool                            `json:"replayed"`
}

type customFieldImportRowResultDocument struct {
	Sequence         uint32                            `json:"sequence"`
	TargetID         string                            `json:"targetId"`
	ExpectedVersion  uint64                            `json:"expectedVersion"`
	Outcome          string                            `json:"outcome"`
	ResultingVersion uint64                            `json:"resultingVersion"`
	FieldErrors      []kernel.ImportFieldErrorDocument `json:"fieldErrors"`
	RecordedAt       string                            `json:"recordedAt"`
}

type customFieldImportResultPageDocument struct {
	Items     []customFieldImportRowResultDocument `json:"items"`
	NextAfter *uint32                              `json:"nextAfter"`
}

type customFieldImportReplayRequest struct {
	SchemaVersion     uint64 `json:"schemaVersion"`
	TenantID          string `json:"tenantId"`
	ActorID           string `json:"actorId"`
	MembershipID      string `json:"membershipId"`
	ObjectType        string `json:"objectType"`
	Action            string `json:"action"`
	KeySHA256         string `json:"keySha256"`
	FingerprintSHA256 string `json:"fingerprintSha256"`
}

type customFieldImportCommitRequest struct {
	SchemaVersion uint64                           `json:"schemaVersion"`
	Job           kernel.ImportJobDocument         `json:"job"`
	Scope         string                           `json:"scope"`
	Command       customFieldImportCommandDocument `json:"command"`
	Audit         customFieldImportAuditDocument   `json:"audit"`
}

func customFieldImportAuditDocumentFromApplication(value application.AuditContext) customFieldImportAuditDocument {
	return customFieldImportAuditDocument{
		RequestID: value.RequestID.String(), CorrelationID: value.CorrelationID.String(),
		IPAddress: value.IPAddress.String(), UserAgent: value.UserAgent,
		AuthenticationMethod: value.AuthenticationMethod,
	}
}

func decodeCustomFieldImportResult(document []byte) (application.Result, error) {
	var wire customFieldImportResultDocument
	if err := decodeCustomFieldImportExact(document, &wire); err != nil || wire.SchemaVersion != 1 {
		return application.Result{}, errors.New("database returned an invalid custom-field import result")
	}
	record, err := restoreCustomFieldImportRecord(wire.Record)
	if err != nil {
		return application.Result{}, err
	}
	return application.Result{Record: record, Replayed: wire.Replayed}, nil
}

func decodeCustomFieldImportRecord(document []byte) (application.Record, error) {
	var wire customFieldImportRecordDocument
	if err := decodeCustomFieldImportExact(document, &wire); err != nil {
		return application.Record{}, errors.New("database returned an invalid custom-field import record")
	}
	return restoreCustomFieldImportRecord(wire)
}

func decodeCustomFieldImportResultPage(document []byte) (application.ResultPage, error) {
	var wire customFieldImportResultPageDocument
	if err := decodeCustomFieldImportExact(document, &wire); err != nil || wire.Items == nil || len(wire.Items) > 100 {
		return application.ResultPage{}, errors.New("database returned an invalid custom-field import result page")
	}
	items := make([]application.RowResult, len(wire.Items))
	for index, source := range wire.Items {
		target, targetErr := uuid.Parse(source.TargetID)
		outcome, outcomeOK := customFieldImportRowOutcome(source.Outcome)
		fieldErrors := make([]kernel.FieldError, len(source.FieldErrors))
		for errorIndex, raw := range source.FieldErrors {
			key, keyErr := kernel.NewKey(raw.Field)
			if keyErr != nil {
				return application.ResultPage{}, errors.New("database returned invalid custom-field import field evidence")
			}
			fieldErrors[errorIndex] = kernel.FieldError{Field: key, Code: raw.Code}
		}
		result, resultErr := kernel.NewImportRowResult(
			source.Sequence, outcome, source.ResultingVersion, fieldErrors,
		)
		recordedAt, recordedErr := time.Parse("2006-01-02T15:04:05.000000Z", source.RecordedAt)
		if targetErr != nil || target.Version() != 7 || !outcomeOK || resultErr != nil || recordedErr != nil {
			return application.ResultPage{}, errors.New("database returned invalid custom-field import row evidence")
		}
		items[index] = application.RowResult{
			Sequence: source.Sequence, Target: target, ExpectedVersion: source.ExpectedVersion,
			Result: result, RecordedAt: recordedAt,
		}
	}
	return application.ResultPage{Items: items, NextAfter: wire.NextAfter}, nil
}

func customFieldImportRowOutcome(value string) (kernel.ImportRowOutcome, bool) {
	for outcome := kernel.ImportRowDryRunValid; outcome <= kernel.ImportRowInternalFailure; outcome++ {
		if outcome.String() == value {
			return outcome, true
		}
	}
	return 0, false
}

func restoreCustomFieldImportRecord(wire customFieldImportRecordDocument) (application.Record, error) {
	job, err := kernel.RestoreImportJobDocument(wire.Job)
	if err != nil {
		return application.Record{}, errors.New("database returned an invalid custom-field import job")
	}
	requestID, requestErr := uuid.Parse(wire.Audit.RequestID)
	correlationID, correlationErr := uuid.Parse(wire.Audit.CorrelationID)
	address, addressErr := netip.ParseAddr(wire.Audit.IPAddress)
	if requestErr != nil || correlationErr != nil || addressErr != nil {
		return application.Record{}, errors.New("database returned invalid custom-field import audit metadata")
	}
	return application.Record{Job: job, RequestedAudit: application.AuditContext{
		RequestID: requestID, CorrelationID: correlationID, IPAddress: address,
		UserAgent: wire.Audit.UserAgent, AuthenticationMethod: wire.Audit.AuthenticationMethod,
	}}, nil
}

func decodeCustomFieldImportExact(document []byte, destination any) error {
	if len(document) == 0 || len(document) > customFieldImportMaximumDocumentBytes {
		return errors.New("custom-field import document size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("custom-field import document has trailing data")
	}
	return nil
}

func mapCustomFieldImportDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return application.ErrRepositoryNotFound
	}
	switch postgresCode(err) {
	case "22023", "23514":
		return application.ErrRepositoryConflict
	case "42501":
		return application.ErrRepositoryForbidden
	case "P0002":
		return application.ErrRepositoryNotFound
	case "40001":
		return application.ErrRepositoryPrecondition
	case "23505":
		return application.ErrRepositoryConflict
	default:
		return mapCommonDatabaseError(err)
	}
}
