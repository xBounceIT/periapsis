package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	kernel "github.com/periapsis-im/periapsis/modules/customfields"
	application "github.com/periapsis-im/periapsis/services/worker/internal/customfieldimport"
)

const (
	customFieldImportWorkerMaximumDocumentBytes = kernel.ImportMaximumPayloadBytes + 2*1024*1024
	customFieldImportWorkerMaximumTokens        = 2_000_000

	customFieldImportListQueuesQuery = `SELECT app.list_custom_field_import_queues_v1($1::jsonb)`
	customFieldImportLoadQuery       = `SELECT app.load_custom_field_import_worker_v1($1::jsonb)`
	customFieldImportTransitionQuery = `SELECT app.commit_custom_field_import_transition_v1($1::jsonb)`
	customFieldImportLoadRowQuery    = `SELECT app.load_custom_field_import_row_v1($1::jsonb)`
	customFieldImportCommitRowQuery  = `SELECT app.commit_custom_field_import_row_v1($1::jsonb)`
	customFieldImportSetTenantQuery  = `SELECT set_config('app.tenant_id', $1::text, true)`
)

type customFieldImportTransactionBeginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// CustomFieldImportRepository is the worker persistence boundary. Runtime
// roles can execute only the closed app.* ABI; they never receive direct DML
// privileges on the import evidence tables.
type CustomFieldImportRepository struct {
	pool customFieldImportTransactionBeginner
}

func NewCustomFieldImportWorkerRepository(pool customFieldImportTransactionBeginner) *CustomFieldImportRepository {
	return &CustomFieldImportRepository{pool: pool}
}

var _ application.Repository = (*CustomFieldImportRepository)(nil)

type customFieldImportIdentityWire struct {
	ServiceAccountID string `json:"serviceAccountId"`
	WorkerID         string `json:"workerId"`
	Purpose          string `json:"purpose"`
}

type customFieldImportQueueWire struct {
	TenantID string `json:"tenantId"`
	JobID    string `json:"jobId"`
}

type customFieldImportRecordWire struct {
	Job   kernel.ImportJobDocument   `json:"job"`
	Audit customFieldImportAuditWire `json:"audit"`
}

type customFieldImportAuditWire struct {
	RequestID            string `json:"requestId"`
	CorrelationID        string `json:"correlationId"`
	IPAddress            string `json:"ipAddress"`
	UserAgent            string `json:"userAgent"`
	AuthenticationMethod string `json:"authenticationMethod"`
}

type customFieldImportExistingWire struct {
	DefinitionID   string          `json:"definitionId"`
	CanonicalValue json.RawMessage `json:"canonicalValue"`
}

type customFieldImportRowSnapshotWire struct {
	SchemaVersion     uint64                          `json:"schemaVersion"`
	FoundAndVisible   bool                            `json:"foundAndVisible"`
	Allowed           bool                            `json:"allowed"`
	DefinitionChanged bool                            `json:"definitionChanged"`
	CurrentVersion    uint64                          `json:"currentVersion"`
	Existing          []customFieldImportExistingWire `json:"existing"`
}

type customFieldImportPatchWire struct {
	DefinitionID   string          `json:"definitionId"`
	SchemaVersion  uint64          `json:"schemaVersion"`
	Presence       string          `json:"presence"`
	CanonicalValue json.RawMessage `json:"canonicalValue"`
}

func (repository *CustomFieldImportRepository) Ready(
	ctx context.Context,
	identity application.Identity,
) error {
	if ctx == nil || ctx.Err() != nil {
		return application.ErrUnavailable
	}
	_, err := repository.ListQueues(ctx, identity, time.Now().UTC().Truncate(time.Microsecond), 1)
	return err
}

func (repository *CustomFieldImportRepository) ListQueues(
	ctx context.Context,
	identity application.Identity,
	now time.Time,
	limit int,
) ([]application.Queue, error) {
	if !repository.valid(ctx) || !validCustomFieldImportIdentity(identity) ||
		!validCustomFieldImportInstant(now) || limit < 1 || limit > 100 {
		return nil, application.ErrInvalidInput
	}
	request := struct {
		SchemaVersion uint64                        `json:"schemaVersion"`
		Identity      customFieldImportIdentityWire `json:"identity"`
		Now           string                        `json:"now"`
		Limit         int                           `json:"limit"`
	}{1, customFieldImportIdentityDocument(identity), customFieldImportInstant(now), limit}
	var response struct {
		SchemaVersion uint64                       `json:"schemaVersion"`
		Queues        []customFieldImportQueueWire `json:"queues"`
	}
	if err := repository.queryRow(ctx, repository.pool, customFieldImportListQueuesQuery, request, &response); err != nil {
		return nil, err
	}
	if response.SchemaVersion != 1 || response.Queues == nil || len(response.Queues) > limit {
		return nil, application.ErrUnavailable
	}
	queues := make([]application.Queue, len(response.Queues))
	seen := make(map[string]struct{}, len(response.Queues))
	for index, wire := range response.Queues {
		tenant, tenantErr := parseCustomFieldImportUUID(wire.TenantID)
		job, jobErr := parseCustomFieldImportUUID(wire.JobID)
		key := wire.TenantID + ":" + wire.JobID
		if tenantErr != nil || jobErr != nil {
			return nil, application.ErrUnavailable
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, application.ErrUnavailable
		}
		seen[key] = struct{}{}
		queues[index] = application.Queue{TenantID: tenant, JobID: job}
	}
	return queues, nil
}

func (repository *CustomFieldImportRepository) Load(
	ctx context.Context,
	identity application.Identity,
	queue application.Queue,
) (application.Record, error) {
	if !repository.valid(ctx) || !validCustomFieldImportIdentity(identity) || !validCustomFieldImportQueue(queue) {
		return application.Record{}, application.ErrInvalidInput
	}
	tx, err := repository.beginTenant(ctx, queue.TenantID)
	if err != nil {
		return application.Record{}, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	request := struct {
		SchemaVersion uint64                        `json:"schemaVersion"`
		Identity      customFieldImportIdentityWire `json:"identity"`
		TenantID      string                        `json:"tenantId"`
		JobID         string                        `json:"jobId"`
	}{1, customFieldImportIdentityDocument(identity), queue.TenantID.String(), queue.JobID.String()}
	var wire customFieldImportRecordWire
	if err := repository.queryRow(ctx, tx, customFieldImportLoadQuery, request, &wire); err != nil {
		return application.Record{}, err
	}
	record, err := restoreCustomFieldImportWorkerRecord(wire, queue)
	if err != nil {
		return application.Record{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return application.Record{}, mapCustomFieldImportWorkerError(err)
	}
	return record, nil
}

func (repository *CustomFieldImportRepository) CommitTransition(
	ctx context.Context,
	identity application.Identity,
	queue application.Queue,
	current kernel.ImportJob,
	next kernel.ImportJob,
) (application.Record, error) {
	if !repository.valid(ctx) || !validCustomFieldImportIdentity(identity) || !validCustomFieldImportQueue(queue) {
		return application.Record{}, application.ErrInvalidInput
	}
	currentDocument, currentErr := kernel.NewImportJobDocument(current)
	nextDocument, nextErr := kernel.NewImportJobDocument(next)
	if currentErr != nil || nextErr != nil {
		return application.Record{}, application.ErrInvalidInput
	}
	tx, err := repository.beginTenant(ctx, queue.TenantID)
	if err != nil {
		return application.Record{}, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	request := struct {
		SchemaVersion uint64                        `json:"schemaVersion"`
		Identity      customFieldImportIdentityWire `json:"identity"`
		TenantID      string                        `json:"tenantId"`
		JobID         string                        `json:"jobId"`
		Current       kernel.ImportJobDocument      `json:"current"`
		Next          kernel.ImportJobDocument      `json:"next"`
	}{
		1, customFieldImportIdentityDocument(identity), queue.TenantID.String(), queue.JobID.String(),
		currentDocument, nextDocument,
	}
	var wire customFieldImportRecordWire
	if err := repository.queryRow(ctx, tx, customFieldImportTransitionQuery, request, &wire); err != nil {
		return application.Record{}, err
	}
	record, err := restoreCustomFieldImportWorkerRecord(wire, queue)
	if err != nil {
		return application.Record{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return application.Record{}, mapCustomFieldImportWorkerError(err)
	}
	return record, nil
}

func (repository *CustomFieldImportRepository) ProcessRow(
	ctx context.Context,
	identity application.Identity,
	queue application.Queue,
	current kernel.ImportJob,
	row kernel.ImportRow,
	fence kernel.EntityID,
	recordedAt time.Time,
	decide application.RowDecider,
) (application.Record, error) {
	if !repository.valid(ctx) || !validCustomFieldImportIdentity(identity) || !validCustomFieldImportQueue(queue) ||
		kernel.ValidateImportJob(current) != nil || row.Sequence() == 0 || !validCustomFieldImportInstant(recordedAt) ||
		decide == nil || uuid.UUID(fence.Bytes()) != identity.WorkerID {
		return application.Record{}, application.ErrInvalidInput
	}
	tx, err := repository.beginTenant(ctx, queue.TenantID)
	if err != nil {
		return application.Record{}, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	loadRequest := struct {
		SchemaVersion uint64                        `json:"schemaVersion"`
		Identity      customFieldImportIdentityWire `json:"identity"`
		TenantID      string                        `json:"tenantId"`
		JobID         string                        `json:"jobId"`
		Revision      uint64                        `json:"revision"`
		FenceID       string                        `json:"fenceId"`
		Sequence      uint32                        `json:"sequence"`
	}{
		1, customFieldImportIdentityDocument(identity), queue.TenantID.String(), queue.JobID.String(),
		current.Revision(), fence.String(), row.Sequence(),
	}
	var snapshotWire customFieldImportRowSnapshotWire
	if err := repository.queryRow(ctx, tx, customFieldImportLoadRowQuery, loadRequest, &snapshotWire); err != nil {
		return application.Record{}, err
	}
	snapshot, err := restoreCustomFieldImportRowSnapshot(snapshotWire, current.Manifest())
	if err != nil {
		return application.Record{}, err
	}
	decision, err := decide(snapshot)
	if err != nil || kernel.ValidateImportJob(decision.Next) != nil {
		return application.Record{}, application.ErrUnavailable
	}
	currentDocument, currentErr := kernel.NewImportJobDocument(current)
	nextDocument, nextErr := kernel.NewImportJobDocument(decision.Next)
	if currentErr != nil || nextErr != nil {
		return application.Record{}, application.ErrUnavailable
	}
	patches, err := customFieldImportPatchDocuments(decision.Patches)
	if err != nil {
		return application.Record{}, err
	}
	result := customFieldImportResultDocument(decision.Result)
	commitRequest := struct {
		SchemaVersion uint64                        `json:"schemaVersion"`
		Identity      customFieldImportIdentityWire `json:"identity"`
		TenantID      string                        `json:"tenantId"`
		JobID         string                        `json:"jobId"`
		FenceID       string                        `json:"fenceId"`
		Sequence      uint32                        `json:"sequence"`
		Current       kernel.ImportJobDocument      `json:"current"`
		Next          kernel.ImportJobDocument      `json:"next"`
		Result        kernel.ImportResultDocument   `json:"result"`
		Patches       []customFieldImportPatchWire  `json:"patches"`
		RecordedAt    string                        `json:"recordedAt"`
	}{
		1, customFieldImportIdentityDocument(identity), queue.TenantID.String(), queue.JobID.String(),
		fence.String(), row.Sequence(), currentDocument, nextDocument, result, patches,
		customFieldImportInstant(recordedAt),
	}
	var recordWire customFieldImportRecordWire
	if err := repository.queryRow(ctx, tx, customFieldImportCommitRowQuery, commitRequest, &recordWire); err != nil {
		return application.Record{}, err
	}
	record, err := restoreCustomFieldImportWorkerRecord(recordWire, queue)
	if err != nil {
		return application.Record{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return application.Record{}, mapCustomFieldImportWorkerError(err)
	}
	return record, nil
}

func (repository *CustomFieldImportRepository) valid(ctx context.Context) bool {
	return repository != nil && !customFieldImportWorkerDependencyNil(repository.pool) &&
		ctx != nil && ctx.Err() == nil
}

func (repository *CustomFieldImportRepository) beginTenant(
	ctx context.Context,
	tenant uuid.UUID,
) (pgx.Tx, error) {
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, mapCustomFieldImportWorkerError(err)
	}
	var established string
	if err := tx.QueryRow(ctx, customFieldImportSetTenantQuery, tenant.String()).Scan(&established); err != nil || established != tenant.String() {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		if err == nil {
			return nil, application.ErrUnavailable
		}
		return nil, mapCustomFieldImportWorkerError(err)
	}
	return tx, nil
}

type customFieldImportWorkerQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (repository *CustomFieldImportRepository) queryRow(
	ctx context.Context,
	querier customFieldImportWorkerQuerier,
	query string,
	request any,
	destination any,
) error {
	if destination == nil || customFieldImportWorkerDependencyNil(querier) {
		return application.ErrUnavailable
	}
	payload, err := json.Marshal(request)
	if err != nil || len(payload) == 0 || len(payload) > customFieldImportWorkerMaximumDocumentBytes {
		return application.ErrInvalidInput
	}
	var document []byte
	if err := querier.QueryRow(ctx, query, payload).Scan(&document); err != nil {
		return mapCustomFieldImportWorkerError(err)
	}
	if len(document) == 0 || len(document) > customFieldImportWorkerMaximumDocumentBytes ||
		customFieldImportWorkerTokenCount(document) > customFieldImportWorkerMaximumTokens {
		return application.ErrUnavailable
	}
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(document), int64(customFieldImportWorkerMaximumDocumentBytes)+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return application.ErrUnavailable
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return application.ErrUnavailable
	}
	return nil
}

func restoreCustomFieldImportWorkerRecord(
	wire customFieldImportRecordWire,
	queue application.Queue,
) (application.Record, error) {
	job, err := kernel.RestoreImportJobDocument(wire.Job)
	requestID, requestErr := parseCustomFieldImportUUID(wire.Audit.RequestID)
	correlationID, correlationErr := parseCustomFieldImportUUID(wire.Audit.CorrelationID)
	_, addressErr := netip.ParseAddr(wire.Audit.IPAddress)
	if err != nil || requestErr != nil || correlationErr != nil || addressErr != nil ||
		wire.Audit.UserAgent == "" || wire.Audit.AuthenticationMethod == "" ||
		uuid.UUID(job.Manifest().Tenant().Bytes()) != queue.TenantID ||
		uuid.UUID(job.Manifest().ID().Bytes()) != queue.JobID || requestID == uuid.Nil || correlationID == uuid.Nil {
		return application.Record{}, application.ErrUnavailable
	}
	return application.Record{Job: job}, nil
}

func restoreCustomFieldImportRowSnapshot(
	wire customFieldImportRowSnapshotWire,
	manifest kernel.ImportManifest,
) (application.RowSnapshot, error) {
	if wire.SchemaVersion != 1 || wire.Existing == nil ||
		!wire.FoundAndVisible && (wire.Allowed || wire.CurrentVersion != 0 || len(wire.Existing) != 0) ||
		wire.FoundAndVisible && wire.CurrentVersion == 0 {
		return application.RowSnapshot{}, application.ErrUnavailable
	}
	definitions := make(map[uuid.UUID]kernel.Definition, len(manifest.Definitions()))
	for _, definition := range manifest.Definitions() {
		definitions[uuid.UUID(definition.ID().Bytes())] = definition
	}
	existing := make([]kernel.FieldValue, len(wire.Existing))
	seen := make(map[uuid.UUID]struct{}, len(wire.Existing))
	for index, item := range wire.Existing {
		definitionID, err := parseCustomFieldImportUUID(item.DefinitionID)
		definition, found := definitions[definitionID]
		if err != nil || !found || len(item.CanonicalValue) == 0 {
			return application.RowSnapshot{}, application.ErrUnavailable
		}
		if _, duplicate := seen[definitionID]; duplicate {
			return application.RowSnapshot{}, application.ErrUnavailable
		}
		seen[definitionID] = struct{}{}
		existing[index], err = kernel.RestoreFieldValue(definition, item.CanonicalValue)
		if err != nil {
			return application.RowSnapshot{}, application.ErrUnavailable
		}
	}
	return application.RowSnapshot{
		FoundAndVisible: wire.FoundAndVisible, Allowed: wire.Allowed,
		DefinitionChanged: wire.DefinitionChanged, CurrentVersion: wire.CurrentVersion,
		Existing: existing,
	}, nil
}

func customFieldImportPatchDocuments(values []kernel.FieldValue) ([]customFieldImportPatchWire, error) {
	result := make([]customFieldImportPatchWire, len(values))
	seen := make(map[uuid.UUID]struct{}, len(values))
	for index, field := range values {
		definitionID := uuid.UUID(field.DefinitionID().Bytes())
		presence := "present"
		if field.Value().Presence() == kernel.PresenceNull {
			presence = "null"
		} else if field.Value().Presence() != kernel.PresencePresent {
			return nil, application.ErrUnavailable
		}
		if _, duplicate := seen[definitionID]; duplicate {
			return nil, application.ErrUnavailable
		}
		seen[definitionID] = struct{}{}
		result[index] = customFieldImportPatchWire{
			DefinitionID: definitionID.String(), SchemaVersion: field.SchemaVersion(),
			Presence: presence, CanonicalValue: field.Value().CanonicalJSON(),
		}
	}
	return result, nil
}

func customFieldImportResultDocument(result kernel.ImportRowResult) kernel.ImportResultDocument {
	errorsDocument := make([]kernel.ImportFieldErrorDocument, len(result.FieldErrors()))
	for index, fieldError := range result.FieldErrors() {
		errorsDocument[index] = kernel.ImportFieldErrorDocument{
			Field: fieldError.Field.String(), Code: fieldError.Code,
		}
	}
	return kernel.ImportResultDocument{
		Sequence: result.Sequence(), Outcome: result.Outcome().String(),
		ResultingVersion: result.ResultingVersion(), FieldErrors: errorsDocument,
	}
}

func customFieldImportIdentityDocument(identity application.Identity) customFieldImportIdentityWire {
	return customFieldImportIdentityWire{
		ServiceAccountID: identity.ServiceAccountID.String(), WorkerID: identity.WorkerID.String(),
		Purpose: application.WorkerPurpose,
	}
}

func validCustomFieldImportIdentity(identity application.Identity) bool {
	return identity.ServiceAccountID != uuid.Nil && identity.ServiceAccountID.Version() == 7 &&
		identity.WorkerID != uuid.Nil && identity.WorkerID.Version() == 7
}

func validCustomFieldImportQueue(queue application.Queue) bool {
	return queue.TenantID != uuid.Nil && queue.TenantID.Version() == 7 &&
		queue.JobID != uuid.Nil && queue.JobID.Version() == 7
}

func parseCustomFieldImportUUID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.Version() != 7 || parsed.String() != value {
		return uuid.Nil, application.ErrUnavailable
	}
	return parsed, nil
}

func validCustomFieldImportInstant(value time.Time) bool {
	_, offset := value.Zone()
	return !value.IsZero() && offset == 0 && value.Year() >= 1970 && value.Year() <= 9999 &&
		value.Nanosecond()%int(time.Microsecond) == 0
}

func customFieldImportInstant(value time.Time) string {
	return value.UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.000000Z")
}

func customFieldImportWorkerTokenCount(document []byte) int {
	decoder := json.NewDecoder(bytes.NewReader(document))
	count := 0
	for {
		if _, err := decoder.Token(); err != nil {
			return count
		}
		count++
		if count > customFieldImportWorkerMaximumTokens {
			return count
		}
	}
}

func customFieldImportWorkerDependencyNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func mapCustomFieldImportWorkerError(err error) error {
	if err == nil {
		return nil
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "40001", "23505":
			return application.ErrConflict
		case "42501":
			return application.ErrAuthorizationRevoked
		case "22023", "23514", "P0002":
			return application.ErrUnavailable
		}
	}
	return application.ErrUnavailable
}
