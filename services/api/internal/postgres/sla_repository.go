package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	kernel "github.com/periapsis-im/periapsis/modules/sla"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/sla"
)

// SLARepository is the API PostgreSQL adapter for the tenant SLA boundary.
// Runtime roles never receive direct SLA table privileges; every read and
// mutation goes through a bounded SECURITY DEFINER ABI after transaction-local
// tenant and actor context is installed.
type SLARepository struct {
	begin transactionBeginner
}

func NewSLARepository(pool *pgxpool.Pool) *SLARepository {
	if pool == nil {
		return nil
	}
	return &SLARepository{begin: poolTransactionBeginner(pool)}
}

var _ application.Repository = (*SLARepository)(nil)

func (repository *SLARepository) ResolveAuthority(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	capability application.Capability,
	resource application.Resource,
) (application.Authority, error) {
	if repository == nil || repository.begin == nil {
		return application.Authority{}, application.ErrRepositoryForbidden
	}
	authority, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.Authority, error) {
			return resolveSLAAuthorityInTransaction(ctx, tx, actor, tenantID, capability, resource)
		},
	)
	return authority, mapSLADatabaseError(err)
}

func (repository *SLARepository) ListCalendars(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	input application.ConfigurationListInput,
	claimed application.Authority,
) (application.CalendarPage, error) {
	page, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.CalendarPage, error) {
			if err := recheckSLAAuthority(ctx, tx, actor, tenantID, application.CapabilityRead, application.Resource{}, claimed); err != nil {
				return application.CalendarPage{}, err
			}
			afterKey, afterID, err := decodeSLAConfigurationCursor(input.After)
			if err != nil {
				return application.CalendarPage{}, err
			}
			documents, err := readSLAConfigurationPage(
				ctx, tx, tenantID, application.ArchiveCalendar, uuid.Nil, afterKey, afterID,
				input.Limit+1, input.IncludeArchived,
			)
			if err != nil {
				return application.CalendarPage{}, err
			}
			result := application.CalendarPage{}
			hasMore := len(documents) > input.Limit
			if hasMore {
				documents = documents[:input.Limit]
			}
			result.Items = make([]application.CalendarRecord, len(documents))
			for index, document := range documents {
				result.Items[index], err = decodeSLACalendar(tenantID, document)
				if err != nil {
					return application.CalendarPage{}, err
				}
			}
			if hasMore && len(result.Items) != 0 {
				last := result.Items[len(result.Items)-1].Value
				result.NextCursor = application.EncodeConfigurationCursor(last.Key(), last.ID())
			}
			return result, nil
		},
	)
	return page, mapSLADatabaseError(err)
}

func (repository *SLARepository) GetCalendar(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	id kernel.EntityID,
	claimed application.Authority,
) (application.CalendarRecord, error) {
	record, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.CalendarRecord, error) {
			if err := recheckSLAAuthority(ctx, tx, actor, tenantID, application.CapabilityRead, application.Resource{}, claimed); err != nil {
				return application.CalendarRecord{}, err
			}
			document, err := readSingleSLAConfiguration(ctx, tx, tenantID, application.ArchiveCalendar, slaUUID(id))
			if err != nil {
				return application.CalendarRecord{}, err
			}
			return decodeSLACalendar(tenantID, document)
		},
	)
	return record, mapSLADatabaseError(err)
}

func (repository *SLARepository) ListPolicies(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	input application.ConfigurationListInput,
	claimed application.Authority,
) (application.PolicyPage, error) {
	page, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.PolicyPage, error) {
			if err := recheckSLAAuthority(ctx, tx, actor, tenantID, application.CapabilityRead, application.Resource{}, claimed); err != nil {
				return application.PolicyPage{}, err
			}
			afterKey, afterID, err := decodeSLAConfigurationCursor(input.After)
			if err != nil {
				return application.PolicyPage{}, err
			}
			documents, err := readSLAConfigurationPage(
				ctx, tx, tenantID, application.ArchivePolicy, uuid.Nil, afterKey, afterID,
				input.Limit+1, input.IncludeArchived,
			)
			if err != nil {
				return application.PolicyPage{}, err
			}
			result := application.PolicyPage{}
			hasMore := len(documents) > input.Limit
			if hasMore {
				documents = documents[:input.Limit]
			}
			result.Items = make([]application.PolicyRecord, len(documents))
			for index, document := range documents {
				result.Items[index], err = decodeSLAPolicy(tenantID, document)
				if err != nil {
					return application.PolicyPage{}, err
				}
			}
			if hasMore && len(result.Items) != 0 {
				last := result.Items[len(result.Items)-1].Value
				result.NextCursor = application.EncodeConfigurationCursor(last.Key(), last.ID())
			}
			return result, nil
		},
	)
	return page, mapSLADatabaseError(err)
}

func (repository *SLARepository) GetPolicy(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	id kernel.EntityID,
	claimed application.Authority,
) (application.PolicyRecord, error) {
	record, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.PolicyRecord, error) {
			if err := recheckSLAAuthority(ctx, tx, actor, tenantID, application.CapabilityRead, application.Resource{}, claimed); err != nil {
				return application.PolicyRecord{}, err
			}
			document, err := readSingleSLAConfiguration(ctx, tx, tenantID, application.ArchivePolicy, slaUUID(id))
			if err != nil {
				return application.PolicyRecord{}, err
			}
			return decodeSLAPolicy(tenantID, document)
		},
	)
	return record, mapSLADatabaseError(err)
}

func (repository *SLARepository) ListColumns(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	input application.ConfigurationListInput,
	claimed application.Authority,
) (application.ColumnPage, error) {
	page, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.ColumnPage, error) {
			if err := recheckSLAAuthority(ctx, tx, actor, tenantID, application.CapabilityRead, application.Resource{}, claimed); err != nil {
				return application.ColumnPage{}, err
			}
			afterKey, afterID, err := decodeSLAConfigurationCursor(input.After)
			if err != nil {
				return application.ColumnPage{}, err
			}
			documents, err := readSLAConfigurationPage(
				ctx, tx, tenantID, application.ArchiveColumn, uuid.Nil, afterKey, afterID,
				input.Limit+1, input.IncludeArchived,
			)
			if err != nil {
				return application.ColumnPage{}, err
			}
			result := application.ColumnPage{}
			hasMore := len(documents) > input.Limit
			if hasMore {
				documents = documents[:input.Limit]
			}
			result.Items = make([]application.ColumnRecord, len(documents))
			for index, document := range documents {
				result.Items[index], err = decodeSLAColumn(tenantID, document, nil)
				if err != nil {
					return application.ColumnPage{}, err
				}
			}
			if hasMore && len(result.Items) != 0 {
				last := result.Items[len(result.Items)-1].Value
				result.NextCursor = application.EncodeConfigurationCursor(last.Key(), last.ID())
			}
			return result, nil
		},
	)
	return page, mapSLADatabaseError(err)
}

func (repository *SLARepository) GetColumn(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	id kernel.EntityID,
	claimed application.Authority,
) (application.ColumnRecord, error) {
	record, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.ColumnRecord, error) {
			if err := recheckSLAAuthority(ctx, tx, actor, tenantID, application.CapabilityRead, application.Resource{}, claimed); err != nil {
				return application.ColumnRecord{}, err
			}
			document, err := readSingleSLAConfiguration(ctx, tx, tenantID, application.ArchiveColumn, slaUUID(id))
			if err != nil {
				return application.ColumnRecord{}, err
			}
			return decodeSLAColumn(tenantID, document, nil)
		},
	)
	return record, mapSLADatabaseError(err)
}

func (repository *SLARepository) PublishCalendar(
	ctx context.Context,
	publication application.CalendarPublication,
) (application.PublicationResult[kernel.BusinessCalendar], error) {
	document, err := encodeSLACalendar(publication.Calendar)
	if err != nil {
		return application.PublicationResult[kernel.BusinessCalendar]{}, application.ErrRepositoryConflict
	}
	result, err := mutateSLAConfiguration(
		ctx, repository, publication.Actor, application.ArchiveCalendar,
		publication.Calendar.ID(), publication.Calendar.Version(), publication.ExpectedActiveVersion,
		publication.Command, publication.Audit, document,
	)
	if err != nil {
		return application.PublicationResult[kernel.BusinessCalendar]{}, err
	}
	record, err := decodeSLACalendar(publication.Actor.TenantID, result.document)
	if err != nil || record.Value.ID() != publication.Calendar.ID() {
		return application.PublicationResult[kernel.BusinessCalendar]{}, application.ErrRepositoryConflict
	}
	return application.PublicationResult[kernel.BusinessCalendar]{
		Value: record.Value, ResourceVersion: record.ResourceVersion,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
		ArchivedAt: record.ArchivedAt, Replayed: result.replayed,
	}, nil
}

func (repository *SLARepository) PublishPolicy(
	ctx context.Context,
	publication application.PolicyPublication,
) (application.PublicationResult[kernel.Policy], error) {
	document, err := encodeSLAPolicy(publication.Policy)
	if err != nil {
		return application.PublicationResult[kernel.Policy]{}, application.ErrRepositoryConflict
	}
	result, err := mutateSLAConfiguration(
		ctx, repository, publication.Actor, application.ArchivePolicy,
		publication.Policy.ID(), publication.Policy.Version(), publication.ExpectedActiveVersion,
		publication.Command, publication.Audit, document,
	)
	if err != nil {
		return application.PublicationResult[kernel.Policy]{}, err
	}
	record, err := decodeSLAPolicy(publication.Actor.TenantID, result.document)
	if err != nil || record.Value.ID() != publication.Policy.ID() {
		return application.PublicationResult[kernel.Policy]{}, application.ErrRepositoryConflict
	}
	return application.PublicationResult[kernel.Policy]{
		Value: record.Value, ResourceVersion: record.ResourceVersion,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
		ArchivedAt: record.ArchivedAt, Replayed: result.replayed,
	}, nil
}

func (repository *SLARepository) PublishColumn(
	ctx context.Context,
	publication application.ColumnPublication,
) (application.PublicationResult[kernel.ColumnDefinition], error) {
	document, err := encodeSLAColumn(publication.Column)
	if err != nil {
		return application.PublicationResult[kernel.ColumnDefinition]{}, application.ErrRepositoryConflict
	}
	result, err := mutateSLAConfiguration(
		ctx, repository, publication.Actor, application.ArchiveColumn,
		publication.Column.ID(), publication.Column.Version(), publication.ExpectedActiveVersion,
		publication.Command, publication.Audit, document,
	)
	if err != nil {
		return application.PublicationResult[kernel.ColumnDefinition]{}, err
	}
	record, err := decodeSLAColumn(publication.Actor.TenantID, result.document, nil)
	if err != nil || record.Value.ID() != publication.Column.ID() {
		return application.PublicationResult[kernel.ColumnDefinition]{}, application.ErrRepositoryConflict
	}
	return application.PublicationResult[kernel.ColumnDefinition]{
		Value: record.Value, ResourceVersion: record.ResourceVersion,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
		ArchivedAt: record.ArchivedAt, Replayed: result.replayed,
	}, nil
}

func (repository *SLARepository) Archive(
	ctx context.Context,
	write application.ArchiveWrite,
) (uint64, bool, error) {
	if repository == nil || repository.begin == nil {
		return 0, false, application.ErrRepositoryForbidden
	}
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (slaMutationReceipt, error) {
			if _, err := resolveSLAAuthorityInTransaction(
				ctx, tx, write.Actor, write.TenantID, application.CapabilityManage, application.Resource{},
			); err != nil {
				return slaMutationReceipt{}, err
			}
			if write.Audit.AuthMethod != write.Actor.AuthenticationMethod || installPersistedTraceContext(ctx, tx) != nil {
				return slaMutationReceipt{}, application.ErrRepositoryForbidden
			}
			var version int64
			var replayed bool
			err := tx.QueryRow(ctx, `
				SELECT resource_version, replayed
				FROM app.archive_sla_configuration_v1(
					$1, $2, $3, $4, $5, $6, $7,
					$8, $9, $10::inet, $11, $12
				)`,
				write.TenantID, string(write.Kind), slaUUID(write.ID), write.ExpectedVersion,
				write.Reason, write.Command.KeyDigest[:], write.Command.RequestDigest[:],
				write.Audit.RequestID, write.Audit.CorrelationID, write.Audit.IPAddress,
				write.Audit.UserAgent, write.Audit.AuthMethod,
			).Scan(&version, &replayed)
			return slaMutationReceipt{resourceVersion: version, replayed: replayed}, err
		},
	)
	if err != nil {
		return 0, false, mapSLADatabaseError(err)
	}
	if result.resourceVersion < 1 || result.resourceVersion > int64(^uint32(0)>>1) {
		return 0, false, application.ErrRepositoryConflict
	}
	return uint64(result.resourceVersion), result.replayed, nil
}

func (repository *SLARepository) LoadPolicyCalendars(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	policy kernel.Policy,
) ([]kernel.BusinessCalendar, error) {
	calendars, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) ([]kernel.BusinessCalendar, error) {
			if _, err := resolveSLAAuthorityInTransaction(
				ctx, tx, actor, tenantID, application.CapabilityManage, application.Resource{},
			); err != nil {
				return nil, err
			}
			return loadPolicyCalendars(ctx, tx, tenantID, policy, application.CapabilityManage)
		},
	)
	return calendars, mapSLADatabaseError(err)
}

func (repository *SLARepository) LoadMetricDefinition(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	id kernel.EntityID,
) (kernel.MetricDefinition, error) {
	metric, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (kernel.MetricDefinition, error) {
			if _, err := resolveSLAAuthorityInTransaction(
				ctx, tx, actor, tenantID, application.CapabilityManage, application.Resource{},
			); err != nil {
				return kernel.MetricDefinition{}, err
			}
			return readSLAMetricDefinition(ctx, tx, tenantID, id, application.CapabilityManage)
		},
	)
	return metric, mapSLADatabaseError(err)
}

func (repository *SLARepository) LoadSimulation(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	policyID kernel.EntityID,
	policyVersion uint64,
) (kernel.Policy, []kernel.BusinessCalendar, error) {
	type result struct {
		policy    kernel.Policy
		calendars []kernel.BusinessCalendar
	}
	loaded, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (result, error) {
			if _, err := resolveSLAAuthorityInTransaction(
				ctx, tx, actor, tenantID, application.CapabilitySimulate, application.Resource{},
			); err != nil {
				return result{}, err
			}
			document, err := readSLAConfigurationRevision(
				ctx, tx, tenantID, application.ArchivePolicy, policyID, policyVersion, application.CapabilitySimulate,
			)
			if err != nil {
				return result{}, err
			}
			record, err := decodeSLAPolicy(tenantID, document)
			if err != nil || record.Value.Version() != policyVersion {
				return result{}, errors.New("database returned the wrong SLA policy revision")
			}
			calendars, err := loadPolicyCalendars(ctx, tx, tenantID, record.Value, application.CapabilitySimulate)
			return result{policy: record.Value, calendars: calendars}, err
		},
	)
	if err != nil {
		return kernel.Policy{}, nil, mapSLADatabaseError(err)
	}
	return loaded.policy, loaded.calendars, nil
}

type slaMutationReceipt struct {
	resourceID      uuid.UUID
	resourceVersion int64
	activeVersion   int64
	replayed        bool
	document        []byte
}

func mutateSLAConfiguration(
	ctx context.Context,
	repository *SLARepository,
	actor application.Actor,
	kind application.ArchiveKind,
	id kernel.EntityID,
	activeVersion uint64,
	expectedVersion uint64,
	binding application.CommandBinding,
	audit application.AuditContext,
	document []byte,
) (slaMutationReceipt, error) {
	if repository == nil || repository.begin == nil {
		return slaMutationReceipt{}, application.ErrRepositoryForbidden
	}
	tenantID := actor.TenantID
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (slaMutationReceipt, error) {
			if _, err := resolveSLAAuthorityInTransaction(
				ctx, tx, actor, tenantID, application.CapabilityManage, application.Resource{},
			); err != nil {
				return slaMutationReceipt{}, err
			}
			if audit.AuthMethod != actor.AuthenticationMethod {
				return slaMutationReceipt{}, application.ErrRepositoryForbidden
			}
			if err := installPersistedTraceContext(ctx, tx); err != nil {
				return slaMutationReceipt{}, err
			}
			function := map[application.ArchiveKind]string{
				application.ArchiveCalendar: "app.publish_sla_calendar_v2",
				application.ArchivePolicy:   "app.publish_sla_policy_v2",
				application.ArchiveColumn:   "app.publish_sla_column_v2",
			}[kind]
			if function == "" {
				return slaMutationReceipt{}, application.ErrRepositoryConflict
			}
			query := fmt.Sprintf(`
				SELECT resource_id, resource_version, active_version, replayed, document
				FROM %s(
					$1, $2, $3, $4::jsonb, $5, $6,
					$7, $8, $9::inet, $10, $11
				)`, function)
			var receipt slaMutationReceipt
			err := tx.QueryRow(ctx, query,
				tenantID, slaUUID(id), expectedVersion, document,
				binding.KeyDigest[:], binding.RequestDigest[:],
				audit.RequestID, audit.CorrelationID, audit.IPAddress,
				audit.UserAgent, audit.AuthMethod,
			).Scan(
				&receipt.resourceID, &receipt.resourceVersion, &receipt.activeVersion,
				&receipt.replayed, &receipt.document,
			)
			return receipt, err
		},
	)
	if err != nil {
		return slaMutationReceipt{}, mapSLADatabaseError(err)
	}
	if result.resourceID != slaUUID(id) || len(result.document) == 0 ||
		!result.replayed && (result.resourceVersion != int64(activeVersion) ||
			result.activeVersion != int64(activeVersion)) {
		return slaMutationReceipt{}, application.ErrRepositoryConflict
	}
	return result, nil
}

func readSLAConfigurationPage(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	kind application.ArchiveKind,
	resourceID uuid.UUID,
	afterKey string,
	afterID uuid.UUID,
	limit int,
	includeArchived bool,
) ([][]byte, error) {
	var resource, afterIdentifier any
	if resourceID != uuid.Nil {
		resource = resourceID
	}
	if afterID != uuid.Nil {
		afterIdentifier = afterID
	}
	rows, err := tx.Query(ctx, `
		SELECT document
		FROM app.read_sla_configuration_v2($1, $2, $3, $4, $5, $6, $7)`,
		tenantID, string(kind), resource, nullableString(afterKey), afterIdentifier, limit, includeArchived,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([][]byte, 0, limit)
	for rows.Next() {
		var document []byte
		if err := rows.Scan(&document); err != nil {
			return nil, err
		}
		result = append(result, slices.Clone(document))
	}
	return result, rows.Err()
}

func readSingleSLAConfiguration(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	kind application.ArchiveKind,
	id uuid.UUID,
) ([]byte, error) {
	documents, err := readSLAConfigurationPage(ctx, tx, tenantID, kind, id, "", uuid.Nil, 1, true)
	if err != nil {
		return nil, err
	}
	if len(documents) == 0 {
		return nil, pgx.ErrNoRows
	}
	if len(documents) != 1 {
		return nil, errors.New("database returned duplicate SLA configuration rows")
	}
	return documents[0], nil
}

func readSLAConfigurationRevision(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	kind application.ArchiveKind,
	id kernel.EntityID,
	version uint64,
	capability application.Capability,
) ([]byte, error) {
	var document []byte
	err := tx.QueryRow(ctx, `
		SELECT document
		FROM app.read_sla_configuration_revision_v2($1, $2, $3, $4, $5)`,
		tenantID, string(kind), slaUUID(id), version, string(capability),
	).Scan(&document)
	return document, err
}

func readSLAMetricDefinition(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	id kernel.EntityID,
	capability application.Capability,
) (kernel.MetricDefinition, error) {
	var document []byte
	if err := tx.QueryRow(ctx, `
		SELECT document
		FROM app.read_sla_metric_definition_v2($1, $2, $3)`,
		tenantID, slaUUID(id), string(capability),
	).Scan(&document); err != nil {
		return kernel.MetricDefinition{}, err
	}
	var decoded slaMetricDocument
	if err := unmarshalSLADocument(document, &decoded); err != nil {
		return kernel.MetricDefinition{}, err
	}
	metric, err := decodeSLAMetric(decoded)
	if err != nil || metric.ID() != id {
		return kernel.MetricDefinition{}, errors.New("database returned the wrong SLA metric definition")
	}
	return metric, nil
}

func loadPolicyCalendars(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	policy kernel.Policy,
	capability application.Capability,
) ([]kernel.BusinessCalendar, error) {
	type reference struct {
		id      kernel.EntityID
		version uint64
	}
	references := make(map[reference]struct{})
	for _, metric := range policy.Metrics() {
		calendarID := metric.CalendarID()
		if calendarID != nil {
			references[reference{id: *calendarID, version: metric.CalendarVersion()}] = struct{}{}
		}
	}
	ordered := make([]reference, 0, len(references))
	for value := range references {
		ordered = append(ordered, value)
	}
	sort.Slice(ordered, func(left, right int) bool {
		return ordered[left].id.String() < ordered[right].id.String() ||
			ordered[left].id == ordered[right].id && ordered[left].version < ordered[right].version
	})
	result := make([]kernel.BusinessCalendar, len(ordered))
	for index, value := range ordered {
		document, err := readSLAConfigurationRevision(
			ctx, tx, tenantID, application.ArchiveCalendar, value.id, value.version, capability,
		)
		if err != nil {
			return nil, err
		}
		record, err := decodeSLACalendar(tenantID, document)
		if err != nil || record.Value.ID() != value.id || record.Value.Version() != value.version {
			return nil, errors.New("database returned the wrong SLA calendar revision")
		}
		result[index] = record.Value
	}
	return result, nil
}

func resolveSLAAuthorityInTransaction(
	ctx context.Context,
	tx databaseTransaction,
	actor application.Actor,
	tenantID uuid.UUID,
	capability application.Capability,
	resource application.Resource,
) (application.Authority, error) {
	if !slaPrincipalMayUseCapability(actor.Kind, capability) {
		return application.Authority{}, authorization.ErrForbidden
	}
	authority, err := phase4Authority(ctx, tx, slaAuthorizationActor(actor), tenantID)
	if err != nil || !validPhase4Authority(authority, actor.MembershipID) ||
		authority.Principal.ID != actor.PrincipalID || authority.TenantID != actor.TenantID {
		if err != nil {
			return application.Authority{}, err
		}
		return application.Authority{}, authorization.ErrForbidden
	}
	// The HTTP surface establishes operator versus customer intent. Compatibility
	// roles are not authorization provenance and cannot safely classify custom or
	// JIT roles (nor read-only operators).
	customer := actor.Kind == application.PrincipalCustomer
	permission, ok := slaAuthorizationPermission(capability)
	if !ok {
		return application.Authority{}, authorization.ErrForbidden
	}
	if customer && !phase4HasPermission(authority, string(permission), authorization.ScopeOwn) {
		return application.Authority{}, authorization.ErrForbidden
	}
	context := authorization.ResourceContext{TenantID: tenantID}
	scope := application.ScopeTenant
	if resource != (application.Resource{}) {
		context, err = loadSLAResourceContext(ctx, tx, actor, tenantID, resource, customer)
		if err != nil {
			return application.Authority{}, err
		}
		scope, err = matchedSLAScope(authority, permission, context, customer)
		if err != nil {
			return application.Authority{}, err
		}
	}
	if err := (authorization.Evaluator{}).RequireTenant(authority, permission, context); err != nil {
		return application.Authority{}, err
	}
	permissionEpoch, subjectEpoch, err := loadSLAAuthorityEpochs(ctx, tx, tenantID, actor.MembershipID)
	if err != nil {
		return application.Authority{}, err
	}
	var roleKeys []kernel.Key
	audience := application.AudienceOperator
	if customer {
		audience = application.AudienceCustomer
	} else {
		roleKeys, err = slaRoleKeys(authority)
		if err != nil {
			return application.Authority{}, err
		}
	}
	return application.Authority{
		TenantID: tenantID, PrincipalID: actor.PrincipalID, MembershipID: actor.MembershipID,
		Capability: capability, Resource: resource, Scope: scope, Audience: audience, Allowed: true,
		RoleKeys: roleKeys, PermissionEpoch: permissionEpoch, SubjectEpoch: subjectEpoch,
		EvaluatedAt: authority.EvaluatedAt, ValidUntil: authority.EvaluatedAt.Add(30 * time.Second),
	}, nil
}

func slaPrincipalMayUseCapability(kind application.PrincipalKind, capability application.Capability) bool {
	switch kind {
	case application.PrincipalCustomer:
		return capability == application.CapabilityPortalAlertRead || capability == application.CapabilityPortalCaseRead
	case application.PrincipalOperator:
		switch capability {
		case application.CapabilityRead, application.CapabilityManage, application.CapabilitySimulate,
			application.CapabilityAlertRead, application.CapabilityCaseRead,
			application.CapabilityAlertOverride, application.CapabilityCaseOverride:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func recheckSLAAuthority(
	ctx context.Context,
	tx databaseTransaction,
	actor application.Actor,
	tenantID uuid.UUID,
	capability application.Capability,
	resource application.Resource,
	claimed application.Authority,
) error {
	current, err := resolveSLAAuthorityInTransaction(ctx, tx, actor, tenantID, capability, resource)
	if err != nil {
		return err
	}
	if current.TenantID != claimed.TenantID || current.PrincipalID != claimed.PrincipalID ||
		current.MembershipID != claimed.MembershipID || current.Capability != claimed.Capability ||
		current.Resource != claimed.Resource || current.Scope != claimed.Scope ||
		current.Audience != claimed.Audience || current.PermissionEpoch != claimed.PermissionEpoch ||
		current.SubjectEpoch != claimed.SubjectEpoch || !slices.Equal(current.RoleKeys, claimed.RoleKeys) {
		return authorization.ErrForbidden
	}
	return nil
}

func loadSLAResourceContext(
	ctx context.Context,
	tx databaseTransaction,
	actor application.Actor,
	tenantID uuid.UUID,
	resource application.Resource,
	customer bool,
) (authorization.ResourceContext, error) {
	if resource.ObjectType != kernel.ObjectAlert && resource.ObjectType != kernel.ObjectCase {
		return authorization.ResourceContext{}, authorization.ErrForbidden
	}
	if customer {
		return loadSLACustomerResourceContext(ctx, tx, actor, tenantID, resource)
	}
	table, ownerColumn := "public.alerts", "created_by"
	if resource.ObjectType == kernel.ObjectCase {
		table, ownerColumn = "public.cases", "created_by_user_id"
	}
	query := fmt.Sprintf(`
		SELECT ticket.%s, ticket.assignee_user_id, ticket.claimed_by_user_id,
		       ticket.assigned_team_id, ticket.assigned_team_epoch_id
		FROM %s AS ticket
		WHERE ticket.tenant_id = $1 AND ticket.id = $2`, ownerColumn, table)
	var owner, assignee, claimed, team, epoch *uuid.UUID
	if err := tx.QueryRow(ctx, query, tenantID, slaUUID(resource.ObjectID)).Scan(
		&owner, &assignee, &claimed, &team, &epoch,
	); err != nil {
		return authorization.ResourceContext{}, err
	}
	if (team == nil) != (epoch == nil) {
		return authorization.ResourceContext{}, errors.New("database returned an invalid SLA team relationship")
	}
	context := authorization.ResourceContext{TenantID: tenantID, OwnerID: owner}
	if assignee != nil && *assignee == actor.PrincipalID {
		context.AssigneeID = assignee
	} else if claimed != nil && *claimed == actor.PrincipalID {
		context.AssigneeID = claimed
	} else {
		context.AssigneeID = assignee
	}
	if team != nil {
		context.OperatorTeamRelationship = &authorization.OperatorTeamRelationship{
			OperatorTeamID: *team, AssignmentEpochID: *epoch,
		}
	}
	return context, nil
}

func loadSLACustomerResourceContext(
	ctx context.Context,
	tx databaseTransaction,
	actor application.Actor,
	tenantID uuid.UUID,
	resource application.Resource,
) (authorization.ResourceContext, error) {
	table, resourceColumn, aggregateKind := "public.alerts", "alert_id", "alert"
	if resource.ObjectType == kernel.ObjectCase {
		table, resourceColumn, aggregateKind = "public.cases", "case_id", "case"
	}
	query := fmt.Sprintf(`
		SELECT $3::uuid
		FROM public.customer_contacts AS contact
		JOIN public.ticket_customer_contacts AS link
		  ON link.tenant_id = contact.tenant_id
		 AND link.contact_id = contact.id
		 AND link.%s = $4
		 AND link.archived_at IS NULL
		JOIN %s AS ticket
		  ON ticket.tenant_id = link.tenant_id
		 AND ticket.id = link.%s
		JOIN public.ticket_workflow_versions AS workflow
		  ON workflow.tenant_id = ticket.tenant_id
		 AND workflow.workflow_id = ticket.workflow_id
		 AND workflow.version = ticket.workflow_version
		 AND workflow.aggregate_kind = $5::public.ticket_aggregate_kind
		JOIN LATERAL (
		  SELECT min(state.value ->> 'visibility') AS visibility
		  FROM jsonb_array_elements(workflow.states) AS state(value)
		  WHERE state.value ->> 'key' = ticket.state_key
		  HAVING count(*) = 1
		) AS customer_state ON customer_state.visibility = 'customer'
		WHERE contact.tenant_id = $1
		  AND contact.linked_membership_id = $2
		  AND contact.linked_user_id = $3
		  AND contact.active
		  AND contact.archived_at IS NULL
		  AND ticket.customer_visible`, resourceColumn, table, resourceColumn)
	var principal uuid.UUID
	if err := tx.QueryRow(
		ctx, query, tenantID, actor.MembershipID, actor.PrincipalID, slaUUID(resource.ObjectID), aggregateKind,
	).Scan(&principal); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Missing, hidden, inactive, unlinked, and cross-tenant tickets are
			// deliberately indistinguishable on the customer route.
			return authorization.ResourceContext{}, authorization.ErrForbidden
		}
		return authorization.ResourceContext{}, err
	}
	if principal != actor.PrincipalID {
		return authorization.ResourceContext{}, authorization.ErrForbidden
	}
	return authorization.ResourceContext{TenantID: tenantID, OwnerID: &principal}, nil
}

func matchedSLAScope(
	authority authorization.TenantAuthority,
	permission authorization.TenantPermission,
	resource authorization.ResourceContext,
	customer bool,
) (application.Scope, error) {
	if customer {
		if phase4HasPermission(authority, string(permission), authorization.ScopeOwn) {
			return application.ScopeOwn, nil
		}
		return "", authorization.ErrForbidden
	}
	tests := []struct {
		scope authorization.Scope
		value application.Scope
	}{
		{authorization.ScopeTenant, application.ScopeTenant},
		{authorization.ScopeOwn, application.ScopeOwn},
		{authorization.ScopeAssigned, application.ScopeAssigned},
		{authorization.ScopeOperatorTeam, application.ScopeOperatorTeam},
	}
	evaluator := authorization.Evaluator{}
	for _, test := range tests {
		candidate := authority
		candidate.Permissions = []authorization.ScopedPermission{{Permission: permission, Scope: test.scope}}
		if phase4HasPermission(authority, string(permission), test.scope) &&
			evaluator.RequireTenant(candidate, permission, resource) == nil {
			return test.value, nil
		}
	}
	return "", authorization.ErrForbidden
}

func loadSLAAuthorityEpochs(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	membershipID uuid.UUID,
) (uint64, uint64, error) {
	var permissionEpoch, subjectEpoch int64
	if err := tx.QueryRow(ctx, `
		SELECT state.revision, profile.version
		FROM public.tenant_authorization_states AS state
		JOIN public.tenant_user_profiles AS profile
		  ON profile.tenant_id = state.tenant_id
		 AND profile.membership_id = $2
		WHERE state.tenant_id = $1`, tenantID, membershipID,
	).Scan(&permissionEpoch, &subjectEpoch); err != nil {
		return 0, 0, err
	}
	if permissionEpoch < 1 || subjectEpoch < 1 {
		return 0, 0, errors.New("database returned invalid SLA authority epochs")
	}
	return uint64(permissionEpoch), uint64(subjectEpoch), nil
}

func slaRoleKeys(authority authorization.TenantAuthority) ([]kernel.Key, error) {
	seen := make(map[string]struct{}, len(authority.RoleGrants))
	values := make([]string, 0, len(authority.RoleGrants))
	for _, grant := range authority.RoleGrants {
		if _, exists := seen[grant.RoleKey]; exists {
			continue
		}
		seen[grant.RoleKey] = struct{}{}
		values = append(values, grant.RoleKey)
	}
	sort.Strings(values)
	result := make([]kernel.Key, len(values))
	for index, value := range values {
		key, err := kernel.NewKey(value)
		if err != nil {
			return nil, errors.New("database returned an invalid SLA role key")
		}
		result[index] = key
	}
	return result, nil
}

func slaAuthorizationActor(actor application.Actor) authorization.Actor {
	return authorization.Actor{
		UserID: actor.PrincipalID, SessionID: actor.SessionID,
		ActiveTenantID: actor.TenantID, AuthenticationMethod: actor.AuthenticationMethod,
	}
}

func slaAuthorizationPermission(capability application.Capability) (authorization.TenantPermission, bool) {
	switch capability {
	case application.CapabilityRead:
		return authorization.TenantPermissionSLARead, true
	case application.CapabilityManage:
		return authorization.TenantPermissionSLAManage, true
	case application.CapabilitySimulate:
		return authorization.TenantPermissionSLASimulate, true
	case application.CapabilityAlertRead:
		return authorization.TenantPermissionAlertRead, true
	case application.CapabilityCaseRead:
		return authorization.TenantPermissionCaseRead, true
	case application.CapabilityPortalAlertRead:
		return authorization.TenantPermissionPortalAlertRead, true
	case application.CapabilityPortalCaseRead:
		return authorization.TenantPermissionPortalCaseRead, true
	case application.CapabilityAlertOverride:
		return authorization.TenantPermissionAlertSLAOverride, true
	case application.CapabilityCaseOverride:
		return authorization.TenantPermissionCaseSLAOverride, true
	default:
		return "", false
	}
}

func decodeSLAConfigurationCursor(value string) (string, uuid.UUID, error) {
	if value == "" {
		return "", uuid.Nil, nil
	}
	key, id, err := application.DecodeConfigurationCursor(value)
	if err != nil {
		return "", uuid.Nil, application.ErrRepositoryConflict
	}
	return key.String(), slaUUID(id), nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func mapSLADatabaseError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, application.ErrRepositoryForbidden), errors.Is(err, authorization.ErrForbidden):
		return application.ErrRepositoryForbidden
	case errors.Is(err, application.ErrRepositoryNotFound), errors.Is(err, authorization.ErrNotFound), errors.Is(err, pgx.ErrNoRows):
		return application.ErrRepositoryNotFound
	case errors.Is(err, application.ErrRepositoryPrecondition):
		return application.ErrRepositoryPrecondition
	case errors.Is(err, application.ErrRepositoryConflict), errors.Is(err, authorization.ErrConflict):
		return application.ErrRepositoryConflict
	}
	switch postgresCode(err) {
	case "42501":
		return application.ErrRepositoryForbidden
	case "P0002":
		return application.ErrRepositoryNotFound
	case "40001":
		return application.ErrRepositoryPrecondition
	case "23505", "23503", "23514", "40P01", "22023", "22P02", "55000":
		return application.ErrRepositoryConflict
	default:
		return err
	}
}
