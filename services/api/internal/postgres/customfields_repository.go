package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	kernel "github.com/periapsis-im/periapsis/modules/customfields"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/customfields"
)

const customDefinitionColumns = `
	definition.id, definition.tenant_id, definition.object_type::text,
	definition.key, definition.label, definition.description,
	definition.data_type::text, definition.required, definition.nullable,
	definition.has_default, definition.default_value,
	definition.minimum_length, definition.maximum_length,
	definition.minimum_number, definition.maximum_number,
	definition.validation_pattern,
	definition.show_in_create, definition.show_in_detail,
	definition.show_in_list, definition.show_in_export,
	definition.required_on_transitions, definition.searchable,
	definition.filterable, definition.sortable,
	definition.allow_structured_json, definition.schema_version,
	definition.archived_at`

type CustomFieldRepository struct {
	begin transactionBeginner
	newID func() (uuid.UUID, error)
}

func NewCustomFieldRepository(pool *pgxpool.Pool) *CustomFieldRepository {
	if pool == nil {
		return nil
	}
	return &CustomFieldRepository{begin: poolTransactionBeginner(pool), newID: uuid.NewV7}
}

func (repository *CustomFieldRepository) ResolveAccess(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	capability application.Capability,
) (application.Access, error) {
	if repository == nil || repository.begin == nil {
		return application.Access{}, errors.New("custom-field repository is not configured")
	}
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.Access, error) {
			authority, resolveErr := phase4Authority(ctx, tx, customAuthorizationActor(actor), tenantID)
			if resolveErr != nil {
				return application.Access{}, resolveErr
			}
			return customAccess(authority, actor, capability)
		},
	)
	return result, mapCustomFieldDatabaseError(err)
}

func (repository *CustomFieldRepository) ResolveDefinitionInventoryAccess(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
) (application.Access, error) {
	if repository == nil || repository.begin == nil {
		return application.Access{}, errors.New("custom-field repository is not configured")
	}
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.Access, error) {
			return resolveCustomDefinitionInventoryAccessInTransaction(ctx, tx, actor, tenantID)
		},
	)
	return result, mapCustomFieldDatabaseError(err)
}

func (repository *CustomFieldRepository) ListDefinitions(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	input application.DefinitionListInput,
	claimedAccess application.Access,
) (application.DefinitionPage, error) {
	afterKey, afterID, err := decodeCustomDefinitionCursor(input.After)
	if err != nil {
		return application.DefinitionPage{}, application.ErrRepositoryConflict
	}
	page, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.DefinitionPage, error) {
			access, accessErr := resolveCustomDefinitionInventoryAccessInTransaction(ctx, tx, actor, tenantID)
			if accessErr != nil || !sameCustomAccess(access, claimedAccess) {
				if accessErr != nil {
					return application.DefinitionPage{}, accessErr
				}
				return application.DefinitionPage{}, authorization.ErrForbidden
			}
			arguments := []any{tenantID, string(input.ObjectType), input.IncludeArchived, input.Limit + 1}
			query := `SELECT ` + customDefinitionColumns + `
				FROM public.custom_field_definitions AS definition
				WHERE definition.tenant_id = $1
				  AND definition.object_type = $2::public.custom_field_object_type
				  AND ($3 OR definition.archived_at IS NULL)`
			if !access.Manage {
				arguments = append(arguments, string(access.Audience))
				query += fmt.Sprintf(` AND EXISTS (
					SELECT 1 FROM public.custom_field_permissions AS permission
					WHERE permission.tenant_id = definition.tenant_id
					  AND permission.definition_id = definition.id
					  AND permission.audience = $%d::public.custom_field_audience
					  AND permission.can_read
					  AND permission.schema_version = definition.schema_version
				)`, len(arguments))
			}
			if input.After != "" {
				arguments = append(arguments, afterKey.String(), afterID)
				query += fmt.Sprintf(" AND (definition.key, definition.id) > ($%d, $%d)", len(arguments)-1, len(arguments))
			}
			query += " ORDER BY definition.key, definition.id LIMIT $4"
			rows, queryErr := tx.Query(ctx, query, arguments...)
			if queryErr != nil {
				return application.DefinitionPage{}, queryErr
			}
			defer rows.Close()
			bases := make([]customDefinitionRow, 0, input.Limit+1)
			for rows.Next() {
				base, scanErr := scanCustomDefinitionRow(rows)
				if scanErr != nil {
					return application.DefinitionPage{}, scanErr
				}
				bases = append(bases, base)
			}
			if rows.Err() != nil {
				return application.DefinitionPage{}, rows.Err()
			}
			hasMore := len(bases) > input.Limit
			if hasMore {
				bases = bases[:input.Limit]
			}
			items := make([]kernel.Definition, len(bases))
			for index, base := range bases {
				definition, hydrateErr := hydrateCustomDefinition(ctx, tx, base)
				if hydrateErr != nil {
					return application.DefinitionPage{}, hydrateErr
				}
				if !access.Manage && !definition.VisibleTo(access.Audience) {
					return application.DefinitionPage{}, errors.New("database returned a hidden custom-field definition")
				}
				items[index] = definition
			}
			result := application.DefinitionPage{Items: items}
			if hasMore && len(bases) != 0 {
				last := bases[len(bases)-1]
				result.NextCursor = encodeCustomDefinitionCursor(last.key, last.id)
			}
			return result, nil
		},
	)
	return page, mapCustomFieldDatabaseError(err)
}

func (repository *CustomFieldRepository) GetDefinition(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	objectType kernel.ObjectType,
	id kernel.EntityID,
	claimedAccess application.Access,
) (kernel.Definition, error) {
	identifier := uuid.UUID(id.Bytes())
	definition, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (kernel.Definition, error) {
			var access application.Access
			var accessErr error
			if claimedAccess.DefinitionInventory {
				access, accessErr = resolveCustomDefinitionInventoryAccessInTransaction(ctx, tx, actor, tenantID)
			} else {
				access, accessErr = resolveCustomAccessInTransaction(
					ctx, tx, actor, tenantID, accessCapability(claimedAccess),
				)
			}
			if accessErr != nil || !sameCustomAccess(access, claimedAccess) {
				if accessErr != nil {
					return kernel.Definition{}, accessErr
				}
				return kernel.Definition{}, authorization.ErrForbidden
			}
			value, loadErr := loadCustomDefinition(ctx, tx, tenantID, objectType, identifier)
			if loadErr != nil {
				return kernel.Definition{}, loadErr
			}
			if !access.Manage && !value.VisibleTo(access.Audience) {
				return kernel.Definition{}, pgx.ErrNoRows
			}
			return value, nil
		},
	)
	return definition, mapCustomFieldDatabaseError(err)
}

func (repository *CustomFieldRepository) InspectDefinitionUpdate(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	current kernel.Definition,
	proposed kernel.DefinitionInput,
	expectedVersion uint64,
) (kernel.DefinitionUpdateState, error) {
	probe, err := kernel.NewDefinition(proposed)
	if err != nil || expectedVersion != current.SchemaVersion() ||
		probe.SchemaVersion() != expectedVersion+1 {
		return kernel.DefinitionUpdateState{}, application.ErrRepositoryPrecondition
	}
	state, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (kernel.DefinitionUpdateState, error) {
			access, accessErr := resolveCustomAccessInTransaction(
				ctx, tx, actor, tenantID, application.CapabilityManage,
			)
			if accessErr != nil || !access.Manage {
				if accessErr != nil {
					return kernel.DefinitionUpdateState{}, accessErr
				}
				return kernel.DefinitionUpdateState{}, authorization.ErrForbidden
			}
			stored, loadErr := loadCustomDefinition(
				ctx, tx, tenantID, current.ObjectType(), uuid.UUID(current.ID().Bytes()),
			)
			if loadErr != nil {
				return kernel.DefinitionUpdateState{}, loadErr
			}
			if !sameCustomDefinition(stored, current) {
				return kernel.DefinitionUpdateState{}, application.ErrRepositoryPrecondition
			}
			rows, queryErr := tx.Query(ctx, `
				SELECT presence::text, canonical_value
				FROM public.custom_field_values
				WHERE tenant_id = $1 AND definition_id = $2
				ORDER BY id`, tenantID, uuid.UUID(current.ID().Bytes()))
			if queryErr != nil {
				return kernel.DefinitionUpdateState{}, queryErr
			}
			defer rows.Close()
			result := kernel.DefinitionUpdateState{ExpectedSchemaVersion: expectedVersion}
			valueCount := int64(0)
			for rows.Next() {
				var presence string
				var canonical []byte
				if scanErr := rows.Scan(&presence, &canonical); scanErr != nil {
					return kernel.DefinitionUpdateState{}, scanErr
				}
				valueCount++
				result.HasStoredValues = true
				if presence == "null" {
					result.HasStoredNullValues = true
				} else if presence != "present" {
					return kernel.DefinitionUpdateState{}, errors.New("database returned an invalid custom-field value presence")
				}
				if _, restoreErr := kernel.RestoreFieldValue(probe, canonical); restoreErr != nil {
					result.HasIncompatibleValues = true
				}
			}
			if rows.Err() != nil {
				return kernel.DefinitionUpdateState{}, rows.Err()
			}
			objectTable := "public.alerts"
			if current.ObjectType() == kernel.ObjectCase {
				objectTable = "public.cases"
			}
			var objectCount int64
			if queryErr = tx.QueryRow(ctx, "SELECT count(*) FROM "+objectTable+" WHERE tenant_id = $1", tenantID).Scan(&objectCount); queryErr != nil {
				return kernel.DefinitionUpdateState{}, queryErr
			}
			if valueCount > objectCount {
				return kernel.DefinitionUpdateState{}, errors.New("database returned more custom-field values than tenant objects")
			}
			result.HasMissingValues = objectCount > valueCount
			optionRows, optionErr := tx.Query(ctx, `
				SELECT DISTINCT option_key
				FROM public.custom_field_values AS value
				CROSS JOIN LATERAL unnest(value.option_keys) AS option_key
				WHERE value.tenant_id = $1 AND value.definition_id = $2
				ORDER BY option_key`, tenantID, uuid.UUID(current.ID().Bytes()))
			if optionErr != nil {
				return kernel.DefinitionUpdateState{}, optionErr
			}
			for optionRows.Next() {
				var raw string
				if scanErr := optionRows.Scan(&raw); scanErr != nil {
					optionRows.Close()
					return kernel.DefinitionUpdateState{}, scanErr
				}
				key, keyErr := kernel.NewKey(raw)
				if keyErr != nil {
					optionRows.Close()
					return kernel.DefinitionUpdateState{}, errors.New("database returned an invalid used custom-field option")
				}
				result.UsedOptionKeys = append(result.UsedOptionKeys, key)
			}
			optionRows.Close()
			if optionRows.Err() != nil {
				return kernel.DefinitionUpdateState{}, optionRows.Err()
			}
			migration, migrationErr := loadCompletedCustomFieldMigration(
				ctx, tx, current, probe,
			)
			if migrationErr != nil {
				return kernel.DefinitionUpdateState{}, migrationErr
			}
			result.Migration = migration
			return result, nil
		},
	)
	return state, mapCustomFieldDatabaseError(err)
}

func (repository *CustomFieldRepository) CreateDefinition(
	ctx context.Context,
	write application.DefinitionWrite,
) (application.DefinitionResult, error) {
	if !validCustomCommand(write.Command, "custom_field.definition.create") ||
		write.ExpectedVersion != 0 || write.Definition.SchemaVersion() != 1 ||
		write.Definition.Archived() {
		return application.DefinitionResult{}, application.ErrRepositoryConflict
	}
	return repository.writeDefinition(ctx, write, nil)
}

func (repository *CustomFieldRepository) ReplaceDefinition(
	ctx context.Context,
	write application.DefinitionWrite,
) (application.DefinitionResult, error) {
	if !validCustomCommand(write.Command, "custom_field.definition.replace") ||
		write.ExpectedVersion == 0 || write.Definition.SchemaVersion() != write.ExpectedVersion+1 {
		return application.DefinitionResult{}, application.ErrRepositoryPrecondition
	}
	return repository.writeDefinition(ctx, write, nil)
}

func (repository *CustomFieldRepository) ArchiveDefinition(
	ctx context.Context,
	archive application.DefinitionArchive,
) (application.DefinitionResult, error) {
	if !validCustomCommand(archive.Command, "custom_field.definition.archive") ||
		archive.ExpectedVersion == 0 || !archive.Archived.Archived() ||
		archive.Archived.SchemaVersion() != archive.ExpectedVersion+1 ||
		!sameCustomDefinitionIdentity(archive.Current, archive.Archived) {
		return application.DefinitionResult{}, application.ErrRepositoryPrecondition
	}
	write := application.DefinitionWrite{
		Actor: archive.Actor, Definition: archive.Archived,
		ExpectedVersion: archive.ExpectedVersion, Command: archive.Command, Audit: archive.Audit,
	}
	return repository.writeDefinition(ctx, write, &archive.Reason)
}

func (repository *CustomFieldRepository) writeDefinition(
	ctx context.Context,
	write application.DefinitionWrite,
	archiveReason *string,
) (application.DefinitionResult, error) {
	tenantID := uuid.UUID(write.Definition.TenantID().Bytes())
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.DefinitionResult, error) {
			access, accessErr := resolveCustomAccessInTransaction(
				ctx, tx, write.Actor, tenantID, application.CapabilityManage,
			)
			if accessErr != nil || !access.Manage {
				if accessErr != nil {
					return application.DefinitionResult{}, accessErr
				}
				return application.DefinitionResult{}, authorization.ErrForbidden
			}
			if traceErr := installPersistedTraceContext(ctx, tx); traceErr != nil {
				return application.DefinitionResult{}, traceErr
			}
			current, loadErr := loadCustomDefinition(
				ctx, tx, tenantID, write.Definition.ObjectType(), uuid.UUID(write.Definition.ID().Bytes()),
			)
			if loadErr == nil {
				if sameCustomDefinition(current, write.Definition) {
					return application.DefinitionResult{Definition: current, Replayed: true}, nil
				}
				if write.ExpectedVersion == 0 || current.SchemaVersion() != write.ExpectedVersion {
					return application.DefinitionResult{}, application.ErrRepositoryPrecondition
				}
			} else if !errors.Is(loadErr, pgx.ErrNoRows) {
				return application.DefinitionResult{}, loadErr
			} else if write.ExpectedVersion != 0 {
				return application.DefinitionResult{}, pgx.ErrNoRows
			}
			ids, idErr := phase4NewIDs(repository.newID, 3)
			if idErr != nil {
				return application.DefinitionResult{}, idErr
			}
			if write.ExpectedVersion == 0 {
				if insertErr := insertCustomDefinition(ctx, tx, write); insertErr != nil {
					return application.DefinitionResult{}, insertErr
				}
			} else {
				if updateErr := updateCustomDefinition(ctx, tx, write, archiveReason); updateErr != nil {
					return application.DefinitionResult{}, updateErr
				}
			}
			if optionErr := persistCustomDefinitionOptions(
				ctx, tx, tenantID, current, write.Definition,
			); optionErr != nil {
				return application.DefinitionResult{}, optionErr
			}
			if permissionErr := persistCustomDefinitionPermissions(ctx, tx, write.Definition); permissionErr != nil {
				return application.DefinitionResult{}, permissionErr
			}
			snapshot, snapshotErr := customDefinitionSnapshot(write.Definition)
			if snapshotErr != nil {
				return application.DefinitionResult{}, snapshotErr
			}
			if _, revisionErr := tx.Exec(ctx, `
				INSERT INTO public.custom_field_definition_revisions (
					id, tenant_id, definition_id, object_type, schema_version,
					snapshot, created_by_membership_id
				) VALUES ($1, $2, $3, $4::public.custom_field_object_type, $5, $6::jsonb, $7)`,
				ids[0], tenantID, uuid.UUID(write.Definition.ID().Bytes()),
				string(write.Definition.ObjectType()), int64(write.Definition.SchemaVersion()),
				string(snapshot), write.Actor.MembershipID,
			); revisionErr != nil {
				return application.DefinitionResult{}, revisionErr
			}
			action := "custom_field.definition.created"
			before := map[string]any{}
			if write.ExpectedVersion != 0 {
				action = "custom_field.definition.replaced"
				before = customDefinitionJournalProjection(current)
			}
			metadata := map[string]any{"commandOperation": write.Command.Operation}
			if archiveReason != nil {
				action = "custom_field.definition.archived"
				metadata["archiveReasonProvided"] = true
			}
			effectErr := appendPhase4MutationEffects(ctx, tx, phase4MutationEffects{
				PermissionKey: "custom_field.manage", Action: action,
				ResourceType:    "custom_field_definition",
				ResourceID:      uuid.UUID(write.Definition.ID().Bytes()),
				ResourceVersion: int64(write.Definition.SchemaVersion()),
				Summary:         "Custom field definition changed",
				Before:          before, After: customDefinitionJournalProjection(write.Definition),
				Metadata: metadata, AuditEventID: ids[1], OutboxEventID: ids[2],
				RequestID: write.Audit.RequestID, CorrelationID: write.Audit.CorrelationID,
				IPAddress: write.Audit.IPAddress, UserAgent: write.Audit.UserAgent,
				AuthenticationMethod: write.Actor.AuthenticationMethod,
			})
			if effectErr != nil {
				return application.DefinitionResult{}, effectErr
			}
			stored, storedErr := loadCustomDefinition(
				ctx, tx, tenantID, write.Definition.ObjectType(), uuid.UUID(write.Definition.ID().Bytes()),
			)
			if storedErr != nil || !sameCustomDefinition(stored, write.Definition) {
				if storedErr != nil {
					return application.DefinitionResult{}, storedErr
				}
				return application.DefinitionResult{}, errors.New("database returned a divergent custom-field definition")
			}
			return application.DefinitionResult{Definition: stored}, nil
		},
	)
	return result, mapCustomFieldDatabaseError(err)
}

func (repository *CustomFieldRepository) ResolveObjectWriteAccess(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	objectType kernel.ObjectType,
	objectID uuid.UUID,
) (application.Access, error) {
	access, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.Access, error) {
			authority, resolveErr := phase4Authority(ctx, tx, customAuthorizationActor(actor), tenantID)
			if resolveErr != nil {
				return application.Access{}, resolveErr
			}
			return resolveCustomObjectAccess(ctx, tx, actor, authority, objectType, objectID, true)
		},
	)
	return access, mapCustomFieldDatabaseError(err)
}

func (repository *CustomFieldRepository) LoadObjectFields(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	objectType kernel.ObjectType,
	objectID uuid.UUID,
	claimedAccess application.Access,
) ([]kernel.Definition, []kernel.FieldValue, uint64, error) {
	type objectProjection struct {
		definitions []kernel.Definition
		values      []kernel.FieldValue
		version     uint64
	}
	projection, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (objectProjection, error) {
			authority, resolveErr := phase4Authority(ctx, tx, customAuthorizationActor(actor), tenantID)
			if resolveErr != nil {
				return objectProjection{}, resolveErr
			}
			access, accessErr := resolveCustomObjectAccess(
				ctx, tx, actor, authority, objectType, objectID, claimedAccess.Write,
			)
			if accessErr != nil || !sameCustomAccess(access, claimedAccess) {
				if accessErr != nil {
					return objectProjection{}, accessErr
				}
				return objectProjection{}, authorization.ErrForbidden
			}
			version, versionErr := loadCustomObjectVersion(ctx, tx, tenantID, objectType, objectID)
			if versionErr != nil {
				return objectProjection{}, versionErr
			}
			definitions, definitionErr := loadCustomObjectDefinitions(ctx, tx, tenantID, objectType)
			if definitionErr != nil {
				return objectProjection{}, definitionErr
			}
			values, valueErr := loadCustomObjectValues(
				ctx, tx, tenantID, objectType, objectID, definitions,
			)
			if valueErr != nil {
				return objectProjection{}, valueErr
			}
			return objectProjection{definitions: definitions, values: values, version: version}, nil
		},
	)
	if err != nil {
		return nil, nil, 0, mapCustomFieldDatabaseError(err)
	}
	return projection.definitions, projection.values, projection.version, nil
}

func (repository *CustomFieldRepository) CommitObjectFields(
	context.Context,
	application.ObjectFieldWrite,
) (application.ObjectWriteResult, error) {
	// 0089 can journal custom-field writes only through
	// custom_field.manage@tenant. Reusing that privilege would bypass the
	// Alert/Case resource scope and customer edit policy. The append-only ABI
	// successor provides the dedicated object-write entry point; until then the
	// adapter remains deliberately fail closed.
	return application.ObjectWriteResult{}, application.ErrRepositoryForbidden
}

type customDefinitionRow struct {
	id                    uuid.UUID
	tenantID              uuid.UUID
	objectType            string
	key                   string
	label                 string
	description           string
	dataType              string
	required              bool
	nullable              bool
	hasDefault            bool
	defaultValue          []byte
	minimumLength         *int32
	maximumLength         *int32
	minimumNumber         *string
	maximumNumber         *string
	validationPattern     *string
	showInCreate          bool
	showInDetail          bool
	showInList            bool
	showInExport          bool
	requiredOnTransitions []string
	searchable            bool
	filterable            bool
	sortable              bool
	allowStructuredJSON   bool
	schemaVersion         int64
	archivedAt            *time.Time
}

type customDefinitionScanner interface {
	Scan(...any) error
}

func scanCustomDefinitionRow(scanner customDefinitionScanner) (customDefinitionRow, error) {
	var row customDefinitionRow
	err := scanner.Scan(
		&row.id, &row.tenantID, &row.objectType, &row.key, &row.label, &row.description,
		&row.dataType, &row.required, &row.nullable, &row.hasDefault, &row.defaultValue,
		&row.minimumLength, &row.maximumLength, &row.minimumNumber, &row.maximumNumber,
		&row.validationPattern, &row.showInCreate, &row.showInDetail, &row.showInList,
		&row.showInExport, &row.requiredOnTransitions, &row.searchable, &row.filterable,
		&row.sortable, &row.allowStructuredJSON, &row.schemaVersion, &row.archivedAt,
	)
	if err != nil {
		return customDefinitionRow{}, err
	}
	if !authorizationUUIDv7(row.id) || !authorizationUUIDv7(row.tenantID) ||
		row.schemaVersion < 1 || row.schemaVersion > math.MaxInt64 {
		return customDefinitionRow{}, errors.New("database returned an invalid custom-field definition row")
	}
	return row, nil
}

func loadCustomDefinition(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	objectType kernel.ObjectType,
	id uuid.UUID,
) (kernel.Definition, error) {
	row, err := scanCustomDefinitionRow(tx.QueryRow(ctx, `SELECT `+customDefinitionColumns+`
		FROM public.custom_field_definitions AS definition
		WHERE definition.tenant_id = $1
		  AND definition.object_type = $2::public.custom_field_object_type
		  AND definition.id = $3`, tenantID, string(objectType), id))
	if err != nil {
		return kernel.Definition{}, err
	}
	return hydrateCustomDefinition(ctx, tx, row)
}

func hydrateCustomDefinition(
	ctx context.Context,
	tx databaseTransaction,
	row customDefinitionRow,
) (kernel.Definition, error) {
	id, err := kernel.ParseEntityID(row.id.String())
	if err != nil {
		return kernel.Definition{}, err
	}
	tenantID, err := kernel.ParseEntityID(row.tenantID.String())
	if err != nil {
		return kernel.Definition{}, err
	}
	key, err := kernel.NewKey(row.key)
	if err != nil {
		return kernel.Definition{}, err
	}
	minimumLength, err := customUint32(row.minimumLength)
	if err != nil {
		return kernel.Definition{}, err
	}
	maximumLength, err := customUint32(row.maximumLength)
	if err != nil {
		return kernel.Definition{}, err
	}
	options, err := loadCustomDefinitionOptions(ctx, tx, row)
	if err != nil {
		return kernel.Definition{}, err
	}
	visibility, editPolicy, err := loadCustomDefinitionPermissions(ctx, tx, row)
	if err != nil {
		return kernel.Definition{}, err
	}
	transitions := make([]kernel.Key, len(row.requiredOnTransitions))
	for index, raw := range row.requiredOnTransitions {
		transitions[index], err = kernel.NewKey(raw)
		if err != nil {
			return kernel.Definition{}, errors.New("database returned an invalid custom-field transition key")
		}
	}
	defaultValue := kernel.MissingInputValue()
	if row.hasDefault {
		if len(row.defaultValue) == 0 || !json.Valid(row.defaultValue) {
			return kernel.Definition{}, errors.New("database returned an invalid custom-field default")
		}
		defaultValue = kernel.JSONInputValue(row.defaultValue)
	} else if row.defaultValue != nil {
		return kernel.Definition{}, errors.New("database returned an unexpected custom-field default")
	}
	minimum, maximum, pattern := "", "", ""
	if row.minimumNumber != nil {
		minimum = *row.minimumNumber
	}
	if row.maximumNumber != nil {
		maximum = *row.maximumNumber
	}
	if row.validationPattern != nil {
		pattern = *row.validationPattern
	}
	definition, err := kernel.NewDefinition(kernel.DefinitionInput{
		ID: id, TenantID: tenantID, ObjectType: kernel.ObjectType(row.objectType),
		Key: key, Label: row.label, Description: row.description,
		DataType: kernel.DataType(row.dataType), Required: row.required, Nullable: row.nullable,
		Default: defaultValue, Constraints: kernel.ConstraintsInput{
			MinimumLength: minimumLength, MaximumLength: maximumLength,
			Minimum: minimum, Maximum: maximum, Pattern: pattern,
		},
		Options: options, Visibility: visibility, EditPolicy: editPolicy,
		Placement: kernel.Placement{
			ShowInCreate: row.showInCreate, ShowInDetail: row.showInDetail,
			ShowInList: row.showInList, ShowInExport: row.showInExport,
		},
		RequiredOnTransitions: transitions, Searchable: row.searchable,
		Filterable: row.filterable, Sortable: row.sortable,
		AllowStructuredJSON: row.allowStructuredJSON, Archived: row.archivedAt != nil,
		SchemaVersion: uint64(row.schemaVersion),
	})
	if err != nil {
		return kernel.Definition{}, errors.New("database returned a non-canonical custom-field definition")
	}
	return definition, nil
}

func loadCustomDefinitionOptions(
	ctx context.Context,
	tx databaseTransaction,
	definition customDefinitionRow,
) ([]kernel.OptionInput, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, key, label, position, introduced_in_schema_version,
		       archived_in_schema_version, archived_at
		FROM public.custom_field_options
		WHERE tenant_id = $1 AND definition_id = $2
		ORDER BY position, id`, definition.tenantID, definition.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]kernel.OptionInput, 0)
	for rows.Next() {
		var id uuid.UUID
		var rawKey, label string
		var position int32
		var introduced int64
		var archivedVersion *int64
		var archivedAt *time.Time
		if scanErr := rows.Scan(
			&id, &rawKey, &label, &position, &introduced, &archivedVersion, &archivedAt,
		); scanErr != nil {
			return nil, scanErr
		}
		if !authorizationUUIDv7(id) || position < 0 || position > math.MaxUint16 ||
			introduced < 1 || introduced > definition.schemaVersion ||
			(archivedVersion == nil) != (archivedAt == nil) ||
			archivedVersion != nil && (*archivedVersion <= introduced || *archivedVersion > definition.schemaVersion) {
			return nil, errors.New("database returned an invalid custom-field option")
		}
		optionID, parseErr := kernel.ParseEntityID(id.String())
		if parseErr != nil {
			return nil, parseErr
		}
		optionKey, keyErr := kernel.NewKey(rawKey)
		if keyErr != nil {
			return nil, keyErr
		}
		result = append(result, kernel.OptionInput{
			ID: optionID, Key: optionKey, Label: label,
			Position: uint16(position), Archived: archivedAt != nil,
		})
	}
	return result, rows.Err()
}

func loadCustomDefinitionPermissions(
	ctx context.Context,
	tx databaseTransaction,
	definition customDefinitionRow,
) (kernel.Visibility, kernel.EditPolicy, error) {
	rows, err := tx.Query(ctx, `
		SELECT audience::text, can_read, can_create, can_update, schema_version
		FROM public.custom_field_permissions
		WHERE tenant_id = $1 AND definition_id = $2
		ORDER BY audience`, definition.tenantID, definition.id)
	if err != nil {
		return kernel.Visibility{}, kernel.EditPolicy{}, err
	}
	defer rows.Close()
	visibility := kernel.Visibility{}
	policy := kernel.EditPolicy{}
	seen := map[string]bool{}
	for rows.Next() {
		var audience string
		var read, create, update bool
		var version int64
		if scanErr := rows.Scan(&audience, &read, &create, &update, &version); scanErr != nil {
			return kernel.Visibility{}, kernel.EditPolicy{}, scanErr
		}
		if seen[audience] || version != definition.schemaVersion || (!read && (create || update)) {
			return kernel.Visibility{}, kernel.EditPolicy{}, errors.New("database returned invalid custom-field permissions")
		}
		seen[audience] = true
		switch audience {
		case "customer":
			visibility.Customer, policy.CustomerCreate, policy.CustomerUpdate = read, create, update
		case "operator":
			visibility.Operator, policy.OperatorCreate, policy.OperatorUpdate = read, create, update
		default:
			return kernel.Visibility{}, kernel.EditPolicy{}, errors.New("database returned an unknown custom-field audience")
		}
	}
	if rows.Err() != nil {
		return kernel.Visibility{}, kernel.EditPolicy{}, rows.Err()
	}
	if !seen["customer"] || !seen["operator"] {
		return kernel.Visibility{}, kernel.EditPolicy{}, errors.New("database returned incomplete custom-field permissions")
	}
	return visibility, policy, nil
}

func customUint32(value *int32) (*uint32, error) {
	if value == nil {
		return nil, nil
	}
	if *value < 0 {
		return nil, errors.New("database returned a negative custom-field length")
	}
	result := uint32(*value)
	return &result, nil
}

func resolveCustomAccessInTransaction(
	ctx context.Context,
	tx databaseTransaction,
	actor application.Actor,
	tenantID uuid.UUID,
	capability application.Capability,
) (application.Access, error) {
	authority, err := phase4Authority(ctx, tx, customAuthorizationActor(actor), tenantID)
	if err != nil {
		return application.Access{}, err
	}
	return customAccess(authority, actor, capability)
}

func resolveCustomDefinitionInventoryAccessInTransaction(
	ctx context.Context,
	tx databaseTransaction,
	actor application.Actor,
	tenantID uuid.UUID,
) (application.Access, error) {
	authority, err := phase4Authority(ctx, tx, customAuthorizationActor(actor), tenantID)
	if err != nil {
		return application.Access{}, err
	}
	return customDefinitionInventoryAccess(authority, actor)
}

func customDefinitionInventoryAccess(
	authority authorization.TenantAuthority,
	actor application.Actor,
) (application.Access, error) {
	access, err := customAccess(authority, actor, application.CapabilityRead)
	if err != nil {
		return application.Access{}, err
	}
	access.DefinitionInventory = true
	if actor.Kind == application.PrincipalHuman &&
		phase4HasPermission(authority, string(application.CapabilityManage), authorization.ScopeTenant) {
		access.Manage = true
	}
	return access, nil
}

func customAccess(
	authority authorization.TenantAuthority,
	actor application.Actor,
	capability application.Capability,
) (application.Access, error) {
	if !validPhase4Authority(authority, actor.MembershipID) ||
		authority.Principal.ID != actor.UserID || authority.TenantID != actor.TenantID {
		return application.Access{}, authorization.ErrForbidden
	}
	if actor.Kind != application.PrincipalCustomer && actor.Kind != application.PrincipalHuman {
		return application.Access{}, authorization.ErrForbidden
	}
	// Actor.Kind is established by the mounted route. LegacyRole is retained
	// only for compatibility projections and must not invert operator/customer
	// audience for custom roles, JIT memberships, or read-only operators.
	customer := actor.Kind == application.PrincipalCustomer
	if capability != application.CapabilityRead && capability != application.CapabilityManage ||
		!phase4HasPermission(authority, string(capability), authorization.ScopeTenant) {
		return application.Access{}, authorization.ErrForbidden
	}
	if capability == application.CapabilityManage && customer {
		return application.Access{}, authorization.ErrForbidden
	}
	audience := kernel.AudienceOperator
	if customer {
		audience = kernel.AudienceCustomer
	}
	return application.Access{
		Audience: audience, Scope: application.ScopeTenant,
		Manage: capability == application.CapabilityManage,
	}, nil
}

func customAuthorizationActor(actor application.Actor) authorization.Actor {
	return authorization.Actor{
		UserID: actor.UserID, SessionID: actor.SessionID,
		ActiveTenantID: actor.ActiveTenantID, AuthenticationMethod: actor.AuthenticationMethod,
	}
}

func accessCapability(access application.Access) application.Capability {
	if access.Manage {
		return application.CapabilityManage
	}
	return application.CapabilityRead
}

func sameCustomAccess(left, right application.Access) bool {
	return left.Audience == right.Audience && left.Scope == right.Scope &&
		left.DefinitionInventory == right.DefinitionInventory &&
		left.Manage == right.Manage && left.Write == right.Write
}

func validCustomCommand(binding application.CommandBinding, operation string) bool {
	return binding.Operation == operation && binding.KeyDigest != [sha256.Size]byte{} &&
		binding.RequestDigest != [sha256.Size]byte{}
}

func mapCustomFieldDatabaseError(err error) error {
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
	case "23505", "23503", "23514", "40001", "40P01", "22023", "22P02":
		return application.ErrRepositoryConflict
	default:
		return err
	}
}

func encodeCustomDefinitionCursor(key string, id uuid.UUID) string {
	payload := make([]byte, 0, 2+len(key)+16)
	payload = append(payload, 1, byte(len(key)))
	payload = append(payload, key...)
	payload = append(payload, id[:]...)
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeCustomDefinitionCursor(value string) (kernel.Key, uuid.UUID, error) {
	if value == "" {
		return kernel.Key{}, uuid.Nil, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(payload) < 18 || payload[0] != 1 ||
		int(payload[1])+18 != len(payload) || base64.RawURLEncoding.EncodeToString(payload) != value {
		return kernel.Key{}, uuid.Nil, application.ErrInvalidInput
	}
	key, err := kernel.NewKey(string(payload[2 : 2+int(payload[1])]))
	if err != nil {
		return kernel.Key{}, uuid.Nil, application.ErrInvalidInput
	}
	identifier, err := uuid.FromBytes(payload[len(payload)-16:])
	if err != nil || !authorizationUUIDv7(identifier) {
		return kernel.Key{}, uuid.Nil, application.ErrInvalidInput
	}
	return key, identifier, nil
}

func sameCustomDefinitionIdentity(left, right kernel.Definition) bool {
	return left.ID() == right.ID() && left.TenantID() == right.TenantID() &&
		left.ObjectType() == right.ObjectType() && left.Key() == right.Key()
}

func sameCustomDefinition(left, right kernel.Definition) bool {
	leftSnapshot, leftErr := customDefinitionSnapshot(left)
	rightSnapshot, rightErr := customDefinitionSnapshot(right)
	return leftErr == nil && rightErr == nil && slices.Equal(leftSnapshot, rightSnapshot)
}

func customDefinitionSnapshot(definition kernel.Definition) ([]byte, error) {
	options := definition.Options()
	optionProjection := make([]map[string]any, len(options))
	for index, option := range options {
		optionProjection[index] = map[string]any{
			"id": option.ID().String(), "key": option.Key().String(),
			"label": option.Label(), "position": option.Position(), "archived": option.Archived(),
		}
	}
	transitions := definition.RequiredOnTransitions()
	transitionProjection := make([]string, len(transitions))
	for index, transition := range transitions {
		transitionProjection[index] = transition.String()
	}
	constraints := definition.Constraints()
	defaultValue := any(nil)
	if definition.Default().Presence() != kernel.PresenceMissing {
		defaultValue = json.RawMessage(definition.Default().CanonicalJSON())
	}
	return json.Marshal(map[string]any{
		"id": definition.ID().String(), "tenantId": definition.TenantID().String(),
		"objectType": definition.ObjectType(), "key": definition.Key().String(),
		"label": definition.Label(), "description": definition.Description(),
		"dataType": definition.DataType(), "required": definition.Required(),
		"nullable": definition.Nullable(), "default": defaultValue,
		"constraints": map[string]any{
			"minimumLength": constraints.MinimumLength(), "maximumLength": constraints.MaximumLength(),
			"minimum": constraints.Minimum(), "maximum": constraints.Maximum(), "pattern": constraints.Pattern(),
		},
		"options": optionProjection, "visibility": definition.Visibility(),
		"editPolicy": definition.EditPolicy(), "placement": definition.Placement(),
		"requiredOnTransitions": transitionProjection, "searchable": definition.Searchable(),
		"filterable": definition.Filterable(), "sortable": definition.Sortable(),
		"allowStructuredJson": definition.AllowStructuredJSON(),
		"archived":            definition.Archived(), "schemaVersion": definition.SchemaVersion(),
	})
}

func customDefinitionJournalProjection(definition kernel.Definition) map[string]any {
	if definition.ID().String() == "00000000-0000-0000-0000-000000000000" {
		return map[string]any{}
	}
	return map[string]any{
		"schemaVersion": definition.SchemaVersion(), "dataType": definition.DataType(),
		"required": definition.Required(), "nullable": definition.Nullable(),
		"archived": definition.Archived(),
	}
}
