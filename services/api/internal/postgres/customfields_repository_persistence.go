package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/customfields"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/customfields"
)

func insertCustomDefinition(
	ctx context.Context,
	tx databaseTransaction,
	write application.DefinitionWrite,
) error {
	definition := write.Definition
	values, err := customDefinitionDatabaseValues(definition)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO public.custom_field_definitions (
			id, tenant_id, object_type, key, label, description, data_type,
			required, nullable, has_default, default_value,
			minimum_length, maximum_length, minimum_number, maximum_number,
			validation_pattern, show_in_create, show_in_detail, show_in_list,
			show_in_export, required_on_transitions, searchable, filterable,
			sortable, allow_structured_json, schema_version,
			created_by_membership_id, updated_by_membership_id
		) VALUES (
			$1, $2, $3::public.custom_field_object_type, $4, $5, $6,
			$7::public.custom_field_data_type, $8, $9, $10, $11::jsonb,
			$12, $13, $14, $15, $16, $17, $18, $19, $20, $21,
			$22, $23, $24, $25, $26, $27, $27
		)`,
		uuid.UUID(definition.ID().Bytes()), uuid.UUID(definition.TenantID().Bytes()),
		string(definition.ObjectType()), definition.Key().String(), definition.Label(),
		definition.Description(), string(definition.DataType()), definition.Required(),
		definition.Nullable(), values.hasDefault, values.defaultJSON,
		values.minimumLength, values.maximumLength, values.minimumNumber,
		values.maximumNumber, values.pattern, definition.Placement().ShowInCreate,
		definition.Placement().ShowInDetail, definition.Placement().ShowInList,
		definition.Placement().ShowInExport, values.transitions,
		definition.Searchable(), definition.Filterable(), definition.Sortable(),
		definition.AllowStructuredJSON(), int64(definition.SchemaVersion()),
		write.Actor.MembershipID,
	)
	return err
}

func updateCustomDefinition(
	ctx context.Context,
	tx databaseTransaction,
	write application.DefinitionWrite,
	archiveReason *string,
) error {
	definition := write.Definition
	values, err := customDefinitionDatabaseValues(definition)
	if err != nil {
		return err
	}
	if archiveReason != nil && !definition.Archived() || archiveReason == nil && definition.Archived() {
		return application.ErrRepositoryConflict
	}
	tag, err := tx.Exec(ctx, `
		UPDATE public.custom_field_definitions
		SET label = $5, description = $6,
		    data_type = $7::public.custom_field_data_type,
		    required = $8, nullable = $9, has_default = $10,
		    default_value = $11::jsonb, minimum_length = $12,
		    maximum_length = $13, minimum_number = $14, maximum_number = $15,
		    validation_pattern = $16, show_in_create = $17,
		    show_in_detail = $18, show_in_list = $19, show_in_export = $20,
		    required_on_transitions = $21, searchable = $22, filterable = $23,
		    sortable = $24, allow_structured_json = $25, schema_version = $26,
		    updated_by_membership_id = $27,
		    archived_by_membership_id = CASE WHEN $28 THEN $27 ELSE NULL END,
		    archived_at = CASE WHEN $28 THEN transaction_timestamp() ELSE NULL END,
		    updated_at = transaction_timestamp()
		WHERE tenant_id = $1 AND id = $2
		  AND object_type = $3::public.custom_field_object_type AND key = $4
		  AND schema_version = $29 AND archived_at IS NULL`,
		uuid.UUID(definition.TenantID().Bytes()), uuid.UUID(definition.ID().Bytes()),
		string(definition.ObjectType()), definition.Key().String(), definition.Label(),
		definition.Description(), string(definition.DataType()), definition.Required(),
		definition.Nullable(), values.hasDefault, values.defaultJSON,
		values.minimumLength, values.maximumLength, values.minimumNumber,
		values.maximumNumber, values.pattern, definition.Placement().ShowInCreate,
		definition.Placement().ShowInDetail, definition.Placement().ShowInList,
		definition.Placement().ShowInExport, values.transitions,
		definition.Searchable(), definition.Filterable(), definition.Sortable(),
		definition.AllowStructuredJSON(), int64(definition.SchemaVersion()),
		write.Actor.MembershipID, definition.Archived(), int64(write.ExpectedVersion),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return application.ErrRepositoryPrecondition
	}
	return nil
}

type customDefinitionValues struct {
	hasDefault    bool
	defaultJSON   any
	minimumLength *int32
	maximumLength *int32
	minimumNumber *string
	maximumNumber *string
	pattern       *string
	transitions   []string
}

func customDefinitionDatabaseValues(definition kernel.Definition) (customDefinitionValues, error) {
	result := customDefinitionValues{}
	if definition.Default().Presence() != kernel.PresenceMissing {
		canonical := definition.Default().CanonicalJSON()
		if !json.Valid(canonical) {
			return customDefinitionValues{}, errors.New("custom-field definition has an invalid canonical default")
		}
		result.hasDefault = true
		result.defaultJSON = string(canonical)
	}
	constraints := definition.Constraints()
	var err error
	result.minimumLength, err = customInt32(constraints.MinimumLength())
	if err != nil {
		return customDefinitionValues{}, err
	}
	result.maximumLength, err = customInt32(constraints.MaximumLength())
	if err != nil {
		return customDefinitionValues{}, err
	}
	result.minimumNumber = optionalCustomString(constraints.Minimum())
	result.maximumNumber = optionalCustomString(constraints.Maximum())
	result.pattern = optionalCustomString(constraints.Pattern())
	transitions := definition.RequiredOnTransitions()
	result.transitions = make([]string, len(transitions))
	for index, transition := range transitions {
		result.transitions[index] = transition.String()
	}
	return result, nil
}

func customInt32(value *uint32) (*int32, error) {
	if value == nil {
		return nil, nil
	}
	if *value > math.MaxInt32 {
		return nil, application.ErrRepositoryConflict
	}
	result := int32(*value)
	return &result, nil
}

func optionalCustomString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func persistCustomDefinitionOptions(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	current kernel.Definition,
	next kernel.Definition,
) error {
	currentOptions := current.Options()
	nextOptions := next.Options()
	currentByID := make(map[kernel.EntityID]kernel.Option, len(currentOptions))
	currentByKey := make(map[kernel.Key]kernel.Option, len(currentOptions))
	for _, option := range currentOptions {
		currentByID[option.ID()] = option
		currentByKey[option.Key()] = option
	}
	desiredPositions := make(map[uint16]struct{}, len(nextOptions))
	for _, option := range nextOptions {
		if _, duplicate := desiredPositions[option.Position()]; duplicate {
			return application.ErrRepositoryConflict
		}
		desiredPositions[option.Position()] = struct{}{}
		byID, idExists := currentByID[option.ID()]
		byKey, keyExists := currentByKey[option.Key()]
		if idExists != keyExists || idExists && (byID.Key() != option.Key() || byKey.ID() != option.ID()) ||
			idExists && byID.Archived() && !option.Archived() || !idExists && option.Archived() {
			return application.ErrRepositoryConflict
		}
	}
	if len(currentOptions) > 0 {
		temporary := make([]uint16, 0, len(currentOptions))
		for candidate := math.MaxUint16; candidate >= 0 && len(temporary) < len(currentOptions); candidate-- {
			position := uint16(candidate)
			if _, used := desiredPositions[position]; !used {
				temporary = append(temporary, position)
			}
			if candidate == 0 {
				break
			}
		}
		if len(temporary) != len(currentOptions) {
			return errors.New("custom-field option positions have no temporary workspace")
		}
		for index, option := range currentOptions {
			tag, err := tx.Exec(ctx, `
				UPDATE public.custom_field_options SET position = $4, updated_at = transaction_timestamp()
				WHERE tenant_id = $1 AND definition_id = $2 AND id = $3`,
				tenantID, uuid.UUID(next.ID().Bytes()), uuid.UUID(option.ID().Bytes()), int32(temporary[index]))
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return application.ErrRepositoryConflict
			}
		}
	}
	for _, option := range nextOptions {
		_, exists := currentByID[option.ID()]
		introducedVersion := int64(next.SchemaVersion())
		if exists {
			introducedVersion = 1 // ignored by the conflict update
		}
		archivedVersion := any(nil)
		if option.Archived() {
			archivedVersion = int64(next.SchemaVersion())
		}
		tag, err := tx.Exec(ctx, `
			INSERT INTO public.custom_field_options (
				id, tenant_id, definition_id, key, label, position,
				introduced_in_schema_version, archived_in_schema_version, archived_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
				CASE WHEN $8::bigint IS NULL THEN NULL ELSE transaction_timestamp() END)
			ON CONFLICT (id) DO UPDATE
			SET label = EXCLUDED.label, position = EXCLUDED.position,
			    archived_in_schema_version = CASE
			      WHEN EXCLUDED.archived_in_schema_version IS NULL THEN NULL
			      ELSE coalesce(custom_field_options.archived_in_schema_version,
			                    EXCLUDED.archived_in_schema_version)
			    END,
			    archived_at = CASE
			      WHEN EXCLUDED.archived_in_schema_version IS NULL THEN NULL
			      ELSE coalesce(custom_field_options.archived_at, transaction_timestamp())
			    END,
			    updated_at = transaction_timestamp()
			WHERE custom_field_options.tenant_id = EXCLUDED.tenant_id
			  AND custom_field_options.definition_id = EXCLUDED.definition_id
			  AND custom_field_options.key = EXCLUDED.key`,
			uuid.UUID(option.ID().Bytes()), tenantID, uuid.UUID(next.ID().Bytes()),
			option.Key().String(), option.Label(), int32(option.Position()),
			introducedVersion, archivedVersion,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return application.ErrRepositoryConflict
		}
	}
	if len(currentOptions) != 0 && len(currentOptions) > len(nextOptions) {
		return application.ErrRepositoryConflict
	}
	return nil
}

func persistCustomDefinitionPermissions(
	ctx context.Context,
	tx databaseTransaction,
	definition kernel.Definition,
) error {
	visibility := definition.Visibility()
	policy := definition.EditPolicy()
	type permission struct {
		audience string
		read     bool
		create   bool
		update   bool
	}
	permissions := []permission{
		{audience: "customer", read: visibility.Customer, create: policy.CustomerCreate, update: policy.CustomerUpdate},
		{audience: "operator", read: visibility.Operator, create: policy.OperatorCreate, update: policy.OperatorUpdate},
	}
	for _, value := range permissions {
		tag, err := tx.Exec(ctx, `
			INSERT INTO public.custom_field_permissions (
				tenant_id, definition_id, audience, can_read, can_create,
				can_update, schema_version
			) VALUES ($1, $2, $3::public.custom_field_audience, $4, $5, $6, $7)
			ON CONFLICT (tenant_id, definition_id, audience) DO UPDATE
			SET can_read = EXCLUDED.can_read, can_create = EXCLUDED.can_create,
			    can_update = EXCLUDED.can_update,
			    schema_version = EXCLUDED.schema_version,
			    updated_at = transaction_timestamp()`,
			uuid.UUID(definition.TenantID().Bytes()), uuid.UUID(definition.ID().Bytes()),
			value.audience, value.read, value.create, value.update, int64(definition.SchemaVersion()))
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("database did not persist a custom-field permission")
		}
	}
	return nil
}

func loadCompletedCustomFieldMigration(
	ctx context.Context,
	tx databaseTransaction,
	current kernel.Definition,
	next kernel.Definition,
) (*kernel.MigrationPin, error) {
	var id uuid.UUID
	var kind, fromDataType, toDataType string
	var fromVersion, toVersion int64
	err := tx.QueryRow(ctx, `
		SELECT id, kind::text, from_data_type::text, to_data_type::text,
		       from_schema_version, to_schema_version
		FROM public.custom_field_migrations
		WHERE tenant_id = $1 AND definition_id = $2
		  AND from_schema_version = $3 AND to_schema_version = $4
		  AND status = 'completed'`,
		uuid.UUID(current.TenantID().Bytes()), uuid.UUID(current.ID().Bytes()),
		int64(current.SchemaVersion()), int64(next.SchemaVersion()),
	).Scan(&id, &kind, &fromDataType, &toDataType, &fromVersion, &toVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	migrationID, err := kernel.ParseEntityID(id.String())
	if err != nil || fromVersion < 1 || toVersion != fromVersion+1 {
		return nil, errors.New("database returned an invalid custom-field migration pin")
	}
	return &kernel.MigrationPin{
		ID: migrationID, TenantID: current.TenantID(), DefinitionID: current.ID(),
		Kind: kernel.MigrationKind(kind), FromDataType: kernel.DataType(fromDataType),
		ToDataType: kernel.DataType(toDataType), FromSchemaVersion: uint64(fromVersion),
		ToSchemaVersion: uint64(toVersion),
	}, nil
}

type customObjectRecord struct {
	version             uint64
	customerVisible     bool
	customerState       bool
	assigneeUserID      *uuid.UUID
	claimedByUserID     *uuid.UUID
	assignedTeamID      *uuid.UUID
	assignedTeamEpochID *uuid.UUID
}

func resolveCustomObjectAccess(
	ctx context.Context,
	tx databaseTransaction,
	actor application.Actor,
	authority authorization.TenantAuthority,
	objectType kernel.ObjectType,
	objectID uuid.UUID,
	write bool,
) (application.Access, error) {
	if !validPhase4Authority(authority, actor.MembershipID) || authority.Principal.ID != actor.UserID ||
		authority.TenantID != actor.TenantID ||
		!phase4HasPermission(authority, "custom_field.read", authorization.ScopeTenant) {
		return application.Access{}, authorization.ErrForbidden
	}
	record, err := loadCustomObjectRecord(ctx, tx, actor.TenantID, objectType, objectID)
	if err != nil {
		return application.Access{}, err
	}
	permission := "alert.read"
	if objectType == kernel.ObjectCase {
		permission = "case.read"
	}
	if write {
		permission = "alert.update"
		if objectType == kernel.ObjectCase {
			permission = "case.update"
		}
	}
	if actor.Kind != application.PrincipalCustomer && actor.Kind != application.PrincipalHuman {
		return application.Access{}, authorization.ErrForbidden
	}
	customer := actor.Kind == application.PrincipalCustomer
	if customer && (!record.customerVisible || !record.customerState) {
		return application.Access{}, authorization.ErrForbidden
	}
	scope := application.Scope("")
	if phase4HasPermission(authority, permission, authorization.ScopeTenant) {
		scope = application.ScopeTenant
	} else if phase4HasPermission(authority, permission, authorization.ScopeAssigned) &&
		(customer || record.assigneeUserID != nil && *record.assigneeUserID == actor.UserID ||
			record.claimedByUserID != nil && *record.claimedByUserID == actor.UserID) {
		scope = application.ScopeAssigned
	} else if phase4HasPermission(authority, permission, authorization.ScopeOperatorTeam) &&
		record.assignedTeamID != nil && record.assignedTeamEpochID != nil &&
		slices.ContainsFunc(authority.OperatorTeamRelationships, func(value authorization.OperatorTeamRelationship) bool {
			return value.OperatorTeamID == *record.assignedTeamID && value.AssignmentEpochID == *record.assignedTeamEpochID
		}) {
		scope = application.ScopeOperatorTeam
	}
	if scope == "" {
		return application.Access{}, authorization.ErrForbidden
	}
	audience := kernel.AudienceOperator
	if customer {
		audience = kernel.AudienceCustomer
	}
	return application.Access{Audience: audience, Scope: scope, Write: write}, nil
}

func loadCustomObjectRecord(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	objectType kernel.ObjectType,
	objectID uuid.UUID,
) (customObjectRecord, error) {
	table, aggregate := "public.alerts", "alert"
	if objectType == kernel.ObjectCase {
		table, aggregate = "public.cases", "case"
	} else if objectType != kernel.ObjectAlert {
		return customObjectRecord{}, application.ErrRepositoryConflict
	}
	var version int64
	var result customObjectRecord
	err := tx.QueryRow(ctx, `
		SELECT ticket.version, ticket.customer_visible,
		       ticket.assignee_user_id, ticket.claimed_by_user_id,
		       ticket.assigned_team_id, ticket.assigned_team_epoch_id,
		       EXISTS (
		         SELECT 1
		         FROM jsonb_array_elements(workflow.states) AS state(value)
		         WHERE state.value ->> 'key' = ticket.state_key
		           AND state.value ->> 'visibility' = 'customer'
		       )
		FROM `+table+` AS ticket
		JOIN public.ticket_workflow_versions AS workflow
		  ON workflow.tenant_id = ticket.tenant_id
		 AND workflow.workflow_id = ticket.workflow_id
		 AND workflow.version = ticket.workflow_version
		 AND workflow.aggregate_kind = $3::public.ticket_aggregate_kind
		WHERE ticket.tenant_id = $1 AND ticket.id = $2`, tenantID, objectID, aggregate).Scan(
		&version, &result.customerVisible, &result.assigneeUserID, &result.claimedByUserID,
		&result.assignedTeamID, &result.assignedTeamEpochID, &result.customerState,
	)
	if err != nil {
		return customObjectRecord{}, err
	}
	if version < 1 || result.assignedTeamID == nil != (result.assignedTeamEpochID == nil) {
		return customObjectRecord{}, errors.New("database returned an invalid custom-field object projection")
	}
	result.version = uint64(version)
	return result, nil
}

func loadCustomObjectVersion(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	objectType kernel.ObjectType,
	objectID uuid.UUID,
) (uint64, error) {
	record, err := loadCustomObjectRecord(ctx, tx, tenantID, objectType, objectID)
	return record.version, err
}

func loadCustomObjectDefinitions(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	objectType kernel.ObjectType,
) ([]kernel.Definition, error) {
	rows, err := tx.Query(ctx, `SELECT `+customDefinitionColumns+`
		FROM public.custom_field_definitions AS definition
		WHERE definition.tenant_id = $1
		  AND definition.object_type = $2::public.custom_field_object_type
		ORDER BY definition.key, definition.id
		LIMIT 513`, tenantID, string(objectType))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bases := make([]customDefinitionRow, 0)
	for rows.Next() {
		base, scanErr := scanCustomDefinitionRow(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		bases = append(bases, base)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	if len(bases) > 512 {
		return nil, errors.New("tenant custom-field definition inventory exceeds the bounded projection")
	}
	result := make([]kernel.Definition, len(bases))
	for index, base := range bases {
		definition, hydrateErr := hydrateCustomDefinition(ctx, tx, base)
		if hydrateErr != nil {
			return nil, hydrateErr
		}
		result[index] = definition
	}
	return result, nil
}

func loadCustomObjectValues(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	objectType kernel.ObjectType,
	objectID uuid.UUID,
	definitions []kernel.Definition,
) ([]kernel.FieldValue, error) {
	byID := make(map[uuid.UUID]kernel.Definition, len(definitions))
	for _, definition := range definitions {
		byID[uuid.UUID(definition.ID().Bytes())] = definition
	}
	subjectColumn := "alert_id"
	if objectType == kernel.ObjectCase {
		subjectColumn = "case_id"
	}
	rows, err := tx.Query(ctx, `
		SELECT definition_id, definition_schema_version, data_type::text,
		       presence::text, canonical_value
		FROM public.custom_field_values
		WHERE tenant_id = $1 AND object_type = $2::public.custom_field_object_type
		  AND `+subjectColumn+` = $3
		ORDER BY definition_id
		LIMIT 513`, tenantID, string(objectType), objectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]kernel.FieldValue, 0)
	seen := make(map[uuid.UUID]struct{})
	for rows.Next() {
		var definitionID uuid.UUID
		var schemaVersion int64
		var dataType, presence string
		var canonical []byte
		if scanErr := rows.Scan(&definitionID, &schemaVersion, &dataType, &presence, &canonical); scanErr != nil {
			return nil, scanErr
		}
		definition, exists := byID[definitionID]
		if !exists || schemaVersion < 1 || uint64(schemaVersion) > definition.SchemaVersion() ||
			dataType != string(definition.DataType()) || presence != "present" && presence != "null" {
			return nil, errors.New("database returned an invalid custom-field value projection")
		}
		if _, duplicate := seen[definitionID]; duplicate {
			return nil, errors.New("database returned duplicate custom-field values")
		}
		seen[definitionID] = struct{}{}
		value, restoreErr := kernel.RestoreFieldValue(definition, canonical)
		if restoreErr != nil {
			return nil, errors.New("database returned a custom-field value incompatible with its definition")
		}
		result = append(result, value)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	if len(result) > 512 {
		return nil, errors.New("custom-field value projection exceeds its bound")
	}
	return result, nil
}
