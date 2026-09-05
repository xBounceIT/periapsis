package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	customkernel "github.com/periapsis-im/periapsis/modules/customfields"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

type ticketDynamicSortPlan struct {
	source     application.SavedViewDefinitionSource
	definition uuid.UUID
	version    uint64
	valueKind  string
	dataType   string
	format     string
	join       string
	expression string
	direction  string
	nulls      string
}

func resolveTicketDynamicSortPlan(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	execution *ticketSavedViewExecution,
	add func(any) string,
) (*ticketDynamicSortPlan, error) {
	if execution == nil || execution.sort.Source() == kernel.SavedViewColumnCore {
		return nil, nil
	}
	pin, ok := execution.sort.Definition()
	if !ok {
		return nil, application.ErrUnavailable
	}
	definitionID := uuid.UUID(pin.ID().Bytes())
	plan := &ticketDynamicSortPlan{
		definition: definitionID, version: pin.Version(),
		direction: execution.sort.Direction().String(), nulls: execution.sort.Nulls().String(),
	}
	objectID := "saved_view_sort.alert_id = ticket.id"
	if kind == kernel.AggregateCase {
		objectID = "saved_view_sort.case_id = ticket.id"
	} else if kind != kernel.AggregateAlert {
		return nil, application.ErrInvalidInput
	}
	switch execution.sort.Source() {
	case kernel.SavedViewColumnCustomField:
		plan.source = application.SavedViewDefinitionCustomField
		var dataType string
		if err := tx.QueryRow(ctx, `SELECT data_type::text
			FROM public.custom_field_definitions
			WHERE tenant_id = $1 AND id = $2 AND schema_version = $3 AND archived_at IS NULL`,
			tenantID, definitionID, int64(pin.Version())).Scan(&dataType); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, application.ErrConflict
			}
			return nil, mapTicketDatabaseError(err)
		}
		column, valueKind := indexedCustomSortColumn(customkernel.DataType(dataType))
		if column == "" {
			return nil, application.ErrUnavailable
		}
		plan.valueKind = valueKind
		plan.dataType = dataType
		plan.expression = "saved_view_sort." + column
		plan.join = `
			LEFT JOIN public.custom_field_values AS saved_view_sort
			  ON saved_view_sort.tenant_id = ticket.tenant_id
			 AND saved_view_sort.object_type = ` + add(kind.String()) + `::public.custom_field_object_type
			 AND ` + objectID + `
			 AND saved_view_sort.definition_id = ` + add(definitionID) + `
			 AND saved_view_sort.definition_schema_version = ` + add(int64(pin.Version())) + `
			 AND saved_view_sort.data_type = ` + add(dataType) + `::public.custom_field_data_type
			 AND saved_view_sort.presence = 'present'`
	case kernel.SavedViewColumnSLA:
		plan.source = application.SavedViewDefinitionSLA
		var format string
		if err := tx.QueryRow(ctx, `SELECT format::text
			FROM app.ticket_sla_column_revisions_v1
			WHERE tenant_id = $1 AND column_id = $2 AND version = $3 AND sortable`,
			tenantID, definitionID, int64(pin.Version())).Scan(&format); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, application.ErrConflict
			}
			return nil, mapTicketDatabaseError(err)
		}
		column, valueKind, projection := slaSortColumn(format)
		if column == "" || projection == "" {
			return nil, application.ErrUnavailable
		}
		plan.valueKind = valueKind
		plan.format = format
		plan.expression = "saved_view_sort." + column
		plan.join = `
			LEFT JOIN app.` + projection + ` AS saved_view_sort
			  ON saved_view_sort.tenant_id = ticket.tenant_id
			 AND saved_view_sort.object_type = ` + add(kind.String()) + `::public.sla_object_type
			 AND saved_view_sort.object_id = ticket.id
			 AND saved_view_sort.column_id = ` + add(definitionID) + `
			 AND saved_view_sort.column_version = ` + add(int(pin.Version()))
	default:
		return nil, application.ErrUnavailable
	}
	return plan, nil
}

func indexedCustomSortColumn(dataType customkernel.DataType) (string, string) {
	switch dataType {
	case customkernel.TypeShortText, customkernel.TypeLongText, customkernel.TypeURL, customkernel.TypeEmail:
		return "text_value", "text"
	case customkernel.TypeInteger, customkernel.TypeDuration:
		return "integer_value", "integer"
	case customkernel.TypeDecimal:
		return "decimal_value", "decimal"
	case customkernel.TypeBoolean:
		return "boolean_value", "boolean"
	case customkernel.TypeDate:
		return "date_value", "date"
	case customkernel.TypeDateTime:
		return "date_time_value", "instant"
	case customkernel.TypeIP:
		return "ip_value", "inet"
	case customkernel.TypeCIDR:
		return "cidr_value", "cidr"
	case customkernel.TypeUser, customkernel.TypeOperatorTeam, customkernel.TypeCustomerContact,
		customkernel.TypeAssetReference, customkernel.TypeIOCReference:
		return "reference_id", "uuid"
	case customkernel.TypeSingleSelect:
		return "option_keys[1]", "single_select"
	default:
		return "", ""
	}
}

func slaSortColumn(format string) (string, string, string) {
	switch format {
	case "datetime":
		return "instant_value", "instant", "ticket_sla_instant_sort_values_v1"
	case "duration":
		return "duration_micros_value", "integer", "ticket_sla_duration_sort_values_v1"
	case "state_badge":
		return "state_value", "text", "ticket_sla_state_sort_values_v1"
	case "percentage":
		return "percentage_value", "float", "ticket_sla_percentage_sort_values_v1"
	default:
		return "", "", ""
	}
}

func ticketDynamicSort(
	plan *ticketDynamicSortPlan,
	encoded string,
	fingerprint [32]byte,
	add func(any) string,
) (string, string, string, error) {
	if plan == nil || plan.expression == "" || plan.direction != "asc" && plan.direction != "desc" ||
		plan.nulls != "first" && plan.nulls != "last" {
		return "", "", "", application.ErrUnavailable
	}
	direction := "ASC"
	operator := ">"
	if plan.direction == "desc" {
		direction, operator = "DESC", "<"
	}
	nulls := "NULLS FIRST"
	if plan.nulls == "last" {
		nulls = "NULLS LAST"
	}
	sortName := fmt.Sprintf("saved:%s:%s:%d:%s:%s", plan.source, plan.definition, plan.version, plan.direction, plan.nulls)
	order := plan.expression + " " + direction + " " + nulls + ", ticket.id " + direction
	if encoded == "" {
		return sortName, order, "", nil
	}
	cursor, err := decodeTicketCursor(encoded, sortName, fingerprint)
	if err != nil || cursor.Dynamic == nil && !cursor.DynamicNull {
		return "", "", "", application.ErrInvalidInput
	}
	id := add(cursor.ID)
	if cursor.DynamicNull {
		if plan.nulls == "last" {
			return sortName, order, "(" + plan.expression + " IS NULL AND ticket.id " + operator + " " + id + ")", nil
		}
		return sortName, order, "((" + plan.expression + " IS NULL AND ticket.id " + operator + " " + id + ") OR " + plan.expression + " IS NOT NULL)", nil
	}
	value, err := dynamicCursorArgument(plan.valueKind, cursor.Dynamic)
	if err != nil {
		return "", "", "", err
	}
	cast, supported := dynamicCursorCast(plan.valueKind)
	if !supported {
		return "", "", "", application.ErrUnavailable
	}
	parameter := add(value) + cast
	equal := plan.expression + " = " + parameter
	after := plan.expression + " " + operator + " " + parameter
	predicate := "(" + after + " OR (" + equal + " AND ticket.id " + operator + " " + id + "))"
	if plan.nulls == "last" {
		predicate = "(" + predicate + " OR " + plan.expression + " IS NULL)"
	}
	return sortName, order, predicate, nil
}

func dynamicCursorCast(kind string) (string, bool) {
	switch kind {
	case "text", "integer", "float", "boolean", "single_select":
		return "", true
	case "decimal":
		return "::numeric", true
	case "date":
		return "::date", true
	case "instant":
		return "::timestamptz", true
	case "inet":
		return "::inet", true
	case "cidr":
		return "::cidr", true
	case "uuid":
		return "::uuid", true
	default:
		return "", false
	}
}

func dynamicCursorArgument(kind string, raw json.RawMessage) (any, error) {
	if len(raw) == 0 || len(raw) > 64*1024 {
		return nil, application.ErrInvalidInput
	}
	switch kind {
	case "text":
		var value string
		if !decodeCanonicalCursorJSON(raw, &value) {
			return nil, application.ErrInvalidInput
		}
		return value, nil
	case "integer":
		var value int64
		if !decodeCanonicalCursorJSON(raw, &value) {
			return nil, application.ErrInvalidInput
		}
		return value, nil
	case "decimal":
		var number json.Number
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if decoder.Decode(&number) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
			!bytes.Equal(raw, []byte(number.String())) {
			return nil, application.ErrInvalidInput
		}
		if !canonicalCursorDecimal(number.String()) {
			return nil, application.ErrInvalidInput
		}
		return number.String(), nil
	case "float":
		var value float64
		if !decodeCanonicalCursorJSON(raw, &value) {
			return nil, application.ErrInvalidInput
		}
		return value, nil
	case "boolean":
		var value bool
		if !decodeCanonicalCursorJSON(raw, &value) {
			return nil, application.ErrInvalidInput
		}
		return value, nil
	case "date":
		var value string
		if !decodeCanonicalCursorJSON(raw, &value) {
			return nil, application.ErrInvalidInput
		}
		date, err := time.Parse("2006-01-02", value)
		if err != nil || date.Format("2006-01-02") != value {
			return nil, application.ErrInvalidInput
		}
		return value, nil
	case "instant":
		var value string
		if !decodeCanonicalCursorJSON(raw, &value) {
			return nil, application.ErrInvalidInput
		}
		instant, err := time.Parse(time.RFC3339Nano, value)
		if err != nil || instant.Nanosecond()%int(time.Microsecond) != 0 ||
			instant.UTC().Format(time.RFC3339Nano) != value {
			return nil, application.ErrInvalidInput
		}
		return instant.UTC(), nil
	case "inet":
		var value string
		if !decodeCanonicalCursorJSON(raw, &value) {
			return nil, application.ErrInvalidInput
		}
		address, err := netip.ParseAddr(value)
		if err != nil || address.Is4In6() || address.Zone() != "" || address.String() != value {
			return nil, application.ErrInvalidInput
		}
		return value, nil
	case "cidr":
		var value string
		if !decodeCanonicalCursorJSON(raw, &value) {
			return nil, application.ErrInvalidInput
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" ||
			prefix.Masked().String() != value {
			return nil, application.ErrInvalidInput
		}
		return value, nil
	case "uuid":
		var value string
		if !decodeCanonicalCursorJSON(raw, &value) {
			return nil, application.ErrInvalidInput
		}
		reference, err := customkernel.ParseEntityID(value)
		if err != nil || reference.String() != value {
			return nil, application.ErrInvalidInput
		}
		return uuid.UUID(reference.Bytes()), nil
	case "single_select":
		var value string
		if !decodeCanonicalCursorJSON(raw, &value) {
			return nil, application.ErrInvalidInput
		}
		key, err := customkernel.NewKey(value)
		if err != nil || key.String() != value {
			return nil, application.ErrInvalidInput
		}
		return value, nil
	default:
		return nil, application.ErrUnavailable
	}
}

func decodeCanonicalCursorJSON(raw json.RawMessage, destination any) bool {
	if json.Unmarshal(raw, destination) != nil {
		return false
	}
	canonical, err := json.Marshal(destination)
	return err == nil && bytes.Equal(raw, canonical)
}

func canonicalCustomDynamicValue(dataType customkernel.DataType, raw json.RawMessage) (json.RawMessage, error) {
	_, kind := indexedCustomSortColumn(dataType)
	if kind == "" || len(raw) == 0 || len(raw) > 64*1024 {
		return nil, application.ErrUnavailable
	}
	cursorValue := raw
	switch dataType {
	case customkernel.TypeDecimal:
		var number json.Number
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if decoder.Decode(&number) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
			!bytes.Equal(raw, []byte(number.String())) {
			return nil, application.ErrUnavailable
		}
		canonical, ok := normalizeStoredCursorDecimal(number.String())
		if !ok {
			return nil, application.ErrUnavailable
		}
		cursorValue = json.RawMessage(canonical)
	case customkernel.TypeDateTime:
		var value string
		if !decodeCanonicalCursorJSON(raw, &value) {
			return nil, application.ErrUnavailable
		}
		instant, err := time.Parse(time.RFC3339Nano, value)
		if err != nil || instant.Nanosecond()%int(time.Microsecond) != 0 {
			return nil, application.ErrUnavailable
		}
		cursorValue, err = json.Marshal(instant.UTC().Format(time.RFC3339Nano))
		if err != nil {
			return nil, application.ErrUnavailable
		}
	case customkernel.TypeIP:
		var value string
		if !decodeCanonicalCursorJSON(raw, &value) {
			return nil, application.ErrUnavailable
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Bits() != prefix.Addr().BitLen() || prefix.Addr().Is4In6() ||
			prefix.Addr().Zone() != "" || prefix.String() != value {
			return nil, application.ErrUnavailable
		}
		cursorValue, err = json.Marshal(prefix.Addr().String())
		if err != nil {
			return nil, application.ErrUnavailable
		}
	case customkernel.TypeSingleSelect:
		var values []string
		if !decodeCanonicalCursorJSON(raw, &values) || len(values) != 1 {
			return nil, application.ErrUnavailable
		}
		key, err := customkernel.NewKey(values[0])
		if err != nil || key.String() != values[0] {
			return nil, application.ErrUnavailable
		}
		cursorValue, err = json.Marshal(values[0])
		if err != nil {
			return nil, application.ErrUnavailable
		}
	}
	value, err := dynamicCursorArgument(kind, cursorValue)
	if err != nil {
		return nil, application.ErrUnavailable
	}
	if kind == "decimal" {
		return append(json.RawMessage(nil), cursorValue...), nil
	}
	canonical, err := json.Marshal(value)
	if err != nil || len(canonical) > 64*1024 {
		return nil, application.ErrUnavailable
	}
	return canonical, nil
}

func normalizeStoredCursorDecimal(value string) (string, bool) {
	if value == "" || len(value) > 256 {
		return "", false
	}
	start := 0
	if value[0] == '-' {
		start = 1
		if len(value) == 1 {
			return "", false
		}
	}
	dot := -1
	for index := start; index < len(value); index++ {
		if value[index] == '.' && dot == -1 {
			dot = index
			continue
		}
		if value[index] < '0' || value[index] > '9' {
			return "", false
		}
	}
	integerEnd := len(value)
	if dot >= 0 {
		integerEnd = dot
		if dot == start || dot == len(value)-1 {
			return "", false
		}
	}
	if integerEnd-start > 1 && value[start] == '0' {
		return "", false
	}
	if dot >= 0 {
		value = strings.TrimRight(value, "0")
		value = strings.TrimSuffix(value, ".")
	}
	if value == "-0" {
		value = "0"
	}
	return value, true
}

func canonicalCursorDecimal(value string) bool {
	canonical, ok := normalizeStoredCursorDecimal(value)
	return ok && canonical == value
}

func slaTypedValuePredicate(alias, format string) string {
	columns := map[string]string{
		"datetime":    "instant_value",
		"duration":    "duration_micros_value",
		"state_badge": "state_value",
		"percentage":  "percentage_value",
	}
	expected, ok := columns[format]
	if !ok {
		return "FALSE"
	}
	parts := make([]string, 0, len(columns))
	for _, column := range []string{"state_value", "instant_value", "duration_micros_value", "percentage_value"} {
		operator := "IS NULL"
		if column == expected {
			operator = "IS NOT NULL"
		}
		parts = append(parts, alias+"."+column+" "+operator)
	}
	return "(" + strings.Join(parts, " AND ") + ")"
}

func dynamicColumnKey(source application.SavedViewDefinitionSource, definition uuid.UUID) string {
	return string(source) + ":" + definition.String()
}

func loadTicketSavedViewDynamicColumns(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	execution *ticketSavedViewExecution,
	items []application.Record,
) error {
	if execution == nil || len(items) == 0 {
		return nil
	}
	objectIDs := make([]uuid.UUID, len(items))
	itemByID := make(map[uuid.UUID]int, len(items))
	for index := range items {
		identifier := uuid.UUID(items[index].Snapshot.ID().Bytes())
		objectIDs[index] = identifier
		itemByID[identifier] = index
		items[index].DynamicColumns = make(map[string]application.DynamicColumnValue)
	}
	customPins := make(map[uuid.UUID]kernel.SavedViewDefinitionPin)
	slaPins := make(map[uuid.UUID]kernel.SavedViewDefinitionPin)
	for _, column := range execution.columns {
		pin, dynamic := column.Definition()
		if !dynamic {
			continue
		}
		identifier := uuid.UUID(pin.ID().Bytes())
		switch column.Source() {
		case kernel.SavedViewColumnCustomField:
			customPins[identifier] = pin
		case kernel.SavedViewColumnSLA:
			slaPins[identifier] = pin
		default:
			return application.ErrUnavailable
		}
	}
	if err := loadTicketCustomDynamicColumns(ctx, tx, tenantID, kind, objectIDs, itemByID, customPins, items); err != nil {
		return err
	}
	return loadTicketSLADynamicColumns(ctx, tx, tenantID, kind, objectIDs, itemByID, slaPins, items)
}

func loadTicketCustomDynamicColumns(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	objectIDs []uuid.UUID,
	itemByID map[uuid.UUID]int,
	pins map[uuid.UUID]kernel.SavedViewDefinitionPin,
	items []application.Record,
) error {
	if len(pins) == 0 {
		return nil
	}
	definitionIDs := make([]uuid.UUID, 0, len(pins))
	for identifier := range pins {
		definitionIDs = append(definitionIDs, identifier)
	}
	subject := "value.alert_id"
	if kind == kernel.AggregateCase {
		subject = "value.case_id"
	}
	rows, err := tx.Query(ctx, `SELECT `+subject+`, value.definition_id,
		value.definition_schema_version, value.data_type::text,
		definition.data_type::text, value.canonical_value::text
		FROM public.custom_field_values AS value
		JOIN public.custom_field_definitions AS definition
		  ON definition.tenant_id = value.tenant_id
		 AND definition.id = value.definition_id
		 AND definition.schema_version = value.definition_schema_version
		 AND definition.archived_at IS NULL
		WHERE value.tenant_id = $1
		  AND value.object_type = $2::public.custom_field_object_type
		  AND `+subject+` = ANY($3::uuid[])
		  AND value.definition_id = ANY($4::uuid[])
		  AND value.presence = 'present'`, tenantID, kind.String(), objectIDs, definitionIDs)
	if err != nil {
		return mapTicketDatabaseError(err)
	}
	defer rows.Close()
	seen := make(map[string]struct{})
	for rows.Next() {
		var objectID, definitionID uuid.UUID
		var version int64
		var valueType, definitionType, canonical string
		if err := rows.Scan(&objectID, &definitionID, &version, &valueType, &definitionType, &canonical); err != nil {
			return mapTicketDatabaseError(err)
		}
		pin, expected := pins[definitionID]
		itemIndex, itemExists := itemByID[objectID]
		key := dynamicColumnKey(application.SavedViewDefinitionCustomField, definitionID)
		if !expected || !itemExists || version <= 0 || uint64(version) != pin.Version() ||
			valueType != definitionType || !projectableCustomScalarType(customkernel.DataType(valueType)) {
			return application.ErrUnavailable
		}
		projected, projectionErr := canonicalCustomDynamicValue(customkernel.DataType(valueType), json.RawMessage(canonical))
		if projectionErr != nil {
			return application.ErrUnavailable
		}
		identity := objectID.String() + ":" + key
		if _, duplicate := seen[identity]; duplicate {
			return application.ErrUnavailable
		}
		seen[identity] = struct{}{}
		items[itemIndex].DynamicColumns[key] = application.DynamicColumnValue{
			Source: application.SavedViewDefinitionCustomField, DefinitionID: definitionID,
			DefinitionVersion: uint64(version), Value: projected,
		}
	}
	if err := rows.Err(); err != nil {
		return mapTicketDatabaseError(err)
	}
	return nil
}

func loadTicketSLADynamicColumns(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	objectIDs []uuid.UUID,
	itemByID map[uuid.UUID]int,
	pins map[uuid.UUID]kernel.SavedViewDefinitionPin,
	items []application.Record,
) error {
	if len(pins) == 0 {
		return nil
	}
	definitionIDs := make([]uuid.UUID, 0, len(pins))
	for identifier := range pins {
		definitionIDs = append(definitionIDs, identifier)
	}
	rows, err := tx.Query(ctx, `SELECT value.object_id, value.column_id, value.column_version,
		value.state_value::text, value.instant_value, value.duration_micros_value,
		value.percentage_value, value.style_key, value.materialized_at,
		value.format::text
		FROM app.ticket_sla_materialized_values_v1 AS value
		WHERE value.tenant_id = $1
		  AND value.object_type = $2::public.sla_object_type
		  AND value.object_id = ANY($3::uuid[])
		  AND value.column_id = ANY($4::uuid[])`, tenantID, kind.String(), objectIDs, definitionIDs)
	if err != nil {
		return mapTicketDatabaseError(err)
	}
	defer rows.Close()
	seen := make(map[string]struct{})
	for rows.Next() {
		var objectID, definitionID uuid.UUID
		var version int32
		var state pgtype.Text
		var instant pgtype.Timestamptz
		var duration pgtype.Int8
		var percentage pgtype.Float8
		var style pgtype.Text
		var materialized time.Time
		var format string
		if err := rows.Scan(
			&objectID, &definitionID, &version, &state, &instant, &duration,
			&percentage, &style, &materialized, &format,
		); err != nil {
			return mapTicketDatabaseError(err)
		}
		pin, expected := pins[definitionID]
		itemIndex, itemExists := itemByID[objectID]
		key := dynamicColumnKey(application.SavedViewDefinitionSLA, definitionID)
		if !expected || !itemExists || version <= 0 || uint64(version) != pin.Version() ||
			materialized.IsZero() || materialized.Nanosecond()%int(time.Microsecond) != 0 {
			return application.ErrUnavailable
		}
		identity := objectID.String() + ":" + key
		if _, duplicate := seen[identity]; duplicate {
			return application.ErrUnavailable
		}
		seen[identity] = struct{}{}
		canonical, canonicalErr := canonicalSLADynamicValue(format, state, instant, duration, percentage)
		if canonicalErr != nil {
			return canonicalErr
		}
		value := application.DynamicColumnValue{
			Source: application.SavedViewDefinitionSLA, DefinitionID: definitionID,
			DefinitionVersion: uint64(version), Value: canonical,
		}
		if style.Valid {
			if style.String == "" || len(style.String) > 64 {
				return application.ErrUnavailable
			}
			value.StyleKey = style.String
		}
		materialized = materialized.UTC()
		value.MaterializedAt = &materialized
		items[itemIndex].DynamicColumns[key] = value
	}
	if err := rows.Err(); err != nil {
		return mapTicketDatabaseError(err)
	}
	return nil
}

func projectableCustomScalarType(dataType customkernel.DataType) bool {
	switch dataType {
	case customkernel.TypeShortText, customkernel.TypeLongText, customkernel.TypeInteger,
		customkernel.TypeDecimal, customkernel.TypeBoolean, customkernel.TypeDate,
		customkernel.TypeDateTime, customkernel.TypeDuration, customkernel.TypeSingleSelect,
		customkernel.TypeURL, customkernel.TypeEmail, customkernel.TypeIP, customkernel.TypeCIDR,
		customkernel.TypeUser, customkernel.TypeOperatorTeam, customkernel.TypeCustomerContact,
		customkernel.TypeAssetReference, customkernel.TypeIOCReference:
		return true
	default:
		return false
	}
}

func validTicketDynamicScalar(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 64*1024 || !json.Valid(raw) || bytes.Equal(raw, []byte("null")) {
		return false
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return false
	}
	switch value.(type) {
	case string, json.Number, bool:
		return true
	default:
		return false
	}
}

func canonicalSLADynamicValue(
	format string,
	state pgtype.Text,
	instant pgtype.Timestamptz,
	duration pgtype.Int8,
	percentage pgtype.Float8,
) (json.RawMessage, error) {
	if predicate := slaTypedValuePredicate("value", format); predicate == "FALSE" {
		return nil, application.ErrUnavailable
	}
	present := 0
	var value any
	if state.Valid {
		present++
		value = state.String
	}
	if instant.Valid {
		present++
		if instant.Time.Nanosecond()%int(time.Microsecond) != 0 {
			return nil, application.ErrUnavailable
		}
		value = instant.Time.UTC().Format(time.RFC3339Nano)
	}
	if duration.Valid {
		present++
		value = duration.Int64
	}
	if percentage.Valid {
		present++
		value = percentage.Float64
	}
	if present != 1 {
		return nil, application.ErrUnavailable
	}
	switch format {
	case "state_badge":
		if !state.Valid {
			return nil, application.ErrUnavailable
		}
	case "datetime":
		if !instant.Valid {
			return nil, application.ErrUnavailable
		}
	case "duration":
		if !duration.Valid {
			return nil, application.ErrUnavailable
		}
	case "percentage":
		if !percentage.Valid {
			return nil, application.ErrUnavailable
		}
	default:
		return nil, application.ErrUnavailable
	}
	encoded, err := json.Marshal(value)
	if err != nil || !validTicketDynamicScalar(encoded) {
		return nil, application.ErrUnavailable
	}
	return encoded, nil
}
