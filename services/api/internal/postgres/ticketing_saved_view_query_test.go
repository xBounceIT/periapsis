package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	customkernel "github.com/periapsis-im/periapsis/modules/customfields"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func TestIndexedCustomSortColumnIsClosedToIndexedScalarTypes(t *testing.T) {
	tests := []struct {
		dataType customkernel.DataType
		column   string
		kind     string
	}{
		{customkernel.TypeShortText, "text_value", "text"},
		{customkernel.TypeLongText, "text_value", "text"},
		{customkernel.TypeURL, "text_value", "text"},
		{customkernel.TypeEmail, "text_value", "text"},
		{customkernel.TypeInteger, "integer_value", "integer"},
		{customkernel.TypeDuration, "integer_value", "integer"},
		{customkernel.TypeDecimal, "decimal_value", "decimal"},
		{customkernel.TypeBoolean, "boolean_value", "boolean"},
		{customkernel.TypeDate, "date_value", "date"},
		{customkernel.TypeDateTime, "date_time_value", "instant"},
		{customkernel.TypeIP, "ip_value", "inet"},
		{customkernel.TypeCIDR, "cidr_value", "cidr"},
		{customkernel.TypeUser, "reference_id", "uuid"},
		{customkernel.TypeOperatorTeam, "reference_id", "uuid"},
		{customkernel.TypeCustomerContact, "reference_id", "uuid"},
		{customkernel.TypeAssetReference, "reference_id", "uuid"},
		{customkernel.TypeIOCReference, "reference_id", "uuid"},
		{customkernel.TypeSingleSelect, "option_keys[1]", "single_select"},
	}
	for _, test := range tests {
		column, kind := indexedCustomSortColumn(test.dataType)
		if column != test.column || kind != test.kind {
			t.Fatalf("indexedCustomSortColumn(%q) = (%q, %q), want (%q, %q)", test.dataType, column, kind, test.column, test.kind)
		}
	}
	for _, denied := range []customkernel.DataType{
		customkernel.TypeMultiSelect,
		customkernel.TypeStructuredJSON,
		customkernel.DataType("future"),
	} {
		if column, kind := indexedCustomSortColumn(denied); column != "" || kind != "" {
			t.Fatalf("unsupported custom sort %q unexpectedly compiled to (%q, %q)", denied, column, kind)
		}
	}
}

func TestTicketDynamicSortBindsCursorValueAndRejectsFingerprintDrift(t *testing.T) {
	definitionID := mustPostgresUUIDv7(t)
	fingerprint := sha256.Sum256([]byte("tenant/view/revision/pins"))
	plan := &ticketDynamicSortPlan{
		source:     application.SavedViewDefinitionCustomField,
		definition: definitionID,
		version:    7,
		valueKind:  "text",
		expression: "(SELECT sorted.text_value FROM values AS sorted WHERE sorted.object_id = ticket.id)",
		direction:  "asc",
		nulls:      "last",
	}
	hostile := "x') OR TRUE; SELECT pg_sleep(10); --"
	cursorID := mustPostgresUUIDv7(t)
	encoded := encodeDynamicTicketCursor(t, ticketCursor{
		Version: 1,
		Sort: fmt.Sprintf(
			"saved:%s:%s:%d:%s:%s",
			plan.source, definitionID, plan.version, plan.direction, plan.nulls,
		),
		ID:          cursorID,
		Fingerprint: base64.RawURLEncoding.EncodeToString(fingerprint[:]),
		Dynamic:     json.RawMessage(strconvJSONString(t, hostile)),
	})
	arguments := make([]any, 0, 2)
	add := func(value any) string {
		arguments = append(arguments, value)
		return fmt.Sprintf("$%d", len(arguments))
	}
	_, order, predicate, err := ticketDynamicSort(plan, encoded, fingerprint, add)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(order, hostile) || strings.Contains(predicate, hostile) ||
		len(arguments) != 2 || arguments[0] != cursorID || arguments[1] != hostile {
		t.Fatalf("dynamic cursor was not parameterized: order=%q predicate=%q arguments=%#v", order, predicate, arguments)
	}
	drift := sha256.Sum256([]byte("different live scope"))
	if _, _, _, err := ticketDynamicSort(plan, encoded, drift, add); !errors.Is(err, application.ErrInvalidInput) {
		t.Fatalf("fingerprint drift error = %v, want invalid input", err)
	}
}

func TestTicketDynamicSortNullCursorPreservesNullOrder(t *testing.T) {
	fingerprint := sha256.Sum256([]byte("null ordering"))
	for _, direction := range []string{"asc", "desc"} {
		for _, nulls := range []string{"first", "last"} {
			t.Run(direction+"_nulls_"+nulls, func(t *testing.T) {
				plan := &ticketDynamicSortPlan{
					source: application.SavedViewDefinitionSLA, definition: mustPostgresUUIDv7(t),
					version: 3, valueKind: "instant", expression: "dynamic_value",
					direction: direction, nulls: nulls,
				}
				sortName := fmt.Sprintf(
					"saved:%s:%s:%d:%s:%s",
					plan.source, plan.definition, plan.version, plan.direction, plan.nulls,
				)
				encoded := encodeDynamicTicketCursor(t, ticketCursor{
					Version: 1, Sort: sortName, ID: mustPostgresUUIDv7(t),
					Fingerprint: base64.RawURLEncoding.EncodeToString(fingerprint[:]), DynamicNull: true,
				})
				arguments := make([]any, 0, 1)
				_, order, predicate, err := ticketDynamicSort(plan, encoded, fingerprint, func(value any) string {
					arguments = append(arguments, value)
					return "$1"
				})
				wantDirection, wantOperator := "ASC", ">"
				if direction == "desc" {
					wantDirection, wantOperator = "DESC", "<"
				}
				if err != nil || !strings.Contains(order, wantDirection+" NULLS "+strings.ToUpper(nulls)) ||
					!strings.Contains(predicate, "ticket.id "+wantOperator+" $1") || len(arguments) != 1 {
					t.Fatalf("null cursor compilation = order %q predicate %q arguments %#v error %v", order, predicate, arguments, err)
				}
				if nulls == "first" && !strings.Contains(predicate, "IS NOT NULL") ||
					nulls == "last" && strings.Contains(predicate, "IS NOT NULL") {
					t.Fatalf("null cursor crossed null partition incorrectly: %q", predicate)
				}
			})
		}
	}
}

func TestTicketDynamicSortCompilesEveryIndexedScalarCursor(t *testing.T) {
	fingerprint := sha256.Sum256([]byte("all indexed scalar cursors"))
	reference := mustPostgresUUIDv7(t)
	tests := []struct {
		kind string
		raw  string
		cast string
	}{
		{kind: "text", raw: `"alpha"`},
		{kind: "integer", raw: `42`},
		{kind: "decimal", raw: `42.5`, cast: "::numeric"},
		{kind: "float", raw: `42.5`},
		{kind: "boolean", raw: `true`},
		{kind: "date", raw: `"2026-08-26"`, cast: "::date"},
		{kind: "instant", raw: `"2026-08-26T10:11:12.123Z"`, cast: "::timestamptz"},
		{kind: "inet", raw: `"2001:db8::1"`, cast: "::inet"},
		{kind: "cidr", raw: `"2001:db8::/48"`, cast: "::cidr"},
		{kind: "uuid", raw: strconvJSONString(t, reference.String()), cast: "::uuid"},
		{kind: "single_select", raw: `"malware"`},
	}
	for _, test := range tests {
		for _, direction := range []string{"asc", "desc"} {
			t.Run(test.kind+"_"+direction, func(t *testing.T) {
				plan := &ticketDynamicSortPlan{
					source: application.SavedViewDefinitionCustomField, definition: mustPostgresUUIDv7(t),
					version: 11, valueKind: test.kind, expression: "saved_view_sort.typed_value",
					direction: direction, nulls: "last",
				}
				sortName := fmt.Sprintf("saved:%s:%s:%d:%s:%s", plan.source, plan.definition, plan.version, direction, plan.nulls)
				encoded := encodeDynamicTicketCursor(t, ticketCursor{
					Version: 1, Sort: sortName, ID: mustPostgresUUIDv7(t),
					Fingerprint: base64.RawURLEncoding.EncodeToString(fingerprint[:]),
					Dynamic:     json.RawMessage(test.raw),
				})
				arguments := make([]any, 0, 2)
				_, order, predicate, err := ticketDynamicSort(plan, encoded, fingerprint, func(value any) string {
					arguments = append(arguments, value)
					return fmt.Sprintf("$%d", len(arguments))
				})
				wantDirection, wantOperator := "ASC", ">"
				if direction == "desc" {
					wantDirection, wantOperator = "DESC", "<"
				}
				if err != nil || len(arguments) != 2 ||
					!strings.Contains(order, wantDirection+" NULLS LAST") ||
					!strings.Contains(predicate, wantOperator+" $2"+test.cast) ||
					!strings.Contains(predicate, "= $2"+test.cast) ||
					!strings.Contains(predicate, " OR saved_view_sort.typed_value IS NULL") {
					t.Fatalf("%s cursor compilation = order %q predicate %q args %#v error %v", test.kind, order, predicate, arguments, err)
				}
			})
		}
	}
}

func TestResolveTicketDynamicSortPlanMapsStalePinsToConflict(t *testing.T) {
	fixture := newPostgresSavedViewFixture(t)
	customPin, ok := fixture.spec.Columns()[1].Definition()
	if !ok {
		t.Fatal("custom fixture column has no definition pin")
	}
	customSort, err := kernel.NewSavedViewDynamicSort(
		kernel.SavedViewColumnCustomField, customPin,
		kernel.SavedViewSortAscending, kernel.SavedViewNullsLast,
	)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		sort kernel.SavedViewSort
	}{
		{name: "custom field", sort: customSort},
		{name: "sla", sort: fixture.spec.Sort()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tx := &savedViewSortLookupTransaction{row: rowFunc(func(...any) error { return pgx.ErrNoRows })}
			_, err := resolveTicketDynamicSortPlan(
				context.Background(), tx, fixture.tenantID, fixture.kind,
				&ticketSavedViewExecution{sort: test.sort}, func(any) string { return "$4" },
			)
			if !errors.Is(err, application.ErrConflict) {
				t.Fatalf("stale pin error = %v, want conflict", err)
			}
		})
	}
}

func TestResolveTicketDynamicSortPlanUsesOneTypedJoin(t *testing.T) {
	fixture := newPostgresSavedViewFixture(t)
	customPin, _ := fixture.spec.Columns()[1].Definition()
	customSort, _ := kernel.NewSavedViewDynamicSort(
		kernel.SavedViewColumnCustomField, customPin,
		kernel.SavedViewSortAscending, kernel.SavedViewNullsLast,
	)
	customTx := &savedViewSortLookupTransaction{row: rowFunc(func(destinations ...any) error {
		*destinations[0].(*string) = string(customkernel.TypeDecimal)
		return nil
	})}
	arguments := make([]any, 0, 4)
	customPlan, err := resolveTicketDynamicSortPlan(
		context.Background(), customTx, fixture.tenantID, fixture.kind,
		&ticketSavedViewExecution{sort: customSort}, func(value any) string {
			arguments = append(arguments, value)
			return fmt.Sprintf("$%d", len(arguments))
		},
	)
	if err != nil || customPlan == nil || customPlan.expression != "saved_view_sort.decimal_value" ||
		!strings.Contains(customPlan.join, "LEFT JOIN public.custom_field_values") ||
		!strings.Contains(customPlan.join, "saved_view_sort.data_type") ||
		!strings.Contains(customTx.query, "schema_version = $3") ||
		strings.Contains(customTx.query, "active_schema_version") ||
		strings.Contains(customPlan.expression, "SELECT") || len(arguments) != 4 {
		t.Fatalf("custom dynamic plan = (%#v, query=%q, args=%#v, err=%v)", customPlan, customTx.query, arguments, err)
	}

	slaTx := &savedViewSortLookupTransaction{row: rowFunc(func(destinations ...any) error {
		*destinations[0].(*string) = "datetime"
		return nil
	})}
	slaPlan, err := resolveTicketDynamicSortPlan(
		context.Background(), slaTx, fixture.tenantID, fixture.kind,
		&ticketSavedViewExecution{sort: fixture.spec.Sort()}, func(any) string { return "$1" },
	)
	if err != nil || slaPlan == nil || slaPlan.expression != "saved_view_sort.instant_value" ||
		!strings.Contains(slaTx.query, "FROM app.ticket_sla_column_revisions_v1") ||
		strings.Contains(slaTx.query, "public.sla_column_versions") ||
		!strings.Contains(slaPlan.join, "LEFT JOIN app.ticket_sla_instant_sort_values_v1") ||
		strings.Contains(slaPlan.join, "public.sla_materialized_column_values") {
		t.Fatalf("SLA dynamic plan = (%#v, err=%v)", slaPlan, err)
	}
}

func TestSLASortColumnUsesOperationShapedProjections(t *testing.T) {
	tests := []struct {
		format     string
		column     string
		valueKind  string
		projection string
	}{
		{"datetime", "instant_value", "instant", "ticket_sla_instant_sort_values_v1"},
		{"duration", "duration_micros_value", "integer", "ticket_sla_duration_sort_values_v1"},
		{"state_badge", "state_value", "text", "ticket_sla_state_sort_values_v1"},
		{"percentage", "percentage_value", "float", "ticket_sla_percentage_sort_values_v1"},
		{"future", "", "", ""},
	}
	for _, test := range tests {
		t.Run(test.format, func(t *testing.T) {
			column, valueKind, projection := slaSortColumn(test.format)
			if column != test.column || valueKind != test.valueKind || projection != test.projection {
				t.Fatalf("slaSortColumn(%q) = (%q, %q, %q)", test.format, column, valueKind, projection)
			}
		})
	}
}

func TestSavedViewSLALoaderUsesOnlyTenantSafeProjection(t *testing.T) {
	source, err := os.ReadFile("ticketing_saved_view_query.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if strings.Count(text, "app.ticket_sla_materialized_values_v1") != 1 ||
		strings.Count(text, "app.ticket_sla_column_revisions_v1") != 1 ||
		strings.Contains(text, "public.sla_materialized_column_values") ||
		strings.Contains(text, "public.sla_column_versions") {
		t.Fatalf("saved-view SLA resolver/sort/loader projection drifted: %q", text)
	}
	for _, projection := range []string{
		"ticket_sla_instant_sort_values_v1",
		"ticket_sla_duration_sort_values_v1",
		"ticket_sla_state_sort_values_v1",
		"ticket_sla_percentage_sort_values_v1",
	} {
		if strings.Count(text, projection) != 1 {
			t.Fatalf("saved-view SLA typed projection %q drifted", projection)
		}
	}
}

func TestDynamicProjectionTypeChecksFailClosed(t *testing.T) {
	if !projectableCustomScalarType(customkernel.TypeBoolean) ||
		projectableCustomScalarType(customkernel.TypeMultiSelect) ||
		projectableCustomScalarType(customkernel.TypeStructuredJSON) {
		t.Fatal("custom dynamic projection scalar allowlist drifted")
	}
	instant := pgtype.Timestamptz{Time: time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC), Valid: true}
	if _, err := canonicalSLADynamicValue("datetime", pgtype.Text{}, instant, pgtype.Int8{}, pgtype.Float8{}); err != nil {
		t.Fatalf("matching SLA datetime projection error = %v", err)
	}
	if _, err := canonicalSLADynamicValue("duration", pgtype.Text{}, instant, pgtype.Int8{}, pgtype.Float8{}); !errors.Is(err, application.ErrUnavailable) {
		t.Fatalf("type-drifted SLA projection error = %v, want unavailable", err)
	}
	if _, err := canonicalSLADynamicValue("future", pgtype.Text{String: "green", Valid: true}, pgtype.Timestamptz{}, pgtype.Int8{}, pgtype.Float8{}); !errors.Is(err, application.ErrUnavailable) {
		t.Fatalf("unknown SLA format error = %v, want unavailable", err)
	}
}

func TestDynamicCursorArgumentIsSingleCanonicalScalar(t *testing.T) {
	validInstant := time.Date(2026, 8, 26, 10, 11, 12, 123_000_000, time.UTC)
	reference := mustPostgresUUIDv7(t)
	tests := []struct {
		name string
		kind string
		raw  string
		ok   bool
	}{
		{name: "text", kind: "text", raw: `""`, ok: true},
		{name: "integer", kind: "integer", raw: `9223372036854775807`, ok: true},
		{name: "decimal", kind: "decimal", raw: `-125.25`, ok: true},
		{name: "decimal beyond float64", kind: "decimal", raw: strings.Repeat("9", 200), ok: true},
		{name: "float", kind: "float", raw: `99.5`, ok: true},
		{name: "boolean", kind: "boolean", raw: `true`, ok: true},
		{name: "date", kind: "date", raw: `"2026-08-26"`, ok: true},
		{name: "instant", kind: "instant", raw: strconvJSONString(t, validInstant.Format(time.RFC3339Nano)), ok: true},
		{name: "inet v4", kind: "inet", raw: `"192.0.2.4"`, ok: true},
		{name: "inet v6", kind: "inet", raw: `"2001:db8::4"`, ok: true},
		{name: "cidr", kind: "cidr", raw: `"2001:db8::/48"`, ok: true},
		{name: "reference", kind: "uuid", raw: strconvJSONString(t, reference.String()), ok: true},
		{name: "single select", kind: "single_select", raw: `"malware_family"`, ok: true},
		{name: "trailing decimal", kind: "decimal", raw: `1.25 true`},
		{name: "overflow decimal", kind: "decimal", raw: `1e999999`},
		{name: "decimal whitespace", kind: "decimal", raw: ` 1.25`},
		{name: "fractional integer", kind: "integer", raw: `1.5`},
		{name: "integer alternate encoding", kind: "integer", raw: `1.0`},
		{name: "boolean string", kind: "boolean", raw: `"true"`},
		{name: "boolean whitespace", kind: "boolean", raw: `true `},
		{name: "invalid date", kind: "date", raw: `"2026-02-30"`},
		{name: "sub-microsecond instant", kind: "instant", raw: `"2026-08-26T10:11:12.123456789Z"`},
		{name: "non-UTC instant", kind: "instant", raw: `"2026-08-26T12:11:12.123+02:00"`},
		{name: "noncanonical inet", kind: "inet", raw: `"2001:0db8::4"`},
		{name: "mapped inet", kind: "inet", raw: `"::ffff:192.0.2.4"`},
		{name: "inet with mask", kind: "inet", raw: `"192.0.2.4/24"`},
		{name: "unmasked cidr", kind: "cidr", raw: `"192.0.2.4/24"`},
		{name: "uppercase reference", kind: "uuid", raw: strconvJSONString(t, strings.ToUpper(reference.String()))},
		{name: "non-v7 reference", kind: "uuid", raw: `"00000000-0000-4000-8000-000000000000"`},
		{name: "invalid option key", kind: "single_select", raw: `"Malware"`},
		{name: "object", kind: "text", raw: `{}`},
		{name: "unknown kind", kind: "future", raw: `1`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := dynamicCursorArgument(test.kind, json.RawMessage(test.raw))
			if test.ok && err != nil {
				t.Fatalf("dynamicCursorArgument() error = %v", err)
			}
			if !test.ok && err == nil {
				t.Fatal("dynamicCursorArgument() accepted hostile value")
			}
		})
	}
}

func TestCanonicalCustomDynamicValueIsTypeExactAndNormalizesSingleSelect(t *testing.T) {
	reference := mustPostgresUUIDv7(t)
	tests := []struct {
		name     string
		dataType customkernel.DataType
		raw      string
		want     string
	}{
		{name: "text", dataType: customkernel.TypeShortText, raw: `"alpha"`, want: `"alpha"`},
		{name: "integer", dataType: customkernel.TypeInteger, raw: `42`, want: `42`},
		{name: "decimal DB scale", dataType: customkernel.TypeDecimal, raw: `42.500`, want: `42.5`},
		{name: "boolean", dataType: customkernel.TypeBoolean, raw: `false`, want: `false`},
		{name: "date", dataType: customkernel.TypeDate, raw: `"2026-08-26"`, want: `"2026-08-26"`},
		{name: "datetime DB offset", dataType: customkernel.TypeDateTime, raw: `"2026-08-26T12:11:12.123+02:00"`, want: `"2026-08-26T10:11:12.123Z"`},
		{name: "ip DB host prefix", dataType: customkernel.TypeIP, raw: `"192.0.2.4/32"`, want: `"192.0.2.4"`},
		{name: "cidr", dataType: customkernel.TypeCIDR, raw: `"192.0.2.0/24"`, want: `"192.0.2.0/24"`},
		{name: "reference", dataType: customkernel.TypeAssetReference, raw: strconvJSONString(t, reference.String()), want: strconvJSONString(t, reference.String())},
		{name: "single select DB array", dataType: customkernel.TypeSingleSelect, raw: `["malware"]`, want: `"malware"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := canonicalCustomDynamicValue(test.dataType, json.RawMessage(test.raw))
			if err != nil || string(got) != test.want {
				t.Fatalf("canonicalCustomDynamicValue() = %s, %v; want %s", got, err, test.want)
			}
		})
	}
	for _, hostile := range []struct {
		dataType customkernel.DataType
		raw      string
	}{
		{dataType: customkernel.TypeBoolean, raw: `1`},
		{dataType: customkernel.TypeDate, raw: `"2026-02-30"`},
		{dataType: customkernel.TypeIP, raw: `"2001:0db8::1/128"`},
		{dataType: customkernel.TypeIP, raw: `"192.0.2.0/24"`},
		{dataType: customkernel.TypeCIDR, raw: `"192.0.2.4/24"`},
		{dataType: customkernel.TypeAssetReference, raw: `"00000000-0000-4000-8000-000000000000"`},
		{dataType: customkernel.TypeSingleSelect, raw: `"malware"`},
		{dataType: customkernel.TypeSingleSelect, raw: `["malware","phishing"]`},
		{dataType: customkernel.TypeSingleSelect, raw: `["Malware"]`},
		{dataType: customkernel.TypeMultiSelect, raw: `["malware"]`},
	} {
		if _, err := canonicalCustomDynamicValue(hostile.dataType, json.RawMessage(hostile.raw)); !errors.Is(err, application.ErrUnavailable) {
			t.Fatalf("hostile %q/%s error = %v, want unavailable", hostile.dataType, hostile.raw, err)
		}
	}
}

func TestDecimalDynamicCursorRoundTripsBeyondFloat64(t *testing.T) {
	fingerprint := sha256.Sum256([]byte("wide numeric cursor"))
	wide := strings.Repeat("9", 200)
	plan := &ticketDynamicSortPlan{
		source: application.SavedViewDefinitionCustomField, definition: mustPostgresUUIDv7(t),
		version: 9, valueKind: "decimal", expression: "saved_view_sort.decimal_value",
		direction: "asc", nulls: "last",
	}
	sortName := fmt.Sprintf("saved:%s:%s:%d:%s:%s", plan.source, plan.definition, plan.version, plan.direction, plan.nulls)
	encoded := encodeDynamicTicketCursor(t, ticketCursor{
		Version: 1, Sort: sortName, ID: mustPostgresUUIDv7(t),
		Fingerprint: base64.RawURLEncoding.EncodeToString(fingerprint[:]),
		Dynamic:     json.RawMessage(wide),
	})
	arguments := make([]any, 0, 2)
	_, _, predicate, err := ticketDynamicSort(plan, encoded, fingerprint, func(value any) string {
		arguments = append(arguments, value)
		return fmt.Sprintf("$%d", len(arguments))
	})
	if err != nil || len(arguments) != 2 || arguments[1] != wide || !strings.Contains(predicate, "$2::numeric") {
		t.Fatalf("wide decimal round trip = predicate %q arguments %#v error %v", predicate, arguments, err)
	}
}

func TestTicketDynamicScalarRejectsNullCollectionsAndTrailingJSON(t *testing.T) {
	for _, valid := range []string{`"text"`, `true`, `0`, `-1.25`} {
		if !validTicketDynamicScalar([]byte(valid)) {
			t.Fatalf("valid scalar %s was rejected", valid)
		}
	}
	for _, invalid := range []string{`null`, `[]`, `{}`, `"text" true`, `NaN`} {
		if validTicketDynamicScalar([]byte(invalid)) {
			t.Fatalf("hostile scalar %s was accepted", invalid)
		}
	}
}

func encodeDynamicTicketCursor(t testing.TB, cursor ticketCursor) string {
	t.Helper()
	raw, err := json.Marshal(cursor)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func strconvJSONString(t testing.TB, value string) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

type savedViewSortLookupTransaction struct {
	recordingTransaction
	row   pgx.Row
	query string
}

func (tx *savedViewSortLookupTransaction) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	tx.query = query
	return tx.row
}
