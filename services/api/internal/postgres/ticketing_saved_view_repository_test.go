package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	customkernel "github.com/periapsis-im/periapsis/modules/customfields"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func TestSavedViewResolvedSpecWireBindsExactCustomAndSLAPins(t *testing.T) {
	fixture := newPostgresSavedViewFixture(t)
	actorID := mustPostgresUUIDv7(t)
	request, err := newSavedViewResolveSpecRequestFromValidated(
		fixture.tenantID, actorID, fixture.ownerID, fixture.kind, fixture.input,
	)
	if err != nil || request.ActorID != actorID.String() || request.OwnerMembershipID != fixture.ownerID.String() {
		t.Fatalf("newSavedViewResolveSpecRequestFromValidated() = (%#v, %v)", request, err)
	}
	requestJSON, err := marshalSavedViewWire(request, maximumSavedViewResolveRequestBytes)
	if err != nil || !bytes.Contains(requestJSON, []byte(`"states":[]`)) {
		t.Fatalf("canonical resolve request = (%s, %v)", requestJSON, err)
	}
	response := savedViewResolvedSpecResponse(t, fixture.canonical)
	resolved, err := restoreSavedViewResolvedSpec(
		response, fixture.tenantID, fixture.kind, fixture.input,
	)
	if err != nil {
		t.Fatalf("restoreSavedViewResolvedSpec() error = %v", err)
	}
	if digest, digestErr := application.SavedViewSpecDigest(
		fixture.tenant, fixture.kind, resolved,
	); digestErr != nil || digest != fixture.digest {
		t.Fatalf("resolved spec digest = %x, %v; want %x", digest, digestErr, fixture.digest)
	}

	tests := []struct {
		name   string
		mutate func(*application.SavedViewSpecInput)
	}{
		{name: "custom id drift", mutate: func(input *application.SavedViewSpecInput) {
			input.Filters.Custom[0].DefinitionID = mustPostgresUUIDv7(t)
		}},
		{name: "custom version drift", mutate: func(input *application.SavedViewSpecInput) {
			input.Filters.Custom[0].ExpectedDefinitionVersion++
		}},
		{name: "sla column version drift", mutate: func(input *application.SavedViewSpecInput) {
			input.Columns[2].ExpectedDefinitionVersion++
		}},
		{name: "sla sort id drift", mutate: func(input *application.SavedViewSpecInput) {
			identifier := mustPostgresUUIDv7(t)
			input.Sort.DefinitionID = &identifier
		}},
		{name: "filter value drift", mutate: func(input *application.SavedViewSpecInput) {
			input.Filters.Custom[0].Value = json.RawMessage(`10.6`)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := clonePostgresSavedViewInput(fixture.input)
			test.mutate(&candidate)
			if _, err := restoreSavedViewResolvedSpec(
				response, fixture.tenantID, fixture.kind, candidate,
			); !errors.Is(err, application.ErrUnavailable) {
				t.Fatalf("pin drift error = %v, want unavailable", err)
			}
		})
	}

	// Numeric spellings are semantic scalar values, not alternate pins. The
	// database may canonicalize 10.50 to 10.5 after resolving decimal type.
	equivalent := clonePostgresSavedViewInput(fixture.input)
	equivalent.Filters.Custom[0].Value = json.RawMessage(`1.050e1`)
	if _, err := restoreSavedViewResolvedSpec(
		response, fixture.tenantID, fixture.kind, equivalent,
	); err != nil {
		t.Fatalf("equivalent decimal spelling error = %v", err)
	}
	losslessBrowser := clonePostgresSavedViewInput(fixture.input)
	losslessBrowser.Filters.Custom[0].Value = json.RawMessage(`"10.5"`)
	if _, err := restoreSavedViewResolvedSpec(
		response, fixture.tenantID, fixture.kind, losslessBrowser,
	); err != nil {
		t.Fatalf("lossless browser decimal string error = %v", err)
	}
	hostileExponent := clonePostgresSavedViewInput(fixture.input)
	hostileExponent.Filters.Custom[0].Value = json.RawMessage(`1e999999999`)
	if _, err := restoreSavedViewResolvedSpec(
		response, fixture.tenantID, fixture.kind, hostileExponent,
	); !errors.Is(err, application.ErrUnavailable) {
		t.Fatalf("unbounded exponent error = %v, want unavailable", err)
	}
}

func TestSavedViewWireRejectsUnknownDuplicateMissingAndDigestDrift(t *testing.T) {
	fixture := newPostgresSavedViewFixture(t)
	record := fixture.recordJSON(t, fixture.viewID)
	valid, err := json.Marshal(savedViewGetResponseV1{SchemaVersion: 1, Record: record})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restoreSavedViewGetResponse(
		valid, fixture.tenantID, fixture.ownerID, fixture.kind,
	); err != nil {
		t.Fatalf("valid get response error = %v", err)
	}
	utcOffset := []byte(strings.ReplaceAll(string(valid), "Z\"", "+00:00\""))
	if _, err := restoreSavedViewGetResponse(
		utcOffset, fixture.tenantID, fixture.ownerID, fixture.kind,
	); err != nil {
		t.Fatalf("zero-offset UTC response error = %v", err)
	}
	nonUTCOffset := []byte(strings.ReplaceAll(string(valid), "Z\"", "+01:00\""))
	if _, err := restoreSavedViewGetResponse(
		nonUTCOffset, fixture.tenantID, fixture.ownerID, fixture.kind,
	); !errors.Is(err, application.ErrUnavailable) {
		t.Fatalf("non-UTC response error = %v, want unavailable", err)
	}

	unknown := fmt.Sprintf(`{"schemaVersion":1,"record":%s,"future":true}`, record)
	duplicate := fmt.Sprintf(`{"schemaVersion":1,"schemaVersion":1,"record":%s}`, record)
	missing := fmt.Sprintf(`{"schemaVersion":1,"record":%s}`,
		strings.Replace(string(record), `,"archivedAt":null`, "", 1))
	for name, raw := range map[string][]byte{
		"unknown field": []byte(unknown), "duplicate field": []byte(duplicate),
		"missing nested field": []byte(missing),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := restoreSavedViewGetResponse(
				raw, fixture.tenantID, fixture.ownerID, fixture.kind,
			); !errors.Is(err, application.ErrUnavailable) {
				t.Fatalf("wire error = %v, want unavailable", err)
			}
		})
	}

	var recordMap map[string]any
	if err := json.Unmarshal(record, &recordMap); err != nil {
		t.Fatal(err)
	}
	recordMap["specSha256"] = strings.Repeat("00", sha256.Size)
	driftedRecord, _ := json.Marshal(recordMap)
	drifted, _ := json.Marshal(savedViewGetResponseV1{SchemaVersion: 1, Record: driftedRecord})
	if _, err := restoreSavedViewGetResponse(
		drifted, fixture.tenantID, fixture.ownerID, fixture.kind,
	); !errors.Is(err, application.ErrUnavailable) {
		t.Fatalf("digest drift error = %v, want unavailable", err)
	}

	oversized := make([]byte, maximumSavedViewRecordResponseBytes+1)
	for index := range oversized {
		oversized[index] = ' '
	}
	if _, err := restoreSavedViewGetResponse(
		oversized, fixture.tenantID, fixture.ownerID, fixture.kind,
	); !errors.Is(err, application.ErrUnavailable) {
		t.Fatalf("oversized response error = %v, want unavailable", err)
	}
}

func TestSavedViewWireTokenLimitIncludesCompoundDelimiters(t *testing.T) {
	withinLimit := []byte("[" + strings.Repeat("0,", maximumSavedViewWireTokens-3) + "0]")
	if err := validateSavedViewJSONTokens(withinLimit); err != nil {
		t.Fatalf("exact token limit error = %v", err)
	}

	overLimit := []byte("[" + strings.Repeat("0,", maximumSavedViewWireTokens-2) + "0]")
	if err := validateSavedViewJSONTokens(overLimit); !errors.Is(err, application.ErrUnavailable) {
		t.Fatalf("token overflow error = %v, want unavailable", err)
	}
}

func TestSavedViewGetCollapsesForeignIdentityWhileListFailsClosed(t *testing.T) {
	fixture := newPostgresSavedViewFixture(t)
	foreignOwner := mustPostgresUUIDv7(t)
	record := fixture.recordJSONWithIdentity(t, fixture.viewID, fixture.tenantID, foreignOwner, fixture.kind)
	getResponse, _ := json.Marshal(savedViewGetResponseV1{SchemaVersion: 1, Record: record})
	if _, err := restoreSavedViewGetResponse(
		getResponse, fixture.tenantID, fixture.ownerID, fixture.kind,
	); !errors.Is(err, application.ErrNotFound) {
		t.Fatalf("foreign owner get error = %v, want not found", err)
	}

	hasMore := false
	listResponse, _ := json.Marshal(savedViewListResponseV1{
		SchemaVersion: 1, Records: []json.RawMessage{record}, HasMore: &hasMore,
	})
	if _, err := restoreSavedViewPage(
		listResponse, fixture.tenantID, fixture.ownerID, fixture.kind, uuid.Nil, 10, true,
	); !errors.Is(err, application.ErrUnavailable) {
		t.Fatalf("foreign owner list error = %v, want unavailable", err)
	}
}

func TestSavedViewPageRequiresStrictOrderAndCanonicalCursor(t *testing.T) {
	fixture := newPostgresSavedViewFixture(t)
	first, second := fixture.viewID, mustPostgresUUIDv7(t)
	if strings.Compare(first.String(), second.String()) > 0 {
		first, second = second, first
	}
	hasMore := true
	response, _ := json.Marshal(savedViewListResponseV1{
		SchemaVersion: 1,
		Records:       []json.RawMessage{fixture.recordJSON(t, first), fixture.recordJSON(t, second)},
		HasMore:       &hasMore,
	})
	page, err := restoreSavedViewPage(
		response, fixture.tenantID, fixture.ownerID, fixture.kind, uuid.Nil, 2, false,
	)
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("restoreSavedViewPage() = (%s, %v)", page, err)
	}
	decoded, err := decodeSavedViewCursor(page.NextCursor)
	if err != nil || decoded != second {
		t.Fatalf("next cursor = (%s, %v), want %s", decoded, err, second)
	}
	for _, malformed := range []string{page.NextCursor + "=", "AQ", encodeSavedViewCursor(uuid.Nil)} {
		if _, err := decodeSavedViewCursor(malformed); !errors.Is(err, application.ErrInvalidInput) {
			t.Fatalf("decodeSavedViewCursor(%q) error = %v", malformed, err)
		}
	}

	response, _ = json.Marshal(savedViewListResponseV1{
		SchemaVersion: 1,
		Records:       []json.RawMessage{fixture.recordJSON(t, second), fixture.recordJSON(t, first)},
		HasMore:       &hasMore,
	})
	if _, err := restoreSavedViewPage(
		response, fixture.tenantID, fixture.ownerID, fixture.kind, uuid.Nil, 2, false,
	); !errors.Is(err, application.ErrUnavailable) {
		t.Fatalf("descending page error = %v, want unavailable", err)
	}
}

func TestSavedViewReplayWireBindsActorOwnerActionAndFingerprint(t *testing.T) {
	fixture := newPostgresSavedViewFixture(t)
	actorID := mustPostgresUUIDv7(t)
	fingerprint := sha256.Sum256([]byte("saved-view replay fingerprint"))
	base := savedViewReplayResponseV1{
		SchemaVersion: 1, ActorID: actorID.String(), OwnerMembershipID: fixture.ownerID.String(),
		Action:                   kernel.SavedViewCreate.String(),
		RequestFingerprintSHA256: encodeSavedViewDigest(fingerprint),
		Record:                   fixture.recordJSON(t, fixture.viewID),
	}
	response, _ := json.Marshal(base)
	result, returned, err := restoreSavedViewReplayResponse(
		response, fixture.tenantID, actorID, fixture.ownerID, fixture.kind, kernel.SavedViewCreate,
	)
	if err != nil || !result.Replayed || returned != fingerprint {
		t.Fatalf("restore replay = (%s, %x, %v)", result, returned, err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*savedViewReplayResponseV1)
	}{
		{name: "actor drift", mutate: func(value *savedViewReplayResponseV1) {
			value.ActorID = mustPostgresUUIDv7(t).String()
		}},
		{name: "owner drift", mutate: func(value *savedViewReplayResponseV1) {
			value.OwnerMembershipID = mustPostgresUUIDv7(t).String()
		}},
		{name: "action drift", mutate: func(value *savedViewReplayResponseV1) {
			value.Action = kernel.SavedViewArchive.String()
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			test.mutate(&candidate)
			raw, _ := json.Marshal(candidate)
			if _, _, err := restoreSavedViewReplayResponse(
				raw, fixture.tenantID, actorID, fixture.ownerID,
				fixture.kind, kernel.SavedViewCreate,
			); !errors.Is(err, application.ErrUnavailable) {
				t.Fatalf("binding drift error = %v, want unavailable", err)
			}
		})
	}
}

func TestSavedViewCommitWireIsRedactedAndBindsMutationSnapshot(t *testing.T) {
	fixture := newPostgresSavedViewFixture(t)
	plan, err := kernel.PlanSavedViewCreation(
		fixture.view.ID(), fixture.tenant, fixture.owner, fixture.kind,
		fixture.view.Name(), fixture.spec,
	)
	if err != nil {
		t.Fatal(err)
	}
	actor := application.Actor{
		UserID: mustPostgresUUIDv7(t), SessionID: mustPostgresUUIDv7(t),
		ActiveTenantID: fixture.tenantID, AuthenticationMethod: "passkey",
		Audit: application.AuditContext{
			RequestID: uuid.New(), CorrelationID: uuid.New(),
			RemoteAddress: netip.MustParseAddr("192.0.2.44"),
			UserAgent:     "saved-view adapter test",
		},
	}
	binding, err := application.BindSavedViewPlanCommand(
		"saved-view-adapter-create-0001", fixture.ownerID, plan,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := application.BindSavedViewPlanCommand(
		"saved-view-adapter-create-0001", mustPostgresUUIDv7(t), plan,
	); !errors.Is(err, application.ErrInvalidInput) {
		t.Fatalf("foreign command owner error = %v, want invalid input", err)
	}
	fingerprint := binding.Fingerprint
	repository := &TicketingRepository{newID: uuid.NewV7}
	write := application.SavedViewWrite{
		Actor: actor, RequiredCapability: application.SavedViewCapabilityManage,
		OwnerMembershipID: fixture.ownerID, Plan: plan,
		Command: binding,
		Audit:   actor.Audit,
	}
	request, next, err := newSavedViewCommitRequest(repository, write)
	if err != nil {
		t.Fatalf("newSavedViewCommitRequest() error = %v", err)
	}
	if request.Action != "create" || request.ExpectedRevision != 0 || request.NextRevision != 1 ||
		request.OwnerMembershipID != fixture.ownerID.String() ||
		request.SpecSHA256 != encodeSavedViewDigest(fixture.digest) ||
		request.Audit.AuthenticationMethod != "passkey" {
		t.Fatalf("commit request binding = %#v", request)
	}
	for _, secret := range []string{fixture.view.Name(), fixture.input.Filters.Search, actor.Audit.UserAgent} {
		if strings.Contains(fmt.Sprintf("%#v", request), secret) {
			t.Fatalf("commit diagnostic leaked %q", secret)
		}
	}
	driftedBinding := binding
	driftedBinding.Fingerprint[0] ^= 0xff
	if _, _, err := newSavedViewCommitRequest(repository, application.SavedViewWrite{
		Actor: actor, RequiredCapability: application.SavedViewCapabilityManage,
		OwnerMembershipID: fixture.ownerID, Plan: plan, Command: driftedBinding, Audit: actor.Audit,
	}); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("plan/command fingerprint drift error = %v, want forbidden", err)
	}
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()
	generated := 0
	canceledRepository := &TicketingRepository{newID: func() (uuid.UUID, error) {
		generated++
		return uuid.NewV7()
	}}
	if _, err := canceledRepository.CommitSavedView(canceledContext, write); !errors.Is(err, context.Canceled) || generated != 0 {
		t.Fatalf("canceled commit = (error:%v, generated:%d)", err, generated)
	}

	response := savedViewCommitResponseV1{
		SchemaVersion: 1, ActorID: actor.UserID.String(),
		OwnerMembershipID: fixture.ownerID.String(), Action: kernel.SavedViewCreate.String(),
		RequestFingerprintSHA256: encodeSavedViewDigest(fingerprint),
		Replayed:                 boolPointer(false), Record: fixture.recordJSON(t, fixture.viewID),
	}
	raw, _ := json.Marshal(response)
	result, err := restoreSavedViewCommitResponse(
		raw, fixture.tenantID, actor.UserID, fixture.ownerID,
		kernel.SavedViewCreate, fingerprint, next,
	)
	if err != nil || result.Replayed {
		t.Fatalf("restore commit = (%s, %v)", result, err)
	}

	response.RequestFingerprintSHA256 = encodeSavedViewDigest(sha256.Sum256([]byte("drift")))
	raw, _ = json.Marshal(response)
	if _, err := restoreSavedViewCommitResponse(
		raw, fixture.tenantID, actor.UserID, fixture.ownerID,
		kernel.SavedViewCreate, fingerprint, next,
	); !errors.Is(err, application.ErrConflict) {
		t.Fatalf("commit fingerprint drift error = %v, want conflict", err)
	}

	response.RequestFingerprintSHA256 = encodeSavedViewDigest(fingerprint)
	response.Replayed = boolPointer(true)
	response.Record = fixture.recordJSON(t, mustPostgresUUIDv7(t))
	raw, _ = json.Marshal(response)
	if result, err := restoreSavedViewCommitResponse(
		raw, fixture.tenantID, actor.UserID, fixture.ownerID,
		kernel.SavedViewCreate, fingerprint, next,
	); err != nil || !result.Replayed {
		t.Fatalf("concurrent create replay = (%s, %v)", result, err)
	}
}

func TestLookupSavedViewReplayUsesBoundedRepeatableReadABI(t *testing.T) {
	fixture := newPostgresSavedViewFixture(t)
	actorID := mustPostgresUUIDv7(t)
	keyHash := sha256.Sum256([]byte("saved-view replay key"))
	fingerprint := sha256.Sum256([]byte("saved-view replay command"))
	response, _ := json.Marshal(savedViewReplayResponseV1{
		SchemaVersion: 1, ActorID: actorID.String(), OwnerMembershipID: fixture.ownerID.String(),
		Action:                   kernel.SavedViewCreate.String(),
		RequestFingerprintSHA256: encodeSavedViewDigest(fingerprint),
		Record:                   fixture.recordJSON(t, fixture.viewID),
	})
	tx := &savedViewABITransaction{rows: []pgx.Row{
		rowFunc(func(destinations ...any) error {
			*destinations[0].(*string) = fixture.tenantID.String()
			*destinations[1].(*string) = actorID.String()
			return nil
		}),
		rowFunc(func(destinations ...any) error {
			*destinations[0].(*string), *destinations[1].(*string) = "", ""
			return nil
		}),
		rowFunc(func(destinations ...any) error {
			*destinations[0].(*[]byte) = slices.Clone(response)
			return nil
		}),
	}}
	beginCalls := 0
	var options pgx.TxOptions
	repository := &TicketingRepository{begin: func(ctx context.Context, requested pgx.TxOptions) (databaseTransaction, error) {
		beginCalls++
		options = requested
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			t.Fatal("saved-view transaction did not install a deadline")
		}
		return tx, nil
	}}
	result, found, err := repository.LookupSavedViewReplay(context.Background(), application.SavedViewReplayQuery{
		TenantID: fixture.tenantID, ActorID: actorID, OwnerMembershipID: fixture.ownerID,
		Kind: fixture.kind, Action: kernel.SavedViewCreate,
		KeyHash: keyHash, Fingerprint: fingerprint,
	})
	if err != nil || !found || !result.Replayed {
		t.Fatalf("LookupSavedViewReplay() = (%s, %t, %v)", result, found, err)
	}
	if beginCalls != 1 || options.IsoLevel != pgx.RepeatableRead || options.AccessMode != pgx.ReadOnly ||
		!tx.committed || len(tx.rows) != 0 || len(tx.queries) != 3 ||
		!strings.Contains(tx.queries[2], "lookup_ticket_saved_view_replay_v1") ||
		len(tx.arguments[2]) != 1 {
		t.Fatalf("replay transaction calls:%d options:%+v committed:%t rows:%d queries:%#v args:%#v",
			beginCalls, options, tx.committed, len(tx.rows), tx.queries, tx.arguments)
	}
	for _, ctx := range tx.contexts {
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			t.Fatal("saved-view query escaped the bounded operation context")
		}
	}
}

func TestSavedViewAdapterPreservesCancellationBeforeDatabaseWork(t *testing.T) {
	fixture := newPostgresSavedViewFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	beginCalls := 0
	repository := &TicketingRepository{begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
		beginCalls++
		return nil, errors.New("unexpected begin")
	}}
	_, _, err := repository.LookupSavedViewReplay(ctx, application.SavedViewReplayQuery{
		TenantID: fixture.tenantID, ActorID: mustPostgresUUIDv7(t),
		OwnerMembershipID: fixture.ownerID, Kind: fixture.kind, Action: kernel.SavedViewCreate,
		KeyHash: sha256.Sum256([]byte("key")), Fingerprint: sha256.Sum256([]byte("fingerprint")),
	})
	if !errors.Is(err, context.Canceled) || beginCalls != 0 {
		t.Fatalf("canceled replay = (error:%v, begin calls:%d)", err, beginCalls)
	}
	generated := 0
	repository.newID = func() (uuid.UUID, error) {
		generated++
		return uuid.NewV7()
	}
	if _, err := repository.ReserveSavedViewID(ctx, fixture.tenantID); !errors.Is(err, context.Canceled) || generated != 0 {
		t.Fatalf("canceled reservation = (error:%v, generated:%d)", err, generated)
	}
}

func TestSavedViewTicketReadAcceptsOnlyOperatorTicketScopes(t *testing.T) {
	authority := authorization.TenantAuthority{Permissions: []authorization.ScopedPermission{{
		Permission: authorization.TenantPermission(application.CapabilityAlertRead),
		Scope:      authorization.ScopeOperatorTeam,
	}}}
	if !savedViewHasTicketRead(authority, kernel.AggregateAlert) ||
		savedViewHasTicketRead(authority, kernel.AggregateCase) {
		t.Fatal("saved-view ticket read permission was not kind-bound")
	}
	authority.Permissions[0].Scope = authorization.ScopePlatform
	if savedViewHasTicketRead(authority, kernel.AggregateAlert) {
		t.Fatal("platform scope was accepted for a private tenant saved view")
	}
}

func TestSavedViewABIQueriesArePurposeSpecificSingleJSONBoundaries(t *testing.T) {
	queries := map[string]struct {
		query    string
		function string
	}{
		"resolve": {savedViewResolveSpecABIQuery, "resolve_ticket_saved_view_spec_v1"},
		"list":    {savedViewListABIQuery, "list_ticket_saved_views_v1"},
		"get":     {savedViewGetABIQuery, "get_ticket_saved_view_v1"},
		"replay":  {savedViewReplayABIQuery, "lookup_ticket_saved_view_replay_v1"},
		"commit":  {savedViewCommitABIQuery, "commit_ticket_saved_view_v1"},
	}
	seen := make(map[string]struct{}, len(queries))
	for purpose, contract := range queries {
		if _, duplicate := seen[contract.query]; duplicate {
			t.Fatalf("%s reused another purpose's database ABI", purpose)
		}
		seen[contract.query] = struct{}{}
		if !strings.Contains(contract.query, "SELECT response") ||
			!strings.Contains(contract.query, "app."+contract.function) ||
			strings.Count(contract.query, "$1::jsonb") != 1 || strings.Contains(contract.query, "public.") {
			t.Fatalf("%s ABI query is not one purpose-specific JSON boundary: %s", purpose, contract.query)
		}
	}
}

func TestSavedViewDatabaseErrorMappingPreservesSecurityAndCancellationSemantics(t *testing.T) {
	for _, test := range []struct {
		input error
		want  error
	}{
		{input: authorization.ErrDenied, want: application.ErrForbidden},
		{input: authorization.ErrNotFound, want: application.ErrForbidden},
		{input: authorization.ErrConflict, want: application.ErrConflict},
		{input: context.Canceled, want: context.Canceled},
		{input: context.DeadlineExceeded, want: context.DeadlineExceeded},
	} {
		if got := mapSavedViewDatabaseError(test.input); !errors.Is(got, test.want) {
			t.Fatalf("mapSavedViewDatabaseError(%v) = %v, want %v", test.input, got, test.want)
		}
	}
	if got := mapSavedViewDatabaseError(pgx.ErrNoRows); !errors.Is(got, application.ErrNotFound) {
		t.Fatalf("optional row miss = %v, want not found", got)
	}
	if got := mapSavedViewRequiredRowError(pgx.ErrNoRows); !errors.Is(got, application.ErrUnavailable) {
		t.Fatalf("required row miss = %v, want unavailable", got)
	}
}

type postgresSavedViewFixture struct {
	tenantID  uuid.UUID
	ownerID   uuid.UUID
	viewID    uuid.UUID
	tenant    kernel.EntityID
	owner     kernel.EntityID
	kind      kernel.AggregateKind
	input     application.SavedViewSpecInput
	spec      kernel.SavedViewSpec
	view      kernel.SavedView
	canonical []byte
	digest    [sha256.Size]byte
	createdAt time.Time
}

func newPostgresSavedViewFixture(t testing.TB) postgresSavedViewFixture {
	t.Helper()
	tenantID, ownerID, viewID := mustPostgresUUIDv7(t), mustPostgresUUIDv7(t), mustPostgresUUIDv7(t)
	tenant, err := ticketEntityID(tenantID)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := ticketEntityID(ownerID)
	if err != nil {
		t.Fatal(err)
	}
	viewEntity, err := ticketEntityID(viewID)
	if err != nil {
		t.Fatal(err)
	}
	customID, slaID := mustPostgresUUIDv7(t), mustPostgresUUIDv7(t)
	customEntity, _ := ticketEntityID(customID)
	slaEntity, _ := ticketEntityID(slaID)
	customKey, _ := kernel.NewKey("risk_score")
	slaKey, _ := kernel.NewKey("response_due_at")
	customPin, err := kernel.NewSavedViewDefinitionPin(
		customEntity, tenant, kernel.AggregateAlert, customKey, 7,
		sha256.Sum256([]byte("custom-risk-score-v7")),
	)
	if err != nil {
		t.Fatal(err)
	}
	slaPin, err := kernel.NewSavedViewDefinitionPin(
		slaEntity, tenant, kernel.AggregateAlert, slaKey, 3,
		sha256.Sum256([]byte("sla-response-due-v3")),
	)
	if err != nil {
		t.Fatal(err)
	}
	customFilter, err := kernel.RestoreSavedViewCustomFilter(
		customPin, customkernel.TypeDecimal, json.RawMessage(`10.5`),
	)
	if err != nil {
		t.Fatal(err)
	}
	filters, err := kernel.NewSavedViewFilters(kernel.SavedViewFiltersInput{
		Queue: kernel.SavedViewQueueAll, Search: "malware campaign",
		Custom: []kernel.SavedViewCustomFilter{customFilter},
	})
	if err != nil {
		t.Fatal(err)
	}
	ticketKey, _ := kernel.NewKey("ticket")
	ticketColumn, _ := kernel.NewSavedViewCoreColumn(
		ticketKey, 320, true, kernel.SavedViewColumnPinnedStart,
	)
	customColumn, _ := kernel.NewSavedViewDynamicColumn(
		kernel.SavedViewColumnCustomField, customPin, 180, true, kernel.SavedViewColumnUnpinned,
	)
	slaColumn, _ := kernel.NewSavedViewDynamicColumn(
		kernel.SavedViewColumnSLA, slaPin, 200, true, kernel.SavedViewColumnUnpinned,
	)
	sortPlan, _ := kernel.NewSavedViewDynamicSort(
		kernel.SavedViewColumnSLA, slaPin, kernel.SavedViewSortAscending, kernel.SavedViewNullsLast,
	)
	spec, err := kernel.NewSavedViewSpec(
		tenant, kernel.AggregateAlert, filters, sortPlan,
		[]kernel.SavedViewColumn{ticketColumn, customColumn, slaColumn},
	)
	if err != nil {
		t.Fatal(err)
	}
	view, err := kernel.NewSavedView(
		viewEntity, tenant, owner, kernel.AggregateAlert, "Pinned incident view",
		spec, kernel.SavedViewActive, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := application.CanonicalSavedViewSpec(tenant, kernel.AggregateAlert, spec)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	return postgresSavedViewFixture{
		tenantID: tenantID, ownerID: ownerID, viewID: viewID,
		tenant: tenant, owner: owner, kind: kernel.AggregateAlert,
		input: application.SavedViewSpecInput{
			Filters: application.SavedViewFiltersInput{
				Queue: "all", Search: "malware campaign",
				Custom: []application.SavedViewCustomFilterInput{{
					DefinitionID: customID, ExpectedDefinitionVersion: 7,
					Operator: customkernel.FilterEqual, Value: json.RawMessage(`10.50`),
				}},
			},
			Sort: application.SavedViewSortInput{
				Source: application.SavedViewDefinitionSLA, DefinitionID: uuidPointer(slaID),
				ExpectedDefinitionVersion: 3, Direction: "asc", Nulls: "last",
			},
			Columns: []application.SavedViewColumnInput{
				{Source: application.SavedViewDefinitionCore, CoreKey: "ticket", Width: 320, Visible: true, Pin: "start"},
				{Source: application.SavedViewDefinitionCustomField, DefinitionID: uuidPointer(customID), ExpectedDefinitionVersion: 7, Width: 180, Visible: true, Pin: "none"},
				{Source: application.SavedViewDefinitionSLA, DefinitionID: uuidPointer(slaID), ExpectedDefinitionVersion: 3, Width: 200, Visible: true, Pin: "none"},
			},
		},
		spec: spec, view: view, canonical: canonical, digest: digest,
		createdAt: time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC),
	}
}

func (fixture postgresSavedViewFixture) recordJSON(t testing.TB, viewID uuid.UUID) json.RawMessage {
	t.Helper()
	return fixture.recordJSONWithIdentity(t, viewID, fixture.tenantID, fixture.ownerID, fixture.kind)
}

func (fixture postgresSavedViewFixture) recordJSONWithIdentity(
	t testing.TB,
	viewID uuid.UUID,
	tenantID uuid.UUID,
	ownerID uuid.UUID,
	kind kernel.AggregateKind,
) json.RawMessage {
	t.Helper()
	wire := map[string]any{
		"id": viewID.String(), "tenantId": tenantID.String(),
		"ownerMembershipId": ownerID.String(), "aggregateKind": kind.String(),
		"name":                fixture.view.Name(),
		"specCanonicalBase64": base64.RawStdEncoding.EncodeToString(fixture.canonical),
		"specSha256":          encodeSavedViewDigest(fixture.digest),
		"status":              "active", "revision": 1,
		"createdAt": fixture.createdAt, "updatedAt": fixture.createdAt, "archivedAt": nil,
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func savedViewResolvedSpecResponse(t testing.TB, canonical []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(canonical)
	raw, err := json.Marshal(savedViewResolvedSpecResponseV1{
		SchemaVersion:       1,
		SpecCanonicalBase64: base64.RawStdEncoding.EncodeToString(canonical),
		SpecSHA256:          encodeSavedViewDigest(digest),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func clonePostgresSavedViewInput(input application.SavedViewSpecInput) application.SavedViewSpecInput {
	result := input
	result.Filters.States = slices.Clone(input.Filters.States)
	result.Filters.Severities = slices.Clone(input.Filters.Severities)
	result.Filters.Priorities = slices.Clone(input.Filters.Priorities)
	result.Filters.Custom = slices.Clone(input.Filters.Custom)
	for index := range result.Filters.Custom {
		result.Filters.Custom[index].Value = slices.Clone(input.Filters.Custom[index].Value)
	}
	result.Columns = slices.Clone(input.Columns)
	for index := range result.Columns {
		result.Columns[index].DefinitionID = cloneUUIDPointer(input.Columns[index].DefinitionID)
	}
	result.Sort.DefinitionID = cloneUUIDPointer(input.Sort.DefinitionID)
	return result
}

func cloneUUIDPointer(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func uuidPointer(value uuid.UUID) *uuid.UUID { return &value }

func boolPointer(value bool) *bool { return &value }

type savedViewABITransaction struct {
	recordingTransaction
	rows      []pgx.Row
	queries   []string
	arguments [][]any
	contexts  []context.Context
}

func (tx *savedViewABITransaction) QueryRow(
	ctx context.Context,
	query string,
	arguments ...any,
) pgx.Row {
	tx.contexts = append(tx.contexts, ctx)
	tx.queries = append(tx.queries, query)
	tx.arguments = append(tx.arguments, arguments)
	if len(tx.rows) == 0 {
		panic("unexpected saved-view ABI query")
	}
	row := tx.rows[0]
	tx.rows = tx.rows[1:]
	return row
}
