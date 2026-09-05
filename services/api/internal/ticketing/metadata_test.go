package ticketing

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

func TestReplaceAlertMetadataBindsExactAuthorizedCommand(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	classification := "restricted"
	input := MetadataReplaceInput{
		EditableMetadata: EditableMetadata{
			Title: "Confirmed intrusion", Description: "Validated by the incident responder",
			Severity: "critical", Priority: "critical", Category: "incident",
			Classification: &classification, CustomerVisible: false,
			Tags: []string{"confirmed", "endpoint"},
		},
		ExpectedVersion: 1, IdempotencyKey: "alert-metadata-replace-0001",
	}
	wantFingerprint, err := metadataFingerprint(
		fixture.tenantUUID, fixture.actor.UserID, fixture.ticketUUID,
		kernel.AggregateAlert, input,
	)
	if err != nil {
		t.Fatal(err)
	}
	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record,
		replaceMetadata: func(ctx context.Context, write MetadataWrite) (MetadataMutationResult, error) {
			if ctx == nil || write.Actor != fixture.actor || write.TenantID != fixture.tenantUUID ||
				write.TicketID != fixture.ticketUUID || write.Kind != kernel.AggregateAlert ||
				write.ExpectedVersion != 1 || write.Audit != fixture.actor.Audit ||
				write.KeyHash != sha256.Sum256([]byte(input.IdempotencyKey)) ||
				write.Fingerprint != wantFingerprint ||
				!sameEditableMetadata(write.Content, input.EditableMetadata) {
				t.Fatalf("metadata write was not exactly bound: %#v", write)
			}
			return metadataTestResult(
				fixture.tenantUUID, fixture.ticketUUID, kernel.AggregateAlert,
				input.EditableMetadata, 2, false,
			), nil
		},
	}
	result, err := mustService(t, repository).ReplaceAlertMetadata(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, input,
	)
	if err != nil || result.Replayed || result.Metadata.Version != 2 ||
		!sameEditableMetadata(result.Metadata.EditableMetadata, input.EditableMetadata) {
		t.Fatalf("ReplaceAlertMetadata() = (%#v, %v)", result, err)
	}
	if repository.metadataCalls.Load() != 1 || len(repository.accessCalls) != 1 ||
		repository.accessCalls[0] != CapabilityAlertUpdate {
		t.Fatalf("calls metadata=%d access=%v", repository.metadataCalls.Load(), repository.accessCalls)
	}
}

func TestReplaceCaseMetadataIncludesCanonicalSummary(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	caseID := mustUUIDv7(t)
	caseRecord := metadataCaseRecord(t, fixture, caseID, 4)
	input := MetadataReplaceInput{
		EditableMetadata: EditableMetadata{
			Title: "Credential theft investigation", Summary: "Executive summary",
			Description: "Case narrative", Severity: "high", Priority: "urgent",
			Category: "identity", Tags: []string{}, CustomerVisible: true,
		},
		ExpectedVersion: 4, IdempotencyKey: "case-metadata-replace-0001",
	}
	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, record: caseRecord,
		replaceMetadata: func(_ context.Context, write MetadataWrite) (MetadataMutationResult, error) {
			if write.Kind != kernel.AggregateCase || write.Content.Summary != input.Summary {
				t.Fatalf("case summary was not bound: %#v", write)
			}
			return metadataTestResult(
				fixture.tenantUUID, caseID, kernel.AggregateCase,
				input.EditableMetadata, 5, false,
			), nil
		},
	}
	result, err := mustService(t, repository).ReplaceCaseMetadata(
		context.Background(), fixture.actor, fixture.tenantUUID, caseID, input,
	)
	if err != nil || result.Metadata.Summary != input.Summary ||
		len(repository.accessCalls) != 1 || repository.accessCalls[0] != CapabilityCaseUpdate {
		t.Fatalf("ReplaceCaseMetadata() = (%#v, %v), access=%v", result, err, repository.accessCalls)
	}
}

func TestReplaceMetadataReplaysExactStaleCommandAfterLaterMutation(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	current := fixture.record
	current.Snapshot = mustSnapshot(
		t, current.Workflow, fixture.tenant, fixture.ticket, true, kernel.Assignment{}, 3,
	)
	current.Title = "Later change"
	current.UpdatedAt = current.UpdatedAt.Add(2 * time.Second)
	input := MetadataReplaceInput{
		EditableMetadata: EditableMetadata{
			Title: "First replacement", Description: "First result", Severity: "high",
			Priority: "urgent", Category: "security", Tags: []string{}, CustomerVisible: true,
		},
		ExpectedVersion: 1, IdempotencyKey: "alert-metadata-replay-0001",
	}
	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, record: current,
		replaceMetadata: func(_ context.Context, _ MetadataWrite) (MetadataMutationResult, error) {
			return metadataTestResult(
				fixture.tenantUUID, fixture.ticketUUID, kernel.AggregateAlert,
				input.EditableMetadata, 2, true,
			), nil
		},
	}
	result, err := mustService(t, repository).ReplaceAlertMetadata(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, input,
	)
	if err != nil || !result.Replayed || result.Metadata.Version != 2 || result.Metadata.Title != "First replacement" {
		t.Fatalf("stale exact replay = (%#v, %v)", result, err)
	}
}

func TestReplaceMetadataRejectsNoopInvalidAndMismatchedResults(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	base := MetadataReplaceInput{
		EditableMetadata: metadataFromRecord(fixture.record), ExpectedVersion: 1,
		IdempotencyKey: "alert-metadata-validation-0001",
	}
	repository := &fakeRepository{fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record}
	service := mustService(t, repository)
	if _, err := service.ReplaceAlertMetadata(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, base,
	); !errors.Is(err, ErrConflict) || repository.metadataCalls.Load() != 0 {
		t.Fatalf("no-op error=%v calls=%d", err, repository.metadataCalls.Load())
	}

	invalid := base
	invalid.Title = "Changed"
	invalid.Summary = "alerts cannot acquire case summaries"
	if _, err := service.ReplaceAlertMetadata(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, invalid,
	); !errors.Is(err, ErrInvalidInput) || repository.metadataCalls.Load() != 0 {
		t.Fatalf("alert summary error=%v calls=%d", err, repository.metadataCalls.Load())
	}

	changed := base
	changed.Title = "Changed"
	repository.replaceMetadata = func(_ context.Context, _ MetadataWrite) (MetadataMutationResult, error) {
		mismatch := changed.EditableMetadata
		mismatch.Priority = "low"
		return metadataTestResult(
			fixture.tenantUUID, fixture.ticketUUID, kernel.AggregateAlert, mismatch, 2, false,
		), nil
	}
	if _, err := service.ReplaceAlertMetadata(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, changed,
	); !errors.Is(err, ErrUnavailable) || repository.metadataCalls.Load() != 1 {
		t.Fatalf("mismatched result error=%v calls=%d", err, repository.metadataCalls.Load())
	}
}

func TestReplaceMetadataFailsClosedForAuthorizationCancellationAndIdempotencyConflict(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	input := MetadataReplaceInput{
		EditableMetadata: metadataFromRecord(fixture.record), ExpectedVersion: 1,
		IdempotencyKey: "alert-metadata-failclosed-0001",
	}
	input.Title = "Changed"

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	repository := &fakeRepository{fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record}
	if _, err := mustService(t, repository).ReplaceAlertMetadata(
		cancelled, fixture.actor, fixture.tenantUUID, fixture.ticketUUID, input,
	); !errors.Is(err, ErrUnavailable) || len(repository.accessCalls) != 0 || repository.metadataCalls.Load() != 0 {
		t.Fatalf("cancelled request error=%v access=%v calls=%d", err, repository.accessCalls, repository.metadataCalls.Load())
	}

	forbidden := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record,
		accessErrors: map[Capability]error{CapabilityAlertUpdate: ErrForbidden},
	}
	if _, err := mustService(t, forbidden).ReplaceAlertMetadata(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, input,
	); !errors.Is(err, ErrForbidden) || forbidden.metadataCalls.Load() != 0 {
		t.Fatalf("forbidden request error=%v calls=%d", err, forbidden.metadataCalls.Load())
	}

	conflict := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record,
		replaceMetadata: func(_ context.Context, _ MetadataWrite) (MetadataMutationResult, error) {
			return MetadataMutationResult{}, ErrConflict
		},
	}
	if _, err := mustService(t, conflict).ReplaceAlertMetadata(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, input,
	); !errors.Is(err, ErrConflict) || conflict.metadataCalls.Load() != 1 {
		t.Fatalf("idempotency conflict error=%v calls=%d", err, conflict.metadataCalls.Load())
	}
}

func TestReplaceMetadataRejectsNonRFCUUIDv7AuditIdentifiersBeforeAuthorization(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	nonRFCV7 := mustUUIDv7(t)
	nonRFCV7[8] &^= 0xc0
	input := MetadataReplaceInput{
		EditableMetadata: metadataFromRecord(fixture.record), ExpectedVersion: 1,
		IdempotencyKey: "alert-metadata-audit-uuid-0001",
	}
	input.Title = "Changed"
	for _, test := range []struct {
		name   string
		mutate func(*Actor)
	}{
		{name: "request ID", mutate: func(actor *Actor) { actor.Audit.RequestID = uuid.New() }},
		{name: "correlation ID", mutate: func(actor *Actor) { actor.Audit.CorrelationID = uuid.New() }},
		{name: "request ID non-RFC variant", mutate: func(actor *Actor) { actor.Audit.RequestID = nonRFCV7 }},
		{name: "correlation ID non-RFC variant", mutate: func(actor *Actor) { actor.Audit.CorrelationID = nonRFCV7 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			actor := fixture.actor
			test.mutate(&actor)
			repository := &fakeRepository{
				fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record,
			}
			if _, err := mustService(t, repository).ReplaceAlertMetadata(
				context.Background(), actor, fixture.tenantUUID, fixture.ticketUUID, input,
			); !errors.Is(err, ErrForbidden) || len(repository.accessCalls) != 0 || repository.metadataCalls.Load() != 0 {
				t.Fatalf("invalid audit identifier error=%v access=%v calls=%d", err, repository.accessCalls, repository.metadataCalls.Load())
			}
		})
	}
}

func TestValidAuditContextMatchesDatabaseUserAgentABI(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	for _, test := range []struct {
		name      string
		userAgent string
		want      bool
	}{
		{name: "canonical absent sentinel", userAgent: "unknown", want: true},
		{name: "ordinary", userAgent: "periapsis-test/1", want: true},
		{name: "nonblank with spaces", userAgent: " periapsis-test/1 ", want: true},
		{name: "empty"},
		{name: "blank", userAgent: "   "},
		{name: "tab", userAgent: "periapsis\ttest"},
		{name: "newline", userAgent: "periapsis\ntest"},
		{name: "C1 control", userAgent: "periapsis\u0085test"},
		{name: "application bound", userAgent: strings.Repeat("a", 513)},
		{name: "invalid UTF-8", userAgent: string([]byte{0xff})},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			audit := fixture.actor.Audit
			audit.UserAgent = test.userAgent
			if got := validAuditContext(audit); got != test.want {
				t.Fatalf("validAuditContext(UserAgent=%q) = %t, want %t", test.userAgent, got, test.want)
			}
		})
	}
}

func TestMetadataFingerprintBindsEveryEditableFieldAndNormalizesEmptyTags(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	input := MetadataReplaceInput{
		EditableMetadata: metadataFromRecord(fixture.record), ExpectedVersion: 1,
		IdempotencyKey: "alert-metadata-fingerprint-0001",
	}
	input.Tags = nil
	normalized := input
	normalized.EditableMetadata = normalizeEditableMetadata(normalized.EditableMetadata)
	first, err := metadataFingerprint(
		fixture.tenantUUID, fixture.actor.UserID, fixture.ticketUUID,
		kernel.AggregateAlert, normalized,
	)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Tags == nil {
		t.Fatal("empty tags were not normalized to an array")
	}
	mutations := []func(*MetadataReplaceInput){
		func(value *MetadataReplaceInput) { value.Title += " changed" },
		func(value *MetadataReplaceInput) { value.Description += " changed" },
		func(value *MetadataReplaceInput) { value.Severity = "low" },
		func(value *MetadataReplaceInput) { value.Priority = "low" },
		func(value *MetadataReplaceInput) { value.Category = "other" },
		func(value *MetadataReplaceInput) {
			classification := "internal"
			value.Classification = &classification
		},
		func(value *MetadataReplaceInput) { value.CustomerVisible = !value.CustomerVisible },
		func(value *MetadataReplaceInput) { value.Tags = []string{"changed"} },
		func(value *MetadataReplaceInput) { value.ExpectedVersion++ },
	}
	for index, mutate := range mutations {
		changed := normalized
		mutate(&changed)
		fingerprint, fingerprintErr := metadataFingerprint(
			fixture.tenantUUID, fixture.actor.UserID, fixture.ticketUUID,
			kernel.AggregateAlert, changed,
		)
		if fingerprintErr != nil || fingerprint == first {
			t.Fatalf("mutation %d fingerprint=%x error=%v", index, fingerprint, fingerprintErr)
		}
	}
	caseInput := normalized
	caseInput.Summary = "Initial case summary"
	caseFingerprint, err := metadataFingerprint(
		fixture.tenantUUID, fixture.actor.UserID, fixture.ticketUUID,
		kernel.AggregateCase, caseInput,
	)
	if err != nil {
		t.Fatal(err)
	}
	caseInput.Summary = "Changed case summary"
	changedSummaryFingerprint, err := metadataFingerprint(
		fixture.tenantUUID, fixture.actor.UserID, fixture.ticketUUID,
		kernel.AggregateCase, caseInput,
	)
	if err != nil || changedSummaryFingerprint == caseFingerprint {
		t.Fatalf("case summary fingerprint=%x error=%v", changedSummaryFingerprint, err)
	}
}

func TestMetadataReplacementUsesContractControlCharacterClasses(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	caseID := mustUUIDv7(t)
	caseRecord := metadataCaseRecord(t, fixture, caseID, 4)
	accepted := MetadataReplaceInput{
		EditableMetadata: metadataFromRecord(caseRecord), ExpectedVersion: 4,
		IdempotencyKey: "case-metadata-controls-0001",
	}
	accepted.Description = "First line\n\tSecond line\rThird line"
	accepted.Summary = "Summary\r\ncontinued"
	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, record: caseRecord,
		replaceMetadata: func(_ context.Context, write MetadataWrite) (MetadataMutationResult, error) {
			return metadataTestResult(
				fixture.tenantUUID, caseID, kernel.AggregateCase, write.Content, 5, false,
			), nil
		},
	}
	if _, err := mustService(t, repository).ReplaceCaseMetadata(
		context.Background(), fixture.actor, fixture.tenantUUID, caseID, accepted,
	); err != nil {
		t.Fatalf("multiline replacement error = %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*MetadataReplaceInput)
	}{
		{name: "title newline", mutate: func(value *MetadataReplaceInput) { value.Title = "Title\ncontinued" }},
		{name: "category tab", mutate: func(value *MetadataReplaceInput) { value.Category = "security\tincident" }},
		{name: "classification carriage return", mutate: func(value *MetadataReplaceInput) {
			classification := "restricted\rclassification"
			value.Classification = &classification
		}},
		{name: "description vertical tab", mutate: func(value *MetadataReplaceInput) { value.Description = "first\vsecond" }},
		{name: "summary form feed", mutate: func(value *MetadataReplaceInput) { value.Summary = "first\fsecond" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := MetadataReplaceInput{
				EditableMetadata: metadataFromRecord(caseRecord), ExpectedVersion: 4,
				IdempotencyKey: "case-metadata-controls-0002",
			}
			candidate.Summary = "Changed summary"
			test.mutate(&candidate)
			invalidRepository := &fakeRepository{
				fixture: fixture, principal: kernel.PrincipalOperator, record: caseRecord,
			}
			if _, err := mustService(t, invalidRepository).ReplaceCaseMetadata(
				context.Background(), fixture.actor, fixture.tenantUUID, caseID, candidate,
			); !errors.Is(err, ErrInvalidInput) || invalidRepository.metadataCalls.Load() != 0 {
				t.Fatalf("replacement error = %v, calls = %d", err, invalidRepository.metadataCalls.Load())
			}
		})
	}
}

func TestMetadataTextUsesExactUnicodeEdgeWhitespaceSet(t *testing.T) {
	t.Parallel()
	edgeWhitespace := []rune{
		'\t', '\n', '\v', '\f', '\r', ' ', '\u0085', '\u00a0', '\u1680',
		'\u2000', '\u2001', '\u2002', '\u2003', '\u2004', '\u2005', '\u2006',
		'\u2007', '\u2008', '\u2009', '\u200a', '\u2028', '\u2029', '\u202f',
		'\u205f', '\u3000',
	}
	for _, character := range edgeWhitespace {
		character := character
		t.Run(fmt.Sprintf("U+%04X", character), func(t *testing.T) {
			t.Parallel()
			if validMetadataText(string(character)+"title", 240, true, false) ||
				validMetadataText("title"+string(character), 240, true, false) {
				t.Fatalf("U+%04X was accepted at a text boundary", character)
			}
		})
	}

	// U+FEFF is a format character, not Unicode White_Space, and is therefore
	// intentionally outside the cross-layer edge-trimming rule.
	if !validMetadataText("\ufefftitle\ufeff", 240, true, false) {
		t.Fatal("U+FEFF was incorrectly treated as edge whitespace")
	}
}

func TestMetadataReplacementCountsUnicodeCodePointsAndBindsMaximumCasePayload(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	caseID := mustUUIDv7(t)
	caseRecord := metadataCaseRecord(t, fixture, caseID, 4)
	input := MetadataReplaceInput{
		EditableMetadata: EditableMetadata{
			Title: strings.Repeat("é", 240), Summary: strings.Repeat("界", 2_000),
			Description: strings.Repeat("界", 20_000), Severity: "high", Priority: "urgent",
			Category: strings.Repeat("é", 120), Tags: []string{}, CustomerVisible: true,
		},
		ExpectedVersion: 4, IdempotencyKey: "case-metadata-unicode-boundary-0001",
	}
	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, record: caseRecord,
		replaceMetadata: func(_ context.Context, write MetadataWrite) (MetadataMutationResult, error) {
			return metadataTestResult(
				fixture.tenantUUID, caseID, kernel.AggregateCase, write.Content, 5, false,
			), nil
		},
	}
	result, err := mustService(t, repository).ReplaceCaseMetadata(
		context.Background(), fixture.actor, fixture.tenantUUID, caseID, input,
	)
	if err != nil || result.Metadata.Title != input.Title ||
		result.Metadata.Description != input.Description || result.Metadata.Summary != input.Summary {
		t.Fatalf("maximum Unicode replacement = (%#v, %v)", result, err)
	}
	if repository.metadataCalls.Load() != 1 {
		t.Fatalf("metadata calls = %d, want 1", repository.metadataCalls.Load())
	}

	tooLong := input
	tooLong.Title += "é"
	invalidRepository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, record: caseRecord,
	}
	if _, err := mustService(t, invalidRepository).ReplaceCaseMetadata(
		context.Background(), fixture.actor, fixture.tenantUUID, caseID, tooLong,
	); !errors.Is(err, ErrInvalidInput) || invalidRepository.metadataCalls.Load() != 0 {
		t.Fatalf("overlong Unicode replacement error = %v, calls = %d", err, invalidRepository.metadataCalls.Load())
	}
}

func metadataTestResult(
	tenantID uuid.UUID,
	ticketID uuid.UUID,
	kind kernel.AggregateKind,
	content EditableMetadata,
	version uint64,
	replayed bool,
) MetadataMutationResult {
	return MetadataMutationResult{
		Metadata: TicketMetadata{
			TenantID: tenantID, TicketID: ticketID, Kind: kind,
			EditableMetadata: normalizeEditableMetadata(content), Version: version,
			UpdatedAt: time.Date(2026, 8, 25, 10, 0, 1, 0, time.UTC),
		},
		Replayed: replayed,
	}
}

func metadataCaseRecord(t testing.TB, fixture serviceFixture, caseID uuid.UUID, version uint64) Record {
	t.Helper()
	workflow := caseWorkflow(t)
	caseEntity, _ := entityID(caseID)
	snapshot, err := kernel.NewTicketSnapshot(
		workflow, fixture.tenant, caseEntity, workflow.InitialState(), version, true, kernel.Assignment{},
	)
	if err != nil {
		t.Fatal(err)
	}
	now := fixture.record.CreatedAt
	return Record{
		Workflow: workflow, Snapshot: snapshot, Number: "CAS-2026-000001",
		Title: "Existing case", Summary: "Existing summary", Description: "Existing description",
		Severity: "medium", Priority: "high", Category: "incident", Tags: []string{},
		CustomFields: map[string]any{}, CustomerCustomFields: map[string]any{},
		Creator: Creator{
			Kind: kernel.PrincipalOperator, ID: fixture.membershipUUID,
			UserID: &fixture.actor.UserID, DisplayName: "Operator",
		},
		DetectionTime: now, OpenedAt: now, CreatedAt: now, UpdatedAt: now,
	}
}
