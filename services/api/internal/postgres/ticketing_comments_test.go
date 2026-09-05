package postgres

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func TestTicketCommentDatabaseErrorDistinguishesCASFromSerialization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		message string
		want    error
	}{
		{name: "explicit comment CAS", message: ticketCommentRevisionConflictMessage, want: application.ErrPreconditionFailed},
		{name: "serialization abort", message: "could not serialize access due to concurrent update", want: application.ErrUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			databaseError := &pgconn.PgError{Code: "40001", Message: test.message}
			if got := mapTicketCommentDatabaseError(fmt.Errorf("wrapped: %w", databaseError)); !errors.Is(got, test.want) {
				t.Fatalf("mapTicketCommentDatabaseError(%q) = %v, want %v", test.message, got, test.want)
			}
		})
	}
}

func TestTicketCommentEditDigestIsTenantScopedInsideTheGlobalKeyLedger(t *testing.T) {
	t.Parallel()

	workflowID := mustPostgresUUIDv7(t)
	ticketID := mustPostgresUUIDv7(t)
	firstTenantID := mustPostgresUUIDv7(t)
	secondTenantID := mustPostgresUUIDv7(t)
	workflow, err := customerProjectionWorkflow(
		workflowID, kernel.AggregateAlert, 1, "open", true, false, "customer",
	)
	if err != nil {
		t.Fatal(err)
	}
	state, err := kernel.NewKey("open")
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := kernel.NewAssignment(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ticketEntity, _ := ticketEntityID(ticketID)
	firstTenant, _ := ticketEntityID(firstTenantID)
	secondTenant, _ := ticketEntityID(secondTenantID)
	firstSnapshot, err := kernel.NewTicketSnapshot(workflow, firstTenant, ticketEntity, state, 1, true, assignment)
	if err != nil {
		t.Fatal(err)
	}
	secondSnapshot, err := kernel.NewTicketSnapshot(workflow, secondTenant, ticketEntity, state, 1, true, assignment)
	if err != nil {
		t.Fatal(err)
	}
	write := application.CommentEditWrite{
		Record: application.Record{Snapshot: firstSnapshot}, CommentID: mustPostgresUUIDv7(t),
		ExpectedRevision: 1, BodyMarkdown: "Corrected", Reason: "Correction",
		AttachmentIDs: []uuid.UUID{}, MentionedIDs: []uuid.UUID{},
	}
	firstDigest, err := ticketCommentEditRequestDigest(write)
	if err != nil {
		t.Fatal(err)
	}
	write.Record.Snapshot = secondSnapshot
	secondDigest, err := ticketCommentEditRequestDigest(write)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest == secondDigest {
		t.Fatal("global comment idempotency digest did not distinguish tenants")
	}
}

func TestTicketCommentProjectionDecoderRejectsDuplicateUnknownAndNonV7Data(t *testing.T) {
	t.Parallel()

	tenantID := mustPostgresUUIDv7(t)
	ticketID := mustPostgresUUIDv7(t)
	commentID := mustPostgresUUIDv7(t)
	membershipID := mustPostgresUUIDv7(t)
	base := fmt.Sprintf(`{
		"id":%q,"visibility":"public","body_markdown":"Safe","body_html":"<p>Safe</p>",
		"author_membership_id":%q,"author_contact_id":null,"author_display_name":"Operator",
		"author_audience":"operator","origin":"api","revision":1,
		"created_at":"2026-09-01T10:00:00.000000Z","updated_at":"2026-09-01T10:00:00.000000Z",
		"editable_until":"2026-09-01T10:15:00.000000Z","can_edit":false,
		"attachments":[],"mentions":[]}`, commentID.String(), membershipID.String())
	comment, err := decodeTicketCommentResult([]byte(base), tenantID, kernel.AggregateAlert, ticketID, false)
	if err != nil || comment.ID != commentID || comment.Author.MembershipID != membershipID {
		t.Fatalf("decodeTicketCommentResult(valid) = (%+v, %v)", comment, err)
	}
	for name, document := range map[string]string{
		"duplicate root key":   strings.Replace(base, `"revision":1`, `"revision":1,"revision":1`, 1),
		"duplicate nested key": strings.Replace(base, `"attachments":[]`, `"attachments":[{"id":"`+mustPostgresUUIDv7(t).String()+`","id":"`+mustPostgresUUIDv7(t).String()+`","original_filename":"x","visibility":"public"}]`, 1),
		"unknown key":          strings.Replace(base, `"can_edit":false`, `"can_edit":false,"author_user_id":"`+mustPostgresUUIDv7(t).String()+`"`, 1),
		"omitted nullable key": strings.Replace(base, `"author_contact_id":null,`, "", 1),
		"unsafe body HTML":     strings.Replace(base, `"body_html":"<p>Safe</p>"`, `"body_html":"<script>alert(1)</script>"`, 1),
		"directional display":  strings.Replace(base, `"author_display_name":"Operator"`, `"author_display_name":"Operator\u202e"`, 1),
		"lone high surrogate":  strings.Replace(base, `"author_display_name":"Operator"`, `"author_display_name":"Operator\ud800"`, 1),
		"lone low surrogate":   strings.Replace(base, `"author_display_name":"Operator"`, `"author_display_name":"Operator\udfff"`, 1),
		"invalid UTF-8":        strings.Replace(base, "Operator", string([]byte{0xff}), 1),
		"uuid v4":              strings.Replace(base, commentID.String(), uuid.New().String(), 1),
		"year zero":            strings.Replace(base, `2026-09-01T10:00:00.000000Z`, `0000-09-01T10:00:00.000000Z`, 1),
		"non UTC":              strings.Replace(base, `2026-09-01T10:00:00.000000Z`, `2026-09-01T12:00:00.000000+02:00`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeTicketCommentResult([]byte(document), tenantID, kernel.AggregateAlert, ticketID, false); err == nil {
				t.Fatalf("unsafe projection accepted: %s", document)
			}
		})
	}
}

func TestTicketCommentJSONDecoderHasContractSizedByteAndDepthBounds(t *testing.T) {
	t.Parallel()

	if maximumTicketCommentProjectionBytes < application.MaximumPageSize*250_000 {
		t.Fatalf("projection byte ceiling %d cannot hold a contract-sized page", maximumTicketCommentProjectionBytes)
	}
	tooDeep := strings.Repeat("[", maximumTicketJSONNesting+1) + "0" +
		strings.Repeat("]", maximumTicketJSONNesting+1)
	if err := rejectDuplicateJSONKeys([]byte(tooDeep)); err == nil {
		t.Fatal("overly deep JSON projection accepted")
	}
	if err := rejectDuplicateJSONKeys([]byte(`{"emoji":"\ud83d\ude80"}`)); err != nil {
		t.Fatalf("valid escaped surrogate pair rejected: %v", err)
	}
	for _, document := range [][]byte{
		[]byte(`{"value":"\ud800"}`),
		[]byte(`{"value":"\udfff"}`),
		{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'},
	} {
		if err := rejectDuplicateJSONKeys(document); err == nil {
			t.Fatalf("invalid JSON Unicode encoding accepted: %q", document)
		}
	}
}

func TestTicketCommentCandidateDecoderUsesDisplayNameThenMembershipOrder(t *testing.T) {
	t.Parallel()

	first := mustPostgresUUIDv7(t)
	second := mustPostgresUUIDv7(t)
	valid := fmt.Sprintf(`[
		{"membership_id":%q,"display_name":"Alpha"},
		{"membership_id":%q,"display_name":"Zulu"}
	]`, second.String(), first.String())
	items, err := decodeTicketCommentCandidates([]byte(valid))
	if err != nil || len(items) != 2 || items[0].DisplayName != "Alpha" {
		t.Fatalf("decodeTicketCommentCandidates() = (%+v, %v)", items, err)
	}
	invalid := fmt.Sprintf(`[
		{"membership_id":%q,"display_name":"Zulu"},
		{"membership_id":%q,"display_name":"Alpha"}
	]`, first.String(), second.String())
	if _, err := decodeTicketCommentCandidates([]byte(invalid)); err == nil {
		t.Fatal("non-canonical candidate order accepted")
	}
}

func TestTicketCommentEditSQLShapesPinPortalReasonInsideDatabase(t *testing.T) {
	t.Parallel()

	if !strings.Contains(editPortalTicketCommentSQL, "edit_customer_portal_ticket_comment_v2") ||
		!strings.Contains(editPortalTicketCommentSQL, "$15") || strings.Contains(editPortalTicketCommentSQL, "$16") ||
		strings.Contains(strings.ToLower(editPortalTicketCommentSQL), "reason") {
		t.Fatalf("portal comment edit ABI drifted: %q", editPortalTicketCommentSQL)
	}
	if !strings.Contains(editTenantTicketCommentSQL, "edit_tenant_ticket_comment_v2") ||
		!strings.Contains(editTenantTicketCommentSQL, "$16") || strings.Contains(editTenantTicketCommentSQL, "$17") {
		t.Fatalf("tenant comment edit ABI drifted: %q", editTenantTicketCommentSQL)
	}
}

func TestTicketCommentSQLABIsHaveExactFunctionAndArgumentShape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, query, function string
		arguments             int
	}{
		{"tenant create", createTenantTicketCommentSQL, "app.create_tenant_ticket_comment_v2", 14},
		{"portal create", createPortalTicketCommentSQL, "app.create_customer_portal_ticket_comment_v2", 13},
		{"tenant edit", editTenantTicketCommentSQL, "app.edit_tenant_ticket_comment_v2", 16},
		{"portal edit", editPortalTicketCommentSQL, "app.edit_customer_portal_ticket_comment_v2", 15},
		{"tenant preflight", preflightTenantTicketCommentEditSQL, "app.get_tenant_ticket_comment_edit_state_v1", 5},
		{"portal preflight", preflightPortalTicketCommentEditSQL, "app.get_customer_portal_ticket_comment_edit_state_v1", 5},
		{"tenant list", listTenantTicketCommentsSQL, "app.list_tenant_ticket_comments_v2", 4},
		{"portal list", listPortalTicketCommentsSQL, "app.list_customer_portal_ticket_comments_v2", 4},
		{"tenant preview", previewTenantTicketCommentSQL, "app.preview_tenant_ticket_comment_v1", 5},
		{"portal preview", previewPortalTicketCommentSQL, "app.preview_customer_portal_ticket_comment_v1", 3},
		{"mention candidates", listTicketCommentMentionCandidatesSQL, "app.list_tenant_ticket_comment_mention_candidates_v1", 4},
		{"tenant revisions", listTenantTicketCommentRevisionsSQL, "app.list_tenant_ticket_comment_revisions_v1", 5},
		{"portal revisions", listPortalTicketCommentRevisionsSQL, "app.list_customer_portal_ticket_comment_revisions_v1", 5},
	}
	placeholder := regexp.MustCompile(`\$(\d+)`)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !strings.Contains(test.query, test.function+"(") {
				t.Fatalf("query does not call %s: %q", test.function, test.query)
			}
			seen := make(map[int]struct{}, test.arguments)
			for _, match := range placeholder.FindAllStringSubmatch(test.query, -1) {
				value, err := strconv.Atoi(match[1])
				if err != nil || value < 1 || value > test.arguments {
					t.Fatalf("unexpected placeholder %q in %q", match[0], test.query)
				}
				seen[value] = struct{}{}
			}
			if len(seen) != test.arguments {
				t.Fatalf("placeholder set=%v, want 1..%d", seen, test.arguments)
			}
		})
	}
}

func TestPrivateCommentCapabilityRequiresPublicAndPrivatePermissions(t *testing.T) {
	t.Parallel()

	for _, capability := range []application.Capability{
		application.CapabilityAlertCommentPrivate, application.CapabilityCaseCommentPrivate,
	} {
		permissions, err := ticketCapabilityPermissions(capability)
		if err != nil || len(permissions) != 2 ||
			!strings.HasSuffix(string(permissions[0]), ".comment.public") ||
			!strings.HasSuffix(string(permissions[1]), ".comment.private") {
			t.Fatalf("ticketCapabilityPermissions(%q) = (%q, %v)", capability, permissions, err)
		}
	}
}
