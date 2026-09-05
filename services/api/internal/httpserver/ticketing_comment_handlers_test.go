package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func (stub *transportTicketingStub) Comments(
	ctx context.Context, actor application.Actor, tenantID uuid.UUID, kind kernel.AggregateKind,
	ticketID uuid.UUID, input application.CursorPageInput,
) (application.CommentPage, error) {
	return stub.comments(ctx, actor, tenantID, kind, ticketID, input, false)
}

func (stub *transportTicketingStub) CommentsPortal(
	ctx context.Context, actor application.Actor, tenantID uuid.UUID, kind kernel.AggregateKind,
	ticketID uuid.UUID, input application.CursorPageInput,
) (application.CommentPage, error) {
	return stub.comments(ctx, actor, tenantID, kind, ticketID, input, true)
}

func (stub *transportTicketingStub) comments(
	ctx context.Context, actor application.Actor, tenantID uuid.UUID, kind kernel.AggregateKind,
	ticketID uuid.UUID, input application.CursorPageInput, portal bool,
) (application.CommentPage, error) {
	stub.commentCalls++
	if stub.commentsFn == nil {
		return application.CommentPage{}, application.ErrUnavailable
	}
	return stub.commentsFn(ctx, actor, tenantID, kind, ticketID, input, portal)
}

func (stub *transportTicketingStub) AddComment(
	ctx context.Context, actor application.Actor, tenantID uuid.UUID, kind kernel.AggregateKind,
	ticketID uuid.UUID, input application.CommentInput,
) (application.Comment, application.Projection, bool, error) {
	return stub.addComment(ctx, actor, tenantID, kind, ticketID, input, false)
}

func (stub *transportTicketingStub) AddPortalComment(
	ctx context.Context, actor application.Actor, tenantID uuid.UUID, kind kernel.AggregateKind,
	ticketID uuid.UUID, input application.CommentInput,
) (application.Comment, application.Projection, bool, error) {
	return stub.addComment(ctx, actor, tenantID, kind, ticketID, input, true)
}

func (stub *transportTicketingStub) addComment(
	ctx context.Context, actor application.Actor, tenantID uuid.UUID, kind kernel.AggregateKind,
	ticketID uuid.UUID, input application.CommentInput, portal bool,
) (application.Comment, application.Projection, bool, error) {
	stub.commentCalls++
	if stub.addCommentFn == nil {
		return application.Comment{}, 0, false, application.ErrUnavailable
	}
	return stub.addCommentFn(ctx, actor, tenantID, kind, ticketID, input, portal)
}

func (stub *transportTicketingStub) PreviewComment(
	ctx context.Context, actor application.Actor, tenantID uuid.UUID, kind kernel.AggregateKind,
	ticketID uuid.UUID, input application.CommentPreviewInput,
) (application.CommentPreview, error) {
	return stub.previewComment(ctx, actor, tenantID, kind, ticketID, input, false)
}

func (stub *transportTicketingStub) PreviewPortalComment(
	ctx context.Context, actor application.Actor, tenantID uuid.UUID, kind kernel.AggregateKind,
	ticketID uuid.UUID, input application.CommentPreviewInput,
) (application.CommentPreview, error) {
	return stub.previewComment(ctx, actor, tenantID, kind, ticketID, input, true)
}

func (stub *transportTicketingStub) previewComment(
	ctx context.Context, actor application.Actor, tenantID uuid.UUID, kind kernel.AggregateKind,
	ticketID uuid.UUID, input application.CommentPreviewInput, portal bool,
) (application.CommentPreview, error) {
	stub.commentCalls++
	if stub.previewCommentFn == nil {
		return application.CommentPreview{}, application.ErrUnavailable
	}
	return stub.previewCommentFn(ctx, actor, tenantID, kind, ticketID, input, portal)
}

func (stub *transportTicketingStub) CommentMentionCandidates(
	ctx context.Context, actor application.Actor, tenantID uuid.UUID, kind kernel.AggregateKind,
	ticketID uuid.UUID, input application.CommentMentionCandidateInput,
) (application.CommentMentionCandidateList, error) {
	stub.commentCalls++
	if stub.candidatesFn == nil {
		return application.CommentMentionCandidateList{}, application.ErrUnavailable
	}
	return stub.candidatesFn(ctx, actor, tenantID, kind, ticketID, input)
}

func (stub *transportTicketingStub) EditComment(
	ctx context.Context, actor application.Actor, tenantID uuid.UUID, kind kernel.AggregateKind,
	ticketID, commentID uuid.UUID, input application.CommentEditInput,
) (application.Comment, application.Projection, bool, error) {
	return stub.editComment(ctx, actor, tenantID, kind, ticketID, commentID, input, false)
}

func (stub *transportTicketingStub) EditPortalComment(
	ctx context.Context, actor application.Actor, tenantID uuid.UUID, kind kernel.AggregateKind,
	ticketID, commentID uuid.UUID, input application.CommentEditInput,
) (application.Comment, application.Projection, bool, error) {
	return stub.editComment(ctx, actor, tenantID, kind, ticketID, commentID, input, true)
}

func (stub *transportTicketingStub) editComment(
	ctx context.Context, actor application.Actor, tenantID uuid.UUID, kind kernel.AggregateKind,
	ticketID, commentID uuid.UUID, input application.CommentEditInput, portal bool,
) (application.Comment, application.Projection, bool, error) {
	stub.commentCalls++
	if stub.editCommentFn == nil {
		return application.Comment{}, 0, false, application.ErrUnavailable
	}
	return stub.editCommentFn(ctx, actor, tenantID, kind, ticketID, commentID, input, portal)
}

func (stub *transportTicketingStub) CommentRevisions(
	ctx context.Context, actor application.Actor, tenantID uuid.UUID, kind kernel.AggregateKind,
	ticketID, commentID uuid.UUID, input application.CommentRevisionPageInput,
) (application.CommentRevisionPage, error) {
	return stub.commentRevisions(ctx, actor, tenantID, kind, ticketID, commentID, input, false)
}

func (stub *transportTicketingStub) CommentRevisionsPortal(
	ctx context.Context, actor application.Actor, tenantID uuid.UUID, kind kernel.AggregateKind,
	ticketID, commentID uuid.UUID, input application.CommentRevisionPageInput,
) (application.CommentRevisionPage, error) {
	return stub.commentRevisions(ctx, actor, tenantID, kind, ticketID, commentID, input, true)
}

func (stub *transportTicketingStub) commentRevisions(
	ctx context.Context, actor application.Actor, tenantID uuid.UUID, kind kernel.AggregateKind,
	ticketID, commentID uuid.UUID, input application.CommentRevisionPageInput, portal bool,
) (application.CommentRevisionPage, error) {
	stub.commentCalls++
	if stub.revisionsFn == nil {
		return application.CommentRevisionPage{}, application.ErrUnavailable
	}
	return stub.revisionsFn(ctx, actor, tenantID, kind, ticketID, commentID, input, portal)
}

func TestMountedOperatorCommentEditBindsCASAndReturnsRevisionHeaders(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	alertID := mustTransportUUIDv7(t)
	commentID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	membershipID := mustTransportUUIDv7(t)
	createdAt := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	bodyMarkdown := "Corrected\n\n- first indicator\n- second indicator"
	bodyHTML, err := application.RenderCommentMarkdown(bodyMarkdown)
	if err != nil {
		t.Fatal(err)
	}
	var captured application.CommentEditInput
	stub := &transportTicketingStub{editCommentFn: func(
		_ context.Context, _ application.Actor, gotTenant uuid.UUID, kind kernel.AggregateKind,
		gotTicket, gotComment uuid.UUID, input application.CommentEditInput, portal bool,
	) (application.Comment, application.Projection, bool, error) {
		if portal || gotTenant != tenantID || kind != kernel.AggregateAlert || gotTicket != alertID || gotComment != commentID {
			t.Fatal("operator edit target drifted")
		}
		captured = input
		comment := transportComment(tenantID, alertID, commentID, membershipID, createdAt, false)
		comment.BodyMarkdown = bodyMarkdown
		comment.BodyHTML = bodyHTML
		return comment, application.ProjectionOperator, true, nil
	}}
	router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	request := ticketingMutationRequest(http.MethodPatch,
		"/api/v1/tenants/"+tenantID.String()+"/alerts/"+alertID.String()+"/comments/"+commentID.String(),
		`{"bodyMarkdown":"Corrected\n\n- first indicator\n- second indicator","reason":"Corrected evidence context"}`)
	request.Header.Set(ifMatchHeader, `"comment-r1"`)
	request.Header.Set(idempotencyKeyHeader, "comment-edit-http-0001")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("ETag") != `"comment-r2"` || response.Header().Get(idempotentReplayHeader) != "true" ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("headers=%#v", response.Header())
	}
	if captured.ExpectedRevision != 1 || captured.IdempotencyKey != "comment-edit-http-0001" ||
		captured.Reason != "Corrected evidence context" || captured.BodyMarkdown != bodyMarkdown {
		t.Fatalf("captured input=%+v", captured)
	}
}

func TestMountedCommentCreateReturnsPinnedProjectionAndRevisionHeaders(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	alertID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	membershipID := mustTransportUUIDv7(t)
	contactID := mustTransportUUIDv7(t)
	createdAt := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name          string
		path          string
		body          string
		bodyMarkdown  string
		portal        bool
		forbiddenBody []string
	}{
		{
			name: "operator", path: "/api/v1/tenants/" + tenantID.String() + "/alerts/" + alertID.String() + "/comments",
			body: `{"visibility":"public","bodyMarkdown":"Created"}`, bodyMarkdown: "Created",
		},
		{
			name: "portal", path: "/api/v1/tenants/" + tenantID.String() + "/portal/alerts/" + alertID.String() + "/comments",
			body: `{"bodyMarkdown":"Customer update"}`, bodyMarkdown: "Customer update", portal: true,
			forbiddenBody: []string{membershipID.String(), contactID.String(), `"membershipId"`, `"contactId"`, `"mentions"`},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			commentID := mustTransportUUIDv7(t)
			bodyHTML, err := application.RenderCommentMarkdown(test.bodyMarkdown)
			if err != nil {
				t.Fatal(err)
			}
			stub := &transportTicketingStub{addCommentFn: func(
				_ context.Context, _ application.Actor, gotTenant uuid.UUID, kind kernel.AggregateKind,
				gotTicket uuid.UUID, input application.CommentInput, portal bool,
			) (application.Comment, application.Projection, bool, error) {
				if gotTenant != tenantID || gotTicket != alertID || kind != kernel.AggregateAlert ||
					portal != test.portal || input.BodyMarkdown != test.bodyMarkdown {
					t.Fatalf("create input drifted: tenant=%s ticket=%s kind=%v portal=%t input=%+v",
						gotTenant, gotTicket, kind, portal, input)
				}
				comment := transportComment(tenantID, alertID, commentID, membershipID, createdAt, test.portal)
				comment.BodyMarkdown = test.bodyMarkdown
				comment.BodyHTML = bodyHTML
				comment.Revision = 1
				comment.UpdatedAt = createdAt
				if test.portal {
					comment.Author.ContactID = &contactID
					return comment, application.ProjectionCustomer, false, nil
				}
				return comment, application.ProjectionOperator, false, nil
			}}
			router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
			request := ticketingMutationRequest(http.MethodPost, test.path, test.body)
			request.Header.Set(idempotencyKeyHeader, "comment-create-http-0001")
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if response.Code != http.StatusCreated {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if response.Header().Get("ETag") != `"comment-r1"` ||
				response.Header().Get(idempotentReplayHeader) != "false" ||
				response.Header().Get("Cache-Control") != "no-store" ||
				response.Header().Get("Location") != test.path+"/"+commentID.String() {
				t.Fatalf("headers=%#v", response.Header())
			}
			payload := response.Body.String()
			for _, forbidden := range test.forbiddenBody {
				if strings.Contains(payload, forbidden) {
					t.Fatalf("customer create payload leaked %q: %s", forbidden, payload)
				}
			}
		})
	}
}

func TestMountedCommentEditRejectsUnpairedJSONSurrogateBeforeUseCase(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	alertID := mustTransportUUIDv7(t)
	commentID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	stub := &transportTicketingStub{}
	router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	request := ticketingMutationRequest(http.MethodPatch,
		"/api/v1/tenants/"+tenantID.String()+"/alerts/"+alertID.String()+"/comments/"+commentID.String(),
		`{"bodyMarkdown":"invalid \ud800 value","reason":"Corrected evidence context"}`)
	request.Header.Set(ifMatchHeader, `"comment-r1"`)
	request.Header.Set(idempotencyKeyHeader, "comment-edit-surrogate-0001")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || stub.commentCalls != 0 {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, stub.commentCalls, response.Body.String())
	}
}

func TestMountedCommentEditRejectsInvalidRawUTF8BeforeUseCase(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	alertID := mustTransportUUIDv7(t)
	commentID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	stub := &transportTicketingStub{}
	router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	body := append([]byte(`{"bodyMarkdown":"invalid `), 0xff)
	body = append(body, []byte(` value","reason":"Corrected evidence context"}`)...)
	request := ticketingMutationRequest(http.MethodPatch,
		"/api/v1/tenants/"+tenantID.String()+"/alerts/"+alertID.String()+"/comments/"+commentID.String(),
		string(body))
	request.Header.Set(ifMatchHeader, `"comment-r1"`)
	request.Header.Set(idempotencyKeyHeader, "comment-edit-invalid-utf8-0001")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || stub.commentCalls != 0 {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, stub.commentCalls, response.Body.String())
	}
}

func TestCommentJSONScalarValidatorAcceptsSurrogatePairsOnly(t *testing.T) {
	t.Parallel()

	if !validJSONUnicodeScalarEscapes([]byte(`{"bodyMarkdown":"valid \ud83d\ude00"}`)) {
		t.Fatal("valid surrogate pair rejected")
	}
	for _, document := range []string{
		`{"bodyMarkdown":"high \ud83d"}`,
		`{"bodyMarkdown":"low \ude00"}`,
		`{"bodyMarkdown":"wrong pair \ud83d\u0041"}`,
	} {
		if validJSONUnicodeScalarEscapes([]byte(document)) {
			t.Fatalf("unpaired surrogate accepted: %s", document)
		}
	}
}

func TestCustomerCommentListStructurallyOmitsInternalIdentifiers(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	alertID := mustTransportUUIDv7(t)
	commentID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	membershipID := mustTransportUUIDv7(t)
	contactID := mustTransportUUIDv7(t)
	createdAt := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	comment := transportComment(tenantID, alertID, commentID, membershipID, createdAt, true)
	comment.Author.ContactID = &contactID
	comment.Author.Audience = application.CommentAudienceCustomer
	comment.Origin = application.CommentOriginCustomerPortal
	stub := &transportTicketingStub{commentsFn: func(
		_ context.Context, _ application.Actor, _ uuid.UUID, _ kernel.AggregateKind, _ uuid.UUID,
		_ application.CursorPageInput, portal bool,
	) (application.CommentPage, error) {
		if !portal {
			t.Fatal("portal list used operator service path")
		}
		return application.CommentPage{Items: []application.Comment{comment}, Projection: application.ProjectionCustomer}, nil
	}}
	router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	request := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tenantID.String()+"/portal/alerts/"+alertID.String()+"/comments", nil)
	prepareTenantLDAPTransportRequest(request, false)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	text := response.Body.String()
	for _, forbidden := range []string{membershipID.String(), contactID.String(), `"membershipId"`, `"mentions"`, `"reason"`} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("customer payload leaked %q: %s", forbidden, text)
		}
	}
	if !strings.Contains(text, `"projection":"customer"`) || !strings.Contains(text, `"visibility":"public"`) {
		t.Fatalf("customer payload missing safe discriminator: %s", text)
	}
}

func TestCommentTransportMappingsRejectUnsafeServiceProjections(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	ticketID := mustTransportUUIDv7(t)
	commentID := mustTransportUUIDv7(t)
	membershipID := mustTransportUUIDv7(t)
	createdAt := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	comment := transportComment(tenantID, ticketID, commentID, membershipID, createdAt, false)
	comment.BodyHTML = `<script>alert(1)</script>`
	if _, err := mapOperatorComment(comment, tenantID, kernel.AggregateAlert, ticketID); err == nil {
		t.Fatal("operator mapper accepted unsafe stored HTML")
	}
	comment.BodyHTML = "<p>Corrected</p>"
	if _, err := mapOperatorComment(comment, mustTransportUUIDv7(t), kernel.AggregateAlert, ticketID); err == nil {
		t.Fatal("operator mapper accepted a cross-tenant projection")
	}
	preview := application.CommentPreview{
		Visibility: kernel.CommentPublic, BodyMarkdown: "Safe", BodyHTML: "<p>different</p>",
		Attachments: []application.CommentAttachment{}, Mentions: []application.CommentMention{},
		Projection: application.ProjectionOperator,
	}
	if _, err := mapOperatorCommentPreview(preview); err == nil {
		t.Fatal("preview mapper accepted non-canonical rendering")
	}
	revisions := application.CommentRevisionPage{
		Projection: application.ProjectionCustomer,
		Items: []application.CommentRevision{{
			Revision: 1, BodyMarkdown: "Safe", BodyHTML: `<img src="https://example.invalid/pixel">`,
			EditedAt: createdAt, Attachments: []application.CommentAttachment{}, Mentions: []application.CommentMention{},
		}},
	}
	if _, err := mapCustomerCommentRevisionPage(revisions); err == nil {
		t.Fatal("customer revision mapper accepted unsafe historical HTML")
	}
	if _, err := mapCommentMentionCandidates(application.CommentMentionCandidateList{
		Items: []application.CommentMentionCandidate{{MembershipID: membershipID, DisplayName: "Analyst\nInjected"}},
	}); err == nil {
		t.Fatal("candidate mapper accepted a control character")
	}
}

func TestCommentRoutesAreMounted(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	alertID := mustTransportUUIDv7(t)
	caseID := mustTransportUUIDv7(t)
	commentID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	base := "/api/v1/tenants/" + tenantID.String()
	tests := []struct {
		method string
		path   string
		body   string
		edit   bool
	}{
		{http.MethodPost, base + "/alerts/" + alertID.String() + "/comments/preview", `{"visibility":"public","bodyMarkdown":"Preview"}`, false},
		{http.MethodGet, base + "/alerts/" + alertID.String() + "/comments/mention-candidates", "", false},
		{http.MethodPatch, base + "/alerts/" + alertID.String() + "/comments/" + commentID.String(), `{"bodyMarkdown":"Edit","reason":"Reason"}`, true},
		{http.MethodGet, base + "/alerts/" + alertID.String() + "/comments/" + commentID.String() + "/revisions", "", false},
		{http.MethodPost, base + "/cases/" + caseID.String() + "/comments/preview", `{"visibility":"public","bodyMarkdown":"Preview"}`, false},
		{http.MethodGet, base + "/cases/" + caseID.String() + "/comments/mention-candidates", "", false},
		{http.MethodPatch, base + "/cases/" + caseID.String() + "/comments/" + commentID.String(), `{"bodyMarkdown":"Edit","reason":"Reason"}`, true},
		{http.MethodGet, base + "/cases/" + caseID.String() + "/comments/" + commentID.String() + "/revisions", "", false},
		{http.MethodPost, base + "/portal/alerts/" + alertID.String() + "/comments/preview", `{"bodyMarkdown":"Preview"}`, false},
		{http.MethodPatch, base + "/portal/alerts/" + alertID.String() + "/comments/" + commentID.String(), `{"bodyMarkdown":"Edit"}`, true},
		{http.MethodGet, base + "/portal/alerts/" + alertID.String() + "/comments/" + commentID.String() + "/revisions", "", false},
		{http.MethodPost, base + "/portal/cases/" + caseID.String() + "/comments/preview", `{"bodyMarkdown":"Preview"}`, false},
		{http.MethodPatch, base + "/portal/cases/" + caseID.String() + "/comments/" + commentID.String(), `{"bodyMarkdown":"Edit"}`, true},
		{http.MethodGet, base + "/portal/cases/" + caseID.String() + "/comments/" + commentID.String() + "/revisions", "", false},
	}
	for _, test := range tests {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			stub := &transportTicketingStub{}
			router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
			var request *http.Request
			if test.method == http.MethodGet {
				request = httptest.NewRequest(test.method, test.path, nil)
				prepareTenantLDAPTransportRequest(request, false)
			} else {
				request = ticketingMutationRequest(test.method, test.path, test.body)
			}
			if test.edit {
				request.Header.Set(ifMatchHeader, `"comment-r1"`)
				request.Header.Set(idempotencyKeyHeader, "comment-route-key-0001")
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code == http.StatusNotFound || response.Code == http.StatusMethodNotAllowed {
				t.Fatalf("route is not mounted: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestCommentEditRequiresExactStrongCommentPrecondition(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	alertID := mustTransportUUIDv7(t)
	commentID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/alerts/" + alertID.String() + "/comments/" + commentID.String()
	for _, test := range []struct {
		name, value string
		status      int
	}{
		{"missing", "", http.StatusPreconditionRequired},
		{"weak", `W/"comment-r1"`, http.StatusBadRequest},
		{"wrong namespace", `"v1"`, http.StatusBadRequest},
		{"zero", `"comment-r0"`, http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			stub := &transportTicketingStub{}
			router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
			request := ticketingMutationRequest(http.MethodPatch, path, `{"bodyMarkdown":"Edit","reason":"Reason"}`)
			if test.value != "" {
				request.Header.Set(ifMatchHeader, test.value)
			}
			request.Header.Set(idempotencyKeyHeader, "comment-precondition-0001")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.status || stub.commentCalls != 0 {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, stub.commentCalls, response.Body.String())
			}
		})
	}
}

func transportComment(
	tenantID, ticketID, commentID, membershipID uuid.UUID,
	createdAt time.Time,
	customer bool,
) application.Comment {
	audience := application.CommentAudienceOperator
	origin := application.CommentOriginAPI
	if customer {
		audience = application.CommentAudienceCustomer
		origin = application.CommentOriginCustomerPortal
	}
	return application.Comment{
		ID: commentID, TenantID: tenantID, ResourceID: ticketID, ResourceKind: kernel.AggregateAlert,
		Visibility: kernel.CommentPublic, BodyMarkdown: "Corrected", BodyHTML: "<p>Corrected</p>",
		Author: application.CommentAuthor{MembershipID: membershipID, DisplayName: "Analyst", Audience: audience},
		Origin: origin, Attachments: []application.CommentAttachment{}, Mentions: []application.CommentMention{},
		Revision: 2, CreatedAt: createdAt, UpdatedAt: createdAt.Add(time.Minute),
		EditableUntil: createdAt.Add(15 * time.Minute), CanEdit: true,
	}
}
