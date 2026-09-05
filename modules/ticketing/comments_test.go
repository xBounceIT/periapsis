package ticketing

import (
	"fmt"
	"strings"
	"testing"
)

func TestCommentConstructionAndAuthorizationFailClosed(t *testing.T) {
	operator := fixtureID(101)
	base := authorityFixture(t, operator)
	publicOperator, err := NewCommentDraft(PrincipalOperator, CommentPublic, "Customer-safe **update**")
	if err != nil {
		t.Fatal(err)
	}
	privateOperator, err := NewCommentDraft(PrincipalOperator, CommentPrivate, "Internal investigation note")
	if err != nil {
		t.Fatal(err)
	}
	publicCustomer, err := NewCommentDraft(PrincipalCustomer, CommentPublic, "Customer response")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCommentDraft(PrincipalCustomer, CommentPrivate, "Must stay private"); err == nil {
		t.Fatal("customer private comment accepted")
	}
	if _, err := NewCommentDraft(PrincipalServiceAccount, CommentPublic, "machine comment"); err == nil {
		t.Fatal("service-account comment accepted")
	}
	for _, body := range []string{
		"<script>alert(1)</script>",
		" leading space",
		"trailing space ",
		"control\x00byte",
		"",
	} {
		if _, err := NewCommentDraft(PrincipalOperator, CommentPrivate, body); err == nil {
			t.Fatalf("unsafe body accepted: %q", body)
		}
	}
	for _, body := range []string{
		"1 < 2 and 3 > 2",
		"Use `<script>alert(1)</script>` as an inert example",
		"```html\n<script>alert(1)</script>\n```",
		strings.Repeat("😀", maxCommentScalars),
	} {
		if _, err := NewCommentDraft(PrincipalOperator, CommentPublic, body); err != nil {
			t.Fatalf("valid Unicode-scalar comment rejected: %v", err)
		}
	}
	if _, err := NewCommentDraft(
		PrincipalOperator,
		CommentPublic,
		strings.Repeat("😀", maxCommentScalars+1),
	); err == nil {
		t.Fatal("comment over the Unicode-scalar limit was accepted")
	}
	if _, err := NewCommentDraft(
		PrincipalOperator,
		CommentPublic,
		"<!-- raw HTML comment -->",
	); err == nil {
		t.Fatal("raw HTML comment was accepted")
	}

	if !CanCreateComment(AggregateAlert, fixtureID(1), publicOperator, base) ||
		!CanCreateComment(AggregateAlert, fixtureID(1), privateOperator, base) {
		t.Fatal("operator with exact permissions was denied")
	}
	customerAuthority := authorityFrom(
		t,
		base,
		PrincipalCustomer,
		true,
		nil,
		[]Permission{PermissionPortalCommentPublic},
		nil,
		nil,
		nil,
	)
	if !CanCreateComment(AggregateAlert, fixtureID(1), publicCustomer, customerAuthority) {
		t.Fatal("customer public comment denied")
	}
	if !CanCreateComment(AggregateCase, fixtureID(1), publicCustomer, customerAuthority) {
		t.Fatal("portal public-comment permission did not authorize a case comment")
	}
	wrongCustomerAuthority := authorityFrom(
		t,
		base,
		PrincipalCustomer,
		true,
		nil,
		[]Permission{PermissionAlertCommentPublic},
		nil,
		nil,
		nil,
	)
	if CanCreateComment(AggregateAlert, fixtureID(1), publicCustomer, wrongCustomerAuthority) {
		t.Fatal("operator public-comment permission authorized a portal comment")
	}

	withoutPrivate := authorityFrom(
		t,
		base,
		PrincipalOperator,
		true,
		base.Roles(),
		[]Permission{PermissionAlertCommentPublic},
		base.ClaimableTeams(),
		base.ManageableTeams(),
		base.AssignableRoster(),
	)
	if CanCreateComment(AggregateAlert, fixtureID(1), privateOperator, withoutPrivate) {
		t.Fatal("public permission authorized a private comment")
	}
	privateOnly := authorityFrom(
		t,
		base,
		PrincipalOperator,
		true,
		base.Roles(),
		[]Permission{PermissionAlertCommentPrivate},
		base.ClaimableTeams(),
		base.ManageableTeams(),
		base.AssignableRoster(),
	)
	if CanCreateComment(AggregateAlert, fixtureID(1), privateOperator, privateOnly) {
		t.Fatal("private permission bypassed the required public-comment capability")
	}
}

func TestPrivateCommentsNeverEnterCustomerProjection(t *testing.T) {
	workflow := alertWorkflowFixture(t)
	visible := mustTicket(t, workflow, fixtureID(301), "new", 1, true, Assignment{})
	channels := []ProjectionChannel{
		ProjectionCustomerPortal,
		ProjectionCustomerAPI,
		ProjectionCustomerEmail,
		ProjectionCustomerWebhook,
		ProjectionCustomerExport,
	}
	if !CanProjectComment(workflow, visible, CommentPrivate, ProjectionOperator) {
		t.Fatal("private comment missing from operator projection")
	}
	for _, channel := range channels {
		if CanProjectComment(workflow, visible, CommentPrivate, channel) {
			t.Fatalf("private comment leaked to %s", channel)
		}
		if !CanProjectComment(workflow, visible, CommentPublic, channel) {
			t.Fatalf("public comment unexpectedly hidden from %s", channel)
		}
	}
	if CanProjectComment(workflow, visible, CommentPublic, ProjectionChannel(255)) ||
		CanProjectComment(workflow, visible, CommentVisibility(255), ProjectionCustomerAPI) {
		t.Fatal("unknown visibility or projection value failed open")
	}
}

func TestTicketAndWorkflowVisibilityBothGateCustomerData(t *testing.T) {
	workflow := alertWorkflowFixture(t)
	aggregateInternal := mustTicket(t, workflow, fixtureID(301), "new", 1, false, Assignment{})
	stateInternal := mustTicket(t, workflow, fixtureID(302), "triage", 1, true, Assignment{})
	for _, ticket := range []TicketSnapshot{aggregateInternal, stateInternal} {
		if CanProjectTicket(workflow, ticket, ProjectionCustomerAPI) ||
			CanProjectComment(workflow, ticket, CommentPublic, ProjectionCustomerEmail) {
			t.Fatalf("customer visibility gate failed for %s", ticket)
		}
		if !CanProjectTicket(workflow, ticket, ProjectionOperator) {
			t.Fatalf("operator projection unexpectedly blocked for %s", ticket)
		}
	}
}

func TestSensitiveTextFormattingIsRedacted(t *testing.T) {
	secret := "sensitive customer detail"
	comment, err := NewCommentDraft(PrincipalOperator, CommentPrivate, secret)
	if err != nil {
		t.Fatal(err)
	}
	reason, err := NewEscalationReason(secret)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewIdempotencyKey("retry-secret-material")
	if err != nil {
		t.Fatal(err)
	}
	for name, rendered := range map[string]string{
		"comment":    fmt.Sprint(comment),
		"comment_go": fmt.Sprintf("%#v", comment),
		"reason":     fmt.Sprint(reason),
		"reason_go":  fmt.Sprintf("%#v", reason),
		"key":        fmt.Sprint(key),
		"key_go":     fmt.Sprintf("%#v", key),
	} {
		if strings.Contains(rendered, secret) || strings.Contains(rendered, "retry-secret-material") ||
			!strings.Contains(rendered, "REDACTED") {
			t.Fatalf("%s formatting leaked or omitted redaction marker: %q", name, rendered)
		}
	}
}
