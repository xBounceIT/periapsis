package ticketing

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

var commentMarkdownParser = goldmark.DefaultParser()

type CommentVisibility uint8

const (
	CommentPublic CommentVisibility = iota + 1
	CommentPrivate
)

func (visibility CommentVisibility) String() string {
	switch visibility {
	case CommentPublic:
		return "public"
	case CommentPrivate:
		return "private"
	default:
		return "unknown"
	}
}

func validCommentVisibility(visibility CommentVisibility) bool {
	return visibility == CommentPublic || visibility == CommentPrivate
}

// CommentDraft holds validated Markdown source. Raw HTML delimiters and control
// characters are rejected; every renderer must still sanitize the resulting HTML.
// String deliberately redacts the body.
type CommentDraft struct {
	author     PrincipalKind
	visibility CommentVisibility
	body       string
}

func NewCommentDraft(
	author PrincipalKind,
	visibility CommentVisibility,
	body string,
) (CommentDraft, error) {
	if (author != PrincipalOperator && author != PrincipalCustomer) ||
		!validCommentVisibility(visibility) || author == PrincipalCustomer && visibility != CommentPublic ||
		!validCommentBody(body) {
		return CommentDraft{}, ErrInvalidComment
	}
	return CommentDraft{author: author, visibility: visibility, body: body}, nil
}

func (comment CommentDraft) Author() PrincipalKind         { return comment.author }
func (comment CommentDraft) Visibility() CommentVisibility { return comment.visibility }
func (comment CommentDraft) Body() string                  { return comment.body }

func (comment CommentDraft) String() string {
	return fmt.Sprintf("CommentDraft{author:%s,visibility:%s,bytes:%d,body:[REDACTED]}",
		comment.author, comment.visibility, len(comment.body))
}

func (comment CommentDraft) GoString() string { return comment.String() }

func validCommentDraft(comment CommentDraft) bool {
	return (comment.author == PrincipalOperator || comment.author == PrincipalCustomer) &&
		validCommentVisibility(comment.visibility) &&
		(comment.author != PrincipalCustomer || comment.visibility == CommentPublic) &&
		validCommentBody(comment.body)
}

func validCommentBody(body string) bool {
	if !utf8.ValidString(body) || body == "" ||
		utf8.RuneCountInString(body) > maxCommentScalars ||
		strings.TrimSpace(body) != body {
		return false
	}
	for _, character := range body {
		if character == '\n' || character == '\t' {
			continue
		}
		if unicode.IsControl(character) || isDirectionalControl(character) {
			return false
		}
	}
	document := commentMarkdownParser.Parse(text.NewReader([]byte(body)))
	hasRawHTML := false
	err := ast.Walk(document, func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		if entering && (node.Kind() == ast.KindHTMLBlock || node.Kind() == ast.KindRawHTML) {
			hasRawHTML = true
			return ast.WalkStop, nil
		}
		return ast.WalkContinue, nil
	})
	return err == nil && !hasRawHTML
}

type ProjectionChannel uint8

const (
	ProjectionOperator ProjectionChannel = iota + 1
	ProjectionCustomerPortal
	ProjectionCustomerAPI
	ProjectionCustomerEmail
	ProjectionCustomerWebhook
	ProjectionCustomerExport
)

func (channel ProjectionChannel) String() string {
	switch channel {
	case ProjectionOperator:
		return "operator"
	case ProjectionCustomerPortal:
		return "customer_portal"
	case ProjectionCustomerAPI:
		return "customer_api"
	case ProjectionCustomerEmail:
		return "customer_email"
	case ProjectionCustomerWebhook:
		return "customer_webhook"
	case ProjectionCustomerExport:
		return "customer_export"
	default:
		return "unknown"
	}
}

func validProjectionChannel(channel ProjectionChannel) bool {
	return channel >= ProjectionOperator && channel <= ProjectionCustomerExport
}

// CanProjectTicket evaluates only workflow and aggregate visibility. A true
// result never substitutes for tenant/resource authorization at the use-case boundary.
func CanProjectTicket(
	workflow WorkflowDefinition,
	ticket TicketSnapshot,
	channel ProjectionChannel,
) bool {
	if !validProjectionChannel(channel) || !validTicketSnapshot(workflow, ticket) {
		return false
	}
	if channel == ProjectionOperator {
		return true
	}
	state, exists := workflow.state(ticket.state)
	return exists && ticket.customerVisible && state.visibility == VisibilityCustomer
}

// CanProjectComment is the shared fail-closed policy for UI, API, email,
// webhook, and export. Private comments can enter only operator projections.
func CanProjectComment(
	workflow WorkflowDefinition,
	ticket TicketSnapshot,
	visibility CommentVisibility,
	channel ProjectionChannel,
) bool {
	if !validCommentVisibility(visibility) || !CanProjectTicket(workflow, ticket, channel) {
		return false
	}
	return channel == ProjectionOperator || visibility == CommentPublic
}

// CanCreateComment rechecks tenant, principal class, and the exact permission.
// The caller must still persist comment, activity, audit, and outbox atomically.
func CanCreateComment(
	kind AggregateKind,
	tenant EntityID,
	draft CommentDraft,
	authority AuthorizationSnapshot,
) bool {
	if !validAggregateKind(kind) || !validEntityID(tenant) || !validCommentDraft(draft) ||
		!validAuthorizationSnapshot(authority) || !authority.tenantAccess || authority.tenant != tenant ||
		authority.principal != draft.author {
		return false
	}
	if draft.author == PrincipalCustomer {
		return draft.visibility == CommentPublic &&
			authority.hasPermission(PermissionPortalCommentPublic)
	}
	switch {
	case kind == AggregateAlert && draft.visibility == CommentPublic:
		return authority.hasPermission(PermissionAlertCommentPublic)
	case kind == AggregateAlert && draft.visibility == CommentPrivate:
		return authority.hasPermission(PermissionAlertCommentPublic) &&
			authority.hasPermission(PermissionAlertCommentPrivate)
	case kind == AggregateCase && draft.visibility == CommentPublic:
		return authority.hasPermission(PermissionCaseCommentPublic)
	case kind == AggregateCase && draft.visibility == CommentPrivate:
		return authority.hasPermission(PermissionCaseCommentPublic) &&
			authority.hasPermission(PermissionCaseCommentPrivate)
	default:
		return false
	}
}
