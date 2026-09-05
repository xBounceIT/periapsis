package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

// A page may contain 100 contract-valid comments or revisions. Each item can
// carry a 100 KB rendered body, up to 80 KB of four-byte Markdown scalars, and
// bounded frozen relation labels, so the decoder ceiling must cover the
// contract maximum while remaining finite.
const (
	maximumTicketCommentProjectionBytes  = 32 << 20
	maximumTicketJSONNesting             = 64
	ticketCommentRevisionConflictMessage = "ticket comment revision conflict"
)

const (
	createTenantTicketCommentSQL = `
		SELECT comment_id, result_revision, result_item, replayed
		FROM app.create_tenant_ticket_comment_v2(
		  $1::public.ticket_aggregate_kind,$2,$3::public.ticket_comment_visibility,
		  $4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14
		)`
	createPortalTicketCommentSQL = `
		SELECT comment_id, result_revision, result_item, replayed
		FROM app.create_customer_portal_ticket_comment_v2(
		  $1::public.ticket_aggregate_kind,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13
		)`
	editTenantTicketCommentSQL = `
		SELECT comment_id, result_revision, result_item, replayed
		FROM app.edit_tenant_ticket_comment_v2(
		  $1::public.ticket_aggregate_kind,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16
		)`
	editPortalTicketCommentSQL = `
		SELECT comment_id, result_revision, result_item, replayed
		FROM app.edit_customer_portal_ticket_comment_v2(
		  $1::public.ticket_aggregate_kind,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15
		)`
	preflightTenantTicketCommentEditSQL = `
		SELECT result_visibility,result_author_membership_id,result_author_contact_id,
		       result_revision,result_created_at,result_editable_until,result_origin,
		       result_author_audience,result_replayed,result_replay_revision
		FROM app.get_tenant_ticket_comment_edit_state_v1(
		  $1::public.ticket_aggregate_kind,$2,$3,$4,$5
		)`
	preflightPortalTicketCommentEditSQL = `
		SELECT result_visibility,result_author_membership_id,result_author_contact_id,
		       result_revision,result_created_at,result_editable_until,result_origin,
		       result_author_audience,result_replayed,result_replay_revision
		FROM app.get_customer_portal_ticket_comment_edit_state_v1(
		  $1::public.ticket_aggregate_kind,$2,$3,$4,$5
		)`
	listTenantTicketCommentsSQL = `
		SELECT result_items, next_cursor
		FROM app.list_tenant_ticket_comments_v2(
		  $1::public.ticket_aggregate_kind,$2,$3,$4
		)`
	listPortalTicketCommentsSQL = `
		SELECT result_items, next_cursor
		FROM app.list_customer_portal_ticket_comments_v2(
		  $1::public.ticket_aggregate_kind,$2,$3,$4
		)`
	previewTenantTicketCommentSQL = `
		SELECT result_attachments, result_mentions
		FROM app.preview_tenant_ticket_comment_v1(
		  $1::public.ticket_aggregate_kind,$2,$3::public.ticket_comment_visibility,$4,$5
		)`
	previewPortalTicketCommentSQL = `
		SELECT result_attachments, result_mentions
		FROM app.preview_customer_portal_ticket_comment_v1(
		  $1::public.ticket_aggregate_kind,$2,$3
		)`
	listTicketCommentMentionCandidatesSQL = `
		SELECT result_items
		FROM app.list_tenant_ticket_comment_mention_candidates_v1(
		  $1::public.ticket_aggregate_kind,$2,$3,$4
		)`
	listTenantTicketCommentRevisionsSQL = `
		SELECT result_items, next_after_revision
		FROM app.list_tenant_ticket_comment_revisions_v1(
		  $1::public.ticket_aggregate_kind,$2,$3,$4,$5
		)`
	listPortalTicketCommentRevisionsSQL = `
		SELECT result_items, next_after_revision
		FROM app.list_customer_portal_ticket_comment_revisions_v1(
		  $1::public.ticket_aggregate_kind,$2,$3,$4,$5
		)`
)

type ticketCommentAttachmentWire struct {
	ID               string `json:"id"`
	OriginalFilename string `json:"original_filename"`
	Visibility       string `json:"visibility"`
}

type ticketCommentMentionWire struct {
	MembershipID string `json:"membership_id"`
	DisplayName  string `json:"display_name"`
}

type ticketCommentNullableStringWire struct {
	Present bool
	Value   *string
}

func (value *ticketCommentNullableStringWire) UnmarshalJSON(document []byte) error {
	value.Present = true
	value.Value = nil
	if bytes.Equal(document, []byte("null")) {
		return nil
	}
	var decoded string
	if err := json.Unmarshal(document, &decoded); err != nil {
		return err
	}
	value.Value = &decoded
	return nil
}

type tenantTicketCommentWire struct {
	ID                 string                          `json:"id"`
	Visibility         string                          `json:"visibility"`
	BodyMarkdown       string                          `json:"body_markdown"`
	BodyHTML           string                          `json:"body_html"`
	AuthorMembershipID string                          `json:"author_membership_id"`
	AuthorContactID    ticketCommentNullableStringWire `json:"author_contact_id"`
	AuthorDisplayName  string                          `json:"author_display_name"`
	AuthorAudience     string                          `json:"author_audience"`
	Origin             string                          `json:"origin"`
	Revision           int                             `json:"revision"`
	CreatedAt          string                          `json:"created_at"`
	UpdatedAt          string                          `json:"updated_at"`
	EditableUntil      string                          `json:"editable_until"`
	CanEdit            *bool                           `json:"can_edit"`
	Attachments        []ticketCommentAttachmentWire   `json:"attachments"`
	Mentions           []ticketCommentMentionWire      `json:"mentions"`
}

type portalTicketCommentWire struct {
	ID                 string                          `json:"id"`
	Visibility         string                          `json:"visibility"`
	BodyMarkdown       string                          `json:"body_markdown"`
	BodyHTML           string                          `json:"body_html"`
	AuthorMembershipID string                          `json:"author_membership_id"`
	AuthorContactID    ticketCommentNullableStringWire `json:"author_contact_id"`
	AuthorDisplayName  string                          `json:"author_display_name"`
	AuthorAudience     string                          `json:"author_audience"`
	Origin             string                          `json:"origin"`
	Revision           int                             `json:"revision"`
	CreatedAt          string                          `json:"created_at"`
	UpdatedAt          string                          `json:"updated_at"`
	EditableUntil      string                          `json:"editable_until"`
	CanEdit            *bool                           `json:"can_edit"`
	Attachments        []ticketCommentAttachmentWire   `json:"attachments"`
}

type ticketCommentRevisionWire struct {
	Revision     int                           `json:"revision"`
	BodyMarkdown string                        `json:"body_markdown"`
	BodyHTML     string                        `json:"body_html"`
	Reason       string                        `json:"reason"`
	EditedAt     string                        `json:"edited_at"`
	Attachments  []ticketCommentAttachmentWire `json:"attachments"`
	Mentions     []ticketCommentMentionWire    `json:"mentions"`
}

type portalTicketCommentRevisionWire struct {
	Revision     int                           `json:"revision"`
	BodyMarkdown string                        `json:"body_markdown"`
	BodyHTML     string                        `json:"body_html"`
	EditedAt     string                        `json:"edited_at"`
	Attachments  []ticketCommentAttachmentWire `json:"attachments"`
}

func mapTicketCommentDatabaseError(err error) error {
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != "40001" {
		return mapTicketDatabaseError(err)
	}
	if databaseError.Message == ticketCommentRevisionConflictMessage {
		return application.ErrPreconditionFailed
	}
	return application.ErrUnavailable
}

func withinTicketCommentReadTransaction[T any](
	ctx context.Context,
	repository *TicketingRepository,
	actorID, tenantID uuid.UUID,
	work func(databaseTransaction) (T, error),
) (T, error) {
	return withinTicketActorTransactionWithOptionsAndMapper(
		ctx, repository, application.Actor{UserID: actorID, ActiveTenantID: tenantID}, tenantID,
		pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, work,
		mapTicketCommentDatabaseError,
	)
}

func withinTicketCommentWriteTransaction[T any](
	ctx context.Context,
	repository *TicketingRepository,
	actor application.Actor,
	tenantID uuid.UUID,
	work func(databaseTransaction) (T, error),
) (T, error) {
	return withinTicketActorTransactionWithOptionsAndMapper(
		ctx, repository, actor, tenantID, pgx.TxOptions{IsoLevel: pgx.Serializable}, work,
		mapTicketCommentDatabaseError,
	)
}

func (repository *TicketingRepository) CreateComment(
	ctx context.Context,
	write application.CommentWrite,
) (application.CommentWriteResult, error) {
	tenantID := uuid.UUID(write.Record.Snapshot.Tenant().Bytes())
	ticketID := uuid.UUID(write.Record.Snapshot.ID().Bytes())
	if rendered, err := application.RenderCommentMarkdown(write.Draft.Body()); err != nil || rendered != write.BodyHTML {
		return application.CommentWriteResult{}, application.ErrInvalidInput
	}
	requestDigest, err := ticketRequestDigest(struct {
		Operation       string      `json:"operation"`
		TenantID        uuid.UUID   `json:"tenant_id"`
		Kind            string      `json:"kind"`
		TicketID        uuid.UUID   `json:"ticket_id"`
		Visibility      string      `json:"visibility"`
		BodyMarkdown    string      `json:"body_markdown"`
		AttachmentIDs   []uuid.UUID `json:"attachment_ids"`
		MentionedIDs    []uuid.UUID `json:"mentioned_membership_ids"`
		AuthorContactID *uuid.UUID  `json:"author_contact_id,omitempty"`
	}{
		Operation: "comment.create", TenantID: tenantID,
		Kind: write.Record.Snapshot.Kind().String(), TicketID: ticketID,
		Visibility: write.Draft.Visibility().String(), BodyMarkdown: write.Draft.Body(),
		AttachmentIDs: write.AttachmentIDs, MentionedIDs: write.MentionedIDs,
		AuthorContactID: write.AuthorContactID,
	})
	if err != nil {
		return application.CommentWriteResult{}, err
	}
	return withinTicketCommentWriteTransaction(ctx, repository, write.Actor, tenantID,
		func(tx databaseTransaction) (application.CommentWriteResult, error) {
			var commentID uuid.UUID
			var resultRevision int
			var document []byte
			var replayed bool
			var queryErr error
			portal := write.AuthorContactID != nil
			if portal {
				queryErr = tx.QueryRow(ctx, createPortalTicketCommentSQL,
					write.Record.Snapshot.Kind().String(), ticketID, *write.AuthorContactID,
					write.Draft.Body(), write.BodyHTML, write.AttachmentIDs,
					write.IdempotencyHash[:], requestDigest[:], write.Audit.RequestID,
					write.Audit.CorrelationID, write.Audit.RemoteAddress.Unmap(), write.Audit.UserAgent,
					write.Actor.AuthenticationMethod,
				).Scan(&commentID, &resultRevision, &document, &replayed)
			} else {
				queryErr = tx.QueryRow(ctx, createTenantTicketCommentSQL,
					write.Record.Snapshot.Kind().String(), ticketID, write.Draft.Visibility().String(),
					write.Draft.Body(), write.BodyHTML, write.AttachmentIDs, write.MentionedIDs,
					write.IdempotencyHash[:], requestDigest[:], write.Audit.RequestID,
					write.Audit.CorrelationID, write.Audit.RemoteAddress.Unmap(), write.Audit.UserAgent,
					write.Actor.AuthenticationMethod,
				).Scan(&commentID, &resultRevision, &document, &replayed)
			}
			if queryErr != nil {
				return application.CommentWriteResult{}, mapTicketCommentDatabaseError(queryErr)
			}
			comment, err := decodeTicketCommentResult(document, tenantID, write.Record.Snapshot.Kind(), ticketID, portal)
			if err != nil || comment.ID != commentID || comment.Revision != resultRevision {
				return application.CommentWriteResult{}, application.ErrUnavailable
			}
			return application.CommentWriteResult{Comment: comment, Replayed: replayed}, nil
		},
	)
}

func (repository *TicketingRepository) EditComment(
	ctx context.Context,
	write application.CommentEditWrite,
) (application.CommentWriteResult, error) {
	tenantID := uuid.UUID(write.Record.Snapshot.Tenant().Bytes())
	ticketID := uuid.UUID(write.Record.Snapshot.ID().Bytes())
	if rendered, err := application.RenderCommentMarkdown(write.BodyMarkdown); err != nil || rendered != write.BodyHTML {
		return application.CommentWriteResult{}, application.ErrInvalidInput
	}
	requestDigest, err := ticketCommentEditRequestDigest(write)
	if err != nil {
		return application.CommentWriteResult{}, err
	}
	return withinTicketCommentWriteTransaction(ctx, repository, write.Actor, tenantID,
		func(tx databaseTransaction) (application.CommentWriteResult, error) {
			var commentID uuid.UUID
			var resultRevision int
			var document []byte
			var replayed bool
			var queryErr error
			portal := write.AuthorContactID != nil
			if portal {
				queryErr = tx.QueryRow(ctx, editPortalTicketCommentSQL,
					write.Record.Snapshot.Kind().String(), ticketID, write.CommentID,
					write.ExpectedRevision, *write.AuthorContactID, write.BodyMarkdown, write.BodyHTML,
					write.AttachmentIDs, write.IdempotencyHash[:], requestDigest[:],
					write.Audit.RequestID, write.Audit.CorrelationID, write.Audit.RemoteAddress.Unmap(),
					write.Audit.UserAgent, write.Actor.AuthenticationMethod,
				).Scan(&commentID, &resultRevision, &document, &replayed)
			} else {
				queryErr = tx.QueryRow(ctx, editTenantTicketCommentSQL,
					write.Record.Snapshot.Kind().String(), ticketID, write.CommentID,
					write.ExpectedRevision, write.BodyMarkdown, write.BodyHTML, write.AttachmentIDs,
					write.MentionedIDs, write.Reason, write.IdempotencyHash[:], requestDigest[:],
					write.Audit.RequestID, write.Audit.CorrelationID, write.Audit.RemoteAddress.Unmap(),
					write.Audit.UserAgent, write.Actor.AuthenticationMethod,
				).Scan(&commentID, &resultRevision, &document, &replayed)
			}
			if queryErr != nil {
				return application.CommentWriteResult{}, mapTicketCommentDatabaseError(queryErr)
			}
			comment, err := decodeTicketCommentResult(document, tenantID, write.Record.Snapshot.Kind(), ticketID, portal)
			if err != nil || comment.ID != commentID || comment.Revision != resultRevision {
				return application.CommentWriteResult{}, application.ErrUnavailable
			}
			return application.CommentWriteResult{Comment: comment, Replayed: replayed}, nil
		},
	)
}

func ticketCommentEditRequestDigest(write application.CommentEditWrite) ([32]byte, error) {
	tenantID := uuid.UUID(write.Record.Snapshot.Tenant().Bytes())
	ticketID := uuid.UUID(write.Record.Snapshot.ID().Bytes())
	return ticketRequestDigest(struct {
		Operation        string      `json:"operation"`
		TenantID         uuid.UUID   `json:"tenant_id"`
		Kind             string      `json:"kind"`
		TicketID         uuid.UUID   `json:"ticket_id"`
		CommentID        uuid.UUID   `json:"comment_id"`
		ExpectedRevision int         `json:"expected_revision"`
		BodyMarkdown     string      `json:"body_markdown"`
		AttachmentIDs    []uuid.UUID `json:"attachment_ids"`
		MentionedIDs     []uuid.UUID `json:"mentioned_membership_ids"`
		Reason           string      `json:"reason"`
		AuthorContactID  *uuid.UUID  `json:"author_contact_id,omitempty"`
	}{
		Operation: "comment.edit", TenantID: tenantID,
		Kind: write.Record.Snapshot.Kind().String(), TicketID: ticketID,
		CommentID: write.CommentID, ExpectedRevision: write.ExpectedRevision,
		BodyMarkdown: write.BodyMarkdown, AttachmentIDs: write.AttachmentIDs,
		MentionedIDs: write.MentionedIDs, Reason: write.Reason, AuthorContactID: write.AuthorContactID,
	})
}

func (repository *TicketingRepository) PreflightCommentEdit(
	ctx context.Context,
	write application.CommentEditWrite,
) (application.CommentEditPreflight, error) {
	tenantID := uuid.UUID(write.Record.Snapshot.Tenant().Bytes())
	ticketID := uuid.UUID(write.Record.Snapshot.ID().Bytes())
	requestDigest, err := ticketCommentEditRequestDigest(write)
	if err != nil {
		return application.CommentEditPreflight{}, err
	}
	return withinTicketCommentReadTransaction(ctx, repository, write.Actor.UserID, tenantID,
		func(tx databaseTransaction) (application.CommentEditPreflight, error) {
			query := preflightTenantTicketCommentEditSQL
			if write.AuthorContactID != nil {
				query = preflightPortalTicketCommentEditSQL
			}
			var visibility, origin, audience string
			var membershipID uuid.UUID
			var contactID pgtype.UUID
			var revision int
			var createdAt, editableUntil time.Time
			var replayed bool
			var replayRevision pgtype.Int4
			if queryErr := tx.QueryRow(
				ctx, query, write.Record.Snapshot.Kind().String(), ticketID, write.CommentID,
				write.IdempotencyHash[:], requestDigest[:],
			).Scan(
				&visibility, &membershipID, &contactID, &revision, &createdAt, &editableUntil,
				&origin, &audience, &replayed, &replayRevision,
			); queryErr != nil {
				return application.CommentEditPreflight{}, mapTicketCommentDatabaseError(queryErr)
			}
			state, stateErr := ticketCommentEditState(
				visibility, membershipID, contactID, revision, createdAt, editableUntil, origin, audience,
			)
			if stateErr != nil {
				return application.CommentEditPreflight{}, application.ErrUnavailable
			}
			replay, replayErr := strictTicketCommentOptionalRevision(replayRevision)
			if replayErr != nil || replayed != (replay != nil) {
				return application.CommentEditPreflight{}, application.ErrUnavailable
			}
			return application.CommentEditPreflight{State: state, Replayed: replayed, ReplayRevision: replay}, nil
		},
	)
}

func (repository *TicketingRepository) ListComments(
	ctx context.Context,
	record application.Record,
	page application.CursorPageInput,
	access application.LiveAccess,
) (application.StoredCommentPage, error) {
	tenantID := uuid.UUID(record.Snapshot.Tenant().Bytes())
	ticketID := uuid.UUID(record.Snapshot.ID().Bytes())
	actorID := uuid.UUID(access.Authority.Actor().Bytes())
	return withinTicketCommentReadTransaction(ctx, repository, actorID, tenantID,
		func(tx databaseTransaction) (application.StoredCommentPage, error) {
			var document []byte
			var next pgtype.UUID
			query := listTenantTicketCommentsSQL
			portal := access.Authority.Principal() == kernel.PrincipalCustomer
			if portal {
				query = listPortalTicketCommentsSQL
			}
			if err := tx.QueryRow(
				ctx, query, record.Snapshot.Kind().String(), ticketID, optionalUUID(page.After), page.Limit,
			).Scan(&document, &next); err != nil {
				return application.StoredCommentPage{}, mapTicketCommentDatabaseError(err)
			}
			items, err := decodeTicketCommentItems(document, tenantID, record.Snapshot.Kind(), ticketID, portal)
			if err != nil || len(items) > page.Limit {
				return application.StoredCommentPage{}, application.ErrUnavailable
			}
			nextCursor, err := strictTicketCommentOptionalUUID(next)
			if err != nil {
				return application.StoredCommentPage{}, application.ErrUnavailable
			}
			return application.StoredCommentPage{Items: items, NextCursor: nextCursor}, nil
		},
	)
}

func (repository *TicketingRepository) PreviewComment(
	ctx context.Context,
	query application.CommentPreviewQuery,
) (application.StoredCommentPreview, error) {
	tenantID := uuid.UUID(query.Record.Snapshot.Tenant().Bytes())
	ticketID := uuid.UUID(query.Record.Snapshot.ID().Bytes())
	return withinTicketCommentReadTransaction(ctx, repository, query.Actor.UserID, tenantID,
		func(tx databaseTransaction) (application.StoredCommentPreview, error) {
			var attachmentsJSON, mentionsJSON []byte
			var err error
			if query.AuthorContactID == nil {
				err = tx.QueryRow(ctx, previewTenantTicketCommentSQL,
					query.Record.Snapshot.Kind().String(), ticketID, query.Visibility.String(),
					query.AttachmentIDs, query.MentionedIDs,
				).Scan(&attachmentsJSON, &mentionsJSON)
			} else {
				err = tx.QueryRow(ctx, previewPortalTicketCommentSQL,
					query.Record.Snapshot.Kind().String(), ticketID, query.AttachmentIDs,
				).Scan(&attachmentsJSON, &mentionsJSON)
			}
			if err != nil {
				return application.StoredCommentPreview{}, mapTicketCommentDatabaseError(err)
			}
			attachments, err := decodeTicketCommentAttachments(attachmentsJSON)
			if err != nil {
				return application.StoredCommentPreview{}, application.ErrUnavailable
			}
			mentions, err := decodeTicketCommentMentions(mentionsJSON)
			if err != nil || query.AuthorContactID != nil && len(mentions) != 0 {
				return application.StoredCommentPreview{}, application.ErrUnavailable
			}
			return application.StoredCommentPreview{Attachments: attachments, Mentions: mentions}, nil
		},
	)
}

func (repository *TicketingRepository) ListCommentMentionCandidates(
	ctx context.Context,
	query application.CommentMentionCandidateQuery,
) ([]application.CommentMentionCandidate, error) {
	tenantID := uuid.UUID(query.Record.Snapshot.Tenant().Bytes())
	ticketID := uuid.UUID(query.Record.Snapshot.ID().Bytes())
	return withinTicketCommentReadTransaction(ctx, repository, query.Actor.UserID, tenantID,
		func(tx databaseTransaction) ([]application.CommentMentionCandidate, error) {
			var document []byte
			if err := tx.QueryRow(ctx, listTicketCommentMentionCandidatesSQL,
				query.Record.Snapshot.Kind().String(), ticketID, query.Search, query.Limit,
			).Scan(&document); err != nil {
				return nil, mapTicketCommentDatabaseError(err)
			}
			items, err := decodeTicketCommentCandidates(document)
			if err != nil || len(items) > query.Limit {
				return nil, application.ErrUnavailable
			}
			return items, nil
		},
	)
}

func (repository *TicketingRepository) ListCommentRevisions(
	ctx context.Context,
	query application.CommentRevisionQuery,
) (application.StoredCommentRevisionPage, error) {
	tenantID := uuid.UUID(query.Record.Snapshot.Tenant().Bytes())
	ticketID := uuid.UUID(query.Record.Snapshot.ID().Bytes())
	return withinTicketCommentReadTransaction(ctx, repository, query.Actor.UserID, tenantID,
		func(tx databaseTransaction) (application.StoredCommentRevisionPage, error) {
			var document []byte
			var next pgtype.Int4
			databaseQuery := listTenantTicketCommentRevisionsSQL
			portal := query.Access.Authority.Principal() == kernel.PrincipalCustomer
			if portal {
				databaseQuery = listPortalTicketCommentRevisionsSQL
			}
			if err := tx.QueryRow(
				ctx, databaseQuery, query.Record.Snapshot.Kind().String(), ticketID, query.CommentID,
				optionalInt(query.Page.AfterRevision), query.Page.Limit,
			).Scan(&document, &next); err != nil {
				return application.StoredCommentRevisionPage{}, mapTicketCommentDatabaseError(err)
			}
			items, err := decodeTicketCommentRevisions(document, portal)
			if err != nil || len(items) > query.Page.Limit {
				return application.StoredCommentRevisionPage{}, application.ErrUnavailable
			}
			nextRevision, err := strictTicketCommentOptionalRevision(next)
			if err != nil {
				return application.StoredCommentRevisionPage{}, application.ErrUnavailable
			}
			return application.StoredCommentRevisionPage{
				Items: items, NextAfterRevision: nextRevision,
			}, nil
		},
	)
}

func decodeTicketCommentResult(
	document []byte,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID uuid.UUID,
	portal bool,
) (application.Comment, error) {
	if portal {
		var wire portalTicketCommentWire
		if err := decodeStrictTicketCommentJSON(document, &wire); err != nil {
			return application.Comment{}, application.ErrUnavailable
		}
		return portalTicketComment(wire, tenantID, kind, ticketID)
	}
	var wire tenantTicketCommentWire
	if err := decodeStrictTicketCommentJSON(document, &wire); err != nil {
		return application.Comment{}, application.ErrUnavailable
	}
	return tenantTicketComment(wire, tenantID, kind, ticketID)
}

func decodeTicketCommentItems(
	document []byte,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID uuid.UUID,
	portal bool,
) ([]application.Comment, error) {
	if portal {
		var wires []portalTicketCommentWire
		if err := decodeStrictTicketCommentJSON(document, &wires); err != nil || wires == nil {
			return nil, application.ErrUnavailable
		}
		items := make([]application.Comment, len(wires))
		for index, wire := range wires {
			item, err := portalTicketComment(wire, tenantID, kind, ticketID)
			if err != nil || index > 0 && strings.Compare(items[index-1].ID.String(), item.ID.String()) >= 0 {
				return nil, application.ErrUnavailable
			}
			items[index] = item
		}
		return items, nil
	}
	var wires []tenantTicketCommentWire
	if err := decodeStrictTicketCommentJSON(document, &wires); err != nil || wires == nil {
		return nil, application.ErrUnavailable
	}
	items := make([]application.Comment, len(wires))
	for index, wire := range wires {
		item, err := tenantTicketComment(wire, tenantID, kind, ticketID)
		if err != nil || index > 0 && strings.Compare(items[index-1].ID.String(), item.ID.String()) >= 0 {
			return nil, application.ErrUnavailable
		}
		items[index] = item
	}
	return items, nil
}

func tenantTicketComment(
	wire tenantTicketCommentWire,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID uuid.UUID,
) (application.Comment, error) {
	attachments, err := ticketCommentAttachments(wire.Attachments)
	if err != nil {
		return application.Comment{}, err
	}
	if !wire.AuthorContactID.Present {
		return application.Comment{}, application.ErrUnavailable
	}
	mentions, err := ticketCommentMentions(wire.Mentions)
	if err != nil {
		return application.Comment{}, err
	}
	comment, err := ticketCommentFromWire(
		wire.ID, wire.Visibility, wire.BodyMarkdown, wire.BodyHTML,
		wire.AuthorMembershipID, wire.AuthorContactID.Value, wire.AuthorDisplayName,
		wire.AuthorAudience, wire.Origin, wire.Revision, wire.CreatedAt, wire.UpdatedAt,
		wire.EditableUntil, wire.CanEdit, attachments, mentions, tenantID, kind, ticketID,
	)
	if err != nil || !application.IsValidCommentProjection(comment, application.ProjectionOperator) {
		return application.Comment{}, application.ErrUnavailable
	}
	return comment, nil
}

func portalTicketComment(
	wire portalTicketCommentWire,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID uuid.UUID,
) (application.Comment, error) {
	attachments, err := ticketCommentAttachments(wire.Attachments)
	if err != nil {
		return application.Comment{}, err
	}
	if !wire.AuthorContactID.Present {
		return application.Comment{}, application.ErrUnavailable
	}
	comment, err := ticketCommentFromWire(
		wire.ID, wire.Visibility, wire.BodyMarkdown, wire.BodyHTML,
		wire.AuthorMembershipID, wire.AuthorContactID.Value, wire.AuthorDisplayName,
		wire.AuthorAudience, wire.Origin, wire.Revision, wire.CreatedAt, wire.UpdatedAt,
		wire.EditableUntil, wire.CanEdit, attachments, []application.CommentMention{}, tenantID, kind, ticketID,
	)
	if err != nil || !application.IsValidCommentProjection(comment, application.ProjectionCustomer) {
		return application.Comment{}, application.ErrUnavailable
	}
	return comment, nil
}

func ticketCommentFromWire(
	idText, visibilityText, bodyMarkdown, bodyHTML, membershipText string,
	contactText *string,
	displayName, audienceText, originText string,
	revision int,
	createdText, updatedText, editableText string,
	canEdit *bool,
	attachments []application.CommentAttachment,
	mentions []application.CommentMention,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID uuid.UUID,
) (application.Comment, error) {
	id, err := strictTicketCommentUUID(idText)
	if err != nil {
		return application.Comment{}, err
	}
	membershipID, err := strictTicketCommentUUID(membershipText)
	if err != nil {
		return application.Comment{}, err
	}
	var contactID *uuid.UUID
	if contactText != nil {
		value, parseErr := strictTicketCommentUUID(*contactText)
		if parseErr != nil {
			return application.Comment{}, parseErr
		}
		contactID = &value
	}
	createdAt, err := strictTicketCommentTime(createdText)
	if err != nil {
		return application.Comment{}, err
	}
	updatedAt, err := strictTicketCommentTime(updatedText)
	if err != nil {
		return application.Comment{}, err
	}
	editableUntil, err := strictTicketCommentTime(editableText)
	if err != nil || canEdit == nil {
		return application.Comment{}, application.ErrUnavailable
	}
	visibility, err := ticketCommentVisibility(visibilityText)
	if err != nil {
		return application.Comment{}, err
	}
	return application.Comment{
		ID: id, TenantID: tenantID, ResourceID: ticketID, ResourceKind: kind,
		Visibility: visibility, BodyMarkdown: bodyMarkdown, BodyHTML: bodyHTML,
		Author: application.CommentAuthor{
			MembershipID: membershipID, ContactID: contactID, DisplayName: displayName,
			Audience: application.CommentAuthorAudience(audienceText),
		},
		Origin: application.CommentOrigin(originText), Attachments: attachments, Mentions: mentions,
		Revision: revision, CreatedAt: createdAt, UpdatedAt: updatedAt,
		EditableUntil: editableUntil, CanEdit: *canEdit,
	}, nil
}

func ticketCommentEditState(
	visibilityText string,
	membershipID uuid.UUID,
	contactValue pgtype.UUID,
	revision int,
	createdAt, editableUntil time.Time,
	originText, audienceText string,
) (application.CommentEditState, error) {
	visibility, err := ticketCommentVisibility(visibilityText)
	if err != nil || !strictTicketCommentUUIDValue(membershipID) || revision < 1 ||
		revision > int(^uint32(0)>>1) || !strictTicketCommentStoredTime(createdAt) ||
		!strictTicketCommentStoredTime(editableUntil) {
		return application.CommentEditState{}, application.ErrUnavailable
	}
	contactID, err := strictTicketCommentOptionalUUID(contactValue)
	if err != nil {
		return application.CommentEditState{}, application.ErrUnavailable
	}
	return application.CommentEditState{
		Visibility: visibility, AuthorMembershipID: membershipID, AuthorContactID: contactID,
		Origin: application.CommentOrigin(originText), AuthorAudience: application.CommentAuthorAudience(audienceText),
		Revision: revision, CreatedAt: createdAt.UTC(), EditableUntil: editableUntil.UTC(),
	}, nil
}

func decodeTicketCommentAttachments(document []byte) ([]application.CommentAttachment, error) {
	var wires []ticketCommentAttachmentWire
	if err := decodeStrictTicketCommentJSON(document, &wires); err != nil || wires == nil {
		return nil, application.ErrUnavailable
	}
	return ticketCommentAttachments(wires)
}

func ticketCommentAttachments(wires []ticketCommentAttachmentWire) ([]application.CommentAttachment, error) {
	if wires == nil || len(wires) > 20 {
		return nil, application.ErrUnavailable
	}
	items := make([]application.CommentAttachment, len(wires))
	for index, wire := range wires {
		id, err := strictTicketCommentUUID(wire.ID)
		if err != nil {
			return nil, err
		}
		visibility, err := ticketCommentVisibility(wire.Visibility)
		if err != nil || !validTicketCommentFilename(wire.OriginalFilename) ||
			index > 0 && strings.Compare(items[index-1].ID.String(), id.String()) >= 0 {
			return nil, application.ErrUnavailable
		}
		items[index] = application.CommentAttachment{
			ID: id, OriginalFilename: wire.OriginalFilename, Visibility: visibility,
		}
	}
	return items, nil
}

func validTicketCommentFilename(value string) bool {
	if value == "" || len(value) > 255 || !utf8.ValidString(value) || strings.TrimSpace(value) != value ||
		value == "." || value == ".." || strings.ContainsAny(value, "/\\\n\t") {
		return false
	}
	for _, character := range value {
		if character < ' ' || character == '\u007f' || character >= '\u0080' && character <= '\u009f' ||
			character == '\u200e' || character == '\u200f' || character >= '\u202a' && character <= '\u202e' ||
			character >= '\u2066' && character <= '\u2069' {
			return false
		}
	}
	return true
}

func decodeTicketCommentMentions(document []byte) ([]application.CommentMention, error) {
	var wires []ticketCommentMentionWire
	if err := decodeStrictTicketCommentJSON(document, &wires); err != nil || wires == nil {
		return nil, application.ErrUnavailable
	}
	return ticketCommentMentions(wires)
}

func ticketCommentMentions(wires []ticketCommentMentionWire) ([]application.CommentMention, error) {
	if wires == nil || len(wires) > 50 {
		return nil, application.ErrUnavailable
	}
	items := make([]application.CommentMention, len(wires))
	for index, wire := range wires {
		id, err := strictTicketCommentUUID(wire.MembershipID)
		if err != nil || wire.DisplayName == "" || utf8.RuneCountInString(wire.DisplayName) > 200 ||
			!utf8.ValidString(wire.DisplayName) || strings.TrimSpace(wire.DisplayName) != wire.DisplayName ||
			index > 0 && strings.Compare(items[index-1].MembershipID.String(), id.String()) >= 0 {
			return nil, application.ErrUnavailable
		}
		items[index] = application.CommentMention{MembershipID: id, DisplayName: wire.DisplayName}
	}
	return items, nil
}

func decodeTicketCommentCandidates(document []byte) ([]application.CommentMentionCandidate, error) {
	var wires []ticketCommentMentionWire
	if err := decodeStrictTicketCommentJSON(document, &wires); err != nil || wires == nil {
		return nil, application.ErrUnavailable
	}
	items := make([]application.CommentMentionCandidate, len(wires))
	for index, wire := range wires {
		id, err := strictTicketCommentUUID(wire.MembershipID)
		if err != nil || wire.DisplayName == "" || utf8.RuneCountInString(wire.DisplayName) > 200 ||
			!utf8.ValidString(wire.DisplayName) || strings.TrimSpace(wire.DisplayName) != wire.DisplayName {
			return nil, application.ErrUnavailable
		}
		if index > 0 {
			previous := items[index-1]
			if strings.Compare(previous.DisplayName, wire.DisplayName) > 0 ||
				(previous.DisplayName == wire.DisplayName && strings.Compare(previous.MembershipID.String(), id.String()) >= 0) {
				return nil, application.ErrUnavailable
			}
		}
		items[index] = application.CommentMentionCandidate{MembershipID: id, DisplayName: wire.DisplayName}
	}
	if !application.IsValidCommentMentionCandidateList(application.CommentMentionCandidateList{Items: items}) {
		return nil, application.ErrUnavailable
	}
	return items, nil
}

func decodeTicketCommentRevisions(document []byte, portal bool) ([]application.CommentRevision, error) {
	if portal {
		var wires []portalTicketCommentRevisionWire
		if err := decodeStrictTicketCommentJSON(document, &wires); err != nil || wires == nil {
			return nil, application.ErrUnavailable
		}
		if len(wires) > application.MaximumPageSize {
			return nil, application.ErrUnavailable
		}
		items := make([]application.CommentRevision, len(wires))
		for index, wire := range wires {
			attachments, err := ticketCommentAttachments(wire.Attachments)
			editedAt, timeErr := strictTicketCommentTime(wire.EditedAt)
			if err != nil || timeErr != nil || index > 0 && items[index-1].Revision <= wire.Revision {
				return nil, application.ErrUnavailable
			}
			items[index] = application.CommentRevision{
				Revision: wire.Revision, BodyMarkdown: wire.BodyMarkdown, BodyHTML: wire.BodyHTML,
				EditedAt: editedAt, Attachments: attachments, Mentions: []application.CommentMention{},
			}
		}
		if !application.IsValidCommentRevisionPageProjection(application.CommentRevisionPage{
			Items: items, Projection: application.ProjectionCustomer,
		}) {
			return nil, application.ErrUnavailable
		}
		return items, nil
	}
	var wires []ticketCommentRevisionWire
	if err := decodeStrictTicketCommentJSON(document, &wires); err != nil || wires == nil {
		return nil, application.ErrUnavailable
	}
	if len(wires) > application.MaximumPageSize {
		return nil, application.ErrUnavailable
	}
	items := make([]application.CommentRevision, len(wires))
	for index, wire := range wires {
		attachments, err := ticketCommentAttachments(wire.Attachments)
		if err != nil {
			return nil, err
		}
		mentions, err := ticketCommentMentions(wire.Mentions)
		editedAt, timeErr := strictTicketCommentTime(wire.EditedAt)
		if err != nil || timeErr != nil || index > 0 && items[index-1].Revision <= wire.Revision {
			return nil, application.ErrUnavailable
		}
		items[index] = application.CommentRevision{
			Revision: wire.Revision, BodyMarkdown: wire.BodyMarkdown, BodyHTML: wire.BodyHTML,
			Reason: wire.Reason, EditedAt: editedAt, Attachments: attachments, Mentions: mentions,
		}
	}
	if !application.IsValidCommentRevisionPageProjection(application.CommentRevisionPage{
		Items: items, Projection: application.ProjectionOperator,
	}) {
		return nil, application.ErrUnavailable
	}
	return items, nil
}

func decodeStrictTicketCommentJSON(document []byte, destination any) error {
	if len(document) == 0 || len(document) > maximumTicketCommentProjectionBytes {
		return application.ErrUnavailable
	}
	if err := rejectDuplicateJSONKeys(document); err != nil {
		return application.ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return application.ErrUnavailable
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return application.ErrUnavailable
	}
	return nil
}

// encoding/json replaces lone escaped UTF-16 surrogates with U+FFFD. Reject
// them before decoding so a closed database ABI cannot be silently normalized
// into a different projection. Valid surrogate pairs remain accepted.
func validJSONUnicodeEscapes(document []byte) bool {
	inString := false
	for index := 0; index < len(document); index++ {
		switch document[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString {
				continue
			}
			index++
			if index >= len(document) {
				return false
			}
			if document[index] != 'u' {
				continue
			}
			if index+4 >= len(document) {
				return false
			}
			codePoint, valid := decodeJSONHexQuad(document[index+1 : index+5])
			if !valid {
				return false
			}
			index += 4
			switch {
			case codePoint >= 0xd800 && codePoint <= 0xdbff:
				if index+6 >= len(document) || document[index+1] != '\\' || document[index+2] != 'u' {
					return false
				}
				low, lowValid := decodeJSONHexQuad(document[index+3 : index+7])
				if !lowValid || low < 0xdc00 || low > 0xdfff {
					return false
				}
				index += 6
			case codePoint >= 0xdc00 && codePoint <= 0xdfff:
				return false
			}
		}
	}
	return true
}

func decodeJSONHexQuad(value []byte) (uint16, bool) {
	if len(value) != 4 {
		return 0, false
	}
	var result uint16
	for _, character := range value {
		result <<= 4
		switch {
		case character >= '0' && character <= '9':
			result += uint16(character - '0')
		case character >= 'a' && character <= 'f':
			result += uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			result += uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return result, true
}

func rejectDuplicateJSONKeys(document []byte) error {
	if !utf8.Valid(document) || !validJSONUnicodeEscapes(document) {
		return errors.New("invalid JSON Unicode encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > maximumTicketJSONNesting {
			return errors.New("JSON nesting limit exceeded")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				key, ok := keyToken.(string)
				if keyErr != nil || !ok {
					return errors.New("invalid JSON object key")
				}
				if _, duplicate := seen[key]; duplicate {
					return errors.New("duplicate JSON object key")
				}
				seen[key] = struct{}{}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return errors.New("invalid JSON object")
			}
		case '[':
			for decoder.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return errors.New("invalid JSON array")
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		return nil
	}
	if err := walk(1); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func strictTicketCommentUUID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.Version() != 7 || parsed.Variant() != uuid.RFC4122 || parsed.String() != value {
		return uuid.Nil, application.ErrUnavailable
	}
	return parsed, nil
}

func strictTicketCommentUUIDValue(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func strictTicketCommentTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() || parsed.Year() < 1 || parsed.Year() > 9999 ||
		parsed.Nanosecond()%int(time.Microsecond) != 0 {
		return time.Time{}, application.ErrUnavailable
	}
	_, offset := parsed.Zone()
	if offset != 0 {
		return time.Time{}, application.ErrUnavailable
	}
	return parsed.UTC(), nil
}

func strictTicketCommentStoredTime(value time.Time) bool {
	_, offset := value.Zone()
	return !value.IsZero() && value.Year() >= 1 && value.Year() <= 9999 && offset == 0 &&
		value.Nanosecond()%int(time.Microsecond) == 0
}

func ticketCommentVisibility(value string) (kernel.CommentVisibility, error) {
	switch value {
	case "public":
		return kernel.CommentPublic, nil
	case "private":
		return kernel.CommentPrivate, nil
	default:
		return 0, application.ErrUnavailable
	}
}

func optionalUUID(value *uuid.UUID) any {
	if value == nil {
		return nil
	}
	return *value
}

func optionalInt(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}

func strictTicketCommentOptionalUUID(value pgtype.UUID) (*uuid.UUID, error) {
	if !value.Valid {
		return nil, nil
	}
	parsed := uuid.UUID(value.Bytes)
	if parsed == uuid.Nil || parsed.Version() != 7 || parsed.Variant() != uuid.RFC4122 {
		return nil, application.ErrUnavailable
	}
	return &parsed, nil
}

func strictTicketCommentOptionalRevision(value pgtype.Int4) (*int, error) {
	if !value.Valid {
		return nil, nil
	}
	if value.Int32 < 1 {
		return nil, application.ErrUnavailable
	}
	result := int(value.Int32)
	return &result, nil
}
