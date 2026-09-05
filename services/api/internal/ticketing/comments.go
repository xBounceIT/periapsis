package ticketing

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

const (
	commentEditWindowSeconds = 900
	maximumCommentEditReason = 500
)

type commentContext struct {
	access LiveAccess
	view   View
}

type commentEditValidation struct {
	context commentContext
	allowed bool
}

func (service *Service) Comments(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
	pageInput CursorPageInput,
) (CommentPage, error) {
	return service.comments(ctx, actor, tenantID, kind, id, pageInput, false)
}

func (service *Service) CommentsPortal(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
	pageInput CursorPageInput,
) (CommentPage, error) {
	return service.comments(ctx, actor, tenantID, kind, id, pageInput, true)
}

func (service *Service) comments(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
	pageInput CursorPageInput,
	portal bool,
) (CommentPage, error) {
	capability := commentReadCapability(kind)
	if portal {
		capability = CapabilityPortalCommentPublic
	}
	readContext, err := service.resolveCommentContext(ctx, actor, tenantID, kind, id, capability, portal)
	if err != nil {
		return CommentPage{}, err
	}
	pageInput, err = validateCursorPage(pageInput)
	if err != nil {
		return CommentPage{}, err
	}
	page, err := service.repository.ListComments(ctx, readContext.view.Record, pageInput, readContext.access)
	if err != nil {
		return CommentPage{}, repositoryError(err)
	}
	if len(page.Items) > pageInput.Limit || !validOptionalCursor(page.NextCursor) ||
		len(page.Items) == 0 && page.NextCursor != nil ||
		len(page.Items) != 0 && pageInput.After != nil && compareUUID(page.Items[0].ID, *pageInput.After) <= 0 {
		return CommentPage{}, ErrUnavailable
	}
	channel := kernel.ProjectionOperator
	if portal {
		channel = kernel.ProjectionCustomerAPI
	}
	editValidations := make(map[kernel.CommentVisibility]commentEditValidation, 2)
	for index := range page.Items {
		comment := &page.Items[index]
		validationContext := readContext
		if !portal && comment.CanEdit {
			validation, resolved := editValidations[comment.Visibility]
			if !resolved {
				resolvedContext, resolveErr := service.resolveCommentContext(
					ctx, actor, tenantID, kind, id, commentWriteCapability(kind, comment.Visibility), false,
				)
				if resolveErr != nil {
					if !errors.Is(resolveErr, ErrForbidden) && !errors.Is(resolveErr, ErrNotFound) {
						return CommentPage{}, resolveErr
					} else {
						validation = commentEditValidation{}
					}
				} else if resolvedContext.view.Projection != readContext.view.Projection ||
					resolvedContext.access.MembershipID != readContext.access.MembershipID ||
					!sameOptionalValue(resolvedContext.access.CustomerContactID, readContext.access.CustomerContactID) ||
					!sameSnapshot(resolvedContext.view.Record.Snapshot, readContext.view.Record.Snapshot) {
					return CommentPage{}, ErrUnavailable
				} else {
					validation = commentEditValidation{context: resolvedContext, allowed: true}
				}
				editValidations[comment.Visibility] = validation
			}
			if validation.allowed {
				validationContext = validation.context
			} else {
				comment.CanEdit = false
			}
		}
		if !validComment(*comment, tenantID, id, kind, readContext.view.Projection, validationContext.access, service.clock()) ||
			!kernel.CanProjectComment(readContext.view.Record.Workflow, readContext.view.Record.Snapshot, comment.Visibility, channel) ||
			index > 0 && compareUUID(page.Items[index-1].ID, comment.ID) >= 0 {
			return CommentPage{}, ErrUnavailable
		}
	}
	if page.NextCursor != nil && page.Items[len(page.Items)-1].ID != *page.NextCursor {
		return CommentPage{}, ErrUnavailable
	}
	return CommentPage{
		Items: page.Items, Projection: readContext.view.Projection, NextCursor: page.NextCursor,
	}, nil
}

func (service *Service) PreviewComment(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
	input CommentPreviewInput,
) (CommentPreview, error) {
	return service.previewComment(ctx, actor, tenantID, kind, id, input, false)
}

func (service *Service) PreviewPortalComment(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
	input CommentPreviewInput,
) (CommentPreview, error) {
	return service.previewComment(ctx, actor, tenantID, kind, id, input, true)
}

func (service *Service) previewComment(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
	input CommentPreviewInput,
	portal bool,
) (CommentPreview, error) {
	if !validActor(actor, tenantID) || !validCommentDraftInput(
		input.Visibility, input.BodyMarkdown, input.AttachmentIDs, input.MentionedIDs,
	) || portal && (input.Visibility != kernel.CommentPublic || len(input.MentionedIDs) != 0) {
		return CommentPreview{}, ErrInvalidInput
	}
	capability := commentWriteCapability(kind, input.Visibility)
	if portal {
		capability = CapabilityPortalCommentPublic
	}
	commentContext, err := service.resolveCommentContext(ctx, actor, tenantID, kind, id, capability, portal)
	if err != nil {
		return CommentPreview{}, err
	}
	bodyHTML, err := RenderCommentMarkdown(input.BodyMarkdown)
	if err != nil {
		return CommentPreview{}, err
	}
	draft, err := kernel.NewCommentDraft(commentContext.access.Authority.Principal(), input.Visibility, input.BodyMarkdown)
	if err != nil {
		return CommentPreview{}, ErrInvalidInput
	}
	if !kernel.CanCreateComment(kind, commentContext.view.Record.Snapshot.Tenant(), draft, commentContext.access.Authority) {
		return CommentPreview{}, ErrForbidden
	}
	stored, err := service.repository.PreviewComment(ctx, CommentPreviewQuery{
		Actor: actor, Record: commentContext.view.Record, Visibility: input.Visibility,
		AttachmentIDs: cloneCommentIDs(input.AttachmentIDs), MentionedIDs: cloneCommentIDs(input.MentionedIDs),
		AuthorContactID: commentAuthorContactID(commentContext.access, portal),
	})
	if err != nil {
		return CommentPreview{}, repositoryError(err)
	}
	if !validCommentRelations(stored.Attachments, stored.Mentions, input.AttachmentIDs, input.MentionedIDs, portal) {
		return CommentPreview{}, ErrUnavailable
	}
	if input.Visibility == kernel.CommentPublic && !allCommentAttachmentsPublic(stored.Attachments) {
		return CommentPreview{}, ErrUnavailable
	}
	return CommentPreview{
		Visibility: input.Visibility, BodyMarkdown: input.BodyMarkdown, BodyHTML: bodyHTML,
		Attachments: stored.Attachments, Mentions: stored.Mentions, Projection: commentContext.view.Projection,
	}, nil
}

func (service *Service) CommentMentionCandidates(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
	input CommentMentionCandidateInput,
) (CommentMentionCandidateList, error) {
	if !validActor(actor, tenantID) || !validCommentMentionSearch(input.Search) {
		return CommentMentionCandidateList{}, ErrInvalidInput
	}
	limit, err := validateCommentLimit(input.Limit)
	if err != nil {
		return CommentMentionCandidateList{}, err
	}
	commentContext, err := service.resolveCommentContext(
		ctx, actor, tenantID, kind, id, commentWriteCapability(kind, kernel.CommentPublic), false,
	)
	if err != nil {
		return CommentMentionCandidateList{}, err
	}
	items, err := service.repository.ListCommentMentionCandidates(ctx, CommentMentionCandidateQuery{
		Actor: actor, Record: commentContext.view.Record, Search: input.Search, Limit: limit,
	})
	if err != nil {
		return CommentMentionCandidateList{}, repositoryError(err)
	}
	if len(items) > limit || !validMentionCandidates(items) {
		return CommentMentionCandidateList{}, ErrUnavailable
	}
	return CommentMentionCandidateList{Items: items}, nil
}

func (service *Service) AddComment(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
	input CommentInput,
) (Comment, Projection, bool, error) {
	return service.addComment(ctx, actor, tenantID, kind, id, input, false)
}

func (service *Service) AddPortalComment(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
	input CommentInput,
) (Comment, Projection, bool, error) {
	return service.addComment(ctx, actor, tenantID, kind, id, input, true)
}

func (service *Service) addComment(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
	input CommentInput,
	portal bool,
) (Comment, Projection, bool, error) {
	if !validMutationActor(actor, tenantID) || !validIdempotencyKey(input.IdempotencyKey) ||
		!validCommentDraftInput(input.Visibility, input.BodyMarkdown, input.AttachmentIDs, input.MentionedIDs) ||
		portal && (input.Visibility != kernel.CommentPublic || len(input.MentionedIDs) != 0) {
		return Comment{}, 0, false, ErrInvalidInput
	}
	capability := commentWriteCapability(kind, input.Visibility)
	if portal {
		capability = CapabilityPortalCommentPublic
	}
	commentContext, err := service.resolveCommentContext(ctx, actor, tenantID, kind, id, capability, portal)
	if err != nil {
		return Comment{}, 0, false, err
	}
	draft, err := kernel.NewCommentDraft(commentContext.access.Authority.Principal(), input.Visibility, input.BodyMarkdown)
	if err != nil {
		return Comment{}, 0, false, ErrInvalidInput
	}
	if !kernel.CanCreateComment(kind, commentContext.view.Record.Snapshot.Tenant(), draft, commentContext.access.Authority) {
		return Comment{}, 0, false, ErrForbidden
	}
	bodyHTML, err := RenderCommentMarkdown(input.BodyMarkdown)
	if err != nil {
		return Comment{}, 0, false, err
	}
	result, err := service.repository.CreateComment(ctx, CommentWrite{
		Actor: actor, Record: commentContext.view.Record, Draft: draft, BodyHTML: bodyHTML,
		AttachmentIDs: cloneCommentIDs(input.AttachmentIDs), MentionedIDs: cloneCommentIDs(input.MentionedIDs),
		AuthorContactID: commentAuthorContactID(commentContext.access, portal),
		IdempotencyHash: sha256.Sum256([]byte(input.IdempotencyKey)), Audit: actor.Audit,
	})
	if err != nil {
		return Comment{}, 0, false, repositoryError(err)
	}
	if !validComment(result.Comment, tenantID, id, kind, commentContext.view.Projection, commentContext.access, service.clock()) ||
		result.Comment.Visibility != input.Visibility || result.Comment.Revision != 1 ||
		result.Comment.BodyMarkdown != input.BodyMarkdown || !result.Replayed && result.Comment.BodyHTML != bodyHTML ||
		!validCommentRelations(result.Comment.Attachments, result.Comment.Mentions, input.AttachmentIDs, input.MentionedIDs, portal) {
		return Comment{}, 0, false, ErrUnavailable
	}
	if !validCreatedCommentAuthor(result.Comment, commentContext.access, portal) {
		return Comment{}, 0, false, ErrUnavailable
	}
	return result.Comment, commentContext.view.Projection, result.Replayed, nil
}

func (service *Service) EditComment(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID, commentID uuid.UUID,
	input CommentEditInput,
) (Comment, Projection, bool, error) {
	return service.editComment(ctx, actor, tenantID, kind, ticketID, commentID, input, false)
}

func (service *Service) EditPortalComment(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID, commentID uuid.UUID,
	input CommentEditInput,
) (Comment, Projection, bool, error) {
	return service.editComment(ctx, actor, tenantID, kind, ticketID, commentID, input, true)
}

func (service *Service) editComment(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID, commentID uuid.UUID,
	input CommentEditInput,
	portal bool,
) (Comment, Projection, bool, error) {
	if !validMutationActor(actor, tenantID) || !validCommentID(commentID) ||
		input.ExpectedRevision < 1 || input.ExpectedRevision >= int(maxResourceVersion) ||
		!validIdempotencyKey(input.IdempotencyKey) || !validCommentSourceAndRelations(
		input.BodyMarkdown, input.AttachmentIDs, input.MentionedIDs,
	) || portal && len(input.MentionedIDs) != 0 ||
		!portal && !validCommentEditReason(input.Reason) || portal && input.Reason != "author_correction" {
		return Comment{}, 0, false, ErrInvalidInput
	}
	capability := commentWriteCapability(kind, kernel.CommentPublic)
	if portal {
		capability = CapabilityPortalCommentPublic
	}
	commentContext, err := service.resolveCommentContext(ctx, actor, tenantID, kind, ticketID, capability, portal)
	if err != nil {
		return Comment{}, 0, false, err
	}
	bodyHTML, err := RenderCommentMarkdown(input.BodyMarkdown)
	if err != nil {
		return Comment{}, 0, false, err
	}
	write := CommentEditWrite{
		Actor: actor, Record: commentContext.view.Record, CommentID: commentID,
		ExpectedRevision: input.ExpectedRevision, BodyMarkdown: input.BodyMarkdown, BodyHTML: bodyHTML,
		AttachmentIDs: cloneCommentIDs(input.AttachmentIDs), MentionedIDs: cloneCommentIDs(input.MentionedIDs),
		Reason: input.Reason, AuthorContactID: commentAuthorContactID(commentContext.access, portal),
		IdempotencyHash: sha256.Sum256([]byte(input.IdempotencyKey)), Audit: actor.Audit,
	}
	preflight, err := service.repository.PreflightCommentEdit(ctx, write)
	if err != nil {
		return Comment{}, 0, false, commentEditRepositoryError(err)
	}
	editState := preflight.State
	if !validStoredCommentEditState(editState) || !validCommentEditReplay(preflight, input.ExpectedRevision) {
		return Comment{}, 0, false, ErrUnavailable
	}
	if !canAuthorEditCommentState(editState, commentContext.access, portal) {
		return Comment{}, 0, false, ErrNotFound
	}
	if editState.Visibility == kernel.CommentPrivate {
		if portal {
			return Comment{}, 0, false, ErrNotFound
		}
		privateContext, privateErr := service.resolveCommentContext(
			ctx, actor, tenantID, kind, ticketID, commentWriteCapability(kind, kernel.CommentPrivate), false,
		)
		if privateErr != nil {
			if errors.Is(privateErr, ErrForbidden) || errors.Is(privateErr, ErrNotFound) {
				return Comment{}, 0, false, ErrNotFound
			}
			return Comment{}, 0, false, privateErr
		}
		if !sameCommentAccessIdentity(commentContext.access, privateContext.access) ||
			commentContext.view.Projection != privateContext.view.Projection ||
			!sameSnapshot(commentContext.view.Record.Snapshot, privateContext.view.Record.Snapshot) {
			return Comment{}, 0, false, ErrUnavailable
		}
		commentContext = privateContext
		write.Record = privateContext.view.Record
	}
	principal := kernel.PrincipalOperator
	if portal {
		principal = kernel.PrincipalCustomer
	}
	draft, draftErr := kernel.NewCommentDraft(principal, editState.Visibility, input.BodyMarkdown)
	if draftErr != nil {
		return Comment{}, 0, false, ErrInvalidInput
	}
	if !kernel.CanCreateComment(kind, commentContext.view.Record.Snapshot.Tenant(), draft, commentContext.access.Authority) {
		return Comment{}, 0, false, ErrForbidden
	}
	if !preflight.Replayed && input.ExpectedRevision != editState.Revision {
		return Comment{}, 0, false, ErrPreconditionFailed
	}
	if !preflight.Replayed && !service.clock().Before(editState.EditableUntil) {
		return Comment{}, 0, false, ErrForbidden
	}
	result, err := service.repository.EditComment(ctx, write)
	if err != nil {
		return Comment{}, 0, false, commentEditRepositoryError(err)
	}
	if !validComment(result.Comment, tenantID, ticketID, kind, commentContext.view.Projection, commentContext.access, service.clock()) ||
		preflight.Replayed && !result.Replayed ||
		result.Comment.ID != commentID || result.Comment.Revision != input.ExpectedRevision+1 ||
		result.Comment.Visibility != editState.Visibility || result.Comment.CreatedAt != editState.CreatedAt ||
		result.Comment.EditableUntil != editState.EditableUntil || result.Comment.Origin != editState.Origin ||
		result.Comment.Author.Audience != editState.AuthorAudience ||
		result.Comment.Author.MembershipID != editState.AuthorMembershipID ||
		!sameOptionalValue(result.Comment.Author.ContactID, editState.AuthorContactID) ||
		result.Comment.BodyMarkdown != input.BodyMarkdown || !result.Replayed && result.Comment.BodyHTML != bodyHTML ||
		!validCommentRelations(result.Comment.Attachments, result.Comment.Mentions, input.AttachmentIDs, input.MentionedIDs, portal) {
		return Comment{}, 0, false, ErrUnavailable
	}
	return result.Comment, commentContext.view.Projection, result.Replayed, nil
}

func commentEditRepositoryError(err error) error {
	mapped := repositoryError(err)
	if errors.Is(mapped, ErrForbidden) || errors.Is(mapped, ErrNotFound) {
		return ErrNotFound
	}
	return mapped
}

func validCommentEditReplay(value CommentEditPreflight, expectedRevision int) bool {
	if !value.Replayed {
		return value.ReplayRevision == nil
	}
	return value.ReplayRevision != nil && *value.ReplayRevision == expectedRevision+1 &&
		value.State.Revision >= *value.ReplayRevision
}

func validStoredCommentEditState(value CommentEditState) bool {
	if value.Visibility != kernel.CommentPublic && value.Visibility != kernel.CommentPrivate ||
		!validCommentID(value.AuthorMembershipID) || value.Revision < 1 || value.Revision > int(maxResourceVersion) ||
		!validCommentStoredInstant(value.CreatedAt) || !validCommentStoredInstant(value.EditableUntil) ||
		!value.EditableUntil.Equal(value.CreatedAt.Add(commentEditWindowSeconds*time.Second)) {
		return false
	}
	return validCommentAuthorOrigin(value.Origin, value.AuthorAudience, value.AuthorContactID)
}

func canAuthorEditCommentState(value CommentEditState, access LiveAccess, portal bool) bool {
	if value.AuthorMembershipID != uuidFromEntity(access.MembershipID) {
		return false
	}
	if portal {
		return value.Visibility == kernel.CommentPublic && value.Origin == CommentOriginCustomerPortal &&
			value.AuthorAudience == CommentAudienceCustomer && value.AuthorContactID != nil &&
			validCommentID(*value.AuthorContactID) && access.CustomerContactID != nil &&
			*value.AuthorContactID == uuidFromEntity(*access.CustomerContactID)
	}
	return value.Origin == CommentOriginAPI && value.AuthorAudience == CommentAudienceOperator &&
		value.AuthorContactID == nil && access.Authority.Principal() == kernel.PrincipalOperator
}

func validCreatedCommentAuthor(value Comment, access LiveAccess, portal bool) bool {
	if value.Author.MembershipID != uuidFromEntity(access.MembershipID) {
		return false
	}
	if portal {
		return value.Origin == CommentOriginCustomerPortal && value.Author.Audience == CommentAudienceCustomer &&
			value.Author.ContactID != nil && access.CustomerContactID != nil &&
			*value.Author.ContactID == uuidFromEntity(*access.CustomerContactID)
	}
	return value.Origin == CommentOriginAPI && value.Author.Audience == CommentAudienceOperator &&
		value.Author.ContactID == nil
}

func sameOptionalValue[T comparable](left, right *T) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func (service *Service) CommentRevisions(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID, commentID uuid.UUID,
	pageInput CommentRevisionPageInput,
) (CommentRevisionPage, error) {
	return service.commentRevisions(ctx, actor, tenantID, kind, ticketID, commentID, pageInput, false)
}

func (service *Service) CommentRevisionsPortal(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID, commentID uuid.UUID,
	pageInput CommentRevisionPageInput,
) (CommentRevisionPage, error) {
	return service.commentRevisions(ctx, actor, tenantID, kind, ticketID, commentID, pageInput, true)
}

func (service *Service) commentRevisions(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID, commentID uuid.UUID,
	pageInput CommentRevisionPageInput,
	portal bool,
) (CommentRevisionPage, error) {
	if !validActor(actor, tenantID) || !validCommentID(commentID) {
		return CommentRevisionPage{}, ErrInvalidInput
	}
	pageInput, err := validateCommentRevisionPage(pageInput)
	if err != nil {
		return CommentRevisionPage{}, err
	}
	capability := commentReadCapability(kind)
	if portal {
		capability = CapabilityPortalCommentPublic
	}
	commentContext, err := service.resolveCommentContext(ctx, actor, tenantID, kind, ticketID, capability, portal)
	if err != nil {
		return CommentRevisionPage{}, err
	}
	page, err := service.repository.ListCommentRevisions(ctx, CommentRevisionQuery{
		Actor: actor, Record: commentContext.view.Record, CommentID: commentID,
		Page: pageInput, Access: commentContext.access,
	})
	if err != nil {
		return CommentRevisionPage{}, repositoryError(err)
	}
	if len(page.Items) > pageInput.Limit || !validCommentRevisionPageResult(page, portal) ||
		len(page.Items) != 0 && pageInput.AfterRevision != nil && page.Items[0].Revision >= *pageInput.AfterRevision {
		return CommentRevisionPage{}, ErrUnavailable
	}
	return CommentRevisionPage{
		Items: page.Items, Projection: commentContext.view.Projection,
		NextAfterRevision: page.NextAfterRevision,
	}, nil
}

func (service *Service) resolveCommentContext(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID uuid.UUID,
	capability Capability,
	portal bool,
) (commentContext, error) {
	if !validActor(actor, tenantID) || !validCapability(capability) ||
		kind != kernel.AggregateAlert && kind != kernel.AggregateCase {
		return commentContext{}, ErrForbidden
	}
	commentAccess, err := service.access(ctx, actor, tenantID, capability)
	if err != nil {
		return commentContext{}, err
	}
	readCapability := readCapability(kind)
	principal := kernel.PrincipalOperator
	if portal {
		readCapability = portalReadCapability(kind)
		principal = kernel.PrincipalCustomer
	}
	readAccess, err := service.access(ctx, actor, tenantID, readCapability)
	if err != nil {
		return commentContext{}, err
	}
	if commentAccess.Authority.Principal() != principal || readAccess.Authority.Principal() != principal ||
		!sameCommentAccessIdentity(commentAccess, readAccess) {
		return commentContext{}, ErrForbidden
	}
	commentView, err := service.getAuthorized(ctx, tenantID, kind, ticketID, commentAccess)
	if err != nil {
		return commentContext{}, err
	}
	readView, err := service.getAuthorized(ctx, tenantID, kind, ticketID, readAccess)
	if err != nil {
		return commentContext{}, err
	}
	if commentView.Projection != readView.Projection || !sameSnapshot(commentView.Record.Snapshot, readView.Record.Snapshot) {
		return commentContext{}, ErrUnavailable
	}
	return commentContext{access: commentAccess, view: commentView}, nil
}

func sameCommentAccessIdentity(left, right LiveAccess) bool {
	if !sameAuthority(left.Authority, right.Authority) || left.MembershipID != right.MembershipID {
		return false
	}
	if left.CustomerContactID == nil || right.CustomerContactID == nil {
		return left.CustomerContactID == nil && right.CustomerContactID == nil
	}
	return *left.CustomerContactID == *right.CustomerContactID
}

func commentAuthorContactID(access LiveAccess, portal bool) *uuid.UUID {
	if !portal || access.CustomerContactID == nil {
		return nil
	}
	value := uuidFromEntity(*access.CustomerContactID)
	return &value
}

func validCommentDraftInput(
	visibility kernel.CommentVisibility,
	body string,
	attachmentIDs, mentionedIDs []uuid.UUID,
) bool {
	return (visibility == kernel.CommentPublic || visibility == kernel.CommentPrivate) &&
		validCommentSourceAndRelations(body, attachmentIDs, mentionedIDs)
}

func validCommentSourceAndRelations(body string, attachmentIDs, mentionedIDs []uuid.UUID) bool {
	return validCommentMarkdownSource(body) &&
		validCanonicalCommentIDs(attachmentIDs, maximumCommentAttachments) &&
		validCanonicalCommentIDs(mentionedIDs, maximumCommentMentions)
}

func validCanonicalCommentIDs(values []uuid.UUID, maximum int) bool {
	if !validUUIDList(values, maximum) {
		return false
	}
	for index := 1; index < len(values); index++ {
		if compareUUID(values[index-1], values[index]) >= 0 {
			return false
		}
	}
	return true
}

func cloneCommentIDs(values []uuid.UUID) []uuid.UUID {
	return append([]uuid.UUID{}, values...)
}

func compareUUID(left, right uuid.UUID) int {
	return strings.Compare(left.String(), right.String())
}

func validCommentMentionSearch(value string) bool {
	if value == "" {
		return true
	}
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 100 ||
		strings.TrimSpace(value) == "" || strings.ContainsAny(value, "<>") {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || commentDirectionalControl(character) {
			return false
		}
	}
	return true
}

func validateCommentLimit(limit int) (int, error) {
	if limit == 0 {
		return DefaultPageSize, nil
	}
	if limit < 1 || limit > MaximumPageSize {
		return 0, ErrInvalidInput
	}
	return limit, nil
}

func validateCommentRevisionPage(page CommentRevisionPageInput) (CommentRevisionPageInput, error) {
	limit, err := validateCommentLimit(page.Limit)
	if err != nil || page.AfterRevision != nil && (*page.AfterRevision < 1 || *page.AfterRevision > int(maxResourceVersion)) {
		return CommentRevisionPageInput{}, ErrInvalidInput
	}
	page.Limit = limit
	return page, nil
}

func validCommentEditReason(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	characters := utf8.RuneCountInString(value)
	if characters < 1 || characters > maximumCommentEditReason || strings.TrimSpace(value) == "" {
		return false
	}
	for index, character := range value {
		if unicode.IsControl(character) || commentDirectionalControl(character) {
			return false
		}
		if character == '<' {
			remainder := value[index+1:]
			if strings.HasPrefix(remainder, "/") {
				remainder = remainder[1:]
			}
			if remainder != "" {
				first, _ := utf8.DecodeRuneInString(remainder)
				if first >= 'A' && first <= 'Z' || first >= 'a' && first <= 'z' {
					return false
				}
			}
		}
	}
	return true
}

func validCommentID(value uuid.UUID) bool {
	_, err := entityID(value)
	return err == nil
}

func validMentionCandidates(items []CommentMentionCandidate) bool {
	seen := make(map[uuid.UUID]struct{}, len(items))
	for index, item := range items {
		if !validCommentID(item.MembershipID) || !validCommentDisplayName(item.DisplayName) {
			return false
		}
		if _, duplicate := seen[item.MembershipID]; duplicate {
			return false
		}
		if index > 0 && compareMentionCandidates(items[index-1], item) >= 0 {
			return false
		}
		seen[item.MembershipID] = struct{}{}
	}
	return true
}

func compareMentionCandidates(left, right CommentMentionCandidate) int {
	if displayOrder := strings.Compare(left.DisplayName, right.DisplayName); displayOrder != 0 {
		return displayOrder
	}
	return compareUUID(left.MembershipID, right.MembershipID)
}

func validCommentRelations(
	attachments []CommentAttachment,
	mentions []CommentMention,
	attachmentIDs, mentionedIDs []uuid.UUID,
	portal bool,
) bool {
	if len(attachments) != len(attachmentIDs) || len(mentions) != len(mentionedIDs) || portal && len(mentions) != 0 {
		return false
	}
	for index, attachment := range attachments {
		if attachment.ID != attachmentIDs[index] || !validCommentAttachment(attachment) ||
			index > 0 && compareUUID(attachments[index-1].ID, attachment.ID) >= 0 {
			return false
		}
	}
	for index, mention := range mentions {
		if mention.MembershipID != mentionedIDs[index] || !validCommentMention(mention) ||
			index > 0 && compareUUID(mentions[index-1].MembershipID, mention.MembershipID) >= 0 {
			return false
		}
	}
	return true
}

func validCommentAttachment(value CommentAttachment) bool {
	return validCommentID(value.ID) && validCommentAttachmentFilename(value.OriginalFilename) &&
		(value.Visibility == kernel.CommentPublic || value.Visibility == kernel.CommentPrivate)
}

func validCommentAttachmentFilename(value string) bool {
	if len(value) < 1 || len(value) > 255 || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value || value == "." || value == ".." ||
		strings.ContainsAny(value, "/\\\n\t") {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || commentDirectionalControl(character) {
			return false
		}
	}
	return true
}

func commentDirectionalControl(character rune) bool {
	return character == '\u200e' || character == '\u200f' ||
		character >= '\u202a' && character <= '\u202e' ||
		character >= '\u2066' && character <= '\u2069'
}

func validCommentMention(value CommentMention) bool {
	return validCommentID(value.MembershipID) && validCommentDisplayName(value.DisplayName)
}

func allCommentAttachmentsPublic(values []CommentAttachment) bool {
	return !slices.ContainsFunc(values, func(value CommentAttachment) bool {
		return value.Visibility != kernel.CommentPublic
	})
}

func validCommentRevisionPageResult(page StoredCommentRevisionPage, portal bool) bool {
	if len(page.Items) == 0 {
		return page.NextAfterRevision == nil
	}
	for index, revision := range page.Items {
		if !validCommentRevision(revision, portal) ||
			index > 0 && (page.Items[index-1].Revision != revision.Revision+1 ||
				!page.Items[index-1].EditedAt.After(revision.EditedAt)) {
			return false
		}
	}
	return page.NextAfterRevision == nil || *page.NextAfterRevision == page.Items[len(page.Items)-1].Revision
}

// IsValidCommentPageProjection repeats the stored-shape and customer-isolation
// checks at the transport boundary without attempting to recompute live edit
// authority.
func IsValidCommentPageProjection(page CommentPage) bool {
	if page.Projection != ProjectionOperator && page.Projection != ProjectionCustomer ||
		len(page.Items) > MaximumPageSize || !validOptionalCursor(page.NextCursor) ||
		len(page.Items) == 0 && page.NextCursor != nil {
		return false
	}
	for index, comment := range page.Items {
		if !IsValidCommentProjection(comment, page.Projection) ||
			index > 0 && compareUUID(page.Items[index-1].ID, comment.ID) >= 0 {
			return false
		}
	}
	return page.NextCursor == nil || page.Items[len(page.Items)-1].ID == *page.NextCursor
}

// IsValidCommentPreviewProjection validates a freshly rendered preview before
// it crosses the HTTP boundary.
func IsValidCommentPreviewProjection(value CommentPreview) bool {
	if value.Projection != ProjectionOperator && value.Projection != ProjectionCustomer ||
		value.Visibility != kernel.CommentPublic && value.Visibility != kernel.CommentPrivate ||
		len(value.Attachments) > maximumCommentAttachments || len(value.Mentions) > maximumCommentMentions ||
		!validCommentRelationProjection(value.Attachments, value.Mentions) {
		return false
	}
	rendered, err := RenderCommentMarkdown(value.BodyMarkdown)
	if err != nil || rendered != value.BodyHTML {
		return false
	}
	if value.Projection == ProjectionCustomer {
		return value.Visibility == kernel.CommentPublic && len(value.Mentions) == 0 &&
			allCommentAttachmentsPublic(value.Attachments)
	}
	return value.Visibility != kernel.CommentPublic || allCommentAttachmentsPublic(value.Attachments)
}

// IsValidCommentMentionCandidateList validates the bounded canonical operator
// projection returned by the application boundary.
func IsValidCommentMentionCandidateList(value CommentMentionCandidateList) bool {
	return len(value.Items) <= MaximumPageSize && validMentionCandidates(value.Items)
}

// IsValidCommentRevisionPageProjection repeats revision sanitation, ordering,
// cursor, and customer redaction checks at the transport boundary.
func IsValidCommentRevisionPageProjection(page CommentRevisionPage) bool {
	if page.Projection != ProjectionOperator && page.Projection != ProjectionCustomer ||
		len(page.Items) > MaximumPageSize {
		return false
	}
	return validCommentRevisionPageResult(StoredCommentRevisionPage{
		Items: page.Items, NextAfterRevision: page.NextAfterRevision,
	}, page.Projection == ProjectionCustomer)
}

func validCommentRevision(value CommentRevision, portal bool) bool {
	if value.Revision < 1 || value.Revision > int(maxResourceVersion) ||
		!validCommentStoredInstant(value.EditedAt) || !validStoredCommentBodies(value.BodyMarkdown, value.BodyHTML) ||
		len(value.Attachments) > maximumCommentAttachments || len(value.Mentions) > maximumCommentMentions {
		return false
	}
	if portal {
		if value.Reason != "" || len(value.Mentions) != 0 || !allCommentAttachmentsPublic(value.Attachments) {
			return false
		}
	} else if value.Revision == 1 {
		if value.Reason != "original_comment" {
			return false
		}
	} else if value.Reason != "author_correction" && !validCommentEditReason(value.Reason) {
		return false
	}
	return validCommentRelationProjection(value.Attachments, value.Mentions)
}

func validCommentRelationProjection(attachments []CommentAttachment, mentions []CommentMention) bool {
	for index, attachment := range attachments {
		if !validCommentAttachment(attachment) || index > 0 && compareUUID(attachments[index-1].ID, attachment.ID) >= 0 {
			return false
		}
	}
	for index, mention := range mentions {
		if !validCommentMention(mention) || index > 0 && compareUUID(mentions[index-1].MembershipID, mention.MembershipID) >= 0 {
			return false
		}
	}
	return true
}

func validStoredCommentBodies(markdown, html string) bool {
	return validCommentMarkdownSource(markdown) && validRenderedCommentHTML(html)
}

func validCommentStoredInstant(value time.Time) bool {
	return validStoredInstant(value) && value.Year() >= 1 && value.Year() <= 9999
}

func validCommentMarkdownSource(value string) bool {
	_, err := kernel.NewCommentDraft(kernel.PrincipalOperator, kernel.CommentPublic, value)
	return err == nil
}

func validCommentDisplayName(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	characters := utf8.RuneCountInString(value)
	if characters < 1 || characters > 200 ||
		strings.TrimSpace(value) != value || strings.ContainsAny(value, "\n\t") {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || commentDirectionalControl(character) {
			return false
		}
	}
	return true
}
