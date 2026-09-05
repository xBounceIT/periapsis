package httpserver

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationticketing "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func mapTicketView(view applicationticketing.View) (map[string]any, error) {
	record := view.Record
	state, found := ticketState(record.Workflow, record.Snapshot.State())
	if !found {
		return nil, errors.New("ticket workflow state is absent")
	}
	base := map[string]any{
		"id": uuid.UUID(record.Snapshot.ID().Bytes()), "tenantId": uuid.UUID(record.Snapshot.Tenant().Bytes()),
		"title": record.Title, "description": record.Description, "severity": record.Severity,
		"priority": record.Priority, "category": record.Category, "tags": nonNilStrings(record.Tags),
		"customerVisible": record.Snapshot.CustomerVisible(), "version": record.Snapshot.Version(),
		"createdAt": record.CreatedAt, "updatedAt": record.UpdatedAt,
		"visibility": visibilityValue(record.Snapshot.CustomerVisible()),
		"projection": viewProjection(view.Projection),
		"workflow": map[string]any{
			"workflowId": uuid.UUID(record.Workflow.ID().Bytes()), "version": record.Workflow.Version(),
			"kind": record.Snapshot.Kind().String(), "stateKey": record.Snapshot.State().String(),
			"initial": state.Initial(), "terminal": state.Terminal(),
			"customerVisible": state.Visibility() == kernel.VisibilityCustomer,
		},
	}
	if view.Projection == applicationticketing.ProjectionCustomer {
		base["customFields"] = nonNilMap(record.CustomerCustomFields)
	} else {
		base["customFields"] = nonNilMap(record.CustomFields)
		if len(record.DynamicColumns) > 0 {
			dynamicColumns, err := mapTicketDynamicColumns(record.DynamicColumns)
			if err != nil {
				return nil, err
			}
			base["dynamicColumns"] = dynamicColumns
		}
		base["assignment"] = assignmentProjection(record)
		base["creator"] = creatorProjection(record)
		if record.Classification != nil {
			base["classification"] = *record.Classification
		}
	}
	switch record.Snapshot.Kind() {
	case kernel.AggregateAlert:
		base["alertNumber"] = record.Number
		base["detectedAt"] = record.DetectedAt
		base["receivedAt"] = record.ReceivedAt
		if view.Projection == applicationticketing.ProjectionOperator {
			base["source"] = record.Source
			base["sourceType"] = record.SourceType
			if record.ExternalID != nil {
				base["externalId"] = *record.ExternalID
			}
			if record.DeduplicationKey != nil {
				base["deduplicationKey"] = *record.DeduplicationKey
			}
			if record.RawPayload != nil {
				base["rawPayload"] = maps.Clone(record.RawPayload)
			}
			putTime(base, "acknowledgedAt", record.AcknowledgedAt)
			putTime(base, "closedAt", record.ClosedAt)
		}
	case kernel.AggregateCase:
		base["caseNumber"] = record.Number
		base["summary"] = record.Summary
		base["detectionTime"] = record.DetectionTime
		base["openedAt"] = record.OpenedAt
		if view.Projection == applicationticketing.ProjectionOperator {
			putTime(base, "assignedAt", record.AssignedAt)
			putTime(base, "firstResponseAt", record.FirstResponseAt)
			putTime(base, "resolvedAt", record.ResolvedAt)
			putTime(base, "closedAt", record.ClosedAt)
		}
	default:
		return nil, errors.New("unknown ticket kind")
	}
	return base, nil
}

func mapTicketPage(page applicationticketing.Page) (map[string]any, error) {
	items := make([]any, 0, len(page.Items))
	for _, item := range page.Items {
		mapped, err := mapTicketView(item)
		if err != nil {
			return nil, err
		}
		items = append(items, mapped)
	}
	result := map[string]any{"items": items}
	if page.NextCursor != "" {
		result["nextCursor"] = page.NextCursor
	}
	if page.AppliedView != nil {
		digest := page.AppliedView.SpecDigest
		result["appliedView"] = map[string]any{
			"id":         uuid.UUID(page.AppliedView.View.ID().Bytes()),
			"revision":   page.AppliedView.View.Revision(),
			"specSha256": fmt.Sprintf("%x", digest[:]),
		}
	}
	return result, nil
}

func mapTicketDynamicColumns(values map[string]applicationticketing.DynamicColumnValue) ([]map[string]any, error) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	result := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		value := values[key]
		scalar, err := mapLosslessTicketScalar(value.Value)
		if err != nil {
			return nil, err
		}
		mapped := map[string]any{
			"source": value.Source, "definitionId": value.DefinitionID,
			"definitionVersion": value.DefinitionVersion,
			"value":             scalar,
		}
		if value.StyleKey != "" {
			mapped["styleKey"] = value.StyleKey
		}
		if value.MaterializedAt != nil {
			mapped["materializedAt"] = *value.MaterializedAt
		}
		result = append(result, mapped)
	}
	return result, nil
}

func mapOperatorComment(
	comment applicationticketing.Comment,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	resourceID uuid.UUID,
) (contract.OperatorComment, error) {
	mappedKind := contract.TicketResourceKind(comment.ResourceKind.String())
	visibility := contract.CommentVisibility(comment.Visibility.String())
	origin := contract.CommentOrigin(comment.Origin)
	audience := contract.CommentAuthorAudience(comment.Author.Audience)
	if !applicationticketing.IsValidCommentProjection(comment, applicationticketing.ProjectionOperator) ||
		comment.TenantID != tenantID || comment.ResourceKind != kind || comment.ResourceID != resourceID ||
		!mappedKind.Valid() || !visibility.Valid() || !origin.Valid() || !audience.Valid() || comment.Author.MembershipID == uuid.Nil {
		return contract.OperatorComment{}, errors.New("invalid operator comment projection")
	}
	attachments, err := mapOperatorCommentAttachments(comment.Attachments)
	if err != nil {
		return contract.OperatorComment{}, err
	}
	mentions := make([]contract.OperatorCommentMention, len(comment.Mentions))
	for index, mention := range comment.Mentions {
		mentions[index] = contract.OperatorCommentMention{
			MembershipId: mention.MembershipID, DisplayName: mention.DisplayName,
			Audience: contract.OperatorCommentMentionAudienceOperator,
		}
	}
	return contract.OperatorComment{
		Id: comment.ID, TenantId: comment.TenantID, ResourceId: comment.ResourceID, ResourceKind: mappedKind,
		Visibility: visibility, BodyMarkdown: comment.BodyMarkdown, BodyHtml: comment.BodyHTML,
		Author: contract.OperatorCommentFrozenAuthor{
			MembershipId: comment.Author.MembershipID, DisplayName: comment.Author.DisplayName, Audience: audience,
		},
		Origin: origin, Attachments: attachments, Mentions: mentions, Revision: comment.Revision,
		CreatedAt: comment.CreatedAt.UTC(), UpdatedAt: comment.UpdatedAt.UTC(),
		EditableUntil: comment.EditableUntil.UTC(), CanEdit: comment.CanEdit,
		Projection: contract.OperatorCommentProjectionOperator,
	}, nil
}

func mapCustomerComment(
	comment applicationticketing.Comment,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	resourceID uuid.UUID,
) (contract.CustomerComment, error) {
	mappedKind := contract.TicketResourceKind(comment.ResourceKind.String())
	origin := contract.CommentOrigin(comment.Origin)
	audience := contract.CommentAuthorAudience(comment.Author.Audience)
	if !applicationticketing.IsValidCommentProjection(comment, applicationticketing.ProjectionCustomer) ||
		comment.TenantID != tenantID || comment.ResourceKind != kind || comment.ResourceID != resourceID ||
		!mappedKind.Valid() || !origin.Valid() || !audience.Valid() || comment.Visibility != kernel.CommentPublic ||
		len(comment.Mentions) != 0 {
		return contract.CustomerComment{}, errors.New("invalid customer comment projection")
	}
	attachments, err := mapCustomerCommentAttachments(comment.Attachments)
	if err != nil {
		return contract.CustomerComment{}, err
	}
	return contract.CustomerComment{
		Id: comment.ID, TenantId: comment.TenantID, ResourceId: comment.ResourceID, ResourceKind: mappedKind,
		Visibility: contract.CustomerCommentVisibilityPublic, BodyMarkdown: comment.BodyMarkdown,
		BodyHtml: comment.BodyHTML, Author: contract.CustomerCommentFrozenAuthor{
			DisplayName: comment.Author.DisplayName, Audience: audience,
		}, Origin: origin, Attachments: attachments, Revision: comment.Revision,
		CreatedAt: comment.CreatedAt.UTC(), UpdatedAt: comment.UpdatedAt.UTC(),
		EditableUntil: comment.EditableUntil.UTC(), CanEdit: comment.CanEdit,
		Projection: contract.CustomerCommentProjectionCustomer,
	}, nil
}

func mapOperatorCommentAttachments(values []applicationticketing.CommentAttachment) ([]contract.OperatorCommentAttachment, error) {
	items := make([]contract.OperatorCommentAttachment, len(values))
	for index, value := range values {
		visibility := contract.CommentVisibility(value.Visibility.String())
		if !visibility.Valid() {
			return nil, errors.New("invalid operator comment attachment visibility")
		}
		items[index] = contract.OperatorCommentAttachment{
			Id: value.ID, OriginalFilename: value.OriginalFilename, Visibility: visibility,
			Projection: contract.OperatorCommentAttachmentProjectionOperator,
		}
	}
	return items, nil
}

func mapCustomerCommentAttachments(values []applicationticketing.CommentAttachment) ([]contract.CustomerCommentAttachment, error) {
	items := make([]contract.CustomerCommentAttachment, len(values))
	for index, value := range values {
		if value.Visibility != kernel.CommentPublic {
			return nil, errors.New("private attachment in customer comment projection")
		}
		items[index] = contract.CustomerCommentAttachment{
			Id: value.ID, OriginalFilename: value.OriginalFilename,
			Projection: contract.CustomerCommentAttachmentProjectionCustomer,
		}
	}
	return items, nil
}

func mapOperatorCommentPage(
	page applicationticketing.CommentPage,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	resourceID uuid.UUID,
) (contract.OperatorCommentList, error) {
	if page.Projection != applicationticketing.ProjectionOperator ||
		!applicationticketing.IsValidCommentPageProjection(page) {
		return contract.OperatorCommentList{}, errors.New("invalid operator comment page projection")
	}
	items := make([]contract.OperatorComment, len(page.Items))
	for index, comment := range page.Items {
		mapped, err := mapOperatorComment(comment, tenantID, kind, resourceID)
		if err != nil {
			return contract.OperatorCommentList{}, err
		}
		items[index] = mapped
	}
	return contract.OperatorCommentList{Items: items, NextCursor: page.NextCursor}, nil
}

func mapCustomerCommentPage(
	page applicationticketing.CommentPage,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	resourceID uuid.UUID,
) (contract.CustomerCommentList, error) {
	if page.Projection != applicationticketing.ProjectionCustomer ||
		!applicationticketing.IsValidCommentPageProjection(page) {
		return contract.CustomerCommentList{}, errors.New("invalid customer comment page projection")
	}
	items := make([]contract.CustomerComment, len(page.Items))
	for index, comment := range page.Items {
		mapped, err := mapCustomerComment(comment, tenantID, kind, resourceID)
		if err != nil {
			return contract.CustomerCommentList{}, err
		}
		items[index] = mapped
	}
	return contract.CustomerCommentList{Items: items, NextCursor: page.NextCursor}, nil
}

func mapOperatorCommentPreview(value applicationticketing.CommentPreview) (contract.OperatorCommentPreview, error) {
	visibility := contract.CommentVisibility(value.Visibility.String())
	if !applicationticketing.IsValidCommentPreviewProjection(value) || !visibility.Valid() {
		return contract.OperatorCommentPreview{}, errors.New("invalid operator comment preview visibility")
	}
	attachments, err := mapOperatorCommentAttachments(value.Attachments)
	if err != nil {
		return contract.OperatorCommentPreview{}, err
	}
	mentions := make([]contract.OperatorCommentMention, len(value.Mentions))
	for index, mention := range value.Mentions {
		mentions[index] = contract.OperatorCommentMention{
			MembershipId: mention.MembershipID, DisplayName: mention.DisplayName,
			Audience: contract.OperatorCommentMentionAudienceOperator,
		}
	}
	return contract.OperatorCommentPreview{
		Visibility: visibility, BodyMarkdown: value.BodyMarkdown,
		BodyHtml: value.BodyHTML, Attachments: attachments, Mentions: mentions,
	}, nil
}

func mapCustomerCommentPreview(value applicationticketing.CommentPreview) (contract.CustomerCommentPreview, error) {
	attachments, err := mapCustomerCommentAttachments(value.Attachments)
	if err != nil || !applicationticketing.IsValidCommentPreviewProjection(value) ||
		value.Visibility != kernel.CommentPublic || len(value.Mentions) != 0 {
		return contract.CustomerCommentPreview{}, errors.New("invalid customer comment preview")
	}
	return contract.CustomerCommentPreview{
		Visibility: contract.CustomerCommentPreviewVisibilityPublic, BodyMarkdown: value.BodyMarkdown,
		BodyHtml: value.BodyHTML, Attachments: attachments,
	}, nil
}

func mapCommentMentionCandidates(value applicationticketing.CommentMentionCandidateList) (contract.CommentMentionCandidateList, error) {
	if !applicationticketing.IsValidCommentMentionCandidateList(value) {
		return contract.CommentMentionCandidateList{}, errors.New("invalid comment mention candidates")
	}
	items := make([]contract.CommentMentionCandidate, len(value.Items))
	for index, item := range value.Items {
		items[index] = contract.CommentMentionCandidate{
			MembershipId: item.MembershipID, DisplayName: item.DisplayName,
			Audience: contract.CommentMentionCandidateAudienceOperator,
		}
	}
	return contract.CommentMentionCandidateList{Items: items}, nil
}

func mapOperatorCommentRevisionPage(value applicationticketing.CommentRevisionPage) (contract.OperatorCommentRevisionList, error) {
	if value.Projection != applicationticketing.ProjectionOperator ||
		!applicationticketing.IsValidCommentRevisionPageProjection(value) {
		return contract.OperatorCommentRevisionList{}, errors.New("invalid operator revision projection")
	}
	items := make([]contract.OperatorCommentRevision, len(value.Items))
	for index, revision := range value.Items {
		attachments, err := mapOperatorCommentAttachments(revision.Attachments)
		if err != nil {
			return contract.OperatorCommentRevisionList{}, err
		}
		mentions := make([]contract.OperatorCommentMention, len(revision.Mentions))
		for mentionIndex, mention := range revision.Mentions {
			mentions[mentionIndex] = contract.OperatorCommentMention{
				MembershipId: mention.MembershipID, DisplayName: mention.DisplayName,
				Audience: contract.OperatorCommentMentionAudienceOperator,
			}
		}
		items[index] = contract.OperatorCommentRevision{
			Revision: revision.Revision, BodyMarkdown: revision.BodyMarkdown, BodyHtml: revision.BodyHTML,
			Reason: revision.Reason, EditedAt: revision.EditedAt.UTC(), Attachments: attachments,
			Mentions: mentions, Projection: contract.OperatorCommentRevisionProjectionOperator,
		}
	}
	return contract.OperatorCommentRevisionList{Items: items, NextAfterRevision: value.NextAfterRevision}, nil
}

func mapCustomerCommentRevisionPage(value applicationticketing.CommentRevisionPage) (contract.CustomerCommentRevisionList, error) {
	if value.Projection != applicationticketing.ProjectionCustomer ||
		!applicationticketing.IsValidCommentRevisionPageProjection(value) {
		return contract.CustomerCommentRevisionList{}, errors.New("invalid customer revision projection")
	}
	items := make([]contract.CustomerCommentRevision, len(value.Items))
	for index, revision := range value.Items {
		attachments, err := mapCustomerCommentAttachments(revision.Attachments)
		if err != nil || revision.Reason != "" || len(revision.Mentions) != 0 {
			return contract.CustomerCommentRevisionList{}, errors.New("unsafe customer comment revision")
		}
		items[index] = contract.CustomerCommentRevision{
			Revision: revision.Revision, BodyMarkdown: revision.BodyMarkdown, BodyHtml: revision.BodyHTML,
			EditedAt: revision.EditedAt.UTC(), Attachments: attachments,
			Projection: contract.CustomerCommentRevisionProjectionCustomer,
		}
	}
	return contract.CustomerCommentRevisionList{Items: items, NextAfterRevision: value.NextAfterRevision}, nil
}

func mapActivityPage(page applicationticketing.ActivityPage) map[string]any {
	items := make([]any, 0, len(page.Items))
	for _, activity := range page.Items {
		mapped := map[string]any{
			"id": activity.ID, "tenantId": activity.TenantID, "resourceId": activity.ResourceID,
			"resourceKind": activity.ResourceKind.String(), "kind": activity.Kind,
			"summary": activity.Summary, "occurredAt": activity.OccurredAt,
			"projection": viewProjection(page.Projection),
		}
		if page.Projection == applicationticketing.ProjectionCustomer {
			mapped["actor"] = map[string]any{"displayName": activity.DisplayName, "origin": activity.Origin}
		} else {
			mapped["actor"] = operatorActivityActor(activity)
			if activity.Details != nil {
				mapped["details"] = maps.Clone(activity.Details)
			}
		}
		items = append(items, mapped)
	}
	result := map[string]any{"items": items}
	if page.NextCursor != nil {
		result["nextCursor"] = *page.NextCursor
	}
	return result
}

func operatorActivityActor(activity applicationticketing.Activity) map[string]any {
	base := map[string]any{"displayName": activity.DisplayName, "origin": activity.Origin}
	switch activity.ActorKind {
	case applicationticketing.ActivityActorHuman:
		base["membershipId"] = activity.ActorID
	case applicationticketing.ActivityActorServiceAccount:
		base["principalType"] = "service_account"
		base["serviceAccountId"] = activity.ActorID
	case applicationticketing.ActivityActorSystem:
		base["principalType"] = "system"
	}
	return base
}

func mapLinkPage(page applicationticketing.LinkPage) map[string]any {
	items := make([]any, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, mapLink(item.Link, item.Projection))
	}
	result := map[string]any{"items": items}
	if page.NextCursor != nil {
		result["nextCursor"] = *page.NextCursor
	}
	return result
}

func mapLink(link applicationticketing.Link, projection applicationticketing.Projection) map[string]any {
	result := map[string]any{
		"id": link.ID, "tenantId": link.TenantID, "alertId": link.AlertID, "caseId": link.CaseID,
		"relationType": link.Relation, "linkedAt": link.LinkedAt, "projection": viewProjection(projection),
	}
	if projection == applicationticketing.ProjectionOperator {
		result["linkedBy"] = link.LinkedBy
		result["escalationReason"] = link.Reason
		result["sourceAlertVersion"] = link.SourceAlertVersion
		result["copySelection"] = map[string]any{
			"fields": nonNilStrings(link.CopyFields), "customFieldKeys": nonNilStrings(link.CustomFieldKeys),
			"publicCommentIds": nonNilUUIDs(link.PublicCommentIDs),
		}
		for key, values := range link.ItemIDs {
			result["copySelection"].(map[string]any)[key] = nonNilUUIDs(values)
		}
		result["copiedFieldSnapshot"] = nonNilMap(link.CopiedFieldSnapshot)
	}
	return result
}

func assignmentProjection(record applicationticketing.Record) map[string]any {
	result := map[string]any{
		"assignedTeamId": nil, "assigneeUserId": nil, "claimedBy": nil, "claimedAt": nil,
	}
	assignment := record.Snapshot.Assignment()
	if team, present := assignment.Team(); present {
		result["assignedTeamId"] = uuid.UUID(team.Bytes())
	}
	if assignee, present := assignment.Assignee(); present {
		result["assigneeUserId"] = uuid.UUID(assignee.Bytes())
	}
	if claimant, present := assignment.Claimant(); present {
		result["claimedBy"] = uuid.UUID(claimant.Bytes())
	}
	if record.ClaimedAt != nil {
		result["claimedAt"] = *record.ClaimedAt
	}
	return result
}

func creatorProjection(record applicationticketing.Record) map[string]any {
	if record.Creator.Kind == kernel.PrincipalServiceAccount {
		return map[string]any{"principalType": "service_account", "serviceAccountId": record.Creator.ID}
	}
	return map[string]any{"principalType": "human", "membershipId": record.Creator.ID}
}

func ticketState(workflow kernel.WorkflowDefinition, key kernel.Key) (kernel.StateDefinition, bool) {
	states := workflow.States()
	index, found := slices.BinarySearchFunc(states, key, func(candidate kernel.StateDefinition, target kernel.Key) int {
		if candidate.Key().String() < target.String() {
			return -1
		}
		if candidate.Key().String() > target.String() {
			return 1
		}
		return 0
	})
	if !found {
		return kernel.StateDefinition{}, false
	}
	return states[index], true
}

func viewProjection(value applicationticketing.Projection) string {
	if value == applicationticketing.ProjectionCustomer {
		return "customer"
	}
	return "operator"
}

func visibilityValue(customerVisible bool) string {
	if customerVisible {
		return "customer"
	}
	return "internal"
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return slices.Clone(values)
}

func nonNilUUIDs(values []uuid.UUID) []uuid.UUID {
	if values == nil {
		return []uuid.UUID{}
	}
	return slices.Clone(values)
}

func nonNilMap(values map[string]any) map[string]any {
	if values == nil {
		return map[string]any{}
	}
	return maps.Clone(values)
}

func putTime(target map[string]any, name string, value *time.Time) {
	if value != nil {
		target[name] = *value
	}
}
