package notificationinbox

import (
	"bytes"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

func normalizeListInput(input ListInput) (ListInput, error) {
	if input.Limit < 0 || input.Limit > MaximumPageLimit {
		return ListInput{}, ErrInvalidInput
	}
	if input.After != nil {
		if !validUUIDv7(*input.After) {
			return ListInput{}, ErrInvalidInput
		}
		cursor := *input.After
		input.After = &cursor
	}
	if input.Limit == 0 {
		input.Limit = DefaultPageLimit
	}
	return input, nil
}

func validActorCoordinate(actor Actor, tenantID uuid.UUID) bool {
	return validUUIDv7(tenantID) && actor.ActiveTenantID == tenantID &&
		validUUIDv7(actor.UserID) && validUUIDv7(actor.SessionID)
}

func validAudit(value AuditMetadata) bool {
	return validUUIDv7(value.RequestID) && validUUIDv7(value.CorrelationID) &&
		value.RemoteAddress.IsValid() && value.RemoteAddress.Zone() == "" &&
		validBoundedText(value.UserAgent, 512, false)
}

func validAccessEvidence(actor Actor, tenantID uuid.UUID, value AccessEvidence, now time.Time) bool {
	return value.TenantID == tenantID && value.UserID == actor.UserID && value.SessionID == actor.SessionID &&
		value.Authenticated && value.Active && validPrincipal(value.Principal) &&
		validInstant(value.EvaluatedAt) && !value.EvaluatedAt.Before(now.Add(-MaximumAccessAge)) &&
		!value.EvaluatedAt.After(now.Add(maximumClockSkew))
}

func validPrincipal(value Principal) bool {
	return value == PrincipalOperator || value == PrincipalCustomer
}

func audienceFor(value Principal) (Audience, bool) {
	switch value {
	case PrincipalOperator:
		return AudienceOperator, true
	case PrincipalCustomer:
		return AudienceCustomer, true
	default:
		return "", false
	}
}

func validItem(value Item, tenantID, userID uuid.UUID, audience Audience, now time.Time) bool {
	if !validUUIDv7(value.ID) || value.TenantID != tenantID || value.UserID != userID || value.Audience != audience ||
		!validEventResource(value.EventType, value.ResourceKind) || !eventSupportsAudience(value.EventType, value.Audience) ||
		!validUUIDv7(value.ResourceID) || !validPositiveRevision(value.ResourceVersion) ||
		!validBoundedText(value.Title, maximumTitleBytes, false) ||
		!validBoundedText(value.Summary, maximumSummaryBytes, true) ||
		!validPositiveRevision(value.Revision) || !validInstant(value.OccurredAt) ||
		value.OccurredAt.After(now.Add(maximumClockSkew)) {
		return false
	}
	if value.ReadAt == nil {
		return true
	}
	return validInstant(*value.ReadAt) && !value.ReadAt.Before(value.OccurredAt) &&
		!value.ReadAt.After(now.Add(maximumClockSkew))
}

func eventSupportsAudience(event EventType, audience Audience) bool {
	if audience != AudienceOperator && audience != AudienceCustomer {
		return false
	}
	switch event {
	case EventAlertWatcherAdded, EventAlertWatcherRemoved,
		EventCaseWatcherAdded, EventCaseWatcherRemoved, EventCommentPrivateAdded:
		return audience == AudienceOperator
	default:
		return true
	}
}

func validEventResource(event EventType, resource ResourceKind) bool {
	if !validResourceKind(resource) {
		return false
	}
	switch event {
	case EventAlertCreated, EventAlertAssigned, EventAlertClaimed, EventAlertStatusChanged,
		EventAlertEscalated, EventAlertWatcherAdded, EventAlertWatcherRemoved:
		return resource == ResourceAlert
	case EventCaseCreated, EventCaseAssigned, EventCaseClaimed, EventCaseTransferred,
		EventCaseStatusChanged, EventCaseWatcherAdded, EventCaseWatcherRemoved:
		return resource == ResourceCase
	case EventCommentPublicAdded, EventCommentPrivateAdded, EventSLAWarning, EventSLABreached:
		return resource == ResourceAlert || resource == ResourceCase
	case EventContactChanged:
		return resource == ResourceContact
	case EventTaskAssigned:
		return resource == ResourceTask
	case EventEvidenceAdded:
		return resource == ResourceEvidence
	case EventWebhookCustom:
		return true
	default:
		return false
	}
}

func validResourceKind(value ResourceKind) bool {
	switch value {
	case ResourceAlert, ResourceCase, ResourceTask, ResourceEvidence, ResourceContact:
		return true
	default:
		return false
	}
}

func validPositiveRevision(value uint64) bool {
	return value > 0 && value <= MaximumRevision
}

func validCASRevision(value uint64, allowZero bool) bool {
	return value < MaximumRevision && (allowZero || value > 0)
}

func validInboxRevision(value uint64, requirePositive bool) bool {
	return value <= MaximumRevision && (!requirePositive || value > 0)
}

func validUnreadState(value UnreadState, tenantID, userID uuid.UUID) bool {
	return value.TenantID == tenantID && value.UserID == userID && value.Count <= MaximumUnreadCount &&
		validInboxRevision(value.InboxRevision, value.Count > 0)
}

func validListSnapshot(value ListSnapshot, params ListParams, now time.Time) bool {
	audience, ok := audienceFor(params.Access.Principal)
	if !ok || value.TenantID != params.TenantID || value.UserID != params.UserID ||
		len(value.Items) > params.FetchLimit || !validInboxRevision(value.InboxRevision, len(value.Items) > 0) {
		return false
	}
	seen := make(map[uuid.UUID]struct{}, len(value.Items))
	for index, item := range value.Items {
		if !validItem(item, params.TenantID, params.UserID, audience, now) ||
			params.UnreadOnly && item.ReadAt != nil {
			return false
		}
		if params.After != nil && compareUUID(item.ID, *params.After) >= 0 {
			return false
		}
		if _, duplicate := seen[item.ID]; duplicate {
			return false
		}
		seen[item.ID] = struct{}{}
		if index > 0 && compareUUID(value.Items[index-1].ID, item.ID) <= 0 {
			return false
		}
	}
	return true
}

func validReadStateResult(value ReadStateResult, params SetReadStateParams, now time.Time) bool {
	audience, ok := audienceFor(params.Access.Principal)
	if !ok || value.Item.ID != params.ItemID ||
		!validItem(value.Item, params.TenantID, params.UserID, audience, now) ||
		(value.Item.ReadAt != nil) != params.Read || !validInboxRevision(value.InboxRevision, true) {
		return false
	}
	wantRevision := params.ExpectedRevision
	if value.Changed {
		wantRevision++
	}
	return value.Item.Revision == wantRevision
}

func validMarkAllReadResult(value MarkAllReadResult, params MarkAllReadParams) bool {
	if value.TenantID != params.TenantID || value.UserID != params.UserID ||
		value.Affected > MaximumUnreadCount || value.Changed != (value.Affected > 0) {
		return false
	}
	wantRevision := params.ExpectedRevision
	if value.Changed {
		wantRevision++
	}
	return value.InboxRevision == wantRevision && validInboxRevision(value.InboxRevision, value.Changed)
}

func cloneItems(values []Item) []Item {
	cloned := make([]Item, len(values))
	for index, value := range values {
		cloned[index] = cloneItem(value)
	}
	return cloned
}

func cloneItem(value Item) Item {
	if value.ReadAt != nil {
		readAt := *value.ReadAt
		value.ReadAt = &readAt
	}
	return value
}

func compareUUID(left, right uuid.UUID) int { return bytes.Compare(left[:], right[:]) }

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validStableKey(value string, maximum int) bool {
	if value == "" || len(value) > maximum || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '_' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func validIdempotencyKey(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._~-", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func validBoundedText(value string, maximum int, optional bool) bool {
	if value == "" {
		return optional
	}
	if len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%1_000 == 0
}
