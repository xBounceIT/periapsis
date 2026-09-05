package ticketing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

type Service struct {
	repository Repository
	clock      func() time.Time
}

const maxResourceVersion = uint64(2_147_483_647)

func NewService(repository Repository, clock func() time.Time) (*Service, error) {
	if repository == nil {
		return nil, errors.New("ticketing repository is required")
	}
	if clock == nil {
		clock = time.Now
	}
	return &Service{repository: repository, clock: clock}, nil
}

func (service *Service) List(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	input ListInput,
) (Page, error) {
	return service.listWithCapability(ctx, actor, tenantID, kind, input, readCapability(kind))
}

// ListPortal applies the explicit portal permission and exact customer-contact
// relationship. Customer link filtering is performed by the repository before
// limits and cursors, not as an in-memory post-filter.
func (service *Service) ListPortal(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	input ListInput,
) (Page, error) {
	return service.listWithCapability(ctx, actor, tenantID, kind, input, portalReadCapability(kind))
}

func (service *Service) listWithCapability(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	input ListInput,
	capability Capability,
) (Page, error) {
	access, err := service.access(ctx, actor, tenantID, capability)
	if err != nil {
		return Page{}, err
	}
	input, err = validateListInput(input)
	if err != nil {
		return Page{}, err
	}
	page, err := service.repository.List(ctx, tenantID, kind, input, access)
	if err != nil {
		return Page{}, repositoryError(err)
	}
	if len(page.Items) > input.Limit || !validOpaqueCursor(page.NextCursor) {
		return Page{}, ErrUnavailable
	}
	projection, err := projectionFor(access)
	if err != nil {
		return Page{}, err
	}
	var applied *SavedViewRecord
	if input.SavedViewID != nil {
		if projection != ProjectionOperator || page.AppliedView == nil {
			return Page{}, ErrUnavailable
		}
		owner := access.MembershipID
		normalized, valid := normalizeSavedViewRecord(*page.AppliedView, tenantID, owner, kind)
		if !valid || normalized.View.Status() != kernel.SavedViewActive ||
			uuidFromEntity(normalized.View.ID()) != *input.SavedViewID {
			return Page{}, ErrUnavailable
		}
		applied = &normalized
	} else if page.AppliedView != nil {
		return Page{}, ErrUnavailable
	}
	views := make([]View, 0, len(page.Items))
	seen := make(map[uuid.UUID]struct{}, len(page.Items))
	for _, record := range page.Items {
		if err := validateRecord(record, tenantID, kind); err != nil || !canAccess(record, access) {
			return Page{}, ErrUnavailable
		}
		if applied == nil && len(record.DynamicColumns) != 0 ||
			applied != nil && !validSavedViewDynamicProjection(record.DynamicColumns, applied.View.Spec()) {
			return Page{}, ErrUnavailable
		}
		id := uuidFromEntity(record.Snapshot.ID())
		if _, duplicate := seen[id]; duplicate {
			return Page{}, ErrUnavailable
		}
		seen[id] = struct{}{}
		if projection == ProjectionCustomer && !kernel.CanProjectTicket(record.Workflow, record.Snapshot, kernel.ProjectionCustomerAPI) {
			return Page{}, ErrUnavailable
		}
		views = append(views, View{Record: record, Projection: projection})
	}
	return Page{Items: views, NextCursor: page.NextCursor, AppliedView: applied}, nil
}

func validSavedViewDynamicProjection(values map[string]DynamicColumnValue, spec kernel.SavedViewSpec) bool {
	allowed := make(map[string]kernel.SavedViewDefinitionPin)
	for _, column := range spec.Columns() {
		definition, dynamic := column.Definition()
		if !dynamic {
			continue
		}
		key := column.Source().String() + ":" + uuidFromEntity(definition.ID()).String()
		allowed[key] = definition
	}
	for key, value := range values {
		definition, exists := allowed[key]
		if !exists || value.DefinitionID != uuidFromEntity(definition.ID()) ||
			value.DefinitionVersion != definition.Version() ||
			string(value.Source) != definitionSourceForKey(key) ||
			len(value.Value) == 0 || len(value.Value) > 64*1024 || !json.Valid(value.Value) ||
			!validDynamicScalar(value.Value) || !validText(value.StyleKey, 64, false) ||
			value.Source == SavedViewDefinitionCustomField && (value.MaterializedAt != nil || value.StyleKey != "") ||
			value.Source == SavedViewDefinitionSLA && (value.MaterializedAt == nil || !validStoredInstant(*value.MaterializedAt)) {
			return false
		}
	}
	return true
}

func definitionSourceForKey(key string) string {
	if strings.HasPrefix(key, string(SavedViewDefinitionCustomField)+":") {
		return string(SavedViewDefinitionCustomField)
	}
	if strings.HasPrefix(key, string(SavedViewDefinitionSLA)+":") {
		return string(SavedViewDefinitionSLA)
	}
	return ""
}

func validDynamicScalar(raw json.RawMessage) bool {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return false
	}
	switch value.(type) {
	case string, json.Number, bool:
		return true
	default:
		return false
	}
}

func (service *Service) Get(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
) (View, error) {
	return service.getWithCapability(ctx, actor, tenantID, kind, id, readCapability(kind))
}

// GetPortal requires both the dedicated portal permission and a current exact
// contact link to the requested customer-visible ticket.
func (service *Service) GetPortal(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
) (View, error) {
	return service.getWithCapability(ctx, actor, tenantID, kind, id, portalReadCapability(kind))
}

func (service *Service) getWithCapability(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
	capability Capability,
) (View, error) {
	access, err := service.access(ctx, actor, tenantID, capability)
	if err != nil {
		return View{}, err
	}
	return service.getAuthorized(ctx, tenantID, kind, id, access)
}

func (service *Service) Activities(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
	pageInput CursorPageInput,
) (ActivityPage, error) {
	return service.activitiesWithCapability(ctx, actor, tenantID, kind, id, pageInput, activityCapability(kind))
}

func (service *Service) ActivitiesPortal(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
	pageInput CursorPageInput,
) (ActivityPage, error) {
	return service.activitiesWithCapability(ctx, actor, tenantID, kind, id, pageInput, portalReadCapability(kind))
}

// ActivityFeed returns one tenant-wide, resource-kind-specific operator feed.
// Requiring a resource kind keeps the authorization decision tied to one exact
// compound capability and gives the UUIDv7 cursor a stable database ordering.
func (service *Service) ActivityFeed(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	pageInput CursorPageInput,
) (ActivityPage, error) {
	access, err := service.access(ctx, actor, tenantID, activityFeedCapability(kind))
	if err != nil {
		return ActivityPage{}, err
	}
	if access.Authority.Principal() != kernel.PrincipalOperator {
		return ActivityPage{}, ErrForbidden
	}
	pageInput, err = validateCursorPage(pageInput)
	if err != nil {
		return ActivityPage{}, err
	}
	page, err := service.repository.ListActivityFeed(ctx, tenantID, kind, pageInput, access)
	if err != nil {
		return ActivityPage{}, repositoryError(err)
	}
	if len(page.Items) > pageInput.Limit || !validOptionalCursor(page.NextCursor) {
		return ActivityPage{}, ErrUnavailable
	}
	seen := make(map[uuid.UUID]struct{}, len(page.Items))
	var previousID uuid.UUID
	for index, activity := range page.Items {
		if !validOperatorActivity(activity, tenantID, kind) {
			return ActivityPage{}, ErrUnavailable
		}
		if _, duplicate := seen[activity.ID]; duplicate {
			return ActivityPage{}, ErrUnavailable
		}
		if index > 0 && bytes.Compare(previousID[:], activity.ID[:]) <= 0 {
			return ActivityPage{}, ErrUnavailable
		}
		seen[activity.ID] = struct{}{}
		previousID = activity.ID
	}
	if page.NextCursor != nil &&
		(len(page.Items) == 0 || *page.NextCursor != page.Items[len(page.Items)-1].ID) {
		return ActivityPage{}, ErrUnavailable
	}
	return ActivityPage{
		Items: page.Items, Projection: ProjectionOperator, NextCursor: page.NextCursor,
	}, nil
}

func (service *Service) activitiesWithCapability(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
	pageInput CursorPageInput,
	capability Capability,
) (ActivityPage, error) {
	access, err := service.access(ctx, actor, tenantID, capability)
	if err != nil {
		return ActivityPage{}, err
	}
	view, err := service.getAuthorized(ctx, tenantID, kind, id, access)
	if err != nil {
		return ActivityPage{}, err
	}
	pageInput, err = validateCursorPage(pageInput)
	if err != nil {
		return ActivityPage{}, err
	}
	page, err := service.repository.ListActivities(ctx, view.Record, pageInput, access)
	if err != nil {
		return ActivityPage{}, repositoryError(err)
	}
	if len(page.Items) > pageInput.Limit || !validOptionalCursor(page.NextCursor) {
		return ActivityPage{}, ErrUnavailable
	}
	for _, activity := range page.Items {
		if !validActivity(activity, view, tenantID, kind) {
			return ActivityPage{}, ErrUnavailable
		}
	}
	return ActivityPage{Items: page.Items, Projection: view.Projection, NextCursor: page.NextCursor}, nil
}

func (service *Service) Links(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
	pageInput CursorPageInput,
) (LinkPage, error) {
	sourceAccess, err := service.access(ctx, actor, tenantID, linkCapability(kind))
	if err != nil {
		return LinkPage{}, err
	}
	otherKind := kernel.AggregateCase
	if kind == kernel.AggregateCase {
		otherKind = kernel.AggregateAlert
	}
	otherAccess, err := service.access(ctx, actor, tenantID, readCapability(otherKind))
	if err != nil {
		return LinkPage{}, err
	}
	if !sameAuthority(sourceAccess.Authority, otherAccess.Authority) {
		return LinkPage{}, ErrUnavailable
	}
	source, err := service.getAuthorized(ctx, tenantID, kind, id, sourceAccess)
	if err != nil {
		return LinkPage{}, err
	}
	pageInput, err = validateCursorPage(pageInput)
	if err != nil {
		return LinkPage{}, err
	}
	page, err := service.repository.ListLinks(ctx, source.Record, pageInput, sourceAccess, otherAccess)
	if err != nil {
		return LinkPage{}, repositoryError(err)
	}
	if len(page.Items) > pageInput.Limit || !validOptionalCursor(page.NextCursor) {
		return LinkPage{}, ErrUnavailable
	}
	items := make([]LinkView, 0, len(page.Items))
	for _, item := range page.Items {
		if !validLink(item.Link, tenantID) || validateRecord(item.Other, tenantID, otherKind) != nil ||
			!canAccess(item.Other, otherAccess) || !linkMatches(item.Link, source.Record, item.Other) {
			return LinkPage{}, ErrUnavailable
		}
		projection, projectionErr := projectionFor(sourceAccess)
		if projectionErr != nil {
			return LinkPage{}, projectionErr
		}
		if projection == ProjectionCustomer &&
			(!kernel.CanProjectTicket(source.Record.Workflow, source.Record.Snapshot, kernel.ProjectionCustomerAPI) ||
				!kernel.CanProjectTicket(item.Other.Workflow, item.Other.Snapshot, kernel.ProjectionCustomerAPI)) {
			return LinkPage{}, ErrUnavailable
		}
		items = append(items, LinkView{Link: item.Link, Other: item.Other, Projection: projection})
	}
	return LinkPage{Items: items, NextCursor: page.NextCursor}, nil
}

func sameAuthority(left, right kernel.AuthorizationSnapshot) bool {
	return left.Tenant() == right.Tenant() && left.Actor() == right.Actor() &&
		left.Principal() == right.Principal() && left.TenantAccess() == right.TenantAccess() &&
		slices.Equal(left.Roles(), right.Roles()) && slices.Equal(left.Permissions(), right.Permissions()) &&
		slices.Equal(left.ClaimableTeams(), right.ClaimableTeams()) &&
		slices.Equal(left.ManageableTeams(), right.ManageableTeams()) &&
		slices.Equal(left.AssignableRoster(), right.AssignableRoster())
}

func (service *Service) access(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	capability Capability,
) (LiveAccess, error) {
	if !validActor(actor, tenantID) || !validCapability(capability) {
		return LiveAccess{}, ErrForbidden
	}
	access, err := service.repository.ResolveAccess(ctx, actor, tenantID, capability)
	if err != nil {
		return LiveAccess{}, repositoryError(err)
	}
	tenant, tenantErr := entityID(tenantID)
	actorID, actorErr := entityID(actor.UserID)
	if tenantErr != nil || actorErr != nil || access.Authority.Tenant() != tenant ||
		access.Authority.Actor() != actorID || !access.Authority.TenantAccess() ||
		access.Authority.Principal() == kernel.PrincipalServiceAccount {
		return LiveAccess{}, ErrForbidden
	}
	if _, err := kernel.NewAuthorizationSnapshot(
		access.Authority.Tenant(), access.Authority.Actor(), access.Authority.Principal(),
		access.Authority.TenantAccess(), access.Authority.Roles(), access.Authority.Permissions(),
		access.Authority.ClaimableTeams(), access.Authority.ManageableTeams(), access.Authority.AssignableRoster(),
	); err != nil {
		return LiveAccess{}, ErrUnavailable
	}
	scopes := slices.Clone(access.Scopes)
	slices.Sort(scopes)
	if len(scopes) == 0 || len(scopes) > 4 {
		return LiveAccess{}, ErrForbidden
	}
	for index, scope := range scopes {
		if !validEnum(string(scope), string(ScopeOwn), string(ScopeAssigned), string(ScopeOperatorTeam), string(ScopeTenant)) ||
			index > 0 && scopes[index-1] == scope {
			return LiveAccess{}, ErrUnavailable
		}
	}
	teams := slices.Clone(access.OperatorTeams)
	slices.SortFunc(teams, func(left, right kernel.EntityID) int { return strings.Compare(left.String(), right.String()) })
	rosterTeams := make(map[kernel.EntityID]struct{})
	for _, pair := range access.Authority.AssignableRoster() {
		if pair.User() == access.Authority.Actor() {
			rosterTeams[pair.Team()] = struct{}{}
		}
	}
	for index, team := range teams {
		_, liveRoster := rosterTeams[team]
		if _, err := entityID(uuidFromEntity(team)); err != nil || !liveRoster || index > 0 && teams[index-1] == team {
			return LiveAccess{}, ErrUnavailable
		}
	}
	if _, err := entityID(uuidFromEntity(access.MembershipID)); err != nil {
		return LiveAccess{}, ErrUnavailable
	}
	if access.Authority.Principal() == kernel.PrincipalCustomer {
		if access.CustomerContactID == nil {
			return LiveAccess{}, ErrForbidden
		}
		if _, err := entityID(uuidFromEntity(*access.CustomerContactID)); err != nil {
			return LiveAccess{}, ErrUnavailable
		}
		copy := *access.CustomerContactID
		access.CustomerContactID = &copy
	} else if access.CustomerContactID != nil {
		return LiveAccess{}, ErrUnavailable
	}
	access.Scopes = scopes
	access.OperatorTeams = teams
	return access, nil
}

func (service *Service) getAuthorized(
	ctx context.Context,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
	access LiveAccess,
) (View, error) {
	if _, err := entityID(id); err != nil {
		return View{}, ErrInvalidInput
	}
	record, err := service.repository.GetForAccess(ctx, tenantID, kind, id, access)
	if err != nil {
		return View{}, repositoryError(err)
	}
	if err := validateRecord(record, tenantID, kind); err != nil || !canAccess(record, access) {
		return View{}, ErrUnavailable
	}
	projection, err := projectionFor(access)
	if err != nil {
		return View{}, err
	}
	if projection == ProjectionCustomer && !kernel.CanProjectTicket(record.Workflow, record.Snapshot, kernel.ProjectionCustomerAPI) {
		return View{}, ErrNotFound
	}
	return View{Record: record, Projection: projection}, nil
}

func readCapability(kind kernel.AggregateKind) Capability {
	if kind == kernel.AggregateAlert {
		return CapabilityAlertRead
	}
	if kind == kernel.AggregateCase {
		return CapabilityCaseRead
	}
	return ""
}

func portalReadCapability(kind kernel.AggregateKind) Capability {
	if kind == kernel.AggregateAlert {
		return CapabilityPortalAlertRead
	}
	if kind == kernel.AggregateCase {
		return CapabilityPortalCaseRead
	}
	return ""
}

func portalExportCapability(kind kernel.AggregateKind) Capability {
	if kind == kernel.AggregateAlert {
		return CapabilityPortalAlertExport
	}
	if kind == kernel.AggregateCase {
		return CapabilityPortalCaseExport
	}
	return ""
}

func activityCapability(kind kernel.AggregateKind) Capability {
	if kind == kernel.AggregateAlert {
		return CapabilityAlertActivityRead
	}
	if kind == kernel.AggregateCase {
		return CapabilityCaseActivityRead
	}
	return ""
}

func activityFeedCapability(kind kernel.AggregateKind) Capability {
	if kind == kernel.AggregateAlert {
		return CapabilityAlertActivityFeed
	}
	if kind == kernel.AggregateCase {
		return CapabilityCaseActivityFeed
	}
	return ""
}

func commentReadCapability(kind kernel.AggregateKind) Capability {
	if kind == kernel.AggregateAlert {
		return CapabilityAlertCommentRead
	}
	if kind == kernel.AggregateCase {
		return CapabilityCaseCommentRead
	}
	return ""
}

func commentWriteCapability(kind kernel.AggregateKind, visibility kernel.CommentVisibility) Capability {
	if kind == kernel.AggregateAlert && visibility == kernel.CommentPublic {
		return CapabilityAlertCommentPublic
	}
	if kind == kernel.AggregateAlert && visibility == kernel.CommentPrivate {
		return CapabilityAlertCommentPrivate
	}
	if kind == kernel.AggregateCase && visibility == kernel.CommentPublic {
		return CapabilityCaseCommentPublic
	}
	if kind == kernel.AggregateCase && visibility == kernel.CommentPrivate {
		return CapabilityCaseCommentPrivate
	}
	return ""
}

func linkCapability(kind kernel.AggregateKind) Capability {
	if kind == kernel.AggregateAlert {
		return CapabilityAlertLinkRead
	}
	if kind == kernel.AggregateCase {
		return CapabilityCaseLinkRead
	}
	return ""
}

func projectionFor(access LiveAccess) (Projection, error) {
	switch access.Authority.Principal() {
	case kernel.PrincipalOperator:
		return ProjectionOperator, nil
	case kernel.PrincipalCustomer:
		return ProjectionCustomer, nil
	default:
		return 0, ErrForbidden
	}
}

func canAccess(record Record, access LiveAccess) bool {
	if access.Authority.Principal() == kernel.PrincipalCustomer {
		return access.CustomerContactID != nil
	}
	actor := access.Authority.Actor()
	assignment := record.Snapshot.Assignment()
	team, hasTeam := assignment.Team()
	assignee, hasAssignee := assignment.Assignee()
	claimant, hasClaimant := assignment.Claimant()
	for _, scope := range access.Scopes {
		switch scope {
		case ScopeTenant:
			return true
		case ScopeOwn:
			if record.Creator.UserID != nil && *record.Creator.UserID == uuidFromEntity(actor) {
				return true
			}
		case ScopeAssigned:
			if hasAssignee && assignee == actor || hasClaimant && claimant == actor {
				return true
			}
		case ScopeOperatorTeam:
			if hasTeam && slices.Contains(access.OperatorTeams, team) {
				return true
			}
		}
	}
	return false
}

func validateListInput(input ListInput) (ListInput, error) {
	if input.Limit == 0 {
		input.Limit = DefaultPageSize
	}
	if input.Limit < 1 || input.Limit > MaximumPageSize || !validOpaqueCursor(input.After) ||
		len(input.States) > 20 || len(input.Severities) > 5 || len(input.Priorities) > 5 ||
		(input.CustomFieldKey == nil) != (input.CustomFieldValue == nil) ||
		!validText(input.Search, 240, false) ||
		input.Queue != "" && !validEnum(input.Queue, "assigned_to_me", "my_operator_teams", "unassigned") ||
		input.Sort != "" && !validEnum(input.Sort, "updated_at_desc", "updated_at_asc", "created_at_desc", "created_at_asc", "priority_desc", "oldest_unclaimed") {
		return ListInput{}, ErrInvalidInput
	}
	if input.SavedViewID != nil {
		if _, err := entityID(*input.SavedViewID); err != nil || ticketListHasInlineSpecification(input) {
			return ListInput{}, ErrInvalidInput
		}
	}
	seenStates := make(map[kernel.Key]struct{}, len(input.States))
	for _, state := range input.States {
		if _, err := contractKey(state.String()); err != nil {
			return ListInput{}, ErrInvalidInput
		}
		if _, duplicate := seenStates[state]; duplicate {
			return ListInput{}, ErrInvalidInput
		}
		seenStates[state] = struct{}{}
	}
	if !validUniqueEnums(input.Severities, "informational", "low", "medium", "high", "critical") ||
		!validUniqueEnums(input.Priorities, "low", "medium", "high", "urgent", "critical") {
		return ListInput{}, ErrInvalidInput
	}
	for _, value := range []*uuid.UUID{input.AssignedTeamID, input.AssigneeUserID, input.ClaimedBy} {
		if value != nil {
			if _, err := entityID(*value); err != nil {
				return ListInput{}, ErrInvalidInput
			}
		}
	}
	if input.CustomFieldKey != nil {
		if _, err := customKey(input.CustomFieldKey.String()); err != nil ||
			input.CustomFieldValue == nil || !validText(*input.CustomFieldValue, 10_000, false) {
			return ListInput{}, ErrInvalidInput
		}
	}
	return input, nil
}

func ticketListHasInlineSpecification(input ListInput) bool {
	return len(input.States) != 0 || len(input.Severities) != 0 || len(input.Priorities) != 0 ||
		input.AssignedTeamID != nil || input.AssigneeUserID != nil || input.ClaimedBy != nil ||
		input.Queue != "" || input.CustomerVisible != nil || input.Search != "" ||
		input.CustomFieldKey != nil || input.CustomFieldValue != nil || input.Sort != ""
}

func validateCursorPage(input CursorPageInput) (CursorPageInput, error) {
	if input.Limit == 0 {
		input.Limit = DefaultPageSize
	}
	if input.Limit < 1 || input.Limit > MaximumPageSize {
		return CursorPageInput{}, ErrInvalidInput
	}
	if input.After != nil {
		if _, err := entityID(*input.After); err != nil {
			return CursorPageInput{}, ErrInvalidInput
		}
	}
	return input, nil
}

func validateRecord(record Record, tenantID uuid.UUID, kind kernel.AggregateKind) error {
	if record.Snapshot.Kind() != kind || record.Snapshot.Tenant() != mustEntityOrZero(tenantID) ||
		record.Workflow.Kind() != kind || !kernel.CanProjectTicket(record.Workflow, record.Snapshot, kernel.ProjectionOperator) ||
		!validText(record.Number, 64, true) || !validText(record.Title, 240, true) ||
		!validText(record.Description, descriptionLimit(kind), false) || !validText(record.Summary, 2_000, false) ||
		!validText(record.Category, 120, true) || !validOptionalText(record.Classification, 120) ||
		!validEnum(record.Severity, "informational", "low", "medium", "high", "critical") ||
		!validEnum(record.Priority, "low", "medium", "high", "urgent", "critical") ||
		!validCustomFields(record.CustomFields) || !validCustomFields(record.CustomerCustomFields) ||
		!validRawPayload(record.RawPayload) || !validTags(record.Tags) || record.Snapshot.Version() > maxResourceVersion ||
		!validStoredInstant(record.CreatedAt) || !validStoredInstant(record.UpdatedAt) || record.UpdatedAt.Before(record.CreatedAt) ||
		!validOptionalStoredInstant(record.AcknowledgedAt) || !validOptionalStoredInstant(record.ClosedAt) ||
		!validOptionalStoredInstant(record.AssignedAt) || !validOptionalStoredInstant(record.FirstResponseAt) ||
		!validOptionalStoredInstant(record.ResolvedAt) || !validOptionalStoredInstant(record.ClaimedAt) {
		return ErrUnavailable
	}
	for _, instant := range []*time.Time{
		record.AcknowledgedAt, record.ClosedAt, record.AssignedAt, record.FirstResponseAt, record.ResolvedAt, record.ClaimedAt,
	} {
		if instant != nil && (instant.Before(record.CreatedAt) || instant.After(record.UpdatedAt)) {
			return ErrUnavailable
		}
	}
	for key, value := range record.CustomerCustomFields {
		fullValue, exists := record.CustomFields[key]
		if !exists || !reflect.DeepEqual(fullValue, value) {
			return ErrUnavailable
		}
	}
	if _, err := entityID(record.Creator.ID); err != nil || record.Creator.Kind < kernel.PrincipalOperator ||
		record.Creator.Kind > kernel.PrincipalServiceAccount || !validText(record.Creator.DisplayName, 240, false) {
		return ErrUnavailable
	}
	if record.Creator.Kind == kernel.PrincipalServiceAccount {
		if record.Creator.UserID != nil {
			return ErrUnavailable
		}
	} else if record.Creator.UserID == nil {
		return ErrUnavailable
	} else if _, err := entityID(*record.Creator.UserID); err != nil {
		return ErrUnavailable
	}
	if kind == kernel.AggregateAlert && (!validText(record.Source, 120, true) || !validText(record.SourceType, 80, true) ||
		!validOptionalText(record.ExternalID, 200) || !validOptionalText(record.DeduplicationKey, 240) ||
		!validStoredInstant(record.DetectedAt) || !validStoredInstant(record.ReceivedAt) ||
		record.ReceivedAt.Before(record.DetectedAt) || record.CreatedAt.Before(record.ReceivedAt)) {
		return ErrUnavailable
	}
	if kind == kernel.AggregateCase && (!validStoredInstant(record.DetectionTime) || !validStoredInstant(record.OpenedAt) ||
		!validText(record.Summary, 2_000, false) || record.OpenedAt.Before(record.DetectionTime) ||
		record.CreatedAt.Before(record.OpenedAt)) {
		return ErrUnavailable
	}
	return nil
}

func descriptionLimit(kind kernel.AggregateKind) int {
	if kind == kernel.AggregateAlert {
		return 10_000
	}
	return 20_000
}

func validOptionalText(value *string, maximum int) bool {
	return value == nil || validText(*value, maximum, true)
}

func validStoredInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Microsecond) == 0
}

func validOptionalStoredInstant(value *time.Time) bool {
	return value == nil || validStoredInstant(*value)
}

func mustEntityOrZero(value uuid.UUID) kernel.EntityID {
	result, _ := entityID(value)
	return result
}

func validTags(tags []string) bool {
	if len(tags) > 100 || !slices.IsSorted(tags) {
		return false
	}
	for index, tag := range tags {
		if !validTag(tag) || index > 0 && tags[index-1] == tag {
			return false
		}
	}
	return true
}

func validTag(value string) bool {
	if len(value) == 0 || len(value) > 64 || !asciiAlphanumeric(value[0]) {
		return false
	}
	for _, character := range value[1:] {
		if character >= '0' && character <= '9' || character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' || strings.ContainsRune("_.:-", character) {
			continue
		}
		return false
	}
	return true
}

func asciiAlphanumeric(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func validUUIDList(values []uuid.UUID, maximum int) bool {
	if len(values) > maximum {
		return false
	}
	seen := make(map[uuid.UUID]struct{}, len(values))
	for _, value := range values {
		if _, err := entityID(value); err != nil {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validOptionalCursor(value *uuid.UUID) bool {
	if value == nil {
		return true
	}
	_, err := entityID(*value)
	return err == nil
}

func validUniqueEnums(values []string, allowed ...string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validEnum(value, allowed...) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validCustomFields(values map[string]any) bool {
	if values == nil || len(values) > 100 || !validJSONMap(values, 64*1024) {
		return values == nil
	}
	for key, value := range values {
		if _, err := customKey(key); err != nil || !validCustomFieldValue(value, 10_000) {
			return false
		}
	}
	return true
}

// ValidateCustomFields applies the canonical closed transport value grammar.
func ValidateCustomFields(values map[string]any) error {
	if !validCustomFields(values) {
		return ErrInvalidInput
	}
	return nil
}

func validRawPayload(values map[string]any) bool {
	if values == nil {
		return true
	}
	if len(values) > 200 || !validJSONMap(values, 256*1024) {
		return false
	}
	for key := range values {
		if !validText(key, 128, true) {
			return false
		}
	}
	return true
}

func validCustomFieldValue(value any, stringLimit int) bool {
	switch typed := value.(type) {
	case nil, bool:
		return true
	case string:
		return validText(typed, stringLimit, false)
	case json.Number:
		_, err := typed.Float64()
		return err == nil
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	case float32:
		return !float32IsNonFinite(typed)
	case float64:
		return !math.IsNaN(typed) && !math.IsInf(typed, 0)
	case []any:
		if len(typed) > 100 {
			return false
		}
		for _, item := range typed {
			if item == nil {
				return false
			}
			if _, nested := item.([]any); nested || !validCustomFieldValue(item, 1_000) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func float32IsNonFinite(value float32) bool {
	return math.IsNaN(float64(value)) || math.IsInf(float64(value), 0)
}

func validIdempotencyKey(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._~-", character) {
			continue
		}
		return false
	}
	return true
}

func validComment(
	comment Comment,
	tenantID, resourceID uuid.UUID,
	kind kernel.AggregateKind,
	projection Projection,
	access LiveAccess,
	now time.Time,
) bool {
	if comment.TenantID != tenantID || comment.ResourceID != resourceID || comment.ResourceKind != kind ||
		!IsValidCommentProjection(comment, projection) {
		return false
	}
	if !comment.CanEdit {
		return true
	}
	tenant, tenantErr := entityID(tenantID)
	draft, draftErr := kernel.NewCommentDraft(
		access.Authority.Principal(), comment.Visibility, comment.BodyMarkdown,
	)
	if tenantErr != nil || draftErr != nil ||
		!kernel.CanCreateComment(kind, tenant, draft, access.Authority) {
		return false
	}
	if !now.Before(comment.EditableUntil) || access.MembershipID != mustEntityOrZero(comment.Author.MembershipID) {
		return false
	}
	if comment.Author.Audience == CommentAudienceOperator {
		return comment.Origin == CommentOriginAPI && projection == ProjectionOperator &&
			access.Authority.Principal() == kernel.PrincipalOperator
	}
	return comment.Origin == CommentOriginCustomerPortal && projection == ProjectionCustomer &&
		access.Authority.Principal() == kernel.PrincipalCustomer &&
		access.CustomerContactID != nil && comment.Author.ContactID != nil &&
		uuidFromEntity(*access.CustomerContactID) == *comment.Author.ContactID
}

// IsValidCommentProjection validates the complete stored shape before an HTTP
// mapper can serialize it. Live edit authority and the edit-window clock are
// checked separately by the application use case.
func IsValidCommentProjection(comment Comment, projection Projection) bool {
	if !validCommentID(comment.ID) || !validCommentID(comment.TenantID) ||
		!validCommentID(comment.ResourceID) || !validCommentID(comment.Author.MembershipID) ||
		comment.ResourceKind != kernel.AggregateAlert && comment.ResourceKind != kernel.AggregateCase ||
		comment.Visibility != kernel.CommentPublic && comment.Visibility != kernel.CommentPrivate ||
		!validStoredCommentBodies(comment.BodyMarkdown, comment.BodyHTML) ||
		comment.Revision < 1 || comment.Revision > int(maxResourceVersion) || !validCommentStoredInstant(comment.CreatedAt) ||
		!validCommentStoredInstant(comment.UpdatedAt) || comment.UpdatedAt.Before(comment.CreatedAt) ||
		!comment.UpdatedAt.Before(comment.EditableUntil) || !validCommentStoredInstant(comment.EditableUntil) ||
		comment.Revision == 1 && !comment.UpdatedAt.Equal(comment.CreatedAt) ||
		comment.Revision > 1 && !comment.UpdatedAt.After(comment.CreatedAt) ||
		!comment.EditableUntil.Equal(comment.CreatedAt.Add(commentEditWindowSeconds*time.Second)) ||
		!validCommentDisplayName(comment.Author.DisplayName) ||
		!validCommentAuthorOrigin(comment.Origin, comment.Author.Audience, comment.Author.ContactID) ||
		(comment.Origin == CommentOriginCustomerPortal || comment.Origin == CommentOriginEscalationCopy) &&
			comment.Visibility != kernel.CommentPublic ||
		len(comment.Attachments) > maximumCommentAttachments || len(comment.Mentions) > maximumCommentMentions ||
		!validCommentRelationProjection(comment.Attachments, comment.Mentions) {
		return false
	}
	if projection == ProjectionCustomer {
		if comment.Visibility != kernel.CommentPublic || len(comment.Mentions) != 0 ||
			!allCommentAttachmentsPublic(comment.Attachments) {
			return false
		}
	} else if projection != ProjectionOperator {
		return false
	}
	if comment.Visibility == kernel.CommentPublic && !allCommentAttachmentsPublic(comment.Attachments) {
		return false
	}
	if !comment.CanEdit {
		return true
	}
	if projection == ProjectionOperator {
		return comment.Origin == CommentOriginAPI && comment.Author.Audience == CommentAudienceOperator
	}
	return comment.Origin == CommentOriginCustomerPortal && comment.Author.Audience == CommentAudienceCustomer
}

func validCommentAuthorOrigin(origin CommentOrigin, audience CommentAuthorAudience, contactID *uuid.UUID) bool {
	switch origin {
	case CommentOriginAPI, CommentOriginSystem:
		return audience == CommentAudienceOperator && contactID == nil
	case CommentOriginCustomerPortal:
		return audience == CommentAudienceCustomer && contactID != nil && validCommentID(*contactID)
	case CommentOriginEscalationCopy:
		return audience == CommentAudienceOperator && contactID == nil ||
			audience == CommentAudienceCustomer && contactID != nil && validCommentID(*contactID)
	default:
		return false
	}
}

func validActivity(activity Activity, view View, tenantID uuid.UUID, kind kernel.AggregateKind) bool {
	if activity.TenantID != tenantID || activity.ResourceID != uuidFromEntity(view.Record.Snapshot.ID()) ||
		activity.ResourceKind != kind {
		return false
	}
	if view.Projection == ProjectionCustomer {
		return validActivityEnvelope(activity, tenantID, kind) &&
			activity.Details == nil && activity.ActorKind == ActivityActorRedacted && activity.ActorID == uuid.Nil &&
			validEnum(activity.Kind, "created", "status_changed", "comment.public", "escalated", "linked", "unlinked")
	}
	return validOperatorActivity(activity, tenantID, kind)
}

func validActivityEnvelope(activity Activity, tenantID uuid.UUID, kind kernel.AggregateKind) bool {
	if activity.TenantID != tenantID || activity.ResourceKind != kind ||
		!validText(activity.Summary, 1_000, true) || !validStoredInstant(activity.OccurredAt) ||
		!validText(activity.DisplayName, 200, true) || !validEnum(activity.Origin, "operator", "customer") ||
		len(activity.Details) > 25 || !validCustomFields(activity.Details) {
		return false
	}
	if _, err := entityID(activity.ID); err != nil {
		return false
	}
	_, err := entityID(activity.ResourceID)
	return err == nil
}

func validOperatorActivity(activity Activity, tenantID uuid.UUID, kind kernel.AggregateKind) bool {
	return validActivityEnvelope(activity, tenantID, kind) && validActivityActor(activity) &&
		validEnum(activity.Kind, "created", "transitioned", "assigned", "claimed", "released", "transferred", "comment.public", "comment.private", "escalated", "linked", "unlinked", "relation_added", "relation_retracted")
}

func validActivityActor(activity Activity) bool {
	switch activity.ActorKind {
	case ActivityActorHuman:
		_, err := entityID(activity.ActorID)
		return err == nil && validEnum(activity.Origin, "operator", "customer")
	case ActivityActorServiceAccount:
		_, err := entityID(activity.ActorID)
		return err == nil && activity.Origin == "operator"
	case ActivityActorSystem:
		return activity.ActorID == uuid.Nil && activity.Origin == "operator"
	default:
		return false
	}
}

func validLink(link Link, tenantID uuid.UUID) bool {
	if link.TenantID != tenantID || !validEnum(link.Relation, "escalation", "correlation") ||
		!validText(link.Reason, 2_000, true) || !validStoredInstant(link.LinkedAt) ||
		link.SourceAlertVersion == 0 || link.SourceAlertVersion > maxResourceVersion ||
		!validCopiedFieldSnapshot(link.CopiedFieldSnapshot) {
		return false
	}
	for _, value := range []uuid.UUID{link.ID, link.AlertID, link.CaseID, link.LinkedBy} {
		if _, err := entityID(value); err != nil {
			return false
		}
	}
	if !slices.IsSorted(link.CopyFields) || !slices.IsSorted(link.CustomFieldKeys) ||
		!validOrderedUUIDs(link.PublicCommentIDs) {
		return false
	}
	for index, field := range link.CopyFields {
		if !validEnum(field, "title", "description", "severity", "priority", "category", "tags", "custom_fields", "iocs", "assets", "attachments", "contacts", "public_comments") ||
			index > 0 && link.CopyFields[index-1] == field {
			return false
		}
	}
	for index, key := range link.CustomFieldKeys {
		if _, err := customKey(key); err != nil || index > 0 && link.CustomFieldKeys[index-1] == key {
			return false
		}
	}
	for field, values := range link.ItemIDs {
		if !validEnum(field, "iocIds", "assetIds", "attachmentIds", "contactIds") || !validOrderedUUIDs(values) {
			return false
		}
	}
	return true
}

func validCopiedFieldSnapshot(values map[string]any) bool {
	if values == nil || len(values) > 9 || !validJSONMap(values, 64*1024) {
		return false
	}
	for key, value := range values {
		switch key {
		case "title":
			text, ok := value.(string)
			if !ok || !validText(text, 240, true) {
				return false
			}
		case "description":
			text, ok := value.(string)
			if !ok || !validText(text, 10_000, true) {
				return false
			}
		case "severity":
			text, ok := value.(string)
			if !ok || !validEnum(text, "informational", "low", "medium", "high", "critical") {
				return false
			}
		case "priority":
			text, ok := value.(string)
			if !ok || !validEnum(text, "low", "medium", "high", "urgent", "critical") {
				return false
			}
		case "category":
			text, ok := value.(string)
			if !ok || !validText(text, 120, true) {
				return false
			}
		case "tags":
			items, ok := value.([]any)
			if !ok {
				return false
			}
			tags := make([]string, len(items))
			for index, item := range items {
				text, stringOK := item.(string)
				if !stringOK {
					return false
				}
				tags[index] = text
			}
			if !validTags(tags) {
				return false
			}
		case "customFields":
			customFields, ok := value.(map[string]any)
			if !ok || !validCustomFields(customFields) {
				return false
			}
		case "publicCommentIds":
			items, ok := value.([]any)
			if !ok || len(items) > 100 {
				return false
			}
			ids := make([]uuid.UUID, len(items))
			for index, item := range items {
				text, stringOK := item.(string)
				id, parseErr := uuid.Parse(text)
				if !stringOK || parseErr != nil {
					return false
				}
				ids[index] = id
			}
			if !validOrderedUUIDs(ids) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func validOrderedUUIDs(values []uuid.UUID) bool {
	if !validUUIDList(values, 256) {
		return false
	}
	return slices.IsSortedFunc(values, func(left, right uuid.UUID) int {
		return strings.Compare(left.String(), right.String())
	})
}

func linkMatches(link Link, source, other Record) bool {
	sourceID := uuidFromEntity(source.Snapshot.ID())
	otherID := uuidFromEntity(other.Snapshot.ID())
	return source.Snapshot.Kind() == kernel.AggregateAlert && link.AlertID == sourceID && link.CaseID == otherID ||
		source.Snapshot.Kind() == kernel.AggregateCase && link.CaseID == sourceID && link.AlertID == otherID
}

func repositoryError(err error) error {
	switch {
	case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrForbidden), errors.Is(err, ErrNotFound),
		errors.Is(err, ErrConflict), errors.Is(err, ErrPreconditionFailed), errors.Is(err, ErrUnavailable):
		return err
	default:
		return ErrUnavailable
	}
}
