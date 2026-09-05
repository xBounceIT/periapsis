package ticketing

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

type EscalationSourceInput struct {
	AlertID         uuid.UUID
	ExpectedVersion uint64
	Selection       CopySelection
}

type EscalationTargetInput struct {
	ExistingCaseID      *uuid.UUID
	ExistingCaseVersion uint64
	NewCase             *CreateCaseInput
}

type EscalationInput struct {
	PathAlertID     uuid.UUID
	ExpectedVersion uint64
	Relation        string
	Reason          string
	Sources         []EscalationSourceInput
	Target          EscalationTargetInput
	IdempotencyKey  string
}

type EscalationResult struct {
	Alert    View
	Case     View
	Links    []LinkView
	Effects  []string
	Replayed bool
}

func (service *Service) Escalate(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	input EscalationInput,
) (EscalationResult, error) {
	return service.escalate(ctx, actor, tenantID, input, EscalationOperationEscalate)
}

// Link exposes the explicit existing-Case action while preserving the same
// planner, selection validation, authorization snapshot, and transactional ABI
// as escalation. A create_case target is rejected before any repository call.
func (service *Service) Link(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	input EscalationInput,
) (EscalationResult, error) {
	if input.Target.NewCase != nil || input.Target.ExistingCaseID == nil {
		return EscalationResult{}, ErrInvalidInput
	}
	return service.escalate(ctx, actor, tenantID, input, EscalationOperationLink)
}

func (service *Service) escalate(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	input EscalationInput,
	operation EscalationOperation,
) (EscalationResult, error) {
	if !validMutationActor(actor, tenantID) {
		return EscalationResult{}, ErrForbidden
	}
	if err := validateEscalationInput(input); err != nil {
		return EscalationResult{}, err
	}
	access, err := service.access(ctx, actor, tenantID, CapabilityAlertEscalate)
	if err != nil {
		return EscalationResult{}, err
	}
	if access.Authority.Principal() != kernel.PrincipalOperator {
		return EscalationResult{}, ErrForbidden
	}
	for _, capability := range escalationSelectionCapabilities(input.Sources) {
		selectionAccess, accessErr := service.access(ctx, actor, tenantID, capability)
		if accessErr != nil {
			return EscalationResult{}, accessErr
		}
		if !sameAuthority(access.Authority, selectionAccess.Authority) {
			return EscalationResult{}, ErrUnavailable
		}
	}
	tenant, _ := entityID(tenantID)
	sources := make([]kernel.EscalationSource, 0, len(input.Sources))
	sourceWorkflows := make([]kernel.EscalationSourceWorkflow, 0, len(input.Sources))
	sourceRecords := make(map[uuid.UUID]Record, len(input.Sources))
	for _, requested := range input.Sources {
		record, getErr := service.repository.Get(ctx, actor.UserID, tenantID, kernel.AggregateAlert, requested.AlertID)
		if getErr != nil {
			return EscalationResult{}, repositoryError(getErr)
		}
		if validateRecord(record, tenantID, kernel.AggregateAlert) != nil || !canAccess(record, access) {
			return EscalationResult{}, ErrUnavailable
		}
		linkID, reserveErr := service.repository.ReserveID(ctx, tenantID)
		if reserveErr != nil {
			return EscalationResult{}, repositoryError(reserveErr)
		}
		evidence, evidenceErr := service.repository.ResolveEscalationSelection(ctx, actor.UserID, record, requested.Selection)
		if evidenceErr != nil {
			return EscalationResult{}, repositoryError(evidenceErr)
		}
		if !selectionEvidenceMatches(requested.Selection, evidence) {
			return EscalationResult{}, ErrUnavailable
		}
		source, sourceErr := kernel.NewEscalationSource(
			record.Workflow, linkID, record.Snapshot, requested.ExpectedVersion,
			requested.Selection.Fields, requested.Selection.CustomFields, evidence.Items, evidence.Comments,
		)
		if sourceErr != nil {
			return EscalationResult{}, ErrInvalidInput
		}
		workflowBinding, bindingErr := kernel.NewEscalationSourceWorkflow(record.Snapshot.ID(), record.Workflow)
		if bindingErr != nil {
			return EscalationResult{}, ErrUnavailable
		}
		sources = append(sources, source)
		sourceWorkflows = append(sourceWorkflows, workflowBinding)
		sourceRecords[requested.AlertID] = record
	}

	var target kernel.EscalationTarget
	var caseWorkflow kernel.WorkflowDefinition
	var newCaseContent *CreateCaseInput
	var existingCaseRecord *Record
	if input.Target.NewCase != nil {
		caseAccess, accessErr := service.access(ctx, actor, tenantID, CapabilityCaseCreate)
		if accessErr != nil {
			return EscalationResult{}, accessErr
		}
		if !sameAuthority(access.Authority, caseAccess.Authority) {
			return EscalationResult{}, ErrUnavailable
		}
		content := *input.Target.NewCase
		content.IdempotencyKey = input.IdempotencyKey
		if err := validateCreateCaseInput(content); err != nil {
			return EscalationResult{}, err
		}
		caseWorkflow, err = service.repository.Workflow(ctx, actor.UserID, tenantID, kernel.AggregateCase, content.WorkflowID)
		if err != nil {
			return EscalationResult{}, repositoryError(err)
		}
		caseID, reserveErr := service.repository.ReserveID(ctx, tenantID)
		if reserveErr != nil {
			return EscalationResult{}, repositoryError(reserveErr)
		}
		target, err = kernel.NewCaseCreationTarget(caseWorkflow, tenant, caseID, 0, content.CustomerVisible)
		if err != nil {
			return EscalationResult{}, ErrUnavailable
		}
		newCaseContent = &content
	} else {
		caseRecord, getErr := service.repository.Get(ctx, actor.UserID, tenantID, kernel.AggregateCase, *input.Target.ExistingCaseID)
		if getErr != nil {
			return EscalationResult{}, repositoryError(getErr)
		}
		caseAccess, accessErr := service.access(ctx, actor, tenantID, CapabilityCaseUpdate)
		if accessErr != nil {
			return EscalationResult{}, accessErr
		}
		if validateRecord(caseRecord, tenantID, kernel.AggregateCase) != nil || !canAccess(caseRecord, caseAccess) {
			return EscalationResult{}, ErrUnavailable
		}
		if !sameAuthority(access.Authority, caseAccess.Authority) {
			return EscalationResult{}, ErrUnavailable
		}
		caseWorkflow = caseRecord.Workflow
		existingCaseRecord = &caseRecord
		target, err = kernel.NewExistingCaseTarget(caseWorkflow, caseRecord.Snapshot, input.Target.ExistingCaseVersion)
		if err != nil {
			return EscalationResult{}, ErrInvalidInput
		}
	}

	relation := kernel.RelationEscalation
	if input.Relation == "correlation" {
		relation = kernel.RelationCorrelation
	}
	reason, err := kernel.NewEscalationReason(input.Reason)
	if err != nil {
		return EscalationResult{}, ErrInvalidInput
	}
	key, err := kernel.NewIdempotencyKey(input.IdempotencyKey)
	if err != nil {
		return EscalationResult{}, ErrInvalidInput
	}
	linkedAt := service.clock().UTC().Truncate(time.Microsecond)
	command, err := kernel.NewEscalationCommand(tenant, key, linkedAt, relation, reason, target, sources)
	if err != nil {
		return EscalationResult{}, ErrInvalidInput
	}
	replayIdentity, err := kernel.NewEscalationReplayIdentity(command, access.Authority)
	if err != nil {
		return EscalationResult{}, ErrForbidden
	}
	fingerprint, err := escalationFingerprint(replayIdentity, input, operation)
	if err != nil {
		return EscalationResult{}, ErrInvalidInput
	}
	replay, found, err := service.repository.LookupEscalationReplay(ctx, EscalationReplayQuery{
		Operation: operation, Identity: replayIdentity, Fingerprint: fingerprint,
	})
	if err != nil {
		return EscalationResult{}, repositoryError(err)
	}
	if found {
		return mapEscalationWriteResult(tenantID, actor.UserID, input, replay, replay.Effects, true, nil)
	}
	plan, err := escalationPlan(kernel.PlanEscalation(sourceWorkflows, caseWorkflow, command, access.Authority))
	if err != nil {
		return EscalationResult{}, err
	}

	var assignmentPlan *kernel.MutationPlan
	if newCaseContent != nil && newCaseContent.AssignedTeamID != nil {
		created, snapshotErr := kernel.SnapshotFromCreatePlan(caseWorkflow, plan.CaseMutation())
		if snapshotErr != nil {
			return EscalationResult{}, ErrUnavailable
		}
		team, assignee, targetErr := assignmentTarget(newCaseContent.AssignedTeamID, newCaseContent.AssigneeUserID)
		if targetErr != nil {
			return EscalationResult{}, targetErr
		}
		assignCommand, commandErr := kernel.NewAssignCommand(tenant, created.ID(), created.Version(), team, assignee)
		if commandErr != nil {
			return EscalationResult{}, ErrInvalidInput
		}
		value, planErr := mutationPlan(kernel.PlanAssign(caseWorkflow, created, assignCommand, access.Authority))
		if planErr != nil {
			return EscalationResult{}, planErr
		}
		assignmentPlan = &value
	}
	effectPlans := append(plan.AlertMutations(), plan.CaseMutation())
	if assignmentPlan != nil {
		effectPlans = append(effectPlans, *assignmentPlan)
	}
	expectedAlert, expectedCase, err := expectedEscalationSnapshots(
		input.PathAlertID, sourceRecords, caseWorkflow, existingCaseRecord, plan, assignmentPlan,
	)
	if err != nil {
		return EscalationResult{}, ErrUnavailable
	}
	effects := effectsForPlans(effectPlans)
	if operation == EscalationOperationLink {
		effects = effectsForLinkLifecyclePlans(effectPlans)
	}
	result, err := service.repository.CommitEscalation(ctx, EscalationWrite{
		Operation: operation, Actor: actor, Content: input, Plan: plan,
		CaseAssignmentPlan: assignmentPlan, Fingerprint: fingerprint,
		Effects: effects, Audit: actor.Audit,
	})
	if err != nil {
		return EscalationResult{}, repositoryError(err)
	}
	if !slices.Equal(result.Effects, effects) {
		return EscalationResult{}, ErrUnavailable
	}
	if !result.Replayed && (!sameSnapshot(expectedAlert, result.Alert.Snapshot) ||
		!sameSnapshot(expectedCase, result.Case.Snapshot) || !newCaseContentMatches(input.Target.NewCase, result.Case)) {
		return EscalationResult{}, ErrUnavailable
	}
	var expectedLinks []kernel.AlertCaseLinkPlan
	if !result.Replayed {
		expectedLinks = plan.Links()
	}
	return mapEscalationWriteResult(tenantID, actor.UserID, input, result, effects, result.Replayed, expectedLinks)
}

func escalationSelectionCapabilities(sources []EscalationSourceInput) []Capability {
	required := map[Capability]bool{}
	for _, source := range sources {
		required[CapabilityDFIRIOCRead] = required[CapabilityDFIRIOCRead] ||
			len(source.Selection.ItemIDs[kernel.CopyIOCs]) > 0
		required[CapabilityDFIRAssetRead] = required[CapabilityDFIRAssetRead] ||
			len(source.Selection.ItemIDs[kernel.CopyAssets]) > 0
		required[CapabilityDFIRAttachmentRead] = required[CapabilityDFIRAttachmentRead] ||
			len(source.Selection.ItemIDs[kernel.CopyAttachments]) > 0
	}
	capabilities := make([]Capability, 0, 3)
	for _, capability := range []Capability{
		CapabilityDFIRIOCRead,
		CapabilityDFIRAssetRead,
		CapabilityDFIRAttachmentRead,
	} {
		if required[capability] {
			capabilities = append(capabilities, capability)
		}
	}
	return capabilities
}

func expectedEscalationSnapshots(
	pathAlertID uuid.UUID,
	sourceRecords map[uuid.UUID]Record,
	caseWorkflow kernel.WorkflowDefinition,
	existingCase *Record,
	plan kernel.EscalationPlan,
	assignmentPlan *kernel.MutationPlan,
) (kernel.TicketSnapshot, kernel.TicketSnapshot, error) {
	pathRecord, exists := sourceRecords[pathAlertID]
	if !exists {
		return kernel.TicketSnapshot{}, kernel.TicketSnapshot{}, ErrUnavailable
	}
	var alertPlan kernel.MutationPlan
	for _, candidate := range plan.AlertMutations() {
		if candidate.Ticket() == pathRecord.Snapshot.ID() {
			alertPlan = candidate
			break
		}
	}
	expectedAlert, err := kernel.ApplyMutationPlan(pathRecord.Workflow, pathRecord.Snapshot, alertPlan)
	if err != nil {
		return kernel.TicketSnapshot{}, kernel.TicketSnapshot{}, err
	}
	var expectedCase kernel.TicketSnapshot
	if existingCase == nil {
		expectedCase, err = kernel.SnapshotFromCreatePlan(caseWorkflow, plan.CaseMutation())
	} else {
		expectedCase, err = kernel.ApplyMutationPlan(caseWorkflow, existingCase.Snapshot, plan.CaseMutation())
	}
	if err != nil {
		return kernel.TicketSnapshot{}, kernel.TicketSnapshot{}, err
	}
	if assignmentPlan != nil {
		expectedCase, err = kernel.ApplyMutationPlan(caseWorkflow, expectedCase, *assignmentPlan)
		if err != nil {
			return kernel.TicketSnapshot{}, kernel.TicketSnapshot{}, err
		}
	}
	return expectedAlert, expectedCase, nil
}

func newCaseContentMatches(input *CreateCaseInput, record Record) bool {
	if input == nil {
		return true
	}
	if record.Title != input.Title || record.Description != input.Description || record.Summary != input.Summary ||
		record.Severity != input.Severity || record.Priority != input.Priority ||
		input.Category != "" && record.Category != input.Category ||
		!equalOptionalString(record.Classification, input.Classification) || !containsAllStrings(record.Tags, input.Tags) ||
		!containsAllCustomFields(record.CustomFields, input.CustomFields) {
		return false
	}
	return input.DetectionTime.IsZero() || record.DetectionTime.Equal(input.DetectionTime)
}

func containsAllStrings(values, required []string) bool {
	for _, value := range required {
		if !slices.Contains(values, value) {
			return false
		}
	}
	return true
}

func containsAllCustomFields(values, required map[string]any) bool {
	for key, requiredValue := range required {
		value, exists := values[key]
		if !exists || !reflect.DeepEqual(value, requiredValue) {
			return false
		}
	}
	return true
}

func equalOptionalString(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func escalationFingerprint(
	identity kernel.EscalationReplayIdentity,
	input EscalationInput,
	operation EscalationOperation,
) ([sha256.Size]byte, error) {
	type newCaseFingerprint struct {
		WorkflowID      *uuid.UUID     `json:"workflow_id"`
		Title           string         `json:"title"`
		Description     string         `json:"description"`
		Summary         string         `json:"summary"`
		Severity        string         `json:"severity"`
		Priority        string         `json:"priority"`
		Category        string         `json:"category"`
		Classification  *string        `json:"classification"`
		Tags            []string       `json:"tags"`
		CustomFields    map[string]any `json:"custom_fields"`
		CustomerVisible bool           `json:"customer_visible"`
		DetectionTime   time.Time      `json:"detection_time"`
		AssignedTeamID  *uuid.UUID     `json:"assigned_team_id"`
		AssigneeUserID  *uuid.UUID     `json:"assignee_user_id"`
	}
	payload := struct {
		KernelFingerprint [sha256.Size]byte   `json:"kernel_fingerprint"`
		Operation         string              `json:"operation"`
		NewCase           *newCaseFingerprint `json:"new_case"`
	}{KernelFingerprint: identity.Fingerprint(), Operation: string(operation)}
	if operation != EscalationOperationEscalate && operation != EscalationOperationLink {
		return [sha256.Size]byte{}, ErrInvalidInput
	}
	if input.Target.NewCase != nil {
		value := input.Target.NewCase
		payload.NewCase = &newCaseFingerprint{
			WorkflowID: value.WorkflowID, Title: value.Title, Description: value.Description,
			Summary: value.Summary, Severity: value.Severity, Priority: value.Priority,
			Category: value.Category, Classification: value.Classification, Tags: value.Tags,
			CustomFields: value.CustomFields, CustomerVisible: value.CustomerVisible,
			DetectionTime: value.DetectionTime, AssignedTeamID: value.AssignedTeamID,
			AssigneeUserID: value.AssigneeUserID,
		}
	}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > 512*1024 {
		return [sha256.Size]byte{}, ErrInvalidInput
	}
	return sha256.Sum256(encoded), nil
}

func mapEscalationWriteResult(
	tenantID uuid.UUID,
	actorID uuid.UUID,
	input EscalationInput,
	result EscalationWriteResult,
	effects []string,
	replayed bool,
	expectedLinks []kernel.AlertCaseLinkPlan,
) (EscalationResult, error) {
	if validateRecord(result.Alert, tenantID, kernel.AggregateAlert) != nil ||
		validateRecord(result.Case, tenantID, kernel.AggregateCase) != nil ||
		uuidFromEntity(result.Alert.Snapshot.ID()) != input.PathAlertID || len(result.Links) != len(input.Sources) ||
		!validEffects(effects) {
		return EscalationResult{}, ErrUnavailable
	}
	sourceByID := make(map[uuid.UUID]EscalationSourceInput, len(input.Sources))
	for _, source := range input.Sources {
		sourceByID[source.AlertID] = source
	}
	expectedLinkByAlert := make(map[uuid.UUID]kernel.AlertCaseLinkPlan, len(expectedLinks))
	for _, link := range expectedLinks {
		expectedLinkByAlert[uuidFromEntity(link.Alert())] = link
	}
	links := make([]LinkView, 0, len(result.Links))
	for _, link := range result.Links {
		source, exists := sourceByID[link.AlertID]
		if !exists || !validLink(link, tenantID) || link.CaseID != uuidFromEntity(result.Case.Snapshot.ID()) ||
			link.SourceAlertVersion != source.ExpectedVersion || link.Relation != input.Relation ||
			link.Reason != input.Reason || link.LinkedBy != actorID || !linkMatchesSelection(link, source.Selection) {
			return EscalationResult{}, ErrUnavailable
		}
		if len(expectedLinks) > 0 {
			expected, present := expectedLinkByAlert[link.AlertID]
			if !present || !linkMatchesPlan(link, expected) {
				return EscalationResult{}, ErrUnavailable
			}
			delete(expectedLinkByAlert, link.AlertID)
		}
		delete(sourceByID, link.AlertID)
		links = append(links, LinkView{Link: link, Other: result.Case, Projection: ProjectionOperator})
	}
	if len(sourceByID) != 0 || len(expectedLinkByAlert) != 0 {
		return EscalationResult{}, ErrUnavailable
	}
	return EscalationResult{
		Alert: View{Record: result.Alert, Projection: ProjectionOperator},
		Case:  View{Record: result.Case, Projection: ProjectionOperator},
		Links: links, Effects: effects, Replayed: replayed,
	}, nil
}

func linkMatchesPlan(link Link, expected kernel.AlertCaseLinkPlan) bool {
	return link.ID == uuidFromEntity(expected.LinkID()) && link.AlertID == uuidFromEntity(expected.Alert()) &&
		link.CaseID == uuidFromEntity(expected.Case()) && link.LinkedAt.Equal(expected.LinkedAt()) &&
		link.LinkedBy == uuidFromEntity(expected.LinkedBy()) && link.Relation == expected.Relation().String() &&
		link.Reason == expected.Reason().Value() && link.SourceAlertVersion == expected.SourceAlertVersion()
}

func validEffects(effects []string) bool {
	if len(effects) < 2 || len(effects) > 4 || !slices.IsSortedFunc(effects, effectOrder) {
		return false
	}
	for index, effect := range effects {
		if !validEnum(effect, "activity", "audit", "sla", "notification") || index > 0 && effects[index-1] == effect {
			return false
		}
	}
	return slices.Contains(effects, "activity") && slices.Contains(effects, "audit")
}

func effectOrder(left, right string) int {
	order := func(value string) int {
		switch value {
		case "activity":
			return 0
		case "audit":
			return 1
		case "sla":
			return 2
		case "notification":
			return 3
		default:
			return 4
		}
	}
	return order(left) - order(right)
}

func linkMatchesSelection(link Link, selection CopySelection) bool {
	fields := make([]string, len(selection.Fields))
	for index, field := range selection.Fields {
		fields[index] = field.String()
	}
	slices.Sort(fields)
	customFields := make([]string, len(selection.CustomFields))
	for index, key := range selection.CustomFields {
		customFields[index] = key.String()
	}
	slices.Sort(customFields)
	comments := slices.Clone(selection.PublicCommentIDs)
	slices.SortFunc(comments, compareUUID)
	if !slices.Equal(link.CopyFields, fields) || !slices.Equal(link.CustomFieldKeys, customFields) ||
		!slices.Equal(link.PublicCommentIDs, comments) || len(link.ItemIDs) != len(selection.ItemIDs) {
		return false
	}
	for field, requested := range selection.ItemIDs {
		key := escalationItemField(field)
		actual, exists := link.ItemIDs[key]
		if key == "" || !exists {
			return false
		}
		expected := slices.Clone(requested)
		slices.SortFunc(expected, compareUUID)
		if !slices.Equal(actual, expected) {
			return false
		}
	}
	return true
}

func escalationItemField(field kernel.CopyField) string {
	switch field {
	case kernel.CopyIOCs:
		return "iocIds"
	case kernel.CopyAssets:
		return "assetIds"
	case kernel.CopyAttachments:
		return "attachmentIds"
	case kernel.CopyContacts:
		return "contactIds"
	default:
		return ""
	}
}

func validateEscalationInput(input EscalationInput) error {
	if !validIdempotencyKey(input.IdempotencyKey) || input.ExpectedVersion == 0 || input.ExpectedVersion > maxResourceVersion ||
		!validEnum(input.Relation, "escalation", "correlation") || !validText(input.Reason, 2_000, true) ||
		len(input.Sources) == 0 || len(input.Sources) > 100 ||
		(input.Target.ExistingCaseID == nil) == (input.Target.NewCase == nil) ||
		input.Target.NewCase != nil && input.Target.ExistingCaseVersion != 0 {
		return ErrInvalidInput
	}
	if _, err := entityID(input.PathAlertID); err != nil {
		return ErrInvalidInput
	}
	seen := make(map[uuid.UUID]struct{}, len(input.Sources))
	pathCount := 0
	for _, source := range input.Sources {
		if _, err := entityID(source.AlertID); err != nil || source.ExpectedVersion == 0 || source.ExpectedVersion > maxResourceVersion {
			return ErrInvalidInput
		}
		if _, duplicate := seen[source.AlertID]; duplicate {
			return ErrInvalidInput
		}
		seen[source.AlertID] = struct{}{}
		if source.AlertID == input.PathAlertID {
			pathCount++
			if source.ExpectedVersion != input.ExpectedVersion {
				return ErrInvalidInput
			}
		}
		if !validCopySelection(source.Selection) {
			return ErrInvalidInput
		}
	}
	if pathCount != 1 {
		return ErrInvalidInput
	}
	if input.Target.ExistingCaseID != nil {
		if _, err := entityID(*input.Target.ExistingCaseID); err != nil || input.Target.ExistingCaseVersion == 0 ||
			input.Target.ExistingCaseVersion > maxResourceVersion {
			return ErrInvalidInput
		}
	}
	return nil
}

// ValidateEscalationInput applies the same bounded syntax checks used by the use case.
func ValidateEscalationInput(input EscalationInput) error { return validateEscalationInput(input) }

func validCopySelection(selection CopySelection) bool {
	if len(selection.Fields) > 12 || len(selection.CustomFields) > 100 ||
		len(selection.PublicCommentIDs) > 100 || !validUUIDList(selection.PublicCommentIDs, 100) {
		return false
	}
	seenFields := make(map[kernel.CopyField]struct{}, len(selection.Fields))
	for _, field := range selection.Fields {
		if field < kernel.CopyTitle || field > kernel.CopyPublicComments {
			return false
		}
		if _, duplicate := seenFields[field]; duplicate {
			return false
		}
		seenFields[field] = struct{}{}
	}
	seenCustomFields := make(map[kernel.Key]struct{}, len(selection.CustomFields))
	for _, key := range selection.CustomFields {
		if _, err := customKey(key.String()); err != nil {
			return false
		}
		if _, duplicate := seenCustomFields[key]; duplicate {
			return false
		}
		seenCustomFields[key] = struct{}{}
	}
	for field, values := range selection.ItemIDs {
		if field < kernel.CopyIOCs || field > kernel.CopyContacts || !validUUIDList(values, 100) {
			return false
		}
	}
	return true
}

func selectionEvidenceMatches(selection CopySelection, evidence SelectionEvidence) bool {
	requestedItems := make(map[string]struct{})
	for field, ids := range selection.ItemIDs {
		for _, id := range ids {
			requestedItems[field.String()+":"+id.String()] = struct{}{}
		}
	}
	if len(requestedItems) != len(evidence.Items) || len(selection.PublicCommentIDs) != len(evidence.Comments) {
		return false
	}
	for _, item := range evidence.Items {
		key := item.Field().String() + ":" + uuidFromEntity(item.ID()).String()
		if _, exists := requestedItems[key]; !exists {
			return false
		}
		delete(requestedItems, key)
	}
	requestedComments := slices.Clone(selection.PublicCommentIDs)
	slices.SortFunc(requestedComments, func(left, right uuid.UUID) int { return strings.Compare(left.String(), right.String()) })
	evidenceComments := slices.Clone(evidence.Comments)
	slices.SortFunc(evidenceComments, func(left, right kernel.CommentReference) int {
		return strings.Compare(left.ID().String(), right.ID().String())
	})
	for index, comment := range evidenceComments {
		if comment.Visibility() != kernel.CommentPublic || uuidFromEntity(comment.ID()) != requestedComments[index] {
			return false
		}
	}
	return len(requestedItems) == 0
}

func escalationPlan(decision kernel.EscalationDecision) (kernel.EscalationPlan, error) {
	if plan, allowed := decision.Plan(); allowed {
		return plan, nil
	}
	switch decision.Reason() {
	case kernel.ReasonInvalidSnapshot:
		return kernel.EscalationPlan{}, ErrUnavailable
	case kernel.ReasonTenantAccess, kernel.ReasonTargetMismatch, kernel.ReasonPrincipalKind,
		kernel.ReasonPermission, kernel.ReasonRole, kernel.ReasonTeamEligibility,
		kernel.ReasonAssigneeEligibility:
		return kernel.EscalationPlan{}, ErrForbidden
	case kernel.ReasonVersionConflict:
		return kernel.EscalationPlan{}, ErrPreconditionFailed
	default:
		return kernel.EscalationPlan{}, ErrConflict
	}
}
