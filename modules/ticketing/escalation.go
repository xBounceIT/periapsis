package ticketing

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"time"
)

const maxIdempotencyKeyBytes = 200

// IdempotencyKey retains only a digest so retry material cannot enter logs or
// long-lived plans. The persistence identity must additionally include tenant
// and actor, both present on EscalationPlan.
type IdempotencyKey struct {
	digest [sha256.Size]byte
}

func NewIdempotencyKey(value string) (IdempotencyKey, error) {
	if !validText(value, maxIdempotencyKeyBytes, false) || strings.ContainsAny(value, "\r\n\t") {
		return IdempotencyKey{}, ErrInvalidEscalation
	}
	return IdempotencyKey{digest: sha256.Sum256([]byte(value))}, nil
}

func NewIdempotencyDigest(value [sha256.Size]byte) (IdempotencyKey, error) {
	if value == ([sha256.Size]byte{}) {
		return IdempotencyKey{}, ErrInvalidEscalation
	}
	return IdempotencyKey{digest: value}, nil
}

func (key IdempotencyKey) Digest() [sha256.Size]byte { return key.digest }
func (key IdempotencyKey) String() string            { return "IdempotencyKey{[REDACTED]}" }
func (key IdempotencyKey) GoString() string          { return key.String() }

func validIdempotencyKey(key IdempotencyKey) bool {
	return key.digest != ([sha256.Size]byte{})
}

type RelationType uint8

const (
	RelationEscalation RelationType = iota + 1
	RelationCorrelation
)

func (relation RelationType) String() string {
	switch relation {
	case RelationEscalation:
		return "escalation"
	case RelationCorrelation:
		return "correlation"
	default:
		return "unknown"
	}
}

func validRelationType(relation RelationType) bool {
	return relation == RelationEscalation || relation == RelationCorrelation
}

type CopyField uint8

const (
	CopyTitle CopyField = iota + 1
	CopyDescription
	CopySeverity
	CopyPriority
	CopyCategory
	CopyTags
	CopyCustomFields
	CopyIOCs
	CopyAssets
	CopyAttachments
	CopyContacts
	CopyPublicComments
)

func (field CopyField) String() string {
	switch field {
	case CopyTitle:
		return "title"
	case CopyDescription:
		return "description"
	case CopySeverity:
		return "severity"
	case CopyPriority:
		return "priority"
	case CopyCategory:
		return "category"
	case CopyTags:
		return "tags"
	case CopyCustomFields:
		return "custom_fields"
	case CopyIOCs:
		return "iocs"
	case CopyAssets:
		return "assets"
	case CopyAttachments:
		return "attachments"
	case CopyContacts:
		return "contacts"
	case CopyPublicComments:
		return "public_comments"
	default:
		return "unknown"
	}
}

func validCopyField(field CopyField) bool {
	return field >= CopyTitle && field <= CopyPublicComments
}

func copyFieldNeedsReferences(field CopyField) bool {
	return field == CopyIOCs || field == CopyAssets || field == CopyAttachments || field == CopyContacts
}

type CopyItemReference struct {
	field CopyField
	id    EntityID
}

func NewCopyItemReference(field CopyField, id EntityID) (CopyItemReference, error) {
	if !copyFieldNeedsReferences(field) || !validEntityID(id) {
		return CopyItemReference{}, ErrInvalidEscalation
	}
	return CopyItemReference{field: field, id: id}, nil
}

func (reference CopyItemReference) Field() CopyField { return reference.field }
func (reference CopyItemReference) ID() EntityID     { return reference.id }

type CommentReference struct {
	id         EntityID
	visibility CommentVisibility
}

func NewCommentReference(id EntityID, visibility CommentVisibility) (CommentReference, error) {
	if !validEntityID(id) || !validCommentVisibility(visibility) {
		return CommentReference{}, ErrInvalidEscalation
	}
	return CommentReference{id: id, visibility: visibility}, nil
}

func (reference CommentReference) ID() EntityID                  { return reference.id }
func (reference CommentReference) Visibility() CommentVisibility { return reference.visibility }

type EscalationReason struct {
	value string
}

func NewEscalationReason(value string) (EscalationReason, error) {
	if !validText(value, maxEscalationReasonBytes, true) {
		return EscalationReason{}, ErrInvalidEscalation
	}
	return EscalationReason{value: value}, nil
}

func (reason EscalationReason) Value() string { return reason.value }
func (reason EscalationReason) String() string {
	return fmt.Sprintf("EscalationReason{bytes:%d,value:[REDACTED]}", len(reason.value))
}

func (reason EscalationReason) GoString() string { return reason.String() }

type EscalationSource struct {
	linkID          EntityID
	alert           TicketSnapshot
	expectedVersion uint64
	copyFields      []CopyField
	customFields    []Key
	items           []CopyItemReference
	publicComments  []CommentReference
}

// EscalationSourceWorkflow binds one source Alert to the exact immutable
// workflow definition pinned by its snapshot. Planning requires one binding
// for every source and rejects missing, duplicate, extra, or drifted bindings.
type EscalationSourceWorkflow struct {
	alert    EntityID
	workflow WorkflowDefinition
}

func NewEscalationSourceWorkflow(
	alert EntityID,
	workflow WorkflowDefinition,
) (EscalationSourceWorkflow, error) {
	if !validEntityID(alert) || !validWorkflowDefinition(workflow) || workflow.kind != AggregateAlert {
		return EscalationSourceWorkflow{}, ErrInvalidEscalation
	}
	return EscalationSourceWorkflow{alert: alert, workflow: workflow}, nil
}

func (binding EscalationSourceWorkflow) Alert() EntityID { return binding.alert }

func (binding EscalationSourceWorkflow) String() string {
	return fmt.Sprintf("EscalationSourceWorkflow{workflow:%s@%d}", binding.workflow.id, binding.workflow.version)
}

func (binding EscalationSourceWorkflow) GoString() string { return binding.String() }

func NewEscalationSource(
	alertWorkflow WorkflowDefinition,
	linkID EntityID,
	alert TicketSnapshot,
	expectedVersion uint64,
	copyFields []CopyField,
	customFields []Key,
	items []CopyItemReference,
	comments []CommentReference,
) (EscalationSource, error) {
	fields, fieldsOK := canonicalCopyFields(copyFields)
	custom, customOK := canonicalKeys(customFields, maxCopiedItems)
	canonicalItems, itemsOK := canonicalCopyItems(items)
	canonicalComments, commentsOK := canonicalCommentReferences(comments)
	if !validWorkflowDefinition(alertWorkflow) || alertWorkflow.kind != AggregateAlert ||
		!validEntityID(linkID) || !validTicketSnapshot(alertWorkflow, alert) ||
		alert.kind != AggregateAlert || expectedVersion == 0 || expectedVersion > maxVersion ||
		!fieldsOK || !customOK || !itemsOK || !commentsOK ||
		len(custom)+len(canonicalItems)+len(canonicalComments) > maxCopiedItems {
		return EscalationSource{}, ErrInvalidEscalation
	}
	for _, comment := range canonicalComments {
		if comment.visibility != CommentPublic {
			return EscalationSource{}, ErrInvalidEscalation
		}
	}
	if hasCopyField(fields, CopyCustomFields) != (len(custom) > 0) ||
		hasCopyField(fields, CopyPublicComments) != (len(canonicalComments) > 0) {
		return EscalationSource{}, ErrInvalidEscalation
	}
	for _, field := range []CopyField{CopyIOCs, CopyAssets, CopyAttachments, CopyContacts} {
		hasReferences := false
		for _, item := range canonicalItems {
			hasReferences = hasReferences || item.field == field
		}
		if hasCopyField(fields, field) != hasReferences {
			return EscalationSource{}, ErrInvalidEscalation
		}
	}
	return EscalationSource{
		linkID:          linkID,
		alert:           alert,
		expectedVersion: expectedVersion,
		copyFields:      fields,
		customFields:    custom,
		items:           canonicalItems,
		publicComments:  canonicalComments,
	}, nil
}

func (source EscalationSource) LinkID() EntityID           { return source.linkID }
func (source EscalationSource) Alert() TicketSnapshot      { return source.alert }
func (source EscalationSource) ExpectedVersion() uint64    { return source.expectedVersion }
func (source EscalationSource) CopyFields() []CopyField    { return slices.Clone(source.copyFields) }
func (source EscalationSource) CustomFields() []Key        { return slices.Clone(source.customFields) }
func (source EscalationSource) Items() []CopyItemReference { return slices.Clone(source.items) }
func (source EscalationSource) PublicComments() []CommentReference {
	return slices.Clone(source.publicComments)
}

type EscalationTarget struct {
	create          bool
	tenant          EntityID
	caseID          EntityID
	workflowID      EntityID
	workflowVersion uint64
	expectedVersion uint64
	customerVisible bool
	existing        TicketSnapshot
}

func NewCaseCreationTarget(
	caseWorkflow WorkflowDefinition,
	tenant EntityID,
	caseID EntityID,
	expectedVersion uint64,
	customerVisible bool,
) (EscalationTarget, error) {
	if !validWorkflowDefinition(caseWorkflow) || caseWorkflow.kind != AggregateCase ||
		!validEntityID(tenant) || !validEntityID(caseID) || expectedVersion != 0 {
		return EscalationTarget{}, ErrInvalidEscalation
	}
	return EscalationTarget{
		create:          true,
		tenant:          tenant,
		caseID:          caseID,
		workflowID:      caseWorkflow.id,
		workflowVersion: caseWorkflow.version,
		customerVisible: customerVisible,
	}, nil
}

func NewExistingCaseTarget(
	caseWorkflow WorkflowDefinition,
	caseTicket TicketSnapshot,
	expectedVersion uint64,
) (EscalationTarget, error) {
	if !validWorkflowDefinition(caseWorkflow) || caseWorkflow.kind != AggregateCase ||
		!validTicketSnapshot(caseWorkflow, caseTicket) || caseTicket.kind != AggregateCase ||
		expectedVersion == 0 || expectedVersion > maxVersion {
		return EscalationTarget{}, ErrInvalidEscalation
	}
	return EscalationTarget{
		tenant:          caseTicket.tenant,
		caseID:          caseTicket.id,
		workflowID:      caseWorkflow.id,
		workflowVersion: caseWorkflow.version,
		expectedVersion: expectedVersion,
		customerVisible: caseTicket.customerVisible,
		existing:        caseTicket,
	}, nil
}

func (target EscalationTarget) CreatesCase() bool       { return target.create }
func (target EscalationTarget) Tenant() EntityID        { return target.tenant }
func (target EscalationTarget) CaseID() EntityID        { return target.caseID }
func (target EscalationTarget) ExpectedVersion() uint64 { return target.expectedVersion }

type EscalationCommand struct {
	tenant   EntityID
	key      IdempotencyKey
	linkedAt time.Time
	relation RelationType
	reason   EscalationReason
	target   EscalationTarget
	sources  []EscalationSource
}

func NewEscalationCommand(
	tenant EntityID,
	key IdempotencyKey,
	linkedAt time.Time,
	relation RelationType,
	reason EscalationReason,
	target EscalationTarget,
	sources []EscalationSource,
) (EscalationCommand, error) {
	if !validEntityID(tenant) || !validIdempotencyKey(key) || !validInstant(linkedAt) ||
		!validRelationType(relation) || !validText(reason.value, maxEscalationReasonBytes, true) ||
		target.tenant != tenant || len(sources) == 0 || len(sources) > maxEscalationAlerts {
		return EscalationCommand{}, ErrInvalidEscalation
	}
	canonical := cloneEscalationSources(sources)
	slices.SortFunc(canonical, func(left, right EscalationSource) int {
		return compareEntityID(left.alert.id, right.alert.id)
	})
	seenLinks := make(map[EntityID]struct{}, len(canonical))
	for index, source := range canonical {
		if source.alert.tenant != tenant || source.alert.kind != AggregateAlert ||
			!validEntityID(source.linkID) || index > 0 && canonical[index-1].alert.id == source.alert.id {
			return EscalationCommand{}, ErrInvalidEscalation
		}
		if _, duplicate := seenLinks[source.linkID]; duplicate {
			return EscalationCommand{}, ErrInvalidEscalation
		}
		seenLinks[source.linkID] = struct{}{}
	}
	return EscalationCommand{
		tenant:   tenant,
		key:      key,
		linkedAt: linkedAt,
		relation: relation,
		reason:   reason,
		target:   target,
		sources:  canonical,
	}, nil
}

func (command EscalationCommand) String() string {
	return fmt.Sprintf("EscalationCommand{relation:%s,sources:%d,creates_case:%t,reason:[REDACTED],key:[REDACTED]}",
		command.relation, len(command.sources), command.target.create)
}

func (command EscalationCommand) GoString() string { return command.String() }

type AlertCaseLinkPlan struct {
	linkID             EntityID
	tenant             EntityID
	alert              EntityID
	caseID             EntityID
	linkedAt           time.Time
	linkedBy           EntityID
	relation           RelationType
	reason             EscalationReason
	copyFields         []CopyField
	customFields       []Key
	items              []CopyItemReference
	publicComments     []CommentReference
	sourceAlertVersion uint64
}

func (link AlertCaseLinkPlan) LinkID() EntityID           { return link.linkID }
func (link AlertCaseLinkPlan) Tenant() EntityID           { return link.tenant }
func (link AlertCaseLinkPlan) Alert() EntityID            { return link.alert }
func (link AlertCaseLinkPlan) Case() EntityID             { return link.caseID }
func (link AlertCaseLinkPlan) LinkedAt() time.Time        { return link.linkedAt }
func (link AlertCaseLinkPlan) LinkedBy() EntityID         { return link.linkedBy }
func (link AlertCaseLinkPlan) Relation() RelationType     { return link.relation }
func (link AlertCaseLinkPlan) Reason() EscalationReason   { return link.reason }
func (link AlertCaseLinkPlan) CopyFields() []CopyField    { return slices.Clone(link.copyFields) }
func (link AlertCaseLinkPlan) CustomFields() []Key        { return slices.Clone(link.customFields) }
func (link AlertCaseLinkPlan) Items() []CopyItemReference { return slices.Clone(link.items) }
func (link AlertCaseLinkPlan) PublicComments() []CommentReference {
	return slices.Clone(link.publicComments)
}
func (link AlertCaseLinkPlan) SourceAlertVersion() uint64 { return link.sourceAlertVersion }

func (link AlertCaseLinkPlan) String() string {
	return fmt.Sprintf("AlertCaseLinkPlan{relation:%s,source_version:%d,fields:%d,items:%d,comments:%d,reason:[REDACTED]}",
		link.relation, link.sourceAlertVersion, len(link.copyFields), len(link.items), len(link.publicComments))
}

func (link AlertCaseLinkPlan) GoString() string { return link.String() }

type EscalationPlan struct {
	tenant         EntityID
	actor          EntityID
	keyDigest      [sha256.Size]byte
	fingerprint    [sha256.Size]byte
	caseMutation   MutationPlan
	alertMutations []MutationPlan
	links          []AlertCaseLinkPlan
}

func (plan EscalationPlan) Tenant() EntityID               { return plan.tenant }
func (plan EscalationPlan) Actor() EntityID                { return plan.actor }
func (plan EscalationPlan) KeyDigest() [sha256.Size]byte   { return plan.keyDigest }
func (plan EscalationPlan) Fingerprint() [sha256.Size]byte { return plan.fingerprint }
func (plan EscalationPlan) CaseMutation() MutationPlan     { return plan.caseMutation }
func (plan EscalationPlan) AlertMutations() []MutationPlan { return slices.Clone(plan.alertMutations) }
func (plan EscalationPlan) Links() []AlertCaseLinkPlan     { return cloneLinkPlans(plan.links) }

func (plan EscalationPlan) String() string {
	return fmt.Sprintf("EscalationPlan{alerts:%d,links:%d,key:[REDACTED],fingerprint:[REDACTED]}",
		len(plan.alertMutations), len(plan.links))
}

func (plan EscalationPlan) GoString() string { return plan.String() }

func (plan EscalationPlan) ReplayIdentity() EscalationReplayIdentity {
	return EscalationReplayIdentity{
		tenant:      plan.tenant,
		actor:       plan.actor,
		keyDigest:   plan.keyDigest,
		fingerprint: plan.fingerprint,
	}
}

// EscalationReplayIdentity contains only the stable request identity. Server-
// generated case/link IDs and linkedAt are result metadata and deliberately do
// not participate, so a post-commit retry can match the original request.
type EscalationReplayIdentity struct {
	tenant      EntityID
	actor       EntityID
	keyDigest   [sha256.Size]byte
	fingerprint [sha256.Size]byte
}

func NewEscalationReplayIdentity(
	command EscalationCommand,
	authority AuthorizationSnapshot,
) (EscalationReplayIdentity, error) {
	if !validAuthorizationSnapshot(authority) || !authority.tenantAccess || authority.tenant != command.tenant ||
		authority.principal != PrincipalOperator || !authority.hasPermission(PermissionAlertEscalate) ||
		command.target.create && !authority.hasPermission(PermissionCaseCreate) ||
		!command.target.create && !authority.hasPermission(PermissionCaseUpdate) ||
		!validIdempotencyKey(command.key) || !validEntityID(command.tenant) ||
		!validRelationType(command.relation) || !validText(command.reason.value, maxEscalationReasonBytes, true) ||
		len(command.sources) == 0 || len(command.sources) > maxEscalationAlerts {
		return EscalationReplayIdentity{}, ErrInvalidEscalation
	}
	return EscalationReplayIdentity{
		tenant:      command.tenant,
		actor:       authority.actor,
		keyDigest:   command.key.digest,
		fingerprint: fingerprintEscalation(command, authority.actor),
	}, nil
}

func (identity EscalationReplayIdentity) Tenant() EntityID               { return identity.tenant }
func (identity EscalationReplayIdentity) Actor() EntityID                { return identity.actor }
func (identity EscalationReplayIdentity) KeyDigest() [sha256.Size]byte   { return identity.keyDigest }
func (identity EscalationReplayIdentity) Fingerprint() [sha256.Size]byte { return identity.fingerprint }
func (identity EscalationReplayIdentity) String() string {
	return "EscalationReplayIdentity{key:[REDACTED],fingerprint:[REDACTED]}"
}
func (identity EscalationReplayIdentity) GoString() string { return identity.String() }

type EscalationDecision struct {
	outcome DecisionOutcome
	reason  DecisionReason
	plan    EscalationPlan
}

func (decision EscalationDecision) Outcome() DecisionOutcome { return decision.outcome }
func (decision EscalationDecision) Reason() DecisionReason   { return decision.reason }
func (decision EscalationDecision) Allowed() bool            { return decision.outcome == OutcomeAllowed }
func (decision EscalationDecision) Plan() (EscalationPlan, bool) {
	return decision.plan, decision.outcome == OutcomeAllowed
}

func PlanEscalation(
	alertWorkflows []EscalationSourceWorkflow,
	caseWorkflow WorkflowDefinition,
	command EscalationCommand,
	authority AuthorizationSnapshot,
) EscalationDecision {
	if !validWorkflowDefinition(caseWorkflow) || caseWorkflow.kind != AggregateCase ||
		!validAuthorizationSnapshot(authority) || !validIdempotencyKey(command.key) ||
		!validInstant(command.linkedAt) || !validRelationType(command.relation) ||
		len(command.sources) == 0 || len(command.sources) > maxEscalationAlerts {
		return escalationDenied(ReasonInvalidSnapshot)
	}
	if !authority.tenantAccess || authority.tenant != command.tenant || command.target.tenant != command.tenant {
		return escalationDenied(ReasonTenantAccess)
	}
	if authority.principal != PrincipalOperator {
		return escalationDenied(ReasonPrincipalKind)
	}
	if !authority.hasPermission(PermissionAlertEscalate) {
		return escalationDenied(ReasonPermission)
	}
	if command.target.workflowID != caseWorkflow.id || command.target.workflowVersion != caseWorkflow.version {
		return escalationDenied(ReasonTargetMismatch)
	}
	workflowByAlert, workflowReason := escalationSourceWorkflowIndex(alertWorkflows, command.sources)
	if workflowReason != ReasonNone {
		return escalationDenied(workflowReason)
	}

	alertMutations := make([]MutationPlan, 0, len(command.sources))
	links := make([]AlertCaseLinkPlan, 0, len(command.sources))
	for _, source := range command.sources {
		alertWorkflow := workflowByAlert[source.alert.id]
		if !validEscalationSource(alertWorkflow, source) || source.alert.tenant != command.tenant {
			return escalationDenied(ReasonTargetMismatch)
		}
		if source.expectedVersion != source.alert.version {
			return escalationConflict(ReasonVersionConflict)
		}
		if source.alert.version == maxVersion {
			return escalationConflict(ReasonVersionExhausted)
		}
		state, exists := alertWorkflow.state(source.alert.state)
		if !exists {
			return escalationDenied(ReasonInvalidSnapshot)
		}
		effects, admitted := state.effectFor(ActionEscalate)
		if !admitted {
			return escalationDenied(ReasonWorkflowState)
		}
		decision := allowedExistingPlan(
			alertWorkflow,
			source.alert,
			authority.actor,
			ActionEscalate,
			source.alert.state,
			source.alert.assignment,
			effects,
		)
		mutation, _ := decision.Plan()
		alertMutations = append(alertMutations, mutation)
		links = append(links, AlertCaseLinkPlan{
			linkID:             source.linkID,
			tenant:             command.tenant,
			alert:              source.alert.id,
			caseID:             command.target.caseID,
			linkedAt:           command.linkedAt,
			linkedBy:           authority.actor,
			relation:           command.relation,
			reason:             command.reason,
			copyFields:         slices.Clone(source.copyFields),
			customFields:       slices.Clone(source.customFields),
			items:              slices.Clone(source.items),
			publicComments:     slices.Clone(source.publicComments),
			sourceAlertVersion: source.alert.version,
		})
	}

	caseMutation, caseDecision := planEscalationCase(caseWorkflow, command.target, authority)
	if caseDecision.outcome != 0 {
		return caseDecision
	}
	plan := EscalationPlan{
		tenant:         command.tenant,
		actor:          authority.actor,
		caseMutation:   caseMutation,
		alertMutations: alertMutations,
		links:          links,
	}
	identity, err := NewEscalationReplayIdentity(command, authority)
	if err != nil {
		return escalationDenied(ReasonInvalidSnapshot)
	}
	plan.keyDigest = identity.keyDigest
	plan.fingerprint = identity.fingerprint
	return EscalationDecision{outcome: OutcomeAllowed, reason: ReasonNone, plan: plan}
}

func escalationSourceWorkflowIndex(
	bindings []EscalationSourceWorkflow,
	sources []EscalationSource,
) (map[EntityID]WorkflowDefinition, DecisionReason) {
	if len(bindings) != len(sources) || len(bindings) == 0 || len(bindings) > maxEscalationAlerts {
		return nil, ReasonTargetMismatch
	}
	workflowByAlert := make(map[EntityID]WorkflowDefinition, len(bindings))
	for _, binding := range bindings {
		if !validEntityID(binding.alert) || !validWorkflowDefinition(binding.workflow) ||
			binding.workflow.kind != AggregateAlert {
			return nil, ReasonInvalidSnapshot
		}
		if _, duplicate := workflowByAlert[binding.alert]; duplicate {
			return nil, ReasonInvalidSnapshot
		}
		workflowByAlert[binding.alert] = binding.workflow
	}
	for _, source := range sources {
		workflow, exists := workflowByAlert[source.alert.id]
		if !exists || workflow.id != source.alert.workflowID || workflow.version != source.alert.workflowVersion {
			return nil, ReasonTargetMismatch
		}
	}
	return workflowByAlert, ReasonNone
}

func validEscalationSource(workflow WorkflowDefinition, source EscalationSource) bool {
	rebuilt, err := NewEscalationSource(
		workflow,
		source.linkID,
		source.alert,
		source.expectedVersion,
		source.copyFields,
		source.customFields,
		source.items,
		source.publicComments,
	)
	return err == nil && rebuilt.linkID == source.linkID && rebuilt.alert == source.alert &&
		rebuilt.expectedVersion == source.expectedVersion && slices.Equal(rebuilt.copyFields, source.copyFields) &&
		slices.Equal(rebuilt.customFields, source.customFields) && slices.Equal(rebuilt.items, source.items) &&
		slices.Equal(rebuilt.publicComments, source.publicComments)
}

func planEscalationCase(
	workflow WorkflowDefinition,
	target EscalationTarget,
	authority AuthorizationSnapshot,
) (MutationPlan, EscalationDecision) {
	if target.create {
		if !authority.hasPermission(PermissionCaseCreate) {
			return MutationPlan{}, escalationDenied(ReasonPermission)
		}
		command, err := NewCreateCommand(
			target.tenant,
			target.caseID,
			target.workflowID,
			target.workflowVersion,
			target.expectedVersion,
			target.customerVisible,
		)
		if err != nil {
			return MutationPlan{}, escalationDenied(ReasonInvalidSnapshot)
		}
		decision := PlanCreate(workflow, command, authority)
		if plan, allowed := decision.Plan(); allowed {
			return plan, EscalationDecision{}
		}
		return MutationPlan{}, EscalationDecision{outcome: decision.outcome, reason: decision.reason}
	}
	if !validTicketSnapshot(workflow, target.existing) || target.existing.id != target.caseID ||
		target.existing.tenant != target.tenant {
		return MutationPlan{}, escalationDenied(ReasonTargetMismatch)
	}
	if !authority.hasPermission(PermissionCaseUpdate) {
		return MutationPlan{}, escalationDenied(ReasonPermission)
	}
	if target.expectedVersion != target.existing.version {
		return MutationPlan{}, escalationConflict(ReasonVersionConflict)
	}
	if target.existing.version == maxVersion {
		return MutationPlan{}, escalationConflict(ReasonVersionExhausted)
	}
	state, exists := workflow.state(target.existing.state)
	if !exists {
		return MutationPlan{}, escalationDenied(ReasonInvalidSnapshot)
	}
	effects, admitted := state.effectFor(ActionLink)
	if !admitted {
		return MutationPlan{}, escalationDenied(ReasonWorkflowState)
	}
	decision := allowedExistingPlan(
		workflow,
		target.existing,
		authority.actor,
		ActionLink,
		target.existing.state,
		target.existing.assignment,
		effects,
	)
	plan, _ := decision.Plan()
	return plan, EscalationDecision{}
}

func escalationDenied(reason DecisionReason) EscalationDecision {
	return EscalationDecision{outcome: OutcomeDenied, reason: reason}
}

func escalationConflict(reason DecisionReason) EscalationDecision {
	return EscalationDecision{outcome: OutcomeConflict, reason: reason}
}

type ReplayOutcome uint8

const (
	ReplayExact ReplayOutcome = iota + 1
	ReplayConflict
)

// CompareEscalationReplay compares the full canonical request identity. Exact
// replay returns the prior result; payload drift under the same key conflicts.
func CompareEscalationReplay(prior, candidate EscalationPlan) ReplayOutcome {
	return CompareEscalationReplayIdentity(prior.ReplayIdentity(), candidate.ReplayIdentity())
}

func CompareEscalationReplayIdentity(prior, candidate EscalationReplayIdentity) ReplayOutcome {
	if validEscalationReplayIdentity(prior) && validEscalationReplayIdentity(candidate) &&
		prior == candidate {
		return ReplayExact
	}
	return ReplayConflict
}

func validEscalationReplayIdentity(identity EscalationReplayIdentity) bool {
	return validEntityID(identity.tenant) && validEntityID(identity.actor) &&
		identity.keyDigest != ([sha256.Size]byte{}) && identity.fingerprint != ([sha256.Size]byte{})
}

func canonicalCopyFields(values []CopyField) ([]CopyField, bool) {
	if len(values) > int(CopyPublicComments) {
		return nil, false
	}
	result := slices.Clone(values)
	for _, field := range result {
		if !validCopyField(field) {
			return nil, false
		}
	}
	slices.Sort(result)
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, false
		}
	}
	return result, true
}

func cloneEscalationSources(sources []EscalationSource) []EscalationSource {
	result := slices.Clone(sources)
	for index := range result {
		result[index].copyFields = slices.Clone(result[index].copyFields)
		result[index].customFields = slices.Clone(result[index].customFields)
		result[index].items = slices.Clone(result[index].items)
		result[index].publicComments = slices.Clone(result[index].publicComments)
	}
	return result
}

func cloneLinkPlans(links []AlertCaseLinkPlan) []AlertCaseLinkPlan {
	result := slices.Clone(links)
	for index := range result {
		result[index].copyFields = slices.Clone(result[index].copyFields)
		result[index].customFields = slices.Clone(result[index].customFields)
		result[index].items = slices.Clone(result[index].items)
		result[index].publicComments = slices.Clone(result[index].publicComments)
	}
	return result
}

func canonicalCopyItems(values []CopyItemReference) ([]CopyItemReference, bool) {
	if len(values) > maxCopiedItems {
		return nil, false
	}
	result := slices.Clone(values)
	for _, item := range result {
		if !copyFieldNeedsReferences(item.field) || !validEntityID(item.id) {
			return nil, false
		}
	}
	slices.SortFunc(result, func(left, right CopyItemReference) int {
		if left.field < right.field {
			return -1
		}
		if left.field > right.field {
			return 1
		}
		return compareEntityID(left.id, right.id)
	})
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, false
		}
	}
	return result, true
}

func canonicalCommentReferences(values []CommentReference) ([]CommentReference, bool) {
	if len(values) > maxCopiedItems {
		return nil, false
	}
	result := slices.Clone(values)
	for _, comment := range result {
		if !validEntityID(comment.id) || !validCommentVisibility(comment.visibility) {
			return nil, false
		}
	}
	slices.SortFunc(result, func(left, right CommentReference) int {
		return compareEntityID(left.id, right.id)
	})
	for index := 1; index < len(result); index++ {
		if result[index-1].id == result[index].id {
			return nil, false
		}
	}
	return result, true
}

func hasCopyField(fields []CopyField, target CopyField) bool {
	_, found := slices.BinarySearch(fields, target)
	return found
}

func fingerprintEscalation(command EscalationCommand, actor EntityID) [sha256.Size]byte {
	var payload bytes.Buffer
	writeEntityID(&payload, command.tenant)
	writeEntityID(&payload, actor)
	if !command.target.create {
		writeEntityID(&payload, command.target.caseID)
	}
	writeEntityID(&payload, command.target.workflowID)
	writeUint64(&payload, command.target.workflowVersion)
	writeUint64(&payload, command.target.expectedVersion)
	payload.WriteByte(byte(command.target.createAsByte()))
	if command.target.create {
		payload.WriteByte(byte(command.target.customerVisibleAsByte()))
	}
	payload.WriteByte(byte(command.relation))
	writeString(&payload, command.reason.value)
	writeUint64(&payload, uint64(len(command.sources)))
	for _, source := range command.sources {
		writeEntityID(&payload, source.alert.id)
		writeEntityID(&payload, source.alert.workflowID)
		writeUint64(&payload, source.alert.workflowVersion)
		writeUint64(&payload, source.expectedVersion)
		writeUint64(&payload, uint64(len(source.copyFields)))
		for _, field := range source.copyFields {
			payload.WriteByte(byte(field))
		}
		writeUint64(&payload, uint64(len(source.customFields)))
		for _, field := range source.customFields {
			writeString(&payload, field.value)
		}
		writeUint64(&payload, uint64(len(source.items)))
		for _, item := range source.items {
			payload.WriteByte(byte(item.field))
			writeEntityID(&payload, item.id)
		}
		writeUint64(&payload, uint64(len(source.publicComments)))
		for _, comment := range source.publicComments {
			writeEntityID(&payload, comment.id)
			payload.WriteByte(byte(comment.visibility))
		}
	}
	return sha256.Sum256(payload.Bytes())
}

func (target EscalationTarget) createAsByte() uint8 {
	if target.create {
		return 1
	}
	return 0
}

func (target EscalationTarget) customerVisibleAsByte() uint8 {
	if target.customerVisible {
		return 1
	}
	return 0
}

func writeEntityID(buffer *bytes.Buffer, id EntityID) {
	buffer.Write(id.value[:])
}

func writeUint64(buffer *bytes.Buffer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	buffer.Write(encoded[:])
}

func writeString(buffer *bytes.Buffer, value string) {
	writeUint64(buffer, uint64(len(value)))
	buffer.WriteString(value)
}
