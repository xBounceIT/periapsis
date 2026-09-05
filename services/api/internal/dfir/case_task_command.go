package dfir

import kernel "github.com/periapsis-im/periapsis/modules/dfir"

type taskMutationEffects struct {
	action  string
	summary string
}

func taskEffects(operation string) (taskMutationEffects, bool) {
	switch operation {
	case operationTaskCreate:
		return taskMutationEffects{action: "dfir.task.created", summary: "DFIR task created"}, true
	case operationTaskTransition:
		return taskMutationEffects{action: "dfir.task.transitioned", summary: "DFIR task transitioned"}, true
	case operationTaskReplaceDetails:
		return taskMutationEffects{action: "dfir.task.details_replaced", summary: "DFIR task details replaced"}, true
	case operationTaskAssign:
		return taskMutationEffects{action: "dfir.task.assigned", summary: "DFIR task assignment changed"}, true
	case operationTaskReschedule:
		return taskMutationEffects{action: "dfir.task.rescheduled", summary: "DFIR task due date changed"}, true
	case operationTaskChecklist:
		return taskMutationEffects{action: "dfir.task.checklist_replaced", summary: "DFIR task checklist replaced"}, true
	case operationTaskComments:
		return taskMutationEffects{action: "dfir.task.comments_replaced", summary: "DFIR task comments replaced"}, true
	default:
		return taskMutationEffects{}, false
	}
}

func newTaskMutationContract(
	actor Actor,
	caseID kernel.EntityID,
	envelope MutationEnvelope,
	access Access,
	operation string,
	auditReason string,
	request any,
) (TaskMutationContract, error) {
	effects, ok := taskEffects(operation)
	if !ok || !validSingleLine(auditReason, 2_000, false) {
		return TaskMutationContract{}, ErrInvalidInput
	}
	base, err := baseWrite(actor, caseID, envelope, operation, map[string]any{
		"caseId":  caseID.String(),
		"request": request,
	})
	if err != nil {
		return TaskMutationContract{}, err
	}
	return TaskMutationContract{
		BaseWrite: base, Access: access, Capability: CapabilityTaskManage,
		ActivityType: effects.action, ActivitySummary: effects.summary, AuditAction: effects.action,
		AuditReason: auditReason, OutboxEventType: effects.action,
	}, nil
}

// ValidTaskMutationContract lets adapters enforce the application-owned
// operation/effect allowlist without duplicating it.
func ValidTaskMutationContract(contract TaskMutationContract, operation string) bool {
	effects, ok := taskEffects(operation)
	return ok && contract.Command.Operation == operation && contract.CaseID != (kernel.EntityID{}) &&
		contract.Capability == CapabilityTaskManage && contract.ActivityType == effects.action &&
		contract.ActivitySummary == effects.summary &&
		contract.AuditAction == effects.action && contract.OutboxEventType == effects.action &&
		validSingleLine(contract.AuditReason, 2_000, false)
}
