package httpserver

import (
	"context"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

// unavailableAlertInvestigationService keeps older focused transport fixtures
// fail-closed while the production composition always supplies the real Alert
// investigation service.
type unavailableAlertInvestigationService struct{}

func (unavailableAlertInvestigationService) Workspace(context.Context, application.Actor, uuid.UUID, kernel.EntityID) (application.AlertInvestigationWorkspace, error) {
	return application.AlertInvestigationWorkspace{}, application.ErrUnavailable
}

func (unavailableAlertInvestigationService) CollectEvidence(context.Context, application.Actor, uuid.UUID, application.AlertEvidenceCollectCommand) (application.MutationResult[kernel.AlertEvidence], error) {
	return application.MutationResult[kernel.AlertEvidence]{}, application.ErrUnavailable
}

func (unavailableAlertInvestigationService) AppendCustody(context.Context, application.Actor, uuid.UUID, application.AlertCustodyCommand) (application.MutationResult[kernel.AlertEvidence], error) {
	return application.MutationResult[kernel.AlertEvidence]{}, application.ErrUnavailable
}

func (unavailableAlertInvestigationService) CreateTask(context.Context, application.Actor, uuid.UUID, application.AlertTaskCreateCommand) (application.MutationResult[kernel.AlertTask], error) {
	return application.MutationResult[kernel.AlertTask]{}, application.ErrUnavailable
}

func (unavailableAlertInvestigationService) TransitionTask(context.Context, application.Actor, uuid.UUID, application.AlertTaskTransitionCommand) (application.MutationResult[kernel.AlertTask], error) {
	return application.MutationResult[kernel.AlertTask]{}, application.ErrUnavailable
}

func (unavailableAlertInvestigationService) ReplaceTaskDetails(context.Context, application.Actor, uuid.UUID, application.AlertTaskDetailsCommand) (application.MutationResult[kernel.AlertTask], error) {
	return application.MutationResult[kernel.AlertTask]{}, application.ErrUnavailable
}

func (unavailableAlertInvestigationService) AssignTask(context.Context, application.Actor, uuid.UUID, application.AlertTaskAssignmentCommand) (application.MutationResult[kernel.AlertTask], error) {
	return application.MutationResult[kernel.AlertTask]{}, application.ErrUnavailable
}

func (unavailableAlertInvestigationService) RescheduleTask(context.Context, application.Actor, uuid.UUID, application.AlertTaskDueDateCommand) (application.MutationResult[kernel.AlertTask], error) {
	return application.MutationResult[kernel.AlertTask]{}, application.ErrUnavailable
}

func (unavailableAlertInvestigationService) ReplaceTaskChecklist(context.Context, application.Actor, uuid.UUID, application.AlertTaskChecklistCommand) (application.MutationResult[kernel.AlertTask], error) {
	return application.MutationResult[kernel.AlertTask]{}, application.ErrUnavailable
}

func (unavailableAlertInvestigationService) ReplaceTaskComments(context.Context, application.Actor, uuid.UUID, application.AlertTaskCommentsCommand) (application.MutationResult[kernel.AlertTask], error) {
	return application.MutationResult[kernel.AlertTask]{}, application.ErrUnavailable
}

func (unavailableAlertInvestigationService) CreateRelationship(context.Context, application.Actor, uuid.UUID, application.AlertRelationshipCreateCommand) (application.MutationResult[kernel.AlertRelationship], error) {
	return application.MutationResult[kernel.AlertRelationship]{}, application.ErrUnavailable
}

func (unavailableAlertInvestigationService) RetractRelationship(context.Context, application.Actor, uuid.UUID, application.AlertRelationshipRetractCommand) (application.MutationResult[kernel.AlertRelationship], error) {
	return application.MutationResult[kernel.AlertRelationship]{}, application.ErrUnavailable
}

var _ AlertInvestigationService = unavailableAlertInvestigationService{}
