package httpserver

import (
	"context"

	"github.com/google/uuid"
	customfieldkernel "github.com/periapsis-im/periapsis/modules/customfields"
	dfirkernel "github.com/periapsis-im/periapsis/modules/dfir"
	applicationcustomfields "github.com/periapsis-im/periapsis/services/api/internal/customfields"
	applicationdfir "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

// The shared transport fixtures use fail-closed Phase 4 boundaries unless a
// focused test supplies a purpose-built service. Production construction still
// rejects missing services.
type transportCustomFieldStub struct{}

func (*transportCustomFieldStub) ListDefinitions(context.Context, applicationcustomfields.Actor, uuid.UUID, applicationcustomfields.DefinitionListInput) (applicationcustomfields.DefinitionPage, error) {
	return applicationcustomfields.DefinitionPage{}, applicationcustomfields.ErrUnavailable
}

func (*transportCustomFieldStub) GetDefinition(context.Context, applicationcustomfields.Actor, uuid.UUID, customfieldkernel.ObjectType, customfieldkernel.EntityID) (customfieldkernel.Definition, error) {
	return customfieldkernel.Definition{}, applicationcustomfields.ErrUnavailable
}

func (*transportCustomFieldStub) CreateDefinition(context.Context, applicationcustomfields.Actor, uuid.UUID, applicationcustomfields.CreateDefinitionInput) (applicationcustomfields.DefinitionResult, error) {
	return applicationcustomfields.DefinitionResult{}, applicationcustomfields.ErrUnavailable
}

func (*transportCustomFieldStub) ReplaceDefinition(context.Context, applicationcustomfields.Actor, uuid.UUID, customfieldkernel.EntityID, applicationcustomfields.ReplaceDefinitionInput) (applicationcustomfields.DefinitionResult, error) {
	return applicationcustomfields.DefinitionResult{}, applicationcustomfields.ErrUnavailable
}

func (*transportCustomFieldStub) ArchiveDefinition(context.Context, applicationcustomfields.Actor, uuid.UUID, customfieldkernel.ObjectType, customfieldkernel.EntityID, applicationcustomfields.ArchiveDefinitionInput) (applicationcustomfields.DefinitionResult, error) {
	return applicationcustomfields.DefinitionResult{}, applicationcustomfields.ErrUnavailable
}

func (*transportCustomFieldStub) ValidateAndCommitObjectFields(context.Context, applicationcustomfields.Actor, uuid.UUID, applicationcustomfields.ObjectWriteInput) (applicationcustomfields.ObjectWriteResult, error) {
	return applicationcustomfields.ObjectWriteResult{}, applicationcustomfields.ErrUnavailable
}

func (*transportCustomFieldStub) ProjectObjectFields(context.Context, applicationcustomfields.Actor, uuid.UUID, applicationcustomfields.ProjectionInput) (applicationcustomfields.Projection, error) {
	return applicationcustomfields.Projection{}, applicationcustomfields.ErrUnavailable
}

type transportDFIRStub struct{}

func (*transportDFIRStub) Workspace(context.Context, applicationdfir.Actor, uuid.UUID, dfirkernel.EntityID) (applicationdfir.Workspace, error) {
	return applicationdfir.Workspace{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) AlertWorkspace(context.Context, applicationdfir.Actor, uuid.UUID, dfirkernel.EntityID) (applicationdfir.AlertWorkspace, error) {
	return applicationdfir.AlertWorkspace{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) CreateIndicator(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.IndicatorCommand) (applicationdfir.MutationResult[dfirkernel.Indicator], error) {
	return applicationdfir.MutationResult[dfirkernel.Indicator]{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) ReplaceIndicator(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.IndicatorCommand) (applicationdfir.MutationResult[dfirkernel.Indicator], error) {
	return applicationdfir.MutationResult[dfirkernel.Indicator]{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) CreateAlertIndicator(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertIndicatorCommand) (applicationdfir.MutationResult[dfirkernel.Indicator], error) {
	return applicationdfir.MutationResult[dfirkernel.Indicator]{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) ReplaceAlertIndicator(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertIndicatorCommand) (applicationdfir.MutationResult[dfirkernel.Indicator], error) {
	return applicationdfir.MutationResult[dfirkernel.Indicator]{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) CreateAsset(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AssetCommand) (applicationdfir.MutationResult[dfirkernel.Asset], error) {
	return applicationdfir.MutationResult[dfirkernel.Asset]{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) ReplaceAsset(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AssetCommand) (applicationdfir.MutationResult[dfirkernel.Asset], error) {
	return applicationdfir.MutationResult[dfirkernel.Asset]{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) CreateAlertAsset(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertAssetCommand) (applicationdfir.MutationResult[dfirkernel.Asset], error) {
	return applicationdfir.MutationResult[dfirkernel.Asset]{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) ReplaceAlertAsset(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertAssetCommand) (applicationdfir.MutationResult[dfirkernel.Asset], error) {
	return applicationdfir.MutationResult[dfirkernel.Asset]{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) CreateTimelineEvent(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.TimelineCommand) (applicationdfir.MutationResult[dfirkernel.TimelineEvent], error) {
	return applicationdfir.MutationResult[dfirkernel.TimelineEvent]{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) CreateAlertTimelineEvent(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertTimelineCommand) (applicationdfir.MutationResult[dfirkernel.TimelineEvent], error) {
	return applicationdfir.MutationResult[dfirkernel.TimelineEvent]{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) CreateTask(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.TaskCreateCommand) (applicationdfir.MutationResult[dfirkernel.Task], error) {
	return applicationdfir.MutationResult[dfirkernel.Task]{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) TransitionTask(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.TaskTransitionCommand) (applicationdfir.MutationResult[dfirkernel.Task], error) {
	return applicationdfir.MutationResult[dfirkernel.Task]{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) ReplaceTaskDetails(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.TaskDetailsCommand) (applicationdfir.MutationResult[dfirkernel.Task], error) {
	return applicationdfir.MutationResult[dfirkernel.Task]{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) AssignTask(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.TaskAssignmentCommand) (applicationdfir.MutationResult[dfirkernel.Task], error) {
	return applicationdfir.MutationResult[dfirkernel.Task]{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) RescheduleTask(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.TaskDueDateCommand) (applicationdfir.MutationResult[dfirkernel.Task], error) {
	return applicationdfir.MutationResult[dfirkernel.Task]{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) ReplaceTaskChecklist(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.TaskChecklistCommand) (applicationdfir.MutationResult[dfirkernel.Task], error) {
	return applicationdfir.MutationResult[dfirkernel.Task]{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) ReplaceTaskComments(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.TaskCommentsCommand) (applicationdfir.MutationResult[dfirkernel.Task], error) {
	return applicationdfir.MutationResult[dfirkernel.Task]{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) CreateRelationship(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.RelationshipCommand) (applicationdfir.MutationResult[dfirkernel.Relationship], error) {
	return applicationdfir.MutationResult[dfirkernel.Relationship]{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) RetractRelationship(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.RelationshipRetractCommand) (applicationdfir.MutationResult[dfirkernel.Relationship], error) {
	return applicationdfir.MutationResult[dfirkernel.Relationship]{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) PrepareUpload(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.PrepareUploadCommand) (applicationdfir.PreparedUpload, error) {
	return applicationdfir.PreparedUpload{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) PrepareDownload(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.DownloadCommand) (applicationdfir.PreparedDownload, error) {
	return applicationdfir.PreparedDownload{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) PrepareAlertUpload(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertPrepareUploadCommand) (applicationdfir.PreparedUpload, error) {
	return applicationdfir.PreparedUpload{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) PrepareAlertDownload(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertDownloadCommand) (applicationdfir.PreparedDownload, error) {
	return applicationdfir.PreparedDownload{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) CollectEvidence(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.EvidenceCommand) (applicationdfir.MutationResult[dfirkernel.Evidence], error) {
	return applicationdfir.MutationResult[dfirkernel.Evidence]{}, applicationdfir.ErrUnavailable
}

func (*transportDFIRStub) AppendCustody(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.CustodyCommand) (applicationdfir.MutationResult[dfirkernel.Evidence], error) {
	return applicationdfir.MutationResult[dfirkernel.Evidence]{}, applicationdfir.ErrUnavailable
}
