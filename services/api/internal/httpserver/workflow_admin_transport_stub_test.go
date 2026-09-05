package httpserver

import (
	"context"

	"github.com/google/uuid"
	applicationticketing "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

// transportWorkflowAdministrationStub keeps the shared HTTP fixture explicit:
// workflow administration is a required application boundary, even in tests
// that do not exercise one of its routes.
type transportWorkflowAdministrationStub struct{}

func (*transportWorkflowAdministrationStub) ListWorkflows(context.Context, applicationticketing.Actor, uuid.UUID, applicationticketing.WorkflowAdminListInput) (applicationticketing.WorkflowAdminPage, error) {
	return applicationticketing.WorkflowAdminPage{}, applicationticketing.ErrUnavailable
}

func (*transportWorkflowAdministrationStub) GetWorkflow(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID) (applicationticketing.WorkflowAdminRecord, error) {
	return applicationticketing.WorkflowAdminRecord{}, applicationticketing.ErrUnavailable
}

func (*transportWorkflowAdministrationStub) ListWorkflowVersions(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.WorkflowVersionListInput) (applicationticketing.WorkflowVersionPage, error) {
	return applicationticketing.WorkflowVersionPage{}, applicationticketing.ErrUnavailable
}

func (*transportWorkflowAdministrationStub) GetWorkflowVersion(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, uint64) (applicationticketing.WorkflowVersionRecord, error) {
	return applicationticketing.WorkflowVersionRecord{}, applicationticketing.ErrUnavailable
}

func (*transportWorkflowAdministrationStub) SimulateWorkflow(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.WorkflowSimulationInput) (applicationticketing.WorkflowSimulationResult, error) {
	return applicationticketing.WorkflowSimulationResult{}, applicationticketing.ErrUnavailable
}

func (*transportWorkflowAdministrationStub) CreateWorkflow(context.Context, applicationticketing.Actor, uuid.UUID, applicationticketing.WorkflowCreateInput) (applicationticketing.WorkflowAdminMutationResult, error) {
	return applicationticketing.WorkflowAdminMutationResult{}, applicationticketing.ErrUnavailable
}

func (*transportWorkflowAdministrationStub) PublishWorkflow(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.WorkflowPublishInput) (applicationticketing.WorkflowAdminMutationResult, error) {
	return applicationticketing.WorkflowAdminMutationResult{}, applicationticketing.ErrUnavailable
}

func (*transportWorkflowAdministrationStub) UpdateWorkflowMetadata(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.WorkflowMetadataInput) (applicationticketing.WorkflowAdminMutationResult, error) {
	return applicationticketing.WorkflowAdminMutationResult{}, applicationticketing.ErrUnavailable
}

func (*transportWorkflowAdministrationStub) SetDefaultWorkflow(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.WorkflowLifecycleInput) (applicationticketing.WorkflowAdminMutationResult, error) {
	return applicationticketing.WorkflowAdminMutationResult{}, applicationticketing.ErrUnavailable
}

func (*transportWorkflowAdministrationStub) ArchiveWorkflow(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.WorkflowLifecycleInput) (applicationticketing.WorkflowAdminMutationResult, error) {
	return applicationticketing.WorkflowAdminMutationResult{}, applicationticketing.ErrUnavailable
}

func (*transportWorkflowAdministrationStub) RestoreWorkflow(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.WorkflowLifecycleInput) (applicationticketing.WorkflowAdminMutationResult, error) {
	return applicationticketing.WorkflowAdminMutationResult{}, applicationticketing.ErrUnavailable
}
