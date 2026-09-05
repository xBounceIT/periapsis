package httpserver

import (
	"context"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

// unavailableSavedViewService keeps rolling replicas fail closed while the
// append-only database ABI or composition wiring is absent. It stores and
// serves no data and cannot be mistaken for an in-memory fallback.
type unavailableSavedViewService struct{}

func (unavailableSavedViewService) ListSavedViews(context.Context, application.Actor, uuid.UUID, kernel.AggregateKind, application.SavedViewListInput) (application.SavedViewPage, error) {
	return application.SavedViewPage{}, application.ErrUnavailable
}
func (unavailableSavedViewService) GetSavedView(context.Context, application.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID) (application.SavedViewRecord, error) {
	return application.SavedViewRecord{}, application.ErrUnavailable
}
func (unavailableSavedViewService) CreateSavedView(context.Context, application.Actor, uuid.UUID, kernel.AggregateKind, application.SavedViewCreateInput) (application.SavedViewMutationResult, error) {
	return application.SavedViewMutationResult{}, application.ErrUnavailable
}
func (unavailableSavedViewService) ReplaceSavedView(context.Context, application.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, application.SavedViewReplaceInput) (application.SavedViewMutationResult, error) {
	return application.SavedViewMutationResult{}, application.ErrUnavailable
}
func (unavailableSavedViewService) ArchiveSavedView(context.Context, application.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, application.SavedViewLifecycleInput) (application.SavedViewMutationResult, error) {
	return application.SavedViewMutationResult{}, application.ErrUnavailable
}
func (unavailableSavedViewService) RestoreSavedView(context.Context, application.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, application.SavedViewLifecycleInput) (application.SavedViewMutationResult, error) {
	return application.SavedViewMutationResult{}, application.ErrUnavailable
}
