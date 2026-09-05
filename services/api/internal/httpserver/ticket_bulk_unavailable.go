package httpserver

import (
	"context"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

// unavailableTicketBulkService keeps rolling replicas fail closed until the
// durable materialization, worker, and audit ABI is fully wired.
type unavailableTicketBulkService struct{}

func (unavailableTicketBulkService) Request(context.Context, application.Actor, uuid.UUID, kernel.AggregateKind, application.TicketBulkRequestInput) (application.TicketBulkResult, error) {
	return application.TicketBulkResult{}, application.ErrUnavailable
}

func (unavailableTicketBulkService) Get(context.Context, application.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID) (application.TicketBulkRecord, error) {
	return application.TicketBulkRecord{}, application.ErrUnavailable
}

func (unavailableTicketBulkService) Cancel(context.Context, application.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, application.TicketBulkCancelInput) (application.TicketBulkResult, error) {
	return application.TicketBulkResult{}, application.ErrUnavailable
}

func (unavailableTicketBulkService) ListResults(context.Context, application.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, application.TicketBulkResultListInput) (application.TicketBulkResultPage, error) {
	return application.TicketBulkResultPage{}, application.ErrUnavailable
}
