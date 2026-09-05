package httpserver

import (
	"context"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

// unavailableAsyncExportService keeps rolling replicas fail closed when the
// tenant RLS repository or private object storage is not configured.
type unavailableAsyncExportService struct{}

func (unavailableAsyncExportService) Request(
	context.Context,
	application.Actor,
	uuid.UUID,
	kernel.AggregateKind,
	application.AsyncExportRequestInput,
) (application.AsyncExportResult, error) {
	return application.AsyncExportResult{}, application.ErrUnavailable
}

func (unavailableAsyncExportService) Get(
	context.Context,
	application.Actor,
	uuid.UUID,
	kernel.AggregateKind,
	kernel.TicketExportAudience,
	uuid.UUID,
) (application.AsyncExportRecord, error) {
	return application.AsyncExportRecord{}, application.ErrUnavailable
}

func (unavailableAsyncExportService) Cancel(
	context.Context,
	application.Actor,
	uuid.UUID,
	kernel.AggregateKind,
	kernel.TicketExportAudience,
	uuid.UUID,
	application.AsyncExportCancelInput,
) (application.AsyncExportResult, error) {
	return application.AsyncExportResult{}, application.ErrUnavailable
}

func (unavailableAsyncExportService) PrepareDownload(
	context.Context,
	application.Actor,
	uuid.UUID,
	kernel.AggregateKind,
	kernel.TicketExportAudience,
	uuid.UUID,
) (application.AsyncExportPreparedDownload, error) {
	return application.AsyncExportPreparedDownload{}, application.ErrUnavailable
}
