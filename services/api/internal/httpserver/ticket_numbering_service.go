package httpserver

import (
	"context"
	"reflect"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/ticketnumbering"
)

// TicketNumberingService is the session-only tenant administration boundary
// for immutable Alert and Case numbering policies. Number allocation itself is
// kept inside the database transaction that creates the ticket.
type TicketNumberingService interface {
	Get(context.Context, authentication.Session, uuid.UUID, kernel.AggregateKind) (kernel.NumberingPolicy, error)
	Preview(context.Context, authentication.Session, uuid.UUID, kernel.AggregateKind, ticketnumbering.PolicyDraft) (ticketnumbering.Preview, error)
	Replace(context.Context, authentication.Session, uuid.UUID, kernel.AggregateKind, ticketnumbering.ReplaceInput) (ticketnumbering.ReplaceResult, error)
}

type unavailableTicketNumberingService struct{}

func (unavailableTicketNumberingService) Get(
	context.Context,
	authentication.Session,
	uuid.UUID,
	kernel.AggregateKind,
) (kernel.NumberingPolicy, error) {
	return kernel.NumberingPolicy{}, ticketnumbering.ErrUnavailable
}

func (unavailableTicketNumberingService) Preview(
	context.Context,
	authentication.Session,
	uuid.UUID,
	kernel.AggregateKind,
	ticketnumbering.PolicyDraft,
) (ticketnumbering.Preview, error) {
	return ticketnumbering.Preview{}, ticketnumbering.ErrUnavailable
}

func (unavailableTicketNumberingService) Replace(
	context.Context,
	authentication.Session,
	uuid.UUID,
	kernel.AggregateKind,
	ticketnumbering.ReplaceInput,
) (ticketnumbering.ReplaceResult, error) {
	return ticketnumbering.ReplaceResult{}, ticketnumbering.ErrUnavailable
}

func ticketNumberingServiceIsNil(service TicketNumberingService) bool {
	if service == nil {
		return true
	}
	value := reflect.ValueOf(service)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

var _ TicketNumberingService = unavailableTicketNumberingService{}
