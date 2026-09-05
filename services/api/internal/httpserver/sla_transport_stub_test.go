package httpserver

import (
	"context"

	"github.com/google/uuid"

	kernel "github.com/periapsis-im/periapsis/modules/sla"
	applicationsla "github.com/periapsis-im/periapsis/services/api/internal/sla"
)

type transportSLAStub struct {
	listCalendars   func(context.Context, applicationsla.Actor, uuid.UUID, applicationsla.ConfigurationListInput) (applicationsla.CalendarPage, error)
	getCalendar     func(context.Context, applicationsla.Actor, uuid.UUID, kernel.EntityID) (applicationsla.CalendarRecord, error)
	publishCalendar func(context.Context, applicationsla.Actor, uuid.UUID, applicationsla.CalendarPublishCommand) (applicationsla.PublicationResult[kernel.BusinessCalendar], error)
	listPolicies    func(context.Context, applicationsla.Actor, uuid.UUID, applicationsla.ConfigurationListInput) (applicationsla.PolicyPage, error)
	getPolicy       func(context.Context, applicationsla.Actor, uuid.UUID, kernel.EntityID) (applicationsla.PolicyRecord, error)
	publishPolicy   func(context.Context, applicationsla.Actor, uuid.UUID, applicationsla.PolicyPublishCommand) (applicationsla.PublicationResult[kernel.Policy], error)
	listColumns     func(context.Context, applicationsla.Actor, uuid.UUID, applicationsla.ConfigurationListInput) (applicationsla.ColumnPage, error)
	getColumn       func(context.Context, applicationsla.Actor, uuid.UUID, kernel.EntityID) (applicationsla.ColumnRecord, error)
	publishColumn   func(context.Context, applicationsla.Actor, uuid.UUID, applicationsla.ColumnPublishCommand) (applicationsla.PublicationResult[kernel.ColumnDefinition], error)
	archive         func(context.Context, applicationsla.Actor, uuid.UUID, applicationsla.ArchiveCommand) (uint64, bool, error)
	simulate        func(context.Context, applicationsla.Actor, uuid.UUID, applicationsla.SimulationCommand) (applicationsla.SimulationResult, error)
	projectObject   func(context.Context, applicationsla.Actor, uuid.UUID, applicationsla.ObjectProjectionCommand) (applicationsla.ObjectProjection, error)
	override        func(context.Context, applicationsla.Actor, uuid.UUID, applicationsla.OverrideRequest) (applicationsla.OverrideResult, error)
}

func (s *transportSLAStub) ListCalendars(ctx context.Context, actor applicationsla.Actor, tenantID uuid.UUID, input applicationsla.ConfigurationListInput) (applicationsla.CalendarPage, error) {
	if s != nil && s.listCalendars != nil {
		return s.listCalendars(ctx, actor, tenantID, input)
	}
	return applicationsla.CalendarPage{}, applicationsla.ErrUnavailable
}

func (s *transportSLAStub) GetCalendar(ctx context.Context, actor applicationsla.Actor, tenantID uuid.UUID, id kernel.EntityID) (applicationsla.CalendarRecord, error) {
	if s != nil && s.getCalendar != nil {
		return s.getCalendar(ctx, actor, tenantID, id)
	}
	return applicationsla.CalendarRecord{}, applicationsla.ErrUnavailable
}

func (s *transportSLAStub) PublishCalendar(ctx context.Context, actor applicationsla.Actor, tenantID uuid.UUID, command applicationsla.CalendarPublishCommand) (applicationsla.PublicationResult[kernel.BusinessCalendar], error) {
	if s != nil && s.publishCalendar != nil {
		return s.publishCalendar(ctx, actor, tenantID, command)
	}
	return applicationsla.PublicationResult[kernel.BusinessCalendar]{}, applicationsla.ErrUnavailable
}

func (s *transportSLAStub) ListPolicies(ctx context.Context, actor applicationsla.Actor, tenantID uuid.UUID, input applicationsla.ConfigurationListInput) (applicationsla.PolicyPage, error) {
	if s != nil && s.listPolicies != nil {
		return s.listPolicies(ctx, actor, tenantID, input)
	}
	return applicationsla.PolicyPage{}, applicationsla.ErrUnavailable
}

func (s *transportSLAStub) GetPolicy(ctx context.Context, actor applicationsla.Actor, tenantID uuid.UUID, id kernel.EntityID) (applicationsla.PolicyRecord, error) {
	if s != nil && s.getPolicy != nil {
		return s.getPolicy(ctx, actor, tenantID, id)
	}
	return applicationsla.PolicyRecord{}, applicationsla.ErrUnavailable
}

func (s *transportSLAStub) PublishPolicy(ctx context.Context, actor applicationsla.Actor, tenantID uuid.UUID, command applicationsla.PolicyPublishCommand) (applicationsla.PublicationResult[kernel.Policy], error) {
	if s != nil && s.publishPolicy != nil {
		return s.publishPolicy(ctx, actor, tenantID, command)
	}
	return applicationsla.PublicationResult[kernel.Policy]{}, applicationsla.ErrUnavailable
}

func (s *transportSLAStub) ListColumns(ctx context.Context, actor applicationsla.Actor, tenantID uuid.UUID, input applicationsla.ConfigurationListInput) (applicationsla.ColumnPage, error) {
	if s != nil && s.listColumns != nil {
		return s.listColumns(ctx, actor, tenantID, input)
	}
	return applicationsla.ColumnPage{}, applicationsla.ErrUnavailable
}

func (s *transportSLAStub) GetColumn(ctx context.Context, actor applicationsla.Actor, tenantID uuid.UUID, id kernel.EntityID) (applicationsla.ColumnRecord, error) {
	if s != nil && s.getColumn != nil {
		return s.getColumn(ctx, actor, tenantID, id)
	}
	return applicationsla.ColumnRecord{}, applicationsla.ErrUnavailable
}

func (s *transportSLAStub) PublishColumn(ctx context.Context, actor applicationsla.Actor, tenantID uuid.UUID, command applicationsla.ColumnPublishCommand) (applicationsla.PublicationResult[kernel.ColumnDefinition], error) {
	if s != nil && s.publishColumn != nil {
		return s.publishColumn(ctx, actor, tenantID, command)
	}
	return applicationsla.PublicationResult[kernel.ColumnDefinition]{}, applicationsla.ErrUnavailable
}

func (s *transportSLAStub) Archive(ctx context.Context, actor applicationsla.Actor, tenantID uuid.UUID, command applicationsla.ArchiveCommand) (uint64, bool, error) {
	if s != nil && s.archive != nil {
		return s.archive(ctx, actor, tenantID, command)
	}
	return 0, false, applicationsla.ErrUnavailable
}

func (s *transportSLAStub) Simulate(ctx context.Context, actor applicationsla.Actor, tenantID uuid.UUID, command applicationsla.SimulationCommand) (applicationsla.SimulationResult, error) {
	if s != nil && s.simulate != nil {
		return s.simulate(ctx, actor, tenantID, command)
	}
	return applicationsla.SimulationResult{}, applicationsla.ErrUnavailable
}

func (s *transportSLAStub) ProjectObject(ctx context.Context, actor applicationsla.Actor, tenantID uuid.UUID, command applicationsla.ObjectProjectionCommand) (applicationsla.ObjectProjection, error) {
	if s != nil && s.projectObject != nil {
		return s.projectObject(ctx, actor, tenantID, command)
	}
	return applicationsla.ObjectProjection{}, applicationsla.ErrUnavailable
}

func (s *transportSLAStub) Override(ctx context.Context, actor applicationsla.Actor, tenantID uuid.UUID, request applicationsla.OverrideRequest) (applicationsla.OverrideResult, error) {
	if s != nil && s.override != nil {
		return s.override(ctx, actor, tenantID, request)
	}
	return applicationsla.OverrideResult{}, applicationsla.ErrUnavailable
}
