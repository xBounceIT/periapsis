package sla

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
)

const maximumRequestDeadline = 30 * time.Second

type Service struct {
	repository Repository
	clock      func() time.Time
}

func NewService(repository Repository, clock func() time.Time) (*Service, error) {
	if repository == nil || clock == nil {
		return nil, errors.New("SLA repository and clock are required")
	}
	now := clock()
	if !validInstant(now.UTC().Truncate(time.Microsecond)) {
		return nil, errors.New("SLA clock is invalid")
	}
	return &Service{repository: repository, clock: clock}, nil
}

func (service *Service) ListCalendars(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	input ConfigurationListInput,
) (CalendarPage, error) {
	now, err := service.requestTime(ctx)
	if err != nil {
		return CalendarPage{}, err
	}
	input, err = normalizeConfigurationList(input)
	if err != nil {
		return CalendarPage{}, err
	}
	authority, err := service.resolveTenantAuthority(ctx, actor, tenantID, CapabilityRead, now)
	if err != nil {
		return CalendarPage{}, err
	}
	page, err := service.repository.ListCalendars(ctx, actor, tenantID, input, authority)
	if err != nil {
		return CalendarPage{}, repositoryError(err)
	}
	if !validCalendarPage(tenantID, input, page) {
		return CalendarPage{}, ErrUnavailable
	}
	return page, nil
}

func (service *Service) GetCalendar(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	id kernel.EntityID,
) (CalendarRecord, error) {
	now, err := service.requestTime(ctx)
	if err != nil || !validKernelID(id) {
		return CalendarRecord{}, ErrInvalidInput
	}
	authority, err := service.resolveTenantAuthority(ctx, actor, tenantID, CapabilityRead, now)
	if err != nil {
		return CalendarRecord{}, err
	}
	record, err := service.repository.GetCalendar(ctx, actor, tenantID, id, authority)
	if err != nil {
		return CalendarRecord{}, repositoryError(err)
	}
	if record.Value.ID() != id || !validCalendarRecord(tenantID, record) {
		return CalendarRecord{}, ErrUnavailable
	}
	return record, nil
}

func (service *Service) ListPolicies(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	input ConfigurationListInput,
) (PolicyPage, error) {
	now, err := service.requestTime(ctx)
	if err != nil {
		return PolicyPage{}, err
	}
	input, err = normalizeConfigurationList(input)
	if err != nil {
		return PolicyPage{}, err
	}
	authority, err := service.resolveTenantAuthority(ctx, actor, tenantID, CapabilityRead, now)
	if err != nil {
		return PolicyPage{}, err
	}
	page, err := service.repository.ListPolicies(ctx, actor, tenantID, input, authority)
	if err != nil {
		return PolicyPage{}, repositoryError(err)
	}
	if !validPolicyPage(tenantID, input, page) {
		return PolicyPage{}, ErrUnavailable
	}
	return page, nil
}

func (service *Service) GetPolicy(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	id kernel.EntityID,
) (PolicyRecord, error) {
	now, err := service.requestTime(ctx)
	if err != nil || !validKernelID(id) {
		return PolicyRecord{}, ErrInvalidInput
	}
	authority, err := service.resolveTenantAuthority(ctx, actor, tenantID, CapabilityRead, now)
	if err != nil {
		return PolicyRecord{}, err
	}
	record, err := service.repository.GetPolicy(ctx, actor, tenantID, id, authority)
	if err != nil {
		return PolicyRecord{}, repositoryError(err)
	}
	if record.Value.ID() != id || !validPolicyRecord(tenantID, record) {
		return PolicyRecord{}, ErrUnavailable
	}
	return record, nil
}

func (service *Service) ListColumns(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	input ConfigurationListInput,
) (ColumnPage, error) {
	now, err := service.requestTime(ctx)
	if err != nil {
		return ColumnPage{}, err
	}
	input, err = normalizeConfigurationList(input)
	if err != nil {
		return ColumnPage{}, err
	}
	authority, err := service.resolveTenantAuthority(ctx, actor, tenantID, CapabilityRead, now)
	if err != nil {
		return ColumnPage{}, err
	}
	page, err := service.repository.ListColumns(ctx, actor, tenantID, input, authority)
	if err != nil {
		return ColumnPage{}, repositoryError(err)
	}
	if !validColumnPage(tenantID, input, page) {
		return ColumnPage{}, ErrUnavailable
	}
	return page, nil
}

func (service *Service) GetColumn(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	id kernel.EntityID,
) (ColumnRecord, error) {
	now, err := service.requestTime(ctx)
	if err != nil || !validKernelID(id) {
		return ColumnRecord{}, ErrInvalidInput
	}
	authority, err := service.resolveTenantAuthority(ctx, actor, tenantID, CapabilityRead, now)
	if err != nil {
		return ColumnRecord{}, err
	}
	record, err := service.repository.GetColumn(ctx, actor, tenantID, id, authority)
	if err != nil {
		return ColumnRecord{}, repositoryError(err)
	}
	if record.Value.ID() != id || !validColumnRecord(tenantID, record) {
		return ColumnRecord{}, ErrUnavailable
	}
	return record, nil
}

func (service *Service) PublishCalendar(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command CalendarPublishCommand,
) (PublicationResult[kernel.BusinessCalendar], error) {
	now, err := service.requestTime(ctx)
	if err != nil || !validEnvelope(command.Envelope) || !validPublicationVersion(command.Input.Version, command.ExpectedActiveVersion) {
		return PublicationResult[kernel.BusinessCalendar]{}, ErrInvalidInput
	}
	if err := service.requireManage(ctx, actor, tenantID, CapabilityManage, now); err != nil {
		return PublicationResult[kernel.BusinessCalendar]{}, err
	}
	tenant, err := kernelTenantID(tenantID)
	if err != nil || command.Input.TenantID != tenant {
		return PublicationResult[kernel.BusinessCalendar]{}, ErrInvalidInput
	}
	calendar, err := kernel.NewBusinessCalendar(command.Input)
	if err != nil {
		return PublicationResult[kernel.BusinessCalendar]{}, ErrInvalidInput
	}
	binding, err := bindCommand("sla.calendar.publish", command.Envelope.IdempotencyKey, calendar.Digest())
	if err != nil {
		return PublicationResult[kernel.BusinessCalendar]{}, err
	}
	result, err := service.repository.PublishCalendar(ctx, CalendarPublication{
		Actor: actor, Calendar: calendar, ExpectedActiveVersion: command.ExpectedActiveVersion,
		Command: binding, Audit: command.Envelope.Audit,
	})
	if err != nil {
		return PublicationResult[kernel.BusinessCalendar]{}, repositoryError(err)
	}
	if !validCalendarPublication(tenantID, calendar, result) {
		return PublicationResult[kernel.BusinessCalendar]{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) PublishPolicy(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command PolicyPublishCommand,
) (PublicationResult[kernel.Policy], error) {
	now, err := service.requestTime(ctx)
	if err != nil || !validEnvelope(command.Envelope) || !validPublicationVersion(command.Input.Version, command.ExpectedActiveVersion) {
		return PublicationResult[kernel.Policy]{}, ErrInvalidInput
	}
	if err := service.requireManage(ctx, actor, tenantID, CapabilityManage, now); err != nil {
		return PublicationResult[kernel.Policy]{}, err
	}
	tenant, err := kernelTenantID(tenantID)
	if err != nil || command.Input.TenantID != tenant {
		return PublicationResult[kernel.Policy]{}, ErrInvalidInput
	}
	policy, err := kernel.NewPolicy(command.Input)
	if err != nil || !phaseFivePolicyObjectTypes(policy.ObjectTypes()) {
		return PublicationResult[kernel.Policy]{}, ErrInvalidInput
	}
	calendars, err := service.repository.LoadPolicyCalendars(ctx, actor, tenantID, policy)
	if err != nil {
		return PublicationResult[kernel.Policy]{}, repositoryError(err)
	}
	if !validPolicyCalendars(policy, calendars) {
		return PublicationResult[kernel.Policy]{}, ErrUnavailable
	}
	binding, err := bindCommand("sla.policy.publish", command.Envelope.IdempotencyKey, policy.Digest())
	if err != nil {
		return PublicationResult[kernel.Policy]{}, err
	}
	result, err := service.repository.PublishPolicy(ctx, PolicyPublication{
		Actor: actor, Policy: policy, ExpectedActiveVersion: command.ExpectedActiveVersion,
		Command: binding, Audit: command.Envelope.Audit,
	})
	if err != nil {
		return PublicationResult[kernel.Policy]{}, repositoryError(err)
	}
	if !validPolicyPublication(tenantID, policy, result) {
		return PublicationResult[kernel.Policy]{}, ErrUnavailable
	}
	return result, nil
}

func phaseFivePolicyObjectTypes(values []kernel.ObjectType) bool {
	if len(values) == 0 || len(values) > 2 {
		return false
	}
	for _, value := range values {
		if value != kernel.ObjectAlert && value != kernel.ObjectCase {
			return false
		}
	}
	return true
}

func (service *Service) PublishColumn(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command ColumnPublishCommand,
) (PublicationResult[kernel.ColumnDefinition], error) {
	now, err := service.requestTime(ctx)
	if err != nil || !validEnvelope(command.Envelope) || !validPublicationVersion(command.Input.Version, command.ExpectedActiveVersion) {
		return PublicationResult[kernel.ColumnDefinition]{}, ErrInvalidInput
	}
	if err := service.requireManage(ctx, actor, tenantID, CapabilityManage, now); err != nil {
		return PublicationResult[kernel.ColumnDefinition]{}, err
	}
	tenant, err := kernelTenantID(tenantID)
	if err != nil || command.Input.TenantID != tenant {
		return PublicationResult[kernel.ColumnDefinition]{}, ErrInvalidInput
	}
	metric, err := service.repository.LoadMetricDefinition(ctx, actor, tenantID, command.Input.MetricID)
	if err != nil {
		return PublicationResult[kernel.ColumnDefinition]{}, repositoryError(err)
	}
	column, err := kernel.NewColumnDefinition(metric, command.Input)
	if err != nil {
		return PublicationResult[kernel.ColumnDefinition]{}, ErrInvalidInput
	}
	binding, err := bindCommand("sla.column.publish", command.Envelope.IdempotencyKey, column.Digest())
	if err != nil {
		return PublicationResult[kernel.ColumnDefinition]{}, err
	}
	result, err := service.repository.PublishColumn(ctx, ColumnPublication{
		Actor: actor, Column: column, ExpectedActiveVersion: command.ExpectedActiveVersion,
		Command: binding, Audit: command.Envelope.Audit,
	})
	if err != nil {
		return PublicationResult[kernel.ColumnDefinition]{}, repositoryError(err)
	}
	if !validColumnPublication(tenantID, column, result) {
		return PublicationResult[kernel.ColumnDefinition]{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) Archive(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command ArchiveCommand,
) (uint64, bool, error) {
	now, err := service.requestTime(ctx)
	if err != nil || !validEnvelope(command.Envelope) || !validArchiveKind(command.Kind) ||
		!validKernelID(command.ID) || command.ExpectedVersion == 0 || command.ExpectedVersion >= uint64(math.MaxInt64) ||
		!validReason(command.Reason) {
		return 0, false, ErrInvalidInput
	}
	if err := service.requireManage(ctx, actor, tenantID, CapabilityManage, now); err != nil {
		return 0, false, err
	}
	digest := digestRequest("periapsis:sla-archive:v1",
		[]byte(command.Kind), entityBytes(command.ID), uint64Bytes(command.ExpectedVersion), []byte(command.Reason),
	)
	binding, err := bindCommand("sla."+string(command.Kind)+".archive", command.Envelope.IdempotencyKey, digest)
	if err != nil {
		return 0, false, err
	}
	version, replayed, err := service.repository.Archive(ctx, ArchiveWrite{
		Actor: actor, TenantID: tenantID, Kind: command.Kind, ID: command.ID,
		ExpectedVersion: command.ExpectedVersion, Reason: command.Reason,
		Command: binding, Audit: command.Envelope.Audit,
	})
	if err != nil {
		return 0, false, repositoryError(err)
	}
	if version != command.ExpectedVersion+1 {
		return 0, false, ErrUnavailable
	}
	return version, replayed, nil
}

func (service *Service) Simulate(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command SimulationCommand,
) (SimulationResult, error) {
	now, err := service.requestTime(ctx)
	if err != nil || !validKernelID(command.PolicyID) || command.PolicyVersion == 0 ||
		!validKernelID(command.SLAInstanceID) || !validKernelID(command.ObjectID) ||
		command.SLAInstanceID == command.ObjectID || command.Snapshot.TenantID().String() != tenantID.String() ||
		!validInstant(command.CreatedAt) || !validInstant(command.EvaluateAt) || command.EvaluateAt.Before(command.CreatedAt) {
		return SimulationResult{}, ErrInvalidInput
	}
	if err := service.requireManage(ctx, actor, tenantID, CapabilitySimulate, now); err != nil {
		return SimulationResult{}, err
	}
	policy, calendars, err := service.repository.LoadSimulation(
		ctx, actor, tenantID, command.PolicyID, command.PolicyVersion,
	)
	if err != nil {
		return SimulationResult{}, repositoryError(err)
	}
	if policy.ID() != command.PolicyID || policy.Version() != command.PolicyVersion ||
		policy.TenantID().String() != tenantID.String() || !validPolicyCalendars(policy, calendars) {
		return SimulationResult{}, ErrUnavailable
	}
	result, err := kernel.SimulateContext(ctx, kernel.SimulationInput{
		Snapshot: command.Snapshot, Policy: policy, SLAInstanceID: command.SLAInstanceID,
		ObjectID:  command.ObjectID,
		CreatedAt: command.CreatedAt, EvaluateAt: command.EvaluateAt,
		MetricBindings: slices.Clone(command.Bindings), Calendars: slices.Clone(calendars),
		Events: slices.Clone(command.Events),
	})
	if err != nil {
		if errors.Is(err, kernel.ErrEngineCanceled) {
			return SimulationResult{}, ErrUnavailable
		}
		return SimulationResult{}, ErrInvalidInput
	}
	return SimulationResult{Result: result, Digest: result.Digest()}, nil
}

func (service *Service) ProjectObject(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command ObjectProjectionCommand,
) (ObjectProjection, error) {
	now, err := service.requestTime(ctx)
	if err != nil || !validKernelID(command.ObjectID) || !validInstant(command.At) || command.At.After(now.Add(time.Second)) {
		return ObjectProjection{}, ErrInvalidInput
	}
	capability, ok := objectReadCapability(actor.Kind, command.ObjectType)
	if !ok || !validActor(actor, tenantID) {
		return ObjectProjection{}, ErrForbidden
	}
	resource := Resource{ObjectType: command.ObjectType, ObjectID: command.ObjectID}
	authority, err := service.repository.ResolveAuthority(ctx, actor, tenantID, capability, resource)
	if err != nil {
		return ObjectProjection{}, repositoryError(err)
	}
	if !validObjectAuthority(actor, tenantID, capability, resource, authority) || !service.authorityCurrent(ctx, authority, now) {
		return ObjectProjection{}, ErrForbidden
	}
	state, err := service.repository.LoadObjectProjection(ctx, actor, tenantID, resource, authority)
	if err != nil {
		return ObjectProjection{}, repositoryError(err)
	}
	return projectObjectState(ctx, actor, tenantID, command, authority, state)
}

func (service *Service) ProcessEvent(
	ctx context.Context,
	tenantID uuid.UUID,
	command EventCommand,
) (EventResult, error) {
	_, err := service.requestTime(ctx)
	if err != nil || !validEnvelope(command.Envelope) || !validEventCommand(tenantID, command) {
		return EventResult{}, ErrInvalidInput
	}
	digest := eventRequestDigest(command)
	binding, err := bindCommand("sla.event.process", command.Envelope.IdempotencyKey, digest)
	if err != nil {
		return EventResult{}, err
	}
	planCalls := 0
	var expectedReceipt EventReceipt
	result, err := service.repository.TransactEvent(ctx, EventTransaction{
		TenantID: tenantID, Command: command, Binding: binding,
		Plan: func(state EventState) (EventPlan, error) {
			planCalls++
			if planCalls != 1 {
				return EventPlan{}, ErrUnavailable
			}
			plan, planErr := planEvent(ctx, command, state)
			if planErr != nil {
				return EventPlan{}, planErr
			}
			if !validEventPlan(tenantID, command, plan) {
				return EventPlan{}, kernel.ErrInvalidMetric
			}
			expectedReceipt = eventReceiptForPlan(tenantID, command, binding, plan)
			return plan, nil
		},
	})
	if err != nil {
		if errors.Is(err, kernel.ErrMetricConflict) {
			return EventResult{}, ErrPreconditionFailed
		}
		if errors.Is(err, kernel.ErrInvalidMetric) || errors.Is(err, kernel.ErrInvalidEvent) ||
			errors.Is(err, kernel.ErrInvalidCalendar) || errors.Is(err, kernel.ErrInvalidPolicy) ||
			errors.Is(err, kernel.ErrAmbiguousPolicy) {
			return EventResult{}, ErrUnavailable
		}
		if errors.Is(err, kernel.ErrEngineCanceled) {
			return EventResult{}, ErrUnavailable
		}
		return EventResult{}, repositoryError(err)
	}
	if planCalls > 1 || result.Replayed != (planCalls == 0) ||
		!validEventReceipt(tenantID, command, binding, result.Receipt) ||
		planCalls == 1 && !sameEventReceipt(result.Receipt, expectedReceipt) {
		return EventResult{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) Override(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	request OverrideRequest,
) (OverrideResult, error) {
	now, err := service.requestTime(ctx)
	if err != nil || !validEnvelope(request.Envelope) || !validOverrideRequest(tenantID, request) {
		return OverrideResult{}, ErrInvalidInput
	}
	capability, ok := overrideCapability(request.ObjectType)
	if !ok || actor.Kind != PrincipalOperator || !validActor(actor, tenantID) {
		return OverrideResult{}, ErrForbidden
	}
	resource := Resource{ObjectType: request.ObjectType, ObjectID: request.ObjectID}
	authority, err := service.repository.ResolveAuthority(ctx, actor, tenantID, capability, resource)
	if err != nil {
		return OverrideResult{}, repositoryError(err)
	}
	if !validObjectAuthority(actor, tenantID, capability, resource, authority) || authority.Audience != AudienceOperator ||
		!service.authorityCurrent(ctx, authority, now) {
		return OverrideResult{}, ErrForbidden
	}
	binding, err := bindCommand("sla.override.apply", request.Envelope.IdempotencyKey, overrideRequestDigest(request))
	if err != nil {
		return OverrideResult{}, err
	}
	planCalls := 0
	var expectedReceipt OverrideReceipt
	result, err := service.repository.TransactOverride(ctx, OverrideTransaction{
		Actor: actor, TenantID: tenantID, Authority: authority, Request: request, Binding: binding,
		Plan: func(state OverrideState) (OverridePlan, error) {
			planCalls++
			if planCalls != 1 {
				return OverridePlan{}, ErrUnavailable
			}
			plan, planErr := planOverride(ctx, actor, tenantID, request, authority, state)
			if planErr != nil {
				return OverridePlan{}, planErr
			}
			if !validOverridePlan(actor, tenantID, request, authority, plan) {
				return OverridePlan{}, ErrUnavailable
			}
			expectedReceipt = overrideReceiptForPlan(actor, tenantID, request, authority, binding, plan, state.OccurredAt)
			return plan, nil
		},
	})
	if err != nil {
		switch {
		case errors.Is(err, kernel.ErrMetricConflict):
			return OverrideResult{}, ErrPreconditionFailed
		case errors.Is(err, kernel.ErrOverrideDenied):
			return OverrideResult{}, ErrForbidden
		case errors.Is(err, kernel.ErrInvalidOverride), errors.Is(err, kernel.ErrInvalidMetric):
			return OverrideResult{}, ErrInvalidInput
		default:
			return OverrideResult{}, repositoryError(err)
		}
	}
	if planCalls > 1 || result.Replayed != (planCalls == 0) ||
		!validOverrideReceipt(actor, tenantID, request, authority, binding, result.Receipt) ||
		planCalls == 1 && !sameOverrideReceipt(result.Receipt, expectedReceipt) {
		return OverrideResult{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) requireManage(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	capability Capability,
	now time.Time,
) error {
	_, err := service.resolveTenantAuthority(ctx, actor, tenantID, capability, now)
	return err
}

func (service *Service) resolveTenantAuthority(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	capability Capability,
	now time.Time,
) (Authority, error) {
	if !validActor(actor, tenantID) || actor.Kind != PrincipalOperator {
		return Authority{}, ErrForbidden
	}
	authority, err := service.repository.ResolveAuthority(ctx, actor, tenantID, capability, Resource{})
	if err != nil {
		return Authority{}, repositoryError(err)
	}
	if !validManageAuthority(actor, tenantID, capability, authority) || !service.authorityCurrent(ctx, authority, now) {
		return Authority{}, ErrForbidden
	}
	return authority, nil
}

func (service *Service) requestTime(ctx context.Context) (time.Time, error) {
	if ctx == nil {
		return time.Time{}, ErrInvalidInput
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	deadline, ok := ctx.Deadline()
	if !validInstant(now) || ctx.Err() != nil || !ok || !deadline.After(now) || deadline.Sub(now) > maximumRequestDeadline {
		return time.Time{}, ErrInvalidInput
	}
	return now, nil
}

func (service *Service) authorityCurrent(ctx context.Context, authority Authority, requestStartedAt time.Time) bool {
	// Authority is evaluated during the repository call, after the request starts.
	// Validate its lifetime against the clock after that call completes.
	now, err := service.requestTime(ctx)
	return err == nil && !now.Before(requestStartedAt) &&
		!now.Before(authority.EvaluatedAt) && now.Before(authority.ValidUntil)
}

func validPublicationVersion(next, expected uint64) bool {
	return next > 0 && expected < math.MaxUint64 && next == expected+1
}

func validArchiveKind(kind ArchiveKind) bool {
	return kind == ArchiveCalendar || kind == ArchivePolicy || kind == ArchiveColumn
}

func validPolicyCalendars(policy kernel.Policy, calendars []kernel.BusinessCalendar) bool {
	required := make(map[kernel.EntityID]uint64)
	for _, metric := range policy.Metrics() {
		if metric.Clock() != kernel.ClockBusiness {
			continue
		}
		calendarID := metric.CalendarID()
		if calendarID == nil || metric.CalendarVersion() == 0 {
			return false
		}
		if version, exists := required[*calendarID]; exists && version != metric.CalendarVersion() {
			return false
		}
		required[*calendarID] = metric.CalendarVersion()
	}
	if len(calendars) != len(required) {
		return false
	}
	seen := make(map[kernel.EntityID]struct{}, len(calendars))
	for _, calendar := range calendars {
		version, exists := required[calendar.ID()]
		if !exists || version != calendar.Version() || calendar.TenantID() != policy.TenantID() ||
			calendar.Digest() == ([32]byte{}) {
			return false
		}
		if _, duplicate := seen[calendar.ID()]; duplicate {
			return false
		}
		seen[calendar.ID()] = struct{}{}
	}
	return true
}

func validCalendarPage(tenantID uuid.UUID, input ConfigurationListInput, page CalendarPage) bool {
	if len(page.Items) > input.Limit || !validPageCursor(input.After, page.NextCursor, len(page.Items)) {
		return false
	}
	seen := make(map[kernel.EntityID]struct{}, len(page.Items))
	for index, record := range page.Items {
		if !validCalendarRecord(tenantID, record) || !input.IncludeArchived && record.ArchivedAt != nil {
			return false
		}
		if _, duplicate := seen[record.Value.ID()]; duplicate {
			return false
		}
		seen[record.Value.ID()] = struct{}{}
		if index > 0 && compareConfigurationIdentity(
			page.Items[index-1].Value.Key().String(), page.Items[index-1].Value.ID(),
			record.Value.Key().String(), record.Value.ID(),
		) >= 0 {
			return false
		}
	}
	return true
}

func validPolicyPage(tenantID uuid.UUID, input ConfigurationListInput, page PolicyPage) bool {
	if len(page.Items) > input.Limit || !validPageCursor(input.After, page.NextCursor, len(page.Items)) {
		return false
	}
	seen := make(map[kernel.EntityID]struct{}, len(page.Items))
	for index, record := range page.Items {
		if !validPolicyRecord(tenantID, record) || !input.IncludeArchived && record.ArchivedAt != nil {
			return false
		}
		if _, duplicate := seen[record.Value.ID()]; duplicate {
			return false
		}
		seen[record.Value.ID()] = struct{}{}
		if index > 0 && compareConfigurationIdentity(
			page.Items[index-1].Value.Key().String(), page.Items[index-1].Value.ID(),
			record.Value.Key().String(), record.Value.ID(),
		) >= 0 {
			return false
		}
	}
	return true
}

func validColumnPage(tenantID uuid.UUID, input ConfigurationListInput, page ColumnPage) bool {
	if len(page.Items) > input.Limit || !validPageCursor(input.After, page.NextCursor, len(page.Items)) {
		return false
	}
	seen := make(map[kernel.EntityID]struct{}, len(page.Items))
	for index, record := range page.Items {
		if !validColumnRecord(tenantID, record) || !input.IncludeArchived && record.ArchivedAt != nil {
			return false
		}
		if _, duplicate := seen[record.Value.ID()]; duplicate {
			return false
		}
		seen[record.Value.ID()] = struct{}{}
		if index > 0 && compareConfigurationIdentity(
			page.Items[index-1].Value.Key().String(), page.Items[index-1].Value.ID(),
			record.Value.Key().String(), record.Value.ID(),
		) >= 0 {
			return false
		}
	}
	return true
}

func validCalendarRecord(tenantID uuid.UUID, record CalendarRecord) bool {
	return record.Value.TenantID().String() == tenantID.String() && record.Value.Digest() != ([32]byte{}) &&
		validConfigurationVersion(record.Value.Version(), record.ResourceVersion, record.ArchivedAt) &&
		validConfigurationTimestamps(record.CreatedAt, record.UpdatedAt, record.ArchivedAt)
}

func validPolicyRecord(tenantID uuid.UUID, record PolicyRecord) bool {
	return record.Value.TenantID().String() == tenantID.String() && record.Value.Digest() != ([32]byte{}) &&
		validConfigurationVersion(record.Value.Version(), record.ResourceVersion, record.ArchivedAt) &&
		validConfigurationTimestamps(record.CreatedAt, record.UpdatedAt, record.ArchivedAt)
}

func validColumnRecord(tenantID uuid.UUID, record ColumnRecord) bool {
	return record.Value.TenantID().String() == tenantID.String() && record.Value.Digest() != ([32]byte{}) &&
		validConfigurationVersion(record.Value.Version(), record.ResourceVersion, record.ArchivedAt) &&
		validConfigurationTimestamps(record.CreatedAt, record.UpdatedAt, record.ArchivedAt)
}

func validCalendarPublication(tenantID uuid.UUID, requested kernel.BusinessCalendar, result PublicationResult[kernel.BusinessCalendar]) bool {
	if result.Value.ID() != requested.ID() {
		return false
	}
	record := CalendarRecord{Value: result.Value, ResourceVersion: result.ResourceVersion, CreatedAt: result.CreatedAt, UpdatedAt: result.UpdatedAt, ArchivedAt: result.ArchivedAt}
	return validCalendarRecord(tenantID, record) && (result.Replayed || result.ArchivedAt == nil && result.Value.Digest() == requested.Digest())
}

func validPolicyPublication(tenantID uuid.UUID, requested kernel.Policy, result PublicationResult[kernel.Policy]) bool {
	if result.Value.ID() != requested.ID() {
		return false
	}
	record := PolicyRecord{Value: result.Value, ResourceVersion: result.ResourceVersion, CreatedAt: result.CreatedAt, UpdatedAt: result.UpdatedAt, ArchivedAt: result.ArchivedAt}
	return validPolicyRecord(tenantID, record) && (result.Replayed || result.ArchivedAt == nil && result.Value.Digest() == requested.Digest())
}

func validColumnPublication(tenantID uuid.UUID, requested kernel.ColumnDefinition, result PublicationResult[kernel.ColumnDefinition]) bool {
	if result.Value.ID() != requested.ID() {
		return false
	}
	record := ColumnRecord{Value: result.Value, ResourceVersion: result.ResourceVersion, CreatedAt: result.CreatedAt, UpdatedAt: result.UpdatedAt, ArchivedAt: result.ArchivedAt}
	return validColumnRecord(tenantID, record) && (result.Replayed || result.ArchivedAt == nil && result.Value.Digest() == requested.Digest())
}

func validConfigurationTimestamps(createdAt, updatedAt time.Time, archivedAt *time.Time) bool {
	if !validInstant(createdAt) || !validInstant(updatedAt) || updatedAt.Before(createdAt) {
		return false
	}
	return archivedAt == nil || validInstant(*archivedAt) && !archivedAt.Before(updatedAt)
}

func validConfigurationVersion(activeVersion, resourceVersion uint64, archivedAt *time.Time) bool {
	if activeVersion == 0 || activeVersion >= uint64(math.MaxInt64) || resourceVersion == 0 {
		return false
	}
	if archivedAt == nil {
		return resourceVersion == activeVersion
	}
	return validInstant(*archivedAt) && resourceVersion == activeVersion+1
}

func validPageCursor(after, next string, itemCount int) bool {
	return validConfigurationCursor(next) && (next == "" || itemCount > 0 && next != after)
}

func compareConfigurationIdentity(leftKey string, leftID kernel.EntityID, rightKey string, rightID kernel.EntityID) int {
	if compared := strings.Compare(leftKey, rightKey); compared != 0 {
		return compared
	}
	return strings.Compare(leftID.String(), rightID.String())
}

func projectObjectState(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command ObjectProjectionCommand,
	authority Authority,
	state ObjectProjectionState,
) (ObjectProjection, error) {
	emptyOperatorInventory := actor.Kind != PrincipalCustomer && len(state.Metrics) == 0
	if !validKernelID(state.SLAInstanceID) || state.AggregateVersion == 0 ||
		state.AggregateVersion >= uint64(math.MaxInt64) || !validKernelID(state.PolicyID) ||
		state.PolicyVersion == 0 || emptyOperatorInventory || len(state.Metrics) > 32 {
		return ObjectProjection{}, ErrUnavailable
	}
	roles, ok := canonicalRoleKeys(authority.RoleKeys)
	if !ok {
		return ObjectProjection{}, ErrUnavailable
	}
	projection := ObjectProjection{
		TenantID: tenantID, Audience: authority.Audience, ObjectType: command.ObjectType, ObjectID: command.ObjectID,
		SLAInstanceID: state.SLAInstanceID, AggregateVersion: state.AggregateVersion,
		PolicyID: state.PolicyID, PolicyVersion: state.PolicyVersion, ProjectedAt: command.At,
	}
	seenMetrics := make(map[kernel.EntityID]struct{}, len(state.Metrics))
	seenMetricKeys := make(map[string]struct{}, len(state.Metrics))
	seenColumns := make(map[kernel.EntityID]struct{})
	seenColumnKeys := make(map[string]struct{})
	var slaInstanceID kernel.EntityID
	for index, work := range state.Metrics {
		instance := work.Instance
		definition := instance.Definition()
		if instance.TenantID().String() != tenantID.String() || instance.ObjectType() != command.ObjectType ||
			instance.ObjectID() != command.ObjectID || instance.PolicyID() != state.PolicyID ||
			instance.PolicyVersion() != state.PolicyVersion {
			return ObjectProjection{}, ErrUnavailable
		}
		if index == 0 {
			slaInstanceID = instance.SLAInstanceID()
			if slaInstanceID != state.SLAInstanceID {
				return ObjectProjection{}, ErrUnavailable
			}
		} else if instance.SLAInstanceID() != slaInstanceID {
			return ObjectProjection{}, ErrUnavailable
		}
		if _, duplicate := seenMetrics[definition.ID()]; duplicate {
			return ObjectProjection{}, ErrUnavailable
		}
		if _, duplicate := seenMetricKeys[definition.Key().String()]; duplicate {
			return ObjectProjection{}, ErrUnavailable
		}
		seenMetrics[definition.ID()] = struct{}{}
		seenMetricKeys[definition.Key().String()] = struct{}{}
		evaluation, err := instance.EvaluateContext(ctx, command.At, work.Calendar)
		if err != nil {
			return ObjectProjection{}, ErrUnavailable
		}
		customer := actor.Kind == PrincipalCustomer
		if definition.APIVisible() && (!customer || definition.CustomerVisible()) {
			state := customerSafeState(evaluation.State, customer)
			metric := MetricProjection{
				MetricID: definition.ID(), MetricInstanceID: instance.ID(), MetricVersion: instance.Version(),
				Key: definition.Key(), Label: definition.Label(), CustomerVisible: definition.CustomerVisible(), State: state,
				StartedAt: evaluation.StartedAt, DueAt: evaluation.DueAt,
				RemainingSeconds:   durationSecondsCeil(evaluation.Remaining),
				ConsumedPercentage: evaluation.ConsumedPercentage,
				BreachedAt:         evaluation.BreachedAt, CompletedAt: evaluation.CompletedAt,
			}
			if !customer {
				metric.PausedAt = instance.PausedAt()
			}
			projection.Metrics = append(projection.Metrics, metric)
		}
		for _, column := range work.Columns {
			if _, duplicate := seenColumns[column.ID()]; duplicate || column.TenantID().String() != tenantID.String() ||
				column.MetricID() != definition.ID() {
				return ObjectProjection{}, ErrUnavailable
			}
			if _, duplicate := seenColumnKeys[column.Key().String()]; duplicate {
				return ObjectProjection{}, ErrUnavailable
			}
			seenColumns[column.ID()] = struct{}{}
			seenColumnKeys[column.Key().String()] = struct{}{}
			if !column.VisibleTo(customer, roles) {
				continue
			}
			value, err := kernel.MaterializeColumnContext(ctx, column, instance, command.At, work.Calendar)
			if err != nil {
				return ObjectProjection{}, ErrUnavailable
			}
			columnState := customerSafeState(value.State(), customer)
			styleKey := value.StyleKey()
			if customer && value.State() == kernel.StatePaused {
				styleKey = kernel.Key{}
			}
			projection.Columns = append(projection.Columns, ColumnProjection{
				ColumnID: column.ID(), Key: column.Key(), Label: column.Label(), Calculation: value.Calculation(),
				Format: column.Format(), CustomerVisible: column.CustomerVisible(), State: columnState,
				Instant: value.Instant(), Duration: value.Duration(), Percentage: value.Percentage(),
				StyleKey: styleKey, MaterializedAt: value.MaterializedAt(),
			})
		}
	}
	slices.SortFunc(projection.Metrics, func(left, right MetricProjection) int {
		return strings.Compare(left.Key.String(), right.Key.String())
	})
	slices.SortFunc(projection.Columns, func(left, right ColumnProjection) int {
		return strings.Compare(left.Key.String(), right.Key.String())
	})
	return projection, nil
}

func validEventCommand(tenantID uuid.UUID, command EventCommand) bool {
	if !validUUIDv7(tenantID) || !validActor(command.Actor, tenantID) || command.Actor.Kind != PrincipalOperator ||
		(command.ObjectType != kernel.ObjectAlert && command.ObjectType != kernel.ObjectCase) ||
		!validKernelID(command.Event.ID) ||
		command.Event.TenantID.String() != tenantID.String() || !validKernelID(command.Event.ObjectID) ||
		command.Event.Key.String() == "" || !validInstant(command.Event.OccurredAt) || !validToken(command.Origin, 128) ||
		!validKernelID(command.OriginID) {
		return false
	}
	return true
}

func planEvent(ctx context.Context, command EventCommand, state EventState) (EventPlan, error) {
	mode := kernel.ObjectEventStateMode(state.Mode)
	planned, err := kernel.PlanObjectEventContext(ctx, command.Event, kernel.ObjectEventState{
		Mode: mode, AggregateVersion: state.AggregateVersion,
		Metrics: state.Metrics, Snapshot: state.Snapshot, Policies: state.Policies,
		Calendars: state.Calendars, Columns: state.Columns,
	})
	if err != nil {
		return EventPlan{}, err
	}
	return EventPlan{
		Assignment: planned.Assignment(), Engine: planned.Engine(),
		ExpectedAggregateVersion: planned.ExpectedAggregateVersion(),
		NextAggregateVersion:     planned.NextAggregateVersion(),
	}, nil
}

func validEventPlan(tenantID uuid.UUID, command EventCommand, plan EventPlan) bool {
	if plan.Assignment == nil {
		return plan.Engine != nil && plan.ExpectedAggregateVersion > 0 &&
			plan.ExpectedAggregateVersion < uint64(math.MaxInt64-1) &&
			plan.NextAggregateVersion == plan.ExpectedAggregateVersion+1 &&
			validEngineEventPlan(tenantID, command, *plan.Engine)
	}
	assignment := plan.Assignment
	if assignment.AssignmentEventID() != command.Event.ID || assignment.ObjectID() != command.Event.ObjectID ||
		!assignment.CreatedAt().Equal(command.Event.OccurredAt) {
		return false
	}
	if !assignment.Matched() {
		return plan.Engine == nil && plan.ExpectedAggregateVersion == 0 && plan.NextAggregateVersion == 0 &&
			assignment.SLAInstanceID() == (kernel.EntityID{}) && len(assignment.Metrics()) == 0
	}
	if plan.Engine == nil || plan.ExpectedAggregateVersion != 0 || plan.NextAggregateVersion != 1 ||
		!validEngineEventPlan(tenantID, command, *plan.Engine) {
		return false
	}
	assigned := assignment.Metrics()
	evaluated := plan.Engine.Metrics()
	if len(assigned) == 0 || len(assigned) != len(evaluated) {
		return false
	}
	initial := make(map[kernel.EntityID]kernel.MetricInstance, len(assigned))
	for _, work := range assigned {
		instance := work.Instance
		if instance.Version() != 1 || instance.SLAInstanceID() != assignment.SLAInstanceID() {
			return false
		}
		initial[instance.ID()] = instance
	}
	for _, metric := range evaluated {
		before, exists := initial[metric.Instance().ID()]
		if !exists || metric.PreviousVersion() != 1 || metric.Instance().SLAInstanceID() != assignment.SLAInstanceID() ||
			metric.Instance().PolicyID() != before.PolicyID() || metric.Instance().PolicyVersion() != before.PolicyVersion() ||
			metric.Instance().Definition().ID() != before.Definition().ID() {
			return false
		}
	}
	return true
}

func validEngineEventPlan(tenantID uuid.UUID, command EventCommand, plan kernel.EnginePlan) bool {
	if plan.EventID() == nil || *plan.EventID() != command.Event.ID || !plan.ObservedAt().Equal(command.Event.OccurredAt) {
		return false
	}
	metrics := plan.Metrics()
	if len(metrics) == 0 || len(metrics) > 32 {
		return false
	}
	seen := make(map[kernel.EntityID]struct{}, len(metrics))
	var slaInstanceID kernel.EntityID
	var policyID kernel.EntityID
	var policyVersion uint64
	for _, metric := range metrics {
		instance := metric.Instance()
		if instance.TenantID().String() != tenantID.String() || instance.ObjectType() != command.ObjectType ||
			instance.ObjectID() != command.Event.ObjectID || metric.PreviousVersion() == 0 ||
			!validKernelID(instance.SLAInstanceID()) || !validKernelID(instance.PolicyID()) ||
			instance.PolicyVersion() == 0 || instance.PolicyVersion() >= uint64(math.MaxInt64) ||
			metric.Changed() && instance.Version() != metric.PreviousVersion()+1 ||
			!metric.Changed() && instance.Version() != metric.PreviousVersion() {
			return false
		}
		if slaInstanceID == (kernel.EntityID{}) {
			slaInstanceID, policyID, policyVersion = instance.SLAInstanceID(), instance.PolicyID(), instance.PolicyVersion()
		} else if instance.SLAInstanceID() != slaInstanceID || instance.PolicyID() != policyID ||
			instance.PolicyVersion() != policyVersion {
			return false
		}
		if _, duplicate := seen[instance.ID()]; duplicate {
			return false
		}
		seen[instance.ID()] = struct{}{}
	}
	return true
}

func validEventReceipt(
	tenantID uuid.UUID,
	command EventCommand,
	binding CommandBinding,
	receipt EventReceipt,
) bool {
	if receipt.Command != binding || receipt.EventID != command.Event.ID || receipt.TenantID != tenantID ||
		receipt.ObjectType != command.ObjectType || receipt.ObjectID != command.Event.ObjectID {
		return false
	}
	switch receipt.Outcome {
	case EventOutcomeNoPolicy:
		return receipt.SLAInstanceID == nil && receipt.PolicyID == nil && receipt.AggregateVersion == 0 &&
			receipt.PolicyVersion == 0
	case EventOutcomeAssigned:
		return validEventReceiptAssignment(receipt) && receipt.AggregateVersion == 1
	case EventOutcomeUpdated:
		return validEventReceiptAssignment(receipt) && receipt.AggregateVersion > 1 &&
			receipt.AggregateVersion < uint64(math.MaxInt64)
	default:
		return false
	}
}

func validEventReceiptAssignment(receipt EventReceipt) bool {
	return receipt.SLAInstanceID != nil && validKernelID(*receipt.SLAInstanceID) &&
		receipt.PolicyID != nil && validKernelID(*receipt.PolicyID) && receipt.PolicyVersion > 0 &&
		receipt.PolicyVersion < uint64(math.MaxInt64)
}

func eventReceiptForPlan(
	tenantID uuid.UUID,
	command EventCommand,
	binding CommandBinding,
	plan EventPlan,
) EventReceipt {
	receipt := EventReceipt{
		Command: binding, EventID: command.Event.ID, TenantID: tenantID,
		ObjectType: command.ObjectType, ObjectID: command.Event.ObjectID,
		AggregateVersion: plan.NextAggregateVersion,
	}
	if plan.Assignment != nil && !plan.Assignment.Matched() {
		receipt.Outcome = EventOutcomeNoPolicy
		return receipt
	}
	if plan.Assignment != nil {
		receipt.Outcome = EventOutcomeAssigned
		policy := plan.Assignment.Policy()
		slaInstanceID, policyID := plan.Assignment.SLAInstanceID(), policy.ID()
		receipt.SLAInstanceID, receipt.PolicyID, receipt.PolicyVersion = &slaInstanceID, &policyID, policy.Version()
		return receipt
	}
	receipt.Outcome = EventOutcomeUpdated
	instance := plan.Engine.Metrics()[0].Instance()
	slaInstanceID, policyID := instance.SLAInstanceID(), instance.PolicyID()
	receipt.SLAInstanceID, receipt.PolicyID, receipt.PolicyVersion = &slaInstanceID, &policyID, instance.PolicyVersion()
	return receipt
}

func sameEventReceipt(left, right EventReceipt) bool {
	return left.Command == right.Command && left.EventID == right.EventID && left.TenantID == right.TenantID &&
		left.ObjectType == right.ObjectType && left.ObjectID == right.ObjectID && left.Outcome == right.Outcome &&
		sameEntityID(left.SLAInstanceID, right.SLAInstanceID) && left.AggregateVersion == right.AggregateVersion &&
		sameEntityID(left.PolicyID, right.PolicyID) && left.PolicyVersion == right.PolicyVersion
}

func validOverrideRequest(tenantID uuid.UUID, request OverrideRequest) bool {
	intent := request.Intent
	requiresSimulation := intent.Kind == kernel.OverrideChangeCalendar || intent.Kind == kernel.OverrideChangePolicy ||
		intent.Kind == kernel.OverrideRecalculate
	if !validUUIDv7(tenantID) || !validKernelID(request.ObjectID) || !validKernelID(request.SLAInstanceID) ||
		request.ExpectedAggregateVersion == 0 || request.ExpectedAggregateVersion >= uint64(math.MaxInt64) ||
		!validKernelID(intent.ID) || !validReason(intent.Reason) ||
		requiresSimulation != (intent.SimulationDigest != ([32]byte{})) {
		return false
	}
	if intent.Kind == kernel.OverrideChangePolicy {
		if request.MetricInstanceID != (kernel.EntityID{}) || request.ExpectedMetricVersion != 0 {
			return false
		}
	} else if !validKernelID(request.MetricInstanceID) || request.ExpectedMetricVersion == 0 ||
		request.ExpectedMetricVersion >= uint64(math.MaxInt64) {
		return false
	}
	switch intent.Kind {
	case kernel.OverrideExtend:
		return intent.Extension > 0 && intent.Extension%time.Microsecond == 0 && emptyOverrideTargets(intent)
	case kernel.OverrideSuspend, kernel.OverrideResume, kernel.OverrideComplete:
		return intent.Extension == 0 && emptyOverrideTargets(intent)
	case kernel.OverrideChangeCalendar:
		return intent.Extension == 0 && validKernelID(intent.ReplacementCalendarID) &&
			intent.ReplacementCalendarVersion > 0 && intent.ReplacementCalendarVersion < uint64(math.MaxInt64) &&
			intent.NewPolicyID == (kernel.EntityID{}) && intent.NewPolicyVersion == 0
	case kernel.OverrideChangePolicy:
		return intent.Extension == 0 && validKernelID(intent.NewPolicyID) && intent.NewPolicyVersion > 0 &&
			intent.NewPolicyVersion < uint64(math.MaxInt64) &&
			intent.ReplacementCalendarID == (kernel.EntityID{}) && intent.ReplacementCalendarVersion == 0
	case kernel.OverrideRecalculate:
		return intent.Extension == 0 && emptyOverrideTargets(intent)
	default:
		return false
	}
}

func emptyOverrideTargets(intent OverrideIntent) bool {
	return intent.NewPolicyID == (kernel.EntityID{}) && intent.NewPolicyVersion == 0 &&
		intent.ReplacementCalendarID == (kernel.EntityID{}) && intent.ReplacementCalendarVersion == 0
}

func planOverride(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	request OverrideRequest,
	authority Authority,
	state OverrideState,
) (OverridePlan, error) {
	if !validInstant(state.OccurredAt) || state.OccurredAt.Before(authority.EvaluatedAt) ||
		!state.OccurredAt.Before(authority.ValidUntil) {
		return OverridePlan{}, kernel.ErrInvalidOverride
	}
	requiresSimulation := request.Intent.Kind == kernel.OverrideChangeCalendar ||
		request.Intent.Kind == kernel.OverrideChangePolicy || request.Intent.Kind == kernel.OverrideRecalculate
	if requiresSimulation && (state.SimulationDigest == ([32]byte{}) || state.SimulationDigest != request.Intent.SimulationDigest) ||
		!requiresSimulation && state.SimulationDigest != ([32]byte{}) {
		return OverridePlan{}, kernel.ErrInvalidOverride
	}
	if request.Intent.Kind == kernel.OverrideChangePolicy {
		return planPolicyOverride(ctx, actor, tenantID, request, authority, state)
	}
	return planMetricOverride(ctx, actor, tenantID, request, authority, state)
}

func planMetricOverride(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	request OverrideRequest,
	authority Authority,
	state OverrideState,
) (OverridePlan, error) {
	if state.Metric == nil {
		return OverridePlan{}, kernel.ErrInvalidOverride
	}
	work := *state.Metric
	instance := work.Instance
	if instance.ID() != request.MetricInstanceID || instance.TenantID().String() != tenantID.String() ||
		instance.ObjectType() != request.ObjectType || instance.ObjectID() != request.ObjectID ||
		instance.SLAInstanceID() != request.SLAInstanceID || instance.Version() != request.ExpectedMetricVersion ||
		state.AggregateVersion != request.ExpectedAggregateVersion ||
		state.AggregateVersion >= uint64(math.MaxInt64-1) ||
		!validMetricOverrideInventory(state.Metrics, instance) ||
		state.ReplacementPolicy != nil || len(state.ReplacementCalendars) != 0 ||
		len(state.ReplacementColumns) != 0 {
		return OverridePlan{}, kernel.ErrInvalidOverride
	}
	intent := request.Intent
	if intent.Kind == kernel.OverrideChangeCalendar {
		if state.ReplacementCalendar == nil || state.ReplacementCalendar.ID() != intent.ReplacementCalendarID ||
			state.ReplacementCalendar.Version() != intent.ReplacementCalendarVersion {
			return OverridePlan{}, kernel.ErrInvalidOverride
		}
	} else if state.ReplacementCalendar != nil {
		return OverridePlan{}, kernel.ErrInvalidOverride
	}
	tenantEntity, err := kernelTenantID(tenantID)
	if err != nil {
		return OverridePlan{}, kernel.ErrInvalidOverride
	}
	actorEntity, err := kernel.ParseEntityID(actor.MembershipID.String())
	if err != nil {
		return OverridePlan{}, kernel.ErrInvalidOverride
	}
	command := kernel.OverrideCommand{
		ID: intent.ID, TenantID: tenantEntity, ObjectID: request.ObjectID, ActorID: actorEntity,
		Kind: intent.Kind, Reason: intent.Reason, OccurredAt: state.OccurredAt,
		Extension: intent.Extension, SimulationDigest: intent.SimulationDigest,
	}
	updated, record, changed, err := instance.ApplyOverrideContext(ctx, request.ExpectedMetricVersion, command, kernel.OverrideAuthority{
		TenantID: tenantEntity, ActorID: actorEntity, CanOverride: true,
		PermissionEpoch: authority.PermissionEpoch, SubjectEpoch: authority.SubjectEpoch,
		EvaluatedAt: authority.EvaluatedAt, ValidUntil: authority.ValidUntil,
	}, work.Calendar, state.ReplacementCalendar)
	if err != nil {
		return OverridePlan{}, err
	}
	if !changed || record == nil {
		return OverridePlan{}, kernel.ErrInvalidOverride
	}
	work.Instance = updated
	if state.ReplacementCalendar != nil {
		calendar := *state.ReplacementCalendar
		work.Calendar = &calendar
	}
	materialization, err := kernel.PlanOverrideMaterializationContext(ctx, kernel.OverrideMaterializationInput{
		Work: work, Record: *record,
	})
	if err != nil {
		return OverridePlan{}, err
	}
	return OverridePlan{
		Instance: updated, Record: record, Materialization: &materialization,
		ExpectedAggregateVersion: state.AggregateVersion,
		NextAggregateVersion:     state.AggregateVersion + 1, Changed: changed,
	}, nil
}

func validMetricOverrideInventory(values []kernel.MetricWork, target kernel.MetricInstance) bool {
	if len(values) == 0 || len(values) > 32 {
		return false
	}
	seen := make(map[kernel.EntityID]struct{}, len(values))
	targetSeen := false
	for _, work := range values {
		instance := work.Instance
		if instance.TenantID() != target.TenantID() || instance.ObjectType() != target.ObjectType() ||
			instance.ObjectID() != target.ObjectID() || instance.SLAInstanceID() != target.SLAInstanceID() ||
			instance.PolicyID() != target.PolicyID() || instance.PolicyVersion() != target.PolicyVersion() {
			return false
		}
		if _, duplicate := seen[instance.ID()]; duplicate {
			return false
		}
		seen[instance.ID()] = struct{}{}
		targetSeen = targetSeen || instance.ID() == target.ID() && instance.Version() == target.Version()
	}
	return targetSeen
}

func planPolicyOverride(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	request OverrideRequest,
	authority Authority,
	state OverrideState,
) (OverridePlan, error) {
	intent := request.Intent
	if state.AggregateVersion != request.ExpectedAggregateVersion || state.AggregateVersion >= uint64(math.MaxInt64-1) ||
		state.ReplacementPolicy == nil ||
		state.ReplacementPolicy.ID() != intent.NewPolicyID ||
		state.ReplacementPolicy.Version() != intent.NewPolicyVersion || state.Metric != nil ||
		state.ReplacementCalendar != nil || len(state.Metrics) == 0 {
		return OverridePlan{}, kernel.ErrInvalidOverride
	}
	tenantEntity, err := kernelTenantID(tenantID)
	if err != nil {
		return OverridePlan{}, kernel.ErrInvalidOverride
	}
	actorEntity, err := kernel.ParseEntityID(actor.MembershipID.String())
	if err != nil {
		return OverridePlan{}, kernel.ErrInvalidOverride
	}
	command := kernel.OverrideCommand{
		ID: intent.ID, TenantID: tenantEntity, ObjectID: request.ObjectID, ActorID: actorEntity,
		Kind: kernel.OverrideChangePolicy, Reason: intent.Reason, OccurredAt: state.OccurredAt,
		NewPolicyID: intent.NewPolicyID, NewPolicyVersion: intent.NewPolicyVersion,
		SimulationDigest: intent.SimulationDigest,
	}
	policyPlan, err := kernel.PlanPolicyOverrideContext(ctx, kernel.PolicyOverrideInput{
		Metrics: slices.Clone(state.Metrics), ReplacementPolicy: *state.ReplacementPolicy,
		ReplacementCalendars: slices.Clone(state.ReplacementCalendars),
		ReplacementColumns:   slices.Clone(state.ReplacementColumns), Command: command,
		Authority: kernel.OverrideAuthority{
			TenantID: tenantEntity, ActorID: actorEntity, CanOverride: true,
			PermissionEpoch: authority.PermissionEpoch, SubjectEpoch: authority.SubjectEpoch,
			EvaluatedAt: authority.EvaluatedAt, ValidUntil: authority.ValidUntil,
		},
	})
	if err != nil || policyPlan.SLAInstanceID() != request.SLAInstanceID {
		if err != nil {
			return OverridePlan{}, err
		}
		return OverridePlan{}, kernel.ErrInvalidOverride
	}
	return OverridePlan{
		Policy: &policyPlan, ExpectedAggregateVersion: request.ExpectedAggregateVersion,
		NextAggregateVersion: request.ExpectedAggregateVersion + 1, Changed: true,
	}, nil
}

func validOverridePlan(
	actor Actor,
	tenantID uuid.UUID,
	request OverrideRequest,
	authority Authority,
	plan OverridePlan,
) bool {
	if !plan.Changed || plan.ExpectedAggregateVersion == 0 ||
		plan.ExpectedAggregateVersion >= uint64(math.MaxInt64-1) ||
		plan.NextAggregateVersion != plan.ExpectedAggregateVersion+1 {
		return false
	}
	actorID, err := kernel.ParseEntityID(actor.MembershipID.String())
	if err != nil {
		return false
	}
	validRecord := func(record kernel.OverrideRecord, instance kernel.MetricInstance) bool {
		next := record.Next()
		definition := instance.Definition()
		return record.ID() == request.Intent.ID && record.TenantID().String() == tenantID.String() &&
			record.ObjectID() == request.ObjectID && record.ActorID() == actorID &&
			record.Kind() == request.Intent.Kind && record.Reason() == request.Intent.Reason &&
			record.AuthorityEpoch() == authority.PermissionEpoch && record.SubjectEpoch() == authority.SubjectEpoch &&
			record.SimulationDigest() == request.Intent.SimulationDigest && record.CommandDigest() != ([32]byte{}) &&
			validInstant(record.OccurredAt()) && !record.OccurredAt().Before(authority.EvaluatedAt) &&
			record.OccurredAt().Before(authority.ValidUntil) && next.PolicyID() == instance.PolicyID() &&
			next.PolicyVersion() == instance.PolicyVersion() && next.MetricID() == definition.ID() &&
			next.MetricKey() == definition.Key() && sameEntityID(next.CalendarID(), definition.CalendarID()) &&
			next.CalendarVersion() == definition.CalendarVersion() && next.Extension() == instance.Extension() &&
			next.EffectiveDuration() == instance.EffectiveDuration()
	}
	if request.Intent.Kind == kernel.OverrideChangePolicy {
		records := []kernel.OverrideRecord(nil)
		metrics := []kernel.MetricWork(nil)
		materialized := []kernel.MetricPlan(nil)
		if plan.Policy != nil {
			records = plan.Policy.Records()
			metrics = plan.Policy.Metrics()
			materialized = plan.Policy.MaterializationPlan().Metrics()
		}
		if plan.Policy == nil || validKernelID(plan.Instance.ID()) || plan.Record != nil || plan.Materialization != nil ||
			plan.Policy.SLAInstanceID() != request.SLAInstanceID ||
			plan.Policy.ReplacementPolicy().ID() != request.Intent.NewPolicyID ||
			plan.Policy.ReplacementPolicy().Version() != request.Intent.NewPolicyVersion ||
			plan.ExpectedAggregateVersion != request.ExpectedAggregateVersion || len(records) == 0 || len(records) != len(metrics) ||
			len(materialized) != len(metrics) {
			return false
		}
		instances := make(map[kernel.Key]kernel.MetricInstance, len(metrics))
		instanceIDs := make(map[kernel.EntityID]struct{}, len(metrics))
		for _, work := range metrics {
			instance := work.Instance
			if instance.TenantID().String() != tenantID.String() || instance.ObjectType() != request.ObjectType ||
				instance.ObjectID() != request.ObjectID || instance.SLAInstanceID() != request.SLAInstanceID ||
				instance.PolicyID() != request.Intent.NewPolicyID ||
				instance.PolicyVersion() != request.Intent.NewPolicyVersion {
				return false
			}
			key := instance.Definition().Key()
			if _, duplicate := instances[key]; duplicate {
				return false
			}
			instances[key] = instance
			instanceIDs[instance.ID()] = struct{}{}
		}
		for _, record := range records {
			instance, exists := instances[record.Next().MetricKey()]
			if !exists || !validRecord(record, instance) ||
				record.Previous().PolicyID() != plan.Policy.PreviousPolicyID() ||
				record.Previous().PolicyVersion() != plan.Policy.PreviousPolicyVersion() ||
				record.Previous().MetricKey() != record.Next().MetricKey() {
				return false
			}
		}
		for _, metric := range materialized {
			instance := metric.Instance()
			if _, exists := instanceIDs[instance.ID()]; !exists ||
				instance.SLAInstanceID() != request.SLAInstanceID ||
				instance.PolicyID() != request.Intent.NewPolicyID ||
				instance.PolicyVersion() != request.Intent.NewPolicyVersion {
				return false
			}
		}
		return true
	}
	materialized := []kernel.MetricPlan(nil)
	if plan.Materialization != nil {
		materialized = plan.Materialization.Metrics()
	}
	if plan.Policy != nil || plan.Record == nil || plan.Materialization == nil || len(materialized) != 1 ||
		plan.Materialization.EventID() != nil || !plan.Materialization.ObservedAt().Equal(plan.Record.OccurredAt()) ||
		plan.Instance.SLAInstanceID() != request.SLAInstanceID ||
		plan.Instance.ID() != request.MetricInstanceID || plan.Instance.TenantID().String() != tenantID.String() ||
		plan.Instance.ObjectType() != request.ObjectType || plan.Instance.ObjectID() != request.ObjectID ||
		!validRecord(*plan.Record, plan.Instance) ||
		plan.ExpectedAggregateVersion != request.ExpectedAggregateVersion ||
		plan.Instance.Version() != request.ExpectedMetricVersion+1 || materialized[0].PreviousVersion() != plan.Instance.Version() ||
		materialized[0].Changed() || materialized[0].Instance().ID() != plan.Instance.ID() ||
		materialized[0].Instance().Version() != plan.Instance.Version() {
		return false
	}
	previous, next := plan.Record.Previous(), plan.Record.Next()
	if previous.PolicyID() != next.PolicyID() || previous.PolicyVersion() != next.PolicyVersion() ||
		previous.MetricID() != next.MetricID() || previous.MetricKey() != next.MetricKey() {
		return false
	}
	switch request.Intent.Kind {
	case kernel.OverrideExtend:
		return next.Extension() == previous.Extension()+request.Intent.Extension &&
			next.EffectiveDuration() == previous.EffectiveDuration()+request.Intent.Extension &&
			sameEntityID(previous.CalendarID(), next.CalendarID()) &&
			previous.CalendarVersion() == next.CalendarVersion()
	case kernel.OverrideChangeCalendar:
		calendarID := next.CalendarID()
		return calendarID != nil && *calendarID == request.Intent.ReplacementCalendarID &&
			next.CalendarVersion() == request.Intent.ReplacementCalendarVersion &&
			(!sameEntityID(previous.CalendarID(), next.CalendarID()) ||
				previous.CalendarVersion() != next.CalendarVersion())
	case kernel.OverrideSuspend, kernel.OverrideResume, kernel.OverrideComplete, kernel.OverrideRecalculate:
		return previous.Extension() == next.Extension() &&
			previous.EffectiveDuration() == next.EffectiveDuration() &&
			sameEntityID(previous.CalendarID(), next.CalendarID()) &&
			previous.CalendarVersion() == next.CalendarVersion()
	default:
		return false
	}
}

func validOverrideReceipt(
	actor Actor,
	tenantID uuid.UUID,
	request OverrideRequest,
	authority Authority,
	binding CommandBinding,
	receipt OverrideReceipt,
) bool {
	actorID, err := kernel.ParseEntityID(actor.MembershipID.String())
	if err != nil || receipt.Command != binding || receipt.OverrideID != request.Intent.ID ||
		receipt.TenantID != tenantID || receipt.ObjectType != request.ObjectType ||
		receipt.ObjectID != request.ObjectID || receipt.Kind != request.Intent.Kind ||
		receipt.SLAInstanceID != request.SLAInstanceID || receipt.PreviousVersion != overrideExpectedVersion(request) ||
		receipt.CurrentVersion != overrideExpectedVersion(request)+1 || receipt.CurrentVersion >= uint64(math.MaxInt64) ||
		receipt.AggregateVersion == 0 ||
		receipt.AggregateVersion >= uint64(math.MaxInt64) || !validKernelID(receipt.PolicyID) ||
		receipt.PolicyVersion == 0 || receipt.PolicyVersion >= uint64(math.MaxInt64) ||
		receipt.ActorID != actorID || receipt.PermissionEpoch != authority.PermissionEpoch ||
		receipt.SubjectEpoch != authority.SubjectEpoch || receipt.SimulationDigest != request.Intent.SimulationDigest ||
		!validInstant(receipt.OccurredAt) || receipt.OccurredAt.Before(authority.EvaluatedAt) ||
		!receipt.OccurredAt.Before(authority.ValidUntil) {
		return false
	}
	if request.Intent.Kind == kernel.OverrideChangePolicy {
		return receipt.Outcome == OverrideOutcomePolicyChanged && receipt.MetricInstanceID == nil &&
			receipt.AggregateVersion == receipt.CurrentVersion && receipt.PolicyID == request.Intent.NewPolicyID &&
			receipt.PolicyVersion == request.Intent.NewPolicyVersion
	}
	return receipt.Outcome == OverrideOutcomeMetricUpdated && receipt.MetricInstanceID != nil &&
		*receipt.MetricInstanceID == request.MetricInstanceID
}

func overrideReceiptForPlan(
	actor Actor,
	tenantID uuid.UUID,
	request OverrideRequest,
	authority Authority,
	binding CommandBinding,
	plan OverridePlan,
	occurredAt time.Time,
) OverrideReceipt {
	actorID, _ := kernel.ParseEntityID(actor.MembershipID.String())
	receipt := OverrideReceipt{
		Command: binding, OverrideID: request.Intent.ID, TenantID: tenantID,
		ObjectType: request.ObjectType, ObjectID: request.ObjectID,
		Kind: request.Intent.Kind, SLAInstanceID: request.SLAInstanceID,
		PreviousVersion: overrideExpectedVersion(request), AggregateVersion: plan.NextAggregateVersion,
		ActorID: actorID, PermissionEpoch: authority.PermissionEpoch,
		SubjectEpoch: authority.SubjectEpoch, OccurredAt: occurredAt,
		SimulationDigest: request.Intent.SimulationDigest,
	}
	if plan.Policy != nil {
		policy := plan.Policy.ReplacementPolicy()
		receipt.Outcome, receipt.CurrentVersion = OverrideOutcomePolicyChanged, plan.NextAggregateVersion
		receipt.PolicyID, receipt.PolicyVersion = policy.ID(), policy.Version()
		return receipt
	}
	instance := plan.Instance
	metricID := instance.ID()
	receipt.Outcome, receipt.MetricInstanceID = OverrideOutcomeMetricUpdated, &metricID
	receipt.CurrentVersion = instance.Version()
	receipt.PolicyID, receipt.PolicyVersion = instance.PolicyID(), instance.PolicyVersion()
	return receipt
}

func sameOverrideReceipt(left, right OverrideReceipt) bool {
	return left.Command == right.Command && left.OverrideID == right.OverrideID && left.TenantID == right.TenantID &&
		left.ObjectType == right.ObjectType && left.ObjectID == right.ObjectID && left.Outcome == right.Outcome &&
		left.Kind == right.Kind && left.SLAInstanceID == right.SLAInstanceID &&
		sameEntityID(left.MetricInstanceID, right.MetricInstanceID) && left.PreviousVersion == right.PreviousVersion &&
		left.CurrentVersion == right.CurrentVersion && left.AggregateVersion == right.AggregateVersion &&
		left.PolicyID == right.PolicyID && left.PolicyVersion == right.PolicyVersion && left.ActorID == right.ActorID &&
		left.PermissionEpoch == right.PermissionEpoch && left.SubjectEpoch == right.SubjectEpoch &&
		left.OccurredAt.Equal(right.OccurredAt) && left.SimulationDigest == right.SimulationDigest
}

func sameEntityID(left, right *kernel.EntityID) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func objectReadCapability(kind PrincipalKind, objectType kernel.ObjectType) (Capability, bool) {
	if kind == PrincipalCustomer {
		switch objectType {
		case kernel.ObjectAlert:
			return CapabilityPortalAlertRead, true
		case kernel.ObjectCase:
			return CapabilityPortalCaseRead, true
		default:
			return "", false
		}
	}
	if kind != PrincipalOperator {
		return "", false
	}
	switch objectType {
	case kernel.ObjectAlert:
		return CapabilityAlertRead, true
	case kernel.ObjectCase:
		return CapabilityCaseRead, true
	default:
		return "", false
	}
}

func overrideCapability(objectType kernel.ObjectType) (Capability, bool) {
	switch objectType {
	case kernel.ObjectAlert:
		return CapabilityAlertOverride, true
	case kernel.ObjectCase:
		return CapabilityCaseOverride, true
	default:
		return "", false
	}
}

func durationSecondsCeil(value time.Duration) int64 {
	if value <= 0 {
		return 0
	}
	return int64((value + time.Second - time.Microsecond) / time.Second)
}

func customerSafeState(value kernel.MetricState, customer bool) kernel.MetricState {
	if customer && value == kernel.StatePaused {
		return kernel.StateOnTrack
	}
	return value
}

func kernelTenantID(value uuid.UUID) (kernel.EntityID, error) {
	return kernel.ParseEntityID(value.String())
}

func validKernelID(value kernel.EntityID) bool {
	_, err := kernel.ParseEntityID(value.String())
	return err == nil
}

func eventRequestDigest(command EventCommand) [32]byte {
	return digestRequest("periapsis:sla-event:v1",
		[]byte(command.ObjectType), entityBytes(command.Event.ID), entityBytes(command.Event.TenantID),
		entityBytes(command.Event.ObjectID), []byte(command.Event.Key.String()),
		uint64Bytes(uint64(command.Event.OccurredAt.UnixMicro())), []byte(command.Origin), entityBytes(command.OriginID),
	)
}

func overrideRequestDigest(request OverrideRequest) [32]byte {
	intent := request.Intent
	return digestRequest("periapsis:sla-override-request:v1",
		[]byte(request.ObjectType), entityBytes(request.ObjectID), entityBytes(request.SLAInstanceID),
		entityBytes(request.MetricInstanceID),
		uint64Bytes(request.ExpectedMetricVersion), uint64Bytes(request.ExpectedAggregateVersion),
		entityBytes(intent.ID), []byte(intent.Kind), []byte(intent.Reason),
		uint64Bytes(uint64(intent.Extension)), entityBytes(intent.NewPolicyID), uint64Bytes(intent.NewPolicyVersion),
		entityBytes(intent.ReplacementCalendarID), uint64Bytes(intent.ReplacementCalendarVersion), intent.SimulationDigest[:],
	)
}

func overrideExpectedVersion(request OverrideRequest) uint64 {
	if request.Intent.Kind == kernel.OverrideChangePolicy {
		return request.ExpectedAggregateVersion
	}
	return request.ExpectedMetricVersion
}

func digestRequest(domain string, values ...[]byte) [32]byte {
	hash := sha256.New()
	buffer := make([]byte, 8)
	write := func(value []byte) {
		binary.BigEndian.PutUint64(buffer, uint64(len(value)))
		_, _ = hash.Write(buffer)
		_, _ = hash.Write(value)
	}
	write([]byte(domain))
	for _, value := range values {
		write(value)
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func entityBytes(value kernel.EntityID) []byte {
	bytes := value.Bytes()
	return slices.Clone(bytes[:])
}

func uint64Bytes(value uint64) []byte {
	result := make([]byte, 8)
	binary.BigEndian.PutUint64(result, value)
	return result
}

func (service Service) String() string   { return "sla.Service{repository:[REDACTED]}" }
func (service Service) GoString() string { return service.String() }
