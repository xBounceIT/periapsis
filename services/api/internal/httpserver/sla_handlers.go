package httpserver

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	kernel "github.com/periapsis-im/periapsis/modules/sla"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationsla "github.com/periapsis-im/periapsis/services/api/internal/sla"
)

func (h *Handler) ListTenantSLABusinessCalendars(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, params contract.ListTenantSLABusinessCalendarsParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.slaOperatorReadActor(w, r, tenant)
	if !ok {
		return
	}
	input, err := slaListInput(params.After, params.Limit, params.IncludeArchived)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	page, err := h.sla.ListCalendars(r.Context(), actor, tenant, input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.SLABusinessCalendar, len(page.Items))
	for index, item := range page.Items {
		items[index], err = mapSLACalendar(item)
		if err != nil {
			writeDomainError(w, r, applicationsla.ErrUnavailable)
			return
		}
	}
	writeSensitiveJSON(w, http.StatusOK, contract.SLABusinessCalendarPage{
		TenantId: tenant, Items: items, NextCursor: slaCursorPointer(page.NextCursor),
	})
}

func (h *Handler) CreateTenantSLABusinessCalendar(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, _ contract.CreateTenantSLABusinessCalendarParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, envelope, ok := h.slaMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body slaCalendarCreateBody
	if decodeSLABody(r, &body) != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return
	}
	input, err := slaCalendarInput(tenant, body.ID, 1, body.Key, body.Label, body.Timezone, body.WeeklySchedules, body.Exceptions)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.sla.PublishCalendar(r.Context(), actor, tenant, applicationsla.CalendarPublishCommand{
		Input: input, ExpectedActiveVersion: 0, Envelope: envelope,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapSLACalendar(calendarPublicationRecord(result))
	if err != nil || !setSLAConfigurationETag(w, applicationsla.ArchiveCalendar, result.Value.ID(), result.ResourceVersion) {
		writeDomainError(w, r, applicationsla.ErrUnavailable)
		return
	}
	w.Header().Set("Location", r.URL.Path+"/"+body.ID.String())
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) GetTenantSLABusinessCalendar(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, calendarID contract.SLABusinessCalendarId,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.slaOperatorReadActor(w, r, tenant)
	if !ok {
		return
	}
	id, err := slaEntity(uuid.UUID(calendarID))
	if err != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return
	}
	record, err := h.sla.GetCalendar(r.Context(), actor, tenant, id)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapSLACalendar(record)
	if err != nil || !setSLAConfigurationETag(w, applicationsla.ArchiveCalendar, id, record.ResourceVersion) {
		writeDomainError(w, r, applicationsla.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ReplaceTenantSLABusinessCalendar(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, calendarID contract.SLABusinessCalendarId,
	_ contract.ReplaceTenantSLABusinessCalendarParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, envelope, ok := h.slaMutationContext(w, r, tenant)
	if !ok {
		return
	}
	id, err := slaEntity(uuid.UUID(calendarID))
	if err != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return
	}
	expected, ok := requireSLAConfigurationPrecondition(w, r, applicationsla.ArchiveCalendar, id)
	if !ok {
		return
	}
	var body slaCalendarReplaceBody
	if decodeSLABody(r, &body) != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return
	}
	input, err := slaCalendarInput(tenant, uuid.UUID(calendarID), expected+1, body.Key, body.Label, body.Timezone, body.WeeklySchedules, body.Exceptions)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.sla.PublishCalendar(r.Context(), actor, tenant, applicationsla.CalendarPublishCommand{
		Input: input, ExpectedActiveVersion: expected, Envelope: envelope,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapSLACalendar(calendarPublicationRecord(result))
	if err != nil || !setSLAConfigurationETag(w, applicationsla.ArchiveCalendar, result.Value.ID(), result.ResourceVersion) {
		writeDomainError(w, r, applicationsla.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ArchiveTenantSLABusinessCalendar(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, calendarID contract.SLABusinessCalendarId,
	_ contract.ArchiveTenantSLABusinessCalendarParams,
) {
	h.archiveSLAConfiguration(w, r, uuid.UUID(tenantID), uuid.UUID(calendarID), applicationsla.ArchiveCalendar)
}

func (h *Handler) ListTenantSLAPolicies(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, params contract.ListTenantSLAPoliciesParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.slaOperatorReadActor(w, r, tenant)
	if !ok {
		return
	}
	input, err := slaListInput(params.After, params.Limit, params.IncludeArchived)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	page, err := h.sla.ListPolicies(r.Context(), actor, tenant, input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.SLAPolicy, len(page.Items))
	for index, item := range page.Items {
		items[index], err = mapSLAPolicy(item)
		if err != nil {
			writeDomainError(w, r, applicationsla.ErrUnavailable)
			return
		}
	}
	writeSensitiveJSON(w, http.StatusOK, contract.SLAPolicyPage{TenantId: tenant, Items: items, NextCursor: slaCursorPointer(page.NextCursor)})
}

func (h *Handler) CreateTenantSLAPolicy(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, _ contract.CreateTenantSLAPolicyParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, envelope, ok := h.slaMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body slaPolicyCreateBody
	if decodeSLABody(r, &body) != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return
	}
	input, err := slaPolicyInput(tenant, body.ID, 1, body.Key, body.Name, body.Description, body.Priority, body.ObjectTypes,
		body.MatchRule, body.EffectiveFrom, body.EffectiveUntil, body.Enabled, body.ApplyToSLAEngineSource, body.Metrics, body.Triggers)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.sla.PublishPolicy(r.Context(), actor, tenant, applicationsla.PolicyPublishCommand{
		Input: input, ExpectedActiveVersion: 0, Envelope: envelope,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapSLAPolicy(policyPublicationRecord(result))
	if err != nil || !setSLAConfigurationETag(w, applicationsla.ArchivePolicy, result.Value.ID(), result.ResourceVersion) {
		writeDomainError(w, r, applicationsla.ErrUnavailable)
		return
	}
	w.Header().Set("Location", r.URL.Path+"/"+body.ID.String())
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) GetTenantSLAPolicy(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, policyID contract.SLAPolicyId,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.slaOperatorReadActor(w, r, tenant)
	if !ok {
		return
	}
	id, err := slaEntity(uuid.UUID(policyID))
	if err != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return
	}
	record, err := h.sla.GetPolicy(r.Context(), actor, tenant, id)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapSLAPolicy(record)
	if err != nil || !setSLAConfigurationETag(w, applicationsla.ArchivePolicy, id, record.ResourceVersion) {
		writeDomainError(w, r, applicationsla.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ReplaceTenantSLAPolicy(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, policyID contract.SLAPolicyId,
	_ contract.ReplaceTenantSLAPolicyParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, envelope, ok := h.slaMutationContext(w, r, tenant)
	if !ok {
		return
	}
	id, err := slaEntity(uuid.UUID(policyID))
	if err != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return
	}
	expected, ok := requireSLAConfigurationPrecondition(w, r, applicationsla.ArchivePolicy, id)
	if !ok {
		return
	}
	var body slaPolicyReplaceBody
	if decodeSLABody(r, &body) != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return
	}
	input, err := slaPolicyInput(tenant, uuid.UUID(policyID), expected+1, body.Key, body.Name, body.Description, body.Priority,
		body.ObjectTypes, body.MatchRule, body.EffectiveFrom, body.EffectiveUntil, body.Enabled,
		body.ApplyToSLAEngineSource, body.Metrics, body.Triggers)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.sla.PublishPolicy(r.Context(), actor, tenant, applicationsla.PolicyPublishCommand{
		Input: input, ExpectedActiveVersion: expected, Envelope: envelope,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapSLAPolicy(policyPublicationRecord(result))
	if err != nil || !setSLAConfigurationETag(w, applicationsla.ArchivePolicy, result.Value.ID(), result.ResourceVersion) {
		writeDomainError(w, r, applicationsla.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ArchiveTenantSLAPolicy(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, policyID contract.SLAPolicyId,
	_ contract.ArchiveTenantSLAPolicyParams,
) {
	h.archiveSLAConfiguration(w, r, uuid.UUID(tenantID), uuid.UUID(policyID), applicationsla.ArchivePolicy)
}

func (h *Handler) SimulateTenantSLAPolicy(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, policyID contract.SLAPolicyId,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.slaOperatorReadActor(w, r, tenant)
	if !ok {
		return
	}
	id, err := slaEntity(uuid.UUID(policyID))
	if err != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return
	}
	var body slaSimulationBody
	if decodeSLABody(r, &body) != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return
	}
	command, err := slaSimulationCommand(tenant, body)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	command.PolicyID = id
	result, err := h.sla.Simulate(r.Context(), actor, tenant, command)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapSLASimulation(tenant, result)
	if err != nil {
		writeDomainError(w, r, applicationsla.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ListTenantSLAColumns(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, params contract.ListTenantSLAColumnsParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.slaOperatorReadActor(w, r, tenant)
	if !ok {
		return
	}
	input, err := slaListInput(params.After, params.Limit, params.IncludeArchived)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	page, err := h.sla.ListColumns(r.Context(), actor, tenant, input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.SLAColumn, len(page.Items))
	for index, item := range page.Items {
		items[index], err = mapSLAColumn(item)
		if err != nil {
			writeDomainError(w, r, applicationsla.ErrUnavailable)
			return
		}
	}
	writeSensitiveJSON(w, http.StatusOK, contract.SLAColumnPage{TenantId: tenant, Items: items, NextCursor: slaCursorPointer(page.NextCursor)})
}

func (h *Handler) CreateTenantSLAColumn(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, _ contract.CreateTenantSLAColumnParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, envelope, ok := h.slaMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body slaColumnCreateBody
	if decodeSLABody(r, &body) != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return
	}
	input, err := slaColumnInput(tenant, body.ID, 1, body.Key, body.Label, body.MetricDefinitionID, body.Calculation,
		body.Format, body.Sortable, body.Filterable, body.CustomerVisible, body.VisibleRoleKeys, body.Position, body.StyleRules)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.sla.PublishColumn(r.Context(), actor, tenant, applicationsla.ColumnPublishCommand{
		Input: input, ExpectedActiveVersion: 0, Envelope: envelope,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapSLAColumn(columnPublicationRecord(result))
	if err != nil || !setSLAConfigurationETag(w, applicationsla.ArchiveColumn, result.Value.ID(), result.ResourceVersion) {
		writeDomainError(w, r, applicationsla.ErrUnavailable)
		return
	}
	w.Header().Set("Location", r.URL.Path+"/"+body.ID.String())
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) GetTenantSLAColumn(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, columnID contract.SLAColumnId,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.slaOperatorReadActor(w, r, tenant)
	if !ok {
		return
	}
	id, err := slaEntity(uuid.UUID(columnID))
	if err != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return
	}
	record, err := h.sla.GetColumn(r.Context(), actor, tenant, id)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapSLAColumn(record)
	if err != nil || !setSLAConfigurationETag(w, applicationsla.ArchiveColumn, id, record.ResourceVersion) {
		writeDomainError(w, r, applicationsla.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ReplaceTenantSLAColumn(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, columnID contract.SLAColumnId,
	_ contract.ReplaceTenantSLAColumnParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, envelope, ok := h.slaMutationContext(w, r, tenant)
	if !ok {
		return
	}
	id, err := slaEntity(uuid.UUID(columnID))
	if err != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return
	}
	expected, ok := requireSLAConfigurationPrecondition(w, r, applicationsla.ArchiveColumn, id)
	if !ok {
		return
	}
	var body slaColumnReplaceBody
	if decodeSLABody(r, &body) != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return
	}
	input, err := slaColumnInput(tenant, uuid.UUID(columnID), expected+1, body.Key, body.Label, body.MetricDefinitionID,
		body.Calculation, body.Format, body.Sortable, body.Filterable, body.CustomerVisible,
		body.VisibleRoleKeys, body.Position, body.StyleRules)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.sla.PublishColumn(r.Context(), actor, tenant, applicationsla.ColumnPublishCommand{
		Input: input, ExpectedActiveVersion: expected, Envelope: envelope,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapSLAColumn(columnPublicationRecord(result))
	if err != nil || !setSLAConfigurationETag(w, applicationsla.ArchiveColumn, result.Value.ID(), result.ResourceVersion) {
		writeDomainError(w, r, applicationsla.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ArchiveTenantSLAColumn(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, columnID contract.SLAColumnId,
	_ contract.ArchiveTenantSLAColumnParams,
) {
	h.archiveSLAConfiguration(w, r, uuid.UUID(tenantID), uuid.UUID(columnID), applicationsla.ArchiveColumn)
}

func (h *Handler) GetTenantAlertSLA(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId,
) {
	h.getTenantObjectSLA(w, r, uuid.UUID(tenantID), uuid.UUID(alertID), kernel.ObjectAlert, applicationsla.PrincipalOperator)
}

func (h *Handler) GetCustomerPortalAlertSLA(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId,
) {
	h.getTenantObjectSLA(w, r, uuid.UUID(tenantID), uuid.UUID(alertID), kernel.ObjectAlert, applicationsla.PrincipalCustomer)
}

func (h *Handler) OverrideTenantAlertSLA(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId,
	_ contract.OverrideTenantAlertSLAParams,
) {
	h.overrideTenantObjectSLA(w, r, uuid.UUID(tenantID), uuid.UUID(alertID), kernel.ObjectAlert)
}

func (h *Handler) GetTenantCaseSLA(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId,
) {
	h.getTenantObjectSLA(w, r, uuid.UUID(tenantID), uuid.UUID(caseID), kernel.ObjectCase, applicationsla.PrincipalOperator)
}

func (h *Handler) GetCustomerPortalCaseSLA(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId,
) {
	h.getTenantObjectSLA(w, r, uuid.UUID(tenantID), uuid.UUID(caseID), kernel.ObjectCase, applicationsla.PrincipalCustomer)
}

func (h *Handler) OverrideTenantCaseSLA(
	w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId,
	_ contract.OverrideTenantCaseSLAParams,
) {
	h.overrideTenantObjectSLA(w, r, uuid.UUID(tenantID), uuid.UUID(caseID), kernel.ObjectCase)
}

func (h *Handler) getTenantObjectSLA(
	w http.ResponseWriter,
	r *http.Request,
	tenantID, objectUUID uuid.UUID,
	objectType kernel.ObjectType,
	intent applicationsla.PrincipalKind,
) {
	w.Header().Set("Cache-Control", "no-store")
	var actor applicationsla.Actor
	var ok bool
	switch intent {
	case applicationsla.PrincipalOperator:
		actor, ok = h.slaOperatorReadActor(w, r, tenantID)
	case applicationsla.PrincipalCustomer:
		actor, ok = h.slaCustomerReadActor(w, r, tenantID)
	default:
		writeDomainError(w, r, applicationsla.ErrForbidden)
		return
	}
	if !ok {
		return
	}
	objectID, err := slaEntity(objectUUID)
	if err != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return
	}
	projection, err := h.sla.ProjectObject(r.Context(), actor, tenantID, applicationsla.ObjectProjectionCommand{
		ObjectType: objectType, ObjectID: objectID, At: time.Now().UTC().Truncate(time.Microsecond),
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if projection.TenantID != tenantID || projection.ObjectType != objectType || projection.ObjectID != objectID {
		writeDomainError(w, r, applicationsla.ErrUnavailable)
		return
	}
	var mapped any
	var etag string
	if intent == applicationsla.PrincipalCustomer {
		mapped, err = mapSLACustomerObject(projection)
		etag = applicationsla.StrongCustomerObjectSLAETag(projection.SLAInstanceID, projection.AggregateVersion)
	} else {
		mapped, err = mapSLAOperatorObject(projection)
		etag = applicationsla.StrongObjectSLAETag(projection.SLAInstanceID, projection.AggregateVersion)
	}
	if err != nil || etag == "" {
		writeDomainError(w, r, applicationsla.ErrUnavailable)
		return
	}
	w.Header().Set("ETag", etag)
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) overrideTenantObjectSLA(
	w http.ResponseWriter, r *http.Request, tenantID, objectUUID uuid.UUID, objectType kernel.ObjectType,
) {
	actor, envelope, ok := h.slaMutationContext(w, r, tenantID)
	if !ok {
		return
	}
	objectID, err := slaEntity(objectUUID)
	if err != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return
	}
	var body slaOverrideBody
	if decodeSLABody(r, &body) != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return
	}
	slaInstanceID, err := slaEntity(body.SLAInstanceID)
	if err != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return
	}
	aggregateVersion, ok := requireSLAObjectPrecondition(w, r, slaInstanceID)
	if !ok {
		return
	}
	request, err := slaOverrideRequest(objectType, objectID, aggregateVersion, body, envelope)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.sla.Override(r.Context(), actor, tenantID, request)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped := mapSLAOverride(result)
	etag := applicationsla.StrongObjectSLAETag(result.Receipt.SLAInstanceID, result.Receipt.AggregateVersion)
	if etag == "" {
		writeDomainError(w, r, applicationsla.ErrUnavailable)
		return
	}
	w.Header().Set("ETag", etag)
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) archiveSLAConfiguration(
	w http.ResponseWriter, r *http.Request, tenantID, resourceUUID uuid.UUID, kind applicationsla.ArchiveKind,
) {
	actor, envelope, ok := h.slaMutationContext(w, r, tenantID)
	if !ok {
		return
	}
	id, err := slaEntity(resourceUUID)
	if err != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return
	}
	expected, ok := requireSLAConfigurationPrecondition(w, r, kind, id)
	if !ok {
		return
	}
	var body slaArchiveBody
	if decodeSLABody(r, &body) != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return
	}
	version, _, err := h.sla.Archive(r.Context(), actor, tenantID, applicationsla.ArchiveCommand{
		Kind: kind, ID: id, ExpectedVersion: expected, Reason: body.Reason, Envelope: envelope,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if !setSLAConfigurationETag(w, kind, id, version) {
		writeDomainError(w, r, applicationsla.ErrUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func slaListInput(after *contract.SLAAfterCursor, limit *contract.PageSize, includeArchived *contract.IncludeArchived) (applicationsla.ConfigurationListInput, error) {
	result := applicationsla.ConfigurationListInput{}
	if after != nil {
		result.After = string(*after)
	}
	if limit != nil {
		if *limit < 1 || *limit > 100 {
			return applicationsla.ConfigurationListInput{}, applicationsla.ErrInvalidInput
		}
		result.Limit = int(*limit)
	}
	if includeArchived != nil {
		result.IncludeArchived = bool(*includeArchived)
	}
	return result, nil
}

func slaCursorPointer(value string) *contract.SLAConfigurationCursor {
	if value == "" {
		return nil
	}
	result := contract.SLAConfigurationCursor(value)
	return &result
}

func requireSLAConfigurationPrecondition(
	w http.ResponseWriter, r *http.Request, kind applicationsla.ArchiveKind, id kernel.EntityID,
) (uint64, bool) {
	if len(r.Header.Values(ifMatchHeader)) == 0 {
		writeDomainError(w, r, authorization.ErrPreconditionRequired)
		return 0, false
	}
	value, err := singleHeader(r, ifMatchHeader, 96)
	if err != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return 0, false
	}
	version, err := applicationsla.ParseStrongConfigurationETag(value, kind, id)
	if err != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return 0, false
	}
	return version, true
}

func requireSLAObjectPrecondition(w http.ResponseWriter, r *http.Request, slaInstanceID kernel.EntityID) (uint64, bool) {
	if len(r.Header.Values(ifMatchHeader)) == 0 {
		writeDomainError(w, r, authorization.ErrPreconditionRequired)
		return 0, false
	}
	value, err := singleHeader(r, ifMatchHeader, 96)
	if err != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return 0, false
	}
	version, err := applicationsla.ParseStrongObjectSLAETag(value, slaInstanceID)
	if err != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return 0, false
	}
	return version, true
}

func setSLAConfigurationETag(w http.ResponseWriter, kind applicationsla.ArchiveKind, id kernel.EntityID, version uint64) bool {
	value := applicationsla.StrongConfigurationETag(kind, id, version)
	if value == "" {
		return false
	}
	w.Header().Set("ETag", value)
	return true
}

func calendarPublicationRecord(value applicationsla.PublicationResult[kernel.BusinessCalendar]) applicationsla.CalendarRecord {
	return applicationsla.CalendarRecord{Value: value.Value, ResourceVersion: value.ResourceVersion, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt, ArchivedAt: value.ArchivedAt}
}

func policyPublicationRecord(value applicationsla.PublicationResult[kernel.Policy]) applicationsla.PolicyRecord {
	return applicationsla.PolicyRecord{Value: value.Value, ResourceVersion: value.ResourceVersion, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt, ArchivedAt: value.ArchivedAt}
}

func columnPublicationRecord(value applicationsla.PublicationResult[kernel.ColumnDefinition]) applicationsla.ColumnRecord {
	return applicationsla.ColumnRecord{Value: value.Value, ResourceVersion: value.ResourceVersion, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt, ArchivedAt: value.ArchivedAt}
}
