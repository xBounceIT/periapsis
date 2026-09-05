package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/mfapolicy"
)

type unavailableMFAPolicyService struct{}

func mfaPolicyServiceIsNil(service MFAPolicyService) bool {
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

func (unavailableMFAPolicyService) ListPlatform(context.Context, authentication.Session, mfapolicy.ListInput) (mfapolicy.Page, error) {
	return mfapolicy.Page{}, mfapolicy.ErrUnavailable
}

func (unavailableMFAPolicyService) ListTenant(context.Context, authentication.Session, uuid.UUID, mfapolicy.ListInput) (mfapolicy.Page, error) {
	return mfapolicy.Page{}, mfapolicy.ErrUnavailable
}

func (unavailableMFAPolicyService) GetPlatform(context.Context, authentication.Session, uuid.UUID, int64) (mfa.PolicyDocument, error) {
	return mfa.PolicyDocument{}, mfapolicy.ErrUnavailable
}

func (unavailableMFAPolicyService) GetTenant(context.Context, authentication.Session, uuid.UUID, uuid.UUID, int64) (mfa.PolicyDocument, error) {
	return mfa.PolicyDocument{}, mfapolicy.ErrUnavailable
}

func (unavailableMFAPolicyService) SimulatePlatform(context.Context, authentication.Session, mfapolicy.SimulationInput) (mfa.PolicySimulation, error) {
	return mfa.PolicySimulation{}, mfapolicy.ErrUnavailable
}

func (unavailableMFAPolicyService) SimulateTenant(context.Context, authentication.Session, uuid.UUID, mfapolicy.SimulationInput) (mfa.PolicySimulation, error) {
	return mfa.PolicySimulation{}, mfapolicy.ErrUnavailable
}

func (unavailableMFAPolicyService) PublishPlatform(context.Context, authentication.Session, mfapolicy.PublishInput) (mfapolicy.MutationResult, error) {
	return mfapolicy.MutationResult{}, mfapolicy.ErrUnavailable
}

func (unavailableMFAPolicyService) PublishTenant(context.Context, authentication.Session, uuid.UUID, mfapolicy.PublishInput) (mfapolicy.MutationResult, error) {
	return mfapolicy.MutationResult{}, mfapolicy.ErrUnavailable
}

func (unavailableMFAPolicyService) RetirePlatform(context.Context, authentication.Session, mfapolicy.RetireInput) (mfapolicy.MutationResult, error) {
	return mfapolicy.MutationResult{}, mfapolicy.ErrUnavailable
}

func (unavailableMFAPolicyService) RetireTenant(context.Context, authentication.Session, uuid.UUID, mfapolicy.RetireInput) (mfapolicy.MutationResult, error) {
	return mfapolicy.MutationResult{}, mfapolicy.ErrUnavailable
}

func (h *Handler) ListPlatformMfaPolicies(
	w http.ResponseWriter,
	r *http.Request,
	params contract.ListPlatformMfaPoliciesParams,
) {
	session, ok := h.mfaPolicySession(w, r, false)
	if !ok {
		return
	}
	input, err := mfaPolicyListInput(params.AfterId, params.AfterRevision, params.Limit, params.IncludeRetired)
	if err != nil || requireTenantLDAPBodyAbsent(r) != nil {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	page, err := h.mfaPolicies.ListPlatform(r.Context(), session, input)
	if err != nil {
		h.writeMFAPolicyError(w, r, err)
		return
	}
	h.writeMFAPolicyPage(w, r, page)
}

func (h *Handler) ListTenantMfaPolicies(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.ListTenantMfaPoliciesParams,
) {
	session, ok := h.mfaPolicySession(w, r, false)
	if !ok {
		return
	}
	tenant := uuid.UUID(tenantID)
	input, err := mfaPolicyListInput(params.AfterId, params.AfterRevision, params.Limit, params.IncludeRetired)
	if err != nil || !validMFAPolicyUUID(tenant) || requireTenantLDAPBodyAbsent(r) != nil {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	page, err := h.mfaPolicies.ListTenant(r.Context(), session, tenant, input)
	if err != nil {
		h.writeMFAPolicyError(w, r, err)
		return
	}
	h.writeMFAPolicyPage(w, r, page)
}

func (h *Handler) GetPlatformMfaPolicyRevision(
	w http.ResponseWriter,
	r *http.Request,
	policyID contract.MfaPolicyId,
	revision contract.MfaPolicyRevision,
) {
	session, ok := h.mfaPolicySession(w, r, false)
	if !ok {
		return
	}
	document, err := h.mfaPolicies.GetPlatform(r.Context(), session, uuid.UUID(policyID), revision)
	if err != nil || requireTenantLDAPBodyAbsent(r) != nil {
		if err == nil {
			err = mfapolicy.ErrInvalidInput
		}
		h.writeMFAPolicyError(w, r, err)
		return
	}
	h.writeMFAPolicyDocument(w, r, document)
}

func (h *Handler) GetTenantMfaPolicyRevision(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	policyID contract.MfaPolicyId,
	revision contract.MfaPolicyRevision,
) {
	session, ok := h.mfaPolicySession(w, r, false)
	if !ok {
		return
	}
	tenant := uuid.UUID(tenantID)
	if !validMFAPolicyUUID(tenant) || requireTenantLDAPBodyAbsent(r) != nil {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	document, err := h.mfaPolicies.GetTenant(r.Context(), session, tenant, uuid.UUID(policyID), revision)
	if err != nil {
		h.writeMFAPolicyError(w, r, err)
		return
	}
	h.writeMFAPolicyDocument(w, r, document)
}

func (h *Handler) SimulatePlatformMfaPolicyChange(w http.ResponseWriter, r *http.Request) {
	session, ok := h.mfaPolicySession(w, r, true)
	if !ok {
		return
	}
	var body contract.PlatformMfaPolicySimulationRequest
	if err := decodePlatformMFAPolicySimulationBody(r, &body); err != nil {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	input, err := platformMFAPolicySimulationInput(body)
	if err != nil {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	result, err := h.mfaPolicies.SimulatePlatform(r.Context(), session, input)
	if err != nil {
		h.writeMFAPolicyError(w, r, err)
		return
	}
	h.writeMFAPolicySimulation(w, r, result)
}

func (h *Handler) SimulateTenantMfaPolicyChange(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
) {
	session, ok := h.mfaPolicySession(w, r, true)
	if !ok {
		return
	}
	tenant := uuid.UUID(tenantID)
	if !validMFAPolicyUUID(tenant) {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	var body contract.TenantMfaPolicySimulationRequest
	if err := decodeTenantMFAPolicySimulationBody(r, &body); err != nil {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	input, err := tenantMFAPolicySimulationInput(body)
	if err != nil {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	result, err := h.mfaPolicies.SimulateTenant(r.Context(), session, tenant, input)
	if err != nil {
		h.writeMFAPolicyError(w, r, err)
		return
	}
	h.writeMFAPolicySimulation(w, r, result)
}

func (h *Handler) PublishPlatformMfaPolicy(
	w http.ResponseWriter,
	r *http.Request,
	params contract.PublishPlatformMfaPolicyParams,
) {
	session, event, ok := h.mfaPolicyMutation(w, r)
	if !ok {
		return
	}
	commandID, reason, err := mfaPolicyCommandHeaders(r, uuid.UUID(params.IdempotencyKey), string(params.XAuditReason))
	if err != nil {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	var body contract.PlatformMfaPolicyCreateRequest
	if err = decodePlatformMFAPolicyCreateBody(r, &body); err != nil {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	target, targetErr := platformMFAPolicyTarget(body.Target)
	requirement, requirementErr := mfaPolicyRequirement(body.Requirement)
	if targetErr != nil || requirementErr != nil || body.ExpectedRevision != contract.PlatformMfaPolicyCreateRequestExpectedRevisionN0 {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	result, err := h.mfaPolicies.PublishPlatform(r.Context(), session, mfapolicy.PublishInput{
		CommandID: commandID, Target: target, ExpectedRevision: 0,
		Requirement: requirement, Reason: reason, Event: event,
	})
	if err != nil {
		h.writeMFAPolicyError(w, r, err)
		return
	}
	h.writeMFAPolicyMutation(w, r, http.StatusCreated, result, true, uuid.Nil)
}

func (h *Handler) PublishTenantMfaPolicy(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.PublishTenantMfaPolicyParams,
) {
	session, event, ok := h.mfaPolicyMutation(w, r)
	if !ok {
		return
	}
	tenant := uuid.UUID(tenantID)
	commandID, reason, err := mfaPolicyCommandHeaders(r, uuid.UUID(params.IdempotencyKey), string(params.XAuditReason))
	if err != nil || !validMFAPolicyUUID(tenant) {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	var body contract.TenantMfaPolicyCreateRequest
	if err = decodeTenantMFAPolicyCreateBody(r, &body); err != nil {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	target, targetErr := tenantMFAPolicyTarget(body.Target)
	requirement, requirementErr := mfaPolicyRequirement(body.Requirement)
	if targetErr != nil || requirementErr != nil || body.ExpectedRevision != contract.TenantMfaPolicyCreateRequestExpectedRevisionN0 {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	result, err := h.mfaPolicies.PublishTenant(r.Context(), session, tenant, mfapolicy.PublishInput{
		CommandID: commandID, Target: target, ExpectedRevision: 0,
		Requirement: requirement, Reason: reason, Event: event,
	})
	if err != nil {
		h.writeMFAPolicyError(w, r, err)
		return
	}
	h.writeMFAPolicyMutation(w, r, http.StatusCreated, result, false, tenant)
}

func (h *Handler) ReplacePlatformMfaPolicy(
	w http.ResponseWriter,
	r *http.Request,
	policyID contract.MfaPolicyId,
	params contract.ReplacePlatformMfaPolicyParams,
) {
	session, event, ok := h.mfaPolicyMutation(w, r)
	if !ok {
		return
	}
	id := uuid.UUID(policyID)
	commandID, reason, err := mfaPolicyCommandHeaders(r, uuid.UUID(params.IdempotencyKey), string(params.XAuditReason))
	if err != nil || !validMFAPolicyUUID(id) {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	var body contract.PlatformMfaPolicyReplaceRequest
	if err = decodePlatformMFAPolicyReplaceBody(r, &body); err != nil {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	if !h.mfaPolicyPrecondition(w, r, string(params.IfMatch), body.ExpectedRevision, true) {
		return
	}
	target, targetErr := platformMFAPolicyTarget(body.Target)
	requirement, requirementErr := mfaPolicyRequirement(body.Requirement)
	if targetErr != nil || requirementErr != nil {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	result, err := h.mfaPolicies.PublishPlatform(r.Context(), session, mfapolicy.PublishInput{
		CommandID: commandID, Target: target, ExpectedRevision: body.ExpectedRevision,
		ExpectedPolicyID: &id, Requirement: requirement, Reason: reason, Event: event,
	})
	if err != nil {
		h.writeMFAPolicyError(w, r, err)
		return
	}
	h.writeMFAPolicyMutation(w, r, http.StatusOK, result, true, uuid.Nil)
}

func (h *Handler) ReplaceTenantMfaPolicy(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	policyID contract.MfaPolicyId,
	params contract.ReplaceTenantMfaPolicyParams,
) {
	session, event, ok := h.mfaPolicyMutation(w, r)
	if !ok {
		return
	}
	tenant, id := uuid.UUID(tenantID), uuid.UUID(policyID)
	commandID, reason, err := mfaPolicyCommandHeaders(r, uuid.UUID(params.IdempotencyKey), string(params.XAuditReason))
	if err != nil || !validMFAPolicyUUID(tenant) || !validMFAPolicyUUID(id) {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	var body contract.TenantMfaPolicyReplaceRequest
	if err = decodeTenantMFAPolicyReplaceBody(r, &body); err != nil {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	if !h.mfaPolicyPrecondition(w, r, string(params.IfMatch), body.ExpectedRevision, true) {
		return
	}
	target, targetErr := tenantMFAPolicyTarget(body.Target)
	requirement, requirementErr := mfaPolicyRequirement(body.Requirement)
	if targetErr != nil || requirementErr != nil {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	result, err := h.mfaPolicies.PublishTenant(r.Context(), session, tenant, mfapolicy.PublishInput{
		CommandID: commandID, Target: target, ExpectedRevision: body.ExpectedRevision,
		ExpectedPolicyID: &id, Requirement: requirement, Reason: reason, Event: event,
	})
	if err != nil {
		h.writeMFAPolicyError(w, r, err)
		return
	}
	h.writeMFAPolicyMutation(w, r, http.StatusOK, result, false, tenant)
}

func (h *Handler) RetirePlatformMfaPolicy(
	w http.ResponseWriter,
	r *http.Request,
	policyID contract.MfaPolicyId,
	params contract.RetirePlatformMfaPolicyParams,
) {
	session, event, ok := h.mfaPolicyMutation(w, r)
	if !ok {
		return
	}
	id := uuid.UUID(policyID)
	commandID, reason, err := mfaPolicyCommandHeaders(r, uuid.UUID(params.IdempotencyKey), string(params.XAuditReason))
	if err != nil || !validMFAPolicyUUID(id) {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	var body contract.PlatformMfaPolicyRetireRequest
	if err = decodePlatformMFAPolicyRetireBody(r, &body); err != nil {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	if !h.mfaPolicyPrecondition(w, r, string(params.IfMatch), body.ExpectedRevision, false) {
		return
	}
	target, err := platformMFAPolicyTarget(body.Target)
	if err != nil {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	result, err := h.mfaPolicies.RetirePlatform(r.Context(), session, mfapolicy.RetireInput{
		CommandID: commandID, Target: target, ExpectedRevision: body.ExpectedRevision,
		ExpectedPolicyID: id, Reason: reason, Event: event,
	})
	if err != nil {
		h.writeMFAPolicyError(w, r, err)
		return
	}
	h.writeMFAPolicyMutation(w, r, http.StatusOK, result, true, uuid.Nil)
}

func (h *Handler) RetireTenantMfaPolicy(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	policyID contract.MfaPolicyId,
	params contract.RetireTenantMfaPolicyParams,
) {
	session, event, ok := h.mfaPolicyMutation(w, r)
	if !ok {
		return
	}
	tenant, id := uuid.UUID(tenantID), uuid.UUID(policyID)
	commandID, reason, err := mfaPolicyCommandHeaders(r, uuid.UUID(params.IdempotencyKey), string(params.XAuditReason))
	if err != nil || !validMFAPolicyUUID(tenant) || !validMFAPolicyUUID(id) {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	var body contract.TenantMfaPolicyRetireRequest
	if err = decodeTenantMFAPolicyRetireBody(r, &body); err != nil {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	if !h.mfaPolicyPrecondition(w, r, string(params.IfMatch), body.ExpectedRevision, false) {
		return
	}
	target, err := tenantMFAPolicyTarget(body.Target)
	if err != nil {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return
	}
	result, err := h.mfaPolicies.RetireTenant(r.Context(), session, tenant, mfapolicy.RetireInput{
		CommandID: commandID, Target: target, ExpectedRevision: body.ExpectedRevision,
		ExpectedPolicyID: id, Reason: reason, Event: event,
	})
	if err != nil {
		h.writeMFAPolicyError(w, r, err)
		return
	}
	h.writeMFAPolicyMutation(w, r, http.StatusOK, result, false, tenant)
}

func mfaPolicyListInput(
	afterID *contract.MfaPolicyAfterId,
	afterRevision *contract.MfaPolicyAfterRevision,
	limit *contract.PageSize,
	includeRetired *contract.IncludeRetiredMfaPolicies,
) (mfapolicy.ListInput, error) {
	if afterID == nil != (afterRevision == nil) {
		return mfapolicy.ListInput{}, mfapolicy.ErrInvalidInput
	}
	input := mfapolicy.ListInput{IncludeRetired: includeRetired != nil && bool(*includeRetired)}
	if limit != nil {
		input.Limit = int(*limit)
	}
	if afterID != nil {
		input.After = &mfapolicy.Cursor{ID: uuid.UUID(*afterID), Revision: int64(*afterRevision)}
	}
	return input, nil
}

func platformMFAPolicySimulationInput(body contract.PlatformMfaPolicySimulationRequest) (mfapolicy.SimulationInput, error) {
	target, err := platformMFAPolicyTarget(body.Target)
	if err != nil {
		return mfapolicy.SimulationInput{}, err
	}
	return mfaPolicySimulationInput(body.Operation, target, body.ExpectedRevision, body.ExpectedPolicyId, body.Requirement, nil)
}

func tenantMFAPolicySimulationInput(body contract.TenantMfaPolicySimulationRequest) (mfapolicy.SimulationInput, error) {
	target, err := tenantMFAPolicyTarget(body.Target)
	if err != nil {
		return mfapolicy.SimulationInput{}, err
	}
	contextValue := mfaPolicySimulationContext(body.Context)
	return mfaPolicySimulationInput(body.Operation, target, body.ExpectedRevision, body.ExpectedPolicyId, body.Requirement, &contextValue)
}

func mfaPolicySimulationInput(
	operation contract.MfaPolicyOperation,
	target mfa.AdministrationTarget,
	expectedRevision int64,
	expectedPolicyID *uuid.UUID,
	requirement *contract.MfaPolicyRequirement,
	contextValue *mfa.PolicySimulationContext,
) (mfapolicy.SimulationInput, error) {
	input := mfapolicy.SimulationInput{
		Operation: mfa.PolicyChangeOperation(operation), Target: target,
		ExpectedRevision: expectedRevision, Context: contextValue,
	}
	if expectedPolicyID != nil {
		id := uuid.UUID(*expectedPolicyID)
		input.ExpectedPolicyID = &id
	}
	if requirement != nil {
		mapped, err := mfaPolicyRequirement(*requirement)
		if err != nil {
			return mfapolicy.SimulationInput{}, err
		}
		input.Requirement = &mapped
	}
	return input, nil
}

func (h *Handler) mfaPolicySession(w http.ResponseWriter, r *http.Request, mutation bool) (authentication.Session, bool) {
	return h.platformIdentityProviderSession(w, r, mutation)
}

func (h *Handler) mfaPolicyMutation(
	w http.ResponseWriter,
	r *http.Request,
) (authentication.Session, authentication.EventContext, bool) {
	session, ok := h.mfaPolicySession(w, r, true)
	if !ok {
		return authentication.Session{}, authentication.EventContext{}, false
	}
	event, err := h.eventContext(r)
	if err != nil {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return authentication.Session{}, authentication.EventContext{}, false
	}
	return session, event, true
}

func mfaPolicyCommandHeaders(r *http.Request, expected uuid.UUID, expectedReason string) (uuid.UUID, string, error) {
	command, err := singleHeader(r, idempotencyKeyHeader, 36)
	if err != nil {
		return uuid.Nil, "", err
	}
	parsed, err := uuid.Parse(command)
	if err != nil || command != parsed.String() || parsed != expected || !validMFAPolicyUUID(parsed) {
		return uuid.Nil, "", mfapolicy.ErrInvalidInput
	}
	reason, err := platformIdentityProviderAuditReason(r, expectedReason)
	if err != nil {
		return uuid.Nil, "", err
	}
	return parsed, reason, nil
}

func (h *Handler) mfaPolicyPrecondition(
	w http.ResponseWriter,
	r *http.Request,
	contractValue string,
	bodyRevision int64,
	requireHeadroom bool,
) bool {
	value, err := singleHeader(r, ifMatchHeader, 32)
	if err != nil {
		if len(r.Header.Values(ifMatchHeader)) == 0 {
			h.writeMFAPolicyError(w, r, mfapolicy.ErrPreconditionRequired)
		} else {
			h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		}
		return false
	}
	if value != contractValue || len(value) < 4 || !strings.HasPrefix(value, "\"v") || !strings.HasSuffix(value, "\"") {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return false
	}
	digits := value[2 : len(value)-1]
	if digits == "" || digits[0] == '0' {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return false
	}
	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
			return false
		}
	}
	revision, parseErr := strconv.ParseInt(digits, 10, 64)
	maximum := mfapolicy.MaximumSafeRevision
	if requireHeadroom {
		maximum--
	}
	if parseErr != nil || revision < 1 || revision > maximum || bodyRevision != revision {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrInvalidInput)
		return false
	}
	return true
}

func (h *Handler) writeMFAPolicyPage(w http.ResponseWriter, r *http.Request, value mfapolicy.Page) {
	mapped, err := mapMFAPolicyPage(value)
	if err != nil {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) writeMFAPolicyDocument(w http.ResponseWriter, r *http.Request, value mfa.PolicyDocument) {
	mapped, err := mapMFAPolicyDocument(value)
	if err != nil || !setMFAPolicyETag(w, value.Revision) {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) writeMFAPolicySimulation(w http.ResponseWriter, r *http.Request, value mfa.PolicySimulation) {
	mapped, err := mapMFAPolicySimulation(value)
	if err != nil {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) writeMFAPolicyMutation(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	value mfapolicy.MutationResult,
	platform bool,
	tenantID uuid.UUID,
) {
	mapped, err := mapMFAPolicyMutation(value)
	if err != nil || !setMFAPolicyETag(w, value.Policy.Revision) {
		h.writeMFAPolicyError(w, r, mfapolicy.ErrUnavailable)
		return
	}
	if status == http.StatusCreated {
		w.Header().Set("Location", mfaPolicyRevisionLocation(platform, tenantID, uuid.UUID(value.Policy.ID), value.Policy.Revision))
	}
	writeSensitiveJSON(w, status, mapped)
}

func setMFAPolicyETag(w http.ResponseWriter, revision int64) bool {
	if revision < 1 || revision > mfapolicy.MaximumSafeRevision {
		return false
	}
	w.Header().Set("ETag", "\"v"+strconv.FormatInt(revision, 10)+"\"")
	return true
}

func mfaPolicyRevisionLocation(platform bool, tenantID, policyID uuid.UUID, revision int64) string {
	if platform {
		return fmt.Sprintf("/api/v1/platform/mfa-policies/%s/revisions/%d", policyID, revision)
	}
	return fmt.Sprintf("/api/v1/tenants/%s/mfa-policies/%s/revisions/%d", tenantID, policyID, revision)
}

func (h *Handler) writeMFAPolicyError(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Cache-Control", "no-store")
	if errors.Is(err, context.Canceled) {
		if errors.Is(r.Context().Err(), context.Canceled) {
			return
		}
		err = mfapolicy.ErrUnavailable
	}
	if errors.Is(err, context.DeadlineExceeded) {
		err = mfapolicy.ErrUnavailable
	}
	switch {
	case errors.Is(err, mfapolicy.ErrInvalidInput):
		writeProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", "The MFA policy request is malformed or fails bounded validation.")
	case errors.Is(err, mfapolicy.ErrForbidden):
		writeProblem(w, r, http.StatusForbidden, "forbidden", "Forbidden", "The MFA policy action is not permitted.")
	case errors.Is(err, mfapolicy.ErrNotFound):
		writeProblem(w, r, http.StatusNotFound, "not_found", "Resource not found", "The requested MFA policy does not exist.")
	case errors.Is(err, mfapolicy.ErrRecoveryUnsafe):
		writeProblem(w, r, http.StatusConflict, "mfa_policy_recovery_unsafe", "Recovery safety conflict", "Publishing this policy would leave no ready direct administrator.")
	case errors.Is(err, mfapolicy.ErrConflict):
		writeProblem(w, r, http.StatusConflict, "conflict", "Conflict", "The MFA policy request conflicts with current state or a prior command.")
	case errors.Is(err, mfapolicy.ErrPreconditionRequired):
		writeProblem(w, r, http.StatusPreconditionRequired, "precondition_required", "Precondition required", "A current strong MFA policy If-Match entity tag is required.")
	case errors.Is(err, mfapolicy.ErrPreconditionFailed):
		writeProblem(w, r, http.StatusPreconditionFailed, "precondition_failed", "Precondition failed", "The MFA policy changed after the supplied revision was issued.")
	case errors.Is(err, mfapolicy.ErrUnavailable):
		w.Header().Set("Retry-After", "5")
		writeProblem(w, r, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable", "A required protected MFA policy dependency is unavailable.")
	default:
		writeProblem(w, r, http.StatusInternalServerError, "internal_error", "Internal server error", "The MFA policy request could not be completed.")
	}
}

var _ MFAPolicyService = unavailableMFAPolicyService{}
