package httpserver

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/webhookurlpolicy"
)

const webhookURLPolicyCacheControl = "private, no-store"

func (h *Handler) GetTenantWebhookUrlPolicy(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
) {
	session, ok := h.platformIdentityProviderSession(w, r, false)
	if !ok {
		return
	}
	tenant := uuid.UUID(tenantID)
	if !validWebhookURLPolicyUUID(tenant) {
		h.writeWebhookURLPolicyError(w, r, webhookurlpolicy.ErrInvalidInput)
		return
	}
	policy, err := h.webhookURLPolicy.Get(r.Context(), session, tenant)
	if err != nil {
		h.writeWebhookURLPolicyError(w, r, err)
		return
	}
	mapped, err := mapWebhookURLPolicy(policy, tenant)
	if err != nil || !setWebhookURLPolicyETag(w, policy.Version()) {
		h.writeWebhookURLPolicyError(w, r, webhookurlpolicy.ErrUnavailable)
		return
	}
	writeWebhookURLPolicyJSON(w, http.StatusOK, mapped)
}

func (h *Handler) PublishTenantWebhookUrlPolicy(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.PublishTenantWebhookUrlPolicyParams,
) {
	session, ok := h.platformIdentityProviderSession(w, r, true)
	if !ok {
		return
	}
	tenant := uuid.UUID(tenantID)
	if !validWebhookURLPolicyUUID(tenant) {
		h.writeWebhookURLPolicyError(w, r, webhookurlpolicy.ErrInvalidInput)
		return
	}
	var body contract.WebhookUrlPolicyPublishRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		h.writeWebhookURLPolicyError(w, r, webhookurlpolicy.ErrInvalidInput)
		return
	}
	expectedVersion, ok := webhookURLPolicyPrecondition(
		w, r, string(params.IfMatch), body.ExpectedVersion,
	)
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil || idempotencyKey != string(params.IdempotencyKey) {
		h.writeWebhookURLPolicyError(w, r, webhookurlpolicy.ErrInvalidInput)
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writeWebhookURLPolicyError(w, r, webhookurlpolicy.ErrInvalidInput)
		return
	}
	event, err := h.eventContext(r)
	if err != nil {
		h.writeWebhookURLPolicyError(w, r, webhookurlpolicy.ErrInvalidInput)
		return
	}
	rules, err := webhookURLPolicyRuleInputs(body.Rules)
	if err != nil {
		h.writeWebhookURLPolicyError(w, r, err)
		return
	}
	result, err := h.webhookURLPolicy.Publish(
		r.Context(), session, tenant,
		webhookurlpolicy.PublishInput{
			ExpectedVersion: expectedVersion,
			Policy:          webhookurlpolicy.PolicyDraft{Rules: rules},
			IdempotencyKey:  idempotencyKey,
			Reason:          reason,
			Event:           event,
		},
	)
	if err != nil {
		h.writeWebhookURLPolicyError(w, r, err)
		return
	}
	mapped, err := mapWebhookURLPolicy(result.Policy, tenant)
	if err != nil || !setWebhookURLPolicyETag(w, result.Policy.Version()) {
		h.writeWebhookURLPolicyError(w, r, webhookurlpolicy.ErrUnavailable)
		return
	}
	w.Header().Set(idempotentReplayHeader, strconv.FormatBool(result.Replayed))
	writeWebhookURLPolicyJSON(w, http.StatusOK, contract.WebhookUrlPolicyMutationResult{
		Policy: mapped, Replayed: result.Replayed,
	})
}

func webhookURLPolicyPrecondition(
	w http.ResponseWriter,
	r *http.Request,
	supplied string,
	bodyVersion int64,
) (int64, bool) {
	values := r.Header.Values(ifMatchHeader)
	if len(values) == 0 {
		w.Header().Set("Cache-Control", webhookURLPolicyCacheControl)
		writeProblem(
			w, r, http.StatusPreconditionRequired, "precondition_required",
			"Precondition required", "A current strong If-Match entity tag is required.",
		)
		return 0, false
	}
	if len(values) != 1 || values[0] != supplied {
		writeWebhookURLPolicyDomainError(w, r, webhookurlpolicy.ErrInvalidInput)
		return 0, false
	}
	value := values[0]
	if len(value) < len("\"v0\"") || value[:2] != "\"v" || value[len(value)-1:] != "\"" {
		writeWebhookURLPolicyDomainError(w, r, webhookurlpolicy.ErrInvalidInput)
		return 0, false
	}
	digits := value[2 : len(value)-1]
	if digits == "" || len(digits) > 1 && digits[0] == '0' {
		writeWebhookURLPolicyDomainError(w, r, webhookurlpolicy.ErrInvalidInput)
		return 0, false
	}
	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			writeWebhookURLPolicyDomainError(w, r, webhookurlpolicy.ErrInvalidInput)
			return 0, false
		}
	}
	version, err := strconv.ParseInt(digits, 10, 32)
	if err != nil || version < 0 || version >= webhookurlpolicy.MaximumPolicyVersion {
		writeWebhookURLPolicyDomainError(w, r, webhookurlpolicy.ErrInvalidInput)
		return 0, false
	}
	canonical := "\"v" + strconv.FormatInt(version, 10) + "\""
	if canonical != value || version != bodyVersion {
		w.Header().Set("Cache-Control", webhookURLPolicyCacheControl)
		writeProblem(
			w, r, http.StatusPreconditionFailed, "precondition_failed",
			"Precondition failed", "The webhook URL policy changed after the supplied entity tag was issued.",
		)
		return 0, false
	}
	return version, true
}

func webhookURLPolicyRuleInputs(
	rules []contract.WebhookUrlPolicyRuleWrite,
) ([]webhookurlpolicy.RuleInput, error) {
	if len(rules) > webhookurlpolicy.MaximumPolicyRules {
		return nil, webhookurlpolicy.ErrInvalidInput
	}
	result := make([]webhookurlpolicy.RuleInput, len(rules))
	for index, rule := range rules {
		if !rule.Effect.Valid() || !rule.Match.Valid() {
			return nil, webhookurlpolicy.ErrInvalidInput
		}
		port := 0
		if rule.Port != nil {
			port = *rule.Port
		}
		result[index] = webhookurlpolicy.RuleInput{
			Effect:   webhookurlpolicy.RuleEffect(rule.Effect),
			Match:    webhookurlpolicy.RuleMatch(rule.Match),
			Hostname: rule.Hostname,
			Port:     port,
		}
	}
	return result, nil
}

func mapWebhookURLPolicy(
	policy webhookurlpolicy.Policy,
	tenantID uuid.UUID,
) (contract.WebhookUrlPolicy, error) {
	if !validWebhookURLPolicyUUID(policy.ID()) ||
		!validWebhookURLPolicyUUID(policy.VersionID()) ||
		!validWebhookURLPolicyUUID(policy.PublishedByMembershipID()) ||
		policy.ID() == policy.VersionID() || policy.TenantID() != tenantID ||
		policy.Version() < 1 || policy.Version() > webhookurlpolicy.MaximumPolicyVersion ||
		policy.PublishedAt().IsZero() || policy.PublishedAt().Location() != time.UTC ||
		policy.PublishedAt().Nanosecond()%int(time.Millisecond) != 0 {
		return contract.WebhookUrlPolicy{}, webhookurlpolicy.ErrUnavailable
	}
	rules := policy.Rules()
	if len(rules) > webhookurlpolicy.MaximumPolicyRules {
		return contract.WebhookUrlPolicy{}, webhookurlpolicy.ErrUnavailable
	}
	mappedRules := make([]contract.WebhookUrlPolicyRule, len(rules))
	for index, rule := range rules {
		effect := contract.WebhookUrlPolicyEffect(rule.Effect())
		match := contract.WebhookUrlPolicyMatch(rule.Match())
		if !effect.Valid() || !match.Valid() || rule.Port() < 1 || rule.Port() > math.MaxUint16 ||
			rule.Hostname() == "" {
			return contract.WebhookUrlPolicy{}, webhookurlpolicy.ErrUnavailable
		}
		mappedRules[index] = contract.WebhookUrlPolicyRule{
			Effect: effect, Match: match, Hostname: rule.Hostname(), Port: rule.Port(),
		}
	}
	return contract.WebhookUrlPolicy{
		Id: policy.ID(), VersionId: policy.VersionID(), TenantId: tenantID,
		Version: contract.ResourceVersion(policy.Version()), Scheme: contract.Https,
		DefaultAction: contract.WebhookUrlPolicyDefaultActionDeny,
		Rules:         mappedRules, PublishedByMembershipId: policy.PublishedByMembershipID(),
		PublishedAt: policy.PublishedAt(),
	}, nil
}

func setWebhookURLPolicyETag(w http.ResponseWriter, version int64) bool {
	if version < 1 || version > webhookurlpolicy.MaximumPolicyVersion {
		return false
	}
	w.Header().Set("ETag", "\"v"+strconv.FormatInt(version, 10)+"\"")
	return true
}

func validWebhookURLPolicyUUID(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func writeWebhookURLPolicyJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", webhookURLPolicyCacheControl)
	writeJSON(w, status, value)
}

func (h *Handler) writeWebhookURLPolicyError(w http.ResponseWriter, r *http.Request, err error) {
	writeWebhookURLPolicyDomainError(w, r, err)
}

func writeWebhookURLPolicyDomainError(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Cache-Control", webhookURLPolicyCacheControl)
	if errors.Is(err, context.Canceled) {
		if errors.Is(r.Context().Err(), context.Canceled) {
			return
		}
		err = webhookurlpolicy.ErrUnavailable
	}
	if errors.Is(err, context.DeadlineExceeded) {
		err = webhookurlpolicy.ErrUnavailable
	}
	switch {
	case errors.Is(err, webhookurlpolicy.ErrInvalidInput):
		writeProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", "The webhook URL policy request is malformed or fails bounded validation.")
	case errors.Is(err, webhookurlpolicy.ErrForbidden), errors.Is(err, authentication.ErrForbidden):
		writeProblem(w, r, http.StatusForbidden, "forbidden", "Forbidden", "The action is not permitted.")
	case errors.Is(err, webhookurlpolicy.ErrNotFound):
		writeProblem(w, r, http.StatusNotFound, "not_found", "Resource not found", "The webhook URL policy does not exist.")
	case errors.Is(err, webhookurlpolicy.ErrConflict), errors.Is(err, webhookurlpolicy.ErrNoChange):
		writeProblem(w, r, http.StatusConflict, "conflict", "Conflict", "The webhook URL policy command conflicts with current protected state or reuses an idempotency key.")
	case errors.Is(err, webhookurlpolicy.ErrUnavailable):
		w.Header().Set("Retry-After", "5")
		writeProblem(w, r, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable", "A required protected dependency is unavailable.")
	default:
		writeProblem(w, r, http.StatusInternalServerError, "internal_error", "Internal server error", "The request could not be completed.")
	}
}
