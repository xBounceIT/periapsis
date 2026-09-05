package webhookurlpolicy

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/google/uuid"
)

const publishPolicyOperation = "webhook_url_policy.publish"

func bindPublishCommand(
	tenantID, actorID, publisherMembershipID uuid.UUID,
	input PublishInput,
) (CommandBinding, error) {
	if !validUUIDv7(tenantID) || !validUUIDv7(actorID) || !validUUIDv7(publisherMembershipID) ||
		input.ExpectedVersion < 0 || input.ExpectedVersion >= MaximumPolicyVersion ||
		!validIdempotencyKey(input.IdempotencyKey) || !validBoundedReason(input.Reason) {
		return CommandBinding{}, ErrInvalidInput
	}
	normalized, _, err := normalizeDraft(input.Policy)
	if err != nil {
		return CommandBinding{}, err
	}
	rules := make([]struct {
		Effect   RuleEffect `json:"effect"`
		Match    RuleMatch  `json:"match"`
		Hostname string     `json:"hostname"`
		Port     int        `json:"port"`
	}, len(normalized.Rules))
	for index, rule := range normalized.Rules {
		rules[index] = struct {
			Effect   RuleEffect `json:"effect"`
			Match    RuleMatch  `json:"match"`
			Hostname string     `json:"hostname"`
			Port     int        `json:"port"`
		}{rule.Effect, rule.Match, rule.Hostname, rule.Port}
	}
	encoded, err := json.Marshal(struct {
		TenantID        uuid.UUID `json:"tenant_id"`
		ExpectedVersion int64     `json:"expected_version"`
		Rules           any       `json:"rules"`
		Reason          string    `json:"reason"`
	}{tenantID, input.ExpectedVersion, rules, input.Reason})
	if err != nil {
		return CommandBinding{}, ErrUnavailable
	}
	return CommandBinding{
		Operation: publishPolicyOperation,
		KeyDigest: framedDigest(
			"periapsis/webhook-url-policy/publish/idempotency/v1",
			tenantID.String(), actorID.String(), publisherMembershipID.String(), input.IdempotencyKey,
		),
		RequestDigest: sha256.Sum256(append(
			[]byte("periapsis/webhook-url-policy/publish/request/v1\x00"), encoded...,
		)),
	}, nil
}
