package ticketnumbering

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

const replacePolicyOperation = "ticket_numbering.policy.replace"

func bindReplaceCommand(
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	input ReplaceInput,
) (CommandBinding, error) {
	if !validUUIDv7(tenantID) || !validAggregateKind(kind) ||
		!validIdempotencyKey(input.IdempotencyKey) || input.ExpectedVersion < 1 ||
		input.ExpectedVersion >= MaximumRevision || !validReason(input.Reason) {
		return CommandBinding{}, ErrInvalidInput
	}
	normalized, _, err := normalizeDraft(input.Policy)
	if err != nil {
		return CommandBinding{}, err
	}
	input.Policy = normalized
	encoded, err := json.Marshal(struct {
		TenantID        uuid.UUID `json:"tenant_id"`
		Kind            string    `json:"kind"`
		ExpectedVersion uint64    `json:"expected_version"`
		Prefix          string    `json:"prefix"`
		Separator       string    `json:"separator"`
		Period          string    `json:"period"`
		Width           uint8     `json:"width"`
		Start           uint64    `json:"start"`
		Reason          string    `json:"reason"`
	}{
		TenantID: tenantID, Kind: kind.String(), ExpectedVersion: input.ExpectedVersion,
		Prefix: input.Policy.Prefix, Separator: input.Policy.Separator,
		Period: input.Policy.Period.String(), Width: input.Policy.Width,
		Start: input.Policy.Start, Reason: input.Reason,
	})
	if err != nil {
		return CommandBinding{}, ErrUnavailable
	}
	return CommandBinding{
		Operation: replacePolicyOperation,
		KeyDigest: sha256.Sum256(append(
			[]byte("periapsis/ticket-numbering/policy-replace/idempotency/v1\x00"),
			[]byte(input.IdempotencyKey)...,
		)),
		RequestDigest: sha256.Sum256(append(
			[]byte("periapsis/ticket-numbering/policy-replace/request/v1\x00"), encoded...,
		)),
	}, nil
}
