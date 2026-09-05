package ticketing

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

const ticketBulkCommandDomain = "periapsis.ticket-bulk-command.v1"

const (
	ticketBulkQueryIntentDomain = "periapsis.ticket-bulk-query-intent.v1\x00"
	ticketBulkIdempotencyDomain = "periapsis.ticket-bulk-idempotency.v1\x00"
)

type TicketBulkCommandAction uint8

const (
	TicketBulkCommandRequest TicketBulkCommandAction = iota + 1
	TicketBulkCommandCancel
)

func (action TicketBulkCommandAction) String() string {
	switch action {
	case TicketBulkCommandRequest:
		return "request"
	case TicketBulkCommandCancel:
		return "cancel"
	default:
		return "unknown"
	}
}

type TicketBulkCommandBinding struct {
	Action      TicketBulkCommandAction
	KeyHash     [sha256.Size]byte
	Fingerprint [sha256.Size]byte
}

func (binding TicketBulkCommandBinding) String() string {
	return fmt.Sprintf(
		"TicketBulkCommandBinding{action:%s,key:[REDACTED],fingerprint:[REDACTED]}",
		binding.Action,
	)
}
func (binding TicketBulkCommandBinding) GoString() string { return binding.String() }

type ticketBulkMutationEnvelope struct {
	Action     string `json:"action"`
	Transition string `json:"transition,omitempty"`
	To         string `json:"to,omitempty"`
	Team       string `json:"team,omitempty"`
	Assignee   string `json:"assignee,omitempty"`
}

type ticketBulkSavedViewEnvelope struct {
	ID         string `json:"id"`
	Owner      string `json:"owner"`
	Revision   uint64 `json:"revision"`
	SpecDigest []byte `json:"spec_digest"`
}

type ticketBulkRequestCommandEnvelope struct {
	Domain          string                       `json:"domain"`
	Tenant          string                       `json:"tenant"`
	Actor           string                       `json:"actor"`
	Membership      string                       `json:"membership"`
	Kind            string                       `json:"kind"`
	Mutation        ticketBulkMutationEnvelope   `json:"mutation"`
	SelectionSource string                       `json:"selection_source"`
	TargetCount     uint32                       `json:"target_count,omitempty"`
	TargetSetDigest []byte                       `json:"target_set_digest,omitempty"`
	QuerySource     string                       `json:"query_source,omitempty"`
	QueryIntent     []byte                       `json:"query_intent,omitempty"`
	SavedView       *ticketBulkSavedViewEnvelope `json:"saved_view,omitempty"`
	RetentionMicros int64                        `json:"retention_micros"`
}

type ticketBulkCancelCommandEnvelope struct {
	Domain           string `json:"domain"`
	Tenant           string `json:"tenant"`
	Actor            string `json:"actor"`
	Membership       string `json:"membership"`
	Kind             string `json:"kind"`
	Job              string `json:"job"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

func bindTicketBulkRequestCommand(
	idempotencyKey string,
	access TicketBulkAccess,
	explicit *kernel.TicketBulkSelection,
	queryInput *TicketBulkQuerySourceInput,
	mutation kernel.TicketBulkMutation,
	retention time.Duration,
) (TicketBulkCommandBinding, error) {
	if !validIdempotencyKey(idempotencyKey) || !validTicketBulkAccessShape(access) ||
		!access.allowed || access.capability != TicketBulkCapabilityRequest ||
		access.mutation != mutation.Action() ||
		retention < kernel.TicketBulkMinimumRetention || retention > kernel.TicketBulkMaximumRetention ||
		retention%time.Microsecond != 0 || (explicit == nil) == (queryInput == nil) {
		return TicketBulkCommandBinding{}, ErrInvalidInput
	}
	mutationEnvelope, err := canonicalTicketBulkMutationEnvelope(mutation)
	if err != nil {
		return TicketBulkCommandBinding{}, err
	}
	envelope := ticketBulkRequestCommandEnvelope{
		Domain: ticketBulkCommandDomain, Tenant: access.tenant.String(), Actor: access.actor.String(),
		Membership: access.membership.String(), Kind: access.kind.String(), Mutation: mutationEnvelope,
		RetentionMicros: retention.Microseconds(),
	}
	if explicit != nil {
		if explicit.Source() != kernel.TicketBulkSelectionExplicit || explicit.TargetCount() == 0 {
			return TicketBulkCommandBinding{}, ErrInvalidInput
		}
		for _, target := range explicit.ExplicitTargets() {
			if target.Version() > maxResourceVersion {
				return TicketBulkCommandBinding{}, ErrInvalidInput
			}
		}
		digest := explicit.TargetSetDigest()
		envelope.SelectionSource = kernel.TicketBulkSelectionExplicit.String()
		envelope.TargetCount = explicit.TargetCount()
		envelope.TargetSetDigest = digest[:]
	} else {
		normalized, err := normalizeTicketBulkQuerySourceInput(*queryInput)
		if err != nil {
			return TicketBulkCommandBinding{}, ErrInvalidInput
		}
		envelope.SelectionSource = kernel.TicketBulkSelectionQuery.String()
		queryIntent, err := json.Marshal(normalized)
		if err != nil {
			return TicketBulkCommandBinding{}, ErrUnavailable
		}
		queryIntent = append([]byte(ticketBulkQueryIntentDomain), queryIntent...)
		digest := sha256.Sum256(queryIntent)
		envelope.QueryIntent = digest[:]
		if normalized.Inline != nil {
			envelope.QuerySource = TicketBulkQueryInline.String()
		} else {
			envelope.QuerySource = TicketBulkQuerySavedView.String()
			pin := normalized.SavedView
			envelope.SavedView = &ticketBulkSavedViewEnvelope{
				ID: pin.ID.String(), Owner: access.membership.String(), Revision: pin.ExpectedRevision,
				SpecDigest: pin.ExpectedSpecDigest[:],
			}
		}
	}
	return newTicketBulkCommandBinding(idempotencyKey, TicketBulkCommandRequest, envelope)
}

func bindTicketBulkCancelCommand(
	idempotencyKey string,
	access TicketBulkAccess,
	jobID uuid.UUID,
	expectedRevision uint64,
) (TicketBulkCommandBinding, error) {
	if !validIdempotencyKey(idempotencyKey) || !validTicketBulkAccessShape(access) ||
		!access.allowed || access.capability != TicketBulkCapabilityCancel || !validWorkflowUUID(jobID) ||
		expectedRevision == 0 || expectedRevision >= maxResourceVersion {
		return TicketBulkCommandBinding{}, ErrInvalidInput
	}
	return newTicketBulkCommandBinding(idempotencyKey, TicketBulkCommandCancel, ticketBulkCancelCommandEnvelope{
		Domain: ticketBulkCommandDomain, Tenant: access.tenant.String(), Actor: access.actor.String(),
		Membership: access.membership.String(), Kind: access.kind.String(), Job: jobID.String(),
		ExpectedRevision: expectedRevision,
	})
}

func newTicketBulkCommandBinding(
	idempotencyKey string,
	action TicketBulkCommandAction,
	envelope any,
) (TicketBulkCommandBinding, error) {
	if action != TicketBulkCommandRequest && action != TicketBulkCommandCancel {
		return TicketBulkCommandBinding{}, ErrInvalidInput
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return TicketBulkCommandBinding{}, ErrUnavailable
	}
	domain := ticketBulkCommandDomain + "\x00" + action.String() + "\x00"
	return TicketBulkCommandBinding{
		Action:      action,
		KeyHash:     sha256.Sum256([]byte(ticketBulkIdempotencyDomain + action.String() + "\x00" + idempotencyKey)),
		Fingerprint: sha256.Sum256(append([]byte(domain), encoded...)),
	}, nil
}

func canonicalTicketBulkMutationEnvelope(
	mutation kernel.TicketBulkMutation,
) (ticketBulkMutationEnvelope, error) {
	envelope := ticketBulkMutationEnvelope{Action: mutation.Action().String()}
	switch mutation.Action() {
	case kernel.ActionTransition:
		transition, to, ok := mutation.Transition()
		if !ok {
			return ticketBulkMutationEnvelope{}, ErrInvalidInput
		}
		envelope.Transition, envelope.To = transition.String(), to.String()
	case kernel.ActionAssign, kernel.ActionTransfer:
		team, assignee, ok := mutation.Assignment()
		if !ok {
			return ticketBulkMutationEnvelope{}, ErrInvalidInput
		}
		envelope.Team = team.String()
		if assignee != nil {
			envelope.Assignee = assignee.String()
		}
	case kernel.ActionClaim:
		team, ok := mutation.ClaimTeam()
		if !ok {
			return ticketBulkMutationEnvelope{}, ErrInvalidInput
		}
		envelope.Team = team.String()
	case kernel.ActionRelease:
	default:
		return ticketBulkMutationEnvelope{}, ErrInvalidInput
	}
	return envelope, nil
}

func validTicketBulkAccessShape(access TicketBulkAccess) bool {
	rebuilt, err := NewTicketBulkAccess(
		access.tenant, access.actor, access.membership, access.kind, access.capability,
		access.principal, access.mutation, access.allowed,
	)
	return err == nil && rebuilt == access
}
