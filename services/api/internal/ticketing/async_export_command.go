package ticketing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

const (
	asyncExportRequestCommandDomain = "periapsis.ticketing.async-export.request.v1"
	asyncExportCancelCommandDomain  = "periapsis.ticketing.async-export.cancel.v1"
	asyncExportIdempotencyDomain    = "periapsis.ticketing.async-export.idempotency.v1\x00"
)

type AsyncExportCommandAction uint8

const (
	AsyncExportCommandRequest AsyncExportCommandAction = iota + 1
	AsyncExportCommandCancel
)

func (action AsyncExportCommandAction) String() string {
	switch action {
	case AsyncExportCommandRequest:
		return "request"
	case AsyncExportCommandCancel:
		return "cancel"
	default:
		return "unknown"
	}
}

type AsyncExportCommandBinding struct {
	Action      AsyncExportCommandAction
	KeyHash     [sha256.Size]byte
	Fingerprint [sha256.Size]byte
}

func (binding AsyncExportCommandBinding) String() string {
	return fmt.Sprintf(
		"AsyncExportCommandBinding{action:%s,key_hash:[REDACTED],fingerprint:[REDACTED]}",
		binding.Action,
	)
}
func (binding AsyncExportCommandBinding) GoString() string { return binding.String() }

type asyncExportRequestCommandEnvelope struct {
	Domain                string `json:"domain"`
	TenantID              string `json:"tenantId"`
	ActorID               string `json:"actorId"`
	OwnerMembershipID     string `json:"ownerMembershipId"`
	CustomerContactID     string `json:"customerContactId,omitempty"`
	Kind                  string `json:"kind"`
	Audience              string `json:"audience"`
	Comments              string `json:"comments"`
	Source                string `json:"source"`
	SavedViewID           string `json:"savedViewId,omitempty"`
	SavedViewRevision     uint64 `json:"savedViewRevision,omitempty"`
	QueryDigest           string `json:"queryDigest"`
	CatalogDigest         string `json:"catalogDigest"`
	ProjectionVersion     uint64 `json:"projectionVersion"`
	Format                string `json:"format"`
	MaximumRows           uint32 `json:"maximumRows"`
	MaximumBytes          uint64 `json:"maximumBytes"`
	MaximumAttempts       uint8  `json:"maximumAttempts"`
	RetentionMicroseconds int64  `json:"retentionMicroseconds"`
}

type asyncExportCancelCommandEnvelope struct {
	Domain            string `json:"domain"`
	TenantID          string `json:"tenantId"`
	ActorID           string `json:"actorId"`
	OwnerMembershipID string `json:"ownerMembershipId"`
	Kind              string `json:"kind"`
	Audience          string `json:"audience"`
	JobID             string `json:"jobId"`
	ExpectedRevision  uint64 `json:"expectedRevision"`
}

func bindAsyncExportRequestCommand(
	idempotencyKey string,
	access AsyncExportAccess,
	query AsyncExportQuerySnapshot,
	comments kernel.TicketExportCommentScope,
	maximumRows uint32,
	maximumBytes uint64,
	retention time.Duration,
) (AsyncExportCommandBinding, error) {
	if !validIdempotencyKey(idempotencyKey) || !validAsyncExportAccessShape(access) ||
		comments < kernel.TicketExportCommentsNone || comments > kernel.TicketExportCommentsPublicAndPrivate ||
		maximumRows == 0 || maximumBytes == 0 || retention < kernel.TicketExportMinimumRetention ||
		retention > kernel.TicketExportMaximumRetention || retention%time.Microsecond != 0 {
		return AsyncExportCommandBinding{}, ErrInvalidInput
	}
	normalized, valid := normalizeAsyncExportQuerySnapshot(query)
	if !valid || normalized.tenant != access.tenant || normalized.kind != access.kind {
		return AsyncExportCommandBinding{}, ErrInvalidInput
	}
	envelope := asyncExportRequestCommandEnvelope{
		Domain: asyncExportRequestCommandDomain, TenantID: access.tenant.String(),
		ActorID: access.actor.String(), OwnerMembershipID: access.membership.String(),
		Kind: access.kind.String(), Audience: access.audience.String(), Comments: comments.String(),
		Source: normalized.source.String(), QueryDigest: hex.EncodeToString(normalized.queryDigest[:]),
		CatalogDigest:     hex.EncodeToString(normalized.catalogDigest[:]),
		ProjectionVersion: kernel.TicketExportProjectionVersion, Format: kernel.TicketExportCSV.String(),
		MaximumRows: maximumRows, MaximumBytes: maximumBytes,
		MaximumAttempts:       kernel.TicketExportMaximumAttempts,
		RetentionMicroseconds: retention.Microseconds(),
	}
	if access.customerContact != nil {
		envelope.CustomerContactID = access.customerContact.String()
	}
	if normalized.savedView != nil {
		envelope.SavedViewID = normalized.savedView.ID().String()
		envelope.SavedViewRevision = normalized.savedView.Revision()
	}
	return asyncExportCommand(idempotencyKey, AsyncExportCommandRequest, envelope)
}

func bindAsyncExportCancelCommand(
	idempotencyKey string,
	access AsyncExportAccess,
	jobID uuid.UUID,
	expectedRevision uint64,
) (AsyncExportCommandBinding, error) {
	if !validIdempotencyKey(idempotencyKey) || !validAsyncExportAccessShape(access) ||
		!validWorkflowUUID(jobID) || expectedRevision == 0 || expectedRevision >= maxResourceVersion {
		return AsyncExportCommandBinding{}, ErrInvalidInput
	}
	envelope := asyncExportCancelCommandEnvelope{
		Domain: asyncExportCancelCommandDomain, TenantID: access.tenant.String(),
		ActorID: access.actor.String(), OwnerMembershipID: access.membership.String(),
		Kind: access.kind.String(), Audience: access.audience.String(), JobID: jobID.String(),
		ExpectedRevision: expectedRevision,
	}
	return asyncExportCommand(idempotencyKey, AsyncExportCommandCancel, envelope)
}

func asyncExportCommand(
	idempotencyKey string,
	action AsyncExportCommandAction,
	envelope any,
) (AsyncExportCommandBinding, error) {
	payload, err := json.Marshal(envelope)
	if err != nil {
		return AsyncExportCommandBinding{}, ErrUnavailable
	}
	return AsyncExportCommandBinding{
		Action:      action,
		KeyHash:     sha256.Sum256([]byte(asyncExportIdempotencyDomain + idempotencyKey)),
		Fingerprint: sha256.Sum256(payload),
	}, nil
}

func validAsyncExportAccessShape(access AsyncExportAccess) bool {
	if !validWorkflowUUID(access.tenant) || !validWorkflowUUID(access.actor) ||
		!validWorkflowUUID(access.membership) || !validSavedViewKind(access.kind) ||
		!validAsyncExportAudience(access.audience) || !validAsyncExportHumanCapability(access.capability) {
		return false
	}
	if access.audience == kernel.TicketExportAudienceCustomer {
		return access.principal == kernel.PrincipalCustomer && access.customerContact != nil &&
			validWorkflowUUID(*access.customerContact) && !access.privateComments
	}
	return access.audience == kernel.TicketExportAudienceOperator &&
		access.principal == kernel.PrincipalOperator && access.customerContact == nil
}
