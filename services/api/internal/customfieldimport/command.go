package customfieldimport

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/customfields"
)

const (
	commandDomain     = "periapsis.custom-field-import-command.v1"
	idempotencyDomain = "periapsis.custom-field-import-idempotency.v1\x00"
)

type CommandAction uint8

const (
	CommandRequest CommandAction = iota + 1
	CommandCancel
)

func (action CommandAction) String() string {
	switch action {
	case CommandRequest:
		return "request"
	case CommandCancel:
		return "cancel"
	default:
		return "unknown"
	}
}

type CommandBinding struct {
	Action      CommandAction
	KeyHash     [sha256.Size]byte
	Fingerprint [sha256.Size]byte
}

func (binding CommandBinding) String() string {
	return fmt.Sprintf(
		"CommandBinding{action:%s,key:[REDACTED],fingerprint:[REDACTED]}", binding.Action,
	)
}
func (binding CommandBinding) GoString() string { return binding.String() }

func bindRequest(
	idempotencyKey string,
	actor Actor,
	tenant uuid.UUID,
	objectType kernel.ObjectType,
	mode kernel.ImportMode,
	requestDigest [sha256.Size]byte,
	retention time.Duration,
) (CommandBinding, error) {
	if !idempotencyKeyPattern.MatchString(idempotencyKey) || !validActor(actor, tenant) ||
		objectType != kernel.ObjectAlert && objectType != kernel.ObjectCase ||
		mode != kernel.ImportDryRun && mode != kernel.ImportCommit ||
		requestDigest == ([sha256.Size]byte{}) || retention < kernel.ImportMinimumRetention ||
		retention > kernel.ImportMaximumRetention || retention%time.Microsecond != 0 {
		return CommandBinding{}, ErrInvalidInput
	}
	envelope := struct {
		Domain          string
		Tenant          string
		Actor           string
		Membership      string
		ObjectType      kernel.ObjectType
		Mode            string
		RequestDigest   []byte
		RetentionMicros int64
	}{
		Domain: commandDomain, Tenant: tenant.String(), Actor: actor.UserID.String(),
		Membership: actor.MembershipID.String(), ObjectType: objectType, Mode: mode.String(),
		RequestDigest: requestDigest[:], RetentionMicros: retention.Microseconds(),
	}
	scope := tenant.String() + "\x00" + actor.UserID.String() + "\x00" + actor.MembershipID.String()
	return newCommandBinding(idempotencyKey, CommandRequest, scope, envelope)
}

func bindCancellation(
	idempotencyKey string,
	actor Actor,
	tenant uuid.UUID,
	objectType kernel.ObjectType,
	jobID uuid.UUID,
	expectedRevision uint64,
) (CommandBinding, error) {
	if !idempotencyKeyPattern.MatchString(idempotencyKey) || !validActor(actor, tenant) ||
		objectType != kernel.ObjectAlert && objectType != kernel.ObjectCase || jobID == uuid.Nil ||
		expectedRevision == 0 || expectedRevision >= maximumImportRevision {
		return CommandBinding{}, ErrInvalidInput
	}
	envelope := struct {
		Domain           string
		Tenant           string
		Actor            string
		Membership       string
		ObjectType       kernel.ObjectType
		Job              string
		ExpectedRevision uint64
	}{
		Domain: commandDomain, Tenant: tenant.String(), Actor: actor.UserID.String(),
		Membership: actor.MembershipID.String(), ObjectType: objectType,
		Job: jobID.String(), ExpectedRevision: expectedRevision,
	}
	scope := tenant.String() + "\x00" + actor.UserID.String() + "\x00" + actor.MembershipID.String()
	return newCommandBinding(idempotencyKey, CommandCancel, scope, envelope)
}

func newCommandBinding(key string, action CommandAction, scope string, envelope any) (CommandBinding, error) {
	if action != CommandRequest && action != CommandCancel {
		return CommandBinding{}, ErrInvalidInput
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return CommandBinding{}, ErrUnavailable
	}
	prefix := []byte(commandDomain + "\x00" + action.String() + "\x00")
	return CommandBinding{
		Action:      action,
		KeyHash:     sha256.Sum256([]byte(idempotencyDomain + action.String() + "\x00" + scope + "\x00" + key)),
		Fingerprint: sha256.Sum256(append(prefix, encoded...)),
	}, nil
}

func validCommandBinding(binding CommandBinding, action CommandAction) bool {
	return binding.Action == action && binding.KeyHash != ([sha256.Size]byte{}) &&
		binding.Fingerprint != ([sha256.Size]byte{})
}
