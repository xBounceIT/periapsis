package ticketnumbering

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

const (
	MaximumRevision  = uint64(2_147_483_647)
	MaximumReasonLen = 2_048
)

type PolicyDraft struct {
	Prefix    string
	Separator string
	Period    kernel.NumberingPeriod
	Width     uint8
	Start     uint64
}

func (PolicyDraft) String() string         { return "ticketnumbering.PolicyDraft{format:[REDACTED]}" }
func (value PolicyDraft) GoString() string { return value.String() }

type Preview struct {
	TenantID        uuid.UUID
	Kind            kernel.AggregateKind
	Prefix          string
	Separator       string
	Period          kernel.NumberingPeriod
	Width           uint8
	Start           uint64
	MaximumSequence uint64
	At              time.Time
	PeriodKey       int
	Example         string
}

func (value Preview) String() string {
	return fmt.Sprintf(
		"ticketnumbering.Preview{kind:%s,period:%s,width:%d,format:[REDACTED]}",
		value.Kind, value.Period, value.Width,
	)
}
func (value Preview) GoString() string { return value.String() }

type ReplaceInput struct {
	ExpectedVersion uint64
	Policy          PolicyDraft
	IdempotencyKey  string
	Reason          string
	Event           authentication.EventContext
}

func (ReplaceInput) String() string         { return "ticketnumbering.ReplaceInput{redacted}" }
func (value ReplaceInput) GoString() string { return value.String() }

// CommandBinding contains one-way, domain-separated digests only. Persistence
// scopes KeyDigest by tenant, actor, operation, and aggregate kind.
type CommandBinding struct {
	Operation     string
	KeyDigest     [sha256.Size]byte
	RequestDigest [sha256.Size]byte
}

func (CommandBinding) String() string         { return "ticketnumbering.CommandBinding{redacted}" }
func (value CommandBinding) GoString() string { return value.String() }

type ReplaceResult struct {
	Policy   kernel.NumberingPolicy
	Replayed bool
}

func (value ReplaceResult) String() string {
	return fmt.Sprintf("ticketnumbering.ReplaceResult{replayed:%t,policy:%s}", value.Replayed, value.Policy)
}
func (value ReplaceResult) GoString() string { return value.String() }
