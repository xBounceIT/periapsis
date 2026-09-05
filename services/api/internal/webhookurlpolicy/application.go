package webhookurlpolicy

import (
	"crypto/sha256"
	"fmt"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

type PolicyDraft struct {
	Rules []RuleInput
}

func (PolicyDraft) String() string         { return "webhookurlpolicy.PolicyDraft{redacted}" }
func (value PolicyDraft) GoString() string { return value.String() }

type PublishInput struct {
	ExpectedVersion int64
	Policy          PolicyDraft
	IdempotencyKey  string
	Reason          string
	Event           authentication.EventContext
}

func (PublishInput) String() string         { return "webhookurlpolicy.PublishInput{redacted}" }
func (value PublishInput) GoString() string { return value.String() }

type CommandBinding struct {
	Operation     string
	KeyDigest     [sha256.Size]byte
	RequestDigest [sha256.Size]byte
}

func (CommandBinding) String() string         { return "webhookurlpolicy.CommandBinding{redacted}" }
func (value CommandBinding) GoString() string { return value.String() }

type PublishResult struct {
	Policy   Policy
	Command  CommandBinding
	Replayed bool
}

func (result PublishResult) String() string {
	return fmt.Sprintf("webhookurlpolicy.PublishResult{replayed:%t,policy:%s}", result.Replayed, result.Policy)
}
func (result PublishResult) GoString() string { return result.String() }
