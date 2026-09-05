// Package platformidentityaccount implements the protected administration
// boundary for provider-global federated identity links. Provider subjects are
// write-only inputs and never appear in account read models.
package platformidentityaccount

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

type AccountState string

const (
	AccountStateActive  AccountState = "active"
	AccountStateRetired AccountState = "retired"
)

type LastObservationState string

const (
	LastObservationStateKnown         LastObservationState = "known"
	LastObservationStateLegacyUnknown LastObservationState = "legacy_unknown"
)

// UserSummary is the bounded global-user projection needed to administer an
// explicit provider account link. It carries no roles, tenant memberships, or
// authentication identifiers.
type UserSummary struct {
	ID          uuid.UUID
	DisplayName string
	Email       *string
	Active      bool
	Version     int64
}

func (summary UserSummary) String() string {
	return fmt.Sprintf(
		"platformidentityaccount.UserSummary{active:%t,metadata:[REDACTED]}",
		summary.Active,
	)
}

func (summary UserSummary) GoString() string { return summary.String() }

// Account is a safe provider-global identity projection. Issuer, subject,
// ciphertext, nonces, aliases, and key material are deliberately absent.
type Account struct {
	ID                            uuid.UUID
	ProviderID                    uuid.UUID
	User                          UserSummary
	State                         AccountState
	AdmittedConfigurationRevision int64
	AdmittedSecurityRevision      int64
	LastObservationState          LastObservationState
	LastObservedAt                *time.Time
	RetiredAt                     *time.Time
	Version                       int64
	CreatedAt                     time.Time
	UpdatedAt                     time.Time
}

func (account Account) String() string {
	return fmt.Sprintf(
		"platformidentityaccount.Account{state:%s,version:%d,metadata:[REDACTED]}",
		account.State, account.Version,
	)
}

func (account Account) GoString() string { return account.String() }

type AccountPage struct {
	Items      []Account
	NextCursor *uuid.UUID
}

type ListInput struct {
	After          *uuid.UUID
	Limit          int
	IncludeRetired bool
}

// PrelinkInput deliberately marks exact issuer and subject material as
// non-serializable. The service canonicalizes and protects the tuple before it
// crosses the repository port.
type PrelinkInput struct {
	UserID         uuid.UUID
	Issuer         string `json:"-"`
	Subject        string `json:"-"`
	Reason         string
	IdempotencyKey string `json:"-"`
	Event          authentication.EventContext
}

func (input PrelinkInput) String() string {
	return "platformidentityaccount.PrelinkInput{material:[REDACTED]}"
}

func (input PrelinkInput) GoString() string { return input.String() }

type RetireInput struct {
	Reason            string
	ExpectedEntityTag *string
	Event             authentication.EventContext
}
