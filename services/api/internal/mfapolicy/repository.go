package mfapolicy

import (
	"context"

	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

// Repository is implemented only by the security-definer PostgreSQL ABI. It
// must revalidate the exact live session, authority, recent local assurance,
// recovery safety, CAS and command replay inside every relevant transaction.
// Mutations must call ValidateResult before committing audit and invalidation.
type Repository interface {
	ListPlatform(context.Context, ListParams) ([]mfa.PolicyDocument, error)
	GetPlatform(context.Context, GetParams) (mfa.PolicyDocument, error)
	SimulatePlatform(context.Context, SimulationParams) (mfa.PolicySimulation, error)
	PublishPlatform(context.Context, PublishParams) (MutationResult, error)
	RetirePlatform(context.Context, RetireParams) (MutationResult, error)

	ListTenant(context.Context, ListParams) ([]mfa.PolicyDocument, error)
	GetTenant(context.Context, GetParams) (mfa.PolicyDocument, error)
	SimulateTenant(context.Context, SimulationParams) (mfa.PolicySimulation, error)
	PublishTenant(context.Context, PublishParams) (MutationResult, error)
	RetireTenant(context.Context, RetireParams) (MutationResult, error)
}
