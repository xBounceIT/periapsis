package identityprovider

import (
	"context"
	"errors"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

var ErrIdentityKeyringUnavailable = errors.New("identity keyring unavailable")

type KeyringEvidenceVerifier interface {
	VerifyIdentityKeyring(context.Context, identity.ReadinessEvidence) (bool, error)
}

// KeyringReadinessVerifier proves that the process keyring has exactly the
// database-bound retained versions and active write version. Verifier bytes
// are non-reversible evidence but are still never logged or returned.
type KeyringReadinessVerifier struct {
	verifier KeyringEvidenceVerifier
	keyring  identity.Keyring
}

func NewKeyringReadinessVerifier(
	verifier KeyringEvidenceVerifier,
	keyring identity.Keyring,
) (*KeyringReadinessVerifier, error) {
	if verifier == nil || keyring.ActiveVersion() < 1 || len(keyring.Versions()) == 0 {
		return nil, ErrIdentityKeyringUnavailable
	}
	return &KeyringReadinessVerifier{verifier: verifier, keyring: keyring}, nil
}

func (v *KeyringReadinessVerifier) Verify(ctx context.Context) error {
	if v == nil || v.verifier == nil {
		return ErrIdentityKeyringUnavailable
	}
	evidence, err := v.keyring.ReadinessEvidence()
	if err != nil {
		return ErrIdentityKeyringUnavailable
	}
	defer clearReadinessEvidence(evidence)
	// The sealed verifier returns false when its NOWAIT session-table locks
	// collide with a normal login or idle touch. Briefly retry that result;
	// only a positive database verification may authorize readiness.
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		verified, err := v.verifier.VerifyIdentityKeyring(ctx, evidence)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return ErrIdentityKeyringUnavailable
		}
		if verified {
			return nil
		}
		if attempt == 10 {
			return ErrIdentityKeyringUnavailable
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func clearReadinessEvidence(evidence identity.ReadinessEvidence) {
	for index := range evidence.Versions {
		clear(evidence.Versions[index].Verifier[:])
	}
}
