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
	// collide with a normal login or idle touch. Allow a bounded write to finish
	// within the caller's deadline, capped at five seconds. The former 250ms
	// attempt limit could expire while ordinary session mutations were still live.
	// Only a positive database verification may authorize readiness.
	retryContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if retryContext.Err() != nil {
			return ErrIdentityKeyringUnavailable
		}
		verified, err := v.verifier.VerifyIdentityKeyring(retryContext, evidence)
		if err != nil {
			if parentErr := ctx.Err(); parentErr != nil {
				return parentErr
			}
			if retryContext.Err() != nil {
				return ErrIdentityKeyringUnavailable
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return ErrIdentityKeyringUnavailable
		}
		if verified {
			return nil
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-retryContext.Done():
			timer.Stop()
			if err := ctx.Err(); err != nil {
				return err
			}
			return ErrIdentityKeyringUnavailable
		case <-timer.C:
		}
	}
}

func clearReadinessEvidence(evidence identity.ReadinessEvidence) {
	for index := range evidence.Versions {
		clear(evidence.Versions[index].Verifier[:])
	}
}
