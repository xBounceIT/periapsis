package notification

import (
	"context"
	"errors"
)

var ErrNotificationKeyringUnavailable = errors.New("notification keyring unavailable")

// KeyVersionVerifier is the bounded persistence boundary for notification
// key reachability. Only version numbers cross it; secret identifiers and
// envelopes remain inside PostgreSQL.
type KeyVersionVerifier interface {
	VerifyNotificationKeyring(context.Context, []int16) (bool, error)
}

type KeyringReadinessVerifier struct {
	verifier KeyVersionVerifier
	keyring  Keyring
}

func NewKeyringReadinessVerifier(verifier KeyVersionVerifier, keyring Keyring) (*KeyringReadinessVerifier, error) {
	if verifier == nil || keyring.ActiveVersion() < 1 || len(keyring.Versions()) == 0 {
		return nil, ErrNotificationKeyringUnavailable
	}
	return &KeyringReadinessVerifier{verifier: verifier, keyring: keyring}, nil
}

func (v *KeyringReadinessVerifier) Verify(ctx context.Context) error {
	if v == nil || v.verifier == nil {
		return ErrNotificationKeyringUnavailable
	}
	versions := v.keyring.Versions()
	verified, err := v.verifier.VerifyNotificationKeyring(ctx, versions)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return ErrNotificationKeyringUnavailable
	}
	if !verified {
		return ErrNotificationKeyringUnavailable
	}
	return nil
}
