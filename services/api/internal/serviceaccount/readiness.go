package serviceaccount

import (
	"context"
	"errors"
)

const liveKeyVersionInventoryLimit int32 = 17

var ErrCredentialKeyringUnavailable = errors.New("API credential keyring unavailable")

// LiveKeyVersionInventory exposes only the bounded, distinct key versions used
// by credentials that can still authenticate. Implementations must return the
// values in strictly ascending order and must never expose credential material.
type LiveKeyVersionInventory interface {
	ListLiveAPIKeyVersions(context.Context, int32) ([]int16, error)
}

// KeyringReadinessVerifier prevents a replica from receiving traffic unless it
// can verify every currently live API credential. CredentialKeyring is
// immutable after construction, so a successful check is valid for the exact
// keyring installed in this process.
type KeyringReadinessVerifier struct {
	inventory LiveKeyVersionInventory
	keyring   CredentialKeyring
}

func NewKeyringReadinessVerifier(inventory LiveKeyVersionInventory, keyring CredentialKeyring) (*KeyringReadinessVerifier, error) {
	if inventory == nil {
		return nil, errors.New("live API credential key-version inventory is required")
	}
	if keyring.activeVersion < 1 || len(keyring.keys) == 0 {
		return nil, errors.New("API credential keyring is required")
	}
	if _, exists := keyring.keys[keyring.activeVersion]; !exists {
		return nil, errors.New("active API credential key version is unavailable")
	}
	return &KeyringReadinessVerifier{inventory: inventory, keyring: keyring}, nil
}

// VerifyLiveKeyVersions checks one complete bounded database snapshot. It
// intentionally returns one public availability error for malformed or
// incomplete inventories and preserves only caller cancellation errors.
func (v *KeyringReadinessVerifier) VerifyLiveKeyVersions(ctx context.Context) error {
	if v == nil || v.inventory == nil {
		return ErrCredentialKeyringUnavailable
	}
	versions, err := v.inventory.ListLiveAPIKeyVersions(ctx, liveKeyVersionInventoryLimit)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return ErrCredentialKeyringUnavailable
	}
	if len(versions) >= int(liveKeyVersionInventoryLimit) || len(versions) > len(v.keyring.keys) {
		return ErrCredentialKeyringUnavailable
	}
	for index, version := range versions {
		if version < 1 || index > 0 && versions[index-1] >= version {
			return ErrCredentialKeyringUnavailable
		}
	}
	if len(v.keyring.MissingVersions(versions)) != 0 {
		return ErrCredentialKeyringUnavailable
	}
	return nil
}
