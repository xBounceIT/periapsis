package federatedauth

import (
	"context"
	"fmt"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

// OIDCClientSecretSnapshot is the exact immutable secret revision selected by
// the post-claim persistence boundary. LoadOIDCClientSecretEnvelope transfers
// ownership of Envelope.Ciphertext to the caller.
type OIDCClientSecretSnapshot struct {
	Lookup   ClientSecretContext
	SecretID identity.EntityID
	Envelope identity.OIDCClientSecretEnvelope
}

func (snapshot OIDCClientSecretSnapshot) String() string {
	return fmt.Sprintf(
		"federatedauth.OIDCClientSecretSnapshot{revision:%t,secret:%t,envelope:%q,material:[REDACTED]}",
		snapshot.Lookup.Revision != 0, snapshot.SecretID != (identity.EntityID{}), snapshot.Envelope.String(),
	)
}
func (snapshot OIDCClientSecretSnapshot) GoString() string { return snapshot.String() }

// OIDCClientSecretEnvelopeSource is implemented by a narrow tenant-derived
// PostgreSQL ABI. It must return only the requested immutable revision and no
// provider configuration or plaintext material.
type OIDCClientSecretEnvelopeSource interface {
	LoadOIDCClientSecretEnvelope(context.Context, ClientSecretContext) (OIDCClientSecretSnapshot, error)
}

// OIDCMaintenanceClientSecretEnvelopeSource is the worker-only historical
// projection used after a refresh/logout job has already pinned provider,
// admission, binding, and secret revision. Unlike interactive login it must
// not require the provider or membership to remain enabled.
type OIDCMaintenanceClientSecretEnvelopeSource interface {
	LoadOIDCMaintenanceClientSecretEnvelope(context.Context, ClientSecretContext) (OIDCClientSecretSnapshot, error)
}

// KeyringOIDCClientSecretSource adapts the encrypted persistence projection to
// ClientSecretSource without exposing a generic decryption operation.
type KeyringOIDCClientSecretSource struct {
	source  OIDCClientSecretEnvelopeSource
	keyring identity.Keyring
}

func NewKeyringOIDCClientSecretSource(
	source OIDCClientSecretEnvelopeSource,
	keyring identity.Keyring,
) (*KeyringOIDCClientSecretSource, error) {
	if source == nil || keyring.ActiveVersion() < 1 {
		return nil, ErrInvalidOptions
	}
	return &KeyringOIDCClientSecretSource{source: source, keyring: keyring}, nil
}

func (source *KeyringOIDCClientSecretSource) String() string {
	return fmt.Sprintf(
		"federatedauth.KeyringOIDCClientSecretSource{configured:%t}",
		source != nil && source.source != nil && source.keyring.ActiveVersion() > 0,
	)
}
func (source *KeyringOIDCClientSecretSource) GoString() string { return source.String() }

var _ ClientSecretSource = (*KeyringOIDCClientSecretSource)(nil)

func (source *KeyringOIDCClientSecretSource) OpenOIDCClientSecret(
	ctx context.Context,
	lookup ClientSecretContext,
) ([]byte, error) {
	if source == nil || source.source == nil || ctx == nil || ctx.Err() != nil ||
		!validOIDCClientSecretLookup(lookup) {
		return nil, ErrAuthentication
	}
	snapshot, err := source.source.LoadOIDCClientSecretEnvelope(ctx, lookup)
	defer clear(snapshot.Envelope.Nonce[:])
	defer clear(snapshot.Envelope.Ciphertext)
	if err != nil || ctx.Err() != nil || snapshot.Lookup != lookup || snapshot.SecretID == (identity.EntityID{}) {
		return nil, ErrAuthentication
	}
	plaintext, err := source.keyring.DecryptOIDCClientSecret(identity.OIDCClientSecretContext{
		Provider: lookup.Provider, BindingID: lookup.BindingID, SecretID: snapshot.SecretID,
	}, snapshot.Envelope)
	if err != nil || ctx.Err() != nil || len(plaintext) == 0 {
		clear(plaintext)
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

// KeyringOIDCMaintenanceClientSecretSource opens a purpose-bound historical
// secret selected by the worker-only maintenance ABI. It supports tenant,
// tenant-admitted platform, and direct-platform ownership shapes.
type KeyringOIDCMaintenanceClientSecretSource struct {
	source  OIDCMaintenanceClientSecretEnvelopeSource
	keyring identity.Keyring
}

func NewKeyringOIDCMaintenanceClientSecretSource(
	source OIDCMaintenanceClientSecretEnvelopeSource,
	keyring identity.Keyring,
) (*KeyringOIDCMaintenanceClientSecretSource, error) {
	if source == nil || keyring.ActiveVersion() < 1 {
		return nil, ErrInvalidOptions
	}
	return &KeyringOIDCMaintenanceClientSecretSource{source: source, keyring: keyring}, nil
}

func (source *KeyringOIDCMaintenanceClientSecretSource) String() string {
	return fmt.Sprintf(
		"federatedauth.KeyringOIDCMaintenanceClientSecretSource{configured:%t}",
		source != nil && source.source != nil && source.keyring.ActiveVersion() > 0,
	)
}

func (source *KeyringOIDCMaintenanceClientSecretSource) GoString() string {
	return source.String()
}

var _ ClientSecretSource = (*KeyringOIDCMaintenanceClientSecretSource)(nil)

func (source *KeyringOIDCMaintenanceClientSecretSource) OpenOIDCClientSecret(
	ctx context.Context,
	lookup ClientSecretContext,
) ([]byte, error) {
	if source == nil || source.source == nil || ctx == nil || ctx.Err() != nil ||
		!validOIDCMaintenanceClientSecretLookup(lookup) {
		return nil, ErrAuthentication
	}
	snapshot, err := source.source.LoadOIDCMaintenanceClientSecretEnvelope(ctx, lookup)
	defer clear(snapshot.Envelope.Nonce[:])
	defer clear(snapshot.Envelope.Ciphertext)
	if err != nil || ctx.Err() != nil || snapshot.Lookup != lookup || snapshot.SecretID == (identity.EntityID{}) {
		return nil, ErrAuthentication
	}
	plaintext, err := source.keyring.DecryptOIDCClientSecret(identity.OIDCClientSecretContext{
		Provider: lookup.Provider, BindingID: lookup.BindingID, SecretID: snapshot.SecretID,
	}, snapshot.Envelope)
	if err != nil || ctx.Err() != nil || len(plaintext) == 0 {
		clear(plaintext)
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

func validOIDCClientSecretLookup(lookup ClientSecretContext) bool {
	if !validDatabaseRevision(lookup.Revision) || lookup.Provider.ProviderID == (identity.EntityID{}) {
		return false
	}
	if lookup.Maintenance != (OIDCMaintenanceSecretProof{}) {
		return false
	}
	switch lookup.Provider.Scope {
	case identity.TenantProviderScope:
		return lookup.Provider.TenantID != (identity.EntityID{}) && lookup.BindingID != (identity.EntityID{}) &&
			lookup.Admission == (identity.TenantAdmissionContext{})
	case identity.PlatformProviderScope:
		return lookup.Provider.TenantID == (identity.EntityID{}) && lookup.BindingID == (identity.EntityID{}) &&
			lookup.Admission.TenantID != (identity.EntityID{}) && lookup.Admission.BindingID != (identity.EntityID{})
	default:
		return false
	}
}

func validOIDCMaintenanceClientSecretLookup(lookup ClientSecretContext) bool {
	if !validDatabaseRevision(lookup.Revision) || lookup.Provider.ProviderID == (identity.EntityID{}) {
		return false
	}
	proof := lookup.Maintenance
	if !validApplyUUIDv7(proof.MaterialID) || !validApplyUUIDv7(proof.SessionFamilyID) ||
		proof.ClaimVersion == 0 || proof.ClaimVersion >= maximumPersistentOIDCCounter ||
		proof.RefreshGeneration == 0 || proof.RefreshGeneration >= maximumPersistentOIDCCounter {
		return false
	}
	switch proof.Kind {
	case OIDCMaintenanceSecretRefresh:
		if proof.JobID != (identity.EntityID{}) || proof.Attempt != 0 {
			return false
		}
	case OIDCMaintenanceSecretLogoutRetry:
		if !validApplyUUIDv7(proof.JobID) || proof.Attempt < 1 || proof.Attempt > 16 {
			return false
		}
	default:
		return false
	}
	switch lookup.Provider.Scope {
	case identity.TenantProviderScope:
		return lookup.Provider.TenantID != (identity.EntityID{}) && lookup.BindingID != (identity.EntityID{}) &&
			lookup.Admission == (identity.TenantAdmissionContext{})
	case identity.PlatformProviderScope:
		return lookup.Provider.TenantID == (identity.EntityID{}) && lookup.BindingID == (identity.EntityID{}) &&
			(lookup.Admission == (identity.TenantAdmissionContext{}) ||
				lookup.Admission.TenantID != (identity.EntityID{}) && lookup.Admission.BindingID != (identity.EntityID{}))
	default:
		return false
	}
}
