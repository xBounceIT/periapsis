package postgres

import (
	"context"
	"crypto/sha256"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

const (
	loadOIDCClientSecretEnvelopeSQL            = `select app.load_oidc_client_secret_envelope_v1($1::jsonb)`
	loadOIDCMaintenanceClientSecretEnvelopeSQL = `select app.load_oidc_maintenance_client_secret_envelope_v1($1::jsonb)`
	loadSAMLSPKeyEnvelopeSQL                   = `select app.load_saml_sp_key_envelope_v1($1::jsonb)`
	loadTenantSAMLLogoutSPKeyEnvelopeSQL       = `select app.load_tenant_saml_logout_sp_key_envelope_v1($1::jsonb)`

	oidcClientSecretNonceBytes        = 12
	maximumOIDCClientSecretCiphertext = 8*1024 + 16
	maximumSAMLSPKeyEnvelopeWireBytes = 128 * 1024
	maximumSAMLSPCertificateWireBytes = 64 * 1024
	maximumSAMLSPCertificateWireCount = 8
)

type oidcClientSecretLookupWire struct {
	Provider  federatedProviderBindingWire  `json:"provider"`
	Admission *federatedTenantAdmissionWire `json:"admission,omitempty"`
	Revision  uint64                        `json:"revision"`
}

type oidcClientSecretEnvelopeWire struct {
	Lookup     oidcClientSecretLookupWire `json:"lookup"`
	SecretID   string                     `json:"secretId"`
	KeyVersion int16                      `json:"keyVersion"`
	Nonce      []byte                     `json:"nonce"`
	Ciphertext []byte                     `json:"ciphertext"`
}

type oidcMaintenanceClientSecretLookupWire struct {
	Provider          federatedProviderBindingWire  `json:"provider"`
	Admission         *federatedTenantAdmissionWire `json:"admission,omitempty"`
	BindingID         *string                       `json:"bindingId"`
	Revision          uint64                        `json:"revision"`
	Kind              string                        `json:"kind"`
	MaterialID        string                        `json:"materialId"`
	SessionFamilyID   string                        `json:"sessionFamilyId"`
	ClaimVersion      uint64                        `json:"claimVersion"`
	RefreshGeneration uint64                        `json:"refreshGeneration"`
	JobID             *string                       `json:"jobId,omitempty"`
	Attempt           *int                          `json:"attempt,omitempty"`
}

type oidcMaintenanceClientSecretEnvelopeWire struct {
	Lookup     oidcMaintenanceClientSecretLookupWire `json:"lookup"`
	SecretID   string                                `json:"secretId"`
	KeyVersion int16                                 `json:"keyVersion"`
	Nonce      []byte                                `json:"nonce"`
	Ciphertext []byte                                `json:"ciphertext"`
}

func (value oidcMaintenanceClientSecretEnvelopeWire) String() string {
	return "postgres.oidcMaintenanceClientSecretEnvelopeWire{material:[REDACTED]}"
}

func (value oidcMaintenanceClientSecretEnvelopeWire) GoString() string { return value.String() }

type samlSPKeyLookupWire struct {
	Provider   federatedProviderBindingWire `json:"provider"`
	Revision   uint64                       `json:"revision"`
	MaterialID string                       `json:"materialId,omitempty"`
}

type samlSPKeyEnvelopeWire struct {
	Lookup             samlSPKeyLookupWire `json:"lookup"`
	KeyID              string              `json:"keyId"`
	EnvelopeKeyVersion uint32              `json:"envelopeKeyVersion"`
	EnvelopeCiphertext []byte              `json:"envelopeCiphertext"`
	CertificateDER     [][]byte            `json:"certificateDer"`
}

var _ federatedauth.OIDCClientSecretEnvelopeSource = (*FederatedAuthRepository)(nil)
var _ federatedauth.OIDCMaintenanceClientSecretEnvelopeSource = (*FederatedAuthRepository)(nil)
var _ federatedauth.SAMLSPKeyEnvelopeSource = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) LoadOIDCClientSecretEnvelope(
	ctx context.Context,
	lookup federatedauth.ClientSecretContext,
) (federatedauth.OIDCClientSecretSnapshot, error) {
	wire, err := oidcClientSecretLookupToWire(lookup)
	if err != nil {
		return federatedauth.OIDCClientSecretSnapshot{}, errFederatedAuthPersistence
	}
	var response oidcClientSecretEnvelopeWire
	defer clearOIDCClientSecretEnvelopeWire(&response)
	if err := repository.queryJSON(ctx, loadOIDCClientSecretEnvelopeSQL, wire, &response); err != nil {
		return federatedauth.OIDCClientSecretSnapshot{}, err
	}
	snapshot, err := oidcClientSecretEnvelopeFromWire(response)
	if err != nil || snapshot.Lookup != lookup {
		clear(snapshot.Envelope.Nonce[:])
		clear(snapshot.Envelope.Ciphertext)
		return federatedauth.OIDCClientSecretSnapshot{}, errFederatedAuthPersistence
	}
	return snapshot, nil
}

func (repository *FederatedAuthRepository) LoadOIDCMaintenanceClientSecretEnvelope(
	ctx context.Context,
	lookup federatedauth.ClientSecretContext,
) (federatedauth.OIDCClientSecretSnapshot, error) {
	wire, err := oidcMaintenanceClientSecretLookupToWire(lookup)
	if err != nil {
		return federatedauth.OIDCClientSecretSnapshot{}, errFederatedAuthPersistence
	}
	var response oidcMaintenanceClientSecretEnvelopeWire
	defer clearOIDCMaintenanceClientSecretEnvelopeWire(&response)
	if err := repository.queryJSONWithResponseLimit(
		ctx, loadOIDCMaintenanceClientSecretEnvelopeSQL, wire, &response,
		maximumFederatedAuthenticationWireBytes,
	); err != nil {
		return federatedauth.OIDCClientSecretSnapshot{}, errFederatedAuthPersistence
	}
	snapshot, err := oidcMaintenanceClientSecretEnvelopeFromWire(response)
	if err != nil || snapshot.Lookup != lookup {
		clear(snapshot.Envelope.Nonce[:])
		clear(snapshot.Envelope.Ciphertext)
		return federatedauth.OIDCClientSecretSnapshot{}, errFederatedAuthPersistence
	}
	return snapshot, nil
}

func (repository *FederatedAuthRepository) LoadSAMLSPKeyEnvelope(
	ctx context.Context,
	lookup federatedsaml.SPKeyRequest,
) (federatedauth.SAMLSPKeySnapshot, error) {
	wire, err := samlSPKeyLookupToWire(lookup)
	if err != nil {
		return federatedauth.SAMLSPKeySnapshot{}, errFederatedAuthPersistence
	}
	var response samlSPKeyEnvelopeWire
	defer clearSAMLSPKeyEnvelopeWire(&response)
	query := loadSAMLSPKeyEnvelopeSQL
	if lookup.LogoutMaterialID != (identity.EntityID{}) {
		query = loadTenantSAMLLogoutSPKeyEnvelopeSQL
	}
	if err := repository.queryJSON(ctx, query, wire, &response); err != nil {
		return federatedauth.SAMLSPKeySnapshot{}, err
	}
	snapshot, err := samlSPKeyEnvelopeFromWire(response)
	if err != nil || response.Lookup != wire || snapshot.Context.Provider != lookup.Provider ||
		snapshot.Context.BindingID != lookup.BindingID ||
		snapshot.Context.KeyRevision != lookup.KeyRevision {
		clear(snapshot.Envelope.Ciphertext)
		for index := range snapshot.CertificateDER {
			clear(snapshot.CertificateDER[index])
		}
		return federatedauth.SAMLSPKeySnapshot{}, errFederatedAuthPersistence
	}
	return snapshot, nil
}

func oidcClientSecretLookupToWire(
	lookup federatedauth.ClientSecretContext,
) (oidcClientSecretLookupWire, error) {
	provider, admission, err := oidcProviderAdmissionToWire(lookup.Provider, lookup.BindingID, lookup.Admission)
	if err != nil || !validFederatedRevision(lookup.Revision) ||
		lookup.Maintenance != (federatedauth.OIDCMaintenanceSecretProof{}) {
		return oidcClientSecretLookupWire{}, errFederatedAuthPersistence
	}
	return oidcClientSecretLookupWire{Provider: provider, Admission: admission, Revision: lookup.Revision}, nil
}

func oidcMaintenanceClientSecretLookupToWire(
	lookup federatedauth.ClientSecretContext,
) (oidcMaintenanceClientSecretLookupWire, error) {
	if !validFederatedRevision(lookup.Revision) || lookup.Revision > maximumOIDCMaintenanceCounter ||
		!validFederatedMaintenanceClientSecretProof(lookup.Maintenance) {
		return oidcMaintenanceClientSecretLookupWire{}, errFederatedAuthPersistence
	}
	materialID, materialErr := requiredFederatedEntityIDWire(lookup.Maintenance.MaterialID)
	familyID, familyErr := requiredFederatedEntityIDWire(lookup.Maintenance.SessionFamilyID)
	if materialErr != nil || familyErr != nil {
		return oidcMaintenanceClientSecretLookupWire{}, errFederatedAuthPersistence
	}
	wire := oidcMaintenanceClientSecretLookupWire{
		Revision: lookup.Revision, Kind: string(lookup.Maintenance.Kind), MaterialID: materialID,
		SessionFamilyID: familyID, ClaimVersion: lookup.Maintenance.ClaimVersion,
		RefreshGeneration: lookup.Maintenance.RefreshGeneration,
	}
	if lookup.Maintenance.Kind == federatedauth.OIDCMaintenanceSecretLogoutRetry {
		jobID, jobErr := requiredFederatedEntityIDWire(lookup.Maintenance.JobID)
		if jobErr != nil {
			return oidcMaintenanceClientSecretLookupWire{}, errFederatedAuthPersistence
		}
		attempt := lookup.Maintenance.Attempt
		wire.JobID, wire.Attempt = &jobID, &attempt
	}
	var err error
	switch lookup.Provider.Scope {
	case identity.TenantProviderScope:
		if lookup.Admission != (identity.TenantAdmissionContext{}) {
			return oidcMaintenanceClientSecretLookupWire{}, errFederatedAuthPersistence
		}
		wire.Provider, err = providerBindingToWire(lookup.Provider, lookup.BindingID, false)
		if err == nil {
			bindingID, bindingErr := requiredFederatedEntityIDWire(lookup.BindingID)
			err = bindingErr
			wire.BindingID = &bindingID
		}
	case identity.PlatformProviderScope:
		if lookup.Provider.TenantID != (identity.EntityID{}) || lookup.BindingID != (identity.EntityID{}) {
			return oidcMaintenanceClientSecretLookupWire{}, errFederatedAuthPersistence
		}
		wire.Provider, err = providerBindingToWire(lookup.Provider, identity.EntityID{}, true)
		if err == nil && lookup.Admission != (identity.TenantAdmissionContext{}) {
			var admission federatedTenantAdmissionWire
			admission, err = tenantAdmissionToWire(lookup.Admission)
			wire.Admission = &admission
			if err == nil {
				bindingID := admission.BindingID
				wire.BindingID = &bindingID
			}
		}
	default:
		return oidcMaintenanceClientSecretLookupWire{}, errFederatedAuthPersistence
	}
	if err != nil {
		return oidcMaintenanceClientSecretLookupWire{}, errFederatedAuthPersistence
	}
	return wire, nil
}

func oidcClientSecretEnvelopeFromWire(
	wire oidcClientSecretEnvelopeWire,
) (federatedauth.OIDCClientSecretSnapshot, error) {
	provider, admission, binding, err := oidcProviderAdmissionFromWire(wire.Lookup.Provider, wire.Lookup.Admission)
	secretID, secretErr := parseFederatedEntityIDWire(wire.SecretID, false)
	if err != nil || secretErr != nil || !validFederatedRevision(wire.Lookup.Revision) || wire.KeyVersion < 1 ||
		len(wire.Nonce) != oidcClientSecretNonceBytes || len(wire.Ciphertext) <= sha256.Size/2 ||
		len(wire.Ciphertext) > maximumOIDCClientSecretCiphertext {
		return federatedauth.OIDCClientSecretSnapshot{}, errFederatedAuthPersistence
	}
	var nonce [oidcClientSecretNonceBytes]byte
	copy(nonce[:], wire.Nonce)
	return federatedauth.OIDCClientSecretSnapshot{
		Lookup: federatedauth.ClientSecretContext{
			Provider: provider, Admission: admission, BindingID: binding, Revision: wire.Lookup.Revision,
		},
		SecretID: secretID,
		Envelope: identity.OIDCClientSecretEnvelope{
			KeyVersion: wire.KeyVersion, Nonce: nonce, Ciphertext: append([]byte(nil), wire.Ciphertext...),
		},
	}, nil
}

func oidcMaintenanceClientSecretEnvelopeFromWire(
	wire oidcMaintenanceClientSecretEnvelopeWire,
) (federatedauth.OIDCClientSecretSnapshot, error) {
	lookup, err := oidcMaintenanceClientSecretLookupFromWire(wire.Lookup)
	secretID, secretErr := parseFederatedEntityIDWire(wire.SecretID, false)
	if err != nil || secretErr != nil || wire.KeyVersion < 1 ||
		len(wire.Nonce) != oidcClientSecretNonceBytes ||
		len(wire.Ciphertext) <= sha256.Size/2 || len(wire.Ciphertext) > maximumOIDCClientSecretCiphertext {
		return federatedauth.OIDCClientSecretSnapshot{}, errFederatedAuthPersistence
	}
	var nonce [oidcClientSecretNonceBytes]byte
	copy(nonce[:], wire.Nonce)
	return federatedauth.OIDCClientSecretSnapshot{
		Lookup: lookup, SecretID: secretID,
		Envelope: identity.OIDCClientSecretEnvelope{
			KeyVersion: wire.KeyVersion, Nonce: nonce, Ciphertext: append([]byte(nil), wire.Ciphertext...),
		},
	}, nil
}

func oidcMaintenanceClientSecretLookupFromWire(
	wire oidcMaintenanceClientSecretLookupWire,
) (federatedauth.ClientSecretContext, error) {
	if !validFederatedRevision(wire.Revision) || wire.Revision > maximumOIDCMaintenanceCounter {
		return federatedauth.ClientSecretContext{}, errFederatedAuthPersistence
	}
	provider, providerBinding, err := providerBindingFromWire(wire.Provider, true)
	if err != nil {
		return federatedauth.ClientSecretContext{}, errFederatedAuthPersistence
	}
	bindingID, bindingErr := optionalSessionLogoutEntityID(wire.BindingID)
	materialID, materialErr := parseFederatedEntityIDWire(wire.MaterialID, false)
	familyID, familyErr := parseFederatedEntityIDWire(wire.SessionFamilyID, false)
	proof := federatedauth.OIDCMaintenanceSecretProof{
		Kind: federatedauth.OIDCMaintenanceSecretKind(wire.Kind), MaterialID: materialID,
		SessionFamilyID: familyID, ClaimVersion: wire.ClaimVersion,
		RefreshGeneration: wire.RefreshGeneration,
	}
	if materialErr != nil || familyErr != nil {
		return federatedauth.ClientSecretContext{}, errFederatedAuthPersistence
	}
	switch proof.Kind {
	case federatedauth.OIDCMaintenanceSecretRefresh:
		if wire.JobID != nil || wire.Attempt != nil {
			return federatedauth.ClientSecretContext{}, errFederatedAuthPersistence
		}
	case federatedauth.OIDCMaintenanceSecretLogoutRetry:
		if wire.JobID == nil || wire.Attempt == nil {
			return federatedauth.ClientSecretContext{}, errFederatedAuthPersistence
		}
		jobID, jobErr := parseFederatedEntityIDWire(*wire.JobID, false)
		if jobErr != nil {
			return federatedauth.ClientSecretContext{}, errFederatedAuthPersistence
		}
		proof.JobID, proof.Attempt = jobID, *wire.Attempt
	default:
		return federatedauth.ClientSecretContext{}, errFederatedAuthPersistence
	}
	if !validFederatedMaintenanceClientSecretProof(proof) {
		return federatedauth.ClientSecretContext{}, errFederatedAuthPersistence
	}
	lookup := federatedauth.ClientSecretContext{Provider: provider, Revision: wire.Revision, Maintenance: proof}
	switch provider.Scope {
	case identity.TenantProviderScope:
		if bindingErr != nil || wire.Admission != nil || bindingID == (identity.EntityID{}) ||
			providerBinding != bindingID {
			return federatedauth.ClientSecretContext{}, errFederatedAuthPersistence
		}
		lookup.BindingID = bindingID
	case identity.PlatformProviderScope:
		if bindingErr != nil || providerBinding != (identity.EntityID{}) {
			return federatedauth.ClientSecretContext{}, errFederatedAuthPersistence
		}
		if wire.Admission != nil {
			admission, admissionErr := tenantAdmissionFromWire(*wire.Admission)
			if admissionErr != nil || bindingID == (identity.EntityID{}) || bindingID != admission.BindingID {
				return federatedauth.ClientSecretContext{}, errFederatedAuthPersistence
			}
			lookup.Admission = admission
		} else if bindingID != (identity.EntityID{}) {
			return federatedauth.ClientSecretContext{}, errFederatedAuthPersistence
		}
	default:
		return federatedauth.ClientSecretContext{}, errFederatedAuthPersistence
	}
	return lookup, nil
}

func validFederatedMaintenanceClientSecretProof(proof federatedauth.OIDCMaintenanceSecretProof) bool {
	if !validFederatedRevision(proof.ClaimVersion) || proof.ClaimVersion >= maximumOIDCMaintenanceCounter ||
		!validFederatedRevision(proof.RefreshGeneration) || proof.RefreshGeneration >= maximumOIDCMaintenanceCounter ||
		entityIDWire(proof.MaterialID) == "" || entityIDWire(proof.SessionFamilyID) == "" {
		return false
	}
	switch proof.Kind {
	case federatedauth.OIDCMaintenanceSecretRefresh:
		return proof.JobID == (identity.EntityID{}) && proof.Attempt == 0
	case federatedauth.OIDCMaintenanceSecretLogoutRetry:
		return entityIDWire(proof.JobID) != "" && proof.Attempt >= 1 && proof.Attempt <= 16
	default:
		return false
	}
}

func samlSPKeyLookupToWire(lookup federatedsaml.SPKeyRequest) (samlSPKeyLookupWire, error) {
	provider, err := providerBindingToWire(lookup.Provider, lookup.BindingID, false)
	if err != nil || !validFederatedRevision(uint64(lookup.KeyRevision)) {
		return samlSPKeyLookupWire{}, errFederatedAuthPersistence
	}
	wire := samlSPKeyLookupWire{Provider: provider, Revision: uint64(lookup.KeyRevision)}
	if lookup.LogoutMaterialID != (identity.EntityID{}) {
		wire.MaterialID, err = requiredFederatedEntityIDWire(lookup.LogoutMaterialID)
		if err != nil {
			return samlSPKeyLookupWire{}, errFederatedAuthPersistence
		}
	}
	return wire, nil
}

func samlSPKeyEnvelopeFromWire(wire samlSPKeyEnvelopeWire) (federatedauth.SAMLSPKeySnapshot, error) {
	provider, binding, err := providerBindingFromWire(wire.Lookup.Provider, false)
	keyID, keyErr := parseFederatedEntityIDWire(wire.KeyID, false)
	if err != nil || keyErr != nil || !validFederatedRevision(wire.Lookup.Revision) ||
		wire.Lookup.Revision > uint64(^uint32(0)) || wire.EnvelopeKeyVersion == 0 ||
		len(wire.EnvelopeCiphertext) == 0 || len(wire.EnvelopeCiphertext) > maximumSAMLSPKeyEnvelopeWireBytes ||
		len(wire.CertificateDER) == 0 || len(wire.CertificateDER) > maximumSAMLSPCertificateWireCount ||
		!validSAMLSPCertificateWire(wire.CertificateDER) {
		return federatedauth.SAMLSPKeySnapshot{}, errFederatedAuthPersistence
	}
	return federatedauth.SAMLSPKeySnapshot{
		Context: federatedauth.SAMLSPKeyProtectionContext{
			Provider: provider, BindingID: binding, KeyID: keyID, KeyRevision: uint32(wire.Lookup.Revision),
		},
		Envelope: federatedauth.ProtectedSAMLSPKey{
			KeyVersion: wire.EnvelopeKeyVersion, Ciphertext: append([]byte(nil), wire.EnvelopeCiphertext...),
		},
		CertificateDER: cloneFederatedBytes2D(wire.CertificateDER),
	}, nil
}

func validSAMLSPCertificateWire(values [][]byte) bool {
	seen := make(map[[sha256.Size]byte]struct{}, len(values))
	for _, value := range values {
		if len(value) == 0 || len(value) > maximumSAMLSPCertificateWireBytes {
			return false
		}
		digest := sha256.Sum256(value)
		if _, duplicate := seen[digest]; duplicate {
			return false
		}
		seen[digest] = struct{}{}
	}
	return true
}

func clearOIDCClientSecretEnvelopeWire(value *oidcClientSecretEnvelopeWire) {
	if value == nil {
		return
	}
	clear(value.Nonce)
	clear(value.Ciphertext)
}

func clearOIDCMaintenanceClientSecretEnvelopeWire(value *oidcMaintenanceClientSecretEnvelopeWire) {
	if value == nil {
		return
	}
	clear(value.Nonce)
	clear(value.Ciphertext)
	*value = oidcMaintenanceClientSecretEnvelopeWire{}
}

func clearSAMLSPKeyEnvelopeWire(value *samlSPKeyEnvelopeWire) {
	if value == nil {
		return
	}
	clear(value.EnvelopeCiphertext)
	for index := range value.CertificateDER {
		clear(value.CertificateDER[index])
	}
}

func cloneFederatedBytes2D(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = append([]byte(nil), values[index]...)
	}
	return result
}
