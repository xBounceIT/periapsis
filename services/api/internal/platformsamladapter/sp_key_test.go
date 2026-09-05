package platformsamladapter

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

type testSPKeyEnvelopeRepository struct {
	guard    sync.Mutex
	snapshot DirectSAMLSPKeyEnvelopeSnapshot
	err      error
	calls    int
	request  federatedsaml.DirectPlatformSPKeyRequest
}

func (repository *testSPKeyEnvelopeRepository) LoadDirectPlatformSAMLSPKeyEnvelope(
	_ context.Context,
	request federatedsaml.DirectPlatformSPKeyRequest,
) (DirectSAMLSPKeyEnvelopeSnapshot, error) {
	repository.guard.Lock()
	defer repository.guard.Unlock()
	repository.calls++
	repository.request = request
	return repository.snapshot, repository.err
}

type spKeyFixture struct {
	source     *ProtectedDirectSAMLSPKeySource
	repository *testSPKeyEnvelopeRepository
	keyring    identity.Keyring
	request    federatedsaml.DirectPlatformSPKeyRequest
	context    identity.DirectPlatformSAMLSPKeyContext
}

func newSPKeyFixture(t *testing.T) spKeyFixture {
	t.Helper()
	root := bytes.Repeat([]byte{0x51}, 32)
	keyring, err := identity.NewKeyring(2, map[int16][]byte{1: bytes.Repeat([]byte{0x31}, 32), 2: root})
	clear(root)
	if err != nil {
		t.Fatalf("identity.NewKeyring() error = %v", err)
	}
	privateKey, certificate := testRSAKeyAndCertificate(t)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	request := federatedsaml.DirectPlatformSPKeyRequest{
		Provider:              identity.ProviderContext{Scope: identity.PlatformProviderScope, ProviderID: testEntity(10)},
		PlatformLoginRevision: 44, KeyRevision: 9_001,
	}
	keyContext := identity.DirectPlatformSAMLSPKeyContext{
		Provider: request.Provider, KeyID: testEntity(101), KeyRevision: request.KeyRevision,
	}
	envelope, err := keyring.EncryptDirectPlatformSAMLSPKey(keyContext, pkcs8)
	clear(pkcs8)
	if err != nil {
		t.Fatalf("EncryptDirectPlatformSAMLSPKey() error = %v", err)
	}
	repository := &testSPKeyEnvelopeRepository{snapshot: DirectSAMLSPKeyEnvelopeSnapshot{
		Request: request, PlatformLoginRevision: request.PlatformLoginRevision, Context: keyContext,
		Envelope: envelope, CertificateDER: [][]byte{certificate}, Live: true,
	}}
	source, err := NewProtectedDirectSAMLSPKeySource(ProtectedDirectSAMLSPKeySourceOptions{
		Repository: repository, Keyring: keyring, Now: testInstant,
	})
	if err != nil {
		t.Fatalf("NewProtectedDirectSAMLSPKeySource() error = %v", err)
	}
	return spKeyFixture{source: source, repository: repository, keyring: keyring, request: request, context: keyContext}
}

func TestValidateDirectSAMLSPKeyBundleMatchesRuntimeAcceptance(t *testing.T) {
	privateKey, certificate := testRSAKeyAndCertificate(t)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(pkcs8)
	now := testInstant()
	if err := ValidateDirectSAMLSPKeyBundle(pkcs8, [][]byte{certificate}, now); err != nil {
		t.Fatalf("ValidateDirectSAMLSPKeyBundle() error = %v", err)
	}

	tests := map[string]struct {
		key          []byte
		certificates [][]byte
		observedAt   time.Time
	}{
		"missing key":         {certificates: [][]byte{certificate}, observedAt: now},
		"malformed key":       {key: []byte("not-pkcs8"), certificates: [][]byte{certificate}, observedAt: now},
		"missing certificate": {key: pkcs8, observedAt: now},
		"duplicate certificate": {
			key: pkcs8, certificates: [][]byte{certificate, append([]byte(nil), certificate...)}, observedAt: now,
		},
		"invalid instant": {key: pkcs8, certificates: [][]byte{certificate}, observedAt: time.Time{}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if err := ValidateDirectSAMLSPKeyBundle(test.key, test.certificates, test.observedAt); !errors.Is(err, ErrProtocolRejected) {
				t.Fatalf("ValidateDirectSAMLSPKeyBundle() error = %v", err)
			}
		})
	}
}

func TestProtectedDirectSAMLSPKeySourceSeparatesSemanticAndRootRevisions(t *testing.T) {
	fixture := newSPKeyFixture(t)
	material, err := fixture.source.LoadDirectPlatformSAMLSPKey(context.Background(), fixture.request)
	if err != nil {
		t.Fatalf("LoadDirectPlatformSAMLSPKey() error = %v", err)
	}
	if material.Context != fixture.context || material.Signer == nil || material.RSADecrypter == nil ||
		len(material.CertificateDER) != 1 || fixture.request.KeyRevision != 9_001 {
		t.Fatalf("material = %q", material.String())
	}
	fixture.repository.guard.Lock()
	snapshot := fixture.repository.snapshot
	fixture.repository.guard.Unlock()
	if snapshot.Envelope.KeyVersion != 2 {
		t.Fatalf("root key version = %d, want 2", snapshot.Envelope.KeyVersion)
	}
	if !allZeroBytes(snapshot.Envelope.Ciphertext) || !allZeroBytes(snapshot.CertificateDER[0]) {
		t.Fatal("repository-owned secret/public working buffers were not cleared")
	}
	if allZeroBytes(material.CertificateDER[0]) {
		t.Fatal("returned public certificate aliases cleared repository buffer")
	}
	if strings.Contains(fixture.source.String(), "9001") || strings.Contains(snapshot.String(), "PRIVATE") {
		t.Fatal("adapter formatting exposed key material")
	}
}

func TestProtectedDirectSAMLSPKeyIsNotTenantPortable(t *testing.T) {
	fixture := newSPKeyFixture(t)
	fixture.repository.guard.Lock()
	envelope := fixture.repository.snapshot.Envelope
	fixture.repository.guard.Unlock()
	tenantContext := identity.SAMLSPKeyContext{
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: testEntity(110), ProviderID: fixture.request.Provider.ProviderID,
		},
		BindingID: testEntity(111), KeyID: fixture.context.KeyID, KeyRevision: uint32(fixture.context.KeyRevision),
	}
	plaintext, err := fixture.keyring.DecryptSAMLSPKey(tenantContext, envelope)
	clear(plaintext)
	if err == nil {
		t.Fatal("direct-platform SP key envelope opened under tenant AAD")
	}

	crossScope := fixture.request
	crossScope.Provider.Scope = identity.TenantProviderScope
	if _, err := fixture.source.LoadDirectPlatformSAMLSPKey(context.Background(), crossScope); !errors.Is(err, federatedsaml.ErrSPKeyUnavailable) {
		t.Fatalf("cross-scope load error = %v", err)
	}
	fixture.repository.guard.Lock()
	calls := fixture.repository.calls
	fixture.repository.guard.Unlock()
	if calls != 0 {
		t.Fatalf("cross-scope request reached repository %d times", calls)
	}
}

func TestProtectedDirectSAMLSPKeyRejectsExactPinAndEnvelopeSubstitution(t *testing.T) {
	tests := map[string]func(*DirectSAMLSPKeyEnvelopeSnapshot){
		"request": func(value *DirectSAMLSPKeyEnvelopeSnapshot) { value.Request.KeyRevision++ },
		"login revision": func(value *DirectSAMLSPKeyEnvelopeSnapshot) {
			value.PlatformLoginRevision++
		},
		"provider": func(value *DirectSAMLSPKeyEnvelopeSnapshot) {
			value.Context.Provider.ProviderID = testEntity(120)
		},
		"key id":       func(value *DirectSAMLSPKeyEnvelopeSnapshot) { value.Context.KeyID = identity.EntityID{} },
		"key revision": func(value *DirectSAMLSPKeyEnvelopeSnapshot) { value.Context.KeyRevision++ },
		"root version": func(value *DirectSAMLSPKeyEnvelopeSnapshot) { value.Envelope.KeyVersion = 1 },
		"nonce":        func(value *DirectSAMLSPKeyEnvelopeSnapshot) { value.Envelope.Nonce = [12]byte{} },
		"not live":     func(value *DirectSAMLSPKeyEnvelopeSnapshot) { value.Live = false },
		"certificate": func(value *DirectSAMLSPKeyEnvelopeSnapshot) {
			value.CertificateDER[0][0] ^= 0xff
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newSPKeyFixture(t)
			fixture.repository.guard.Lock()
			mutate(&fixture.repository.snapshot)
			fixture.repository.guard.Unlock()
			if _, err := fixture.source.LoadDirectPlatformSAMLSPKey(context.Background(), fixture.request); !errors.Is(err, federatedsaml.ErrSPKeyUnavailable) {
				t.Fatalf("LoadDirectPlatformSAMLSPKey() error = %v", err)
			}
		})
	}
}

func TestProtectedDirectSAMLSPKeyRejectsUnrelatedSecondaryCertificate(t *testing.T) {
	fixture := newSPKeyFixture(t)
	secondaryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(88), Subject: pkix.Name{CommonName: "unrelated"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
	}
	secondary, err := x509.CreateCertificate(rand.Reader, template, template, &secondaryKey.PublicKey, secondaryKey)
	if err != nil {
		t.Fatal(err)
	}
	fixture.repository.guard.Lock()
	fixture.repository.snapshot.CertificateDER = append(fixture.repository.snapshot.CertificateDER, secondary)
	fixture.repository.guard.Unlock()
	if _, err := fixture.source.LoadDirectPlatformSAMLSPKey(context.Background(), fixture.request); !errors.Is(err, federatedsaml.ErrSPKeyUnavailable) {
		t.Fatalf("unrelated secondary certificate error = %v", err)
	}
}

func TestProtectedDirectSAMLSPKeyAllowsExpiredCertificateOnlyForAttestedLogoutMaterial(t *testing.T) {
	future := testInstant().Add(2 * 365 * 24 * time.Hour)
	fixture := newSPKeyFixture(t)
	source, err := NewProtectedDirectSAMLSPKeySource(ProtectedDirectSAMLSPKeySourceOptions{
		Repository: fixture.repository, Keyring: fixture.keyring, Now: func() time.Time { return future },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.LoadDirectPlatformSAMLSPKey(context.Background(), fixture.request); !errors.Is(err, federatedsaml.ErrSPKeyUnavailable) {
		t.Fatalf("interactive expired-certificate load error = %v", err)
	}
	fixture = newSPKeyFixture(t)
	source, err = NewProtectedDirectSAMLSPKeySource(ProtectedDirectSAMLSPKeySourceOptions{
		Repository: fixture.repository, Keyring: fixture.keyring, Now: func() time.Time { return future },
	})
	if err != nil {
		t.Fatal(err)
	}
	historical := fixture.request
	historical.LogoutMaterialID = testEntity(122)
	fixture.repository.guard.Lock()
	fixture.repository.snapshot.Request = historical
	fixture.repository.guard.Unlock()
	material, err := source.LoadDirectPlatformSAMLSPKey(context.Background(), historical)
	if err != nil || material.Signer == nil || material.Context != fixture.context {
		t.Fatalf("historical expired-certificate load = %q, %v", material.String(), err)
	}
}

func TestProtectedDirectSAMLSPKeyHonorsCancellationBeforeRepository(t *testing.T) {
	fixture := newSPKeyFixture(t)
	invalid := fixture.request
	invalid.LogoutMaterialID = identity.EntityID{1}
	if _, err := fixture.source.LoadDirectPlatformSAMLSPKey(context.Background(), invalid); !errors.Is(err, federatedsaml.ErrSPKeyUnavailable) {
		t.Fatalf("invalid logout material load error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fixture.source.LoadDirectPlatformSAMLSPKey(ctx, fixture.request); !errors.Is(err, federatedsaml.ErrSPKeyUnavailable) {
		t.Fatalf("canceled load error = %v", err)
	}
	fixture.repository.guard.Lock()
	calls := fixture.repository.calls
	fixture.repository.guard.Unlock()
	if calls != 0 {
		t.Fatalf("canceled request reached repository %d times", calls)
	}
}

func allZeroBytes(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
