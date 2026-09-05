package federatedauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

type samlSPKeyEnvelopeSourceFunc func(context.Context, federatedsaml.SPKeyRequest) (SAMLSPKeySnapshot, error)

func (function samlSPKeyEnvelopeSourceFunc) LoadSAMLSPKeyEnvelope(
	ctx context.Context,
	request federatedsaml.SPKeyRequest,
) (SAMLSPKeySnapshot, error) {
	return function(ctx, request)
}

type samlSPKeyEnvelopeOpenerFunc func(context.Context, SAMLSPKeyProtectionContext, ProtectedSAMLSPKey) ([]byte, error)

func (function samlSPKeyEnvelopeOpenerFunc) OpenSAMLSPKeyEnvelope(
	ctx context.Context,
	protection SAMLSPKeyProtectionContext,
	envelope ProtectedSAMLSPKey,
) ([]byte, error) {
	return function(ctx, protection, envelope)
}

func TestProtectedSAMLSPKeySourceOpensExactECDSARevision(t *testing.T) {
	privateKey, certificate, encoded := samlECDSAKeyFixture(t)
	request, snapshot := samlSPKeySnapshotFixture(encoded, certificate)
	request.LogoutMaterialID = serviceID(75)
	returnedCiphertext := snapshot.Envelope.Ciphertext
	returnedCertificate := snapshot.CertificateDER[0]
	openerCiphertext := []byte(nil)
	source, err := NewProtectedSAMLSPKeySource(
		samlSPKeyEnvelopeSourceFunc(func(
			_ context.Context,
			got federatedsaml.SPKeyRequest,
		) (SAMLSPKeySnapshot, error) {
			if got != request {
				t.Fatalf("request = %+v, want %+v", got, request)
			}
			return snapshot, nil
		}),
		samlSPKeyEnvelopeOpenerFunc(func(
			_ context.Context,
			got SAMLSPKeyProtectionContext,
			envelope ProtectedSAMLSPKey,
		) ([]byte, error) {
			if got != snapshot.Context || envelope.KeyVersion != snapshot.Envelope.KeyVersion ||
				string(envelope.Ciphertext) != "sealed-saml-key" {
				t.Fatalf("opener context/envelope drift: %s %s", got, envelope)
			}
			openerCiphertext = envelope.Ciphertext
			return append([]byte(nil), encoded...), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	material, err := source.LoadSAMLSPKey(context.Background(), request)
	if err != nil || material.Provider != request.Provider || material.BindingID != request.BindingID ||
		material.KeyRevision != request.KeyRevision || material.Signer == nil || material.RSADecrypter != nil ||
		len(material.CertificateDER) != 1 {
		t.Fatalf("LoadSAMLSPKey() = %s, %v", material, err)
	}
	got, ok := material.Signer.(*ecdsa.PrivateKey)
	if !ok || got.D.Cmp(privateKey.D) != 0 {
		t.Fatal("LoadSAMLSPKey() returned a different signing key")
	}
	if !allZero(returnedCiphertext) || !allZero(returnedCertificate) || !allZero(openerCiphertext) ||
		allZero(material.CertificateDER[0]) {
		t.Fatal("secret source did not transfer and clear intermediate storage")
	}
}

func TestProtectedSAMLSPKeySourceReturnsRSADecrypterForExactKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := samlCertificateForSigner(t, &privateKey.PublicKey, privateKey)
	request, snapshot := samlSPKeySnapshotFixture(encoded, certificate)
	source, _ := NewProtectedSAMLSPKeySource(
		samlSPKeyEnvelopeSourceFunc(func(context.Context, federatedsaml.SPKeyRequest) (SAMLSPKeySnapshot, error) {
			return cloneSAMLSPKeySnapshot(snapshot), nil
		}),
		samlSPKeyEnvelopeOpenerFunc(func(context.Context, SAMLSPKeyProtectionContext, ProtectedSAMLSPKey) ([]byte, error) {
			return append([]byte(nil), encoded...), nil
		}),
	)
	material, err := source.LoadSAMLSPKey(context.Background(), request)
	if err != nil || material.RSADecrypter == nil || material.Signer != material.RSADecrypter ||
		material.RSADecrypter.N.Cmp(privateKey.N) != 0 {
		t.Fatalf("LoadSAMLSPKey() = %s, %v", material, err)
	}
}

func TestProtectedSAMLSPKeySourceRejectsProjectionKeyAndCertificateDrift(t *testing.T) {
	_, certificate, encoded := samlECDSAKeyFixture(t)
	request, valid := samlSPKeySnapshotFixture(encoded, certificate)
	_, otherCertificate, _ := samlECDSAKeyFixture(t)
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed25519Encoded, err := x509.MarshalPKCS8PrivateKey(ed25519Key)
	if err != nil {
		t.Fatal(err)
	}

	for name, arrange := range map[string]func(*SAMLSPKeySnapshot, *[]byte, *error){
		"source detail": func(_ *SAMLSPKeySnapshot, _ *[]byte, sourceErr *error) {
			*sourceErr = errors.New("kms-key-canary detail")
		},
		"provider swap": func(snapshot *SAMLSPKeySnapshot, _ *[]byte, _ *error) {
			snapshot.Context.Provider.ProviderID = serviceID(90)
		},
		"binding swap": func(snapshot *SAMLSPKeySnapshot, _ *[]byte, _ *error) {
			snapshot.Context.BindingID = serviceID(91)
		},
		"revision swap": func(snapshot *SAMLSPKeySnapshot, _ *[]byte, _ *error) {
			snapshot.Context.KeyRevision++
		},
		"empty envelope": func(snapshot *SAMLSPKeySnapshot, _ *[]byte, _ *error) {
			snapshot.Envelope.Ciphertext = nil
		},
		"certificate mismatch": func(snapshot *SAMLSPKeySnapshot, _ *[]byte, _ *error) {
			snapshot.CertificateDER[0] = append([]byte(nil), otherCertificate...)
		},
		"duplicate certificate": func(snapshot *SAMLSPKeySnapshot, _ *[]byte, _ *error) {
			snapshot.CertificateDER = append(snapshot.CertificateDER, append([]byte(nil), snapshot.CertificateDER[0]...))
		},
		"unsupported key": func(_ *SAMLSPKeySnapshot, opened *[]byte, _ *error) {
			*opened = append([]byte(nil), ed25519Encoded...)
		},
		"opener detail": func(_ *SAMLSPKeySnapshot, _ *[]byte, sourceErr *error) {
			*sourceErr = errors.New("keyring-canary detail")
		},
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := cloneSAMLSPKeySnapshot(valid)
			opened := append([]byte(nil), encoded...)
			var injected error
			arrange(&snapshot, &opened, &injected)
			openerCalled := false
			source, _ := NewProtectedSAMLSPKeySource(
				samlSPKeyEnvelopeSourceFunc(func(context.Context, federatedsaml.SPKeyRequest) (SAMLSPKeySnapshot, error) {
					if name == "source detail" {
						return snapshot, injected
					}
					return snapshot, nil
				}),
				samlSPKeyEnvelopeOpenerFunc(func(context.Context, SAMLSPKeyProtectionContext, ProtectedSAMLSPKey) ([]byte, error) {
					openerCalled = true
					if name == "opener detail" {
						return nil, injected
					}
					return opened, nil
				}),
			)
			material, loadErr := source.LoadSAMLSPKey(context.Background(), request)
			if !errors.Is(loadErr, federatedsaml.ErrSPKeyUnavailable) || material.Signer != nil ||
				strings.Contains(loadErr.Error(), "canary") {
				t.Fatalf("LoadSAMLSPKey() = %s, %v", material, loadErr)
			}
			projectionInvalid := name != "certificate mismatch" && name != "unsupported key" && name != "opener detail"
			if projectionInvalid && openerCalled {
				t.Fatal("invalid database projection reached keyring")
			}
		})
	}
}

func TestValidatedSAMLPrivateKeyRejectsInconsistentECDSAPublicPoint(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateKey.PublicKey.X = other.PublicKey.X
	privateKey.PublicKey.Y = other.PublicKey.Y
	if _, _, err := validatedSAMLPrivateKey(privateKey); !errors.Is(err, federatedsaml.ErrSPKeyUnavailable) {
		t.Fatalf("inconsistent ECDSA key error = %v", err)
	}
}

func TestProtectedSAMLSPKeySourceHonorsCancellationBeforeKeyring(t *testing.T) {
	_, certificate, encoded := samlECDSAKeyFixture(t)
	request, snapshot := samlSPKeySnapshotFixture(encoded, certificate)
	ctx, cancel := context.WithCancel(context.Background())
	openerCalled := false
	source, _ := NewProtectedSAMLSPKeySource(
		samlSPKeyEnvelopeSourceFunc(func(context.Context, federatedsaml.SPKeyRequest) (SAMLSPKeySnapshot, error) {
			cancel()
			return cloneSAMLSPKeySnapshot(snapshot), nil
		}),
		samlSPKeyEnvelopeOpenerFunc(func(context.Context, SAMLSPKeyProtectionContext, ProtectedSAMLSPKey) ([]byte, error) {
			openerCalled = true
			return append([]byte(nil), encoded...), nil
		}),
	)
	if _, err := source.LoadSAMLSPKey(ctx, request); !errors.Is(err, federatedsaml.ErrSPKeyUnavailable) {
		t.Fatalf("LoadSAMLSPKey() error = %v", err)
	}
	if openerCalled {
		t.Fatal("cancelled load reached keyring")
	}
}

func TestProtectedSAMLSPKeySourceRejectsMalformedRequestBeforePersistence(t *testing.T) {
	called := false
	source, _ := NewProtectedSAMLSPKeySource(
		samlSPKeyEnvelopeSourceFunc(func(context.Context, federatedsaml.SPKeyRequest) (SAMLSPKeySnapshot, error) {
			called = true
			return SAMLSPKeySnapshot{}, nil
		}),
		samlSPKeyEnvelopeOpenerFunc(func(context.Context, SAMLSPKeyProtectionContext, ProtectedSAMLSPKey) ([]byte, error) {
			return nil, nil
		}),
	)
	request, _ := samlSPKeySnapshotFixture([]byte{1}, []byte{1})
	request.KeyRevision = 0
	if _, err := source.LoadSAMLSPKey(context.Background(), request); !errors.Is(err, federatedsaml.ErrSPKeyUnavailable) {
		t.Fatalf("LoadSAMLSPKey() error = %v", err)
	}
	if called {
		t.Fatal("malformed key request reached persistence")
	}
	request.KeyRevision = 5
	request.LogoutMaterialID = identity.EntityID{1}
	if _, err := source.LoadSAMLSPKey(context.Background(), request); !errors.Is(err, federatedsaml.ErrSPKeyUnavailable) {
		t.Fatalf("malformed logout material request error = %v", err)
	}
	if called {
		t.Fatal("malformed logout material reached persistence")
	}
}

func TestProtectedSAMLSPKeyFormattingNeverLeaksMaterial(t *testing.T) {
	const canary = "saml-private-key-canary"
	values := []any{
		ProtectedSAMLSPKey{Ciphertext: []byte(canary)},
		SAMLSPKeyProtectionContext{},
		SAMLSPKeySnapshot{Envelope: ProtectedSAMLSPKey{Ciphertext: []byte(canary)}, CertificateDER: [][]byte{[]byte(canary)}},
		&ProtectedSAMLSPKeySource{},
	}
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if output := fmt.Sprintf(format, value); strings.Contains(output, canary) {
				t.Fatalf("%T leaked with %s: %s", value, format, output)
			}
		}
	}
}

func samlECDSAKeyFixture(t *testing.T) (*ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, samlCertificateForSigner(t, &privateKey.PublicKey, privateKey), encoded
}

func samlCertificateForSigner(t *testing.T, publicKey any, privateKey any) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "saml-sp-key"},
		NotBefore: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func samlSPKeySnapshotFixture(privateKey, certificate []byte) (federatedsaml.SPKeyRequest, SAMLSPKeySnapshot) {
	tenantID := serviceID(71)
	request := federatedsaml.SPKeyRequest{
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: serviceID(72),
		},
		BindingID: serviceID(73), KeyRevision: 5,
	}
	return request, SAMLSPKeySnapshot{
		Context: SAMLSPKeyProtectionContext{
			Provider: request.Provider, BindingID: request.BindingID, KeyID: serviceID(74), KeyRevision: request.KeyRevision,
		},
		Envelope:       ProtectedSAMLSPKey{KeyVersion: 3, Ciphertext: []byte("sealed-saml-key")},
		CertificateDER: [][]byte{append([]byte(nil), certificate...)},
	}
}

func cloneSAMLSPKeySnapshot(value SAMLSPKeySnapshot) SAMLSPKeySnapshot {
	value.Envelope.Ciphertext = append([]byte(nil), value.Envelope.Ciphertext...)
	value.CertificateDER = cloneBytes2D(value.CertificateDER)
	return value
}
