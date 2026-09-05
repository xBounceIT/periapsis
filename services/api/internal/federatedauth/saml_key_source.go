package federatedauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

const (
	maximumSAMLSPKeyEnvelopeBytes = 128 * 1024
	maximumSAMLSPCertificateBytes = 64 * 1024
	maximumSAMLSPCertificates     = 8
)

// ProtectedSAMLSPKey is an opaque deployment-keyring or KMS envelope. The
// adapter never assumes a wire format and never formats its bytes.
type ProtectedSAMLSPKey struct {
	KeyVersion uint32
	Ciphertext []byte `json:"-"`
}

func (key ProtectedSAMLSPKey) String() string {
	return fmt.Sprintf(
		"federatedauth.ProtectedSAMLSPKey{key_version:%t,ciphertext_bytes:%d,material:[REDACTED]}",
		key.KeyVersion != 0, len(key.Ciphertext),
	)
}
func (key ProtectedSAMLSPKey) GoString() string { return key.String() }

// SAMLSPKeyProtectionContext is authenticated context for one private key
// row. KeyID is a concrete FK target and cannot alias any other secret table.
type SAMLSPKeyProtectionContext struct {
	Provider    identity.ProviderContext
	BindingID   identity.EntityID
	KeyID       identity.EntityID
	KeyRevision uint32
}

func (value SAMLSPKeyProtectionContext) String() string {
	return fmt.Sprintf(
		"federatedauth.SAMLSPKeyProtectionContext{scope:%v,revision:%t,material:[REDACTED]}",
		value.Provider.Scope, value.KeyRevision != 0,
	)
}
func (value SAMLSPKeyProtectionContext) GoString() string { return value.String() }

// SAMLSPKeySnapshot is the immutable database projection selected by the
// requested provider/binding/revision. Load transfers ownership of the
// envelope ciphertext and certificate slices to the adapter.
type SAMLSPKeySnapshot struct {
	Context        SAMLSPKeyProtectionContext
	Envelope       ProtectedSAMLSPKey
	CertificateDER [][]byte
}

func (snapshot SAMLSPKeySnapshot) String() string {
	return fmt.Sprintf(
		"federatedauth.SAMLSPKeySnapshot{context:%q,envelope:%q,certificates:%d,material:[REDACTED]}",
		snapshot.Context.String(), snapshot.Envelope.String(), len(snapshot.CertificateDER),
	)
}
func (snapshot SAMLSPKeySnapshot) GoString() string { return snapshot.String() }

// SAMLSPKeyEnvelopeSource is implemented by a tenant-derived narrow database
// ABI. It returns exactly one active or retained immutable revision.
type SAMLSPKeyEnvelopeSource interface {
	LoadSAMLSPKeyEnvelope(context.Context, federatedsaml.SPKeyRequest) (SAMLSPKeySnapshot, error)
}

// SAMLSPKeyEnvelopeOpener owns the deployment keyring/KMS operation. It must
// authenticate every Context field, return a fresh PKCS#8 DER slice, and keep
// no plaintext or envelope bytes after returning.
type SAMLSPKeyEnvelopeOpener interface {
	OpenSAMLSPKeyEnvelope(context.Context, SAMLSPKeyProtectionContext, ProtectedSAMLSPKey) ([]byte, error)
}

// ProtectedSAMLSPKeySource validates the exact persistence projection, opens
// it outside a database transaction, parses only PKCS#8 RSA/ECDSA keys, and
// proves the first certificate belongs to the private key before returning a
// library crypto artifact.
type ProtectedSAMLSPKeySource struct {
	source SAMLSPKeyEnvelopeSource
	opener SAMLSPKeyEnvelopeOpener
}

func NewProtectedSAMLSPKeySource(
	source SAMLSPKeyEnvelopeSource,
	opener SAMLSPKeyEnvelopeOpener,
) (*ProtectedSAMLSPKeySource, error) {
	if source == nil || opener == nil {
		return nil, ErrInvalidOptions
	}
	return &ProtectedSAMLSPKeySource{source: source, opener: opener}, nil
}

func (source *ProtectedSAMLSPKeySource) String() string {
	return fmt.Sprintf("federatedauth.ProtectedSAMLSPKeySource{configured:%t}",
		source != nil && source.source != nil && source.opener != nil)
}
func (source *ProtectedSAMLSPKeySource) GoString() string { return source.String() }

var _ federatedsaml.SPKeySource = (*ProtectedSAMLSPKeySource)(nil)

func (source *ProtectedSAMLSPKeySource) LoadSAMLSPKey(
	ctx context.Context,
	request federatedsaml.SPKeyRequest,
) (federatedsaml.SPKeyMaterial, error) {
	if source == nil || source.source == nil || source.opener == nil || !activeContext(ctx) ||
		!validSAMLSPKeyRequest(request) {
		return federatedsaml.SPKeyMaterial{}, federatedsaml.ErrSPKeyUnavailable
	}
	snapshot, err := source.source.LoadSAMLSPKeyEnvelope(ctx, request)
	defer clear(snapshot.Envelope.Ciphertext)
	defer clearBytes2D(snapshot.CertificateDER)
	if err != nil || !activeContext(ctx) || !validSAMLSPKeySnapshot(snapshot, request) {
		return federatedsaml.SPKeyMaterial{}, federatedsaml.ErrSPKeyUnavailable
	}
	envelope := ProtectedSAMLSPKey{
		KeyVersion: snapshot.Envelope.KeyVersion,
		Ciphertext: append([]byte(nil), snapshot.Envelope.Ciphertext...),
	}
	plaintext, err := source.opener.OpenSAMLSPKeyEnvelope(ctx, snapshot.Context, envelope)
	clear(envelope.Ciphertext)
	defer clear(plaintext)
	if err != nil || !activeContext(ctx) {
		return federatedsaml.SPKeyMaterial{}, federatedsaml.ErrSPKeyUnavailable
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(plaintext)
	if err != nil {
		return federatedsaml.SPKeyMaterial{}, federatedsaml.ErrSPKeyUnavailable
	}
	signer, decrypter, err := validatedSAMLPrivateKey(privateKey)
	if err != nil || !certificateMatchesSAMLSigner(snapshot.CertificateDER[0], signer) {
		return federatedsaml.SPKeyMaterial{}, federatedsaml.ErrSPKeyUnavailable
	}
	return federatedsaml.SPKeyMaterial{
		Provider: request.Provider, BindingID: request.BindingID, KeyRevision: request.KeyRevision,
		Signer: signer, RSADecrypter: decrypter, CertificateDER: cloneBytes2D(snapshot.CertificateDER),
	}, nil
}

func validSAMLSPKeyRequest(request federatedsaml.SPKeyRequest) bool {
	return validSAMLProviderBindingPersistence(request.Provider, request.BindingID) && request.KeyRevision > 0 &&
		(request.LogoutMaterialID == (identity.EntityID{}) || validApplyUUIDv7(request.LogoutMaterialID))
}

func validSAMLSPKeySnapshot(snapshot SAMLSPKeySnapshot, request federatedsaml.SPKeyRequest) bool {
	if snapshot.Context.Provider != request.Provider || snapshot.Context.BindingID != request.BindingID ||
		snapshot.Context.KeyID == (identity.EntityID{}) || snapshot.Context.KeyRevision != request.KeyRevision ||
		snapshot.Envelope.KeyVersion == 0 || len(snapshot.Envelope.Ciphertext) == 0 ||
		len(snapshot.Envelope.Ciphertext) > maximumSAMLSPKeyEnvelopeBytes || len(snapshot.CertificateDER) == 0 ||
		len(snapshot.CertificateDER) > maximumSAMLSPCertificates {
		return false
	}
	seen := make(map[[sha256.Size]byte]struct{}, len(snapshot.CertificateDER))
	for _, encoded := range snapshot.CertificateDER {
		if len(encoded) == 0 || len(encoded) > maximumSAMLSPCertificateBytes {
			return false
		}
		digest := sha256.Sum256(encoded)
		if _, duplicate := seen[digest]; duplicate {
			return false
		}
		seen[digest] = struct{}{}
		certificate, err := x509.ParseCertificate(encoded)
		if err != nil || certificate.PublicKey == nil {
			return false
		}
	}
	return true
}

func validatedSAMLPrivateKey(value any) (crypto.Signer, *rsa.PrivateKey, error) {
	switch key := value.(type) {
	case *rsa.PrivateKey:
		if key == nil || key.N == nil || key.N.BitLen() < 2048 || key.E < 65537 || key.Validate() != nil {
			return nil, nil, federatedsaml.ErrSPKeyUnavailable
		}
		return key, key, nil
	case *ecdsa.PrivateKey:
		if key == nil || key.Curve == nil || key.D == nil || key.PublicKey.X == nil || key.PublicKey.Y == nil ||
			!validSAMLEllipticCurve(key.Curve) || !key.Curve.IsOnCurve(key.PublicKey.X, key.PublicKey.Y) ||
			key.D.Sign() <= 0 || key.D.Cmp(key.Curve.Params().N) >= 0 {
			return nil, nil, federatedsaml.ErrSPKeyUnavailable
		}
		expectedX, expectedY := key.Curve.ScalarBaseMult(key.D.Bytes())
		if expectedX.Cmp(key.PublicKey.X) != 0 || expectedY.Cmp(key.PublicKey.Y) != 0 {
			return nil, nil, federatedsaml.ErrSPKeyUnavailable
		}
		return key, nil, nil
	default:
		return nil, nil, federatedsaml.ErrSPKeyUnavailable
	}
}

func validSAMLEllipticCurve(curve elliptic.Curve) bool {
	if curve == nil {
		return false
	}
	name := curve.Params().Name
	return name == elliptic.P256().Params().Name || name == elliptic.P384().Params().Name ||
		name == elliptic.P521().Params().Name
}

func certificateMatchesSAMLSigner(encoded []byte, signer crypto.Signer) bool {
	certificate, err := x509.ParseCertificate(encoded)
	if err != nil || signer == nil {
		return false
	}
	certificateKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return false
	}
	signerKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	return err == nil && bytes.Equal(certificateKey, signerKey)
}

func clearBytes2D(values [][]byte) {
	for index := range values {
		clear(values[index])
	}
}

func cloneBytes2D(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = append([]byte(nil), values[index]...)
	}
	return result
}
