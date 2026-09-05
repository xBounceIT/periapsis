package platformsamladapter

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
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

// DirectSAMLSPKeyEnvelopeSnapshot is one immutable platform SP-key row. The
// semantic KeyRevision is uint64 and selects/authenticates the row; the
// envelope KeyVersion is the independent int16 identity-root-key version.
// PlatformLoginRevision is an exact live-authority lookup pin, while the
// purpose-separated keyring AAD intentionally consists only of Provider,
// KeyID, KeyRevision, envelope version, and direct-platform SP-key purpose.
type DirectSAMLSPKeyEnvelopeSnapshot struct {
	Request               federatedsaml.DirectPlatformSPKeyRequest
	PlatformLoginRevision uint64
	Context               identity.DirectPlatformSAMLSPKeyContext
	Envelope              identity.SAMLSPKeyEnvelope `json:"-"`
	CertificateDER        [][]byte                   `json:"-"`
	Live                  bool
}

func (snapshot DirectSAMLSPKeyEnvelopeSnapshot) String() string {
	return fmt.Sprintf(
		"platformsamladapter.DirectSAMLSPKeyEnvelopeSnapshot{request:%q,loginRevision:%t,keyRevision:%t,envelopeVersion:%t,certificates:%d,live:%t,material:[REDACTED]}",
		snapshot.Request.String(), snapshot.PlatformLoginRevision != 0, snapshot.Context.KeyRevision != 0,
		snapshot.Envelope.KeyVersion > 0, len(snapshot.CertificateDER), snapshot.Live,
	)
}

func (snapshot DirectSAMLSPKeyEnvelopeSnapshot) GoString() string { return snapshot.String() }

type DirectSAMLSPKeyEnvelopeRepository interface {
	// Returned nonce, ciphertext, and certificate buffers transfer to the
	// caller and are cleared before LoadDirectPlatformSAMLSPKey returns.
	LoadDirectPlatformSAMLSPKeyEnvelope(context.Context, federatedsaml.DirectPlatformSPKeyRequest) (DirectSAMLSPKeyEnvelopeSnapshot, error)
}

type ProtectedDirectSAMLSPKeySourceOptions struct {
	Repository DirectSAMLSPKeyEnvelopeRepository
	Keyring    identity.Keyring
	Now        func() time.Time
}

// ProtectedDirectSAMLSPKeySource is deliberately only a
// federatedsaml.DirectPlatformSPKeySource. It cannot satisfy the tenant key
// source interface and therefore cannot provide a cross-authority fallback.
type ProtectedDirectSAMLSPKeySource struct {
	repository DirectSAMLSPKeyEnvelopeRepository
	keyring    identity.Keyring
	now        func() time.Time
}

// ValidateSAMLSPKeyBundle applies the fail-closed key and certificate checks
// shared by tenant-owned and direct-platform administration. It validates
// only the material; the caller remains responsible for selecting the
// authority-specific encryption context and for clearing every input buffer.
func ValidateSAMLSPKeyBundle(pkcs8 []byte, certificates [][]byte, observedAt time.Time) error {
	if len(pkcs8) == 0 || len(pkcs8) > maximumEnvelopeBytes-16 || len(certificates) == 0 ||
		len(certificates) > 8 || !validInstant(observedAt) {
		return ErrProtocolRejected
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return ErrProtocolRejected
	}
	signer, _, ok := validatedDirectSAMLPrivateKey(privateKey)
	if !ok || !allCertificatesMatchSigner(certificates, signer) {
		return ErrProtocolRejected
	}
	seen := make(map[[sha256.Size]byte]struct{}, len(certificates))
	for _, encoded := range certificates {
		if len(encoded) == 0 || len(encoded) > maximumCertificateBytes {
			return ErrProtocolRejected
		}
		digest := sha256.Sum256(encoded)
		if _, duplicate := seen[digest]; duplicate {
			return ErrProtocolRejected
		}
		seen[digest] = struct{}{}
		certificate, err := x509.ParseCertificate(encoded)
		if err != nil || certificate.PublicKey == nil || observedAt.Before(certificate.NotBefore.UTC()) ||
			!observedAt.Before(certificate.NotAfter.UTC()) {
			return ErrProtocolRejected
		}
	}
	return nil
}

// ValidateDirectSAMLSPKeyBundle is retained for the direct-platform
// administration ABI. The validation rules are intentionally shared, while
// encryption and AAD remain disjoint at the caller boundary.
func ValidateDirectSAMLSPKeyBundle(pkcs8 []byte, certificates [][]byte, observedAt time.Time) error {
	return ValidateSAMLSPKeyBundle(pkcs8, certificates, observedAt)
}

func NewProtectedDirectSAMLSPKeySource(
	options ProtectedDirectSAMLSPKeySourceOptions,
) (*ProtectedDirectSAMLSPKeySource, error) {
	if options.Repository == nil || options.Keyring.ActiveVersion() < 1 || options.Now == nil {
		return nil, ErrInvalidOptions
	}
	return &ProtectedDirectSAMLSPKeySource{
		repository: options.Repository, keyring: options.Keyring, now: options.Now,
	}, nil
}

func (source *ProtectedDirectSAMLSPKeySource) String() string {
	return fmt.Sprintf(
		"platformsamladapter.ProtectedDirectSAMLSPKeySource{authority:direct_platform,configured:%t,material:[REDACTED]}",
		source != nil && source.repository != nil && source.keyring.ActiveVersion() > 0,
	)
}

func (source *ProtectedDirectSAMLSPKeySource) GoString() string { return source.String() }

func (source *ProtectedDirectSAMLSPKeySource) LoadDirectPlatformSAMLSPKey(
	ctx context.Context,
	request federatedsaml.DirectPlatformSPKeyRequest,
) (federatedsaml.DirectPlatformSPKeyMaterial, error) {
	if source == nil || source.repository == nil || source.keyring.ActiveVersion() < 1 || !activeContext(ctx) ||
		!validDirectSPKeyRequest(request) {
		return federatedsaml.DirectPlatformSPKeyMaterial{}, federatedsaml.ErrSPKeyUnavailable
	}
	now, ok := canonicalNow(source.now)
	if !ok {
		return federatedsaml.DirectPlatformSPKeyMaterial{}, federatedsaml.ErrSPKeyUnavailable
	}
	snapshot, err := source.repository.LoadDirectPlatformSAMLSPKeyEnvelope(ctx, request)
	defer clearDirectSPKeySnapshot(&snapshot)
	if err != nil || !activeContext(ctx) || !validDirectSPKeySnapshot(snapshot, request, now) {
		return federatedsaml.DirectPlatformSPKeyMaterial{}, federatedsaml.ErrSPKeyUnavailable
	}
	envelope := identity.SAMLSPKeyEnvelope{
		KeyVersion: snapshot.Envelope.KeyVersion,
		Nonce:      snapshot.Envelope.Nonce,
		Ciphertext: append([]byte(nil), snapshot.Envelope.Ciphertext...),
	}
	defer clear(envelope.Nonce[:])
	defer clear(envelope.Ciphertext)
	plaintext, err := source.keyring.DecryptDirectPlatformSAMLSPKey(snapshot.Context, envelope)
	defer clear(plaintext)
	if err != nil || !activeContext(ctx) {
		return federatedsaml.DirectPlatformSPKeyMaterial{}, federatedsaml.ErrSPKeyUnavailable
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(plaintext)
	if err != nil {
		return federatedsaml.DirectPlatformSPKeyMaterial{}, federatedsaml.ErrSPKeyUnavailable
	}
	signer, decrypter, ok := validatedDirectSAMLPrivateKey(privateKey)
	if !ok || !allCertificatesMatchSigner(snapshot.CertificateDER, signer) {
		return federatedsaml.DirectPlatformSPKeyMaterial{}, federatedsaml.ErrSPKeyUnavailable
	}
	return federatedsaml.DirectPlatformSPKeyMaterial{
		Context: snapshot.Context, Signer: signer, RSADecrypter: decrypter,
		CertificateDER: cloneBytes2D(snapshot.CertificateDER),
	}, nil
}

func allCertificatesMatchSigner(certificates [][]byte, signer crypto.Signer) bool {
	if len(certificates) == 0 || signer == nil {
		return false
	}
	for _, certificate := range certificates {
		if !certificateMatchesSigner(certificate, signer) {
			return false
		}
	}
	return true
}

func validDirectSPKeyRequest(request federatedsaml.DirectPlatformSPKeyRequest) bool {
	return validDirectProvider(request.Provider) && validRevision(request.PlatformLoginRevision) &&
		validRevision(request.KeyRevision) &&
		(request.LogoutMaterialID == (identity.EntityID{}) || validUUIDv7(request.LogoutMaterialID))
}

func validDirectSPKeySnapshot(
	snapshot DirectSAMLSPKeyEnvelopeSnapshot,
	request federatedsaml.DirectPlatformSPKeyRequest,
	now time.Time,
) bool {
	if snapshot.Request != request || snapshot.PlatformLoginRevision != request.PlatformLoginRevision ||
		snapshot.Context.Provider != request.Provider || !validUUIDv7(snapshot.Context.KeyID) ||
		snapshot.Context.KeyRevision != request.KeyRevision || !snapshot.Live ||
		snapshot.Envelope.KeyVersion < 1 || snapshot.Envelope.Nonce == ([12]byte{}) ||
		len(snapshot.Envelope.Ciphertext) <= 16 || len(snapshot.Envelope.Ciphertext) > maximumEnvelopeBytes ||
		len(snapshot.CertificateDER) == 0 || len(snapshot.CertificateDER) > 8 || !validInstant(now) {
		return false
	}
	seen := make(map[[sha256.Size]byte]struct{}, len(snapshot.CertificateDER))
	for _, encoded := range snapshot.CertificateDER {
		if len(encoded) == 0 || len(encoded) > maximumCertificateBytes {
			return false
		}
		digest := sha256.Sum256(encoded)
		if _, duplicate := seen[digest]; duplicate {
			return false
		}
		seen[digest] = struct{}{}
		certificate, err := x509.ParseCertificate(encoded)
		// Interactive ceremonies require a currently valid certificate. A
		// database-attested stored logout must keep using its exact session-time
		// signing revision after rotation or certificate expiry; the Redirect
		// binding carries only the signature, not a newly asserted certificate.
		if err != nil || certificate.PublicKey == nil ||
			(!validUUIDv7(request.LogoutMaterialID) &&
				(now.Before(certificate.NotBefore.UTC()) || !now.Before(certificate.NotAfter.UTC()))) {
			return false
		}
	}
	return true
}

func validatedDirectSAMLPrivateKey(value any) (crypto.Signer, *rsa.PrivateKey, bool) {
	switch key := value.(type) {
	case *rsa.PrivateKey:
		if key == nil || key.N == nil || key.N.BitLen() < 2048 || key.E < 65537 || key.D == nil ||
			len(key.Primes) < 2 || key.Validate() != nil {
			return nil, nil, false
		}
		return key, key, true
	case *ecdsa.PrivateKey:
		if key == nil || key.Curve == nil || key.D == nil || key.PublicKey.X == nil || key.PublicKey.Y == nil ||
			!validDirectSAMLCurve(key.Curve) || !key.Curve.IsOnCurve(key.PublicKey.X, key.PublicKey.Y) ||
			key.D.Sign() <= 0 || key.D.Cmp(key.Curve.Params().N) >= 0 {
			return nil, nil, false
		}
		expectedX, expectedY := key.Curve.ScalarBaseMult(key.D.Bytes())
		if expectedX.Cmp(key.PublicKey.X) != 0 || expectedY.Cmp(key.PublicKey.Y) != 0 {
			return nil, nil, false
		}
		return key, nil, true
	default:
		return nil, nil, false
	}
}

func validDirectSAMLCurve(curve elliptic.Curve) bool {
	if curve == nil || curve.Params() == nil {
		return false
	}
	name := curve.Params().Name
	return name == elliptic.P256().Params().Name || name == elliptic.P384().Params().Name ||
		name == elliptic.P521().Params().Name
}

func certificateMatchesSigner(encoded []byte, signer crypto.Signer) bool {
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

func cloneBytes2D(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = append([]byte(nil), values[index]...)
	}
	return result
}

func clearBytes2D(values [][]byte) {
	for index := range values {
		clear(values[index])
	}
}

func clearDirectSPKeySnapshot(snapshot *DirectSAMLSPKeyEnvelopeSnapshot) {
	if snapshot == nil {
		return
	}
	clear(snapshot.Envelope.Nonce[:])
	clear(snapshot.Envelope.Ciphertext)
	clearBytes2D(snapshot.CertificateDER)
	*snapshot = DirectSAMLSPKeyEnvelopeSnapshot{}
}

var _ federatedsaml.DirectPlatformSPKeySource = (*ProtectedDirectSAMLSPKeySource)(nil)
