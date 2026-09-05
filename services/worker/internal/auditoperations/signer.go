package auditoperations

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"

	"github.com/google/uuid"
)

var signingKeyIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,127}$`)

type Ed25519Signer struct {
	keyID   string
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func LoadEd25519Signer(path, keyID string) (*Ed25519Signer, error) {
	if !signingKeyIDPattern.MatchString(keyID) || path == "" || !filepath.IsAbs(path) ||
		filepath.Clean(path) != path {
		return nil, ErrInvalidConfiguration
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 16*1024 {
		return nil, ErrInvalidConfiguration
	}
	document, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	defer clear(document)
	block, remainder := pem.Decode(document)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(remainder)) != 0 {
		return nil, ErrInvalidConfiguration
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(private) != ed25519.PrivateKeySize {
		return nil, ErrInvalidConfiguration
	}
	key := append(ed25519.PrivateKey(nil), private...)
	public := append(ed25519.PublicKey(nil), key.Public().(ed25519.PublicKey)...)
	return &Ed25519Signer{keyID: keyID, private: key, public: public}, nil
}

func (signer *Ed25519Signer) KeyID() string {
	if signer == nil {
		return ""
	}
	return signer.keyID
}

func (signer *Ed25519Signer) Sign(segment Segment, digest [32]byte, size int64) ([64]byte, error) {
	var result [64]byte
	if signer == nil || len(signer.private) != ed25519.PrivateKeySize ||
		!validSegmentForSignature(segment, digest, size, signer.keyID) {
		return result, ErrInvalidInput
	}
	signature := ed25519.Sign(signer.private, segmentSignaturePayload(segment, digest, size, signer.keyID))
	copy(result[:], signature)
	return result, nil
}

func (signer *Ed25519Signer) Verify(segment Segment, digest [32]byte, size int64, signature [64]byte) bool {
	return signer != nil && len(signer.public) == ed25519.PublicKeySize &&
		validSegmentForSignature(segment, digest, size, signer.keyID) &&
		ed25519.Verify(signer.public, segmentSignaturePayload(segment, digest, size, signer.keyID), signature[:])
}

func (*Ed25519Signer) String() string          { return "auditoperations.Ed25519Signer{[REDACTED]}" }
func (signer *Ed25519Signer) GoString() string { return signer.String() }

func validSegmentForSignature(segment Segment, digest [32]byte, size int64, keyID string) bool {
	return segment.Stream.Valid() && validUUIDv7(segment.ID) &&
		(segment.Stream == PlatformStream && segment.TenantID == uuid.Nil ||
			segment.Stream == TenantStream && validUUIDv7(segment.TenantID)) &&
		segment.Start > 0 && segment.End >= segment.Start && segment.EventCount == segment.End-segment.Start+1 &&
		len(segment.PreviousHash) == 64 && len(segment.EndHash) == 64 &&
		validObjectKey(segment.Stream, segment.TenantID, segment.ObjectKey) && digest != ([32]byte{}) &&
		size > 0 && size <= MaximumArtifactBytes && signingKeyIDPattern.MatchString(keyID)
}

func segmentSignaturePayload(segment Segment, digest [32]byte, size int64, keyID string) []byte {
	buffer := bytes.NewBuffer(make([]byte, 0, 512))
	writeFramed(buffer, []byte("periapsis/audit-retention-segment/v1"))
	writeFramed(buffer, []byte(segment.Stream))
	writeFramed(buffer, segment.TenantID[:])
	writeFramed(buffer, segment.ID[:])
	writeInt64(buffer, segment.Start)
	writeInt64(buffer, segment.End)
	writeInt64(buffer, segment.EventCount)
	writeFramed(buffer, []byte(segment.PreviousHash))
	writeFramed(buffer, []byte(segment.EndHash))
	writeFramed(buffer, []byte(segment.ObjectKey))
	writeFramed(buffer, digest[:])
	writeInt64(buffer, size)
	writeFramed(buffer, []byte(keyID))
	return buffer.Bytes()
}

func writeFramed(buffer *bytes.Buffer, value []byte) {
	_ = binary.Write(buffer, binary.BigEndian, uint32(len(value)))
	_, _ = buffer.Write(value)
}

func writeInt64(buffer *bytes.Buffer, value int64) {
	_ = binary.Write(buffer, binary.BigEndian, value)
}
