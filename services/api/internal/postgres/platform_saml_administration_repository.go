package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

const (
	maximumPlatformSAMLMetadataAdminProjectionBytes = 1024 * 1024
	maximumPlatformSAMLMetadataDocumentBytes        = 512 * 1024
	maximumPlatformSAMLSPKeyCiphertextBytes         = 128 * 1024
	maximumPlatformSAMLCertificateBytes             = 64 * 1024
	platformSAMLAdministrationTimestampLayout       = "2006-01-02T15:04:05.000000Z"
)

var _ platformidentityprovider.SAMLAdministrationRepository = (*PlatformIdentityProviderRepository)(nil)

type platformSAMLMetadataAdminWire struct {
	ProviderID        uuid.UUID `json:"providerId"`
	ProviderVersion   int64     `json:"providerVersion"`
	MetadataRevision  int64     `json:"metadataRevision"`
	Document          []byte    `json:"document"`
	Digest            []byte    `json:"digest"`
	RetrievedAt       string    `json:"retrievedAt"`
	MaximumValidUntil string    `json:"maximumValidUntil"`
}

func (repository *PlatformIdentityProviderRepository) LoadSAMLMetadataAdmin(
	ctx context.Context,
	params platformidentityprovider.LoadSAMLMetadataAdminParams,
) (platformidentityprovider.SAMLMetadataAdminSnapshot, error) {
	if !platformIdentityProviderUUIDv7(params.ProviderID) {
		return platformidentityprovider.SAMLMetadataAdminSnapshot{}, authentication.ErrInvalidInput
	}
	return withPlatformIdentityProviderTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityprovider.SAMLMetadataAdminSnapshot, error) {
			document, err := queries.LoadPlatformSAMLMetadataAdmin(ctx, dbsql.LoadPlatformSAMLMetadataAdminParams{
				SessionID:            toDatabaseUUID(params.SessionID),
				ProviderID:           toDatabaseUUID(params.ProviderID),
				AuthenticationMethod: params.AuthenticationMethod,
			})
			if err != nil {
				return platformidentityprovider.SAMLMetadataAdminSnapshot{}, err
			}
			return decodePlatformSAMLMetadataAdmin(document)
		},
	)
}

func (repository *PlatformIdentityProviderRepository) ReplaceSAMLMetadata(
	ctx context.Context,
	params platformidentityprovider.ReplaceSAMLMetadataParams,
) (platformidentityprovider.SAMLMaterialMutationReceipt, error) {
	if !validPlatformIdentityProviderMutation(
		params.SessionParams, params.ProviderID, params.ExpectedVersion, params.Reason, params.Event,
	) || len(params.Document) < 1 || len(params.Document) > maximumPlatformSAMLMetadataDocumentBytes ||
		params.Digest == ([sha256.Size]byte{}) || sha256.Sum256(params.Document) != params.Digest ||
		!validPlatformSAMLAdministrationInstant(params.RetrievedAt) ||
		!validPlatformSAMLAdministrationInstant(params.MaximumValidUntil) ||
		!params.MaximumValidUntil.After(params.RetrievedAt) {
		return platformidentityprovider.SAMLMaterialMutationReceipt{}, authentication.ErrInvalidInput
	}
	event, err := eventArguments(params.Event)
	if err != nil {
		return platformidentityprovider.SAMLMaterialMutationReceipt{}, authentication.ErrInvalidInput
	}
	auditID, err := platformIdentityProviderAuditID(repository)
	if err != nil {
		return platformidentityprovider.SAMLMaterialMutationReceipt{}, err
	}
	document := append([]byte(nil), params.Document...)
	digest := append([]byte(nil), params.Digest[:]...)
	defer clear(document)
	defer clear(digest)

	return withPlatformIdentityProviderTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityprovider.SAMLMaterialMutationReceipt, error) {
			row, queryErr := queries.ReplacePlatformSAMLMetadata(ctx, dbsql.ReplacePlatformSAMLMetadataParams{
				SessionID:            toDatabaseUUID(params.SessionID),
				ProviderID:           toDatabaseUUID(params.ProviderID),
				ExpectedVersion:      params.ExpectedVersion,
				Document:             document,
				DocumentDigest:       digest,
				RetrievedAt:          databaseTime(params.RetrievedAt),
				MaximumValidUntil:    databaseTime(params.MaximumValidUntil),
				ProtectedApproval:    params.ProtectedApproval,
				AuditEventID:         toDatabaseUUID(auditID),
				RequestID:            event.requestID,
				CorrelationID:        event.correlationID,
				IpAddress:            params.Event.RemoteAddress.Unmap(),
				UserAgent:            params.Event.UserAgent,
				AuthenticationMethod: params.AuthenticationMethod,
				Reason:               params.Reason,
			})
			if queryErr != nil {
				return platformidentityprovider.SAMLMaterialMutationReceipt{}, queryErr
			}
			return restorePlatformSAMLMaterialMutationReceipt(params.ProviderID, params.ExpectedVersion, row.Version, row.MaterialRevision)
		},
	)
}

func (repository *PlatformIdentityProviderRepository) ReplaceSAMLSPKey(
	ctx context.Context,
	params platformidentityprovider.ReplaceSAMLSPKeyParams,
) (platformidentityprovider.SAMLMaterialMutationReceipt, error) {
	if !validPlatformIdentityProviderMutation(
		params.SessionParams, params.ProviderID, params.ExpectedVersion, params.Reason, params.Event,
	) || !platformIdentityProviderUUIDv7(params.Key.KeyID) ||
		params.Key.KeyRevision < 2 || !validPlatformSAMLRevision(uint64(params.Key.KeyRevision)) ||
		params.Key.Envelope.KeyVersion < 1 || len(params.Key.Envelope.Ciphertext) < 17 ||
		len(params.Key.Envelope.Ciphertext) > maximumPlatformSAMLSPKeyCiphertextBytes ||
		!validPlatformSAMLCertificates(params.Key.CertificateDER) ||
		!validPlatformSAMLCertificateValidity(params.Key.CertificateDER, params.Key.CertificateValidity) {
		return platformidentityprovider.SAMLMaterialMutationReceipt{}, authentication.ErrInvalidInput
	}
	event, err := eventArguments(params.Event)
	if err != nil {
		return platformidentityprovider.SAMLMaterialMutationReceipt{}, authentication.ErrInvalidInput
	}
	auditID, err := platformIdentityProviderAuditID(repository)
	if err != nil {
		return platformidentityprovider.SAMLMaterialMutationReceipt{}, err
	}
	nonce := append([]byte(nil), params.Key.Envelope.Nonce[:]...)
	ciphertext := append([]byte(nil), params.Key.Envelope.Ciphertext...)
	certificates, ok := encodePlatformSAMLCertificateRecords(
		params.Key.CertificateDER, params.Key.CertificateValidity,
	)
	if !ok {
		return platformidentityprovider.SAMLMaterialMutationReceipt{}, authentication.ErrInvalidInput
	}
	defer clear(nonce)
	defer clear(ciphertext)
	defer clearPlatformSAMLCertificates(certificates)

	return withPlatformIdentityProviderTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityprovider.SAMLMaterialMutationReceipt, error) {
			row, queryErr := queries.ReplacePlatformSAMLSPKey(ctx, dbsql.ReplacePlatformSAMLSPKeyParams{
				SessionID:            toDatabaseUUID(params.SessionID),
				ProviderID:           toDatabaseUUID(params.ProviderID),
				KeyID:                toDatabaseUUID(params.Key.KeyID),
				ExpectedVersion:      params.ExpectedVersion,
				KeyVersion:           int32(params.Key.Envelope.KeyVersion),
				Nonce:                nonce,
				Ciphertext:           ciphertext,
				Certificates:         certificates,
				AuditEventID:         toDatabaseUUID(auditID),
				RequestID:            event.requestID,
				CorrelationID:        event.correlationID,
				IpAddress:            params.Event.RemoteAddress.Unmap(),
				UserAgent:            params.Event.UserAgent,
				AuthenticationMethod: params.AuthenticationMethod,
				Reason:               params.Reason,
			})
			if queryErr != nil {
				return platformidentityprovider.SAMLMaterialMutationReceipt{}, queryErr
			}
			if row.MaterialRevision != params.Key.KeyRevision {
				return platformidentityprovider.SAMLMaterialMutationReceipt{}, authentication.ErrUnavailable
			}
			return restorePlatformSAMLMaterialMutationReceipt(params.ProviderID, params.ExpectedVersion, row.Version, row.MaterialRevision)
		},
	)
}

type platformSAMLCertificateRecord struct {
	DER       []byte    `json:"der"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
}

func validPlatformSAMLCertificateValidity(
	certificateDER [][]byte,
	validity []platformidentityprovider.SAMLCertificateValidity,
) bool {
	if len(certificateDER) != len(validity) || len(validity) == 0 {
		return false
	}
	for index, der := range certificateDER {
		certificate, err := x509.ParseCertificate(der)
		if err != nil || !bytes.Equal(certificate.Raw, der) ||
			!certificate.NotBefore.Equal(validity[index].NotBefore) ||
			!certificate.NotAfter.Equal(validity[index].NotAfter) ||
			!validPlatformSAMLAdministrationInstant(validity[index].NotBefore) ||
			!validPlatformSAMLAdministrationInstant(validity[index].NotAfter) ||
			!validity[index].NotAfter.After(validity[index].NotBefore) {
			return false
		}
	}
	return true
}

func encodePlatformSAMLCertificateRecords(
	certificateDER [][]byte,
	validity []platformidentityprovider.SAMLCertificateValidity,
) ([][]byte, bool) {
	if !validPlatformSAMLCertificateValidity(certificateDER, validity) {
		return nil, false
	}
	result := make([][]byte, len(certificateDER))
	for index, der := range certificateDER {
		document, err := json.Marshal(platformSAMLCertificateRecord{
			DER: der, NotBefore: validity[index].NotBefore, NotAfter: validity[index].NotAfter,
		})
		if err != nil || len(document) > maximumPlatformSAMLCertificateBytes*2 {
			clearPlatformSAMLCertificates(result)
			return nil, false
		}
		result[index] = document
	}
	return result, true
}

func (repository *PlatformIdentityProviderRepository) ClearSAMLSPKey(
	ctx context.Context,
	params platformidentityprovider.ClearSAMLSPKeyParams,
) (platformidentityprovider.SAMLMaterialMutationReceipt, error) {
	if !validPlatformIdentityProviderMutation(
		params.SessionParams, params.ProviderID, params.ExpectedVersion, params.Reason, params.Event,
	) {
		return platformidentityprovider.SAMLMaterialMutationReceipt{}, authentication.ErrInvalidInput
	}
	event, err := eventArguments(params.Event)
	if err != nil {
		return platformidentityprovider.SAMLMaterialMutationReceipt{}, authentication.ErrInvalidInput
	}
	auditID, err := platformIdentityProviderAuditID(repository)
	if err != nil {
		return platformidentityprovider.SAMLMaterialMutationReceipt{}, err
	}
	return withPlatformIdentityProviderTransaction(
		ctx, repository, params.SessionParams,
		func(queries *dbsql.Queries) (platformidentityprovider.SAMLMaterialMutationReceipt, error) {
			row, queryErr := queries.ClearPlatformSAMLSPKey(ctx, dbsql.ClearPlatformSAMLSPKeyParams{
				SessionID:            toDatabaseUUID(params.SessionID),
				ProviderID:           toDatabaseUUID(params.ProviderID),
				ExpectedVersion:      params.ExpectedVersion,
				AuditEventID:         toDatabaseUUID(auditID),
				RequestID:            event.requestID,
				CorrelationID:        event.correlationID,
				IpAddress:            params.Event.RemoteAddress.Unmap(),
				UserAgent:            params.Event.UserAgent,
				AuthenticationMethod: params.AuthenticationMethod,
				Reason:               params.Reason,
			})
			if queryErr != nil {
				return platformidentityprovider.SAMLMaterialMutationReceipt{}, queryErr
			}
			return restorePlatformSAMLMaterialMutationReceipt(params.ProviderID, params.ExpectedVersion, row.Version, row.MaterialRevision)
		},
	)
}

func decodePlatformSAMLMetadataAdmin(document []byte) (platformidentityprovider.SAMLMetadataAdminSnapshot, error) {
	trimmed := bytes.TrimSpace(document)
	if len(trimmed) < 2 || len(trimmed) > maximumPlatformSAMLMetadataAdminProjectionBytes || trimmed[0] != '{' {
		return platformidentityprovider.SAMLMetadataAdminSnapshot{}, authentication.ErrUnavailable
	}
	var wire platformSAMLMetadataAdminWire
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return platformidentityprovider.SAMLMetadataAdminSnapshot{}, authentication.ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return platformidentityprovider.SAMLMetadataAdminSnapshot{}, authentication.ErrUnavailable
	}
	retrievedAt, retrievedErr := parsePlatformSAMLAdministrationInstant(wire.RetrievedAt)
	maximumValidUntil, maximumErr := parsePlatformSAMLAdministrationInstant(wire.MaximumValidUntil)
	if retrievedErr != nil || maximumErr != nil || !platformIdentityProviderUUIDv7(wire.ProviderID) ||
		wire.ProviderVersion < 1 || !validPlatformSAMLRevision(uint64(wire.ProviderVersion)) ||
		wire.MetadataRevision < 1 || !validPlatformSAMLRevision(uint64(wire.MetadataRevision)) ||
		len(wire.Document) < 1 || len(wire.Document) > maximumPlatformSAMLMetadataDocumentBytes ||
		len(wire.Digest) != sha256.Size || !maximumValidUntil.After(retrievedAt) ||
		sha256.Sum256(wire.Document) != [sha256.Size]byte(wire.Digest) {
		clear(wire.Document)
		clear(wire.Digest)
		return platformidentityprovider.SAMLMetadataAdminSnapshot{}, authentication.ErrUnavailable
	}
	var digest [sha256.Size]byte
	copy(digest[:], wire.Digest)
	clear(wire.Digest)
	return platformidentityprovider.SAMLMetadataAdminSnapshot{
		ProviderID: wire.ProviderID, ProviderVersion: wire.ProviderVersion,
		MetadataRevision: wire.MetadataRevision, Document: wire.Document, Digest: digest,
		RetrievedAt: retrievedAt, MaximumValidUntil: maximumValidUntil,
	}, nil
}

func restorePlatformSAMLMaterialMutationReceipt(
	providerID uuid.UUID,
	expectedVersion int64,
	version int64,
	materialRevision int64,
) (platformidentityprovider.SAMLMaterialMutationReceipt, error) {
	receipt, err := platformidentityprovider.RestoreSAMLMaterialMutationReceipt(
		platformidentityprovider.SAMLMaterialMutationReceiptInput{
			ProviderID: providerID, Version: version, MaterialRevision: materialRevision,
		},
	)
	if err != nil || version != expectedVersion+1 {
		return platformidentityprovider.SAMLMaterialMutationReceipt{}, authentication.ErrUnavailable
	}
	return receipt, nil
}

func validPlatformSAMLAdministrationInstant(value time.Time) bool {
	return validPlatformSAMLInstant(value) && value == value.UTC()
}

func parsePlatformSAMLAdministrationInstant(value string) (time.Time, error) {
	parsed, err := time.Parse(platformSAMLAdministrationTimestampLayout, value)
	if err != nil || !validPlatformSAMLAdministrationInstant(parsed) || parsed.Format(platformSAMLAdministrationTimestampLayout) != value {
		return time.Time{}, authentication.ErrUnavailable
	}
	return parsed, nil
}

func validPlatformSAMLCertificates(certificates [][]byte) bool {
	if len(certificates) < 1 || len(certificates) > 8 {
		return false
	}
	seen := make(map[string]struct{}, len(certificates))
	for _, certificate := range certificates {
		if len(certificate) < 1 || len(certificate) > maximumPlatformSAMLCertificateBytes {
			return false
		}
		key := string(certificate)
		if _, exists := seen[key]; exists {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

func clonePlatformSAMLCertificates(certificates [][]byte) [][]byte {
	result := make([][]byte, len(certificates))
	for index := range certificates {
		result[index] = append([]byte(nil), certificates[index]...)
	}
	return result
}

func clearPlatformSAMLCertificates(certificates [][]byte) {
	for index := range certificates {
		clear(certificates[index])
	}
	clear(certificates)
}
