package dfir

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

type StorageObjectInput struct {
	ID                EntityID
	TenantID          EntityID
	Bucket            string
	ObjectKey         string
	OriginalFilename  string
	Classification    EvidenceClassification
	ExpectedSizeBytes int64
	UploadExpiresAt   time.Time
	CreatedBy         EntityID
	CreatedAt         time.Time
}

type StorageObject struct {
	id                EntityID
	tenantID          EntityID
	bucket            string
	objectKey         string
	originalFilename  string
	classification    EvidenceClassification
	expectedSizeBytes int64
	uploadExpiresAt   time.Time
	createdBy         EntityID
	createdAt         time.Time
	updatedAt         time.Time
	state             ScanState
	contentSHA256     string
	sizeBytes         int64
	detectedMIME      string
	verifiedAt        *time.Time
	retentionUntil    *time.Time
	legalHold         bool
	version           uint64
}

// StorageObjectState is the complete persistence representation needed to
// restore the aggregate without replaying external object-store operations.
// Its formatting is deliberately redacted because location and filename are
// customer data.
type StorageObjectState struct {
	ID                EntityID
	TenantID          EntityID
	Bucket            string
	ObjectKey         string
	OriginalFilename  string
	Classification    EvidenceClassification
	ExpectedSizeBytes int64
	UploadExpiresAt   time.Time
	CreatedBy         EntityID
	CreatedAt         time.Time
	UpdatedAt         time.Time
	State             ScanState
	ContentSHA256     string
	SizeBytes         int64
	DetectedMIME      string
	VerifiedAt        *time.Time
	RetentionUntil    *time.Time
	LegalHold         bool
	Version           uint64
}

func (state StorageObjectState) String() string {
	return fmt.Sprintf(
		"dfir.StorageObjectState{state:%s,classification:%s,version:%d,location:[REDACTED],filename:[REDACTED],hash:[REDACTED]}",
		state.State, state.Classification, state.Version,
	)
}

func (state StorageObjectState) GoString() string { return state.String() }

func NewStorageObject(input StorageObjectInput) (StorageObject, error) {
	if !validEntityID(input.ID) || !validEntityID(input.TenantID) || !validBucketName(input.Bucket) ||
		!validTenantObjectKey(input.ObjectKey, input.TenantID) || !validOriginalFilename(input.OriginalFilename) ||
		!validEvidenceClassification(input.Classification) || !validEntityID(input.CreatedBy) ||
		!validInstant(input.CreatedAt) || input.ExpectedSizeBytes <= 0 ||
		input.ExpectedSizeBytes > maximumStorageObjectBytes || !validInstant(input.UploadExpiresAt) ||
		!input.UploadExpiresAt.After(input.CreatedAt) || input.UploadExpiresAt.After(input.CreatedAt.Add(time.Hour)) {
		return StorageObject{}, ErrInvalidStorageObject
	}
	return StorageObject{
		id: input.ID, tenantID: input.TenantID, bucket: input.Bucket,
		objectKey: input.ObjectKey, originalFilename: input.OriginalFilename,
		classification: input.Classification, createdBy: input.CreatedBy,
		expectedSizeBytes: input.ExpectedSizeBytes, uploadExpiresAt: input.UploadExpiresAt,
		createdAt: input.CreatedAt, updatedAt: input.CreatedAt,
		state: ScanPendingUpload, version: 1,
	}, nil
}

func RestoreStorageObject(state StorageObjectState) (StorageObject, error) {
	verifiedAt, verifiedOK := canonicalOptionalInstant(state.VerifiedAt)
	retentionUntil, retentionOK := canonicalOptionalInstant(state.RetentionUntil)
	if !verifiedOK || !retentionOK {
		return StorageObject{}, ErrInvalidStorageObject
	}
	object := StorageObject{
		id: state.ID, tenantID: state.TenantID, bucket: state.Bucket,
		objectKey: state.ObjectKey, originalFilename: state.OriginalFilename,
		classification: state.Classification, createdBy: state.CreatedBy,
		expectedSizeBytes: state.ExpectedSizeBytes, uploadExpiresAt: state.UploadExpiresAt,
		createdAt: state.CreatedAt, updatedAt: state.UpdatedAt, state: state.State,
		contentSHA256: state.ContentSHA256, sizeBytes: state.SizeBytes,
		detectedMIME: state.DetectedMIME, verifiedAt: verifiedAt,
		retentionUntil: retentionUntil, legalHold: state.LegalHold, version: state.Version,
	}
	if !object.valid() {
		return StorageObject{}, ErrInvalidStorageObject
	}
	return object, nil
}

func (object StorageObject) ID() EntityID                           { return object.id }
func (object StorageObject) TenantID() EntityID                     { return object.tenantID }
func (object StorageObject) Bucket() string                         { return object.bucket }
func (object StorageObject) ObjectKey() string                      { return object.objectKey }
func (object StorageObject) OriginalFilename() string               { return object.originalFilename }
func (object StorageObject) Classification() EvidenceClassification { return object.classification }
func (object StorageObject) ExpectedSizeBytes() int64               { return object.expectedSizeBytes }
func (object StorageObject) UploadExpiresAt() time.Time             { return object.uploadExpiresAt }
func (object StorageObject) CreatedBy() EntityID                    { return object.createdBy }
func (object StorageObject) CreatedAt() time.Time                   { return object.createdAt }
func (object StorageObject) UpdatedAt() time.Time                   { return object.updatedAt }
func (object StorageObject) State() ScanState                       { return object.state }
func (object StorageObject) ContentSHA256() string                  { return object.contentSHA256 }
func (object StorageObject) SizeBytes() int64                       { return object.sizeBytes }
func (object StorageObject) DetectedMIME() string                   { return object.detectedMIME }
func (object StorageObject) VerifiedAt() *time.Time                 { return cloneInstant(object.verifiedAt) }
func (object StorageObject) RetentionUntil() *time.Time             { return cloneInstant(object.retentionUntil) }
func (object StorageObject) LegalHold() bool                        { return object.legalHold }
func (object StorageObject) Version() uint64                        { return object.version }
func (object StorageObject) Snapshot() StorageObjectState {
	return StorageObjectState{
		ID: object.id, TenantID: object.tenantID, Bucket: object.bucket,
		ObjectKey: object.objectKey, OriginalFilename: object.originalFilename,
		Classification: object.classification, CreatedBy: object.createdBy,
		ExpectedSizeBytes: object.expectedSizeBytes, UploadExpiresAt: object.uploadExpiresAt,
		CreatedAt: object.createdAt, UpdatedAt: object.updatedAt, State: object.state,
		ContentSHA256: object.contentSHA256, SizeBytes: object.sizeBytes,
		DetectedMIME: object.detectedMIME, VerifiedAt: cloneInstant(object.verifiedAt),
		RetentionUntil: cloneInstant(object.retentionUntil), LegalHold: object.legalHold,
		Version: object.version,
	}
}
func (object StorageObject) CanIssueDownload() bool {
	return object.state == ScanAvailable && object.valid()
}
func (object StorageObject) String() string {
	return fmt.Sprintf(
		"dfir.StorageObject{state:%s,classification:%s,version:%d,verified:%t,legalHold:%t,location:[REDACTED],filename:[REDACTED],hash:[REDACTED]}",
		object.state, object.classification, object.version, object.verifiedAt != nil, object.legalHold,
	)
}
func (object StorageObject) GoString() string { return object.String() }

func (object StorageObject) MarkUploaded(expectedVersion uint64, at time.Time) (StorageObject, error) {
	return object.advance(expectedVersion, ScanUploaded, at)
}

func (object StorageObject) BeginVerification(expectedVersion uint64, at time.Time) (StorageObject, error) {
	return object.advance(expectedVersion, ScanVerifying, at)
}

func (object StorageObject) CompleteVerification(
	expectedVersion uint64,
	contentSHA256 string,
	sizeBytes int64,
	detectedMIME string,
	at time.Time,
) (StorageObject, error) {
	if err := object.requireExpectedVersion(expectedVersion); err != nil {
		return StorageObject{}, err
	}
	digest, digestErr := normalizeHexDigest(contentSHA256, 32)
	mediaType, mimeErr := normalizeMediaType(detectedMIME)
	if object.state != ScanVerifying || digestErr != nil || sizeBytes != object.expectedSizeBytes ||
		sizeBytes <= 0 || sizeBytes > maximumStorageObjectBytes || mimeErr != nil ||
		!validInstant(at) || at.Before(object.updatedAt) {
		return StorageObject{}, ErrInvalidStorageObject
	}
	updated := object.clone()
	updated.state = ScanQuarantined
	updated.contentSHA256 = digest
	updated.sizeBytes = sizeBytes
	updated.detectedMIME = mediaType
	updated.verifiedAt = cloneInstant(&at)
	updated.updatedAt = at
	updated.version++
	return updated, nil
}

func (object StorageObject) RejectVerification(expectedVersion uint64, at time.Time) (StorageObject, error) {
	return object.advance(expectedVersion, ScanRejected, at)
}

func (object StorageObject) BeginScan(expectedVersion uint64, at time.Time) (StorageObject, error) {
	return object.advance(expectedVersion, ScanScanning, at)
}

func (object StorageObject) CompleteScan(
	expectedVersion uint64,
	result ScanState,
	at time.Time,
) (StorageObject, error) {
	if result != ScanAvailable && result != ScanRejected && result != ScanFailed {
		return StorageObject{}, ErrInvalidStorageObject
	}
	return object.advance(expectedVersion, result, at)
}

func (object StorageObject) RetryScan(expectedVersion uint64, at time.Time) (StorageObject, error) {
	return object.advance(expectedVersion, ScanScanning, at)
}

func (object StorageObject) ChangeLegalHold(
	expectedVersion uint64,
	enabled bool,
	at time.Time,
) (StorageObject, error) {
	if err := object.requireExpectedVersion(expectedVersion); err != nil {
		return StorageObject{}, err
	}
	if object.legalHold == enabled || object.state != ScanAvailable && object.state != ScanRetained ||
		!validInstant(at) || at.Before(object.updatedAt) {
		return StorageObject{}, ErrInvalidStorageObject
	}
	updated := object.clone()
	updated.legalHold = enabled
	updated.updatedAt = at
	updated.version++
	if enabled || updated.retentionUntil != nil && updated.retentionUntil.After(at) {
		updated.state = ScanRetained
	} else {
		updated.state = ScanAvailable
	}
	return updated, nil
}

func (object StorageObject) ChangeRetention(
	expectedVersion uint64,
	retentionUntil *time.Time,
	at time.Time,
) (StorageObject, error) {
	if err := object.requireExpectedVersion(expectedVersion); err != nil {
		return StorageObject{}, err
	}
	retention, ok := canonicalOptionalInstant(retentionUntil)
	if !ok || equalInstants(object.retentionUntil, retention) ||
		object.state != ScanAvailable && object.state != ScanRetained ||
		!validInstant(at) || at.Before(object.updatedAt) ||
		retention != nil && retention.Before(object.createdAt) {
		return StorageObject{}, ErrInvalidStorageObject
	}
	updated := object.clone()
	updated.retentionUntil = retention
	updated.updatedAt = at
	updated.version++
	if updated.legalHold || retention != nil && retention.After(at) {
		updated.state = ScanRetained
	} else {
		updated.state = ScanAvailable
	}
	return updated, nil
}

func (object StorageObject) Delete(expectedVersion uint64, at time.Time) (StorageObject, error) {
	if err := object.requireExpectedVersion(expectedVersion); err != nil {
		return StorageObject{}, err
	}
	if !validInstant(at) || at.Before(object.updatedAt) {
		return StorageObject{}, ErrInvalidStorageObject
	}
	if object.state == ScanRetained || object.legalHold ||
		object.retentionUntil != nil && object.retentionUntil.After(at) {
		return StorageObject{}, ErrStorageObjectRetained
	}
	if object.state != ScanAvailable {
		return StorageObject{}, ErrInvalidStorageObject
	}
	return object.advance(expectedVersion, ScanDeleted, at)
}

func (object StorageObject) advance(
	expectedVersion uint64,
	next ScanState,
	at time.Time,
) (StorageObject, error) {
	if err := object.requireExpectedVersion(expectedVersion); err != nil {
		return StorageObject{}, err
	}
	if !validScanTransition(object.state, next) || !validInstant(at) || at.Before(object.updatedAt) {
		return StorageObject{}, ErrInvalidStorageObject
	}
	if (object.state == ScanQuarantined || object.state == ScanScanning || object.state == ScanFailed) &&
		object.verifiedAt == nil {
		return StorageObject{}, ErrInvalidStorageObject
	}
	updated := object.clone()
	updated.state = next
	updated.updatedAt = at
	updated.version++
	return updated, nil
}

func (object StorageObject) requireExpectedVersion(expectedVersion uint64) error {
	if expectedVersion != object.version {
		return ErrStorageObjectConflict
	}
	if !object.valid() {
		return ErrInvalidStorageObject
	}
	if object.version >= maximumAggregateVersion {
		return ErrInvalidStorageObject
	}
	return nil
}

func (object StorageObject) valid() bool {
	if object.version == 0 || object.version > maximumAggregateVersion ||
		!validEntityID(object.id) || !validEntityID(object.tenantID) ||
		!validBucketName(object.bucket) || !validTenantObjectKey(object.objectKey, object.tenantID) ||
		!validOriginalFilename(object.originalFilename) ||
		!validEvidenceClassification(object.classification) || !validEntityID(object.createdBy) ||
		!validInstant(object.createdAt) || !validInstant(object.updatedAt) ||
		object.expectedSizeBytes < 0 || object.expectedSizeBytes > maximumStorageObjectBytes ||
		object.expectedSizeBytes == 0 && object.state != ScanDeleted ||
		!validInstant(object.uploadExpiresAt) || !object.uploadExpiresAt.After(object.createdAt) ||
		object.uploadExpiresAt.After(object.createdAt.Add(time.Hour)) ||
		object.updatedAt.Before(object.createdAt) || !validScanState(object.state) ||
		object.retentionUntil != nil && (!validInstant(*object.retentionUntil) || object.retentionUntil.Before(object.createdAt)) {
		return false
	}

	verified := object.validVerifiedContent()
	unverified := object.contentSHA256 == "" && object.sizeBytes == 0 && object.detectedMIME == "" && object.verifiedAt == nil
	switch object.state {
	case ScanPendingUpload, ScanUploaded, ScanVerifying:
		return unverified && !object.legalHold && object.retentionUntil == nil
	case ScanQuarantined, ScanScanning, ScanFailed:
		return verified && !object.legalHold && object.retentionUntil == nil
	case ScanRejected:
		return (verified || unverified) && !object.legalHold && object.retentionUntil == nil
	case ScanAvailable:
		return verified && !object.legalHold &&
			(object.retentionUntil == nil || !object.retentionUntil.After(object.updatedAt))
	case ScanRetained:
		return verified && (object.legalHold ||
			object.retentionUntil != nil && object.retentionUntil.After(object.updatedAt))
	case ScanDeleted:
		return (verified || unverified) && !object.legalHold &&
			(object.retentionUntil == nil || !object.retentionUntil.After(object.updatedAt))
	default:
		return false
	}
}

func (object StorageObject) validVerifiedContent() bool {
	digest, digestErr := normalizeHexDigest(object.contentSHA256, 32)
	mediaType, mimeErr := normalizeMediaType(object.detectedMIME)
	return digestErr == nil && digest == object.contentSHA256 && object.sizeBytes == object.expectedSizeBytes &&
		object.sizeBytes > 0 && object.sizeBytes <= maximumStorageObjectBytes &&
		mimeErr == nil && mediaType == object.detectedMIME && object.verifiedAt != nil &&
		validInstant(*object.verifiedAt) && !object.verifiedAt.Before(object.createdAt) &&
		!object.verifiedAt.After(object.updatedAt)
}

func (object StorageObject) clone() StorageObject {
	result := object
	result.verifiedAt = cloneInstant(object.verifiedAt)
	result.retentionUntil = cloneInstant(object.retentionUntil)
	return result
}

var bucketNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

func validBucketName(value string) bool {
	if !bucketNamePattern.MatchString(value) || strings.Contains(value, "..") ||
		strings.Contains(value, ".-") || strings.Contains(value, "-.") {
		return false
	}
	_, addressErr := netip.ParseAddr(value)
	return addressErr != nil
}

func validTenantObjectKey(value string, tenantID EntityID) bool {
	if !validSingleLineText(value, 1_024, false) || strings.HasPrefix(value, "/") ||
		strings.Contains(value, `\`) || !strings.HasPrefix(value, tenantID.String()+"/") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}
