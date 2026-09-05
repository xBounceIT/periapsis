package dfiradapter

import (
	"context"
	"encoding/base64"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/periapsis-im/periapsis/services/api/internal/auditoperations"
)

var _ auditoperations.ArtifactStorage = (*S3Storage)(nil)

// OpenAuditExport performs a direct manifest-bound GET. No presigned URL,
// object key, storage credential, or redirect is exposed to the browser.
func (storage *S3Storage) OpenAuditExport(
	ctx context.Context,
	location auditoperations.ArtifactLocation,
) (auditoperations.ArtifactReader, error) {
	if !storage.valid() || ctx == nil || ctx.Err() != nil || !validAuditExportLocation(location) ||
		location.Bytes > storage.maximum || !location.ExpiresAt.After(storage.clock().UTC()) {
		return auditoperations.ArtifactReader{}, ErrStorageUnavailable
	}
	result, err := storage.objects.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(storage.bucket), Key: aws.String(location.ObjectKey),
		ExpectedBucketOwner: storage.expectedBucketOwner, ChecksumMode: types.ChecksumModeEnabled,
	})
	if err != nil || ctx.Err() != nil || !validAuditExportObject(result, location) {
		if result != nil && result.Body != nil {
			_ = result.Body.Close()
		}
		return auditoperations.ArtifactReader{}, ErrStorageUnavailable
	}
	return auditoperations.ArtifactReader{Body: result.Body, Size: location.Bytes}, nil
}

func validAuditExportLocation(location auditoperations.ArtifactLocation) bool {
	if location.ArtifactID == [16]byte{} || location.ExportID == [16]byte{} ||
		location.Digest == [32]byte{} || location.Rows < 0 || location.Rows > 1_000_000 ||
		location.Bytes < 0 || location.Bytes > 1_073_741_824 ||
		(location.Rows == 0) != (location.Bytes == 0) || location.ExpiresAt.IsZero() {
		return false
	}
	expectedKey := "platform/audit/exports/" + location.ExportID.String() + "/v1.jsonl"
	if location.Stream == auditoperations.StreamTenant && location.TenantID != nil {
		expectedKey = "tenants/" + location.TenantID.String() + "/audit/exports/" + location.ExportID.String() + "/v1.jsonl"
	} else if location.Stream != auditoperations.StreamPlatform || location.TenantID != nil {
		return false
	}
	return location.ObjectKey == expectedKey
}

func validAuditExportObject(
	result *s3.GetObjectOutput,
	location auditoperations.ArtifactLocation,
) bool {
	if result == nil || result.Body == nil || result.ContentLength == nil ||
		*result.ContentLength != location.Bytes || aws.ToString(result.ContentType) != "application/x-ndjson" ||
		result.ContentEncoding != nil || result.ServerSideEncryption != types.ServerSideEncryptionAes256 ||
		aws.ToString(result.ChecksumSHA256) != base64.StdEncoding.EncodeToString(location.Digest[:]) ||
		!validTicketExportETag(aws.ToString(result.ETag)) {
		return false
	}
	expected := map[string]string{
		"periapsis-audit-stream": string(location.Stream),
		"periapsis-export-job":   location.ExportID.String(),
		"periapsis-artifact":     location.ArtifactID.String(),
		"periapsis-sha256":       fmtTicketExportDigest(location.Digest),
		"periapsis-rows":         strconv.FormatInt(location.Rows, 10),
		"periapsis-bytes":        strconv.FormatInt(location.Bytes, 10),
		"periapsis-projection":   "1",
		"periapsis-format":       "jsonl",
		"periapsis-state":        "final",
	}
	if location.TenantID != nil {
		expected["periapsis-tenant"] = location.TenantID.String()
	}
	if len(result.Metadata) != len(expected) {
		return false
	}
	for key, value := range expected {
		if result.Metadata[key] != value {
			return false
		}
	}
	return true
}
