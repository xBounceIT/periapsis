package dfiradapter

import (
	"context"
	"encoding/base64"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

var _ application.AsyncExportDownloadStorage = (*S3Storage)(nil)

// PrepareAsyncExportDownload verifies the exact immutable manifest published
// by the worker before minting a short-lived GET capability. The object key is
// derived, never accepted from the database or request.
func (storage *S3Storage) PrepareAsyncExportDownload(
	ctx context.Context,
	location application.AsyncExportArtifactLocation,
	expiresAt time.Time,
) (application.AsyncExportDownloadGrant, error) {
	_, key, keyErr := kernel.TicketExportArtifactObjectKeys(
		location.TenantID,
		location.JobID,
		location.ArtifactID,
	)
	if !storage.valid() || ctx == nil || ctx.Err() != nil || keyErr != nil ||
		len(key) == 0 || len(key) > maximumObjectKey || location.Revision == 0 ||
		location.Revision > math.MaxInt64 || location.Attempt == 0 ||
		location.Attempt > kernel.TicketExportMaximumAttempts ||
		location.Projection != kernel.TicketExportProjectionVersion ||
		location.Digest == ([32]byte{}) || location.Rows > kernel.TicketExportOperatorMaximumRows ||
		location.Bytes == 0 || location.Bytes > kernel.TicketExportOperatorMaximumBytes {
		return application.AsyncExportDownloadGrant{}, ErrStorageUnavailable
	}
	now := storage.clock().UTC()
	lifetime := expiresAt.Sub(now)
	if lifetime <= 0 || lifetime > application.AsyncExportDownloadMaximumLifetime {
		return application.AsyncExportDownloadGrant{}, ErrStorageUnavailable
	}
	head, err := storage.objects.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket:              aws.String(storage.bucket),
		Key:                 aws.String(key),
		ExpectedBucketOwner: storage.expectedBucketOwner,
		ChecksumMode:        types.ChecksumModeEnabled,
	})
	if err != nil || ctx.Err() != nil || !validTicketExportHead(head, location) {
		return application.AsyncExportDownloadGrant{}, ErrStorageUnavailable
	}
	request, err := storage.presigner.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket:                     aws.String(storage.bucket),
		Key:                        aws.String(key),
		ResponseCacheControl:       aws.String("private, no-store"),
		ResponseContentDisposition: aws.String(`attachment; filename="periapsis-ticket-export.csv"`),
		ResponseContentType:        aws.String("text/csv; charset=utf-8"),
	}, func(options *s3.PresignOptions) {
		options.Expires = lifetime
	})
	if err != nil || request == nil || request.Method != http.MethodGet ||
		!onlyHostHeader(request.SignedHeader, endpointAuthority(storage.endpoint)) ||
		!validPresignedExpiry(request.URL, lifetime, application.AsyncExportDownloadMaximumLifetime) ||
		!storage.validPresignedObjectTarget(request.URL, storage.bucket, key) {
		return application.AsyncExportDownloadGrant{}, ErrStorageUnavailable
	}
	return application.AsyncExportDownloadGrant{
		TargetURL: request.URL,
		ExpiresAt: expiresAt.UTC(),
	}, nil
}

func validTicketExportHead(
	head *s3.HeadObjectOutput,
	location application.AsyncExportArtifactLocation,
) bool {
	if head == nil || aws.ToInt64(head.ContentLength) != int64(location.Bytes) ||
		aws.ToString(head.ContentType) != "text/csv; charset=utf-8" ||
		head.ContentEncoding != nil || head.ServerSideEncryption != types.ServerSideEncryptionAes256 ||
		aws.ToString(head.ChecksumSHA256) != base64.StdEncoding.EncodeToString(location.Digest[:]) ||
		!validTicketExportETag(aws.ToString(head.ETag)) {
		return false
	}
	expected := map[string]string{
		"periapsis-tenant":     location.TenantID.String(),
		"periapsis-job":        location.JobID.String(),
		"periapsis-artifact":   location.ArtifactID.String(),
		"periapsis-revision":   strconv.FormatUint(location.Revision, 10),
		"periapsis-attempt":    strconv.FormatUint(uint64(location.Attempt), 10),
		"periapsis-sha256":     fmtTicketExportDigest(location.Digest),
		"periapsis-rows":       strconv.FormatUint(uint64(location.Rows), 10),
		"periapsis-bytes":      strconv.FormatUint(location.Bytes, 10),
		"periapsis-projection": strconv.FormatUint(location.Projection, 10),
		"periapsis-state":      "final",
	}
	if len(head.Metadata) != len(expected) {
		return false
	}
	for key, value := range expected {
		if head.Metadata[key] != value {
			return false
		}
	}
	return true
}

func fmtTicketExportDigest(digest [32]byte) string {
	const digits = "0123456789abcdef"
	encoded := make([]byte, len(digest)*2)
	for index, value := range digest {
		encoded[index*2] = digits[value>>4]
		encoded[index*2+1] = digits[value&0x0f]
	}
	return string(encoded)
}

func validTicketExportETag(value string) bool {
	if len(value) < 3 || len(value) > 256 || value[0] != '"' || value[len(value)-1] != '"' {
		return false
	}
	for index := 1; index < len(value)-1; index++ {
		if value[index] < 0x21 || value[index] > 0x7e || value[index] == '"' || value[index] == '\\' {
			return false
		}
	}
	return true
}
