package dfiradapter

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func TestTicketExportDownloadVerifiesExactHeadBeforePresign(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 20, 0, 0, 0, time.UTC)
	location := testTicketExportLocation(t)
	_, key, err := kernel.TicketExportArtifactObjectKeys(
		location.TenantID,
		location.JobID,
		location.ArtifactID,
	)
	if err != nil {
		t.Fatal(err)
	}
	owner := "123456789012"
	var headCalls, presignCalls atomic.Int32
	storage := &S3Storage{
		objects: &fakeS3Objects{headObject: func(
			_ context.Context,
			input *s3.HeadObjectInput,
			_ ...func(*s3.Options),
		) (*s3.HeadObjectOutput, error) {
			headCalls.Add(1)
			if aws.ToString(input.Bucket) != "periapsis-evidence" ||
				aws.ToString(input.Key) != key ||
				aws.ToString(input.ExpectedBucketOwner) != owner ||
				input.ChecksumMode != types.ChecksumModeEnabled {
				t.Fatalf("HEAD input = %#v", input)
			}
			return validTicketExportHeadFixture(location), nil
		}},
		presigner: &fakeS3Presigner{get: func(
			_ context.Context,
			input *s3.GetObjectInput,
			options ...func(*s3.PresignOptions),
		) (*v4.PresignedHTTPRequest, error) {
			presignCalls.Add(1)
			presignOptions := &s3.PresignOptions{}
			for _, option := range options {
				option(presignOptions)
			}
			if aws.ToString(input.Key) != key ||
				aws.ToString(input.ResponseCacheControl) != "private, no-store" ||
				aws.ToString(input.ResponseContentType) != "text/csv; charset=utf-8" ||
				aws.ToString(input.ResponseContentDisposition) != `attachment; filename="periapsis-ticket-export.csv"` ||
				presignOptions.Expires != application.AsyncExportDownloadMaximumLifetime {
				t.Fatalf("presign input = %#v, options = %#v", input, presignOptions)
			}
			return &v4.PresignedHTTPRequest{
				Method: http.MethodGet,
				URL: "https://storage.example/periapsis-evidence/" + key +
					"?X-Amz-Expires=300&X-Amz-Signature=secret",
				SignedHeader: http.Header{"Host": {"storage.example"}},
			}, nil
		}},
		endpoint:            mustEndpoint(t, "https://storage.example"),
		bucket:              "periapsis-evidence",
		maximum:             32 * 1024 * 1024,
		clock:               func() time.Time { return now },
		expectedBucketOwner: aws.String(owner),
	}
	grant, err := storage.PrepareAsyncExportDownload(
		context.Background(),
		location,
		now.Add(application.AsyncExportDownloadMaximumLifetime),
	)
	if err != nil || headCalls.Load() != 1 || presignCalls.Load() != 1 ||
		grant.ExpiresAt != now.Add(application.AsyncExportDownloadMaximumLifetime) ||
		!strings.HasPrefix(grant.TargetURL, "https://storage.example/") {
		t.Fatalf("grant = (%s, %v), HEAD=%d presign=%d", grant, err, headCalls.Load(), presignCalls.Load())
	}
	if strings.Contains(grant.String(), "Signature") || strings.Contains(grant.GoString(), key) {
		t.Fatal("download grant diagnostics exposed the signed capability")
	}
}

func TestTicketExportDownloadRejectsHeadDriftBeforePresign(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 20, 0, 0, 0, time.UTC)
	location := testTicketExportLocation(t)
	mutations := map[string]func(*s3.HeadObjectOutput){
		"wrong bytes":      func(head *s3.HeadObjectOutput) { head.ContentLength = aws.Int64(int64(location.Bytes + 1)) },
		"wrong checksum":   func(head *s3.HeadObjectOutput) { head.ChecksumSHA256 = aws.String("foreign") },
		"wrong metadata":   func(head *s3.HeadObjectOutput) { head.Metadata["periapsis-tenant"] = testStorageID },
		"extra metadata":   func(head *s3.HeadObjectOutput) { head.Metadata["foreign"] = "value" },
		"content encoding": func(head *s3.HeadObjectOutput) { head.ContentEncoding = aws.String("gzip") },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			head := validTicketExportHeadFixture(location)
			mutate(head)
			var presignCalls atomic.Int32
			storage := &S3Storage{
				objects: &fakeS3Objects{headObject: func(
					context.Context,
					*s3.HeadObjectInput,
					...func(*s3.Options),
				) (*s3.HeadObjectOutput, error) {
					return head, nil
				}},
				presigner: &fakeS3Presigner{get: func(
					context.Context,
					*s3.GetObjectInput,
					...func(*s3.PresignOptions),
				) (*v4.PresignedHTTPRequest, error) {
					presignCalls.Add(1)
					return nil, nil
				}},
				endpoint: mustEndpoint(t, "https://storage.example"), bucket: "periapsis-evidence",
				maximum: 32 * 1024 * 1024, clock: func() time.Time { return now },
			}
			if _, err := storage.PrepareAsyncExportDownload(
				context.Background(), location, now.Add(time.Minute),
			); err == nil || presignCalls.Load() != 0 {
				t.Fatalf("drifted HEAD error = %v, presign calls = %d", err, presignCalls.Load())
			}
		})
	}
}

func testTicketExportLocation(t *testing.T) application.AsyncExportArtifactLocation {
	t.Helper()
	digest := sha256.Sum256([]byte("exact export artifact"))
	return application.AsyncExportArtifactLocation{
		TenantID:   ticketExportEntityID(t, testTenantID),
		JobID:      ticketExportEntityID(t, "018f0000-0000-7000-8000-000000000091"),
		ArtifactID: ticketExportEntityID(t, "018f0000-0000-7000-8000-000000000092"),
		Revision:   3, Attempt: 1, Projection: kernel.TicketExportProjectionVersion,
		Digest: digest, Rows: 17, Bytes: 211,
	}
}

func ticketExportEntityID(t *testing.T, raw string) kernel.EntityID {
	t.Helper()
	parsed, err := uuid.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	id, err := kernel.NewEntityID([16]byte(parsed))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func validTicketExportHeadFixture(
	location application.AsyncExportArtifactLocation,
) *s3.HeadObjectOutput {
	return &s3.HeadObjectOutput{
		ContentLength:        aws.Int64(int64(location.Bytes)),
		ContentType:          aws.String("text/csv; charset=utf-8"),
		ServerSideEncryption: types.ServerSideEncryptionAes256,
		ChecksumSHA256:       aws.String(base64.StdEncoding.EncodeToString(location.Digest[:])),
		ETag:                 aws.String(`"0123456789abcdef"`),
		Metadata: map[string]string{
			"periapsis-tenant":     location.TenantID.String(),
			"periapsis-job":        location.JobID.String(),
			"periapsis-artifact":   location.ArtifactID.String(),
			"periapsis-revision":   "3",
			"periapsis-attempt":    "1",
			"periapsis-sha256":     fmtTicketExportDigest(location.Digest),
			"periapsis-rows":       "17",
			"periapsis-bytes":      "211",
			"periapsis-projection": "1",
			"periapsis-state":      "final",
		},
	}
}
