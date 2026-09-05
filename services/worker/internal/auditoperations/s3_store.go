package auditoperations

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"
)

var bucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

type s3API interface {
	HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

type S3Options struct {
	Bucket              string
	ExpectedBucketOwner string
}

type S3Store struct {
	api                 s3API
	bucket              string
	expectedBucketOwner *string
}

func NewS3Store(api s3API, options S3Options) (*S3Store, error) {
	if api == nil || !bucketPattern.MatchString(options.Bucket) ||
		!validExpectedBucketOwner(options.ExpectedBucketOwner) {
		return nil, ErrInvalidConfiguration
	}
	var owner *string
	if options.ExpectedBucketOwner != "" {
		owner = aws.String(options.ExpectedBucketOwner)
	}
	return &S3Store{api: api, bucket: options.Bucket, expectedBucketOwner: owner}, nil
}

func (*S3Store) String() string         { return "auditoperations.S3Store{[REDACTED]}" }
func (store *S3Store) GoString() string { return store.String() }

func (store *S3Store) Check(ctx context.Context) error {
	if store == nil || store.api == nil || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	result, err := store.api.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(store.bucket), ExpectedBucketOwner: store.expectedBucketOwner,
	})
	if err != nil || result == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}

func (store *S3Store) Put(ctx context.Context, artifact Artifact) error {
	if store == nil || store.api == nil || ctx == nil || ctx.Err() != nil || !validArtifact(artifact, true) {
		return ErrInvalidInput
	}
	file, err := os.Open(artifact.Path)
	if err != nil {
		return ErrUnavailable
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != artifact.Bytes ||
		!fileDigestMatches(file, artifact.Digest) {
		return ErrArtifactConflict
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ErrUnavailable
	}
	metadata := artifactMetadata(artifact)
	if head, found, headErr := store.head(ctx, artifact.ObjectKey); headErr != nil {
		return headErr
	} else if found {
		if store.validHead(head, artifact, metadata) {
			return nil
		}
		return ErrArtifactConflict
	}
	checksum := base64.StdEncoding.EncodeToString(artifact.Digest[:])
	_, putErr := store.api.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(store.bucket), Key: aws.String(artifact.ObjectKey), Body: file,
		ContentLength: aws.Int64(artifact.Bytes), ContentType: aws.String("application/x-ndjson"),
		Metadata: metadata, ChecksumSHA256: aws.String(checksum), IfNoneMatch: aws.String("*"),
		ChecksumAlgorithm:    types.ChecksumAlgorithmSha256,
		ServerSideEncryption: types.ServerSideEncryptionAes256,
		ExpectedBucketOwner:  store.expectedBucketOwner,
	})
	head, found, headErr := store.head(ctx, artifact.ObjectKey)
	if headErr != nil || !found {
		return ErrUnavailable
	}
	if !store.validHead(head, artifact, metadata) {
		return ErrArtifactConflict
	}
	// Reconcile a lost successful response through the exact protected HEAD.
	_ = putErr
	return nil
}

func (store *S3Store) Verify(ctx context.Context, artifact Artifact) error {
	if store == nil || store.api == nil || ctx == nil || ctx.Err() != nil || !validArtifact(artifact, false) {
		return ErrInvalidInput
	}
	result, err := store.api.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(store.bucket), Key: aws.String(artifact.ObjectKey),
		ExpectedBucketOwner: store.expectedBucketOwner, ChecksumMode: types.ChecksumModeEnabled,
	})
	if err != nil || result == nil || result.Body == nil {
		return ErrUnavailable
	}
	defer result.Body.Close()
	if !validObjectHeaders(result.ContentLength, result.ContentType, result.ContentEncoding,
		result.ServerSideEncryption, result.ChecksumSHA256, result.Metadata, artifact) {
		return ErrArtifactConflict
	}
	digest := sha256.New()
	written, copyErr := io.Copy(digest, io.LimitReader(result.Body, artifact.Bytes+1))
	if copyErr != nil || written != artifact.Bytes || !bytesEqual(digest.Sum(nil), artifact.Digest[:]) {
		return ErrArtifactConflict
	}
	return nil
}

func (store *S3Store) DeleteExact(ctx context.Context, artifact Artifact) error {
	if err := store.Verify(ctx, artifact); err != nil {
		return err
	}
	head, found, err := store.head(ctx, artifact.ObjectKey)
	if err != nil || !found || head == nil || !validETag(aws.ToString(head.ETag)) {
		return ErrUnavailable
	}
	result, err := store.api.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(store.bucket), Key: aws.String(artifact.ObjectKey),
		ExpectedBucketOwner: store.expectedBucketOwner, IfMatch: head.ETag,
	})
	if err != nil || result == nil {
		return ErrUnavailable
	}
	if _, found, err := store.head(ctx, artifact.ObjectKey); err != nil || found {
		return ErrUnavailable
	}
	return nil
}

func (store *S3Store) head(ctx context.Context, key string) (*s3.HeadObjectOutput, bool, error) {
	result, err := store.api.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(store.bucket), Key: aws.String(key),
		ExpectedBucketOwner: store.expectedBucketOwner, ChecksumMode: types.ChecksumModeEnabled,
	})
	if err != nil {
		if objectNotFound(err) {
			return nil, false, nil
		}
		return nil, false, ErrUnavailable
	}
	if result == nil {
		return nil, false, ErrUnavailable
	}
	return result, true, nil
}

func (store *S3Store) validHead(head *s3.HeadObjectOutput, artifact Artifact, metadata map[string]string) bool {
	if head == nil || !validETag(aws.ToString(head.ETag)) {
		return false
	}
	return validObjectHeaders(head.ContentLength, head.ContentType, head.ContentEncoding,
		head.ServerSideEncryption, head.ChecksumSHA256, head.Metadata, artifact)
}

func validObjectHeaders(length *int64, contentType *string, contentEncoding *string,
	encryption types.ServerSideEncryption, checksum *string, metadata map[string]string, artifact Artifact) bool {
	if length == nil || *length != artifact.Bytes || aws.ToString(contentType) != "application/x-ndjson" ||
		contentEncoding != nil || encryption != types.ServerSideEncryptionAes256 ||
		aws.ToString(checksum) != base64.StdEncoding.EncodeToString(artifact.Digest[:]) {
		return false
	}
	expected := artifactMetadata(artifact)
	if len(metadata) != len(expected) {
		return false
	}
	for key, value := range expected {
		if metadata[key] != value {
			return false
		}
	}
	return true
}

func artifactMetadata(artifact Artifact) map[string]string {
	metadata := map[string]string{
		"periapsis-audit-stream": string(artifact.Stream),
		"periapsis-sha256":       hex.EncodeToString(artifact.Digest[:]),
		"periapsis-rows":         strconv.FormatInt(artifact.Rows, 10),
		"periapsis-bytes":        strconv.FormatInt(artifact.Bytes, 10),
		"periapsis-projection":   "1",
		"periapsis-format":       "jsonl",
		"periapsis-state":        "final",
	}
	if artifact.Stream == TenantStream {
		metadata["periapsis-tenant"] = artifact.TenantID.String()
	}
	if artifact.Kind == ExportArtifactKind {
		metadata["periapsis-export-job"] = artifact.JobID.String()
		metadata["periapsis-artifact"] = artifact.ArtifactID.String()
	} else {
		metadata["periapsis-segment"] = artifact.SegmentID.String()
		metadata["periapsis-start-sequence"] = strconv.FormatInt(artifact.StartSequence, 10)
		metadata["periapsis-end-sequence"] = strconv.FormatInt(artifact.EndSequence, 10)
		metadata["periapsis-signing-key"] = artifact.SigningKeyID
		metadata["periapsis-signature"] = base64.StdEncoding.EncodeToString(artifact.Signature[:])
	}
	return metadata
}

func validArtifact(artifact Artifact, requirePath bool) bool {
	if !artifact.Stream.Valid() || !validObjectKey(artifact.Stream, artifact.TenantID, artifact.ObjectKey) ||
		artifact.Digest == ([32]byte{}) || artifact.Rows < 0 || artifact.Rows > MaximumArtifactRows ||
		artifact.Bytes < 0 || artifact.Bytes > MaximumArtifactBytes || artifact.ProjectionVersion != 1 ||
		artifact.Format != "jsonl" || requirePath && artifact.Path == "" {
		return false
	}
	if artifact.Kind == ExportArtifactKind {
		expected := "platform/audit/exports/" + artifact.JobID.String() + "/v1.jsonl"
		if artifact.Stream == TenantStream {
			expected = "tenants/" + artifact.TenantID.String() + "/audit/exports/" + artifact.JobID.String() + "/v1.jsonl"
		}
		return validUUIDv7(artifact.JobID) && validUUIDv7(artifact.ArtifactID) && artifact.SegmentID == uuid.Nil &&
			artifact.ObjectKey == expected && (artifact.Rows == 0) == (artifact.Bytes == 0)
	}
	expected := "platform/audit/segments/" + strconv.FormatInt(artifact.StartSequence, 10) + "-" +
		strconv.FormatInt(artifact.EndSequence, 10) + "/" + artifact.SegmentID.String() + ".jsonl"
	if artifact.Stream == TenantStream {
		expected = "tenants/" + artifact.TenantID.String() + "/audit/segments/" +
			strconv.FormatInt(artifact.StartSequence, 10) + "-" + strconv.FormatInt(artifact.EndSequence, 10) +
			"/" + artifact.SegmentID.String() + ".jsonl"
	}
	return artifact.Kind == SegmentArtifactKind && validUUIDv7(artifact.SegmentID) &&
		artifact.JobID == uuid.Nil && artifact.ArtifactID == uuid.Nil && artifact.Rows > 0 &&
		artifact.Rows == artifact.EndSequence-artifact.StartSequence+1 && artifact.Bytes > 0 &&
		signingKeyIDPattern.MatchString(artifact.SigningKeyID) && artifact.Signature != ([64]byte{}) &&
		artifact.ObjectKey == expected
}

func fileDigestMatches(file *os.File, expected [32]byte) bool {
	if file == nil {
		return false
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return false
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return false
	}
	return bytesEqual(digest.Sum(nil), expected[:])
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var mismatch byte
	for index := range left {
		mismatch |= left[index] ^ right[index]
	}
	return mismatch == 0
}

func validExpectedBucketOwner(value string) bool {
	if value == "" {
		return true
	}
	if len(value) != 12 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func objectNotFound(err error) bool {
	var apiError smithy.APIError
	return errors.As(err, &apiError) &&
		(apiError.ErrorCode() == "NotFound" || apiError.ErrorCode() == "NoSuchKey")
}

func validETag(value string) bool {
	return len(value) >= 34 && len(value) <= 130 && strings.HasPrefix(value, "\"") &&
		strings.HasSuffix(value, "\"")
}
