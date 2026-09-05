package dfirscan

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	expectedSizeMetadata = "periapsis-expected-size"
	declaredMIMEMetadata = "periapsis-declared-mime"
	maximumObjectKey     = 1_024
)

type s3ObjectAPI interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
}

// S3Store reads immutable upload keys through the same endpoint-pinned client
// used by orphan cleanup. Signed metadata is the only declared-MIME source.
type S3Store struct {
	api                 s3ObjectAPI
	bucket              string
	maximumObjectSize   int64
	expectedBucketOwner *string
}

func (*S3Store) String() string         { return "dfirscan.S3Store{[REDACTED]}" }
func (store *S3Store) GoString() string { return store.String() }

func NewS3Store(api *s3.Client, bucket string, maximumObjectSize int64, expectedBucketOwner string) (*S3Store, error) {
	return newS3Store(api, bucket, maximumObjectSize, expectedBucketOwner)
}

func newS3Store(api s3ObjectAPI, bucket string, maximumObjectSize int64, expectedBucketOwner string) (*S3Store, error) {
	if api == nil || !validS3Bucket(bucket) || maximumObjectSize < 1_024*1_024 ||
		maximumObjectSize > 5_000_000_000 || !validExpectedBucketOwner(expectedBucketOwner) {
		return nil, ErrInvalidConfiguration
	}
	var owner *string
	if expectedBucketOwner != "" {
		owner = aws.String(expectedBucketOwner)
	}
	return &S3Store{
		api: api, bucket: bucket, maximumObjectSize: maximumObjectSize,
		expectedBucketOwner: owner,
	}, nil
}

func (store *S3Store) Check(ctx context.Context) error {
	if !store.valid() || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	result, err := store.api.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(store.bucket), ExpectedBucketOwner: store.expectedBucketOwner,
	})
	if err != nil || result == nil {
		return ErrUnavailable
	}
	return nil
}

func (store *S3Store) Open(
	ctx context.Context,
	location ObjectLocation,
	expectedSize int64,
	expectedDeclaredMIME string,
) (ObjectReader, error) {
	if !store.valid() || ctx == nil || ctx.Err() != nil || !store.validLocation(location) ||
		expectedSize <= 0 || expectedSize > store.maximumObjectSize ||
		expectedDeclaredMIME == "" || len(expectedDeclaredMIME) > 512 {
		return ObjectReader{}, ErrUnavailable
	}
	result, err := store.api.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(store.bucket), Key: aws.String(location.Key),
		ExpectedBucketOwner: store.expectedBucketOwner,
	})
	if err != nil {
		if isMissingObject(err) {
			return ObjectReader{}, ErrObjectNotFound
		}
		return ObjectReader{}, ErrUnavailable
	}
	if result == nil || result.Body == nil {
		return ObjectReader{}, ErrUnavailable
	}
	closeOnFailure := func(failure error) (ObjectReader, error) {
		_ = result.Body.Close()
		return ObjectReader{}, failure
	}
	if result.ContentLength == nil || *result.ContentLength != expectedSize ||
		*result.ContentLength <= 0 || *result.ContentLength > store.maximumObjectSize ||
		result.ContentEncoding != nil || result.ContentType == nil ||
		*result.ContentType != expectedDeclaredMIME || len(result.Metadata) != 2 {
		return closeOnFailure(ErrObjectDrift)
	}
	metadataSize, sizePresent := result.Metadata[expectedSizeMetadata]
	metadataDeclaredMIME, mimePresent := result.Metadata[declaredMIMEMetadata]
	parsedSize, parseErr := strconv.ParseInt(metadataSize, 10, 64)
	if !sizePresent || parseErr != nil || strconv.FormatInt(parsedSize, 10) != metadataSize ||
		parsedSize != expectedSize || !mimePresent || metadataDeclaredMIME != expectedDeclaredMIME {
		return closeOnFailure(ErrObjectDrift)
	}
	return ObjectReader{
		Body: result.Body, SizeBytes: *result.ContentLength, DeclaredMIME: metadataDeclaredMIME,
	}, nil
}

func (store *S3Store) valid() bool {
	return store != nil && store.api != nil && validS3Bucket(store.bucket) &&
		store.maximumObjectSize >= 1_024*1_024 && store.maximumObjectSize <= 5_000_000_000
}

func (store *S3Store) validLocation(location ObjectLocation) bool {
	return location.Bucket == store.bucket && location.TenantID.Version() == 7 &&
		location.ObjectID.Version() == 7 && len(location.Key) <= maximumObjectKey &&
		location.Key == location.TenantID.String()+"/"+location.ObjectID.String()
}

func validS3Bucket(value string) bool {
	if len(value) < 3 || len(value) > 63 ||
		((value[0] < 'a' || value[0] > 'z') && (value[0] < '0' || value[0] > '9')) ||
		strings.Contains(value, "..") ||
		strings.Contains(value, ".-") || strings.Contains(value, "-.") {
		return false
	}
	for index := range value {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '.' || character == '-' {
			continue
		}
		return false
	}
	if value[len(value)-1] == '.' || value[len(value)-1] == '-' {
		return false
	}
	_, addressErr := netip.ParseAddr(value)
	return addressErr != nil
}

func validExpectedBucketOwner(value string) bool {
	if value == "" {
		return true
	}
	if len(value) != 12 {
		return false
	}
	for index := range value {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func isMissingObject(err error) bool {
	var coded interface{ ErrorCode() string }
	if !errors.As(err, &coded) {
		return false
	}
	switch coded.ErrorCode() {
	case "NoSuchKey", "NotFound", "NoSuchObject":
		return true
	default:
		return false
	}
}

var _ ObjectStore = (*S3Store)(nil)
