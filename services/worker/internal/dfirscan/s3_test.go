package dfirscan

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestS3StoreRequiresMatchingSignedContentTypeAndDeclaredMIMEMetadata(t *testing.T) {
	t.Parallel()
	tenantID, storageID := mustUUIDv7(t), mustUUIDv7(t)
	body := &closeTrackingReader{Reader: bytes.NewReader([]byte("evidence"))}
	api := &s3ObjectFake{get: &s3.GetObjectOutput{
		Body: body, ContentLength: aws.Int64(8), ContentType: aws.String("text/plain"),
		Metadata: map[string]string{
			expectedSizeMetadata: "8", declaredMIMEMetadata: "text/plain",
		},
	}}
	store, err := newS3Store(api, "periapsis-evidence", 10*1024*1024, "123456789012")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := store.Open(context.Background(), ObjectLocation{
		TenantID: tenantID, ObjectID: storageID, Bucket: "periapsis-evidence",
		Key: tenantID.String() + "/" + storageID.String(),
	}, 8, "text/plain")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer reader.Body.Close()
	if reader.DeclaredMIME != "text/plain" || reader.SizeBytes != 8 {
		t.Fatalf("ObjectReader = %+v", reader)
	}
	if api.getInput == nil || aws.ToString(api.getInput.ExpectedBucketOwner) != "123456789012" {
		t.Fatal("expected-bucket-owner boundary was not applied")
	}
}

func TestS3StoreFailsClosedOnMissingOrMismatchedContentType(t *testing.T) {
	t.Parallel()
	for name, contentType := range map[string]*string{
		"missing":  nil,
		"mismatch": aws.String("text/html"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tenantID, storageID := mustUUIDv7(t), mustUUIDv7(t)
			body := &closeTrackingReader{Reader: bytes.NewReader([]byte("evidence"))}
			api := &s3ObjectFake{get: &s3.GetObjectOutput{
				Body: body, ContentLength: aws.Int64(8), ContentType: contentType,
				Metadata: map[string]string{
					expectedSizeMetadata: "8", declaredMIMEMetadata: "text/plain",
				},
			}}
			store, err := newS3Store(api, "periapsis-evidence", 10*1024*1024, "")
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.Open(context.Background(), ObjectLocation{
				TenantID: tenantID, ObjectID: storageID, Bucket: "periapsis-evidence",
				Key: tenantID.String() + "/" + storageID.String(),
			}, 8, "text/plain")
			if !errors.Is(err, ErrObjectDrift) || !body.closed {
				t.Fatalf("Open() error/closed = %v/%t", err, body.closed)
			}
		})
	}
}

func TestS3StoreFailsClosedOnMetadataDriftAndClosesBody(t *testing.T) {
	t.Parallel()
	tenantID, storageID := mustUUIDv7(t), mustUUIDv7(t)
	body := &closeTrackingReader{Reader: bytes.NewReader([]byte("evidence"))}
	api := &s3ObjectFake{get: &s3.GetObjectOutput{
		Body: body, ContentLength: aws.Int64(8), ContentType: aws.String("text/plain"),
		Metadata: map[string]string{
			expectedSizeMetadata: "8", declaredMIMEMetadata: "application/octet-stream",
		},
	}}
	store, err := newS3Store(api, "periapsis-evidence", 10*1024*1024, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Open(context.Background(), ObjectLocation{
		TenantID: tenantID, ObjectID: storageID, Bucket: "periapsis-evidence",
		Key: tenantID.String() + "/" + storageID.String(),
	}, 8, "text/plain")
	if !errors.Is(err, ErrObjectDrift) || !body.closed {
		t.Fatalf("Open() error/closed = %v/%t", err, body.closed)
	}
}

func TestS3StoreDistinguishesMissingObject(t *testing.T) {
	t.Parallel()
	tenantID, storageID := mustUUIDv7(t), mustUUIDv7(t)
	store, err := newS3Store(&s3ObjectFake{err: codedS3Error("NoSuchKey")}, "periapsis-evidence", 10*1024*1024, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Open(context.Background(), ObjectLocation{
		TenantID: tenantID, ObjectID: storageID, Bucket: "periapsis-evidence",
		Key: tenantID.String() + "/" + storageID.String(),
	}, 8, "text/plain")
	if !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("Open() error = %v", err)
	}
}

func TestValidS3BucketAcceptsAlphabeticAndNumericPrefixes(t *testing.T) {
	t.Parallel()
	for _, bucket := range []string{"periapsis-evidence", "1-evidence"} {
		if !validS3Bucket(bucket) {
			t.Fatalf("validS3Bucket(%q) = false", bucket)
		}
	}
}

type s3ObjectFake struct {
	get      *s3.GetObjectOutput
	err      error
	getInput *s3.GetObjectInput
}

func (api *s3ObjectFake) GetObject(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	api.getInput = input
	return api.get, api.err
}

func (*s3ObjectFake) HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	return &s3.HeadBucketOutput{}, nil
}

type codedS3Error string

func (value codedS3Error) Error() string     { return "s3 failure" }
func (value codedS3Error) ErrorCode() string { return string(value) }

type closeTrackingReader struct {
	io.Reader
	closed bool
}

func (reader *closeTrackingReader) Close() error {
	reader.closed = true
	return nil
}
