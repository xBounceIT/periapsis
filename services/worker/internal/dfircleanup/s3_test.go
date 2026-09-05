package dfircleanup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestS3DeleterHardDeletesExactVersionsAndVerifiesAbsence(t *testing.T) {
	claim := validClaim(cleanupTestTime())
	api := &fakeS3Delete{
		versions: []types.ObjectVersion{
			{Key: aws.String(claim.ObjectKey), VersionId: aws.String("version-1")},
			{Key: aws.String(claim.ObjectKey + "-other"), VersionId: aws.String("other-version")},
		},
		markers: []types.DeleteMarkerEntry{
			{Key: aws.String(claim.ObjectKey), VersionId: aws.String("marker-1")},
		},
	}
	deleter, err := newS3Deleter(api, "periapsis-evidence", "123456789012")
	if err != nil {
		t.Fatal(err)
	}
	location := ObjectLocation{Bucket: claim.Bucket, Key: claim.ObjectKey}
	if err := deleter.Delete(context.Background(), location); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if api.listCalls != 2 || len(api.deleted) != 2 {
		t.Fatalf("S3 calls: list=%d deleted=%#v", api.listCalls, api.deleted)
	}
	for _, deleted := range api.deleted {
		if deleted.bucket != location.Bucket || deleted.key != location.Key || deleted.versionID == "" ||
			deleted.expectedOwner != "123456789012" {
			t.Fatalf("DeleteObject() input = %#v", deleted)
		}
	}
	formatted := fmt.Sprintf("%s %#v %s %#v", deleter, deleter, location, location)
	if strings.Contains(formatted, location.Key) || strings.Contains(formatted, location.Bucket) {
		t.Fatalf("formatter leaked object location: %s", formatted)
	}
}

func TestS3DeleterRejectsHostileLocationBeforeSDK(t *testing.T) {
	api := &fakeS3Delete{}
	deleter, err := newS3Deleter(api, "periapsis-evidence", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, location := range []ObjectLocation{
		{Bucket: "other", Key: validClaim(cleanupTestTime()).ObjectKey},
		{Bucket: "periapsis-evidence", Key: "../secret"},
		{Bucket: "periapsis-evidence", Key: "019d0200-0001-7001-8001-000000000001/%2e%2e"},
	} {
		if err := deleter.Delete(context.Background(), location); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Delete(%#v) error = %v", location, err)
		}
	}
	if len(api.deleted) != 0 || api.listCalls != 0 {
		t.Fatalf("S3 calls: list=%d delete=%d", api.listCalls, len(api.deleted))
	}
}

func TestS3DeleterDoesNotFinalizeWhileAnyVersionPersists(t *testing.T) {
	claim := validClaim(cleanupTestTime())
	api := &fakeS3Delete{
		versions:      []types.ObjectVersion{{Key: aws.String(claim.ObjectKey), VersionId: aws.String("version-1")}},
		ignoreDeletes: true,
	}
	deleter, err := newS3Deleter(api, claim.Bucket, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := deleter.Delete(context.Background(), ObjectLocation{Bucket: claim.Bucket, Key: claim.ObjectKey}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Delete() persistent version error = %v", err)
	}
	if api.listCalls != 2 || len(api.deleted) != 1 {
		t.Fatalf("S3 calls: list=%d deleted=%d", api.listCalls, len(api.deleted))
	}
}

func TestS3DeleterReadinessRequiresVersionListingPermission(t *testing.T) {
	api := &fakeS3Delete{}
	deleter, err := newS3Deleter(api, "periapsis-evidence", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := deleter.Check(context.Background()); err != nil || api.listCalls != 1 {
		t.Fatalf("Check() error=%v listCalls=%d", err, api.listCalls)
	}
	api.listErr = errors.New("access denied")
	if err := deleter.Check(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Check() access-denied error = %v", err)
	}
}

func TestLoadS3ConfigRejectsAmbientOrMetadataDestinations(t *testing.T) {
	base := map[string]string{
		"PERIAPSIS_S3_ENDPOINT":               "https://s3.example.com",
		"PERIAPSIS_S3_REGION":                 "eu-west-1",
		"PERIAPSIS_S3_BUCKET":                 "periapsis-evidence",
		"PERIAPSIS_S3_ACCESS_KEY":             "access-key",
		"PERIAPSIS_S3_SECRET_KEY":             "secret-key-material",
		"PERIAPSIS_DFIR_PRIVATE_EGRESS_CIDRS": "10.0.0.0/8",
	}
	lookup := func(values map[string]string) func(string) (string, bool) {
		return func(name string) (string, bool) { value, ok := values[name]; return value, ok }
	}
	if _, err := loadS3Config("development", lookup(base), func(string) ([]byte, error) { return nil, errors.New("unused") }); err != nil {
		t.Fatalf("loadS3Config(valid) error = %v", err)
	}
	hostile := make(map[string]string, len(base))
	for key, value := range base {
		hostile[key] = value
	}
	hostile["PERIAPSIS_S3_ENDPOINT"] = "https://169.254.169.254"
	if _, err := loadS3Config("development", lookup(hostile), func(string) ([]byte, error) { return nil, nil }); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("metadata endpoint error = %v", err)
	}
	if _, err := loadS3Config("production", lookup(base), func(string) ([]byte, error) { return nil, nil }); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("production inline secret error = %v", err)
	}
	base["PERIAPSIS_TICKET_EXPORT_EXPECTED_BUCKET_OWNER"] = "1234"
	if _, err := loadS3Config("development", lookup(base), func(string) ([]byte, error) { return nil, nil }); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("malformed expected owner error = %v", err)
	}
}

func TestS3ConfigClearsOnlySourceCredentials(t *testing.T) {
	config := S3Config{
		bucket: "periapsis-evidence", accessKey: "access-key",
		secretKey: "secret-key-material", sessionToken: "session-token",
	}
	config.ClearSecrets()
	if config.accessKey != "" || config.secretKey != "" || config.sessionToken != "" ||
		config.Bucket() != "periapsis-evidence" {
		t.Fatalf("cleared S3 configuration = %#v", config)
	}
	if strings.Contains(fmt.Sprintf("%s %#v", config, config), "secret") {
		t.Fatal("S3 configuration formatter exposed credential material")
	}
}

func TestS3NamesRejectAmbiguousAddressForms(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "2130706433", "0x7f.0x0.0x0.0x1"} {
		if validBucket(value) {
			t.Fatalf("validBucket(%q) = true", value)
		}
	}
	for _, value := range []string{"2130706433", "0x7f.0x0.0x0.0x1"} {
		if validHost(value) {
			t.Fatalf("validHost(%q) = true", value)
		}
	}
	if !validHost("127.0.0.1") {
		t.Fatal("canonical IP literal host was rejected before egress-policy validation")
	}
	for _, value := range []string{"periapsis-evidence", "s3.example.com"} {
		if !validBucket(value) && value == "periapsis-evidence" {
			t.Fatalf("validBucket(%q) = false", value)
		}
		if !validHost(value) && value == "s3.example.com" {
			t.Fatalf("validHost(%q) = false", value)
		}
	}
}

type fakeS3Delete struct {
	listCalls     int
	versions      []types.ObjectVersion
	markers       []types.DeleteMarkerEntry
	deleted       []deletedVersion
	ignoreDeletes bool
	listErr       error
	deleteErr     error
}

type deletedVersion struct {
	bucket        string
	key           string
	versionID     string
	expectedOwner string
}

func (api *fakeS3Delete) ListObjectVersions(_ context.Context, input *s3.ListObjectVersionsInput, _ ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error) {
	api.listCalls++
	if api.listErr != nil {
		return nil, api.listErr
	}
	prefix := aws.ToString(input.Prefix)
	versions := make([]types.ObjectVersion, 0, len(api.versions))
	for _, version := range api.versions {
		if strings.HasPrefix(aws.ToString(version.Key), prefix) && !api.wasDeleted(version.Key, version.VersionId) {
			versions = append(versions, version)
		}
	}
	markers := make([]types.DeleteMarkerEntry, 0, len(api.markers))
	for _, marker := range api.markers {
		if strings.HasPrefix(aws.ToString(marker.Key), prefix) && !api.wasDeleted(marker.Key, marker.VersionId) {
			markers = append(markers, marker)
		}
	}
	return &s3.ListObjectVersionsOutput{
		Versions: versions, DeleteMarkers: markers, IsTruncated: aws.Bool(false),
	}, nil
}

func (api *fakeS3Delete) DeleteObject(_ context.Context, input *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	if api.deleteErr != nil {
		return nil, api.deleteErr
	}
	api.deleted = append(api.deleted, deletedVersion{
		bucket: aws.ToString(input.Bucket), key: aws.ToString(input.Key),
		versionID: aws.ToString(input.VersionId), expectedOwner: aws.ToString(input.ExpectedBucketOwner),
	})
	return &s3.DeleteObjectOutput{}, nil
}

func (api *fakeS3Delete) wasDeleted(key, versionID *string) bool {
	if api.ignoreDeletes {
		return false
	}
	for _, deleted := range api.deleted {
		if deleted.key == aws.ToString(key) && deleted.versionID == aws.ToString(versionID) {
			return true
		}
	}
	return false
}
