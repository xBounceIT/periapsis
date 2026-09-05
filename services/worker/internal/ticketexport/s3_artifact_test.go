package ticketexport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

func TestS3ArtifactStoreSealsPromotesAndPurgesWithExactConditions(t *testing.T) {
	fixture := newS3ArtifactFixture(t, 1<<20)
	api := newFakeS3ArtifactAPI()
	store := newTestS3ArtifactStore(t, api, fixture.directory)
	artifact := openS3Artifact(t, store, fixture.request)
	body := []byte("ticket,title\r\nA-1,Investigate\r\n")
	if written, err := artifact.Write(body); err != nil || written != len(body) {
		t.Fatalf("Write() = %d, %v", written, err)
	}
	localPath := artifact.localPath
	if !s3ArtifactSpoolPattern.MatchString(filepath.Base(localPath)) {
		t.Fatalf("temporary spool name is not sweepable: %q", filepath.Base(localPath))
	}
	if _, err := os.Stat(localPath); err != nil {
		t.Fatalf("temporary spool missing: %v", err)
	}
	manifest := StreamManifest{
		ArtifactID: fixture.request.ArtifactID, Digest: sha256.Sum256(body),
		Rows: 1, Bytes: uint64(len(body)),
	}
	if err := artifact.Seal(context.Background(), manifest); err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if artifact.localPath != "" {
		t.Fatalf("local path retained after seal: %q", artifact.localPath)
	}
	if _, err := os.Stat(localPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary spool still exists: %v", err)
	}
	temporaryKey, finalKey := mustS3ArtifactKeys(t, fixture.request.Binding, fixture.request.ArtifactID)
	if got := api.object(temporaryKey); !bytes.Equal(got.body, body) || got.metadata["periapsis-state"] != "temporary" {
		t.Fatalf("temporary object = %#v", got)
	}
	promotion, err := artifact.Promote(context.Background(), fixture.request.ArtifactID)
	if err != nil || promotion != PromotionApplied {
		t.Fatalf("Promote() = %s, %v", promotionName(promotion), err)
	}
	if api.has(temporaryKey) {
		t.Fatal("temporary object survived promotion")
	}
	if got := api.object(finalKey); !bytes.Equal(got.body, body) || got.metadata["periapsis-state"] != "final" {
		t.Fatalf("final object = %#v", got)
	}
	promotion, err = artifact.Promote(context.Background(), fixture.request.ArtifactID)
	if err != nil || promotion != PromotionReplayed {
		t.Fatalf("replayed Promote() = %s, %v", promotionName(promotion), err)
	}
	if err := artifact.Abort(context.Background()); err != nil || !api.has(finalKey) {
		t.Fatalf("Abort() after promotion removed final object: %v", err)
	}
	if err := artifact.Purge(context.Background(), fixture.request.ArtifactID); err != nil {
		t.Fatalf("Purge() error = %v", err)
	}
	if api.has(finalKey) || api.has(temporaryKey) {
		t.Fatal("Purge() left an object")
	}
	if err := artifact.Purge(context.Background(), fixture.request.ArtifactID); err != nil {
		t.Fatalf("replayed Purge() error = %v", err)
	}
	stats := api.snapshot()
	if stats.putCalls != 1 || stats.copyCalls != 1 || !stats.putCreateOnly ||
		!stats.copyCreateOnly || !stats.copySourceMatched || !stats.deleteConditional ||
		!stats.encrypted || !stats.checksummed || !stats.headChecksummed {
		t.Fatalf("S3 conditions = %#v", stats)
	}
}

func TestS3ArtifactStoreReconcilesExactDurableArtifactWithoutListing(t *testing.T) {
	fixture := newS3ArtifactFixture(t, 1<<20)
	api := newFakeS3ArtifactAPI()
	store := newTestS3ArtifactStore(t, api, fixture.directory)
	session := openS3Artifact(t, store, fixture.request)
	payload := []byte("id,title\n1,incident\n")
	if _, err := session.Write(payload); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	manifest := StreamManifest{
		ArtifactID: fixture.request.ArtifactID,
		Digest:     sha256.Sum256(payload),
		Rows:       1,
		Bytes:      uint64(len(payload)),
	}
	if err := session.Seal(context.Background(), manifest); err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if disposition, err := session.Promote(context.Background(), manifest.ArtifactID); err != nil || disposition != PromotionApplied {
		t.Fatalf("Promote() = (%s, %v)", promotionName(disposition), err)
	}
	temporaryKey, finalKey, err := kernel.TicketExportArtifactObjectKeys(
		fixture.request.Binding.TenantID,
		fixture.request.Binding.JobID,
		fixture.request.ArtifactID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if api.has(temporaryKey) || !api.has(finalKey) {
		t.Fatal("promotion did not leave only the canonical final object")
	}
	reconcile := reconcileArtifactFromRequest(fixture.request, manifest)
	if err := store.PurgeArtifact(context.Background(), reconcile); err != nil {
		t.Fatalf("PurgeArtifact() error = %v", err)
	}
	if api.has(temporaryKey) || api.has(finalKey) {
		t.Fatal("reconciliation retained a matching artifact object")
	}
	if !api.snapshot().deleteConditional {
		t.Fatal("reconciliation delete was not bound to the preflight ETag")
	}
	if err := store.PurgeArtifact(context.Background(), reconcile); err != nil {
		t.Fatalf("idempotent PurgeArtifact() error = %v", err)
	}
}

func TestS3ArtifactStoreReconciliationPreflightsEveryObjectBeforeDeleting(t *testing.T) {
	fixture := newS3ArtifactFixture(t, 1<<20)
	api := newFakeS3ArtifactAPI()
	store := newTestS3ArtifactStore(t, api, fixture.directory)
	session := openS3Artifact(t, store, fixture.request)
	payload := []byte("id\n1\n")
	if _, err := session.Write(payload); err != nil {
		t.Fatal(err)
	}
	manifest := StreamManifest{
		ArtifactID: fixture.request.ArtifactID,
		Digest:     sha256.Sum256(payload),
		Rows:       1,
		Bytes:      uint64(len(payload)),
	}
	if err := session.Seal(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	temporaryKey, finalKey, err := kernel.TicketExportArtifactObjectKeys(
		fixture.request.Binding.TenantID,
		fixture.request.Binding.JobID,
		fixture.request.ArtifactID,
	)
	if err != nil {
		t.Fatal(err)
	}
	temporary := api.object(temporaryKey)
	conflict := temporary
	conflict.metadata = cloneS3Metadata(temporary.metadata)
	conflict.metadata["periapsis-state"] = "untrusted"
	api.setObject(finalKey, conflict)
	if err := store.PurgeArtifact(
		context.Background(),
		reconcileArtifactFromRequest(fixture.request, manifest),
	); !errors.Is(err, ErrArtifactConflict) {
		t.Fatalf("PurgeArtifact() error = %v", err)
	}
	if !api.has(temporaryKey) || !api.has(finalKey) || api.snapshot().deleteCalls != 0 {
		t.Fatal("manifest conflict caused a partial delete")
	}
}

func TestS3ArtifactStoreReconciliationRejectsInvalidAndCanceledRequests(t *testing.T) {
	fixture := newS3ArtifactFixture(t, 100)
	store := newTestS3ArtifactStore(t, newFakeS3ArtifactAPI(), fixture.directory)
	manifest := StreamManifest{
		ArtifactID: fixture.request.ArtifactID,
		Digest:     sha256.Sum256([]byte("x")),
		Rows:       1,
		Bytes:      1,
	}
	request := reconcileArtifactFromRequest(fixture.request, manifest)
	request.Digest = [sha256.Size]byte{}
	if err := store.PurgeArtifact(context.Background(), request); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid PurgeArtifact() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request = reconcileArtifactFromRequest(fixture.request, manifest)
	if err := store.PurgeArtifact(ctx, request); !errors.Is(err, ErrInterrupted) {
		t.Fatalf("canceled PurgeArtifact() error = %v", err)
	}
	var typedNil *S3ArtifactStore
	if err := typedNil.PurgeArtifact(context.Background(), request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("typed-nil PurgeArtifact() error = %v", err)
	}
}

func TestRunOnceWithS3ArtifactStoreKeepsAttemptLifetimeAfterOpen(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{
		"": {Rows: []Row{testRow(1, RowTicket, "A-1")}},
	})
	api := newFakeS3ArtifactAPI()
	var putObservedManifest atomic.Bool
	api.putHook = func() {
		putObservedManifest.Store(repository.snapshot().manifest != nil)
	}
	store := newTestS3ArtifactStore(t, api, t.TempDir())
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if err != nil || result.Outcome != OutcomeSucceeded || result.Rows != 1 {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	snapshot := repository.snapshot()
	_, finalKey := mustS3ArtifactKeys(t, LeaseBinding{
		TenantID: fixture.tenant, JobID: fixture.jobID,
	}, snapshot.artifactID)
	if !api.has(finalKey) || !putObservedManifest.Load() {
		t.Fatal("worker canceled the storage lifetime before publication")
	}
}

func TestS3ArtifactStoreReconcilesAmbiguousPutCopyAndDelete(t *testing.T) {
	for _, test := range []struct {
		name       string
		configure  func(*fakeS3ArtifactAPI)
		firstError bool
	}{
		{name: "put response lost", configure: func(api *fakeS3ArtifactAPI) { api.putErrorAfterApply = errors.New("raw put secret") }},
		{name: "copy response lost", configure: func(api *fakeS3ArtifactAPI) { api.copyErrorAfterApply = errors.New("raw copy secret") }},
		{name: "delete response lost", configure: func(api *fakeS3ArtifactAPI) { api.deleteErrorAfterApply = errors.New("raw delete secret") }, firstError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newS3ArtifactFixture(t, 1<<20)
			api := newFakeS3ArtifactAPI()
			test.configure(api)
			store := newTestS3ArtifactStore(t, api, fixture.directory)
			artifact := openS3Artifact(t, store, fixture.request)
			body := []byte("ticket\r\nA-1\r\n")
			_, _ = artifact.Write(body)
			manifest := StreamManifest{
				ArtifactID: fixture.request.ArtifactID, Digest: sha256.Sum256(body),
				Rows: 1, Bytes: uint64(len(body)),
			}
			if err := artifact.Seal(context.Background(), manifest); err != nil {
				t.Fatalf("Seal() error = %v", err)
			}
			promotion, err := artifact.Promote(context.Background(), fixture.request.ArtifactID)
			if test.firstError {
				if !errors.Is(err, ErrUnavailable) || promotion != PromotionRejected {
					t.Fatalf("first Promote() = %s, %v", promotionName(promotion), err)
				}
				api.deleteErrorAfterApply = nil
				promotion, err = artifact.Promote(context.Background(), fixture.request.ArtifactID)
				if err != nil || promotion != PromotionReplayed {
					t.Fatalf("reconciled Promote() = %s, %v", promotionName(promotion), err)
				}
			} else if err != nil || promotion != PromotionApplied {
				t.Fatalf("Promote() = %s, %v", promotionName(promotion), err)
			}
			_, finalKey := mustS3ArtifactKeys(t, fixture.request.Binding, fixture.request.ArtifactID)
			if !api.has(finalKey) {
				t.Fatal("reconciliation lost final object")
			}
		})
	}
}

func TestS3ArtifactStoreNeverDeletesCollidingObjects(t *testing.T) {
	fixture := newS3ArtifactFixture(t, 1<<20)
	api := newFakeS3ArtifactAPI()
	store := newTestS3ArtifactStore(t, api, fixture.directory)
	artifact := openS3Artifact(t, store, fixture.request)
	body := []byte("ticket\r\nA-1\r\n")
	_, _ = artifact.Write(body)
	manifest := StreamManifest{
		ArtifactID: fixture.request.ArtifactID, Digest: sha256.Sum256(body),
		Rows: 1, Bytes: uint64(len(body)),
	}
	if err := artifact.Seal(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	temporaryKey, finalKey := mustS3ArtifactKeys(t, fixture.request.Binding, fixture.request.ArtifactID)
	collision := fakeS3Object{
		body: []byte("another tenant object"), metadata: map[string]string{"owner": "other"},
		contentType: "application/octet-stream", encryption: types.ServerSideEncryptionAes256,
		etag: "\"collision\"",
	}
	api.setObject(finalKey, collision)
	promotion, err := artifact.Promote(context.Background(), fixture.request.ArtifactID)
	if err != nil || promotion != PromotionRejected {
		t.Fatalf("Promote() = %s, %v", promotionName(promotion), err)
	}
	if err := artifact.Abort(context.Background()); err != nil {
		t.Fatalf("Abort() error = %v", err)
	}
	if api.has(temporaryKey) {
		t.Fatal("owned temporary object survived abort")
	}
	if got := api.object(finalKey); !bytes.Equal(got.body, collision.body) {
		t.Fatal("Abort() deleted or replaced colliding final object")
	}
	if err := artifact.Purge(context.Background(), fixture.request.ArtifactID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Purge() collision error = %v", err)
	}
	if got := api.object(finalKey); !bytes.Equal(got.body, collision.body) {
		t.Fatal("Purge() deleted colliding final object")
	}
}

func TestS3ArtifactStoreRejectsExactMetadataWithDifferentObjectChecksum(t *testing.T) {
	fixture := newS3ArtifactFixture(t, 1<<20)
	api := newFakeS3ArtifactAPI()
	store := newTestS3ArtifactStore(t, api, fixture.directory)
	artifact := openS3Artifact(t, store, fixture.request)
	body := []byte("ticket\r\nA-1\r\n")
	_, _ = artifact.Write(body)
	manifest := StreamManifest{
		ArtifactID: fixture.request.ArtifactID, Digest: sha256.Sum256(body),
		Rows: 1, Bytes: uint64(len(body)),
	}
	if err := artifact.Seal(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	temporaryKey, finalKey := mustS3ArtifactKeys(t, fixture.request.Binding, fixture.request.ArtifactID)
	collision := api.object(temporaryKey)
	collision.metadata = artifact.metadata(manifest, "final")
	collision.body = bytes.Repeat([]byte{'x'}, len(body))
	collisionDigest := sha256.Sum256(collision.body)
	collision.checksum = base64.StdEncoding.EncodeToString(collisionDigest[:])
	collision.etag = fmt.Sprintf("\"%x\"", collisionDigest[:16])
	api.setObject(finalKey, collision)

	promotion, err := artifact.Promote(context.Background(), fixture.request.ArtifactID)
	if err != nil || promotion != PromotionRejected {
		t.Fatalf("Promote() = %s, %v", promotionName(promotion), err)
	}
	if !api.has(temporaryKey) || !api.has(finalKey) || api.snapshot().copyCalls != 0 {
		t.Fatal("checksum collision was copied over or caused owned temporary deletion")
	}
	if err := artifact.Purge(context.Background(), fixture.request.ArtifactID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Purge() collision error = %v", err)
	}
	if !api.has(finalKey) {
		t.Fatal("Purge() deleted checksum-mismatched final object")
	}
}

func TestS3ArtifactStoreNeverDeletesManifestWithDifferentAttemptBinding(t *testing.T) {
	fixture := newS3ArtifactFixture(t, 1<<20)
	api := newFakeS3ArtifactAPI()
	store := newTestS3ArtifactStore(t, api, fixture.directory)
	artifact := openS3Artifact(t, store, fixture.request)
	body := []byte("ticket\r\nA-1\r\n")
	_, _ = artifact.Write(body)
	manifest := StreamManifest{
		ArtifactID: fixture.request.ArtifactID, Digest: sha256.Sum256(body),
		Rows: 1, Bytes: uint64(len(body)),
	}
	if err := artifact.Seal(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	temporaryKey, finalKey := mustS3ArtifactKeys(t, fixture.request.Binding, fixture.request.ArtifactID)
	collision := api.object(temporaryKey)
	collision.metadata = artifact.metadata(manifest, "final")
	collision.metadata["periapsis-revision"] = "999"
	api.setObject(finalKey, collision)

	promotion, err := artifact.Promote(context.Background(), fixture.request.ArtifactID)
	if err != nil || promotion != PromotionRejected {
		t.Fatalf("Promote() = %s, %v", promotionName(promotion), err)
	}
	if !api.has(temporaryKey) || !api.has(finalKey) || api.snapshot().copyCalls != 0 {
		t.Fatal("binding collision was copied over or caused owned temporary deletion")
	}
	if err := artifact.Purge(context.Background(), fixture.request.ArtifactID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Purge() collision error = %v", err)
	}
	if !api.has(finalKey) {
		t.Fatal("Purge() deleted a differently bound final object")
	}
}

func TestS3ArtifactStorePreservesUnknownTemporaryCollision(t *testing.T) {
	fixture := newS3ArtifactFixture(t, 1<<20)
	api := newFakeS3ArtifactAPI()
	store := newTestS3ArtifactStore(t, api, fixture.directory)
	temporaryKey, _ := mustS3ArtifactKeys(t, fixture.request.Binding, fixture.request.ArtifactID)
	collision := fakeS3Object{
		body: []byte("foreign"), metadata: map[string]string{"owner": "foreign"},
		contentType: "application/octet-stream", encryption: types.ServerSideEncryptionAes256,
		etag: "\"foreign\"",
	}
	api.setObject(temporaryKey, collision)
	artifact := openS3Artifact(t, store, fixture.request)
	body := []byte("ticket\r\n")
	_, _ = artifact.Write(body)
	manifest := StreamManifest{
		ArtifactID: fixture.request.ArtifactID, Digest: sha256.Sum256(body), Bytes: uint64(len(body)),
	}
	if err := artifact.Seal(context.Background(), manifest); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Seal() collision error = %v", err)
	}
	if err := artifact.Abort(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Abort() collision error = %v", err)
	}
	if got := api.object(temporaryKey); !bytes.Equal(got.body, collision.body) {
		t.Fatal("collision was deleted")
	}
}

func TestS3ArtifactStoreBoundsAndPoisonsLocalStreamBeforeUpload(t *testing.T) {
	fixture := newS3ArtifactFixture(t, 4)
	api := newFakeS3ArtifactAPI()
	artifact := openS3Artifact(t, newTestS3ArtifactStore(t, api, fixture.directory), fixture.request)
	if written, err := artifact.Write([]byte("12345")); written != 0 || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("oversized Write() = %d, %v", written, err)
	}
	if written, err := artifact.Write([]byte("1")); written != 0 || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("poisoned Write() = %d, %v", written, err)
	}
	manifest := StreamManifest{
		ArtifactID: fixture.request.ArtifactID, Digest: sha256.Sum256(nil), Bytes: 1,
	}
	if err := artifact.Seal(context.Background(), manifest); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Seal() error = %v", err)
	}
	if api.snapshot().putCalls != 0 {
		t.Fatal("poisoned stream reached S3")
	}
	if err := artifact.Abort(context.Background()); err != nil {
		t.Fatalf("Abort() error = %v", err)
	}
}

func TestS3ArtifactStoreEnforcesAudienceRowLimitAtSeal(t *testing.T) {
	fixture := newS3ArtifactFixture(t, 100)
	fixture.request.Binding.Audience = kernel.TicketExportAudienceCustomer
	fixture.request.MaximumBytes = kernel.TicketExportCustomerMaximumBytes
	api := newFakeS3ArtifactAPI()
	artifact := openS3Artifact(
		t, newTestS3ArtifactStore(t, api, fixture.directory), fixture.request,
	)
	body := []byte("ticket\r\n")
	_, _ = artifact.Write(body)
	manifest := StreamManifest{
		ArtifactID: fixture.request.ArtifactID, Digest: sha256.Sum256(body),
		Rows: kernel.TicketExportCustomerMaximumRows + 1, Bytes: uint64(len(body)),
	}
	if err := artifact.Seal(context.Background(), manifest); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Seal() customer row bound error = %v", err)
	}
	if api.snapshot().putCalls != 0 {
		t.Fatal("over-limit customer export reached S3")
	}
	if err := artifact.Abort(context.Background()); err != nil {
		t.Fatalf("Abort() error = %v", err)
	}
}

func TestS3ArtifactStoreLifetimeCancellationStopsWrites(t *testing.T) {
	fixture := newS3ArtifactFixture(t, 100)
	api := newFakeS3ArtifactAPI()
	store := newTestS3ArtifactStore(t, api, fixture.directory)
	ctx, cancel := context.WithCancel(context.Background())
	session, err := store.OpenTemporary(context.Background(), ctx, fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	artifact := session.(*s3TemporaryArtifact)
	cancel()
	if written, err := artifact.Write([]byte("ticket")); written != 0 || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Write() after cancellation = %d, %v", written, err)
	}
	if err := artifact.Abort(context.Background()); err != nil {
		t.Fatalf("Abort() error = %v", err)
	}
}

func TestS3ArtifactStoreOpenDeadlineDoesNotOwnWriterLifetime(t *testing.T) {
	fixture := newS3ArtifactFixture(t, 100)
	store := newTestS3ArtifactStore(t, newFakeS3ArtifactAPI(), fixture.directory)
	openContext, cancelOpen := context.WithCancel(context.Background())
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	t.Cleanup(cancelLifetime)
	session, err := store.OpenTemporary(openContext, lifetime, fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	artifact := session.(*s3TemporaryArtifact)
	cancelOpen()
	if written, err := artifact.Write([]byte("ticket")); err != nil || written != len("ticket") {
		t.Fatalf("Write() after open cancellation = %d, %v", written, err)
	}
	if err := artifact.Abort(context.Background()); err != nil {
		t.Fatalf("Abort() error = %v", err)
	}
}

func TestS3ArtifactStoreRetriesTransientLocalSpoolRemoval(t *testing.T) {
	fixture := newS3ArtifactFixture(t, 100)
	store := newTestS3ArtifactStore(t, newFakeS3ArtifactAPI(), fixture.directory)
	artifact := openS3Artifact(t, store, fixture.request)
	localPath := artifact.localPath
	removeCalls := 0
	store.removeFile = func(path string) error {
		removeCalls++
		if removeCalls == 1 {
			return errors.New("transient local filesystem failure")
		}
		return os.Remove(path)
	}
	if err := artifact.Abort(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("first Abort() error = %v", err)
	}
	if artifact.localPath != localPath {
		t.Fatal("failed removal discarded the only retryable local path")
	}
	if err := artifact.Abort(context.Background()); err != nil {
		t.Fatalf("second Abort() error = %v", err)
	}
	if artifact.localPath != "" || removeCalls != 2 {
		t.Fatalf("local cleanup path = %q, calls = %d", artifact.localPath, removeCalls)
	}
}

func TestS3ArtifactStoreSweepsCrashSpoolsBoundedlyAndRetryably(t *testing.T) {
	fixture := newS3ArtifactFixture(t, 100)
	store := newTestS3ArtifactStore(t, newFakeS3ArtifactAPI(), fixture.directory)
	active := openS3Artifact(t, store, fixture.request)
	activePath := active.localPath
	oldPath := filepath.Join(fixture.directory, ".ticket-export-111.partial")
	recentPath := filepath.Join(fixture.directory, ".ticket-export-222.partial")
	foreignPath := filepath.Join(fixture.directory, "foreign-customer-file")
	for _, path := range []string{oldPath, recentPath, foreignPath} {
		if err := os.WriteFile(path, []byte("sensitive"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cutoff := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
	oldTime := cutoff.Add(-time.Hour)
	for _, path := range []string{oldPath, activePath} {
		if err := os.Chtimes(path, oldTime, oldTime); err != nil {
			t.Fatal(err)
		}
	}
	removeCalls := 0
	store.removeFile = func(path string) error {
		if path == oldPath {
			removeCalls++
			if removeCalls == 1 {
				return errors.New("transient local cleanup failure")
			}
		}
		return os.Remove(path)
	}
	first, err := store.SweepSpoolsBefore(context.Background(), cutoff, 10)
	if !errors.Is(err, ErrCleanupPending) || !first.Remaining || first.Removed != 0 {
		t.Fatalf("first sweep = %#v, %v", first, err)
	}
	second, err := store.SweepSpoolsBefore(context.Background(), cutoff, 10)
	if err != nil || second.Remaining || second.Removed != 1 || removeCalls != 2 {
		t.Fatalf("second sweep = %#v, %v, calls=%d", second, err, removeCalls)
	}
	if _, err := os.Stat(oldPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old spool survived: %v", err)
	}
	for _, path := range []string{recentPath, foreignPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("sweep removed non-stale/non-owned file %q: %v", path, err)
		}
	}
	if _, err := os.Stat(activePath); err != nil {
		t.Fatalf("sweep removed an active spool: %v", err)
	}
	if err := active.Abort(context.Background()); err != nil {
		t.Fatalf("active Abort() error = %v", err)
	}
	bounded, err := store.SweepSpoolsBefore(context.Background(), cutoff, 1)
	if err != nil || bounded.Examined != 1 || !bounded.Remaining {
		t.Fatalf("bounded sweep = %#v, %v", bounded, err)
	}
	unsafeCutoff := time.Now().UTC().Truncate(time.Microsecond).Add(-MinimumSpoolSweepAge + time.Minute)
	if _, err := store.SweepSpoolsBefore(context.Background(), unsafeCutoff, 10); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unsafe cutoff error = %v", err)
	}
}

func TestS3ArtifactStoreRejectsInvalidConfigurationAndRequests(t *testing.T) {
	fixture := newS3ArtifactFixture(t, 100)
	api := newFakeS3ArtifactAPI()
	typedNil := (*fakeS3ArtifactAPI)(nil)
	for _, test := range []struct {
		name    string
		api     s3ArtifactAPI
		options S3ArtifactOptions
	}{
		{name: "nil api", options: validS3ArtifactOptions(fixture.directory)},
		{name: "typed nil api", api: typedNil, options: validS3ArtifactOptions(fixture.directory)},
		{name: "invalid bucket", api: api, options: S3ArtifactOptions{Bucket: "127.0.0.1", TemporaryDirectory: fixture.directory}},
		{name: "relative directory", api: api, options: S3ArtifactOptions{Bucket: "periapsis-exports", TemporaryDirectory: "tmp"}},
		{name: "invalid owner", api: api, options: S3ArtifactOptions{Bucket: "periapsis-exports", ExpectedBucketOwner: "123", TemporaryDirectory: fixture.directory}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewS3ArtifactStore(test.api, test.options); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("NewS3ArtifactStore() error = %v", err)
			}
		})
	}
	store := newTestS3ArtifactStore(t, api, fixture.directory)
	invalid := fixture.request
	invalid.Binding.WorkerID = testEntityID(t, 99)
	if _, err := store.OpenTemporary(context.Background(), context.Background(), invalid); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("OpenTemporary() error = %v", err)
	}
	invalid = fixture.request
	invalid.Binding.Audience = kernel.TicketExportAudienceCustomer
	invalid.MaximumBytes = kernel.TicketExportCustomerMaximumBytes + 1
	if _, err := store.OpenTemporary(context.Background(), context.Background(), invalid); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("OpenTemporary() customer bound error = %v", err)
	}
	invalid = fixture.request
	invalid.Binding.Attempt = kernel.TicketExportMaximumAttempts + 1
	if _, err := store.OpenTemporary(context.Background(), context.Background(), invalid); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("OpenTemporary() attempt bound error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.OpenTemporary(ctx, context.Background(), fixture.request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("OpenTemporary() canceled error = %v", err)
	}
	if _, err := store.OpenTemporary(context.Background(), ctx, fixture.request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("OpenTemporary() canceled lifetime error = %v", err)
	}
}

func TestS3ArtifactStoreReadinessPinsBucketAndOwnerAndFailsClosed(t *testing.T) {
	fixture := newS3ArtifactFixture(t, 100)
	api := newFakeS3ArtifactAPI()
	store := newTestS3ArtifactStore(t, api, fixture.directory)
	if err := store.Check(context.Background()); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	snapshot := api.snapshot()
	if snapshot.headBucketCalls != 1 || !snapshot.headBucketMatched {
		t.Fatalf("HeadBucket readiness = %#v", snapshot)
	}
	api.headBucketError = errors.New("provider detail")
	if err := store.Check(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("failed Check() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.Check(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("canceled Check() error = %v", err)
	}
	var typedNil *S3ArtifactStore
	if err := typedNil.Check(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("typed-nil Check() error = %v", err)
	}
}

func TestS3ArtifactDiagnosticsRedactLocationsAndIdentities(t *testing.T) {
	fixture := newS3ArtifactFixture(t, 100)
	store := newTestS3ArtifactStore(t, newFakeS3ArtifactAPI(), fixture.directory)
	artifact := openS3Artifact(t, store, fixture.request)
	diagnostic := fmt.Sprintf("%s %#v %s %#v", store, store, artifact, artifact)
	for _, sensitive := range []string{
		fixture.request.Binding.TenantID.String(), fixture.request.Binding.JobID.String(),
		fixture.request.ArtifactID.String(), fixture.directory, store.bucket,
	} {
		if strings.Contains(diagnostic, sensitive) {
			t.Fatalf("diagnostic leaked %q: %s", sensitive, diagnostic)
		}
	}
	_ = artifact.Abort(context.Background())
}

type s3ArtifactFixture struct {
	directory string
	request   TemporaryRequest
}

func newS3ArtifactFixture(t *testing.T, maximumBytes uint64) s3ArtifactFixture {
	t.Helper()
	fixture := newWorkerFixture(
		t, kernel.TicketExportAudienceOperator, 100, kernel.TicketExportOperatorMaximumBytes,
	)
	fence := sha256.Sum256([]byte("s3-artifact-fence"))
	claimPlan, err := kernel.PlanTicketExportClaim(
		fixture.pendingJob, fixture.identity.WorkerID, fence,
		fixture.now, fixture.now.Add(5*time.Minute),
	)
	if err != nil {
		t.Fatalf("PlanTicketExportClaim() error = %v", err)
	}
	job := claimPlan.Next()
	definition := job.Definition()
	lease := job.Lease()
	return s3ArtifactFixture{
		directory: t.TempDir(),
		request: TemporaryRequest{
			Identity: fixture.identity,
			Binding: LeaseBinding{
				TenantID: definition.Tenant(), JobID: definition.ID(), Kind: definition.Kind(),
				Audience: definition.Audience(), WorkerID: lease.Worker(), Revision: job.Revision(),
				Attempt: job.Attempts(), Fence: lease.Fence(), QueryDigest: definition.QueryDigest(),
				CatalogDigest: definition.CatalogDigest(), ProjectionVersion: definition.ProjectionVersion(),
				LeaseClaimedAt: lease.ClaimedAt(), LeaseExpiresAt: lease.ExpiresAt(),
				JobExpiresAt: job.ExpiresAt(),
			},
			ArtifactID: testArtifactID(120), MaximumBytes: maximumBytes,
		},
	}
}

func reconcileArtifactFromRequest(
	request TemporaryRequest,
	manifest StreamManifest,
) ReconcileArtifact {
	return ReconcileArtifact{
		TenantID:          request.Binding.TenantID,
		JobID:             request.Binding.JobID,
		ArtifactID:        manifest.ArtifactID,
		Kind:              request.Binding.Kind,
		Audience:          request.Binding.Audience,
		ObjectRevision:    request.Binding.Revision,
		ObjectAttempt:     request.Binding.Attempt,
		ProjectionVersion: request.Binding.ProjectionVersion,
		Digest:            manifest.Digest,
		Rows:              manifest.Rows,
		Bytes:             manifest.Bytes,
	}
}

func validS3ArtifactOptions(directory string) S3ArtifactOptions {
	return S3ArtifactOptions{
		Bucket: "periapsis-exports", ExpectedBucketOwner: "123456789012",
		TemporaryDirectory: directory,
	}
}

func newTestS3ArtifactStore(t *testing.T, api s3ArtifactAPI, directory string) *S3ArtifactStore {
	t.Helper()
	store, err := NewS3ArtifactStore(api, validS3ArtifactOptions(directory))
	if err != nil {
		t.Fatalf("NewS3ArtifactStore() error = %v", err)
	}
	return store
}

func openS3Artifact(
	t *testing.T,
	store *S3ArtifactStore,
	request TemporaryRequest,
) *s3TemporaryArtifact {
	t.Helper()
	session, err := store.OpenTemporary(context.Background(), context.Background(), request)
	if err != nil {
		t.Fatalf("OpenTemporary() error = %v", err)
	}
	artifact, ok := session.(*s3TemporaryArtifact)
	if !ok {
		t.Fatalf("OpenTemporary() type = %T", session)
	}
	return artifact
}

func promotionName(value PromotionDisposition) string {
	switch value {
	case PromotionApplied:
		return "applied"
	case PromotionReplayed:
		return "replayed"
	case PromotionRejected:
		return "rejected"
	default:
		return "unknown"
	}
}

type fakeS3Object struct {
	body        []byte
	metadata    map[string]string
	contentType string
	encryption  types.ServerSideEncryption
	etag        string
	checksum    string
}

type fakeS3ArtifactSnapshot struct {
	headBucketCalls   int
	headBucketMatched bool
	putCalls          int
	copyCalls         int
	deleteCalls       int
	putCreateOnly     bool
	copyCreateOnly    bool
	copySourceMatched bool
	deleteConditional bool
	encrypted         bool
	checksummed       bool
	headChecksummed   bool
}

type fakeS3ArtifactAPI struct {
	mu                    sync.Mutex
	objects               map[string]fakeS3Object
	putErrorAfterApply    error
	copyErrorAfterApply   error
	deleteErrorAfterApply error
	headBucketError       error
	putHook               func()
	stats                 fakeS3ArtifactSnapshot
}

func newFakeS3ArtifactAPI() *fakeS3ArtifactAPI {
	return &fakeS3ArtifactAPI{objects: make(map[string]fakeS3Object)}
}

func (api *fakeS3ArtifactAPI) HeadBucket(
	_ context.Context,
	input *s3.HeadBucketInput,
	_ ...func(*s3.Options),
) (*s3.HeadBucketOutput, error) {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.stats.headBucketCalls++
	api.stats.headBucketMatched = aws.ToString(input.Bucket) == "periapsis-exports" &&
		aws.ToString(input.ExpectedBucketOwner) == "123456789012"
	if api.headBucketError != nil {
		return nil, api.headBucketError
	}
	return &s3.HeadBucketOutput{}, nil
}

func (api *fakeS3ArtifactAPI) PutObject(
	_ context.Context,
	input *s3.PutObjectInput,
	_ ...func(*s3.Options),
) (*s3.PutObjectOutput, error) {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.stats.putCalls++
	if api.putHook != nil {
		api.putHook()
	}
	key := aws.ToString(input.Key)
	if aws.ToString(input.IfNoneMatch) == "*" {
		api.stats.putCreateOnly = true
	}
	if _, exists := api.objects[key]; exists {
		return nil, s3TestAPIError("PreconditionFailed")
	}
	body, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, err
	}
	if input.ServerSideEncryption == types.ServerSideEncryptionAes256 {
		api.stats.encrypted = true
	}
	digest := sha256.Sum256(body)
	expectedChecksum := base64.StdEncoding.EncodeToString(digest[:])
	if input.ChecksumAlgorithm == types.ChecksumAlgorithmSha256 &&
		aws.ToString(input.ChecksumSHA256) == expectedChecksum {
		api.stats.checksummed = true
	} else {
		return nil, errors.New("invalid checksum")
	}
	api.objects[key] = fakeS3Object{
		body: append([]byte(nil), body...), metadata: cloneS3Metadata(input.Metadata),
		contentType: aws.ToString(input.ContentType), encryption: input.ServerSideEncryption,
		etag: fmt.Sprintf("\"%x\"", digest[:16]), checksum: base64.StdEncoding.EncodeToString(digest[:]),
	}
	return &s3.PutObjectOutput{}, api.putErrorAfterApply
}

func (api *fakeS3ArtifactAPI) HeadObject(
	_ context.Context,
	input *s3.HeadObjectInput,
	_ ...func(*s3.Options),
) (*s3.HeadObjectOutput, error) {
	api.mu.Lock()
	defer api.mu.Unlock()
	if input.ChecksumMode == types.ChecksumModeEnabled {
		api.stats.headChecksummed = true
	}
	object, exists := api.objects[aws.ToString(input.Key)]
	if !exists {
		return nil, s3TestAPIError("NotFound")
	}
	return &s3.HeadObjectOutput{
		ContentLength: aws.Int64(int64(len(object.body))), ContentType: aws.String(object.contentType),
		Metadata: cloneS3Metadata(object.metadata), ServerSideEncryption: object.encryption,
		ETag: aws.String(object.etag), ChecksumSHA256: aws.String(object.checksum),
	}, nil
}

func (api *fakeS3ArtifactAPI) CopyObject(
	_ context.Context,
	input *s3.CopyObjectInput,
	_ ...func(*s3.Options),
) (*s3.CopyObjectOutput, error) {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.stats.copyCalls++
	if aws.ToString(input.IfNoneMatch) == "*" {
		api.stats.copyCreateOnly = true
	}
	encodedSource := aws.ToString(input.CopySource)
	decodedSource, err := url.PathUnescape(encodedSource)
	if err != nil {
		return nil, err
	}
	_, sourceKey, ok := strings.Cut(decodedSource, "/")
	if !ok {
		return nil, errors.New("invalid copy source")
	}
	source, exists := api.objects[sourceKey]
	if !exists || aws.ToString(input.CopySourceIfMatch) != source.etag {
		return nil, s3TestAPIError("PreconditionFailed")
	}
	api.stats.copySourceMatched = true
	destination := aws.ToString(input.Key)
	if _, exists := api.objects[destination]; exists {
		return nil, s3TestAPIError("PreconditionFailed")
	}
	api.objects[destination] = fakeS3Object{
		body: append([]byte(nil), source.body...), metadata: cloneS3Metadata(input.Metadata),
		contentType: aws.ToString(input.ContentType), encryption: input.ServerSideEncryption,
		etag: source.etag, checksum: source.checksum,
	}
	return &s3.CopyObjectOutput{}, api.copyErrorAfterApply
}

func (api *fakeS3ArtifactAPI) DeleteObject(
	_ context.Context,
	input *s3.DeleteObjectInput,
	_ ...func(*s3.Options),
) (*s3.DeleteObjectOutput, error) {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.stats.deleteCalls++
	key := aws.ToString(input.Key)
	object, exists := api.objects[key]
	if exists && aws.ToString(input.IfMatch) != object.etag {
		return nil, s3TestAPIError("PreconditionFailed")
	}
	if input.IfMatch != nil {
		api.stats.deleteConditional = true
	}
	delete(api.objects, key)
	return &s3.DeleteObjectOutput{}, api.deleteErrorAfterApply
}

func (api *fakeS3ArtifactAPI) has(key string) bool {
	api.mu.Lock()
	defer api.mu.Unlock()
	_, exists := api.objects[key]
	return exists
}

func (api *fakeS3ArtifactAPI) object(key string) fakeS3Object {
	api.mu.Lock()
	defer api.mu.Unlock()
	return cloneS3Object(api.objects[key])
}

func (api *fakeS3ArtifactAPI) setObject(key string, object fakeS3Object) {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.objects[key] = cloneS3Object(object)
}

func (api *fakeS3ArtifactAPI) snapshot() fakeS3ArtifactSnapshot {
	api.mu.Lock()
	defer api.mu.Unlock()
	return api.stats
}

func cloneS3Object(value fakeS3Object) fakeS3Object {
	value.body = append([]byte(nil), value.body...)
	value.metadata = cloneS3Metadata(value.metadata)
	return value
}

func cloneS3Metadata(value map[string]string) map[string]string {
	result := make(map[string]string, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func mustS3ArtifactKeys(
	t *testing.T,
	binding LeaseBinding,
	artifactID kernel.EntityID,
) (string, string) {
	t.Helper()
	temporary, final, err := kernel.TicketExportArtifactObjectKeys(
		binding.TenantID,
		binding.JobID,
		artifactID,
	)
	if err != nil {
		t.Fatal(err)
	}
	return temporary, final
}

func s3TestAPIError(code string) error {
	return &smithy.GenericAPIError{Code: code, Message: "redacted test failure"}
}
