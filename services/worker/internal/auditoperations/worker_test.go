package auditoperations

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestWorkerMaterializesRedactedExportAndDeletesRevokedArtifact(t *testing.T) {
	for _, finalState := range []string{"succeeded", "authorization_revoked"} {
		t.Run(finalState, func(t *testing.T) {
			jobID := mustV7(t)
			tenantID := mustV7(t)
			store := &memoryStore{}
			repository := &fakeRepository{}
			repository.claim = func(stream Stream, id uuid.UUID, fence [32]byte) (ExportClaim, bool, error) {
				if stream == PlatformStream {
					return ExportClaim{}, false, nil
				}
				return ExportClaim{
					Stream: stream, TenantID: tenantID, JobID: jobID, WorkerID: id, Fence: fence,
					NormalizedFilter: json.RawMessage(`{}`), ProjectionVersion: 1, Format: "jsonl",
					ObjectKey: "tenants/" + tenantID.String() + "/audit/exports/" + jobID.String() + "/v1.jsonl",
					ExpiresAt: time.Now().Add(time.Hour), LeaseExpiresAt: time.Now().Add(5 * time.Minute),
				}, true, nil
			}
			repository.exportPage = func(claim ExportClaim, after int64) ([]PageRow, error) {
				if after != 0 {
					return nil, nil
				}
				return []PageRow{{Sequence: 1, Document: testProjection(TenantStream, tenantID, 1, nil)}}, nil
			}
			repository.finalState = finalState
			worker := newTestWorker(t, repository, store, testSigner{})
			summary, err := worker.RunOnce(context.Background())
			if err != nil {
				t.Fatalf("RunOnce() error = %v", err)
			}
			if summary.ExportsClaimed != 1 || store.puts != 1 {
				t.Fatalf("summary/store = %#v/%#v", summary, store)
			}
			if finalState == "succeeded" && (summary.ExportsSucceeded != 1 || store.deletes != 0) {
				t.Fatalf("successful export = %#v/%#v", summary, store)
			}
			if finalState == "authorization_revoked" && (summary.ExportsDiscarded != 1 || store.deletes != 1) {
				t.Fatalf("revoked export = %#v/%#v", summary, store)
			}
		})
	}
}

func TestWorkerPreservesVerifiesAndPrunesSignedSegment(t *testing.T) {
	tenantID := mustV7(t)
	segment := Segment{
		Stream: TenantStream, TenantID: tenantID, ID: mustV7(t), State: "closed", Revision: 1,
		Start: 1, End: 1, PreviousHash: zeroHash(), EndHash: hashText('a'), EventCount: 1,
	}
	segment.ObjectKey = "tenants/" + tenantID.String() + "/audit/segments/1-1/" + segment.ID.String() + ".jsonl"
	repository := &fakeRepository{tenantCandidates: []uuid.UUID{tenantID}, retentionWork: segment}
	repository.retentionPage = func(_ Segment, after int64) ([]PageRow, error) {
		if after != 0 {
			return nil, nil
		}
		return []PageRow{{Sequence: 1, Document: testProjection(TenantStream, tenantID, 1, nil)}}, nil
	}
	signer := ephemeralSigner(t)
	store := &memoryStore{}
	worker := newTestWorker(t, repository, store, signer)
	summary, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if summary.SegmentsPreserved != 1 || summary.SegmentsPruned != 1 ||
		repository.preserved != 1 || repository.pruned != 1 || store.verifies != 1 {
		t.Fatalf("retention summary = %#v repo=%#v store=%#v", summary, repository, store)
	}
	if store.last.Signature == ([64]byte{}) || !signer.Verify(
		segment, store.last.Digest, store.last.Bytes, store.last.Signature,
	) {
		t.Fatal("preserved segment signature was not bound to the artifact")
	}
}

func TestProjectionRejectsNestedCredentialKeys(t *testing.T) {
	tenantID := mustV7(t)
	document := testProjection(TenantStream, tenantID, 1, map[string]any{
		"nested": map[string]any{"password": "not-redacted"},
	})
	if _, err := canonicalProjection(document, TenantStream, tenantID, 1); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("canonicalProjection() error = %v", err)
	}
}

func TestLoadEd25519SignerUsesEphemeralPKCS8FileAndBindsEveryField(t *testing.T) {
	signer := ephemeralSigner(t)
	segment := Segment{
		Stream: PlatformStream, ID: mustV7(t), State: "closed", Revision: 1,
		Start: 4, End: 5, PreviousHash: hashText('a'), EndHash: hashText('b'), EventCount: 2,
	}
	segment.ObjectKey = "platform/audit/segments/4-5/" + segment.ID.String() + ".jsonl"
	digest := [32]byte{1, 2, 3}
	signature, err := signer.Sign(segment, digest, 123)
	if err != nil || !signer.Verify(segment, digest, 123, signature) {
		t.Fatalf("sign/verify = %v", err)
	}
	tampered := segment
	tampered.End++
	if signer.Verify(tampered, digest, 123, signature) || signer.String() != "auditoperations.Ed25519Signer{[REDACTED]}" {
		t.Fatal("signature accepted a tampered segment or exposed key diagnostics")
	}
}

func ephemeralSigner(t *testing.T) *Ed25519Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "audit-retention-signing.pem")
	document := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := LoadEd25519Signer(path, "test-ed25519-v1")
	if err != nil {
		t.Fatalf("LoadEd25519Signer() error = %v", err)
	}
	return signer
}

func newTestWorker(t *testing.T, repository Repository, store ArtifactStore, signer SegmentSigner) *Worker {
	t.Helper()
	worker, err := New(Options{
		Repository: repository, Artifacts: store, Signer: signer, WorkerID: mustV7(t),
		PageSize: 2, TenantBatch: 10, RetentionRows: 10, ReceiptBatch: 10,
		LeaseDuration: 10 * time.Minute, OperationTimeout: time.Second,
		SpoolDirectory: t.TempDir(), NewID: uuid.NewV7,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return worker
}

type fakeRepository struct {
	claim            func(Stream, uuid.UUID, [32]byte) (ExportClaim, bool, error)
	exportPage       func(ExportClaim, int64) ([]PageRow, error)
	finalState       string
	tenantCandidates []uuid.UUID
	retentionWork    Segment
	retentionPage    func(Segment, int64) ([]PageRow, error)
	preserved        int
	pruned           int
}

func (repository *fakeRepository) ClaimExport(_ context.Context, stream Stream, workerID uuid.UUID,
	fence [32]byte, _ time.Duration, _ uuid.UUID) (ExportClaim, bool, error) {
	if repository.claim == nil {
		return ExportClaim{}, false, nil
	}
	return repository.claim(stream, workerID, fence)
}
func (repository *fakeRepository) ReadExportPage(_ context.Context, claim ExportClaim, after int64, _ int) ([]PageRow, error) {
	return repository.exportPage(claim, after)
}
func (repository *fakeRepository) FinalizeExport(_ context.Context, _ ExportClaim, _ uuid.UUID,
	_ [32]byte, _, _ int64, _ uuid.UUID) (ExportFinalization, error) {
	return ExportFinalization{State: repository.finalState}, nil
}
func (repository *fakeRepository) ListTenantRetentionCandidates(context.Context, uuid.UUID, int) ([]uuid.UUID, error) {
	return append([]uuid.UUID(nil), repository.tenantCandidates...), nil
}
func (repository *fakeRepository) GetRetentionWork(_ context.Context, stream Stream, tenantID, _ uuid.UUID) (Segment, bool, error) {
	if repository.retentionWork.ID == uuid.Nil || repository.retentionWork.Stream != stream ||
		repository.retentionWork.TenantID != tenantID {
		return Segment{}, false, nil
	}
	return repository.retentionWork, true, nil
}
func (*fakeRepository) CloseRetentionSegment(context.Context, Stream, uuid.UUID, uuid.UUID, int, string, uuid.UUID) (Segment, bool, error) {
	return Segment{}, false, nil
}
func (repository *fakeRepository) ReadRetentionPage(_ context.Context, segment Segment, _ uuid.UUID,
	after int64, _ int) ([]PageRow, error) {
	return repository.retentionPage(segment, after)
}
func (repository *fakeRepository) PreserveRetentionSegment(context.Context, Segment, uuid.UUID, [32]byte,
	int64, string, [64]byte, string, uuid.UUID) error {
	repository.preserved++
	return nil
}
func (repository *fakeRepository) PruneRetentionSegment(context.Context, Segment, uuid.UUID, Artifact,
	string, uuid.UUID) error {
	repository.pruned++
	return nil
}
func (*fakeRepository) PruneTenantReceipts(context.Context, uuid.UUID, uuid.UUID, int, string, uuid.UUID) (int, error) {
	return 0, nil
}
func (*fakeRepository) PrunePlatformReceipts(context.Context, uuid.UUID, int, string, uuid.UUID) (int, error) {
	return 0, nil
}

type memoryStore struct {
	puts     int
	verifies int
	deletes  int
	last     Artifact
}

func (*memoryStore) Check(context.Context) error { return nil }
func (store *memoryStore) Put(_ context.Context, artifact Artifact) error {
	contents, err := os.ReadFile(artifact.Path)
	if err != nil || int64(len(contents)) != artifact.Bytes {
		return ErrUnavailable
	}
	store.puts++
	store.last = artifact
	store.last.Path = ""
	return nil
}
func (store *memoryStore) Verify(_ context.Context, artifact Artifact) error {
	store.verifies++
	if artifact.ObjectKey != store.last.ObjectKey || artifact.Digest != store.last.Digest ||
		artifact.Signature != store.last.Signature {
		return ErrArtifactConflict
	}
	return nil
}
func (store *memoryStore) DeleteExact(_ context.Context, artifact Artifact) error {
	if artifact.ObjectKey != store.last.ObjectKey || artifact.Digest != store.last.Digest {
		return ErrArtifactConflict
	}
	store.deletes++
	return nil
}

type testSigner struct{}

func (testSigner) KeyID() string { return "test-key-v1" }
func (testSigner) Sign(Segment, [32]byte, int64) ([64]byte, error) {
	return [64]byte{1}, nil
}
func (testSigner) Verify(Segment, [32]byte, int64, [64]byte) bool { return true }

func mustV7(t *testing.T) uuid.UUID {
	t.Helper()
	value, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func testProjection(stream Stream, tenantID uuid.UUID, sequence int64, metadata map[string]any) json.RawMessage {
	document := map[string]any{
		"projectionVersion": 1, "stream": string(stream), "sequence": sequence,
		"id": uuid.Must(uuid.NewV7()).String(), "occurredAt": time.Now().UTC().Format(time.RFC3339Nano),
		"actorType": "system", "action": "test.event", "resourceType": "test",
		"authenticationMethod": "worker", "outcome": "success", "metadata": metadata,
		"previousHash": zeroHash(), "eventHash": hashText('a'),
	}
	if stream == TenantStream {
		document["tenantId"] = tenantID.String()
	}
	encoded, _ := json.Marshal(document)
	return encoded
}

func zeroHash() string           { return hashText('0') }
func hashText(value byte) string { return string(makeFilled(64, value)) }
func makeFilled(length int, value byte) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = value
	}
	return result
}
