package dfir

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestStorageObjectVerifiedScanRetentionAndDeletionLifecycle(t *testing.T) {
	object, err := NewStorageObject(validStorageObjectInput())
	if err != nil {
		t.Fatalf("NewStorageObject() error = %v", err)
	}
	if object.State() != ScanPendingUpload || object.Version() != 1 || object.CanIssueDownload() {
		t.Fatal("new object did not start as a non-downloadable pending upload")
	}

	base := object.CreatedAt()
	object, err = object.MarkUploaded(1, base.Add(time.Microsecond))
	object = mustStorageTransition(t, object, err)
	object, err = object.BeginVerification(2, base.Add(2*time.Microsecond))
	object = mustStorageTransition(t, object, err)
	object, err = object.CompleteVerification(
		3,
		strings.Repeat("AB", 32),
		1_048_576,
		"Application/PDF; Charset=UTF-8",
		base.Add(3*time.Microsecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := object.ContentSHA256(), strings.Repeat("ab", 32); got != want {
		t.Fatalf("ContentSHA256() = %q, want %q", got, want)
	}
	if got, want := object.DetectedMIME(), "application/pdf; charset=UTF-8"; got != want {
		t.Fatalf("DetectedMIME() = %q, want %q", got, want)
	}
	if object.State() != ScanQuarantined || object.CanIssueDownload() {
		t.Fatal("verified object escaped quarantine")
	}

	object, err = object.BeginScan(4, base.Add(4*time.Microsecond))
	object = mustStorageTransition(t, object, err)
	object, err = object.CompleteScan(5, ScanAvailable, base.Add(5*time.Microsecond))
	object = mustStorageTransition(t, object, err)
	if !object.CanIssueDownload() {
		t.Fatal("available verified object was not downloadable")
	}

	retention := base.Add(time.Hour)
	object, err = object.ChangeRetention(6, &retention, base.Add(6*time.Microsecond))
	if err != nil || object.State() != ScanRetained {
		t.Fatalf("future retention did not retain object: state=%q error=%v", object.State(), err)
	}
	if _, err := object.Delete(7, base.Add(7*time.Microsecond)); !errors.Is(err, ErrStorageObjectRetained) {
		t.Fatalf("retained delete error = %v, want ErrStorageObjectRetained", err)
	}
	object, err = object.ChangeLegalHold(7, true, base.Add(7*time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	object, err = object.ChangeRetention(8, nil, base.Add(8*time.Microsecond))
	if err != nil || object.State() != ScanRetained {
		t.Fatalf("clearing retention bypassed legal hold: state=%q error=%v", object.State(), err)
	}
	object, err = object.ChangeLegalHold(9, false, base.Add(9*time.Microsecond))
	if err != nil || object.State() != ScanAvailable {
		t.Fatalf("release did not restore availability: state=%q error=%v", object.State(), err)
	}
	object, err = object.Delete(10, base.Add(10*time.Microsecond))
	if err != nil || object.State() != ScanDeleted || object.CanIssueDownload() {
		t.Fatalf("delete result: state=%q downloadable=%t error=%v", object.State(), object.CanIssueDownload(), err)
	}
}

func TestStorageObjectScanRetryAndTerminalRejection(t *testing.T) {
	object := mustVerifiedStorageObject(t)
	base := object.UpdatedAt()
	var err error
	object, err = object.BeginScan(object.Version(), base.Add(time.Microsecond))
	object = mustStorageTransition(t, object, err)
	object, err = object.CompleteScan(object.Version(), ScanFailed, base.Add(2*time.Microsecond))
	object = mustStorageTransition(t, object, err)
	object, err = object.RetryScan(object.Version(), base.Add(3*time.Microsecond))
	object = mustStorageTransition(t, object, err)
	object, err = object.CompleteScan(object.Version(), ScanRejected, base.Add(4*time.Microsecond))
	object = mustStorageTransition(t, object, err)
	if object.CanIssueDownload() {
		t.Fatal("scanner-rejected object was downloadable")
	}
	if _, err := object.RetryScan(object.Version(), base.Add(5*time.Microsecond)); err == nil {
		t.Fatal("terminally rejected object was retryable")
	}
}

func TestStorageObjectRejectsUnsafeLocationIdentityAndMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*StorageObjectInput)
	}{
		{"IP bucket", func(input *StorageObjectInput) { input.Bucket = "192.0.2.1" }},
		{"uppercase bucket", func(input *StorageObjectInput) { input.Bucket = "Evidence-Bucket" }},
		{"ambiguous bucket", func(input *StorageObjectInput) { input.Bucket = "evidence..bucket" }},
		{"foreign tenant prefix", func(input *StorageObjectInput) { input.ObjectKey = fixtureID(2).String() + "/evidence/file" }},
		{"absolute key", func(input *StorageObjectInput) { input.ObjectKey = "/" + input.ObjectKey }},
		{"empty key segment", func(input *StorageObjectInput) { input.ObjectKey = input.TenantID.String() + "//file" }},
		{"parent key segment", func(input *StorageObjectInput) { input.ObjectKey = input.TenantID.String() + "/../file" }},
		{"backslash key", func(input *StorageObjectInput) { input.ObjectKey = input.TenantID.String() + `/private\file` }},
		{"path filename", func(input *StorageObjectInput) { input.OriginalFilename = `..\private.e01` }},
		{"directional filename", func(input *StorageObjectInput) { input.OriginalFilename = "invoice\u202Efdp.exe" }},
		{"unknown classification", func(input *StorageObjectInput) { input.Classification = "secret" }},
		{"missing expected size", func(input *StorageObjectInput) { input.ExpectedSizeBytes = 0 }},
		{"oversized expected size", func(input *StorageObjectInput) { input.ExpectedSizeBytes = maximumStorageObjectBytes + 1 }},
		{"expired upload", func(input *StorageObjectInput) { input.UploadExpiresAt = input.CreatedAt }},
		{"unbounded upload lifetime", func(input *StorageObjectInput) {
			input.UploadExpiresAt = input.CreatedAt.Add(time.Hour + time.Microsecond)
		}},
		{"local timestamp", func(input *StorageObjectInput) { input.CreatedAt = input.CreatedAt.In(time.FixedZone("local", 3_600)) }},
		{"missing author", func(input *StorageObjectInput) { input.CreatedBy = EntityID{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validStorageObjectInput()
			test.mutate(&input)
			if _, err := NewStorageObject(input); !errors.Is(err, ErrInvalidStorageObject) {
				t.Fatalf("NewStorageObject() error = %v, want ErrInvalidStorageObject", err)
			}
		})
	}
}

func TestStorageObjectFailsClosedForConflictCorruptionAndInvalidCommands(t *testing.T) {
	object := mustVerifiedStorageObject(t)
	base := object.UpdatedAt()
	if _, err := object.BeginScan(object.Version()-1, time.Time{}); !errors.Is(err, ErrStorageObjectConflict) {
		t.Fatalf("stale malformed command error = %v, want conflict", err)
	}
	if _, err := object.BeginScan(object.Version(), base.Add(-time.Microsecond)); !errors.Is(err, ErrInvalidStorageObject) {
		t.Fatalf("time-regressing command error = %v", err)
	}
	if _, err := object.CompleteScan(object.Version(), ScanAvailable, base.Add(time.Microsecond)); !errors.Is(err, ErrInvalidStorageObject) {
		t.Fatalf("scan completion outside scanning error = %v", err)
	}
	if _, err := object.Delete(object.Version(), base.Add(time.Microsecond)); !errors.Is(err, ErrInvalidStorageObject) {
		t.Fatalf("quarantine delete error = %v, want invalid lifecycle", err)
	}

	corruptions := []func(*StorageObject){
		func(value *StorageObject) { value.contentSHA256 = strings.Repeat("z", 64) },
		func(value *StorageObject) { value.detectedMIME = "application/pdf\ntext/plain" },
		func(value *StorageObject) { value.verifiedAt = nil },
		func(value *StorageObject) { value.legalHold = true },
		func(value *StorageObject) { value.version = maximumAggregateVersion + 1 },
	}
	for index, corrupt := range corruptions {
		copy := object
		corrupt(&copy)
		if copy.CanIssueDownload() {
			t.Fatalf("corruption %d remained downloadable", index)
		}
		if _, err := copy.BeginScan(copy.Version(), base.Add(time.Microsecond)); !errors.Is(err, ErrInvalidStorageObject) {
			t.Fatalf("corruption %d transition error = %v", index, err)
		}
	}
}

func TestStorageObjectAcceptsMaximumSafeRevisionButCannotIncrementIt(t *testing.T) {
	state := mustVerifiedStorageObject(t).Snapshot()
	state.Version = MaximumResourceVersion - 1
	object, err := RestoreStorageObject(state)
	if err != nil {
		t.Fatalf("RestoreStorageObject(maximum-1) error = %v", err)
	}
	advanced, err := object.BeginScan(object.Version(), object.UpdatedAt().Add(time.Microsecond))
	if err != nil || advanced.Version() != MaximumResourceVersion {
		t.Fatalf("maximum safe transition = (%d, %v)", advanced.Version(), err)
	}
	if _, err = advanced.CompleteScan(
		advanced.Version(), ScanAvailable, advanced.UpdatedAt().Add(time.Microsecond),
	); !errors.Is(err, ErrInvalidStorageObject) {
		t.Fatalf("terminal maximum transition error = %v, want ErrInvalidStorageObject", err)
	}

	state.Version = MaximumResourceVersion + 1
	if _, err = RestoreStorageObject(state); !errors.Is(err, ErrInvalidStorageObject) {
		t.Fatalf("unsafe storage projection error = %v, want ErrInvalidStorageObject", err)
	}
}

func TestStorageObjectFormattingRedactsSensitiveMetadata(t *testing.T) {
	object := mustVerifiedStorageObject(t)
	for _, rendered := range []string{fmt.Sprint(object), fmt.Sprintf("%#v", object)} {
		for _, sensitive := range []string{
			object.Bucket(), object.ObjectKey(), object.OriginalFilename(), object.ContentSHA256(),
		} {
			if strings.Contains(rendered, sensitive) {
				t.Fatalf("storage formatting leaked %q: %q", sensitive, rendered)
			}
		}
	}
}

func TestStorageObjectSnapshotRestoresExactlyAndRejectsMalformedProjection(t *testing.T) {
	object := mustVerifiedStorageObject(t)
	state := object.Snapshot()
	restored, err := RestoreStorageObject(state)
	if err != nil || restored.Snapshot().Version != state.Version ||
		restored.ContentSHA256() != object.ContentSHA256() {
		t.Fatalf("restored storage object=%#v error=%v", restored, err)
	}
	for _, rendered := range []string{fmt.Sprint(state), fmt.Sprintf("%#v", state)} {
		for _, sensitive := range []string{state.Bucket, state.ObjectKey, state.OriginalFilename, state.ContentSHA256} {
			if strings.Contains(rendered, sensitive) {
				t.Fatalf("storage state formatting leaked %q: %q", sensitive, rendered)
			}
		}
	}

	state.ContentSHA256 = strings.Repeat("z", 64)
	if _, err := RestoreStorageObject(state); !errors.Is(err, ErrInvalidStorageObject) {
		t.Fatalf("malformed storage projection error = %v", err)
	}
}

func TestStorageObjectRejectsObjectLargerThanS3Limit(t *testing.T) {
	object, err := NewStorageObject(validStorageObjectInput())
	if err != nil {
		t.Fatal(err)
	}
	base := object.CreatedAt()
	object, err = object.MarkUploaded(1, base.Add(time.Microsecond))
	object = mustStorageTransition(t, object, err)
	object, err = object.BeginVerification(2, base.Add(2*time.Microsecond))
	object = mustStorageTransition(t, object, err)
	if _, err := object.CompleteVerification(
		3, strings.Repeat("ab", 32), maximumStorageObjectBytes+1,
		"application/octet-stream", base.Add(3*time.Microsecond),
	); !errors.Is(err, ErrInvalidStorageObject) {
		t.Fatalf("oversized object error = %v", err)
	}
}

func TestStorageObjectRejectsVerifiedSizeDifferentFromPersistedExpectation(t *testing.T) {
	object, err := NewStorageObject(validStorageObjectInput())
	if err != nil {
		t.Fatal(err)
	}
	base := object.CreatedAt()
	object, err = object.MarkUploaded(1, base.Add(time.Microsecond))
	object = mustStorageTransition(t, object, err)
	object, err = object.BeginVerification(2, base.Add(2*time.Microsecond))
	object = mustStorageTransition(t, object, err)
	if _, err := object.CompleteVerification(
		3, strings.Repeat("ab", 32), object.ExpectedSizeBytes()-1,
		"application/octet-stream", base.Add(3*time.Microsecond),
	); !errors.Is(err, ErrInvalidStorageObject) {
		t.Fatalf("size mismatch error = %v", err)
	}
}

func validStorageObjectInput() StorageObjectInput {
	tenantID := fixtureID(1)
	return StorageObjectInput{
		ID: fixtureID(100), TenantID: tenantID,
		Bucket: "periapsis-evidence-dev", ObjectKey: tenantID.String() + "/evidence/019d-object",
		OriginalFilename: "private-disk-image.e01", Classification: EvidenceRestricted,
		ExpectedSizeBytes: 1_048_576,
		CreatedBy:         fixtureID(9), CreatedAt: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC),
		UploadExpiresAt: time.Date(2026, 8, 25, 12, 15, 0, 0, time.UTC),
	}
}

func mustVerifiedStorageObject(t *testing.T) StorageObject {
	t.Helper()
	object, err := NewStorageObject(validStorageObjectInput())
	if err != nil {
		t.Fatal(err)
	}
	base := object.CreatedAt()
	object, err = object.MarkUploaded(1, base.Add(time.Microsecond))
	object = mustStorageTransition(t, object, err)
	object, err = object.BeginVerification(2, base.Add(2*time.Microsecond))
	object = mustStorageTransition(t, object, err)
	object, err = object.CompleteVerification(
		3, strings.Repeat("ab", 32), 1_048_576, "application/octet-stream", base.Add(3*time.Microsecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	return object
}

func mustStorageTransition(t *testing.T, object StorageObject, err error) StorageObject {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return object
}
