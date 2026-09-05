package dfir

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

func TestNewServiceFailsClosedWithoutEveryDependency(t *testing.T) {
	t.Parallel()
	repository := &fakeRepository{}
	storage := &fakeObjectStorage{}
	scanner := &fakeScanner{}
	config := ServiceConfig{Bucket: "periapsis-evidence", MaximumSize: 1_024}
	for name, build := range map[string]func() (*Service, error){
		"repository": func() (*Service, error) { return NewService(nil, storage, scanner, config) },
		"storage":    func() (*Service, error) { return NewService(repository, nil, scanner, config) },
		"scanner":    func() (*Service, error) { return NewService(repository, storage, nil, config) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := build(); err == nil {
				t.Fatal("NewService succeeded with an absent production dependency")
			}
		})
	}
}

func TestDownloadGrantAuditWriteHasOnlyTheRedactedAllowlistedShape(t *testing.T) {
	t.Parallel()
	allowed := map[string]struct{}{
		"Actor": {}, "Audit": {}, "Root": {}, "RootVersion": {}, "Subject": {},
		"AttachmentID": {}, "AttachmentVersion": {}, "AttachmentState": {},
		"StorageObjectID": {}, "StorageVersion": {}, "StorageState": {}, "Access": {},
		"PortalAuthorization": {}, "ExpiresAt": {},
	}
	typeOfWrite := reflect.TypeOf(DownloadGrantAuditWrite{})
	if typeOfWrite.NumField() != len(allowed) {
		t.Fatalf("download audit write has %d fields, safe allowlist has %d", typeOfWrite.NumField(), len(allowed))
	}
	for index := range typeOfWrite.NumField() {
		field := typeOfWrite.Field(index)
		if _, ok := allowed[field.Name]; !ok {
			t.Fatalf("download audit write grew non-allowlisted field %q", field.Name)
		}
		lower := strings.ToLower(field.Name)
		for _, forbidden := range []string{"url", "signature", "bucket", "key", "hash", "filename", "content", "payload"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("download audit write can represent forbidden %q data via %q", forbidden, field.Name)
			}
		}
	}
}

func TestNewServiceRejectsMultipartSizedSinglePutConfiguration(t *testing.T) {
	t.Parallel()
	_, err := NewService(
		&fakeRepository{},
		&fakeObjectStorage{},
		&fakeScanner{},
		ServiceConfig{Bucket: "periapsis-evidence", MaximumSize: maximumObjectBytes + 1},
	)
	if err == nil {
		t.Fatal("NewService accepted a size above the portable S3 single-PUT ceiling")
	}
}

func TestDFIRResourceMutationVersionUsesExactJSONCeiling(t *testing.T) {
	t.Parallel()
	if !validResourceMutationVersion(3_000_000_000) ||
		!validResourceMutationVersion(kernel.MaximumResourceVersion-1) {
		t.Fatal("an incrementable safe DFIR resource revision was rejected")
	}
	for _, version := range []uint64{0, kernel.MaximumResourceVersion, kernel.MaximumResourceVersion + 1} {
		if validResourceMutationVersion(version) {
			t.Fatalf("non-incrementable DFIR resource revision %d was accepted", version)
		}
	}
}

func TestCaseResourceMutationsRejectTerminalRevisionBeforeRepository(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(8)
	caseID := testEntityID(t, 9)
	actor := testActor(tenantID, PrincipalHuman)
	repository := &fakeRepository{
		resolveAccess: func(context.Context, Actor, uuid.UUID, Capability, ResourceScope) (Access, error) {
			return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, nil
		},
		replaceIndicator: func(context.Context, IndicatorWrite) (MutationResult[kernel.Indicator], error) {
			t.Fatal("terminal IOC revision reached the repository")
			return MutationResult[kernel.Indicator]{}, nil
		},
		replaceAsset: func(context.Context, AssetWrite) (MutationResult[kernel.Asset], error) {
			t.Fatal("terminal asset revision reached the repository")
			return MutationResult[kernel.Asset]{}, nil
		},
	}
	service := mustService(t, repository, &fakeObjectStorage{}, &fakeScanner{})
	if _, err := service.ReplaceIndicator(context.Background(), actor, tenantID, IndicatorCommand{
		CaseID: caseID, Input: indicatorInput(t, tenantID, 10),
		ExpectedVersion: kernel.MaximumResourceVersion, Envelope: testEnvelope(11),
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("terminal IOC revision error = %v, want ErrInvalidInput", err)
	}
	if _, err := service.ReplaceAsset(context.Background(), actor, tenantID, AssetCommand{
		CaseID: caseID, Input: alertAssetInput(t, tenantID, 12),
		ExpectedVersion: kernel.MaximumResourceVersion, Envelope: testEnvelope(13),
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("terminal asset revision error = %v, want ErrInvalidInput", err)
	}
}

func TestCreateIndicatorBindsAuthorityTenantAndIdempotency(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(1)
	caseID := testEntityID(t, 2)
	actor := testActor(tenantID, PrincipalHuman)
	envelope := testEnvelope(4)
	created := 0
	repository := &fakeRepository{
		resolveAccess: func(_ context.Context, got Actor, gotTenant uuid.UUID, capability Capability, scope ResourceScope) (Access, error) {
			if got != actor || gotTenant != tenantID || capability != CapabilityIOCManage || scope.CaseID != caseID {
				t.Fatal("authority request was not fully tenant/resource bound")
			}
			return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, nil
		},
		createIndicator: func(_ context.Context, write IndicatorWrite) (MutationResult[kernel.Indicator], error) {
			created++
			if write.Command.Operation != operationIOCCreate ||
				write.Command.KeyDigest != sha256.Sum256([]byte(envelope.IdempotencyKey)) ||
				write.Command.RequestDigest == ([32]byte{}) || write.Actor != actor ||
				write.CaseID != caseID || write.ExpectedVersion != 0 {
				t.Fatal("transaction write lost command identity or authority")
			}
			if write.Indicator.NormalizedValue() != "example.com" {
				t.Fatalf("normalized IOC = %q", write.Indicator.NormalizedValue())
			}
			return MutationResult[kernel.Indicator]{Resource: write.Indicator}, nil
		},
	}
	service := mustService(t, repository, &fakeObjectStorage{}, &fakeScanner{})
	result, err := service.CreateIndicator(context.Background(), actor, tenantID, IndicatorCommand{
		CaseID: caseID, Input: indicatorInput(t, tenantID, 3), Envelope: envelope,
	})
	if err != nil || created != 1 || result.Resource.NormalizedValue() != "example.com" {
		t.Fatalf("CreateIndicator() = (%s, %v), writes = %d", result.Resource, err, created)
	}

	customer := testActor(tenantID, PrincipalCustomer)
	repository.resolveAccess = func(context.Context, Actor, uuid.UUID, Capability, ResourceScope) (Access, error) {
		return Access{Audience: kernel.AudienceCustomer, Scope: ScopeAssigned}, nil
	}
	_, err = service.CreateIndicator(context.Background(), customer, tenantID, IndicatorCommand{
		CaseID: caseID, Input: indicatorInput(t, tenantID, 5), Envelope: testEnvelope(6),
	})
	if !errors.Is(err, ErrForbidden) || created != 1 {
		t.Fatalf("customer manage error = %v, writes = %d", err, created)
	}
}

func TestPrepareUploadSupportsCaseChildrenAndRejectsHeaderAliases(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(10)
	caseID := testEntityID(t, 11)
	assetID := testEntityID(t, 12)
	tenantEntity := testEntityIDFromUUID(t, tenantID)
	subject, err := kernel.NewEntityReference(tenantEntity, kernel.EntityAsset, assetID)
	if err != nil {
		t.Fatal(err)
	}
	actor := testActor(tenantID, PrincipalHuman)
	now := time.Now().UTC().Truncate(time.Microsecond)
	repository := &fakeRepository{
		resolveSubjectAccess: func(_ context.Context, got Actor, gotTenant uuid.UUID, capability Capability, gotCase kernel.EntityID, gotSubject kernel.EntityReference) (SubjectAccess, error) {
			if got != actor || gotTenant != tenantID || capability != CapabilityAttachmentManage || gotCase != caseID || !sameEntityReference(gotSubject, subject) {
				t.Fatal("subject authorization was not exact")
			}
			return SubjectAccess{CaseID: caseID, Access: Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, SubjectVisibility: kernel.VisibilityPrivate}, nil
		},
		createStorageObject: func(_ context.Context, write StorageWrite) (PreparedUploadRecord, error) {
			if write.CaseID != caseID || !sameEntityReference(write.Attachment.Subject(), subject) ||
				write.Storage.ObjectKey() != tenantID.String()+"/"+write.Storage.ID().String() {
				t.Fatal("storage write was not bound to the resolved case and tenant key")
			}
			if write.Attachment.StorageObjectID() != write.Storage.ID() || write.Attachment.Visibility() != kernel.VisibilityPrivate {
				t.Fatal("pending attachment was not atomically bound to storage and subject visibility")
			}
			return PreparedUploadRecord{Storage: write.Storage, Attachment: write.Attachment}, nil
		},
	}
	storage := &fakeObjectStorage{prepareUpload: func(_ context.Context, _ ObjectLocation, maximum int64, contentType string, expires time.Time) (UploadGrant, error) {
		if maximum != 1_024 || contentType != "text/plain" {
			t.Fatal("bounded upload metadata was not forwarded")
		}
		return UploadGrant{TargetURL: "https://storage.invalid/upload?secret=redacted", Method: "PUT", ExpiresAt: expires}, nil
	}}
	service := mustServiceAt(t, repository, storage, &fakeScanner{}, now)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	result, err := service.PrepareUpload(ctx, actor, tenantID, PrepareUploadCommand{
		CaseID: caseID, AttachmentID: testEntityID(t, 17), StorageObjectID: testEntityID(t, 13), Subject: subject, OriginalFilename: "capture.txt",
		Classification: kernel.EvidenceInternal, SizeBytes: 1_024, ContentType: "text/plain",
		RequestedVisibility: kernel.VisibilityPublic,
		Envelope:            testEnvelope(14),
	})
	if err != nil || result.Object.State() != kernel.ScanPendingUpload {
		t.Fatalf("PrepareUpload() = (%s, %v)", result.Object, err)
	}
	if strings.Contains(result.Grant.String(), "storage.invalid") || strings.Contains(result.Grant.GoString(), "secret") {
		t.Fatal("upload grant formatting exposed a signed URL")
	}

	storage.prepareUpload = func(context.Context, ObjectLocation, int64, string, time.Time) (UploadGrant, error) {
		return UploadGrant{TargetURL: "https://storage.invalid/upload", Method: "PUT", ExpiresAt: now.Add(time.Minute), Headers: []UploadHeader{
			{Name: "X-Amz-Meta-Test", Value: "a"}, {Name: "x-amz-meta-test", Value: "b"},
		}}, nil
	}
	_, err = service.PrepareUpload(ctx, actor, tenantID, PrepareUploadCommand{
		CaseID: caseID, AttachmentID: testEntityID(t, 18), StorageObjectID: testEntityID(t, 15), Subject: subject, OriginalFilename: "capture.txt",
		Classification: kernel.EvidenceInternal, SizeBytes: 1_024, ContentType: "text/plain",
		RequestedVisibility: kernel.VisibilityPrivate,
		Envelope:            testEnvelope(16),
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("case-insensitive duplicate upload header error = %v", err)
	}
}

func TestPrepareUploadRejectsReplayAfterObjectProcessing(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(18)
	tenantEntity := testEntityIDFromUUID(t, tenantID)
	caseID := testEntityID(t, 19)
	subject, err := kernel.NewEntityReference(tenantEntity, kernel.EntityCase, caseID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	repository := &fakeRepository{
		resolveSubjectAccess: func(context.Context, Actor, uuid.UUID, Capability, kernel.EntityID, kernel.EntityReference) (SubjectAccess, error) {
			return SubjectAccess{
				CaseID: caseID, Access: Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant},
				SubjectVisibility: kernel.VisibilityPrivate,
			}, nil
		},
		createStorageObject: func(_ context.Context, write StorageWrite) (PreparedUploadRecord, error) {
			uploaded, transitionErr := write.Storage.MarkUploaded(write.Storage.Version(), now.Add(time.Second))
			if transitionErr != nil {
				t.Fatal(transitionErr)
			}
			verifying, transitionErr := uploaded.BeginVerification(uploaded.Version(), now.Add(2*time.Second))
			if transitionErr != nil {
				t.Fatal(transitionErr)
			}
			quarantined, transitionErr := verifying.CompleteVerification(
				verifying.Version(), strings.Repeat("a", 64), 1_024, "application/octet-stream", now.Add(3*time.Second),
			)
			if transitionErr != nil {
				t.Fatal(transitionErr)
			}
			scanning, transitionErr := quarantined.BeginScan(quarantined.Version(), now.Add(4*time.Second))
			if transitionErr != nil {
				t.Fatal(transitionErr)
			}
			available, transitionErr := scanning.CompleteScan(scanning.Version(), kernel.ScanAvailable, now.Add(5*time.Second))
			if transitionErr != nil {
				t.Fatal(transitionErr)
			}
			return PreparedUploadRecord{Storage: available, Attachment: write.Attachment, Replayed: true}, nil
		},
	}
	presigned := false
	storage := &fakeObjectStorage{prepareUpload: func(context.Context, ObjectLocation, int64, string, time.Time) (UploadGrant, error) {
		presigned = true
		return UploadGrant{}, nil
	}}
	service := mustServiceAt(t, repository, storage, &fakeScanner{}, now)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err = service.PrepareUpload(ctx, testActor(tenantID, PrincipalHuman), tenantID, PrepareUploadCommand{
		CaseID: caseID, AttachmentID: testEntityID(t, 20), StorageObjectID: testEntityID(t, 21),
		Subject: subject, OriginalFilename: "processed.bin", Classification: kernel.EvidenceInternal,
		RequestedVisibility: kernel.VisibilityPrivate, SizeBytes: 1_024,
		ContentType: "application/octet-stream", Envelope: testEnvelope(22),
	})
	if !errors.Is(err, ErrUnavailable) || presigned {
		t.Fatalf("processed replay error = %v, presigned = %t", err, presigned)
	}
}

func TestVerifyAndScanObjectUsesBoundedStreamingTransitions(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(20)
	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	now := createdAt.Add(time.Second)
	pending := pendingStorageObject(t, tenantID, 21, createdAt)
	payload := []byte("forensic payload")
	closed := false
	repository := &fakeRepository{
		getStorageObjectAsWorker: func(context.Context, WorkerContext, kernel.EntityID) (kernel.StorageObject, error) {
			return pending, nil
		},
		markStorageUploadedAsWorker: func(_ context.Context, write WorkerStorageWrite) (kernel.StorageObject, error) {
			if write.Current.State() != kernel.ScanPendingUpload || write.Updated.State() != kernel.ScanUploaded {
				t.Fatal("object existence did not atomically advance pending upload")
			}
			return write.Updated, nil
		},
		beginStorageVerification: func(_ context.Context, write WorkerStorageWrite) (kernel.StorageObject, error) {
			if write.Current.State() != kernel.ScanUploaded || write.Updated.State() != kernel.ScanVerifying {
				t.Fatal("invalid verification transition")
			}
			return write.Updated, nil
		},
		completeStorageVerification: func(_ context.Context, write WorkerStorageWrite) (kernel.StorageObject, error) {
			want := sha256.Sum256(payload)
			if write.Updated.ContentSHA256() != fmtDigest(want) || write.Updated.SizeBytes() != int64(len(payload)) ||
				write.Updated.State() != kernel.ScanQuarantined {
				t.Fatal("hash verification did not produce the expected immutable metadata")
			}
			return write.Updated, nil
		},
	}
	storage := &fakeObjectStorage{open: func(context.Context, ObjectLocation) (ObjectReader, error) {
		return ObjectReader{Body: &trackingReadCloser{Reader: bytes.NewReader(payload), closed: &closed}, SizeBytes: int64(len(payload))}, nil
	}}
	service := mustServiceAt(t, repository, storage, &fakeScanner{}, now)
	worker := testWorker(tenantID, 22)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	verified, err := service.VerifyUploadedObject(ctx, worker, pending.ID())
	cancel()
	if err != nil || verified.State() != kernel.ScanQuarantined || !closed {
		t.Fatalf("VerifyUploadedObject() = (%s, %v), closed = %t", verified, err, closed)
	}

	closed = false
	repository.getStorageObjectAsWorker = func(context.Context, WorkerContext, kernel.EntityID) (kernel.StorageObject, error) {
		return verified, nil
	}
	repository.beginStorageScan = func(_ context.Context, write WorkerStorageWrite) (kernel.StorageObject, error) {
		if write.Updated.State() != kernel.ScanScanning {
			t.Fatal("scan did not enter scanning state")
		}
		return write.Updated, nil
	}
	repository.completeStorageScan = func(_ context.Context, write WorkerStorageWrite) (kernel.StorageObject, error) {
		if write.Updated.State() != kernel.ScanRejected {
			t.Fatalf("malware verdict persisted state = %s", write.Updated.State())
		}
		return write.Updated, nil
	}
	storage.open = func(context.Context, ObjectLocation) (ObjectReader, error) {
		return ObjectReader{Body: &trackingReadCloser{Reader: bytes.NewReader(payload), closed: &closed}, SizeBytes: int64(len(payload))}, nil
	}
	scanner := &fakeScanner{scan: func(_ context.Context, reader io.Reader, maximum int64) (ScanVerdict, error) {
		if maximum != 1_024 {
			t.Fatalf("scanner maximum = %d", maximum)
		}
		consumed, readErr := io.ReadAll(reader)
		if readErr != nil || !bytes.Equal(consumed, payload) {
			t.Fatal("scanner did not receive the exact object")
		}
		return ScanVerdictMalicious, nil
	}}
	service.scanner = scanner
	ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
	scanned, err := service.ScanVerifiedObject(ctx, worker, verified.ID())
	cancel()
	if err != nil || scanned.State() != kernel.ScanRejected || !closed {
		t.Fatalf("ScanVerifiedObject() = (%s, %v), closed = %t", scanned, err, closed)
	}
}

func TestWorkerRejectsOversizedUnknownAndCrossTenantObjects(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(30)
	otherTenant := testUUID(31)
	now := time.Now().UTC().Truncate(time.Microsecond)
	uploaded := uploadedStorageObject(t, otherTenant, 32, now)
	opened := false
	repository := &fakeRepository{getStorageObjectAsWorker: func(context.Context, WorkerContext, kernel.EntityID) (kernel.StorageObject, error) {
		return uploaded, nil
	}}
	storage := &fakeObjectStorage{open: func(context.Context, ObjectLocation) (ObjectReader, error) {
		opened = true
		return ObjectReader{}, nil
	}}
	service := mustServiceAt(t, repository, storage, &fakeScanner{}, now)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := service.VerifyUploadedObject(ctx, testWorker(tenantID, 33), uploaded.ID())
	if !errors.Is(err, ErrUnavailable) || opened {
		t.Fatalf("cross-tenant worker error = %v, opened = %t", err, opened)
	}
}

func TestWorkerRejectsMalformedTransitionProjectionBeforeObjectRead(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(40)
	otherTenant := testUUID(41)
	now := time.Now().UTC().Truncate(time.Microsecond)
	uploaded := uploadedStorageObject(t, tenantID, 42, now)
	foreignUploaded := uploadedStorageObject(t, otherTenant, 42, now)
	foreignVerifying, err := foreignUploaded.BeginVerification(foreignUploaded.Version(), now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	repository := &fakeRepository{
		getStorageObjectAsWorker: func(context.Context, WorkerContext, kernel.EntityID) (kernel.StorageObject, error) {
			return uploaded, nil
		},
		beginStorageVerification: func(context.Context, WorkerStorageWrite) (kernel.StorageObject, error) {
			return foreignVerifying, nil
		},
	}
	opened := false
	storage := &fakeObjectStorage{open: func(context.Context, ObjectLocation) (ObjectReader, error) {
		opened = true
		return ObjectReader{}, nil
	}}
	service := mustServiceAt(t, repository, storage, &fakeScanner{}, now.Add(time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err = service.VerifyUploadedObject(ctx, testWorker(tenantID, 43), uploaded.ID())
	if !errors.Is(err, ErrUnavailable) || opened {
		t.Fatalf("malformed transition error = %v, opened = %t", err, opened)
	}
}

func TestPrepareDownloadFailsClosedForPrivateCustomerAndReturnsRedactedGrantToOperator(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(34)
	tenantEntity := testEntityIDFromUUID(t, tenantID)
	caseID := testEntityID(t, 35)
	subject, err := kernel.NewEntityReference(tenantEntity, kernel.EntityCase, caseID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	storageObject := availableStorageObject(t, tenantID, 36, now)
	attachment, err := kernel.NewAttachment(kernel.AttachmentInput{
		ID: testEntityID(t, 38), TenantID: tenantEntity, Subject: subject,
		StorageObjectID: storageObject.ID(), OriginalFilename: storageObject.OriginalFilename(),
		RequestedVisibility: kernel.VisibilityPrivate, SubjectVisibility: kernel.VisibilityPublic,
		UploadedBy: storageObject.CreatedBy(), UploadedAt: storageObject.CreatedAt(), ScanState: kernel.ScanAvailable,
	})
	if err != nil {
		t.Fatal(err)
	}
	operator := testActor(tenantID, PrincipalHuman)
	operatorAudit := testEnvelope(35).Audit
	storageReads, auditCalls := 0, 0
	repository := &fakeRepository{
		resolveAccess: func(_ context.Context, actor Actor, gotTenant uuid.UUID, capability Capability, scope ResourceScope) (Access, error) {
			if gotTenant != tenantID || capability != CapabilityAttachmentRead || scope.CaseID != caseID {
				t.Fatal("download access was not bound to the requested Case")
			}
			audience := kernel.AudienceOperator
			accessScope := ScopeTenant
			if actor.Kind == PrincipalCustomer {
				audience, accessScope = kernel.AudienceCustomer, ScopeAssigned
			}
			return Access{Audience: audience, Scope: accessScope}, nil
		},
		getAttachment: func(context.Context, uuid.UUID, kernel.EntityID, kernel.EntityID, Access) (AttachmentDownloadRecord, error) {
			return AttachmentDownloadRecord{Attachment: attachment, AttachmentVersion: 4, RootVersion: 7}, nil
		},
		getCaseStorageObject: func(_ context.Context, gotTenant uuid.UUID, gotCase, gotAttachment, gotStorage kernel.EntityID, _ Access) (kernel.StorageObject, error) {
			if gotTenant != tenantID || gotCase != caseID || gotAttachment != attachment.ID() || gotStorage != storageObject.ID() {
				t.Fatal("download storage read lost its exact Case and attachment purpose")
			}
			storageReads++
			return storageObject, nil
		},
		auditDownloadGrant: func(_ context.Context, write DownloadGrantAuditWrite) error {
			auditCalls++
			if write.Actor != operator || write.Audit != operatorAudit ||
				write.Root != (PortalAttachmentRoot{Kind: PortalTicketCase, ID: caseID}) || write.RootVersion != 7 ||
				!sameEntityReference(write.Subject, subject) || write.AttachmentID != attachment.ID() || write.AttachmentVersion != 4 ||
				write.AttachmentState != kernel.ScanAvailable || write.StorageObjectID != storageObject.ID() ||
				write.StorageVersion != storageObject.Version() || write.StorageState != kernel.ScanAvailable ||
				write.Access != (Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}) ||
				write.PortalAuthorization != nil || !write.ExpiresAt.Equal(now.Add(5*time.Minute)) {
				t.Fatalf("operator Case download audit lost its exact safe fence: %#v", write)
			}
			return nil
		},
	}
	presigns := 0
	objectStorage := &fakeObjectStorage{prepareDownload: func(_ context.Context, location ObjectLocation, expires time.Time) (DownloadGrant, error) {
		presigns++
		if location.Bucket != storageObject.Bucket() || location.Key != storageObject.ObjectKey() {
			t.Fatal("download was not bound to the authorized storage object")
		}
		return DownloadGrant{TargetURL: "https://storage.invalid/download?signature=secret", ExpiresAt: expires}, nil
	}}
	service := mustServiceAt(t, repository, objectStorage, &fakeScanner{}, now)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err = service.PrepareDownload(ctx, testActor(tenantID, PrincipalCustomer), tenantID, DownloadCommand{
		CaseID: caseID, AttachmentID: attachment.ID(), Subject: subject, Audit: testEnvelope(34).Audit,
	})
	if !errors.Is(err, ErrForbidden) || storageReads != 0 || presigns != 0 {
		t.Fatalf("private customer download = %v, storage reads = %d, presigns = %d", err, storageReads, presigns)
	}

	result, err := service.PrepareDownload(ctx, operator, tenantID, DownloadCommand{
		CaseID: caseID, AttachmentID: attachment.ID(), Subject: subject, Audit: operatorAudit,
	})
	if err != nil || storageReads != 1 || presigns != 1 || auditCalls != 1 {
		t.Fatalf("operator download = (%s, %v), storage reads = %d, presigns = %d, audits = %d", result.Grant, err, storageReads, presigns, auditCalls)
	}
	if strings.Contains(result.Grant.String(), "signature") || strings.Contains(result.Grant.GoString(), "storage.invalid") {
		t.Fatal("download grant formatting exposed its signed target")
	}

	repository.auditDownloadGrant = func(context.Context, DownloadGrantAuditWrite) error {
		auditCalls++
		return errors.New("audit storage unavailable")
	}
	dropped, err := service.PrepareDownload(ctx, operator, tenantID, DownloadCommand{
		CaseID: caseID, AttachmentID: attachment.ID(), Subject: subject, Audit: testEnvelope(36).Audit,
	})
	if !errors.Is(err, ErrUnavailable) || dropped.Grant.TargetURL != "" || storageReads != 2 || presigns != 2 || auditCalls != 2 {
		t.Fatalf("failed audit returned grant = (%s, %v), storage reads=%d presigns=%d audits=%d", dropped.Grant, err, storageReads, presigns, auditCalls)
	}
}

func TestEvidenceCollectionAndCustodyRemainHashChained(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(60)
	caseID := testEntityID(t, 61)
	now := time.Now().UTC().Truncate(time.Microsecond)
	storageObject := availableStorageObject(t, tenantID, 62, now)
	actor := testActor(tenantID, PrincipalHuman)
	var evidence kernel.Evidence
	buildCalls, applyCalls := 0, 0
	repository := &fakeRepository{
		resolveAccess: func(context.Context, Actor, uuid.UUID, Capability, ResourceScope) (Access, error) {
			return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, nil
		},
		getCaseStorageObject: func(context.Context, uuid.UUID, kernel.EntityID, kernel.EntityID, kernel.EntityID, Access) (kernel.StorageObject, error) {
			return storageObject, nil
		},
		createEvidence: func(_ context.Context, write EvidenceWrite) (MutationResult[kernel.Evidence], error) {
			if write.Command.Operation != operationEvidenceCreate || write.Build == nil ||
				write.StorageObjectID != storageObject.ID() {
				t.Fatal("evidence create was not payload-bound or chain-valid")
			}
			buildCalls++
			built, err := write.Build(storageObject)
			if err != nil || !built.VerifyCustodyChain() || built.ID() != write.EvidenceID ||
				built.CustodyEvents()[0].ID() != write.InitialCustodyEventID {
				t.Fatalf("evidence Build() = (%s, %v)", built, err)
			}
			evidence = built
			return MutationResult[kernel.Evidence]{Resource: built}, nil
		},
	}
	service := mustServiceAt(t, repository, &fakeObjectStorage{}, &fakeScanner{}, now.Add(time.Second))
	collectCommand := EvidenceCommand{
		CaseID: caseID, EvidenceID: testEntityID(t, 63), StorageObjectID: storageObject.ID(),
		InitialCustodyEventID: testEntityID(t, 64), Title: "Memory image", EvidenceType: "memory_image",
		Classification: kernel.EvidenceInternal, CollectedAt: now, Source: "incident-response",
		Envelope: testEnvelope(65),
	}
	created, err := service.CollectEvidence(context.Background(), actor, tenantID, collectCommand)
	if err != nil || !created.Resource.VerifyCustodyChain() || len(created.Resource.CustodyEvents()) != 1 || buildCalls != 1 {
		t.Fatalf("CollectEvidence() = (%s, %v)", created.Resource, err)
	}
	historicalCreate := created.Resource
	repository.createEvidence = func(_ context.Context, write EvidenceWrite) (MutationResult[kernel.Evidence], error) {
		if write.Build == nil {
			t.Fatal("replayed evidence write lost its fresh-path builder")
		}
		return MutationResult[kernel.Evidence]{Resource: historicalCreate, Replayed: true}, nil
	}
	storageObject = kernel.StorageObject{}
	replayedCreate, err := service.CollectEvidence(context.Background(), actor, tenantID, collectCommand)
	if err != nil || !replayedCreate.Replayed || buildCalls != 1 ||
		!sameFingerprint(evidenceFingerprint(replayedCreate.Resource, 0), evidenceFingerprint(historicalCreate, 0)) {
		t.Fatalf("evidence replay after storage drift = (%s, replayed=%t, builds=%d, %v)",
			replayedCreate.Resource, replayedCreate.Replayed, buildCalls, err)
	}
	repository.getEvidence = func(context.Context, uuid.UUID, kernel.EntityID, kernel.EntityID, Access) (kernel.Evidence, error) {
		return evidence, nil
	}
	repository.appendCustody = func(_ context.Context, write CustodyWrite) (MutationResult[kernel.Evidence], error) {
		if write.Command.Operation != operationCustodyAppend || write.Apply == nil ||
			write.EvidenceID != evidence.ID() {
			t.Fatal("custody mutation was not atomic and chain-valid")
		}
		applyCalls++
		updated, err := write.Apply(evidence)
		if err != nil || !updated.VerifyCustodyChain() || updated.Version() != evidence.Version()+1 ||
			updated.CustodyEvents()[len(updated.CustodyEvents())-1].ID() != write.EventID {
			t.Fatalf("custody Apply() = (%s, %v)", updated, err)
		}
		return MutationResult[kernel.Evidence]{Resource: updated}, nil
	}
	custodyCommand := CustodyCommand{
		CaseID: caseID, EvidenceID: evidence.ID(), ExpectedVersion: evidence.Version(),
		Event: kernel.CustodyEventInput{ID: testEntityID(t, 66), ActorID: testEntityIDFromUUID(t, actor.MembershipID),
			Action: kernel.CustodyAccessed, Reason: "forensic review", OccurredAt: now.Add(time.Second)},
		Envelope: testEnvelope(67),
	}
	updated, err := service.AppendCustody(context.Background(), actor, tenantID, custodyCommand)
	if err != nil || !updated.Resource.VerifyCustodyChain() || len(updated.Resource.CustodyEvents()) != 2 || applyCalls != 1 {
		t.Fatalf("AppendCustody() = (%s, %v)", updated.Resource, err)
	}
	historicalCustody := updated.Resource
	liveEvidence, err := historicalCustody.AppendCustodyEvent(historicalCustody.Version(), kernel.CustodyEventInput{
		ID: testEntityID(t, 68), ActorID: testEntityIDFromUUID(t, actor.MembershipID),
		Action: kernel.CustodyAccessed, Reason: "later review", OccurredAt: now.Add(2 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	repository.appendCustody = func(_ context.Context, write CustodyWrite) (MutationResult[kernel.Evidence], error) {
		if write.Apply == nil || liveEvidence.Version() != custodyCommand.ExpectedVersion+2 {
			t.Fatal("custody replay fixture did not preserve the advanced live revision")
		}
		return MutationResult[kernel.Evidence]{Resource: historicalCustody, Replayed: true}, nil
	}
	service.clock = func() time.Time { return now.Add(3 * time.Second) }
	replayedCustody, err := service.AppendCustody(context.Background(), actor, tenantID, custodyCommand)
	if err != nil || !replayedCustody.Replayed || applyCalls != 1 ||
		!sameFingerprint(evidenceFingerprint(replayedCustody.Resource, 1), evidenceFingerprint(historicalCustody, 1)) {
		t.Fatalf("custody replay after later mutation = (%s, replayed=%t, applies=%d, %v)",
			replayedCustody.Resource, replayedCustody.Replayed, applyCalls, err)
	}
	overflow := custodyCommand
	overflow.ExpectedVersion = kernel.MaximumCustodyEvents
	overflow.Envelope = testEnvelope(69)
	if _, err := service.AppendCustody(context.Background(), actor, tenantID, overflow); !errors.Is(err, ErrInvalidInput) || applyCalls != 1 {
		t.Fatalf("terminal custody revision = (applies=%d, %v)", applyCalls, err)
	}
}

func TestRepositoryErrorsAreMappedWithoutLeakingDetails(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(40)
	actor := testActor(tenantID, PrincipalHuman)
	for name, testCase := range map[string]struct {
		repositoryError error
		want            error
	}{
		"forbidden":    {ErrRepositoryForbidden, ErrForbidden},
		"not-found":    {ErrRepositoryNotFound, ErrNotFound},
		"conflict":     {ErrRepositoryConflict, ErrConflict},
		"precondition": {ErrRepositoryPrecondition, ErrPreconditionFailed},
		"canceled":     {context.Canceled, context.Canceled},
		"deadline":     {context.DeadlineExceeded, context.DeadlineExceeded},
		"unknown":      {errors.New("postgres secret DSN and customer evidence"), ErrUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			repository := &fakeRepository{resolveAccess: func(context.Context, Actor, uuid.UUID, Capability, ResourceScope) (Access, error) {
				return Access{}, testCase.repositoryError
			}}
			service := mustService(t, repository, &fakeObjectStorage{}, &fakeScanner{})
			_, err := service.CreateIndicator(context.Background(), actor, tenantID, IndicatorCommand{
				CaseID: testEntityID(t, 41), Input: indicatorInput(t, tenantID, 42), Envelope: testEnvelope(43),
			})
			if !errors.Is(err, testCase.want) || err.Error() != testCase.want.Error() {
				t.Fatalf("mapped error = %q, want %q", err, testCase.want)
			}
		})
	}
}

func TestCommandBindingDetectsNormalizedPayloadDrift(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(50)
	first, err := kernel.NewIndicator(indicatorInput(t, tenantID, 51))
	if err != nil {
		t.Fatal(err)
	}
	changedInput := indicatorInput(t, tenantID, 51)
	changedInput.Confidence = 81
	changed, err := kernel.NewIndicator(changedInput)
	if err != nil {
		t.Fatal(err)
	}
	firstBinding, err := commandBinding(operationIOCCreate, "dfir-command-binding-0001", indicatorFingerprint(first, 0))
	if err != nil {
		t.Fatal(err)
	}
	changedBinding, err := commandBinding(operationIOCCreate, "dfir-command-binding-0001", indicatorFingerprint(changed, 0))
	if err != nil {
		t.Fatal(err)
	}
	if firstBinding.KeyDigest != changedBinding.KeyDigest || firstBinding.RequestDigest == changedBinding.RequestDigest {
		t.Fatal("same key with normalized payload drift was not distinguishable")
	}
}

type fakeRepository struct {
	resolveAccess               func(context.Context, Actor, uuid.UUID, Capability, ResourceScope) (Access, error)
	resolveAlertAccess          func(context.Context, Actor, uuid.UUID, Capability, AlertResourceScope) (Access, error)
	resolveSubjectAccess        func(context.Context, Actor, uuid.UUID, Capability, kernel.EntityID, kernel.EntityReference) (SubjectAccess, error)
	resolveAlertSubjectAccess   func(context.Context, Actor, uuid.UUID, Capability, kernel.EntityID, kernel.EntityReference) (AlertSubjectAccess, error)
	loadWorkspace               func(context.Context, uuid.UUID, kernel.EntityID, WorkspaceAccess) (Workspace, error)
	loadAlertWorkspace          func(context.Context, uuid.UUID, kernel.EntityID, WorkspaceAccess) (AlertWorkspace, error)
	createIndicator             func(context.Context, IndicatorWrite) (MutationResult[kernel.Indicator], error)
	replaceIndicator            func(context.Context, IndicatorWrite) (MutationResult[kernel.Indicator], error)
	createAsset                 func(context.Context, AssetWrite) (MutationResult[kernel.Asset], error)
	replaceAsset                func(context.Context, AssetWrite) (MutationResult[kernel.Asset], error)
	createTimelineEvent         func(context.Context, TimelineWrite) (MutationResult[kernel.TimelineEvent], error)
	commitTask                  func(context.Context, TaskCreateWrite) (MutationResult[kernel.Task], error)
	mutateTask                  func(context.Context, TaskMutationWrite) (MutationResult[kernel.Task], error)
	createRelationship          func(context.Context, RelationshipWrite) (MutationResult[kernel.Relationship], error)
	mutateRelationship          func(context.Context, RelationshipMutationWrite) (MutationResult[kernel.Relationship], error)
	createStorageObject         func(context.Context, StorageWrite) (PreparedUploadRecord, error)
	getCaseStorageObject        func(context.Context, uuid.UUID, kernel.EntityID, kernel.EntityID, kernel.EntityID, Access) (kernel.StorageObject, error)
	getAlertStorageObject       func(context.Context, uuid.UUID, kernel.EntityID, kernel.EntityID, kernel.EntityID, Access) (kernel.StorageObject, error)
	getStorageObjectAsWorker    func(context.Context, WorkerContext, kernel.EntityID) (kernel.StorageObject, error)
	markStorageUploadedAsWorker func(context.Context, WorkerStorageWrite) (kernel.StorageObject, error)
	beginStorageVerification    func(context.Context, WorkerStorageWrite) (kernel.StorageObject, error)
	completeStorageVerification func(context.Context, WorkerStorageWrite) (kernel.StorageObject, error)
	rejectStorageVerification   func(context.Context, WorkerStorageWrite) error
	beginStorageScan            func(context.Context, WorkerStorageWrite) (kernel.StorageObject, error)
	completeStorageScan         func(context.Context, WorkerStorageWrite) (kernel.StorageObject, error)
	getAttachment               func(context.Context, uuid.UUID, kernel.EntityID, kernel.EntityID, Access) (AttachmentDownloadRecord, error)
	getAlertAttachment          func(context.Context, uuid.UUID, kernel.EntityID, kernel.EntityID, Access) (AttachmentDownloadRecord, error)
	auditDownloadGrant          func(context.Context, DownloadGrantAuditWrite) error
	createEvidence              func(context.Context, EvidenceWrite) (MutationResult[kernel.Evidence], error)
	getEvidence                 func(context.Context, uuid.UUID, kernel.EntityID, kernel.EntityID, Access) (kernel.Evidence, error)
	appendCustody               func(context.Context, CustodyWrite) (MutationResult[kernel.Evidence], error)
}

func (repository *fakeRepository) ResolveAlertAccess(ctx context.Context, actor Actor, tenantID uuid.UUID, capability Capability, scope AlertResourceScope) (Access, error) {
	if repository.resolveAlertAccess == nil {
		return Access{}, ErrRepositoryForbidden
	}
	return repository.resolveAlertAccess(ctx, actor, tenantID, capability, scope)
}

func (repository *fakeRepository) ResolveAccess(ctx context.Context, actor Actor, tenantID uuid.UUID, capability Capability, scope ResourceScope) (Access, error) {
	if repository.resolveAccess == nil {
		return Access{}, ErrRepositoryForbidden
	}
	return repository.resolveAccess(ctx, actor, tenantID, capability, scope)
}
func (repository *fakeRepository) ResolveSubjectAccess(ctx context.Context, actor Actor, tenantID uuid.UUID, capability Capability, caseID kernel.EntityID, subject kernel.EntityReference) (SubjectAccess, error) {
	if repository.resolveSubjectAccess == nil {
		return SubjectAccess{}, ErrRepositoryForbidden
	}
	return repository.resolveSubjectAccess(ctx, actor, tenantID, capability, caseID, subject)
}
func (repository *fakeRepository) ResolveAlertSubjectAccess(ctx context.Context, actor Actor, tenantID uuid.UUID, capability Capability, alertID kernel.EntityID, subject kernel.EntityReference) (AlertSubjectAccess, error) {
	if repository.resolveAlertSubjectAccess == nil {
		return AlertSubjectAccess{}, ErrRepositoryForbidden
	}
	return repository.resolveAlertSubjectAccess(ctx, actor, tenantID, capability, alertID, subject)
}
func (repository *fakeRepository) LoadWorkspace(ctx context.Context, _ Actor, tenantID uuid.UUID, caseID kernel.EntityID, access WorkspaceAccess) (Workspace, error) {
	if repository.loadWorkspace == nil {
		return Workspace{}, ErrRepositoryForbidden
	}
	return repository.loadWorkspace(ctx, tenantID, caseID, access)
}
func (repository *fakeRepository) LoadAlertWorkspace(ctx context.Context, _ Actor, tenantID uuid.UUID, alertID kernel.EntityID, access WorkspaceAccess) (AlertWorkspace, error) {
	if repository.loadAlertWorkspace == nil {
		return AlertWorkspace{}, ErrRepositoryForbidden
	}
	return repository.loadAlertWorkspace(ctx, tenantID, alertID, access)
}
func (repository *fakeRepository) CreateIndicator(ctx context.Context, write IndicatorWrite) (MutationResult[kernel.Indicator], error) {
	return repository.createIndicator(ctx, write)
}
func (repository *fakeRepository) ReplaceIndicator(ctx context.Context, write IndicatorWrite) (MutationResult[kernel.Indicator], error) {
	return repository.replaceIndicator(ctx, write)
}
func (repository *fakeRepository) CreateAsset(ctx context.Context, write AssetWrite) (MutationResult[kernel.Asset], error) {
	return repository.createAsset(ctx, write)
}
func (repository *fakeRepository) ReplaceAsset(ctx context.Context, write AssetWrite) (MutationResult[kernel.Asset], error) {
	return repository.replaceAsset(ctx, write)
}
func (repository *fakeRepository) CreateTimelineEvent(ctx context.Context, write TimelineWrite) (MutationResult[kernel.TimelineEvent], error) {
	return repository.createTimelineEvent(ctx, write)
}
func (repository *fakeRepository) CommitTask(ctx context.Context, write TaskCreateWrite) (MutationResult[kernel.Task], error) {
	if repository.commitTask == nil {
		return MutationResult[kernel.Task]{}, ErrRepositoryForbidden
	}
	return repository.commitTask(ctx, write)
}
func (repository *fakeRepository) MutateTask(ctx context.Context, write TaskMutationWrite) (MutationResult[kernel.Task], error) {
	if repository.mutateTask == nil {
		return MutationResult[kernel.Task]{}, ErrRepositoryForbidden
	}
	return repository.mutateTask(ctx, write)
}
func (repository *fakeRepository) CreateRelationship(ctx context.Context, write RelationshipWrite) (MutationResult[kernel.Relationship], error) {
	return repository.createRelationship(ctx, write)
}
func (repository *fakeRepository) MutateRelationship(ctx context.Context, write RelationshipMutationWrite) (MutationResult[kernel.Relationship], error) {
	if repository.mutateRelationship == nil {
		return MutationResult[kernel.Relationship]{}, ErrRepositoryForbidden
	}
	return repository.mutateRelationship(ctx, write)
}
func (repository *fakeRepository) CreateStorageObject(ctx context.Context, write StorageWrite) (PreparedUploadRecord, error) {
	return repository.createStorageObject(ctx, write)
}
func (repository *fakeRepository) GetCaseStorageObject(ctx context.Context, _ Actor, tenantID uuid.UUID, caseID, attachmentID, id kernel.EntityID, access Access) (kernel.StorageObject, error) {
	if repository.getCaseStorageObject == nil {
		return kernel.StorageObject{}, ErrRepositoryForbidden
	}
	return repository.getCaseStorageObject(ctx, tenantID, caseID, attachmentID, id, access)
}
func (repository *fakeRepository) GetAlertStorageObject(ctx context.Context, _ Actor, tenantID uuid.UUID, alertID, attachmentID, id kernel.EntityID, access Access) (kernel.StorageObject, error) {
	if repository.getAlertStorageObject == nil {
		return kernel.StorageObject{}, ErrRepositoryForbidden
	}
	return repository.getAlertStorageObject(ctx, tenantID, alertID, attachmentID, id, access)
}
func (repository *fakeRepository) GetStorageObjectAsWorker(ctx context.Context, worker WorkerContext, id kernel.EntityID) (kernel.StorageObject, error) {
	return repository.getStorageObjectAsWorker(ctx, worker, id)
}
func (repository *fakeRepository) MarkStorageUploadedAsWorker(ctx context.Context, write WorkerStorageWrite) (kernel.StorageObject, error) {
	return repository.markStorageUploadedAsWorker(ctx, write)
}
func (repository *fakeRepository) BeginStorageVerification(ctx context.Context, write WorkerStorageWrite) (kernel.StorageObject, error) {
	return repository.beginStorageVerification(ctx, write)
}
func (repository *fakeRepository) CompleteStorageVerification(ctx context.Context, write WorkerStorageWrite) (kernel.StorageObject, error) {
	return repository.completeStorageVerification(ctx, write)
}
func (repository *fakeRepository) RejectStorageVerification(ctx context.Context, write WorkerStorageWrite) error {
	if repository.rejectStorageVerification == nil {
		return nil
	}
	return repository.rejectStorageVerification(ctx, write)
}
func (repository *fakeRepository) BeginStorageScan(ctx context.Context, write WorkerStorageWrite) (kernel.StorageObject, error) {
	return repository.beginStorageScan(ctx, write)
}
func (repository *fakeRepository) CompleteStorageScan(ctx context.Context, write WorkerStorageWrite) (kernel.StorageObject, error) {
	return repository.completeStorageScan(ctx, write)
}
func (repository *fakeRepository) GetAttachment(ctx context.Context, _ Actor, tenantID uuid.UUID, caseID, id kernel.EntityID, access Access) (AttachmentDownloadRecord, error) {
	return repository.getAttachment(ctx, tenantID, caseID, id, access)
}
func (repository *fakeRepository) GetAlertAttachment(ctx context.Context, _ Actor, tenantID uuid.UUID, alertID, id kernel.EntityID, access Access) (AttachmentDownloadRecord, error) {
	if repository.getAlertAttachment == nil {
		return AttachmentDownloadRecord{}, ErrRepositoryForbidden
	}
	return repository.getAlertAttachment(ctx, tenantID, alertID, id, access)
}
func (repository *fakeRepository) AuditDownloadGrant(ctx context.Context, write DownloadGrantAuditWrite) error {
	if repository.auditDownloadGrant == nil {
		return ErrRepositoryForbidden
	}
	return repository.auditDownloadGrant(ctx, write)
}
func (repository *fakeRepository) CreateEvidence(ctx context.Context, write EvidenceWrite) (MutationResult[kernel.Evidence], error) {
	return repository.createEvidence(ctx, write)
}
func (repository *fakeRepository) GetEvidence(ctx context.Context, _ Actor, tenantID uuid.UUID, caseID, id kernel.EntityID, access Access) (kernel.Evidence, error) {
	return repository.getEvidence(ctx, tenantID, caseID, id, access)
}
func (repository *fakeRepository) AppendCustody(ctx context.Context, write CustodyWrite) (MutationResult[kernel.Evidence], error) {
	return repository.appendCustody(ctx, write)
}

type fakeObjectStorage struct {
	prepareUpload   func(context.Context, ObjectLocation, int64, string, time.Time) (UploadGrant, error)
	prepareDownload func(context.Context, ObjectLocation, time.Time) (DownloadGrant, error)
	open            func(context.Context, ObjectLocation) (ObjectReader, error)
}

func (storage *fakeObjectStorage) PrepareUpload(ctx context.Context, location ObjectLocation, maximum int64, contentType string, expiry time.Time) (UploadGrant, error) {
	if storage.prepareUpload == nil {
		return UploadGrant{}, errors.New("not configured")
	}
	return storage.prepareUpload(ctx, location, maximum, contentType, expiry)
}
func (storage *fakeObjectStorage) PrepareDownload(ctx context.Context, location ObjectLocation, expiry time.Time) (DownloadGrant, error) {
	if storage.prepareDownload == nil {
		return DownloadGrant{}, errors.New("not configured")
	}
	return storage.prepareDownload(ctx, location, expiry)
}
func (storage *fakeObjectStorage) Open(ctx context.Context, location ObjectLocation) (ObjectReader, error) {
	if storage.open == nil {
		return ObjectReader{}, errors.New("not configured")
	}
	return storage.open(ctx, location)
}

type fakeScanner struct {
	scan func(context.Context, io.Reader, int64) (ScanVerdict, error)
}

func (scanner *fakeScanner) Scan(ctx context.Context, reader io.Reader, maximum int64) (ScanVerdict, error) {
	if scanner.scan == nil {
		return ScanVerdictFailed, errors.New("not configured")
	}
	return scanner.scan(ctx, reader, maximum)
}

type trackingReadCloser struct {
	io.Reader
	closed *bool
}

func (reader *trackingReadCloser) Close() error { *reader.closed = true; return nil }

func mustService(t *testing.T, repository Repository, storage ObjectStorage, scanner MalwareScanner) *Service {
	return mustServiceAt(t, repository, storage, scanner, testTime(0))
}
func mustServiceAt(t *testing.T, repository Repository, storage ObjectStorage, scanner MalwareScanner, now time.Time) *Service {
	t.Helper()
	service, err := NewService(repository, storage, scanner, ServiceConfig{
		Bucket: "periapsis-evidence", MaximumSize: 1_024, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}
func testActor(tenantID uuid.UUID, kind PrincipalKind) Actor {
	return Actor{
		TenantID: tenantID, UserID: testUUID(240), SessionID: testUUID(242), ActiveTenantID: tenantID,
		MembershipID: testUUID(241), AuthenticationMethod: "password", Kind: kind,
	}
}
func testEnvelope(seed byte) MutationEnvelope {
	return MutationEnvelope{IdempotencyKey: "phase4-command-" + string(rune('a'+seed%26)), Audit: AuditContext{
		RequestID: testUUID(seed), CorrelationID: testUUID(seed + 1), IPAddress: netip.MustParseAddr("192.0.2.20"),
		UserAgent: "phase4-test", AuthenticationMethod: "password",
	}}
}
func testWorker(tenantID uuid.UUID, seed byte) WorkerContext {
	return WorkerContext{TenantID: tenantID, OperationID: testUUID(seed), CorrelationID: testUUID(seed + 1)}
}
func indicatorInput(t *testing.T, tenantID uuid.UUID, seed byte) kernel.IndicatorInput {
	t.Helper()
	return kernel.IndicatorInput{ID: testEntityID(t, seed), TenantID: testEntityIDFromUUID(t, tenantID),
		Type: kernel.IndicatorDomain, Value: "Example.COM", Source: "analyst", Confidence: 80, TLP: kernel.TLPAmber,
		FirstSeen: testTime(1), LastSeen: testTime(2), Malicious: kernel.MaliciousSuspicious,
	}
}
func uploadedStorageObject(t *testing.T, tenantID uuid.UUID, seed byte, now time.Time) kernel.StorageObject {
	t.Helper()
	object := pendingStorageObject(t, tenantID, seed, now)
	var err error
	object, err = object.MarkUploaded(object.Version(), now.Add(time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	return object
}

func pendingStorageObject(t *testing.T, tenantID uuid.UUID, seed byte, now time.Time) kernel.StorageObject {
	t.Helper()
	tenantEntity := testEntityIDFromUUID(t, tenantID)
	object, err := kernel.NewStorageObject(kernel.StorageObjectInput{ID: testEntityID(t, seed), TenantID: tenantEntity,
		Bucket: "periapsis-evidence", ObjectKey: tenantID.String() + "/" + testEntityID(t, seed).String(),
		OriginalFilename: "capture.bin", Classification: kernel.EvidenceInternal,
		ExpectedSizeBytes: int64(len("forensic payload")), UploadExpiresAt: now.Add(15 * time.Minute),
		CreatedBy: testEntityID(t, seed+1), CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return object
}

func availableStorageObject(t *testing.T, tenantID uuid.UUID, seed byte, now time.Time) kernel.StorageObject {
	t.Helper()
	object := uploadedStorageObject(t, tenantID, seed, now)
	var err error
	object, err = object.BeginVerification(object.Version(), now.Add(2*time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("forensic payload"))
	object, err = object.CompleteVerification(object.Version(), fmtDigest(digest), int64(len("forensic payload")), "text/plain", now.Add(3*time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	object, err = object.BeginScan(object.Version(), now.Add(4*time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	object, err = object.CompleteScan(object.Version(), kernel.ScanAvailable, now.Add(5*time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	return object
}
func testEntityIDFromUUID(t *testing.T, value uuid.UUID) kernel.EntityID {
	t.Helper()
	id, err := kernel.NewEntityID([16]byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func testEntityID(t *testing.T, seed byte) kernel.EntityID {
	return testEntityIDFromUUID(t, testUUID(seed))
}
func testUUID(seed byte) uuid.UUID {
	return uuid.UUID{0x01, 0x9d, 0x02, 0x00, 0, seed, 0x70, seed, 0x80, seed, 0, 0, 0, 0, 0, seed}
}
func testTime(offset int) time.Time { return time.Date(2026, 8, 25, 12, 0, 0, offset*1_000, time.UTC) }
func fmtDigest(value [sha256.Size]byte) string {
	const alphabet = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, current := range value {
		result[index*2] = alphabet[current>>4]
		result[index*2+1] = alphabet[current&0x0f]
	}
	return string(result)
}
