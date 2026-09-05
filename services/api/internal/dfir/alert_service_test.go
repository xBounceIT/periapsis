package dfir

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

func TestAlertWorkspaceRequiresEveryExactLiveCapability(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(60)
	alertID := testEntityID(t, 61)
	actor := testActor(tenantID, PrincipalHuman)
	wantCapabilities := map[Capability]bool{
		CapabilityIOCRead: false, CapabilityAssetRead: false,
		CapabilityTimelineRead: false, CapabilityAttachmentRead: false,
	}
	repository := &fakeRepository{
		resolveAlertAccess: func(_ context.Context, got Actor, gotTenant uuid.UUID, capability Capability, scope AlertResourceScope) (Access, error) {
			if got != actor || gotTenant != tenantID || scope.AlertID != alertID {
				t.Fatal("Alert workspace authorization was not bound to the exact actor, tenant, and Alert")
			}
			if _, expected := wantCapabilities[capability]; !expected || wantCapabilities[capability] {
				t.Fatalf("unexpected or duplicate capability resolution: %q", capability)
			}
			wantCapabilities[capability] = true
			return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, nil
		},
		loadAlertWorkspace: func(_ context.Context, gotTenant uuid.UUID, gotAlert kernel.EntityID, access WorkspaceAccess) (AlertWorkspace, error) {
			if gotTenant != tenantID || gotAlert != alertID || len(access) != len(wantCapabilities) {
				t.Fatal("Alert workspace repository read lost its exact root or access tuple")
			}
			for capability, resolved := range wantCapabilities {
				if !resolved || access[capability] != (Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}) {
					t.Fatalf("missing live Alert access for %q", capability)
				}
			}
			return AlertWorkspace{}, nil
		},
	}
	service := mustService(t, repository, &fakeObjectStorage{}, &fakeScanner{})
	if _, err := service.AlertWorkspace(context.Background(), actor, tenantID, alertID); err != nil {
		t.Fatalf("AlertWorkspace() error = %v", err)
	}
	for capability, resolved := range wantCapabilities {
		if !resolved {
			t.Fatalf("capability %q was not resolved", capability)
		}
	}

	called := false
	repository.resolveAlertAccess = func(context.Context, Actor, uuid.UUID, Capability, AlertResourceScope) (Access, error) {
		called = true
		return Access{}, nil
	}
	if _, err := service.AlertWorkspace(
		context.Background(), testActor(tenantID, PrincipalCustomer), tenantID, alertID,
	); !errors.Is(err, ErrForbidden) || called {
		t.Fatalf("customer Alert workspace = (%v, resolved=%t), want forbidden before repository", err, called)
	}
}

func TestAlertWorkspaceRejectsCaseRootedOrIndirectResources(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(62)
	tenant := testEntityIDFromUUID(t, tenantID)
	alertID := testEntityID(t, 63)
	caseID := testEntityID(t, 64)
	event, err := kernel.NewTimelineEvent(alertTimelineInput(t, tenantID, alertID, 65))
	if err != nil {
		t.Fatal(err)
	}
	workspace := AlertWorkspace{Timeline: []Versioned[kernel.TimelineEvent]{{Resource: event, Version: 1}}}
	if !validAlertWorkspace(workspace, tenantID, alertID) {
		t.Fatal("valid direct Alert timeline was rejected")
	}
	referencedIndicator, err := kernel.NewIndicator(indicatorInput(t, tenantID, 67))
	if err != nil {
		t.Fatal(err)
	}
	linkedInput := alertTimelineInput(t, tenantID, alertID, 59)
	linkedInput.IOCIDs = []kernel.EntityID{referencedIndicator.ID()}
	linkedEvent, err := kernel.NewTimelineEvent(linkedInput)
	if err != nil {
		t.Fatal(err)
	}
	workspace.Timeline[0].Resource = linkedEvent
	if validAlertWorkspace(workspace, tenantID, alertID) {
		t.Fatal("timeline reference outside the direct Alert inventory was accepted")
	}
	workspace.Indicators = []Versioned[kernel.Indicator]{{Resource: referencedIndicator, Version: 1}}
	workspace.SharedResources = []SharedResource{{ResourceKind: kernel.EntityIOC, ResourceID: referencedIndicator.ID(), Roots: []RelatedRoot{{Kind: kernel.EntityAlert, ID: alertID}}}}
	if !validAlertWorkspace(workspace, tenantID, alertID) {
		t.Fatal("timeline reference to the direct Alert inventory was rejected")
	}

	caseInput := alertTimelineInput(t, tenantID, alertID, 66)
	caseInput.AlertID, caseInput.CaseID = kernel.EntityID{}, caseID
	caseEvent, err := kernel.NewTimelineEvent(caseInput)
	if err != nil {
		t.Fatal(err)
	}
	workspace.Timeline[0].Resource = caseEvent
	if validAlertWorkspace(workspace, tenantID, alertID) {
		t.Fatal("Case-rooted timeline leaked into an Alert workspace")
	}

	workspace = AlertWorkspace{Indicators: []Versioned[kernel.Indicator]{{Resource: referencedIndicator, Version: 1}}}
	foreignSubject, err := kernel.NewEntityReference(tenant, kernel.EntityIOC, testEntityID(t, 68))
	if err != nil {
		t.Fatal(err)
	}
	attachment, err := kernel.NewAttachment(kernel.AttachmentInput{
		ID: testEntityID(t, 69), TenantID: tenant, Subject: foreignSubject,
		StorageObjectID: testEntityID(t, 70), OriginalFilename: "capture.bin",
		RequestedVisibility: kernel.VisibilityPrivate, SubjectVisibility: kernel.VisibilityPrivate,
		UploadedBy: testEntityID(t, 71), UploadedAt: testTime(0), ScanState: kernel.ScanPendingUpload,
	})
	if err != nil {
		t.Fatal(err)
	}
	workspace.Attachments = []kernel.Attachment{attachment}
	if validAlertWorkspace(workspace, tenantID, alertID) {
		t.Fatal("attachment to an IOC outside the direct Alert projection was accepted")
	}
}

func TestAlertIndicatorAndAssetWritesBindRootIdempotencyAndCAS(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(72)
	alertID := testEntityID(t, 73)
	actor := testActor(tenantID, PrincipalHuman)
	repository := &fakeRepository{
		resolveAlertAccess: allowExactAlertAccess(t, actor, tenantID, alertID),
	}
	var indicatorDigest [sha256.Size]byte
	repository.createIndicator = func(_ context.Context, write IndicatorWrite) (MutationResult[kernel.Indicator], error) {
		if write.AlertID != alertID || write.CaseID != (kernel.EntityID{}) || write.ExpectedVersion != 0 ||
			write.Command.Operation != operationIOCCreate || write.Command.RequestDigest == ([sha256.Size]byte{}) {
			t.Fatal("Alert IOC create lost its root, command, or create-only version")
		}
		indicatorDigest = write.Command.RequestDigest
		return MutationResult[kernel.Indicator]{Resource: write.Indicator}, nil
	}
	repository.replaceAsset = func(_ context.Context, write AssetWrite) (MutationResult[kernel.Asset], error) {
		if write.AlertID != alertID || write.CaseID != (kernel.EntityID{}) || write.ExpectedVersion != 7 ||
			write.Command.Operation != operationAssetReplace || write.Command.RequestDigest == ([sha256.Size]byte{}) {
			t.Fatal("Alert asset replace lost its root, command, or CAS version")
		}
		return MutationResult[kernel.Asset]{Resource: write.Asset}, nil
	}
	service := mustService(t, repository, &fakeObjectStorage{}, &fakeScanner{})
	if _, err := service.CreateAlertIndicator(context.Background(), actor, tenantID, AlertIndicatorCommand{
		AlertID: alertID, Input: indicatorInput(t, tenantID, 74), Envelope: testEnvelope(75),
	}); err != nil {
		t.Fatalf("CreateAlertIndicator() error = %v", err)
	}
	if indicatorDigest == ([sha256.Size]byte{}) {
		t.Fatal("Alert IOC request digest was not captured")
	}
	if _, err := service.ReplaceAlertAsset(context.Background(), actor, tenantID, AlertAssetCommand{
		AlertID: alertID, Input: alertAssetInput(t, tenantID, 76), ExpectedVersion: 7, Envelope: testEnvelope(77),
	}); err != nil {
		t.Fatalf("ReplaceAlertAsset() error = %v", err)
	}
	repository.replaceAsset = func(context.Context, AssetWrite) (MutationResult[kernel.Asset], error) {
		return MutationResult[kernel.Asset]{}, ErrRepositoryPrecondition
	}
	if _, err := service.ReplaceAlertAsset(context.Background(), actor, tenantID, AlertAssetCommand{
		AlertID: alertID, Input: alertAssetInput(t, tenantID, 76), ExpectedVersion: 7, Envelope: testEnvelope(77),
	}); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("stale Alert asset CAS error = %v, want precondition failed", err)
	}
	foreignActor := actor
	foreignActor.TenantID, foreignActor.ActiveTenantID = testUUID(79), testUUID(79)
	if _, err := service.CreateAlertIndicator(context.Background(), foreignActor, tenantID, AlertIndicatorCommand{
		AlertID: alertID, Input: indicatorInput(t, tenantID, 74), Envelope: testEnvelope(75),
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-tenant Alert IOC error = %v, want forbidden", err)
	}

	otherAlert := testEntityID(t, 78)
	first, err := commandBinding(operationIOCCreate, "shared-key", alertScopedFingerprint(alertID, map[string]any{"value": "same"}))
	if err != nil {
		t.Fatal(err)
	}
	second, err := commandBinding(operationIOCCreate, "shared-key", alertScopedFingerprint(otherAlert, map[string]any{"value": "same"}))
	if err != nil {
		t.Fatal(err)
	}
	if first.KeyDigest != second.KeyDigest || first.RequestDigest == second.RequestDigest {
		t.Fatal("Alert identity was not bound into the normalized idempotency request")
	}
}

func TestAlertResourceMutationsRejectTerminalRevisionBeforeRepository(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(84)
	alertID := testEntityID(t, 85)
	actor := testActor(tenantID, PrincipalHuman)
	repository := &fakeRepository{
		resolveAlertAccess: allowExactAlertAccess(t, actor, tenantID, alertID),
		replaceIndicator: func(context.Context, IndicatorWrite) (MutationResult[kernel.Indicator], error) {
			t.Fatal("terminal Alert IOC revision reached the repository")
			return MutationResult[kernel.Indicator]{}, nil
		},
		replaceAsset: func(context.Context, AssetWrite) (MutationResult[kernel.Asset], error) {
			t.Fatal("terminal Alert asset revision reached the repository")
			return MutationResult[kernel.Asset]{}, nil
		},
	}
	service := mustService(t, repository, &fakeObjectStorage{}, &fakeScanner{})
	if _, err := service.ReplaceAlertIndicator(context.Background(), actor, tenantID, AlertIndicatorCommand{
		AlertID: alertID, Input: indicatorInput(t, tenantID, 86),
		ExpectedVersion: kernel.MaximumResourceVersion, Envelope: testEnvelope(87),
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("terminal Alert IOC revision error = %v, want ErrInvalidInput", err)
	}
	if _, err := service.ReplaceAlertAsset(context.Background(), actor, tenantID, AlertAssetCommand{
		AlertID: alertID, Input: alertAssetInput(t, tenantID, 88),
		ExpectedVersion: kernel.MaximumResourceVersion, Envelope: testEnvelope(89),
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("terminal Alert asset revision error = %v, want ErrInvalidInput", err)
	}
}

func TestAlertTimelineReplayOwnsOriginalServerIngestionTime(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(94)
	alertID := testEntityID(t, 95)
	actor := testActor(tenantID, PrincipalHuman)
	input := alertTimelineInput(t, tenantID, alertID, 96)
	storedInput := input
	storedInput.IngestedAt = testTime(4)
	stored, err := kernel.NewTimelineEvent(storedInput)
	if err != nil {
		t.Fatal(err)
	}
	repository := &fakeRepository{
		resolveAlertAccess: allowExactAlertAccess(t, actor, tenantID, alertID),
		createTimelineEvent: func(_ context.Context, write TimelineWrite) (MutationResult[kernel.TimelineEvent], error) {
			if !write.Event.IngestedAt().Equal(testTime(5)) {
				t.Fatalf("current attempt ingestion time = %s", write.Event.IngestedAt())
			}
			return MutationResult[kernel.TimelineEvent]{Resource: stored, Replayed: true}, nil
		},
	}
	service := mustServiceAt(t, repository, &fakeObjectStorage{}, &fakeScanner{}, testTime(5))
	result, err := service.CreateAlertTimelineEvent(context.Background(), actor, tenantID, AlertTimelineCommand{
		Input: input, Envelope: testEnvelope(97),
	})
	if err != nil || !result.Replayed || !result.Resource.IngestedAt().Equal(storedInput.IngestedAt) {
		t.Fatalf("timeline replay = (%s, replayed=%t, %v)", result.Resource, result.Replayed, err)
	}
}

func TestAlertUploadRejectsObjectSizeMismatchAndCanceledContext(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(98)
	tenant := testEntityIDFromUUID(t, tenantID)
	alertID := testEntityID(t, 99)
	actor := testActor(tenantID, PrincipalHuman)
	subject, err := kernel.NewEntityReference(tenant, kernel.EntityAlert, alertID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	resolves, writes := 0, 0
	repository := &fakeRepository{
		resolveAlertSubjectAccess: func(context.Context, Actor, uuid.UUID, Capability, kernel.EntityID, kernel.EntityReference) (AlertSubjectAccess, error) {
			resolves++
			return AlertSubjectAccess{
				AlertID: alertID, Access: Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant},
				SubjectVisibility: kernel.VisibilityPrivate,
			}, nil
		},
		createStorageObject: func(_ context.Context, write StorageWrite) (PreparedUploadRecord, error) {
			writes++
			state := write.Storage.Snapshot()
			state.ExpectedSizeBytes++
			mismatched, restoreErr := kernel.RestoreStorageObject(state)
			if restoreErr != nil {
				t.Fatal(restoreErr)
			}
			return PreparedUploadRecord{Storage: mismatched, Attachment: write.Attachment}, nil
		},
	}
	presigns := 0
	storage := &fakeObjectStorage{prepareUpload: func(context.Context, ObjectLocation, int64, string, time.Time) (UploadGrant, error) {
		presigns++
		return UploadGrant{}, nil
	}}
	service := mustServiceAt(t, repository, storage, &fakeScanner{}, now)
	command := AlertPrepareUploadCommand{
		AlertID: alertID, AttachmentID: testEntityID(t, 100), StorageObjectID: testEntityID(t, 101),
		Subject: subject, OriginalFilename: "capture.bin", Classification: kernel.EvidenceInternal,
		RequestedVisibility: kernel.VisibilityPrivate, SizeBytes: 128, ContentType: "application/octet-stream",
		Envelope: testEnvelope(102),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := service.PrepareAlertUpload(ctx, actor, tenantID, command); !errors.Is(err, ErrUnavailable) || writes != 1 || presigns != 0 {
		t.Fatalf("mismatched upload = (%v, writes=%d, presigns=%d)", err, writes, presigns)
	}

	canceled, cancelNow := context.WithTimeout(context.Background(), time.Minute)
	cancelNow()
	if _, err := service.PrepareAlertUpload(canceled, actor, tenantID, command); !errors.Is(err, context.Canceled) || resolves != 1 || writes != 1 || presigns != 0 {
		t.Fatalf("canceled upload = (%v, resolves=%d, writes=%d, presigns=%d)", err, resolves, writes, presigns)
	}
	if _, err := service.PrepareAlertDownload(canceled, actor, tenantID, AlertDownloadCommand{
		AlertID: alertID, AttachmentID: command.AttachmentID, Subject: subject, Audit: testEnvelope(90).Audit,
	}); !errors.Is(err, context.Canceled) || resolves != 1 || writes != 1 || presigns != 0 {
		t.Fatalf("canceled download = (%v, resolves=%d, writes=%d, presigns=%d)", err, resolves, writes, presigns)
	}

	repository.createStorageObject = func(_ context.Context, write StorageWrite) (PreparedUploadRecord, error) {
		writes++
		return PreparedUploadRecord{Storage: write.Storage, Attachment: write.Attachment}, nil
	}
	duringStorageDeadline, cancelStorageDeadline := context.WithTimeout(context.Background(), time.Minute)
	defer cancelStorageDeadline()
	duringStorage, cancelDuringStorage := context.WithCancel(duringStorageDeadline)
	storage.prepareUpload = func(context.Context, ObjectLocation, int64, string, time.Time) (UploadGrant, error) {
		presigns++
		cancelDuringStorage()
		return UploadGrant{}, context.Canceled
	}
	if _, err := service.PrepareAlertUpload(duringStorage, actor, tenantID, command); !errors.Is(err, context.Canceled) ||
		resolves != 2 || writes != 2 || presigns != 1 {
		t.Fatalf("upload canceled during signing = (%v, resolves=%d, writes=%d, presigns=%d)", err, resolves, writes, presigns)
	}
}

func TestCreateAlertTimelineAllowsSameRootEvidenceAndRejectsCaseRoot(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(79)
	alertID := testEntityID(t, 80)
	actor := testActor(tenantID, PrincipalHuman)
	writes := 0
	repository := &fakeRepository{
		resolveAlertAccess: allowExactAlertAccess(t, actor, tenantID, alertID),
		createTimelineEvent: func(_ context.Context, write TimelineWrite) (MutationResult[kernel.TimelineEvent], error) {
			writes++
			if write.AlertID != alertID || write.CaseID != (kernel.EntityID{}) || write.Event.AlertID() != alertID ||
				write.Event.CaseID() != (kernel.EntityID{}) {
				t.Fatal("Alert timeline write was not directly Alert-rooted")
			}
			return MutationResult[kernel.TimelineEvent]{Resource: write.Event}, nil
		},
	}
	service := mustServiceAt(t, repository, &fakeObjectStorage{}, &fakeScanner{}, testTime(0))
	input := alertTimelineInput(t, tenantID, alertID, 81)
	if _, err := service.CreateAlertTimelineEvent(context.Background(), actor, tenantID, AlertTimelineCommand{
		Input: input, Envelope: testEnvelope(82),
	}); err != nil || writes != 1 {
		t.Fatalf("CreateAlertTimelineEvent() = (%v, writes=%d)", err, writes)
	}

	evidenceID := testEntityID(t, 83)
	input.EvidenceIDs = []kernel.EntityID{evidenceID}
	if _, err := service.CreateAlertTimelineEvent(context.Background(), actor, tenantID, AlertTimelineCommand{
		Input: input, Envelope: testEnvelope(84),
	}); err != nil || writes != 2 {
		t.Fatalf("Alert timeline evidence link = (%v, writes=%d), want accepted write", err, writes)
	}
	input.EvidenceIDs = nil
	input.CaseID = testEntityID(t, 85)
	if _, err := service.CreateAlertTimelineEvent(context.Background(), actor, tenantID, AlertTimelineCommand{
		Input: input, Envelope: testEnvelope(86),
	}); !errors.Is(err, ErrInvalidInput) || writes != 2 {
		t.Fatalf("ambiguous Alert/Case timeline = (%v, writes=%d), want invalid without write", err, writes)
	}
}

func TestAlertAttachmentPreparationUsesOnlyDirectAlertSubjects(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(87)
	tenant := testEntityIDFromUUID(t, tenantID)
	alertID := testEntityID(t, 88)
	assetID := testEntityID(t, 89)
	actor := testActor(tenantID, PrincipalHuman)
	subject, err := kernel.NewEntityReference(tenant, kernel.EntityAsset, assetID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	access := AlertSubjectAccess{
		AlertID: alertID, Access: Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant},
		SubjectVisibility: kernel.VisibilityPrivate,
	}
	downloadAudit := testEnvelope(93).Audit
	downloadAudits := 0
	var storedAttachment kernel.Attachment
	var storedObject kernel.StorageObject
	repository := &fakeRepository{
		resolveAlertSubjectAccess: func(_ context.Context, got Actor, gotTenant uuid.UUID, capability Capability, gotAlert kernel.EntityID, gotSubject kernel.EntityReference) (AlertSubjectAccess, error) {
			if got != actor || gotTenant != tenantID || gotAlert != alertID || !sameEntityReference(gotSubject, subject) ||
				(capability != CapabilityAttachmentManage && capability != CapabilityAttachmentRead) {
				t.Fatal("attachment authority was not bound to the direct Alert subject")
			}
			return access, nil
		},
		createStorageObject: func(_ context.Context, write StorageWrite) (PreparedUploadRecord, error) {
			if write.AlertID != alertID || write.CaseID != (kernel.EntityID{}) || !sameEntityReference(write.Attachment.Subject(), subject) ||
				write.Attachment.Visibility() != kernel.VisibilityPrivate {
				t.Fatal("prepared upload was not bound to the direct private Alert subject")
			}
			storedAttachment, storedObject = write.Attachment, write.Storage
			return PreparedUploadRecord{Storage: write.Storage, Attachment: write.Attachment}, nil
		},
		getAlertAttachment: func(_ context.Context, gotTenant uuid.UUID, gotAlert, gotID kernel.EntityID, gotAccess Access) (AttachmentDownloadRecord, error) {
			if gotTenant != tenantID || gotAlert != alertID || gotID != storedAttachment.ID() || gotAccess != access.Access {
				t.Fatal("download attachment lookup lost its exact Alert fence")
			}
			return AttachmentDownloadRecord{Attachment: storedAttachment, AttachmentVersion: 5, RootVersion: 9}, nil
		},
		getAlertStorageObject: func(_ context.Context, gotTenant uuid.UUID, gotAlert, gotAttachment, gotID kernel.EntityID, gotAccess Access) (kernel.StorageObject, error) {
			if gotTenant != tenantID || gotAlert != alertID || gotAttachment != storedAttachment.ID() ||
				gotID != storedObject.ID() || gotAccess != access.Access {
				t.Fatal("download storage lookup lost its exact Alert fence")
			}
			return storedObject, nil
		},
		auditDownloadGrant: func(_ context.Context, write DownloadGrantAuditWrite) error {
			downloadAudits++
			if write.Actor != actor || write.Audit != downloadAudit ||
				write.Root != (PortalAttachmentRoot{Kind: PortalTicketAlert, ID: alertID}) || write.RootVersion != 9 ||
				!sameEntityReference(write.Subject, subject) || write.AttachmentID != storedAttachment.ID() ||
				write.AttachmentVersion != 5 || write.AttachmentState != kernel.ScanAvailable ||
				write.StorageObjectID != storedObject.ID() || write.StorageVersion != storedObject.Version() ||
				write.StorageState != kernel.ScanAvailable || write.Access != access.Access ||
				write.PortalAuthorization != nil || !write.ExpiresAt.Equal(now.Add(5*time.Minute)) {
				t.Fatalf("operator Alert download audit lost its exact safe fence: %#v", write)
			}
			return nil
		},
	}
	downloadPresigns := 0
	storage := &fakeObjectStorage{
		prepareUpload: func(_ context.Context, location ObjectLocation, maximum int64, contentType string, expiresAt time.Time) (UploadGrant, error) {
			if location.Key != tenantID.String()+"/"+testEntityID(t, 90).String() || maximum != 128 || contentType != "application/octet-stream" {
				t.Fatal("Alert upload grant was not constrained to the canonical object location")
			}
			return UploadGrant{TargetURL: "https://storage.invalid/alert-upload?signature=redacted", Method: "PUT", ExpiresAt: expiresAt}, nil
		},
		prepareDownload: func(_ context.Context, location ObjectLocation, expiresAt time.Time) (DownloadGrant, error) {
			downloadPresigns++
			if location.Key != storedObject.ObjectKey() {
				t.Fatal("Alert download used a non-canonical object location")
			}
			return DownloadGrant{TargetURL: "https://storage.invalid/alert-download?signature=redacted", ExpiresAt: expiresAt}, nil
		},
	}
	service := mustServiceAt(t, repository, storage, &fakeScanner{}, now)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	upload, err := service.PrepareAlertUpload(ctx, actor, tenantID, AlertPrepareUploadCommand{
		AlertID: alertID, AttachmentID: testEntityID(t, 91), StorageObjectID: testEntityID(t, 90),
		Subject: subject, OriginalFilename: "capture.bin", Classification: kernel.EvidenceInternal,
		RequestedVisibility: kernel.VisibilityPublic, SizeBytes: 128, ContentType: "application/octet-stream",
		Envelope: testEnvelope(92),
	})
	if err != nil || upload.Object.State() != kernel.ScanPendingUpload {
		t.Fatalf("PrepareAlertUpload() = (%s, %v)", upload.Object, err)
	}

	storedObject = availableStorageObject(t, tenantID, 90, now.Add(-time.Minute))
	storedAttachment, err = kernel.NewAttachment(kernel.AttachmentInput{
		ID: testEntityID(t, 91), TenantID: tenant, Subject: subject,
		StorageObjectID: storedObject.ID(), OriginalFilename: "capture.bin",
		RequestedVisibility: kernel.VisibilityPrivate, SubjectVisibility: kernel.VisibilityPrivate,
		UploadedBy: storedObject.CreatedBy(), UploadedAt: storedObject.CreatedAt(), ScanState: kernel.ScanAvailable,
	})
	if err != nil {
		t.Fatal(err)
	}
	download, err := service.PrepareAlertDownload(ctx, actor, tenantID, AlertDownloadCommand{
		AlertID: alertID, AttachmentID: storedAttachment.ID(), Subject: subject, Audit: downloadAudit,
	})
	if err != nil || download.Attachment.ID() != storedAttachment.ID() || downloadAudits != 1 {
		t.Fatalf("PrepareAlertDownload() = (%s, %v)", download.Attachment, err)
	}
	if downloadPresigns != 1 {
		t.Fatalf("download presigns = %d, want 1", downloadPresigns)
	}
	storedAttachment, err = kernel.NewAttachment(kernel.AttachmentInput{
		ID: testEntityID(t, 91), TenantID: tenant, Subject: subject,
		StorageObjectID: storedObject.ID(), OriginalFilename: "capture.bin",
		RequestedVisibility: kernel.VisibilityPrivate, SubjectVisibility: kernel.VisibilityPrivate,
		UploadedBy: storedObject.CreatedBy(), UploadedAt: storedObject.CreatedAt().Add(time.Microsecond),
		ScanState: kernel.ScanAvailable,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.PrepareAlertDownload(ctx, actor, tenantID, AlertDownloadCommand{
		AlertID: alertID, AttachmentID: storedAttachment.ID(), Subject: subject, Audit: testEnvelope(94).Audit,
	}); !errors.Is(err, ErrNotFound) || downloadPresigns != 1 {
		t.Fatalf("mismatched attachment/storage timestamp = (%v, presigns=%d)", err, downloadPresigns)
	}
	storedAttachment, err = kernel.NewAttachment(kernel.AttachmentInput{
		ID: testEntityID(t, 91), TenantID: tenant, Subject: subject,
		StorageObjectID: storedObject.ID(), OriginalFilename: "capture.bin",
		RequestedVisibility: kernel.VisibilityPrivate, SubjectVisibility: kernel.VisibilityPrivate,
		UploadedBy: storedObject.CreatedBy(), UploadedAt: storedObject.CreatedAt(), ScanState: kernel.ScanAvailable,
	})
	if err != nil {
		t.Fatal(err)
	}
	state := storedObject.Snapshot()
	state.OriginalFilename = "other-purpose.bin"
	storedObject, err = kernel.RestoreStorageObject(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.PrepareAlertDownload(ctx, actor, tenantID, AlertDownloadCommand{
		AlertID: alertID, AttachmentID: storedAttachment.ID(), Subject: subject, Audit: testEnvelope(95).Audit,
	}); !errors.Is(err, ErrNotFound) || downloadPresigns != 1 {
		t.Fatalf("mismatched attachment/storage purpose = (%v, presigns=%d)", err, downloadPresigns)
	}

	access.AlertID = testEntityID(t, 93)
	if _, err := service.PrepareAlertDownload(ctx, actor, tenantID, AlertDownloadCommand{
		AlertID: alertID, AttachmentID: storedAttachment.ID(), Subject: subject, Audit: testEnvelope(96).Audit,
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("mismatched resolved Alert download error = %v, want forbidden", err)
	}

	access.AlertID = alertID
	storedObject = availableStorageObject(t, tenantID, 90, now.Add(-time.Minute))
	storedAttachment, err = kernel.NewAttachment(kernel.AttachmentInput{
		ID: testEntityID(t, 91), TenantID: tenant, Subject: subject,
		StorageObjectID: storedObject.ID(), OriginalFilename: storedObject.OriginalFilename(),
		RequestedVisibility: kernel.VisibilityPrivate, SubjectVisibility: kernel.VisibilityPrivate,
		UploadedBy: storedObject.CreatedBy(), UploadedAt: storedObject.CreatedAt(), ScanState: kernel.ScanAvailable,
	})
	if err != nil {
		t.Fatal(err)
	}
	repository.auditDownloadGrant = func(context.Context, DownloadGrantAuditWrite) error {
		downloadAudits++
		return errors.New("audit storage unavailable")
	}
	dropped, err := service.PrepareAlertDownload(ctx, actor, tenantID, AlertDownloadCommand{
		AlertID: alertID, AttachmentID: storedAttachment.ID(), Subject: subject, Audit: testEnvelope(97).Audit,
	})
	if !errors.Is(err, ErrUnavailable) || dropped.Grant.TargetURL != "" ||
		downloadPresigns != 2 || downloadAudits != 2 {
		t.Fatalf("failed Alert audit returned grant = (%s, %v), presigns=%d audits=%d", dropped.Grant, err, downloadPresigns, downloadAudits)
	}
}

func allowExactAlertAccess(
	t *testing.T,
	actor Actor,
	tenantID uuid.UUID,
	alertID kernel.EntityID,
) func(context.Context, Actor, uuid.UUID, Capability, AlertResourceScope) (Access, error) {
	t.Helper()
	return func(_ context.Context, got Actor, gotTenant uuid.UUID, capability Capability, scope AlertResourceScope) (Access, error) {
		if got != actor || gotTenant != tenantID || scope.AlertID != alertID ||
			(capability != CapabilityIOCManage && capability != CapabilityAssetManage && capability != CapabilityTimelineManage) {
			t.Fatalf("unexpected Alert authority request: actor=%#v tenant=%s capability=%q root=%s", got, gotTenant, capability, scope.AlertID)
		}
		return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, nil
	}
}

func alertAssetInput(t *testing.T, tenantID uuid.UUID, seed byte) kernel.AssetInput {
	t.Helper()
	return kernel.AssetInput{
		ID: testEntityID(t, seed), TenantID: testEntityIDFromUUID(t, tenantID),
		Hostname: "WORKSTATION-01", IPAddresses: []string{"192.0.2.10"},
		AssetType: "endpoint", OperatingSystem: "Private OS", Owner: "Private Owner",
		BusinessUnit: "security", Criticality: kernel.AssetCriticalityCritical,
		Environment: "production", ExternalID: "private-external-id", Tags: []string{"triage"},
		FirstSeen: testTime(1), LastSeen: testTime(2), CustomAttributes: json.RawMessage(`{"serial":"private"}`),
	}
}

func alertTimelineInput(t *testing.T, tenantID uuid.UUID, alertID kernel.EntityID, seed byte) kernel.TimelineEventInput {
	t.Helper()
	return kernel.TimelineEventInput{
		ID: testEntityID(t, seed), TenantID: testEntityIDFromUUID(t, tenantID), AlertID: alertID,
		EventTime: testTime(0), IngestedAt: testTime(0), OriginalTimezone: "UTC",
		Precision: kernel.PrecisionMicrosecond, Source: "endpoint_sensor", Category: "process_start",
		Title: "Observed event", Description: "Private event details", Tags: []string{"triage"},
	}
}
