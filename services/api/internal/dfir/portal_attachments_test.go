package dfir

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

func TestListCustomerPortalAttachmentsBindsAuthorizationFiltersBeforeBoundedPagination(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(1)
	root := PortalAttachmentRoot{Kind: PortalTicketAlert, ID: testEntityID(t, 2)}
	actor := testActor(tenantID, PrincipalCustomer)
	authorization := PortalAttachmentAuthorization{
		TenantID: tenantID, Root: root, ContactID: testUUID(3), TicketVersion: 7,
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	items := []kernel.Attachment{
		portalAttachmentFixture(t, tenantID, root.ID, 20, 40, now.Add(-time.Minute)),
		portalAttachmentFixture(t, tenantID, root.ID, 19, 39, now.Add(-2*time.Minute)),
		portalAttachmentFixture(t, tenantID, root.ID, 18, 38, now.Add(-3*time.Minute)),
	}
	authorizations, lists := 0, 0
	repository := &portalRepositoryFake{fakeRepository: &fakeRepository{
		auditDownloadGrant: func(context.Context, DownloadGrantAuditWrite) error { return nil },
	}}
	repository.list = func(_ context.Context, gotActor Actor, gotTenant uuid.UUID, query PortalAttachmentListQuery) ([]kernel.Attachment, error) {
		lists++
		if gotActor != actor || gotTenant != tenantID || query.Root != root || query.Authorization != authorization ||
			query.Bucket != "periapsis-evidence" || query.Limit != 3 {
			t.Fatalf("unbound portal list query: actor=%#v tenant=%s query=%#v", gotActor, gotTenant, query)
		}
		if lists == 1 {
			if query.After != nil {
				t.Fatal("first page unexpectedly had a cursor position")
			}
			return items, nil
		}
		if query.After == nil || query.After.ID != items[1].ID() || !query.After.UploadedAt.Equal(items[1].UploadedAt()) {
			t.Fatalf("second page cursor = %#v", query.After)
		}
		return []kernel.Attachment{items[2]}, nil
	}
	service := mustPortalService(t, repository, &fakeObjectStorage{}, portalAuthorizerFunc(func(
		_ context.Context, gotActor Actor, gotTenant uuid.UUID, gotRoot PortalAttachmentRoot,
	) (PortalAttachmentAuthorization, error) {
		authorizations++
		if gotActor != actor || gotTenant != tenantID || gotRoot != root {
			t.Fatal("portal authorizer lost the exact actor or root")
		}
		return authorization, nil
	}), now)

	first, err := service.ListCustomerPortalAttachments(context.Background(), actor, tenantID, root, CustomerPortalAttachmentListInput{Limit: 2})
	if err != nil || len(first.Items) != 2 || first.NextCursor == "" || lists != 1 || authorizations != 1 {
		t.Fatalf("first page = (%#v, %v), lists=%d authorizations=%d", first, err, lists, authorizations)
	}
	for index, item := range first.Items {
		if item.ID != items[index].ID() || item.ResourceKind != PortalTicketAlert || item.ResourceID != root.ID ||
			item.OriginalFilename != "capture.bin" || !item.UploadedAt.Equal(items[index].UploadedAt()) {
			t.Fatalf("customer allowlist item[%d] = %#v", index, item)
		}
	}
	second, err := service.ListCustomerPortalAttachments(context.Background(), actor, tenantID, root, CustomerPortalAttachmentListInput{
		Limit: 2, After: first.NextCursor,
	})
	if err != nil || len(second.Items) != 1 || second.NextCursor != "" || second.Items[0].ID != items[2].ID() {
		t.Fatalf("second page = (%#v, %v)", second, err)
	}

	otherRoot := root
	otherRoot.ID = testEntityID(t, 4)
	service.portalAuthorizer = portalAuthorizerFunc(func(context.Context, Actor, uuid.UUID, PortalAttachmentRoot) (PortalAttachmentAuthorization, error) {
		changed := authorization
		changed.Root = otherRoot
		return changed, nil
	})
	if _, err = service.ListCustomerPortalAttachments(context.Background(), actor, tenantID, otherRoot, CustomerPortalAttachmentListInput{
		Limit: 2, After: first.NextCursor,
	}); !errors.Is(err, ErrInvalidInput) || lists != 2 {
		t.Fatalf("cross-root cursor = (%v, lists=%d), want invalid before repository", err, lists)
	}
}

func TestPrepareCustomerPortalAttachmentDownloadReauthorizesAndRechecksBeforePresign(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(11)
	root := PortalAttachmentRoot{Kind: PortalTicketCase, ID: testEntityID(t, 12)}
	actor := testActor(tenantID, PrincipalCustomer)
	authorization := PortalAttachmentAuthorization{
		TenantID: tenantID, Root: root, ContactID: testUUID(13), TicketVersion: 9,
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	storageObject := availableStorageObject(t, tenantID, 30, now.Add(-time.Minute))
	attachment := portalAttachmentForStorage(t, tenantID, root.ID, 31, storageObject)
	audit := testEnvelope(14).Audit
	authorizations, reads, presigns, audits := 0, 0, 0, 0
	repository := &portalRepositoryFake{fakeRepository: &fakeRepository{
		auditDownloadGrant: func(_ context.Context, write DownloadGrantAuditWrite) error {
			audits++
			if write.Actor != actor || write.Audit != audit || write.Root != root || write.RootVersion != authorization.TicketVersion ||
				write.Subject != attachment.Subject() || write.AttachmentID != attachment.ID() || write.AttachmentVersion != 4 ||
				write.AttachmentState != kernel.ScanAvailable || write.StorageObjectID != storageObject.ID() ||
				write.StorageVersion != storageObject.Version() || write.StorageState != kernel.ScanAvailable ||
				write.Access != (Access{Audience: kernel.AudienceCustomer, Scope: ScopeOwn}) ||
				write.PortalAuthorization == nil || *write.PortalAuthorization != authorization ||
				!write.ExpiresAt.Equal(now.Add(5*time.Minute)) {
				t.Fatalf("portal download audit lost its exact safe authorization fence: %#v", write)
			}
			return nil
		},
	}}
	repository.get = func(_ context.Context, gotActor Actor, gotTenant uuid.UUID, query PortalAttachmentDownloadQuery) (PortalAttachmentDownloadRecord, error) {
		reads++
		if gotActor != actor || gotTenant != tenantID || query.Root != root || query.AttachmentID != attachment.ID() ||
			query.Authorization != authorization {
			t.Fatalf("unbound portal download query: %#v", query)
		}
		return PortalAttachmentDownloadRecord{
			Attachment: attachment, AttachmentVersion: 4, RootVersion: authorization.TicketVersion, Storage: storageObject,
		}, nil
	}
	storage := &fakeObjectStorage{prepareDownload: func(_ context.Context, location ObjectLocation, expiresAt time.Time) (DownloadGrant, error) {
		presigns++
		if location.Bucket != storageObject.Bucket() || location.Key != storageObject.ObjectKey() || !expiresAt.Equal(now.Add(5*time.Minute)) {
			t.Fatalf("download capability not bound to canonical object: %#v %s", location, expiresAt)
		}
		return DownloadGrant{TargetURL: "https://storage.invalid/customer-download?signature=redacted", ExpiresAt: expiresAt}, nil
	}}
	service := mustPortalService(t, repository, storage, portalAuthorizerFunc(func(
		_ context.Context, gotActor Actor, gotTenant uuid.UUID, gotRoot PortalAttachmentRoot,
	) (PortalAttachmentAuthorization, error) {
		authorizations++
		if gotActor != actor || gotTenant != tenantID || gotRoot != root {
			t.Fatal("portal download authorization was not exact")
		}
		return authorization, nil
	}), now)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	result, err := service.PrepareCustomerPortalAttachmentDownload(
		ctx, actor, tenantID, root, attachment.ID(), audit,
	)
	if err != nil || result.Attachment.ID != attachment.ID() || result.Attachment.ResourceID != root.ID ||
		result.Grant.TargetURL == "" || authorizations != 2 || reads != 2 || presigns != 1 || audits != 1 {
		t.Fatalf("PrepareCustomerPortalAttachmentDownload() = (%#v, %v), auth=%d reads=%d presigns=%d audits=%d", result, err, authorizations, reads, presigns, audits)
	}
	repository.auditDownloadGrant = func(context.Context, DownloadGrantAuditWrite) error {
		audits++
		return errors.New("audit storage unavailable")
	}
	dropped, err := service.PrepareCustomerPortalAttachmentDownload(
		ctx, actor, tenantID, root, attachment.ID(), testEnvelope(15).Audit,
	)
	if !errors.Is(err, ErrUnavailable) || dropped.Grant.TargetURL != "" ||
		authorizations != 4 || reads != 4 || presigns != 2 || audits != 2 {
		t.Fatalf("failed portal audit returned grant = (%#v, %v), auth=%d reads=%d presigns=%d audits=%d", dropped, err, authorizations, reads, presigns, audits)
	}
}

func TestPrepareCustomerPortalAttachmentDownloadFailsClosedOnAuthorizationOrPurposeDrift(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(51)
	root := PortalAttachmentRoot{Kind: PortalTicketAlert, ID: testEntityID(t, 52)}
	actor := testActor(tenantID, PrincipalCustomer)
	now := time.Now().UTC().Truncate(time.Microsecond)
	authorization := PortalAttachmentAuthorization{TenantID: tenantID, Root: root, ContactID: testUUID(53), TicketVersion: 3}
	storageObject := availableStorageObject(t, tenantID, 60, now.Add(-time.Minute))
	attachment := portalAttachmentForStorage(t, tenantID, root.ID, 61, storageObject)

	for name, mutate := range map[string]func(*PortalAttachmentDownloadRecord, *PortalAttachmentAuthorization){
		"object purpose": func(record *PortalAttachmentDownloadRecord, _ *PortalAttachmentAuthorization) {
			state := record.Storage.Snapshot()
			state.OriginalFilename = "other.bin"
			record.Storage, _ = kernel.RestoreStorageObject(state)
		},
		"live ticket version": func(_ *PortalAttachmentDownloadRecord, auth *PortalAttachmentAuthorization) {
			auth.TicketVersion++
		},
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			record := PortalAttachmentDownloadRecord{
				Attachment: attachment, AttachmentVersion: 4, RootVersion: authorization.TicketVersion, Storage: storageObject,
			}
			secondAuthorization := authorization
			mutate(&record, &secondAuthorization)
			authorizations, reads, presigns := 0, 0, 0
			repository := &portalRepositoryFake{fakeRepository: &fakeRepository{}, get: func(
				context.Context, Actor, uuid.UUID, PortalAttachmentDownloadQuery,
			) (PortalAttachmentDownloadRecord, error) {
				reads++
				return record, nil
			}}
			service := mustPortalService(t, repository, &fakeObjectStorage{prepareDownload: func(
				context.Context, ObjectLocation, time.Time,
			) (DownloadGrant, error) {
				presigns++
				return DownloadGrant{}, nil
			}}, portalAuthorizerFunc(func(context.Context, Actor, uuid.UUID, PortalAttachmentRoot) (PortalAttachmentAuthorization, error) {
				authorizations++
				if authorizations == 2 {
					return secondAuthorization, nil
				}
				return authorization, nil
			}), now)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			_, err := service.PrepareCustomerPortalAttachmentDownload(
				ctx, actor, tenantID, root, attachment.ID(), testEnvelope(54).Audit,
			)
			wantErr, wantAuthorizations := ErrNotFound, 1
			if name == "live ticket version" {
				wantErr, wantAuthorizations = ErrConflict, 2
			}
			if !errors.Is(err, wantErr) || authorizations != wantAuthorizations || reads != 1 || presigns != 0 {
				t.Fatalf("drift error=%v auth=%d reads=%d presigns=%d", err, authorizations, reads, presigns)
			}
		})
	}
}

func TestCustomerPortalAttachmentsHonorCancellationAndFailClosedWithoutPortalDependencies(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(71)
	root := PortalAttachmentRoot{Kind: PortalTicketCase, ID: testEntityID(t, 72)}
	actor := testActor(tenantID, PrincipalCustomer)
	service := mustServiceAt(t, &fakeRepository{}, &fakeObjectStorage{}, &fakeScanner{}, testTime(0))
	if _, err := service.ListCustomerPortalAttachments(context.Background(), actor, tenantID, root, CustomerPortalAttachmentListInput{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing portal dependencies error = %v, want unavailable", err)
	}
	if _, err := service.PrepareCustomerPortalAttachmentDownload(
		context.Background(), actor, tenantID, root, kernel.EntityID{}, testEnvelope(73).Audit,
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid attachment identifier error = %v, want invalid input", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.ListCustomerPortalAttachments(canceled, actor, tenantID, root, CustomerPortalAttachmentListInput{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled list error = %v", err)
	}
}

func TestCustomerPortalAttachmentDownloadDropsGrantWhenRequestIsCancelledDuringPresign(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(81)
	root := PortalAttachmentRoot{Kind: PortalTicketCase, ID: testEntityID(t, 82)}
	actor := testActor(tenantID, PrincipalCustomer)
	authorization := PortalAttachmentAuthorization{TenantID: tenantID, Root: root, ContactID: testUUID(83), TicketVersion: 2}
	now := time.Now().UTC().Truncate(time.Microsecond)
	storageObject := availableStorageObject(t, tenantID, 84, now.Add(-time.Minute))
	attachment := portalAttachmentForStorage(t, tenantID, root.ID, 86, storageObject)
	audits := 0
	repository := &portalRepositoryFake{fakeRepository: &fakeRepository{
		auditDownloadGrant: func(context.Context, DownloadGrantAuditWrite) error {
			audits++
			return nil
		},
	}, get: func(
		context.Context, Actor, uuid.UUID, PortalAttachmentDownloadQuery,
	) (PortalAttachmentDownloadRecord, error) {
		return PortalAttachmentDownloadRecord{
			Attachment: attachment, AttachmentVersion: 4, RootVersion: authorization.TicketVersion, Storage: storageObject,
		}, nil
	}}
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(time.Minute))
	defer cancel()
	presigns := 0
	service := mustPortalService(t, repository, &fakeObjectStorage{prepareDownload: func(
		context.Context, ObjectLocation, time.Time,
	) (DownloadGrant, error) {
		presigns++
		cancel()
		return DownloadGrant{TargetURL: "https://storage.invalid/cancelled?signature=redacted", ExpiresAt: now.Add(time.Minute)}, nil
	}}, portalAuthorizerFunc(func(context.Context, Actor, uuid.UUID, PortalAttachmentRoot) (PortalAttachmentAuthorization, error) {
		return authorization, nil
	}), now)
	if _, err := service.PrepareCustomerPortalAttachmentDownload(
		ctx, actor, tenantID, root, attachment.ID(), testEnvelope(87).Audit,
	); !errors.Is(err, context.Canceled) || presigns != 1 || audits != 0 {
		t.Fatalf("cancelled presign = (error=%v, calls=%d, audits=%d)", err, presigns, audits)
	}
}

type portalAuthorizerFunc func(context.Context, Actor, uuid.UUID, PortalAttachmentRoot) (PortalAttachmentAuthorization, error)

func (authorize portalAuthorizerFunc) AuthorizePortalAttachment(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	root PortalAttachmentRoot,
) (PortalAttachmentAuthorization, error) {
	return authorize(ctx, actor, tenantID, root)
}

type portalRepositoryFake struct {
	*fakeRepository
	list func(context.Context, Actor, uuid.UUID, PortalAttachmentListQuery) ([]kernel.Attachment, error)
	get  func(context.Context, Actor, uuid.UUID, PortalAttachmentDownloadQuery) (PortalAttachmentDownloadRecord, error)
}

func (repository *portalRepositoryFake) ListPortalAttachments(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	query PortalAttachmentListQuery,
) ([]kernel.Attachment, error) {
	if repository.list == nil {
		return nil, ErrRepositoryForbidden
	}
	return repository.list(ctx, actor, tenantID, query)
}

func (repository *portalRepositoryFake) GetPortalAttachmentDownload(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	query PortalAttachmentDownloadQuery,
) (PortalAttachmentDownloadRecord, error) {
	if repository.get == nil {
		return PortalAttachmentDownloadRecord{}, ErrRepositoryForbidden
	}
	return repository.get(ctx, actor, tenantID, query)
}

func mustPortalService(
	t *testing.T,
	repository Repository,
	storage ObjectStorage,
	authorizer PortalAttachmentAuthorizer,
	now time.Time,
) *Service {
	t.Helper()
	service, err := NewService(repository, storage, &fakeScanner{}, ServiceConfig{
		Bucket: "periapsis-evidence", MaximumSize: 1_024, Clock: func() time.Time { return now },
		PortalAuthorizer: authorizer,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func portalAttachmentFixture(
	t *testing.T,
	tenantID uuid.UUID,
	rootID kernel.EntityID,
	attachmentSeed byte,
	storageSeed byte,
	uploadedAt time.Time,
) kernel.Attachment {
	t.Helper()
	tenant := testEntityIDFromUUID(t, tenantID)
	subject, err := kernel.NewEntityReference(tenant, kernel.EntityAlert, rootID)
	if err != nil {
		t.Fatal(err)
	}
	attachment, err := kernel.NewAttachment(kernel.AttachmentInput{
		ID: testEntityID(t, attachmentSeed), TenantID: tenant, Subject: subject,
		StorageObjectID: testEntityID(t, storageSeed), OriginalFilename: "capture.bin",
		RequestedVisibility: kernel.VisibilityPublic, SubjectVisibility: kernel.VisibilityPublic,
		UploadedBy: testEntityID(t, storageSeed+1), UploadedAt: uploadedAt, ScanState: kernel.ScanAvailable,
	})
	if err != nil {
		t.Fatal(err)
	}
	return attachment
}

func portalAttachmentForStorage(
	t *testing.T,
	tenantID uuid.UUID,
	rootID kernel.EntityID,
	attachmentSeed byte,
	storage kernel.StorageObject,
) kernel.Attachment {
	t.Helper()
	tenant := testEntityIDFromUUID(t, tenantID)
	subject, err := kernel.NewEntityReference(tenant, kernel.EntityCase, rootID)
	if err != nil {
		t.Fatal(err)
	}
	attachment, err := kernel.NewAttachment(kernel.AttachmentInput{
		ID: testEntityID(t, attachmentSeed), TenantID: tenant, Subject: subject,
		StorageObjectID: storage.ID(), OriginalFilename: storage.OriginalFilename(),
		RequestedVisibility: kernel.VisibilityPublic, SubjectVisibility: kernel.VisibilityPublic,
		UploadedBy: storage.CreatedBy(), UploadedAt: storage.CreatedAt(), ScanState: storage.State(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return attachment
}
