package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

func TestDFIRCaseSharedSubjectUsesRequestedDirectLiveAssociation(t *testing.T) {
	t.Parallel()
	tenantID, firstCase, secondCase, resourceID := alertTestUUID(220), alertTestUUID(221), alertTestUUID(222), alertTestUUID(223)
	for _, kind := range []kernel.EntityKind{kernel.EntityIOC, kernel.EntityAsset} {
		t.Run(string(kind), func(t *testing.T) {
			subject, err := kernel.NewEntityReference(entityID(tenantID), kind, entityID(resourceID))
			if err != nil {
				t.Fatal(err)
			}
			live := true
			calls := 0
			tx := &dfirTransactionStub{row: func(query string, args []any, destinations []any) error {
				calls++
				if len(args) != 3 || args[0] != tenantID || args[2] != resourceID ||
					!strings.Contains(query, "link.case_id = $2") || !strings.Contains(query, "resource.archived_at IS NULL") ||
					strings.Contains(query, "alert_case_links") || strings.Contains(query, "coalesce") {
					return errors.New("Case resource lookup inferred ownership or ignored the live exact link")
				}
				*(destinations[0].(*bool)) = live && (args[1] == firstCase || args[1] == secondCase)
				return nil
			}}
			for _, caseID := range []uuid.UUID{firstCase, secondCase} {
				visibility, err := resolveDFIRCaseSubject(context.Background(), tx, tenantID, caseID, subject)
				if err != nil || visibility != kernel.VisibilityPrivate {
					t.Fatalf("shared subject on Case %s = %q, %v", caseID, visibility, err)
				}
			}
			if _, err := resolveDFIRCaseSubject(context.Background(), tx, tenantID, alertTestUUID(224), subject); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("unlinked Case subject = %v", err)
			}
			live = false
			if _, err := resolveDFIRCaseSubject(context.Background(), tx, tenantID, firstCase, subject); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("archived subject = %v", err)
			}
			priorCalls := calls
			for _, invalid := range []struct{ tenant, root uuid.UUID }{
				{alertTestUUID(225), firstCase}, {tenantID, uuid.Nil}, {uuid.Nil, firstCase},
			} {
				if _, err := resolveDFIRCaseSubject(context.Background(), tx, invalid.tenant, invalid.root, subject); !errors.Is(err, authorization.ErrForbidden) {
					t.Fatalf("invalid request = %v", err)
				}
			}
			if calls != priorCalls {
				t.Fatal("invalid tenant/root reached the database")
			}
		})
	}
}

func TestDFIRCaseAttachmentLoadAndStoragePurposeRemainPathBound(t *testing.T) {
	t.Parallel()
	tenantID, firstCase, secondCase := alertTestUUID(230), alertTestUUID(231), alertTestUUID(232)
	attachmentID, resourceID, storageID := alertTestUUID(233), alertTestUUID(234), alertTestUUID(235)
	sourceTenant := tenantID
	version := int64(1)
	rootLinked, copied, customerVisible := true, false, true
	visibility := string(kernel.VisibilityPrivate)
	storageRead := errors.New("verified exact storage read reached")
	for _, kind := range []kernel.EntityKind{kernel.EntityIOC, kernel.EntityAsset} {
		t.Run(string(kind), func(t *testing.T) {
			for _, caseID := range []uuid.UUID{firstCase, secondCase} {
				tx := &dfirTransactionStub{row: func(query string, args []any, destinations []any) error {
					if len(args) == 0 || args[0] != tenantID {
						return errors.New("attachment lookup lost its tenant")
					}
					switch {
					case strings.Contains(query, "id = $2 AND storage_object_id = $3"):
						if len(args) != 3 || args[1] != attachmentID || args[2] != storageID {
							return errors.New("storage lookup lost its exact attachment purpose")
						}
						*(destinations[0].(*uuid.UUID)) = attachmentID
					case strings.Contains(query, "FROM public.dfir_attachments"):
						if args[1] != attachmentID {
							return errors.New("wrong attachment was loaded")
						}
						*(destinations[0].(*uuid.UUID)) = attachmentID
						*(destinations[1].(*uuid.UUID)) = sourceTenant
						*(destinations[2].(*string)) = string(kind)
						for _, index := range []int{3, 4, 5, 6, 7, 8} {
							*(destinations[index].(**uuid.UUID)) = nil
						}
						index := 5
						if kind == kernel.EntityAsset {
							index = 6
						}
						*(destinations[index].(**uuid.UUID)) = &resourceID
						*(destinations[9].(*uuid.UUID)) = storageID
						*(destinations[10].(*string)) = "sample.txt"
						*(destinations[11].(*string)) = visibility
						*(destinations[12].(*string)) = string(kernel.ScanAvailable)
						*(destinations[13].(*uuid.UUID)) = alertTestUUID(236)
						*(destinations[14].(*time.Time)) = alertTestTime(0)
						*(destinations[15].(*int64)) = version
					case strings.Contains(query, "FROM public.dfir_attachment_case_links"):
						if len(args) != 3 || args[1] != attachmentID || args[2] != caseID {
							return errors.New("copy lookup lost the requested Case")
						}
						*(destinations[0].(*bool)) = copied
					case strings.Contains(query, "resource.archived_at IS NULL"):
						if args[1] != caseID || args[2] != resourceID {
							return errors.New("shared attachment lost the requested Case")
						}
						*(destinations[0].(*bool)) = rootLinked
					case strings.Contains(query, "FROM public.cases AS ticket"):
						return dfirCaseAccessRow(&customerVisible, nil, nil, nil, nil, customerVisible)(query, args, destinations)
					case strings.Contains(query, "FROM public.dfir_storage_objects"):
						if len(args) != 2 || args[1] != storageID {
							return errors.New("storage identity changed")
						}
						return storageRead
					default:
						return errors.New("unexpected or unscoped attachment query")
					}
					return nil
				}}
				rootLinked, copied, customerVisible = true, false, true
				visibility, sourceTenant, version = string(kernel.VisibilityPrivate), tenantID, 1
				attachment, err := loadDFIRAttachment(context.Background(), tx, tenantID, caseID, attachmentID)
				if err != nil || attachment.Subject().Kind() != kind || attachment.Subject().ID() != entityID(resourceID) {
					t.Fatalf("shared Case attachment = %v", err)
				}
				if _, err := loadExactDFIRStorageObjectForRoot(context.Background(), tx, tenantID, kernel.EntityCase, caseID, attachmentID, storageID); !errors.Is(err, storageRead) {
					t.Fatalf("exact Case storage read = %v", err)
				}
				rootLinked = false
				if _, err := loadExactDFIRStorageObjectForRoot(context.Background(), tx, tenantID, kernel.EntityCase, caseID, attachmentID, storageID); !errors.Is(err, pgx.ErrNoRows) {
					t.Fatalf("revoked subject still reached storage: %v", err)
				}
				copied, visibility = true, string(kernel.VisibilityPublic)
				if _, err := loadDFIRAttachment(context.Background(), tx, tenantID, caseID, attachmentID); err != nil {
					t.Fatalf("explicitly copied attachment required copying its whole IOC/asset: %v", err)
				}
				customerVisible = false
				if _, err := loadDFIRAttachment(context.Background(), tx, tenantID, caseID, attachmentID); err == nil {
					t.Fatal("public copy exceeded Case visibility")
				}
				visibility = string(kernel.VisibilityPrivate)
				version = int64(kernel.MaximumResourceVersion) + 1
				if _, err := loadDFIRAttachment(context.Background(), tx, tenantID, caseID, attachmentID); err == nil {
					t.Fatal("unsafe attachment revision accepted")
				}
				version, sourceTenant = 1, alertTestUUID(237)
				if _, err := loadDFIRAttachment(context.Background(), tx, tenantID, caseID, attachmentID); err == nil {
					t.Fatal("cross-tenant attachment projection accepted")
				}
			}
		})
	}
}

func TestCaseWorkspaceFiltersArchivedSharedAttachmentSubjectsBeforeLoading(t *testing.T) {
	t.Parallel()
	tenantID, caseID := alertTestUUID(210), alertTestUUID(211)
	for _, customer := range []bool{false, true} {
		found := false
		tx := &dfirTransactionStub{query: func(query string, args []any) (pgx.Rows, error) {
			if len(args) != 3 || args[0] != tenantID || args[1] != caseID {
				return nil, errors.New("workspace query lost its path")
			}
			if strings.Contains(query, "FROM public.dfir_attachments AS attachment") {
				found = true
				for _, required := range []string{
					"ioc.archived_at IS NULL", "asset.archived_at IS NULL",
					"source_alert.deleted_at IS NULL", "source_alert.id IS NOT NULL",
					"ioc.id IS NOT NULL OR asset.id IS NOT NULL", "copied.attachment_id = attachment.id",
					"copied.case_id = $2", "ORDER BY attachment.id LIMIT $3",
				} {
					if !strings.Contains(query, required) {
						return nil, errors.New("attachment inventory omitted live-resource filtering or explicit copy: " + required)
					}
				}
				if customer != strings.Contains(query, "attachment.visibility = 'public'") {
					return nil, errors.New("attachment inventory lost customer visibility")
				}
			}
			return &dfirRowsStub{}, nil
		}}
		if _, err := loadDFIRWorkspace(context.Background(), tx, tenantID, caseID, customer); err != nil || !found {
			t.Fatalf("Case attachment inventory: checked=%t, %v", found, err)
		}
	}
}
