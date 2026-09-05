package postgres

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func TestSharedAttachmentRequiresAllRootAttachmentAuthorityBeforePrepareOrReplay(t *testing.T) {
	t.Parallel()
	actor, authority := sharedDFIRTestAuthority()
	caseID, alertID, resourceID := alertTestUUID(240), alertTestUUID(241), alertTestUUID(242)
	for _, kind := range []kernel.EntityKind{kernel.EntityIOC, kernel.EntityAsset} {
		t.Run(string(kind), func(t *testing.T) {
			subject, err := kernel.NewEntityReference(entityID(actor.TenantID), kind, entityID(resourceID))
			if err != nil {
				t.Fatal(err)
			}
			attachment, err := kernel.NewAttachment(kernel.AttachmentInput{
				ID: alertTestEntityID(243), TenantID: entityID(actor.TenantID), Subject: subject,
				StorageObjectID: alertTestEntityID(244), OriginalFilename: "shared.txt",
				RequestedVisibility: kernel.VisibilityPrivate, SubjectVisibility: kernel.VisibilityPrivate,
				UploadedBy: entityID(actor.MembershipID), UploadedAt: alertTestTime(0), ScanState: kernel.ScanPendingUpload,
			})
			if err != nil {
				t.Fatal(err)
			}
			write := application.StorageWrite{
				BaseWrite: application.BaseWrite{Actor: actor, CaseID: entityID(caseID)}, Attachment: attachment,
			}
			allowed := map[uuid.UUID]bool{caseID: true, alertID: true}
			visited := make([]uuid.UUID, 0)
			accessTx := sharedDFIRAccessTransaction(actor, allowed, &visited)
			locks := make([]uuid.UUID, 0)
			tx := &dfirTransactionStub{
				row: func(query string, args []any, destinations []any) error {
					if strings.Contains(query, "FOR UPDATE") {
						if len(args) != 2 || args[0] != actor.TenantID {
							return errors.New("unscoped shared attachment lock")
						}
						id := args[1].(uuid.UUID)
						locks = append(locks, id)
						*(destinations[0].(*uuid.UUID)) = id
						return nil
					}
					if !slices.Equal(locks, []uuid.UUID{resourceID, alertID, caseID}) {
						return errors.New("attachment authority was checked before deterministic resource/root locks")
					}
					return accessTx.row(query, args, destinations)
				},
				query: func(query string, args []any) (pgx.Rows, error) {
					if !slices.Equal(locks, []uuid.UUID{resourceID}) || len(args) != 2 || args[1] != resourceID ||
						!strings.Contains(query, "ORDER BY root_kind, root_id LIMIT 65") {
						return nil, errors.New("shared attachment associations were not locked and bounded")
					}
					return &dfirRowsStub{rows: [][]any{{"case", caseID}, {"alert", alertID}}}, nil
				},
			}
			current := authority
			if _, err := authorizeDFIRSharedAttachment(context.Background(), tx, current, write); !errors.Is(err, authorization.ErrForbidden) {
				t.Fatalf("IOC/asset manage substituted for attachment manage: %v", err)
			}
			current.Permissions = append(slices.Clone(current.Permissions), authorization.ScopedPermission{
				Permission: authorization.TenantPermissionDFIRAttachmentManage, Scope: authorization.ScopeAssigned,
			})
			for _, path := range []kernel.EntityKind{kernel.EntityCase, kernel.EntityAlert} {
				write.CaseID, write.AlertID = entityID(caseID), kernel.EntityID{}
				if path == kernel.EntityAlert {
					write.CaseID, write.AlertID = kernel.EntityID{}, entityID(alertID)
				}
				locks, visited = nil, nil
				roots, err := authorizeDFIRSharedAttachment(context.Background(), tx, current, write)
				if err != nil || len(roots) != 2 || len(visited) != 2 {
					t.Fatalf("all-authorized %s prepare = roots %v, visited %v, %v", path, roots, visited, err)
				}
				allowed[caseID] = false
				locks, visited = nil, nil
				if _, err := authorizeDFIRSharedAttachment(context.Background(), tx, current, write); !errors.Is(err, authorization.ErrForbidden) {
					t.Fatalf("revocation on a linked Case did not reject %s retry: %v", path, err)
				}
				allowed[caseID] = true
			}
			write.CaseID, write.AlertID = alertTestEntityID(245), kernel.EntityID{}
			locks = nil
			if _, err := authorizeDFIRSharedAttachment(context.Background(), tx, current, write); !errors.Is(err, authorization.ErrForbidden) {
				t.Fatalf("unlinked prepare path accepted: %v", err)
			}
		})
	}
}

func TestSharedAttachmentActivityIsBoundedAndContainsOnlyPendingCommandAndEventIDs(t *testing.T) {
	t.Parallel()
	commandID, eventID := alertTestUUID(250), alertTestUUID(251)
	calls := 0
	tx := &dfirTransactionStub{exec: func(query string, args []any) (pgconn.CommandTag, error) {
		calls++
		if !strings.Contains(query, "app.append_shared_dfir_activities_v1($1, $2::uuid[])") ||
			len(args) != 2 || args[0] != commandID || !slices.Equal(args[1].([]uuid.UUID), []uuid.UUID{eventID}) {
			return pgconn.CommandTag{}, errors.New("shared attachment fanout lost its exact redacted command ABI")
		}
		return pgconn.NewCommandTag("SELECT 1"), nil
	}}
	repository := &DFIRRepository{newID: func() (uuid.UUID, error) { return eventID, nil }}
	roots := []dfirSharedRoot{{kind: kernel.EntityCase, id: alertTestUUID(252)}, {kind: kernel.EntityAlert, id: alertTestUUID(253)}}
	for _, count := range []int{0, 1, 2} {
		if err := repository.appendSharedAttachmentActivities(context.Background(), tx, commandID, roots[:count]); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("fanout calls = %d, expected exactly the additional root", calls)
	}
}
