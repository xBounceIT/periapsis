package postgres

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func TestDFIRSharedAttachmentsStayPathBoundInPostgres(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("PERIAPSIS_DFIR_SHARED_ATTACHMENTS_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("PERIAPSIS_DFIR_SHARED_ATTACHMENTS_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse DFIR shared-attachment database URL: %v", err)
	}
	config.MaxConns = 1
	config.ConnConfig.RuntimeParams["timezone"] = "UTC"
	config.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
		connection.TypeMap().RegisterType(&pgtype.Type{
			Name: "timestamptz", OID: pgtype.TimestamptzOID,
			Codec: &pgtype.TimestamptzCodec{ScanLocation: time.UTC},
		})
		_, connectErr := connection.Exec(ctx, `SET ROLE "periapsis_api"`)
		return connectErr
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect DFIR shared-attachment database: %v", err)
	}
	defer pool.Close()

	connection, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire DFIR shared-attachment connection: %v", err)
	}
	defer connection.Release()
	assertDFIRSharedAttachmentRole(t, ctx, connection, "periapsis_api", false)

	tx, err := connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatalf("begin DFIR shared-attachment fixture: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatalf("reset runtime role before fixture setup: %v", err)
	}
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE "periapsis_migrator"`); err != nil {
		t.Fatalf("set DFIR shared-attachment fixture role: %v", err)
	}
	assertDFIRSharedAttachmentRole(t, ctx, tx, "periapsis_migrator", true)

	fixture := seedDFIRSharedAttachmentFixture(t, ctx, tx)
	setDFIRSharedAttachmentAPIRole(t, ctx, tx, fixture.tenantID, fixture.userID)

	t.Run("download audit uses the same exact path as the attachment read", func(t *testing.T) {
		for _, input := range []struct {
			name         string
			caseID       uuid.UUID
			kind         kernel.EntityKind
			resourceID   uuid.UUID
			attachmentID uuid.UUID
			storageID    uuid.UUID
			wantCode     string
			fixtureState string
		}{
			{"shared IOC first Case", fixture.firstCaseID, kernel.EntityIOC, fixture.iocID, fixture.iocAttachmentID, fixture.iocStorageID, "", ""},
			{"shared IOC second Case", fixture.secondCaseID, kernel.EntityIOC, fixture.iocID, fixture.iocAttachmentID, fixture.iocStorageID, "", ""},
			{"shared asset first Case", fixture.firstCaseID, kernel.EntityAsset, fixture.assetID, fixture.assetAttachmentID, fixture.assetStorageID, "", ""},
			{"shared asset second Case", fixture.secondCaseID, kernel.EntityAsset, fixture.assetID, fixture.assetAttachmentID, fixture.assetStorageID, "", ""},
			{"explicit attachment copy without IOC copy", fixture.firstCaseID, kernel.EntityIOC, fixture.copiedIOCID, fixture.copiedAttachmentID, fixture.copiedStorageID, "", ""},
			{"copy survives original IOC archival", fixture.firstCaseID, kernel.EntityIOC, fixture.copiedIOCID, fixture.copiedAttachmentID, fixture.copiedStorageID, "", "archive copied IOC"},
			{"Alert link does not implicitly copy an IOC attachment", fixture.firstCaseID, kernel.EntityIOC, fixture.copiedIOCID, fixture.uncopiedAttachmentID, fixture.uncopiedStorageID, "42501", ""},
			{"linked Alert first Case", fixture.firstCaseID, kernel.EntityAlert, fixture.alertID, fixture.alertAttachmentID, fixture.alertStorageID, "", ""},
			{"linked Alert second Case", fixture.secondCaseID, kernel.EntityAlert, fixture.alertID, fixture.alertAttachmentID, fixture.alertStorageID, "", ""},
			{"deleted source Alert", fixture.firstCaseID, kernel.EntityAlert, fixture.alertID, fixture.alertAttachmentID, fixture.alertStorageID, "42501", "delete source Alert"},
			{"unlinked IOC", fixture.unlinkedCaseID, kernel.EntityIOC, fixture.iocID, fixture.iocAttachmentID, fixture.iocStorageID, "42501", ""},
			{"unlinked asset", fixture.unlinkedCaseID, kernel.EntityAsset, fixture.assetID, fixture.assetAttachmentID, fixture.assetStorageID, "42501", ""},
			{"archived IOC", fixture.firstCaseID, kernel.EntityIOC, fixture.archivedIOCID, fixture.archivedIOCAttachmentID, fixture.archivedIOCStorageID, "42501", ""},
			{"archived asset", fixture.firstCaseID, kernel.EntityAsset, fixture.archivedAssetID, fixture.archivedAssetAttachmentID, fixture.archivedAssetStorageID, "42501", ""},
			{"copy is not in another Case", fixture.secondCaseID, kernel.EntityIOC, fixture.copiedIOCID, fixture.copiedAttachmentID, fixture.copiedStorageID, "42501", ""},
			{"foreign root", fixture.foreignCaseID, kernel.EntityIOC, fixture.iocID, fixture.iocAttachmentID, fixture.iocStorageID, "P0002", ""},
		} {
			t.Run(input.name, func(t *testing.T) {
				nested, beginErr := tx.Begin(ctx)
				if beginErr != nil {
					t.Fatal(beginErr)
				}
				defer func() { _ = nested.Rollback(ctx) }()
				if input.fixtureState == "delete source Alert" {
					var tombstoneVersion int64
					if deleteErr := nested.QueryRow(ctx, `SELECT tombstone_version FROM app.delete_tenant_alert_v1(
						$1,1,'Download audit deleted-source regression',$2,$3,$4,$5,'192.0.2.90',
						'dfir-shared-download-runtime','totp')`, fixture.alertID,
						bytes.Repeat([]byte{43}, 32), bytes.Repeat([]byte{44}, 32),
						mustDFIRSharedAttachmentUUID(t), mustDFIRSharedAttachmentUUID(t),
					).Scan(&tombstoneVersion); deleteErr != nil || tombstoneVersion != 2 {
						t.Fatalf("delete source Alert = version %d, %v", tombstoneVersion, deleteErr)
					}
				} else if input.fixtureState != "" {
					if input.fixtureState != "archive copied IOC" {
						t.Fatalf("unsupported fixture state %q", input.fixtureState)
					}
					if _, roleErr := nested.Exec(ctx, `RESET ROLE; SET LOCAL ROLE "periapsis_migrator"`); roleErr != nil {
						t.Fatal(roleErr)
					}
					changed, setupErr := nested.Exec(ctx, `UPDATE public.dfir_iocs SET archived_at=transaction_timestamp() WHERE tenant_id=$1 AND id=$2`, fixture.tenantID, fixture.copiedIOCID)
					if setupErr != nil || changed.RowsAffected() != 1 {
						t.Fatalf("fixture change = %v, %v", changed, setupErr)
					}
					setDFIRSharedAttachmentAPIRole(t, ctx, nested, fixture.tenantID, fixture.userID)
				}
				attachment, readErr := loadDFIRAttachment(ctx, nested, fixture.tenantID, input.caseID, input.attachmentID)
				if input.wantCode == "" {
					if readErr != nil || attachment.Subject().ID() != entityID(input.resourceID) {
						t.Fatalf("authorized attachment read = %+v, %v", attachment, readErr)
					}
					if _, storageErr := loadExactDFIRStorageObjectForRoot(ctx, nested, fixture.tenantID, kernel.EntityCase, input.caseID, input.attachmentID, input.storageID); storageErr != nil {
						t.Fatalf("authorized exact storage read: %v", storageErr)
					}
				} else if !errors.Is(readErr, pgx.ErrNoRows) {
					t.Fatalf("unavailable attachment read = %v, want no rows", readErr)
				}
				eventID := mustDFIRSharedAttachmentUUID(t)
				auditTx, beginErr := nested.Begin(ctx)
				if beginErr != nil {
					t.Fatal(beginErr)
				}
				auditErr := appendDFIRSharedAttachmentTestAudit(t, ctx, auditTx, fixture, eventID, input.caseID, input.kind, input.resourceID, input.attachmentID, input.storageID)
				if input.wantCode != "" {
					var databaseErr *pgconn.PgError
					if !errors.As(auditErr, &databaseErr) || databaseErr.Code != input.wantCode {
						t.Fatalf("download audit = %v, want SQLSTATE %s", auditErr, input.wantCode)
					}
					if rollbackErr := auditTx.Rollback(ctx); rollbackErr != nil {
						t.Fatal(rollbackErr)
					}
				} else {
					if auditErr != nil {
						t.Fatalf("download audit rejected an authorized path-bound read: %v", auditErr)
					}
					if commitErr := auditTx.Commit(ctx); commitErr != nil {
						t.Fatal(commitErr)
					}
				}
				if _, roleErr := nested.Exec(ctx, `RESET ROLE; SET LOCAL ROLE "periapsis_migrator"`); roleErr != nil {
					t.Fatal(roleErr)
				}
				var count int
				if queryErr := nested.QueryRow(ctx, `SELECT count(*) FROM public.audit_events WHERE tenant_id=$1 AND id=$2`, fixture.tenantID, eventID).Scan(&count); queryErr != nil {
					t.Fatal(queryErr)
				}
				wantCount := 0
				if input.wantCode == "" {
					wantCount = 1
				}
				if count != wantCount {
					t.Fatalf("download audit effects = %d, want %d", count, wantCount)
				}
				if wantCount == 1 {
					var rootID, attachmentID uuid.UUID
					var rootKind, action string
					if queryErr := nested.QueryRow(ctx, `
						SELECT (metadata->>'rootId')::uuid,metadata->>'rootKind',resource_id,action
						FROM public.audit_events WHERE tenant_id=$1 AND id=$2`, fixture.tenantID, eventID,
					).Scan(&rootID, &rootKind, &attachmentID, &action); queryErr != nil {
						t.Fatal(queryErr)
					}
					if rootID != input.caseID || rootKind != "case" || attachmentID != input.attachmentID || action != "dfir.case.attachment.download_grant_issued" {
						t.Fatalf("download audit lost its exact root and attachment: %s %s %s %s", rootKind, rootID, attachmentID, action)
					}
				}
			})
		}
	})

	t.Run("subjects resolve only through a live requested Case association", func(t *testing.T) {
		for _, resource := range []struct {
			kind kernel.EntityKind
			id   uuid.UUID
		}{
			{kind: kernel.EntityIOC, id: fixture.iocID},
			{kind: kernel.EntityAsset, id: fixture.assetID},
		} {
			subject := mustDFIRSharedAttachmentReference(t, fixture.tenantID, resource.kind, resource.id)
			for _, caseID := range []uuid.UUID{fixture.firstCaseID, fixture.secondCaseID} {
				visibility, resolveErr := resolveDFIRCaseSubject(ctx, tx, fixture.tenantID, caseID, subject)
				if resolveErr != nil || visibility != kernel.VisibilityPrivate {
					t.Fatalf("resolve %s through Case %s = %q, %v", resource.kind, caseID, visibility, resolveErr)
				}
			}
			if _, resolveErr := resolveDFIRCaseSubject(ctx, tx, fixture.tenantID, fixture.unlinkedCaseID, subject); !errors.Is(resolveErr, pgx.ErrNoRows) {
				t.Fatalf("resolve %s through unlinked Case = %v, want no rows", resource.kind, resolveErr)
			}
		}

		for _, archived := range []struct {
			kind kernel.EntityKind
			id   uuid.UUID
		}{
			{kind: kernel.EntityIOC, id: fixture.archivedIOCID},
			{kind: kernel.EntityAsset, id: fixture.archivedAssetID},
		} {
			subject := mustDFIRSharedAttachmentReference(t, fixture.tenantID, archived.kind, archived.id)
			if _, resolveErr := resolveDFIRCaseSubject(ctx, tx, fixture.tenantID, fixture.firstCaseID, subject); !errors.Is(resolveErr, pgx.ErrNoRows) {
				t.Fatalf("resolve archived %s = %v, want no rows", archived.kind, resolveErr)
			}
		}

		foreignSubject := mustDFIRSharedAttachmentReference(t, fixture.foreignTenantID, kernel.EntityIOC, fixture.foreignIOCID)
		if _, resolveErr := resolveDFIRCaseSubject(ctx, tx, fixture.tenantID, fixture.firstCaseID, foreignSubject); !errors.Is(resolveErr, authorization.ErrForbidden) {
			t.Fatalf("resolve cross-tenant subject = %v, want forbidden", resolveErr)
		}
	})

	t.Run("attachment loads and exact storage purpose stay on the path", func(t *testing.T) {
		for _, shared := range []struct {
			kind         kernel.EntityKind
			resourceID   uuid.UUID
			attachmentID uuid.UUID
			storageID    uuid.UUID
		}{
			{kind: kernel.EntityIOC, resourceID: fixture.iocID, attachmentID: fixture.iocAttachmentID, storageID: fixture.iocStorageID},
			{kind: kernel.EntityAsset, resourceID: fixture.assetID, attachmentID: fixture.assetAttachmentID, storageID: fixture.assetStorageID},
		} {
			for _, caseID := range []uuid.UUID{fixture.firstCaseID, fixture.secondCaseID} {
				attachment, loadErr := loadDFIRAttachment(ctx, tx, fixture.tenantID, caseID, shared.attachmentID)
				if loadErr != nil || attachment.Subject().Kind() != shared.kind || attachment.Subject().ID() != entityID(shared.resourceID) {
					t.Fatalf("load %s attachment through Case %s = %+v, %v", shared.kind, caseID, attachment, loadErr)
				}
				storage, storageErr := loadExactDFIRStorageObjectForRoot(
					ctx, tx, fixture.tenantID, kernel.EntityCase, caseID, shared.attachmentID, shared.storageID,
				)
				if storageErr != nil || storage.ID() != entityID(shared.storageID) {
					t.Fatalf("load exact %s storage through Case %s = %+v, %v", shared.kind, caseID, storage.Snapshot(), storageErr)
				}
			}
			if _, loadErr := loadDFIRAttachment(ctx, tx, fixture.tenantID, fixture.unlinkedCaseID, shared.attachmentID); !errors.Is(loadErr, pgx.ErrNoRows) {
				t.Fatalf("load %s attachment through unlinked Case = %v, want no rows", shared.kind, loadErr)
			}
			if _, storageErr := loadExactDFIRStorageObjectForRoot(
				ctx, tx, fixture.tenantID, kernel.EntityCase, fixture.unlinkedCaseID, shared.attachmentID, shared.storageID,
			); !errors.Is(storageErr, pgx.ErrNoRows) {
				t.Fatalf("load %s storage through unlinked Case = %v, want no rows", shared.kind, storageErr)
			}
		}

		if _, storageErr := loadExactDFIRStorageObjectForRoot(
			ctx, tx, fixture.tenantID, kernel.EntityCase, fixture.firstCaseID,
			fixture.iocAttachmentID, fixture.assetStorageID,
		); !errors.Is(storageErr, pgx.ErrNoRows) {
			t.Fatalf("load attachment with another attachment's storage = %v, want no rows", storageErr)
		}
		if _, loadErr := loadDFIRAttachment(
			ctx, tx, fixture.foreignTenantID, fixture.foreignCaseID, fixture.foreignAttachmentID,
		); !errors.Is(loadErr, pgx.ErrNoRows) {
			t.Fatalf("load foreign attachment under main-tenant RLS = %v, want no rows", loadErr)
		}
	})

	t.Run("workspace omits archived subjects and copies only the attachment", func(t *testing.T) {
		first, loadErr := loadDFIRWorkspace(ctx, tx, fixture.tenantID, fixture.firstCaseID, false)
		if loadErr != nil {
			t.Fatalf("load first Case workspace: %v", loadErr)
		}
		assertDFIRSharedAttachmentIDs(t, first.Attachments, []uuid.UUID{
			fixture.alertAttachmentID,
			fixture.iocAttachmentID,
			fixture.assetAttachmentID,
			fixture.copiedAttachmentID,
			fixture.ceilingAttachmentID,
		})
		assertDFIRSharedIndicatorIDs(t, first.Indicators, []uuid.UUID{fixture.iocID})
		assertDFIRSharedAssetIDs(t, first.Assets, []uuid.UUID{fixture.assetID})
		copied, loadErr := loadDFIRAttachment(ctx, tx, fixture.tenantID, fixture.firstCaseID, fixture.copiedAttachmentID)
		if loadErr != nil || copied.Subject().Kind() != kernel.EntityIOC || copied.Subject().ID() != entityID(fixture.copiedIOCID) {
			t.Fatalf("load explicitly copied attachment without Case IOC = %+v, %v", copied, loadErr)
		}

		second, loadErr := loadDFIRWorkspace(ctx, tx, fixture.tenantID, fixture.secondCaseID, false)
		if loadErr != nil {
			t.Fatalf("load second Case workspace: %v", loadErr)
		}
		assertDFIRSharedAttachmentIDs(t, second.Attachments, []uuid.UUID{
			fixture.alertAttachmentID,
			fixture.iocAttachmentID,
			fixture.assetAttachmentID,
		})
		if _, loadErr = loadDFIRAttachment(ctx, tx, fixture.tenantID, fixture.secondCaseID, fixture.copiedAttachmentID); !errors.Is(loadErr, pgx.ErrNoRows) {
			t.Fatalf("copied attachment leaked into another Case = %v, want no rows", loadErr)
		}

		for _, archivedID := range []uuid.UUID{fixture.archivedIOCAttachmentID, fixture.archivedAssetAttachmentID} {
			if _, loadErr = loadDFIRAttachment(ctx, tx, fixture.tenantID, fixture.firstCaseID, archivedID); !errors.Is(loadErr, pgx.ErrNoRows) {
				t.Fatalf("archived-subject attachment %s loaded directly: %v", archivedID, loadErr)
			}
		}
	})

	t.Run("JSON-safe ceiling is accepted and unsafe projections fail closed", func(t *testing.T) {
		attachment, loadErr := loadDFIRAttachment(
			ctx, tx, fixture.tenantID, fixture.firstCaseID, fixture.ceilingAttachmentID,
		)
		if loadErr != nil || attachment.ID() != entityID(fixture.ceilingAttachmentID) {
			t.Fatalf("load maximum-safe attachment = %+v, %v", attachment, loadErr)
		}
		storage, loadErr := loadExactDFIRStorageObjectForRoot(
			ctx, tx, fixture.tenantID, kernel.EntityCase, fixture.firstCaseID,
			fixture.ceilingAttachmentID, fixture.ceilingStorageID,
		)
		if loadErr != nil || storage.Version() != kernel.MaximumResourceVersion {
			t.Fatalf("load maximum-safe storage version = %d, %v", storage.Version(), loadErr)
		}

		if _, err = tx.Exec(ctx, `SAVEPOINT unsafe_attachment_projection`); err != nil {
			t.Fatalf("save unsafe attachment projection: %v", err)
		}
		if _, err = tx.Exec(ctx, `RESET ROLE`); err != nil {
			t.Fatalf("reset API role for unsafe attachment projection: %v", err)
		}
		if _, err = tx.Exec(ctx, `SET LOCAL ROLE "periapsis_migrator"`); err != nil {
			t.Fatalf("set migrator role for unsafe attachment projection: %v", err)
		}
		if _, err = tx.Exec(ctx, `UPDATE public.dfir_attachments SET version = $1 WHERE tenant_id = $2 AND id = $3`,
			int64(kernel.MaximumResourceVersion)+1, fixture.tenantID, fixture.ceilingAttachmentID); err != nil {
			t.Fatalf("install unsafe attachment projection as migrator: %v", err)
		}
		setDFIRSharedAttachmentAPIRole(t, ctx, tx, fixture.tenantID, fixture.userID)
		if _, loadErr = loadDFIRAttachment(ctx, tx, fixture.tenantID, fixture.firstCaseID, fixture.ceilingAttachmentID); loadErr == nil || !strings.Contains(loadErr.Error(), "attachment version is invalid") {
			t.Fatalf("unsafe attachment projection error = %v", loadErr)
		}
		if _, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT unsafe_attachment_projection`); err != nil {
			t.Fatalf("rollback unsafe attachment projection: %v", err)
		}
		if _, err = tx.Exec(ctx, `RELEASE SAVEPOINT unsafe_attachment_projection`); err != nil {
			t.Fatalf("release unsafe attachment projection: %v", err)
		}
		assertDFIRSharedAttachmentRole(t, ctx, tx, "periapsis_api", false)

		if _, err = tx.Exec(ctx, `SAVEPOINT unsafe_storage_version`); err != nil {
			t.Fatalf("save unsafe storage version: %v", err)
		}
		if _, err = tx.Exec(ctx, `RESET ROLE`); err != nil {
			t.Fatalf("reset API role for unsafe storage version: %v", err)
		}
		if _, err = tx.Exec(ctx, `SET LOCAL ROLE "periapsis_migrator"`); err != nil {
			t.Fatalf("set migrator role for unsafe storage version: %v", err)
		}
		unsafeStorageID := mustDFIRSharedAttachmentUUID(t)
		_, insertErr := tx.Exec(ctx, `
			INSERT INTO public.dfir_storage_objects (
				id, tenant_id, bucket, object_key, original_filename, classification, state,
				expected_size_bytes, upload_expires_at, created_by_membership_id, version,
				created_at, updated_at
			) VALUES ($1, $2, 'dfir-runtime', $3, 'unsafe.bin', 'internal', 'pending_upload',
				1, $4, $5, $6, $7, $7)`,
			unsafeStorageID, fixture.tenantID, fixture.tenantID.String()+"/"+unsafeStorageID.String(),
			fixture.observedAt.Add(30*time.Minute), fixture.membershipID,
			int64(kernel.MaximumResourceVersion)+1, fixture.observedAt,
		)
		var postgresError *pgconn.PgError
		if !errors.As(insertErr, &postgresError) || postgresError.Code != "23514" {
			t.Fatalf("unsafe storage version error = %v, want check violation", insertErr)
		}
		if _, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT unsafe_storage_version`); err != nil {
			t.Fatalf("rollback unsafe storage version: %v", err)
		}
		if _, err = tx.Exec(ctx, `RELEASE SAVEPOINT unsafe_storage_version`); err != nil {
			t.Fatalf("release unsafe storage version: %v", err)
		}
		assertDFIRSharedAttachmentRole(t, ctx, tx, "periapsis_api", false)
	})
}

type dfirSharedAttachmentFixture struct {
	tenantID                  uuid.UUID
	foreignTenantID           uuid.UUID
	userID                    uuid.UUID
	membershipID              uuid.UUID
	sessionID                 uuid.UUID
	firstCaseID               uuid.UUID
	secondCaseID              uuid.UUID
	unlinkedCaseID            uuid.UUID
	foreignCaseID             uuid.UUID
	alertID                   uuid.UUID
	iocID                     uuid.UUID
	assetID                   uuid.UUID
	archivedIOCID             uuid.UUID
	archivedAssetID           uuid.UUID
	copiedIOCID               uuid.UUID
	foreignIOCID              uuid.UUID
	iocStorageID              uuid.UUID
	alertStorageID            uuid.UUID
	assetStorageID            uuid.UUID
	archivedIOCStorageID      uuid.UUID
	archivedAssetStorageID    uuid.UUID
	copiedStorageID           uuid.UUID
	uncopiedStorageID         uuid.UUID
	ceilingStorageID          uuid.UUID
	foreignStorageID          uuid.UUID
	iocAttachmentID           uuid.UUID
	alertAttachmentID         uuid.UUID
	assetAttachmentID         uuid.UUID
	archivedIOCAttachmentID   uuid.UUID
	archivedAssetAttachmentID uuid.UUID
	copiedAttachmentID        uuid.UUID
	uncopiedAttachmentID      uuid.UUID
	ceilingAttachmentID       uuid.UUID
	foreignAttachmentID       uuid.UUID
	observedAt                time.Time
}

func seedDFIRSharedAttachmentFixture(t testing.TB, ctx context.Context, tx pgx.Tx) dfirSharedAttachmentFixture {
	t.Helper()
	ids := make([]uuid.UUID, 29)
	for index := range ids {
		ids[index] = mustDFIRSharedAttachmentUUID(t)
	}
	fixture := dfirSharedAttachmentFixture{
		tenantID: ids[0], foreignTenantID: ids[1], userID: ids[2], membershipID: ids[3],
		firstCaseID: ids[8], secondCaseID: ids[9], unlinkedCaseID: ids[10], foreignCaseID: ids[11], alertID: ids[12],
		iocID: ids[13], assetID: ids[14], archivedIOCID: ids[15], archivedAssetID: ids[16], copiedIOCID: ids[17], foreignIOCID: ids[18],
		iocStorageID: ids[19], assetStorageID: ids[20], archivedIOCStorageID: ids[21], archivedAssetStorageID: ids[22],
		copiedStorageID: ids[23], ceilingStorageID: ids[24], foreignStorageID: ids[25],
		iocAttachmentID: ids[26], assetAttachmentID: ids[27], archivedIOCAttachmentID: ids[28],
		observedAt: time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC),
	}
	fixture.archivedAssetAttachmentID = mustDFIRSharedAttachmentUUID(t)
	fixture.copiedAttachmentID = mustDFIRSharedAttachmentUUID(t)
	fixture.ceilingAttachmentID = mustDFIRSharedAttachmentUUID(t)
	fixture.foreignAttachmentID = mustDFIRSharedAttachmentUUID(t)
	fixture.sessionID = mustDFIRSharedAttachmentUUID(t)
	fixture.alertStorageID = mustDFIRSharedAttachmentUUID(t)
	fixture.alertAttachmentID = mustDFIRSharedAttachmentUUID(t)
	fixture.uncopiedStorageID = mustDFIRSharedAttachmentUUID(t)
	fixture.uncopiedAttachmentID = mustDFIRSharedAttachmentUUID(t)
	foreignUserID, foreignMembershipID := ids[4], ids[5]
	alertCaseLinkID, attachmentCaseLinkID := ids[6], ids[7]
	suffix := strings.ReplaceAll(fixture.tenantID.String(), "-", "")

	if _, err := tx.Exec(ctx, `
		INSERT INTO public.tenants (id, slug, name) VALUES
		  ($1, $2, 'DFIR shared attachments integration'),
		  ($3, $4, 'Foreign DFIR shared attachments integration')`,
		fixture.tenantID, "dfir-shared-go-"+suffix[len(suffix)-12:],
		fixture.foreignTenantID, "dfir-shared-foreign-go-"+suffix[len(suffix)-12:],
	); err != nil {
		t.Fatalf("insert DFIR shared-attachment tenants: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.audit_chain_heads (tenant_id) VALUES ($1), ($2)`,
		fixture.tenantID, fixture.foreignTenantID); err != nil {
		t.Fatalf("insert DFIR shared-attachment audit heads: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.users (id, email, display_name) VALUES
		  ($1, $2, 'DFIR attachment operator'),
		  ($3, $4, 'Foreign DFIR attachment operator')`,
		fixture.userID, "dfir-shared-operator-"+suffix[len(suffix)-12:]+"@example.invalid",
		foreignUserID, "dfir-shared-foreign-"+suffix[len(suffix)-12:]+"@example.invalid",
	); err != nil {
		t.Fatalf("insert DFIR shared-attachment users: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.tenant_memberships (id, tenant_id, user_id, role, status) VALUES
		  ($1, $2, $3, 'tenant_admin', 'active'),
		  ($4, $5, $6, 'tenant_admin', 'active')`,
		fixture.membershipID, fixture.tenantID, fixture.userID,
		foreignMembershipID, fixture.foreignTenantID, foreignUserID,
	); err != nil {
		t.Fatalf("insert DFIR shared-attachment memberships: %v", err)
	}
	if _, err := tx.Exec(ctx, `SELECT app.seed_tenant_authorization($1, $2), app.seed_tenant_authorization($3, $4)`,
		fixture.tenantID, fixture.membershipID, fixture.foreignTenantID, foreignMembershipID); err != nil {
		t.Fatalf("seed DFIR shared-attachment authorization: %v", err)
	}

	setDFIRSharedAttachmentFixtureContext(t, ctx, tx, fixture.tenantID, fixture.userID)
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.auth_sessions (
			id, user_id, rotation_family_id, active_tenant_id, token_digest,
			csrf_secret_digest, authentication_method, mfa_satisfied_at, last_seen_at,
			idle_expires_at, absolute_expires_at, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,'totp',date_trunc('milliseconds',transaction_timestamp())-interval '2 minutes',
			date_trunc('milliseconds',transaction_timestamp())-interval '1 minute',date_trunc('milliseconds',transaction_timestamp())+interval '1 hour',
			date_trunc('milliseconds',transaction_timestamp())+interval '8 hours',date_trunc('milliseconds',transaction_timestamp())-interval '10 minutes')`,
		fixture.sessionID, fixture.userID, mustDFIRSharedAttachmentUUID(t), fixture.tenantID,
		bytes.Repeat([]byte{41}, 32), bytes.Repeat([]byte{42}, 32),
	); err != nil {
		t.Fatalf("insert live DFIR download audit session: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.cases (
			id, tenant_id, number, workflow_id, workflow_version, state_key,
			title, created_by_membership_id, created_by_user_id
		)
		SELECT input.id, input.tenant_id, input.number, workflow.id,
		       workflow.current_version, state.value->>'key', input.title,
		       input.membership_id, input.user_id
		FROM (VALUES
		  ($1::uuid, $2::uuid, 'CAS-2099-920001', 'Shared attachments Case one', $3::uuid, $4::uuid),
		  ($5::uuid, $2::uuid, 'CAS-2099-920002', 'Shared attachments Case two', $3::uuid, $4::uuid),
		  ($6::uuid, $2::uuid, 'CAS-2099-920003', 'Unlinked shared attachments Case', $3::uuid, $4::uuid)
		) AS input(id, tenant_id, number, title, membership_id, user_id)
		JOIN public.ticket_workflows AS workflow
		  ON workflow.tenant_id = input.tenant_id
		 AND workflow.aggregate_kind = 'case' AND workflow.is_default AND workflow.archived_at IS NULL
		JOIN public.ticket_workflow_versions AS workflow_version
		  ON workflow_version.tenant_id = workflow.tenant_id
		 AND workflow_version.workflow_id = workflow.id
		 AND workflow_version.aggregate_kind = workflow.aggregate_kind
		 AND workflow_version.version = workflow.current_version
		CROSS JOIN LATERAL jsonb_array_elements(workflow_version.states) AS state(value)
		WHERE (state.value->>'initial')::boolean`,
		fixture.firstCaseID, fixture.tenantID, fixture.membershipID, fixture.userID,
		fixture.secondCaseID, fixture.unlinkedCaseID,
	); err != nil {
		t.Fatalf("insert main-tenant DFIR shared-attachment Cases: %v", err)
	}
	setDFIRSharedAttachmentFixtureContext(t, ctx, tx, fixture.foreignTenantID, foreignUserID)
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.cases (
			id, tenant_id, number, workflow_id, workflow_version, state_key,
			title, created_by_membership_id, created_by_user_id
		)
		SELECT $1, $2, 'CAS-2099-920004', workflow.id, workflow.current_version,
		       state.value->>'key', 'Foreign shared attachments Case', $3, $4
		FROM public.ticket_workflows AS workflow
		JOIN public.ticket_workflow_versions AS workflow_version
		  ON workflow_version.tenant_id = workflow.tenant_id
		 AND workflow_version.workflow_id = workflow.id
		 AND workflow_version.aggregate_kind = workflow.aggregate_kind
		 AND workflow_version.version = workflow.current_version
		CROSS JOIN LATERAL jsonb_array_elements(workflow_version.states) AS state(value)
		WHERE workflow.tenant_id = $2 AND workflow.aggregate_kind = 'case'
		  AND workflow.is_default AND workflow.archived_at IS NULL
		  AND (state.value->>'initial')::boolean`,
		fixture.foreignCaseID, fixture.foreignTenantID, foreignMembershipID, foreignUserID,
	); err != nil {
		t.Fatalf("insert foreign DFIR shared-attachment Case: %v", err)
	}
	setDFIRSharedAttachmentFixtureContext(t, ctx, tx, fixture.tenantID, fixture.userID)
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.alerts (
			id, tenant_id, number, workflow_id, workflow_version, state_key,
			title, created_by, created_by_membership_id
		)
		SELECT $1, $2, 'ALT-2099-920001', workflow.id, workflow.current_version,
		       state.value->>'key', 'Copied attachment source Alert', $3, $4
		FROM public.ticket_workflows AS workflow
		JOIN public.ticket_workflow_versions AS workflow_version
		  ON workflow_version.tenant_id = workflow.tenant_id
		 AND workflow_version.workflow_id = workflow.id
		 AND workflow_version.aggregate_kind = workflow.aggregate_kind
		 AND workflow_version.version = workflow.current_version
		CROSS JOIN LATERAL jsonb_array_elements(workflow_version.states) AS state(value)
		WHERE workflow.tenant_id = $2 AND workflow.aggregate_kind = 'alert'
		  AND workflow.is_default AND workflow.archived_at IS NULL
		  AND (state.value->>'initial')::boolean`,
		fixture.alertID, fixture.tenantID, fixture.userID, fixture.membershipID,
	); err != nil {
		t.Fatalf("insert copied-attachment source Alert: %v", err)
	}

	type iocFixture struct {
		id       uuid.UUID
		tenantID uuid.UUID
		memberID uuid.UUID
		value    string
	}
	for _, value := range []iocFixture{
		{id: fixture.iocID, tenantID: fixture.tenantID, memberID: fixture.membershipID, value: "shared-ioc.example"},
		{id: fixture.archivedIOCID, tenantID: fixture.tenantID, memberID: fixture.membershipID, value: "archived-shared-ioc.example"},
		{id: fixture.copiedIOCID, tenantID: fixture.tenantID, memberID: fixture.membershipID, value: "copied-alert-ioc.example"},
		{id: fixture.foreignIOCID, tenantID: fixture.foreignTenantID, memberID: foreignMembershipID, value: "foreign-shared-ioc.example"},
	} {
		actorUserID := fixture.userID
		if value.tenantID == fixture.foreignTenantID {
			actorUserID = foreignUserID
		}
		setDFIRSharedAttachmentFixtureContext(t, ctx, tx, value.tenantID, actorUserID)
		if _, err := tx.Exec(ctx, `
			INSERT INTO public.dfir_iocs (
				id, tenant_id, type, value, normalized_value, description, source,
				confidence, tlp, first_seen, last_seen, malicious_state, tags, enrichment,
				created_by_membership_id, updated_by_membership_id, version, created_at, updated_at
			) VALUES ($1, $2, 'domain', $3, $3, '', 'integration', 80, 'amber',
				$4, $4, 'suspicious', ARRAY[]::text[], '{}'::jsonb, $5, $5, 1, $4, $4)`,
			value.id, value.tenantID, value.value, fixture.observedAt, value.memberID,
		); err != nil {
			t.Fatalf("insert DFIR shared-attachment IOC %s: %v", value.id, err)
		}
	}
	for _, value := range []struct {
		id         uuid.UUID
		externalID string
	}{
		{id: fixture.assetID, externalID: "shared-asset"},
		{id: fixture.archivedAssetID, externalID: "archived-shared-asset"},
	} {
		setDFIRSharedAttachmentFixtureContext(t, ctx, tx, fixture.tenantID, fixture.userID)
		if _, err := tx.Exec(ctx, `
			INSERT INTO public.dfir_assets (
				id, tenant_id, original_identifiers, asset_type, criticality, environment,
				external_id, tags, first_seen, last_seen, created_by_membership_id,
				updated_by_membership_id, version, created_at, updated_at
			) VALUES ($1, $2, '{"ipAddresses":[],"macAddresses":[]}'::jsonb,
				'endpoint', 'high', 'test', $3, ARRAY[]::text[], $4, $4, $5, $5, 1, $4, $4)`,
			value.id, fixture.tenantID, value.externalID, fixture.observedAt, fixture.membershipID,
		); err != nil {
			t.Fatalf("insert DFIR shared-attachment asset %s: %v", value.id, err)
		}
	}

	for _, link := range []struct {
		id         uuid.UUID
		tenantID   uuid.UUID
		resourceID uuid.UUID
		caseID     *uuid.UUID
		alertID    *uuid.UUID
		memberID   uuid.UUID
		asset      bool
	}{
		{id: mustDFIRSharedAttachmentUUID(t), tenantID: fixture.tenantID, resourceID: fixture.iocID, caseID: &fixture.firstCaseID, memberID: fixture.membershipID},
		{id: mustDFIRSharedAttachmentUUID(t), tenantID: fixture.tenantID, resourceID: fixture.iocID, caseID: &fixture.secondCaseID, memberID: fixture.membershipID},
		{id: mustDFIRSharedAttachmentUUID(t), tenantID: fixture.tenantID, resourceID: fixture.assetID, caseID: &fixture.firstCaseID, memberID: fixture.membershipID, asset: true},
		{id: mustDFIRSharedAttachmentUUID(t), tenantID: fixture.tenantID, resourceID: fixture.assetID, caseID: &fixture.secondCaseID, memberID: fixture.membershipID, asset: true},
		{id: mustDFIRSharedAttachmentUUID(t), tenantID: fixture.tenantID, resourceID: fixture.archivedIOCID, caseID: &fixture.firstCaseID, memberID: fixture.membershipID},
		{id: mustDFIRSharedAttachmentUUID(t), tenantID: fixture.tenantID, resourceID: fixture.archivedAssetID, caseID: &fixture.firstCaseID, memberID: fixture.membershipID, asset: true},
		{id: mustDFIRSharedAttachmentUUID(t), tenantID: fixture.tenantID, resourceID: fixture.copiedIOCID, alertID: &fixture.alertID, memberID: fixture.membershipID},
		{id: mustDFIRSharedAttachmentUUID(t), tenantID: fixture.foreignTenantID, resourceID: fixture.foreignIOCID, caseID: &fixture.foreignCaseID, memberID: foreignMembershipID},
	} {
		actorUserID := fixture.userID
		if link.tenantID == fixture.foreignTenantID {
			actorUserID = foreignUserID
		}
		setDFIRSharedAttachmentFixtureContext(t, ctx, tx, link.tenantID, actorUserID)
		statement := `INSERT INTO public.dfir_ioc_links
			(id, tenant_id, ioc_id, alert_id, case_id, created_by_membership_id, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`
		if link.asset {
			statement = `INSERT INTO public.dfir_asset_links
				(id, tenant_id, asset_id, alert_id, case_id, created_by_membership_id, created_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7)`
		}
		if _, err := tx.Exec(ctx, statement, link.id, link.tenantID, link.resourceID,
			link.alertID, link.caseID, link.memberID, fixture.observedAt); err != nil {
			t.Fatalf("insert DFIR shared-attachment link %s: %v", link.id, err)
		}
	}
	setDFIRSharedAttachmentFixtureContext(t, ctx, tx, fixture.tenantID, fixture.userID)
	if _, err := tx.Exec(ctx, `UPDATE public.dfir_iocs SET archived_at = $1 WHERE tenant_id = $2 AND id = $3`,
		fixture.observedAt.Add(time.Minute), fixture.tenantID, fixture.archivedIOCID); err != nil {
		t.Fatalf("archive DFIR shared-attachment IOC: %v", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE public.dfir_assets SET archived_at = $1 WHERE tenant_id = $2 AND id = $3`,
		fixture.observedAt.Add(time.Minute), fixture.tenantID, fixture.archivedAssetID); err != nil {
		t.Fatalf("archive DFIR shared-attachment asset: %v", err)
	}

	type storedAttachment struct {
		storageID    uuid.UUID
		attachmentID uuid.UUID
		tenantID     uuid.UUID
		membershipID uuid.UUID
		kind         kernel.EntityKind
		subjectID    uuid.UUID
		filename     string
		version      int64
	}
	stored := []storedAttachment{
		{fixture.uncopiedStorageID, fixture.uncopiedAttachmentID, fixture.tenantID, fixture.membershipID, kernel.EntityIOC, fixture.copiedIOCID, "uncopied-ioc.txt", 1},
		{fixture.alertStorageID, fixture.alertAttachmentID, fixture.tenantID, fixture.membershipID, kernel.EntityAlert, fixture.alertID, "alert.txt", 1},
		{fixture.iocStorageID, fixture.iocAttachmentID, fixture.tenantID, fixture.membershipID, kernel.EntityIOC, fixture.iocID, "ioc.txt", 1},
		{fixture.assetStorageID, fixture.assetAttachmentID, fixture.tenantID, fixture.membershipID, kernel.EntityAsset, fixture.assetID, "asset.txt", 1},
		{fixture.archivedIOCStorageID, fixture.archivedIOCAttachmentID, fixture.tenantID, fixture.membershipID, kernel.EntityIOC, fixture.archivedIOCID, "archived-ioc.txt", 1},
		{fixture.archivedAssetStorageID, fixture.archivedAssetAttachmentID, fixture.tenantID, fixture.membershipID, kernel.EntityAsset, fixture.archivedAssetID, "archived-asset.txt", 1},
		{fixture.copiedStorageID, fixture.copiedAttachmentID, fixture.tenantID, fixture.membershipID, kernel.EntityIOC, fixture.copiedIOCID, "copied-ioc.txt", 1},
		{fixture.ceilingStorageID, fixture.ceilingAttachmentID, fixture.tenantID, fixture.membershipID, kernel.EntityCase, fixture.firstCaseID, "ceiling.txt", int64(kernel.MaximumResourceVersion)},
		{fixture.foreignStorageID, fixture.foreignAttachmentID, fixture.foreignTenantID, foreignMembershipID, kernel.EntityIOC, fixture.foreignIOCID, "foreign-ioc.txt", 1},
	}
	for index, value := range stored {
		actorUserID := fixture.userID
		if value.tenantID == fixture.foreignTenantID {
			actorUserID = foreignUserID
		}
		setDFIRSharedAttachmentFixtureContext(t, ctx, tx, value.tenantID, actorUserID)
		digest := bytes.Repeat([]byte{byte(index + 1)}, 32)
		if _, err := tx.Exec(ctx, `
			INSERT INTO public.dfir_storage_objects (
				id, tenant_id, bucket, object_key, original_filename, classification, state,
				expected_size_bytes, upload_expires_at, content_sha256, size_bytes,
				detected_mime, verified_at, created_by_membership_id, version, created_at, updated_at
			) VALUES ($1, $2, 'dfir-runtime', $3, $4, 'internal', 'available', 32,
				$5, $6, 32, 'application/octet-stream', $7, $8, $9, $7, $7)`,
			value.storageID, value.tenantID, value.tenantID.String()+"/"+value.storageID.String(),
			value.filename, fixture.observedAt.Add(30*time.Minute), digest,
			fixture.observedAt, value.membershipID, value.version,
		); err != nil {
			t.Fatalf("insert DFIR shared-attachment storage %s: %v", value.storageID, err)
		}
		var alertID, caseID, iocID, assetID any
		switch value.kind {
		case kernel.EntityAlert:
			alertID = value.subjectID
		case kernel.EntityCase:
			caseID = value.subjectID
		case kernel.EntityIOC:
			iocID = value.subjectID
		case kernel.EntityAsset:
			assetID = value.subjectID
		default:
			t.Fatalf("unsupported fixture attachment kind %s", value.kind)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO public.dfir_attachments (
				id, tenant_id, subject_kind, alert_id, case_id, ioc_id, asset_id,
				storage_object_id, original_filename, visibility, scan_state,
				uploaded_by_membership_id, uploaded_at, version
			) VALUES ($1, $2, $3::public.dfir_entity_kind, $4, $5, $6, $7,
				$8, $9, 'private', 'available', $10, $11, $12)`,
			value.attachmentID, value.tenantID, string(value.kind), alertID, caseID, iocID, assetID,
			value.storageID, value.filename, value.membershipID, fixture.observedAt, value.version,
		); err != nil {
			t.Fatalf("insert DFIR shared attachment %s: %v", value.attachmentID, err)
		}
	}

	setDFIRSharedAttachmentFixtureContext(t, ctx, tx, fixture.tenantID, fixture.userID)
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.alert_case_links (
			id, tenant_id, alert_id, case_id, relation, reason,
			linked_by_membership_id, linked_by_user_id, source_alert_version, linked_at
		) VALUES ($1, $2, $3, $4, 'escalation', 'Explicit attachment-copy provenance',
			$5, $6, 1, $7)`,
		alertCaseLinkID, fixture.tenantID, fixture.alertID, fixture.firstCaseID,
		fixture.membershipID, fixture.userID, fixture.observedAt,
	); err != nil {
		t.Fatalf("insert source Alert-to-Case link: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.dfir_attachment_case_links (
			id, tenant_id, attachment_id, case_id, source_alert_id,
			source_alert_version, escalation_link_id, created_by_membership_id, created_at
		) VALUES ($1, $2, $3, $4, $5, 1, $6, $7, $8)`,
		attachmentCaseLinkID, fixture.tenantID, fixture.copiedAttachmentID,
		fixture.firstCaseID, fixture.alertID, alertCaseLinkID, fixture.membershipID, fixture.observedAt,
	); err != nil {
		t.Fatalf("insert explicit DFIR attachment copy: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.alert_case_links (
			id, tenant_id, alert_id, case_id, relation, reason,
			linked_by_membership_id, linked_by_user_id, source_alert_version, linked_at
		) VALUES ($1,$2,$3,$4,'escalation','Second explicit Alert association',$5,$6,1,$7)`,
		mustDFIRSharedAttachmentUUID(t), fixture.tenantID, fixture.alertID, fixture.secondCaseID,
		fixture.membershipID, fixture.userID, fixture.observedAt,
	); err != nil {
		t.Fatalf("insert second Alert-to-Case association: %v", err)
	}
	return fixture
}

func appendDFIRSharedAttachmentTestAudit(
	t testing.TB, ctx context.Context, tx pgx.Tx, fixture dfirSharedAttachmentFixture,
	eventID, caseID uuid.UUID, kind kernel.EntityKind, resourceID, attachmentID, storageID uuid.UUID,
) error {
	t.Helper()
	var returned uuid.UUID
	err := tx.QueryRow(ctx, appendDFIRDownloadGrantAuditQuery,
		eventID, "human", fixture.sessionID, fixture.membershipID, "case", caseID, int64(1),
		string(kind), resourceID, attachmentID, int64(1), storageID, int64(1),
		"available", "available", "operator", "tenant", nil, time.Now().UTC().Truncate(time.Microsecond).Add(4*time.Minute),
		mustDFIRSharedAttachmentUUID(t), mustDFIRSharedAttachmentUUID(t), "192.0.2.90",
		"dfir-shared-download-runtime", "totp",
	).Scan(&returned)
	if err == nil && returned != eventID {
		return errors.New("download audit returned a different event identifier")
	}
	return err
}

func setDFIRSharedAttachmentFixtureContext(
	t testing.TB,
	ctx context.Context,
	tx pgx.Tx,
	tenantID uuid.UUID,
	userID uuid.UUID,
) {
	t.Helper()
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true), set_config('app.user_id', $2, true)`, tenantID.String(), userID.String()); err != nil {
		t.Fatalf("install DFIR shared-attachment fixture context: %v", err)
	}
}

func setDFIRSharedAttachmentAPIRole(
	t testing.TB,
	ctx context.Context,
	tx pgx.Tx,
	tenantID uuid.UUID,
	userID uuid.UUID,
) {
	t.Helper()
	if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatalf("reset DFIR shared-attachment fixture role: %v", err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE "periapsis_api"`); err != nil {
		t.Fatalf("restore DFIR shared-attachment API role: %v", err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true), set_config('app.user_id', $2, true)`, tenantID.String(), userID.String()); err != nil {
		t.Fatalf("install DFIR shared-attachment API context: %v", err)
	}
	assertDFIRSharedAttachmentRole(t, ctx, tx, "periapsis_api", false)
}

type dfirSharedAttachmentRoleQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func assertDFIRSharedAttachmentRole(
	t testing.TB,
	ctx context.Context,
	query dfirSharedAttachmentRoleQuerier,
	expected string,
	expectedBypassRLS bool,
) {
	t.Helper()
	var current string
	var bypassRLS bool
	if err := query.QueryRow(ctx, `
		SELECT role.rolname, role.rolbypassrls
		FROM pg_catalog.pg_roles AS role
		WHERE role.rolname = current_user`).Scan(&current, &bypassRLS); err != nil {
		t.Fatalf("read DFIR shared-attachment database role: %v", err)
	}
	if current != expected || bypassRLS != expectedBypassRLS {
		t.Fatalf("DFIR shared-attachment database role = (%s, bypass_rls=%t), want (%s, %t)",
			current, bypassRLS, expected, expectedBypassRLS)
	}
}

func mustDFIRSharedAttachmentUUID(t testing.TB) uuid.UUID {
	t.Helper()
	value, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("generate DFIR shared-attachment UUIDv7: %v", err)
	}
	return value
}

func mustDFIRSharedAttachmentReference(
	t testing.TB,
	tenantID uuid.UUID,
	kind kernel.EntityKind,
	id uuid.UUID,
) kernel.EntityReference {
	t.Helper()
	value, err := kernel.NewEntityReference(entityID(tenantID), kind, entityID(id))
	if err != nil {
		t.Fatalf("construct %s shared-attachment subject: %v", kind, err)
	}
	return value
}

func assertDFIRSharedAttachmentIDs(t testing.TB, values []kernel.Attachment, expected []uuid.UUID) {
	t.Helper()
	actual := make([]uuid.UUID, len(values))
	for index, value := range values {
		actual[index] = uuid.UUID(value.ID().Bytes())
	}
	assertDFIRSharedUUIDSet(t, "attachment", actual, expected)
}

func assertDFIRSharedIndicatorIDs(t testing.TB, values []application.Versioned[kernel.Indicator], expected []uuid.UUID) {
	t.Helper()
	actual := make([]uuid.UUID, len(values))
	for index, value := range values {
		actual[index] = uuid.UUID(value.Resource.ID().Bytes())
	}
	assertDFIRSharedUUIDSet(t, "IOC", actual, expected)
}

func assertDFIRSharedAssetIDs(t testing.TB, values []application.Versioned[kernel.Asset], expected []uuid.UUID) {
	t.Helper()
	actual := make([]uuid.UUID, len(values))
	for index, value := range values {
		actual[index] = uuid.UUID(value.Resource.ID().Bytes())
	}
	assertDFIRSharedUUIDSet(t, "asset", actual, expected)
}

func assertDFIRSharedUUIDSet(t testing.TB, label string, actual []uuid.UUID, expected []uuid.UUID) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("%s IDs = %v, want %v", label, actual, expected)
	}
	remaining := make(map[uuid.UUID]struct{}, len(expected))
	for _, id := range expected {
		remaining[id] = struct{}{}
	}
	for _, id := range actual {
		if _, ok := remaining[id]; !ok {
			t.Fatalf("unexpected %s ID %s in %v", label, id, actual)
		}
		delete(remaining, id)
	}
	if len(remaining) != 0 {
		t.Fatalf("missing %s IDs %v", label, remaining)
	}
}
