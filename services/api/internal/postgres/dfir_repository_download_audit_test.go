package postgres

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func TestAuditDownloadGrantAppendsOneDistinctRedactedEventPerSuccessfulGrant(t *testing.T) {
	t.Parallel()
	write := validDFIRDownloadGrantAuditWriteFixture(t)
	firstEventID := uuid.MustParse("00000000-0000-7000-8000-000000000671")
	secondEventID := uuid.MustParse("00000000-0000-7000-8000-000000000672")
	portalEventID := uuid.MustParse("00000000-0000-7000-8000-000000000673")
	generated := []uuid.UUID{firstEventID, secondEventID, portalEventID}
	generatedIndex := 0
	appendCalls := 0
	appended := make([]uuid.UUID, 0, len(generated))
	evaluatedAt := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

	transaction := &dfirTransactionStub{
		row: func(query string, arguments []any, destinations []any) error {
			switch {
			case strings.Contains(query, "set_config('app.tenant_id'"):
				if len(arguments) != 2 || len(destinations) != 2 {
					return errors.New("unexpected tenant context shape")
				}
				*(destinations[0].(*string)) = write.Actor.TenantID.String()
				*(destinations[1].(*string)) = write.Actor.UserID.String()
				return nil
			case strings.Contains(query, "get_current_tenant_authorization_context"):
				if len(arguments) != 0 || len(destinations) != 6 {
					return errors.New("unexpected authority context shape")
				}
				*(destinations[0].(*pgtype.UUID)) = toDatabaseUUID(write.Actor.TenantID)
				*(destinations[1].(*pgtype.UUID)) = toDatabaseUUID(write.Actor.MembershipID)
				*(destinations[2].(*int64)) = 8
				*(destinations[3].(*string)) = "active"
				*(destinations[4].(*string)) = "analyst"
				*(destinations[5].(*pgtype.Timestamptz)) = databaseTime(evaluatedAt)
				return nil
			case strings.Contains(query, "append_dfir_download_grant_audit_v1"):
				appendCalls++
				var portalContactID any
				if write.PortalAuthorization != nil {
					portalContactID = write.PortalAuthorization.ContactID
				}
				if len(arguments) != 24 || len(destinations) != 1 {
					return errors.New("unexpected download audit ABI shape")
				}
				eventID, ok := arguments[0].(uuid.UUID)
				if !ok || eventID.Version() != 7 || eventID.Variant() != uuid.RFC4122 ||
					arguments[1] != string(write.Actor.Kind) || arguments[2] != write.Actor.SessionID ||
					arguments[3] != write.Actor.MembershipID || arguments[4] != string(application.PortalTicketCase) ||
					arguments[5] != uuid.UUID(write.Root.ID.Bytes()) || arguments[6] != int64(write.RootVersion) ||
					arguments[7] != string(write.Subject.Kind()) || arguments[8] != uuid.UUID(write.Subject.ID().Bytes()) ||
					arguments[9] != uuid.UUID(write.AttachmentID.Bytes()) || arguments[10] != int64(write.AttachmentVersion) ||
					arguments[11] != uuid.UUID(write.StorageObjectID.Bytes()) || arguments[12] != int64(write.StorageVersion) ||
					arguments[13] != string(write.AttachmentState) || arguments[14] != string(write.StorageState) ||
					arguments[15] != string(write.Access.Audience) || arguments[16] != string(write.Access.Scope) ||
					arguments[17] != portalContactID || arguments[18] != write.ExpiresAt || arguments[19] != write.Audit.RequestID ||
					arguments[20] != write.Audit.CorrelationID || arguments[21] != write.Audit.IPAddress ||
					arguments[22] != write.Audit.UserAgent || arguments[23] != write.Audit.AuthenticationMethod {
					return errors.New("download audit ABI lost an exact safe binding")
				}
				for _, argument := range arguments {
					text := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(toSafeTestString(argument)), "\\", "/")))
					for _, forbidden := range []string{"x-amz-signature", "secret-object-key", "customer-file.pdf", "sha256-canary"} {
						if strings.Contains(text, forbidden) {
							return errors.New("download audit ABI leaked secret material")
						}
					}
				}
				appended = append(appended, eventID)
				*(destinations[0].(*uuid.UUID)) = eventID
				return nil
			default:
				return errors.New("unexpected download audit QueryRow")
			}
		},
		query: func(query string, _ []any) (pgx.Rows, error) {
			switch {
			case strings.Contains(query, "resolve_current_tenant_human_authority_v3"):
				return &dfirRowsStub{rows: [][]any{{
					"dfir.attachment.read", "tenant", false, pgtype.Timestamptz{},
				}}}, nil
			case strings.Contains(query, "resolve_current_tenant_operator_teams"),
				strings.Contains(query, "resolve_current_tenant_human_role_grant_paths"):
				return &dfirRowsStub{}, nil
			default:
				return nil, errors.New("unexpected download audit Query")
			}
		},
	}
	repository := &DFIRRepository{
		begin: func(_ context.Context, options pgx.TxOptions) (databaseTransaction, error) {
			if options.IsoLevel != pgx.ReadCommitted || options.AccessMode != pgx.ReadWrite {
				t.Fatalf("download audit transaction options = %#v", options)
			}
			return transaction, nil
		},
		newID: func() (uuid.UUID, error) {
			if generatedIndex >= len(generated) {
				return uuid.Nil, errors.New("unexpected audit identifier allocation")
			}
			value := generated[generatedIndex]
			generatedIndex++
			return value, nil
		},
	}

	if err := repository.AuditDownloadGrant(context.Background(), write); err != nil {
		t.Fatalf("first AuditDownloadGrant() error = %v", err)
	}
	if err := repository.AuditDownloadGrant(context.Background(), write); err != nil {
		t.Fatalf("second AuditDownloadGrant() error = %v", err)
	}
	write.Actor.Kind = application.PrincipalCustomer
	write.Access = application.Access{Audience: kernel.AudienceCustomer, Scope: application.ScopeOwn}
	write.PortalAuthorization = &application.PortalAttachmentAuthorization{
		TenantID: write.Actor.TenantID, Root: write.Root,
		ContactID: uuid.MustParse("00000000-0000-7000-8000-000000000674"), TicketVersion: write.RootVersion,
	}
	if err := repository.AuditDownloadGrant(context.Background(), write); err != nil {
		t.Fatalf("portal AuditDownloadGrant() error = %v", err)
	}
	if appendCalls != 3 || generatedIndex != 3 || len(appended) != 3 ||
		appended[0] != firstEventID || appended[1] != secondEventID || appended[2] != portalEventID ||
		appended[0] == appended[1] || appended[0] == appended[2] || appended[1] == appended[2] {
		t.Fatalf("download audit events = calls:%d generated:%d appended:%v", appendCalls, generatedIndex, appended)
	}
}

func TestAuditDownloadGrantRejectsInvalidOrUnrepresentableFencesBeforeAllocatingEvent(t *testing.T) {
	t.Parallel()
	base := validDFIRDownloadGrantAuditWriteFixture(t)
	mutations := map[string]func(*application.DownloadGrantAuditWrite){
		"root revision above JSON-safe boundary": func(write *application.DownloadGrantAuditWrite) {
			write.RootVersion = maximumDFIRDownloadRevision + 1
		},
		"attachment revision above JSON-safe boundary": func(write *application.DownloadGrantAuditWrite) {
			write.AttachmentVersion = maximumDFIRDownloadRevision + 1
		},
		"storage revision above JSON-safe boundary": func(write *application.DownloadGrantAuditWrite) {
			write.StorageVersion = maximumDFIRDownloadRevision + 1
		},
		"unsafe audit text": func(write *application.DownloadGrantAuditWrite) {
			write.Audit.UserAgent = "agent\nforged"
		},
		"authentication drift": func(write *application.DownloadGrantAuditWrite) {
			write.Audit.AuthenticationMethod = "saml"
		},
		"state drift": func(write *application.DownloadGrantAuditWrite) {
			write.AttachmentState = kernel.ScanQuarantined
		},
		"operator portal binding": func(write *application.DownloadGrantAuditWrite) {
			write.PortalAuthorization = &application.PortalAttachmentAuthorization{}
		},
	}
	for name, mutate := range mutations {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			write := base
			mutate(&write)
			allocated, began := false, false
			repository := &DFIRRepository{
				begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
					began = true
					return nil, errors.New("invalid write reached transaction")
				},
				newID: func() (uuid.UUID, error) {
					allocated = true
					return uuid.NewV7()
				},
			}
			if err := repository.AuditDownloadGrant(context.Background(), write); !errors.Is(err, application.ErrRepositoryForbidden) {
				t.Fatalf("AuditDownloadGrant() error = %v, want repository forbidden", err)
			}
			if allocated || began {
				t.Fatalf("invalid write crossed repository boundary: allocated=%t began=%t", allocated, began)
			}
		})
	}
}

func validDFIRDownloadGrantAuditWriteFixture(t *testing.T) application.DownloadGrantAuditWrite {
	t.Helper()
	tenantID := uuid.MustParse("00000000-0000-7000-8000-000000000661")
	rootID := uuid.MustParse("00000000-0000-7000-8000-000000000662")
	attachmentID := uuid.MustParse("00000000-0000-7000-8000-000000000663")
	storageID := uuid.MustParse("00000000-0000-7000-8000-000000000664")
	subject, err := kernel.NewEntityReference(entityID(tenantID), kernel.EntityCase, entityID(rootID))
	if err != nil {
		t.Fatal(err)
	}
	return application.DownloadGrantAuditWrite{
		Actor: application.Actor{
			TenantID: tenantID, ActiveTenantID: tenantID,
			UserID:               uuid.MustParse("00000000-0000-7000-8000-000000000665"),
			SessionID:            uuid.MustParse("00000000-0000-7000-8000-000000000666"),
			MembershipID:         uuid.MustParse("00000000-0000-7000-8000-000000000667"),
			AuthenticationMethod: "oidc", Kind: application.PrincipalHuman,
		},
		Audit: application.AuditContext{
			RequestID:     uuid.MustParse("00000000-0000-7000-8000-000000000668"),
			CorrelationID: uuid.MustParse("00000000-0000-7000-8000-000000000669"),
			IPAddress:     netip.MustParseAddr("192.0.2.61"), UserAgent: "dfir-download-audit-test",
			AuthenticationMethod: "oidc",
		},
		Root:        application.PortalAttachmentRoot{Kind: application.PortalTicketCase, ID: entityID(rootID)},
		RootVersion: 11, Subject: subject, AttachmentID: entityID(attachmentID), AttachmentVersion: 13,
		AttachmentState: kernel.ScanAvailable, StorageObjectID: entityID(storageID), StorageVersion: 17,
		StorageState: kernel.ScanAvailable, Access: application.Access{Audience: kernel.AudienceOperator, Scope: application.ScopeTenant},
		ExpiresAt: time.Date(2026, 9, 4, 12, 5, 0, 0, time.UTC),
	}
}

func toSafeTestString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		return ""
	}
}
