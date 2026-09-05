package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func TestDFIRAccessRequiresExactLiveAuthorityAndUsesExplicitPrecedence(t *testing.T) {
	t.Parallel()
	tenantID := uuid.MustParse("00000000-0000-7000-8000-000000000501")
	userID := uuid.MustParse("00000000-0000-7000-8000-000000000502")
	membershipID := uuid.MustParse("00000000-0000-7000-8000-000000000503")
	caseID := uuid.MustParse("00000000-0000-7000-8000-000000000504")
	teamID := uuid.MustParse("00000000-0000-7000-8000-000000000505")
	epochID := uuid.MustParse("00000000-0000-7000-8000-000000000506")
	actor := application.Actor{
		TenantID: tenantID, ActiveTenantID: tenantID, UserID: userID,
		MembershipID: membershipID, SessionID: uuid.MustParse("00000000-0000-7000-8000-000000000507"),
		AuthenticationMethod: "oidc", Kind: application.PrincipalHuman,
	}
	authority := authorization.TenantAuthority{
		TenantID: tenantID, MembershipID: membershipID,
		MembershipStatus: authorization.MembershipStatusActive,
		Principal:        authorization.TenantPrincipal{ID: userID, Kind: authorization.PrincipalKindHuman},
		LegacyRole:       authorization.LegacyMembershipRoleCustomerUser,
		Permissions: []authorization.ScopedPermission{
			{Permission: authorization.TenantPermissionDFIRIOCRead, Scope: authorization.ScopeAssigned},
			{Permission: authorization.TenantPermissionDFIRIOCRead, Scope: authorization.ScopeOperatorTeam},
			{Permission: authorization.TenantPermissionDFIRIOCRead, Scope: authorization.ScopeTenant},
		},
		OperatorTeamRelationships: []authorization.OperatorTeamRelationship{{
			OperatorTeamID: teamID, AssignmentEpochID: epochID,
		}},
	}
	tx := &dfirTransactionStub{row: func(_ string, _ []any, destinations []any) error {
		*(destinations[0].(*bool)) = true
		*(destinations[1].(**uuid.UUID)) = &userID
		*(destinations[2].(**uuid.UUID)) = nil
		*(destinations[3].(**uuid.UUID)) = &teamID
		*(destinations[4].(**uuid.UUID)) = &epochID
		*(destinations[5].(*bool)) = true
		return nil
	}}
	access, err := dfirAccessForCase(context.Background(), tx, authority, actor, application.CapabilityIOCRead, caseID)
	if err != nil {
		t.Fatal(err)
	}
	if access.Scope != application.ScopeTenant || access.Audience != kernel.AudienceOperator {
		t.Fatalf("access = %#v, want tenant/operator", access)
	}
	authority.MembershipID = uuid.MustParse("00000000-0000-7000-8000-000000000508")
	if err := validateDFIRAuthority(authority, actor); !errors.Is(err, authorization.ErrForbidden) {
		t.Fatalf("mismatched membership error = %v", err)
	}
}

func TestDFIRCustomerAccessIsReadOnlyAssignedAndCaseVisibilityBound(t *testing.T) {
	t.Parallel()
	tenantID := uuid.MustParse("00000000-0000-7000-8000-000000000511")
	userID := uuid.MustParse("00000000-0000-7000-8000-000000000512")
	membershipID := uuid.MustParse("00000000-0000-7000-8000-000000000513")
	caseID := uuid.MustParse("00000000-0000-7000-8000-000000000514")
	actor := application.Actor{TenantID: tenantID, UserID: userID, MembershipID: membershipID, Kind: application.PrincipalCustomer}
	authority := authorization.TenantAuthority{
		TenantID: tenantID, MembershipID: membershipID,
		MembershipStatus: authorization.MembershipStatusActive,
		Principal:        authorization.TenantPrincipal{ID: userID, Kind: authorization.PrincipalKindHuman},
		LegacyRole:       authorization.LegacyMembershipRoleAnalyst,
		Permissions: []authorization.ScopedPermission{
			{Permission: authorization.TenantPermissionDFIRAttachmentRead, Scope: authorization.ScopeAssigned},
			{Permission: authorization.TenantPermissionDFIRAttachmentManage, Scope: authorization.ScopeAssigned},
		},
	}
	visible := true
	tx := &dfirTransactionStub{row: dfirCaseAccessRow(&visible, nil, nil, nil, nil, true)}
	access, err := dfirAccessForCase(context.Background(), tx, authority, actor, application.CapabilityAttachmentRead, caseID)
	if err != nil {
		t.Fatal(err)
	}
	if access.Scope != application.ScopeAssigned || access.Audience != kernel.AudienceCustomer {
		t.Fatalf("access = %#v", access)
	}
	if _, err = dfirAccessForCase(context.Background(), tx, authority, actor, application.CapabilityAttachmentManage, caseID); !errors.Is(err, authorization.ErrForbidden) {
		t.Fatalf("customer manage error = %v", err)
	}
	tx.row = dfirCaseAccessRow(&visible, nil, nil, nil, nil, false)
	if _, err = dfirAccessForCase(context.Background(), tx, authority, actor, application.CapabilityAttachmentRead, caseID); !errors.Is(err, authorization.ErrForbidden) {
		t.Fatalf("hidden Case read error = %v", err)
	}
}

func TestDFIRAttachmentSubjectRejectsAmbiguousAndMalformedProjection(t *testing.T) {
	t.Parallel()
	caseID := uuid.MustParse("00000000-0000-7000-8000-000000000521")
	assetID := uuid.MustParse("00000000-0000-7000-8000-000000000522")
	kind, id, err := dfirAttachmentSubject("case", nil, &caseID, nil, nil, nil, nil)
	if err != nil || kind != kernel.EntityCase || id != caseID {
		t.Fatalf("valid subject = (%q, %s, %v)", kind, id, err)
	}
	if _, _, err = dfirAttachmentSubject("case", nil, &caseID, nil, &assetID, nil, nil); err == nil {
		t.Fatal("ambiguous attachment subject was accepted")
	}
	if _, _, err = dfirAttachmentSubject("external", nil, nil, nil, nil, nil, nil); err == nil {
		t.Fatal("unsupported external attachment subject was accepted")
	}
}

func TestDFIRCommandAndDatabaseErrorMappingFailClosed(t *testing.T) {
	t.Parallel()
	valid := application.CommandBinding{
		Operation: "dfir.ioc.create", KeyDigest: sha256.Sum256([]byte("key")),
		RequestDigest: sha256.Sum256([]byte("request")),
	}
	if !validDFIRCommand(valid, "dfir.ioc.create") || validDFIRCommand(valid, "dfir.asset.create") {
		t.Fatal("command operation binding is not exact")
	}
	valid.KeyDigest = [sha256.Size]byte{}
	if validDFIRCommand(valid, "dfir.ioc.create") {
		t.Fatal("zero idempotency digest was accepted")
	}
	for code, expected := range map[string]error{
		"42501": application.ErrRepositoryForbidden,
		"P0002": application.ErrRepositoryNotFound,
		"40001": application.ErrRepositoryPrecondition,
		"55000": application.ErrRepositoryConflict,
	} {
		mapped := mapDFIRDatabaseError(&pgconn.PgError{Code: code})
		if !errors.Is(mapped, expected) {
			t.Fatalf("mapDFIRDatabaseError(%s) = %v, want %v", code, mapped, expected)
		}
	}
}

func TestDFIRJSONAndNullableProjectionValidation(t *testing.T) {
	t.Parallel()
	var decoded dfirOriginalIdentifiers
	if err := decodeDFIRJSON([]byte(`{"ipAddresses":[],"macAddresses":[],"unknown":true}`), &decoded); err == nil {
		t.Fatal("unknown JSON projection member was accepted")
	}
	if err := decodeDFIRJSON([]byte(`{"ipAddresses":[],"macAddresses":[]} {}`), &decoded); err == nil {
		t.Fatal("trailing JSON projection was accepted")
	}
	empty := ""
	if sameOptionalString(&empty, "") || !sameOptionalString(nil, "") {
		t.Fatal("nullable database string was not interpreted canonically")
	}
}

func TestDFIRDatabaseResourceVersionUsesExactJSONCeiling(t *testing.T) {
	t.Parallel()
	for _, version := range []int64{1, 3_000_000_000, int64(kernel.MaximumResourceVersion)} {
		if !validDFIRDatabaseResourceVersion(version) {
			t.Fatalf("safe DFIR database revision %d was rejected", version)
		}
	}
	for _, version := range []int64{0, -1, int64(kernel.MaximumResourceVersion) + 1} {
		if validDFIRDatabaseResourceVersion(version) {
			t.Fatalf("unsafe DFIR database revision %d was accepted", version)
		}
	}
}

func TestInstallDFIRWorkerTenantUsesTransactionLocalExactContext(t *testing.T) {
	t.Parallel()
	tenantID := uuid.MustParse("00000000-0000-7000-8000-000000000531")
	tx := &dfirTransactionStub{row: func(query string, arguments []any, destinations []any) error {
		if len(arguments) != 1 || arguments[0] != tenantID.String() ||
			len(destinations) != 1 || query == "" {
			return errors.New("unexpected worker context query")
		}
		*(destinations[0].(*string)) = tenantID.String()
		return nil
	}}
	if err := installDFIRWorkerTenant(context.Background(), tx, tenantID); err != nil {
		t.Fatal(err)
	}
	tx.row = func(_ string, _ []any, destinations []any) error {
		*(destinations[0].(*string)) = uuid.MustParse("00000000-0000-7000-8000-000000000532").String()
		return nil
	}
	if err := installDFIRWorkerTenant(context.Background(), tx, tenantID); err == nil {
		t.Fatal("mismatched installed worker tenant was accepted")
	}
}

func TestLoadDFIRCustodyUsesMembershipIdentityForCanonicalHashProjection(t *testing.T) {
	t.Parallel()
	tenantID := uuid.MustParse("00000000-0000-7000-8000-000000000541")
	evidenceID := uuid.MustParse("00000000-0000-7000-8000-000000000542")
	eventID := uuid.MustParse("00000000-0000-7000-8000-000000000543")
	membershipID := uuid.MustParse("00000000-0000-7000-8000-000000000544")
	previous := make([]byte, sha256.Size)
	eventHash := make([]byte, sha256.Size)
	previous[0], eventHash[0] = 1, 2
	occurredAt := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	tx := &dfirTransactionStub{query: func(query string, _ []any) (pgx.Rows, error) {
		if !strings.Contains(query, "coalesce(actor_membership_id, actor_service_account_id, actor_id)") {
			return nil, errors.New("custody query did not select the canonical membership identity")
		}
		return &dfirRowsStub{rows: [][]any{{
			eventID, tenantID, evidenceID, int64(1), "collected", membershipID,
			"initial collection", "", previous, eventHash, occurredAt,
		}}}, nil
	}}
	values, err := loadDFIRCustody(context.Background(), tx, tenantID, evidenceID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values[0].ActorID.String() != membershipID.String() {
		t.Fatalf("custody projection = %#v", values)
	}
}

type dfirTransactionStub struct {
	row   func(string, []any, []any) error
	query func(string, []any) (pgx.Rows, error)
	exec  func(string, []any) (pgconn.CommandTag, error)
}

func (transaction *dfirTransactionStub) Exec(_ context.Context, query string, arguments ...any) (pgconn.CommandTag, error) {
	if transaction.exec == nil {
		return pgconn.CommandTag{}, errors.New("unexpected Exec")
	}
	return transaction.exec(query, arguments)
}

func (transaction *dfirTransactionStub) Query(_ context.Context, query string, arguments ...any) (pgx.Rows, error) {
	if transaction.query == nil {
		return nil, errors.New("unexpected Query")
	}
	return transaction.query(query, arguments)
}

func (transaction *dfirTransactionStub) QueryRow(_ context.Context, query string, arguments ...any) pgx.Row {
	return dfirRowStub{scan: func(destinations ...any) error {
		if transaction.row == nil {
			return errors.New("unexpected QueryRow")
		}
		return transaction.row(query, arguments, destinations)
	}}
}

func (*dfirTransactionStub) Commit(context.Context) error   { return nil }
func (*dfirTransactionStub) Rollback(context.Context) error { return nil }

type dfirRowStub struct {
	scan func(...any) error
}

func (row dfirRowStub) Scan(destinations ...any) error { return row.scan(destinations...) }

type dfirRowsStub struct {
	rows   [][]any
	index  int
	closed bool
}

func (rows *dfirRowsStub) Close() { rows.closed = true }
func (*dfirRowsStub) Err() error  { return nil }
func (*dfirRowsStub) CommandTag() pgconn.CommandTag {
	return pgconn.CommandTag{}
}
func (*dfirRowsStub) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (rows *dfirRowsStub) Next() bool {
	if rows.index >= len(rows.rows) {
		rows.closed = true
		return false
	}
	rows.index++
	return true
}
func (rows *dfirRowsStub) Scan(destinations ...any) error {
	if rows.index == 0 || rows.index > len(rows.rows) {
		return errors.New("Scan called without a current row")
	}
	values := rows.rows[rows.index-1]
	if len(values) != len(destinations) {
		return errors.New("unexpected scan cardinality")
	}
	for index, value := range values {
		switch destination := destinations[index].(type) {
		case *uuid.UUID:
			*destination = value.(uuid.UUID)
		case *int64:
			*destination = value.(int64)
		case *bool:
			*destination = value.(bool)
		case *string:
			*destination = value.(string)
		case *pgtype.UUID:
			*destination = value.(pgtype.UUID)
		case *pgtype.Timestamptz:
			*destination = value.(pgtype.Timestamptz)
		case *[]byte:
			*destination = append((*destination)[:0], value.([]byte)...)
		case *time.Time:
			*destination = value.(time.Time)
		default:
			return errors.New("unsupported scan destination")
		}
	}
	return nil
}
func (rows *dfirRowsStub) Values() ([]any, error) {
	if rows.index == 0 || rows.index > len(rows.rows) {
		return nil, errors.New("Values called without a current row")
	}
	return rows.rows[rows.index-1], nil
}
func (*dfirRowsStub) RawValues() [][]byte { return nil }
func (*dfirRowsStub) Conn() *pgx.Conn     { return nil }

func dfirCaseAccessRow(
	customerVisible *bool,
	assignee, claimed, team, epoch *uuid.UUID,
	customerState bool,
) func(string, []any, []any) error {
	return func(_ string, _ []any, destinations []any) error {
		*(destinations[0].(*bool)) = *customerVisible
		*(destinations[1].(**uuid.UUID)) = assignee
		*(destinations[2].(**uuid.UUID)) = claimed
		*(destinations[3].(**uuid.UUID)) = team
		*(destinations[4].(**uuid.UUID)) = epoch
		*(destinations[5].(*bool)) = customerState
		return nil
	}
}
