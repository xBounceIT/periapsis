package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

type platformOIDCTenantSwitchRow func(...any) error

func (row platformOIDCTenantSwitchRow) Scan(destinations ...any) error { return row(destinations...) }

type platformOIDCTenantSwitchScriptStep struct {
	queryContains string
	row           pgx.Row
}

type platformOIDCTenantSwitchTransaction struct {
	steps      []platformOIDCTenantSwitchScriptStep
	calls      []string
	arguments  [][]any
	contexts   []context.Context
	commitErr  error
	committed  bool
	rolledBack bool
}

func (*platformOIDCTenantSwitchTransaction) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	panic("unexpected Exec")
}

func (*platformOIDCTenantSwitchTransaction) Query(context.Context, string, ...any) (pgx.Rows, error) {
	panic("unexpected Query")
}

func (tx *platformOIDCTenantSwitchTransaction) QueryRow(
	ctx context.Context,
	query string,
	arguments ...any,
) pgx.Row {
	index := len(tx.calls)
	tx.calls = append(tx.calls, query)
	tx.arguments = append(tx.arguments, arguments)
	tx.contexts = append(tx.contexts, ctx)
	if index >= len(tx.steps) {
		return platformOIDCTenantSwitchRow(func(...any) error { return errors.New("unexpected query") })
	}
	step := tx.steps[index]
	if !strings.Contains(query, step.queryContains) {
		return platformOIDCTenantSwitchRow(func(...any) error {
			return errors.New("tenant switch query order mismatch")
		})
	}
	return step.row
}

func (tx *platformOIDCTenantSwitchTransaction) Commit(context.Context) error {
	tx.committed = true
	return tx.commitErr
}

func (tx *platformOIDCTenantSwitchTransaction) Rollback(context.Context) error {
	tx.rolledBack = true
	return nil
}

type platformOIDCTenantSwitchFixture struct {
	request authentication.DirectPlatformTenantSwitchRequest
	load    platformOIDCTenantSwitchLoadWire
	source  authentication.Session
	result  authentication.Session
}

func TestFederatedAuthRepositorySwitchDirectPlatformTenantUsesOneAtomicTransaction(t *testing.T) {
	fixture := newPlatformOIDCTenantSwitchFixture(t)
	loadPayload := marshalPlatformOIDCTenantSwitchTestWire(t, fixture.load)
	var capturedApplyPayload []byte
	tx := &platformOIDCTenantSwitchTransaction{}
	tx.steps = []platformOIDCTenantSwitchScriptStep{
		{queryContains: "app.admit_auth_attempts", row: platformOIDCTenantSwitchRateRow(true, time.Time{})},
		{queryContains: "app.get_auth_session_v3", row: platformOIDCTenantSwitchSessionRow(fixture.source)},
		{queryContains: "app.load_platform_oidc_tenant_switch_v1", row: platformOIDCTenantSwitchJSONRow(loadPayload)},
		{queryContains: "app.apply_platform_oidc_tenant_switch_v1", row: platformOIDCTenantSwitchRow(func(destinations ...any) error {
			payload, ok := txJSONArgument(tx, 3)
			if !ok {
				return errors.New("missing tenant switch apply payload")
			}
			capturedApplyPayload = payload
			var command platformOIDCTenantSwitchApplyWire
			if err := unmarshalMFAWire(payload, &command); err != nil {
				return err
			}
			if command.SourceSessionID != fixture.request.SourceSessionID.String() || command.Decision != "rotate" ||
				command.AuthenticationMethod != "" || command.Audit.AuthenticationMethod != "oidc" ||
				command.Session.ID != fixture.request.NewSessionID.String() ||
				command.Session.RotationFamilyID != fixture.request.RotationFamilyID.String() ||
				command.Session.SessionVersion != 2 || command.Session.RecoveryRestricted ||
				!bytes.Equal(command.Session.TokenDigest, fixture.request.NewTokenDigest[:]) ||
				!bytes.Equal(command.Session.CSRFSecretDigest, fixture.request.NewCSRFDigest[:]) {
				return errors.New("tenant switch apply command did not preserve the session envelope")
			}
			if !jsonSemanticallyEqual(command.Target.PolicySnapshot, fixture.CommandPinsPolicy(t)) {
				return errors.New("tenant switch apply command changed the policy snapshot")
			}
			wantAuditID, err := platformOIDCDirectStableAuditEventID(
				platformOIDCTenantSwitchAuditContext(fixture.request.Event), platformOIDCTenantSwitchAuditAction,
				fixture.request.SourceSessionID[:], fixture.request.TargetTenantID[:], fixture.request.NewSessionID[:],
			)
			if err != nil || command.Audit.EventID != wantAuditID.String() {
				return errors.New("tenant switch audit identifier is not stable")
			}
			givenDigest := append([]byte(nil), command.RequestDigest...)
			command.RequestDigest = nil
			encoded, err := json.Marshal(command)
			if err != nil {
				return err
			}
			wantDigest := sha256.Sum256(encoded)
			clear(encoded)
			if !bytes.Equal(givenDigest, wantDigest[:]) {
				return errors.New("tenant switch request digest is not canonical")
			}
			response := platformOIDCTenantSwitchApplyResultWire{
				Applied: tenantSwitchBoolPointer(true), Decision: "rotated",
				SourceSessionID: command.SourceSessionID, SessionID: command.Session.ID,
				TargetTenantID: command.Target.TenantID, SessionVersion: command.Session.SessionVersion,
			}
			return scanPlatformOIDCTenantSwitchJSON(destinations, marshalPlatformOIDCTenantSwitchTestWire(t, response))
		})},
		{queryContains: "app.get_auth_session_v3", row: platformOIDCTenantSwitchSessionRow(fixture.result)},
	}
	repository := &FederatedAuthRepository{begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
		return tx, nil
	}}

	got, err := repository.SwitchDirectPlatformTenant(context.Background(), fixture.request)
	if err != nil {
		t.Fatalf("SwitchDirectPlatformTenant() error = %v", err)
	}
	if got.ID != fixture.result.ID || got.ActiveTenantID == nil || *got.ActiveTenantID != fixture.request.TargetTenantID ||
		!bytes.Equal(got.CSRFDigest, fixture.request.NewCSRFDigest[:]) {
		t.Fatalf("SwitchDirectPlatformTenant() = %+v, want exact rotated session", got)
	}
	if !tx.committed || len(tx.calls) != 5 {
		t.Fatalf("transaction committed = %t, query count = %d, want true/5", tx.committed, len(tx.calls))
	}
	if scopes, ok := tx.arguments[0][0].([]string); !ok || len(scopes) != 1 || scopes[0] != "tenant_switch" {
		t.Fatalf("rate admission scopes = %#v, want tenant_switch only", tx.arguments[0][0])
	}
	for _, call := range tx.calls {
		if strings.Contains(call, "app.load_platform_oidc_tenant_switch_v1") ||
			strings.Contains(call, "app.apply_platform_oidc_tenant_switch_v1") ||
			strings.Contains(call, "app.admit_auth_attempts") || strings.Contains(call, "app.get_auth_session_v3") {
			continue
		}
		t.Fatalf("unexpected query outside the protected tenant switch path: %s", call)
	}
	if len(capturedApplyPayload) == 0 || !allZeroFederatedBytes(capturedApplyPayload) {
		t.Fatal("tenant switch JSON payload was not cleared after persistence")
	}
	for _, index := range []int{0, 1, 4} {
		for _, argument := range tx.arguments[index] {
			if raw, ok := argument.([]byte); ok && len(raw) == sha256.Size && !allZeroFederatedBytes(raw) {
				t.Fatalf("secret digest argument for query %d was not cleared", index)
			}
			if rawList, ok := argument.([][]byte); ok {
				for _, raw := range rawList {
					if !allZeroFederatedBytes(raw) {
						t.Fatalf("rate digest argument for query %d was not cleared", index)
					}
				}
			}
		}
	}
}

func TestFederatedAuthRepositorySwitchDirectPlatformTenantDispatchesSAMLWithoutOIDCFallback(t *testing.T) {
	fixture := newPlatformOIDCTenantSwitchFixture(t)
	fixture.request.AuthenticationMethod = "saml"
	fixture.source.AuthenticationMethod = "saml"
	fixture.result.AuthenticationMethod = "saml"
	fixture.load.Source.AuthenticationMethod = "saml"
	tx := &platformOIDCTenantSwitchTransaction{}
	tx.steps = []platformOIDCTenantSwitchScriptStep{
		{queryContains: "app.admit_auth_attempts", row: platformOIDCTenantSwitchRateRow(true, time.Time{})},
		{queryContains: "app.get_auth_session_v3", row: platformOIDCTenantSwitchSessionRow(fixture.source)},
		{queryContains: "app.load_platform_saml_tenant_switch_v1", row: platformOIDCTenantSwitchJSONRow(
			marshalPlatformOIDCTenantSwitchTestWire(t, fixture.load),
		)},
		{queryContains: "app.apply_platform_saml_tenant_switch_v1", row: platformOIDCTenantSwitchRow(func(destinations ...any) error {
			payload, ok := txJSONArgument(tx, 3)
			if !ok {
				return errors.New("missing SAML tenant-switch command")
			}
			var command platformOIDCTenantSwitchApplyWire
			if err := unmarshalMFAWire(payload, &command); err != nil {
				return err
			}
			if command.AuthenticationMethod != "saml" || command.Audit.AuthenticationMethod != "saml" {
				return errors.New("SAML tenant-switch proof is not method-bound")
			}
			wantAuditID, err := platformOIDCDirectStableAuditEventID(
				platformOIDCTenantSwitchAuditContext(fixture.request.Event), platformSAMLTenantSwitchAuditAction,
				fixture.request.SourceSessionID[:], fixture.request.TargetTenantID[:], fixture.request.NewSessionID[:],
			)
			if err != nil || command.Audit.EventID != wantAuditID.String() {
				return errors.New("SAML tenant-switch audit identifier is not protocol-separated")
			}
			return scanPlatformOIDCTenantSwitchJSON(destinations, marshalPlatformOIDCTenantSwitchTestWire(
				t, platformOIDCTenantSwitchRotatedResult(fixture),
			))
		})},
		{queryContains: "app.get_auth_session_v3", row: platformOIDCTenantSwitchSessionRow(fixture.result)},
	}
	repository := &FederatedAuthRepository{begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
		return tx, nil
	}}
	got, err := repository.SwitchDirectPlatformTenant(context.Background(), fixture.request)
	if err != nil || got.AuthenticationMethod != "saml" || !tx.committed {
		t.Fatalf("SAML tenant switch result/error/commit = %q/%v/%t, want saml/nil/true", got.AuthenticationMethod, err, tx.committed)
	}
	for _, call := range tx.calls {
		if strings.Contains(call, "platform_oidc_tenant_switch") {
			t.Fatalf("SAML dispatch reached OIDC tenant-switch ABI: %s", call)
		}
	}

	unknown := fixture.request
	unknown.AuthenticationMethod = "ldap"
	beginCalled := false
	repository.begin = func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
		beginCalled = true
		return nil, errors.New("must not begin")
	}
	if _, err = repository.SwitchDirectPlatformTenant(context.Background(), unknown); err != errFederatedAuthPersistence || beginCalled {
		t.Fatalf("unknown dispatch error/begin = %v/%t, want persistence/false", err, beginCalled)
	}
}

func TestFederatedAuthRepositorySwitchDirectPlatformTenantReplaysSAMLWithoutOIDCFallback(t *testing.T) {
	fixture := newPlatformOIDCTenantSwitchFixture(t)
	fixture.request.AuthenticationMethod = "saml"
	fixture.source.AuthenticationMethod = "saml"
	fixture.result.AuthenticationMethod = "saml"
	fixture.load.Source.AuthenticationMethod = "saml"
	tx := &platformOIDCTenantSwitchTransaction{}
	tx.steps = []platformOIDCTenantSwitchScriptStep{
		{queryContains: "app.admit_auth_attempts", row: platformOIDCTenantSwitchRateRow(true, time.Time{})},
		{queryContains: "app.get_auth_session_v3", row: platformOIDCTenantSwitchRow(func(...any) error { return pgx.ErrNoRows })},
		{queryContains: "app.lookup_platform_saml_tenant_switch_replay_v1", row: platformOIDCTenantSwitchRow(func(destinations ...any) error {
			payload, ok := txJSONArgument(tx, 2)
			if !ok {
				return errors.New("missing SAML replay lookup")
			}
			var lookup platformOIDCTenantSwitchReplayLookupWire
			if err := unmarshalMFAWire(payload, &lookup); err != nil {
				return err
			}
			if lookup.Audit.AuthenticationMethod != "saml" {
				return errors.New("SAML replay lookup is not method-bound")
			}
			wantAuditID, err := platformOIDCDirectStableAuditEventID(
				platformOIDCTenantSwitchAuditContext(fixture.request.Event), platformSAMLTenantSwitchAuditAction,
				fixture.request.SourceSessionID[:], fixture.request.TargetTenantID[:], fixture.request.NewSessionID[:],
			)
			if err != nil || lookup.Audit.EventID != wantAuditID.String() {
				return errors.New("SAML replay lookup audit proof changed")
			}
			return scanPlatformOIDCTenantSwitchJSON(destinations, marshalPlatformOIDCTenantSwitchTestWire(
				t, platformOIDCTenantSwitchReplayResultWire{
					Matched: tenantSwitchBoolPointer(true), Result: platformOIDCTenantSwitchRotatedResult(fixture),
				},
			))
		})},
		{queryContains: "app.get_auth_session_v3", row: platformOIDCTenantSwitchSessionRow(fixture.result)},
	}
	repository := &FederatedAuthRepository{begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
		return tx, nil
	}}
	got, err := repository.SwitchDirectPlatformTenant(context.Background(), fixture.request)
	if err != nil || got.AuthenticationMethod != "saml" || !tx.committed {
		t.Fatalf("SAML replay result/error/commit = %q/%v/%t, want saml/nil/true", got.AuthenticationMethod, err, tx.committed)
	}
	for _, call := range tx.calls {
		if strings.Contains(call, "platform_oidc_tenant_switch") {
			t.Fatalf("SAML replay reached OIDC tenant-switch ABI: %s", call)
		}
	}
}

func TestFederatedAuthRepositorySwitchDirectPlatformTenantRejectsCrossFamilySAMLState(t *testing.T) {
	tests := map[string]func(*platformOIDCTenantSwitchFixture) []platformOIDCTenantSwitchScriptStep{
		"OIDC source session": func(fixture *platformOIDCTenantSwitchFixture) []platformOIDCTenantSwitchScriptStep {
			return []platformOIDCTenantSwitchScriptStep{
				{queryContains: "app.admit_auth_attempts", row: platformOIDCTenantSwitchRateRow(true, time.Time{})},
				{queryContains: "app.get_auth_session_v3", row: platformOIDCTenantSwitchSessionRow(fixture.source)},
			}
		},
		"OIDC load projection": func(fixture *platformOIDCTenantSwitchFixture) []platformOIDCTenantSwitchScriptStep {
			fixture.source.AuthenticationMethod = "saml"
			return []platformOIDCTenantSwitchScriptStep{
				{queryContains: "app.admit_auth_attempts", row: platformOIDCTenantSwitchRateRow(true, time.Time{})},
				{queryContains: "app.get_auth_session_v3", row: platformOIDCTenantSwitchSessionRow(fixture.source)},
				{queryContains: "app.load_platform_saml_tenant_switch_v1", row: platformOIDCTenantSwitchJSONRow(
					marshalPlatformOIDCTenantSwitchTestWire(t, fixture.load),
				)},
			}
		},
	}
	for name, steps := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newPlatformOIDCTenantSwitchFixture(t)
			fixture.request.AuthenticationMethod = "saml"
			tx := &platformOIDCTenantSwitchTransaction{steps: steps(&fixture)}
			repository := &FederatedAuthRepository{begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
				return tx, nil
			}}
			if _, err := repository.SwitchDirectPlatformTenant(context.Background(), fixture.request); !errors.Is(err, authentication.ErrForbidden) {
				t.Fatalf("SwitchDirectPlatformTenant() error = %v, want forbidden", err)
			}
			if !tx.committed {
				t.Fatal("cross-family denial did not commit the rate-limit decision")
			}
			for _, call := range tx.calls {
				if strings.Contains(call, "apply_platform_saml_tenant_switch") ||
					strings.Contains(call, "platform_oidc_tenant_switch") {
					t.Fatalf("cross-family SAML denial reached a mutation or OIDC ABI: %s", call)
				}
			}
		})
	}
}

func TestFederatedAuthRepositorySwitchDirectPlatformTenantReplaysCommittedRotation(t *testing.T) {
	fixture := newPlatformOIDCTenantSwitchFixture(t)
	rotated := platformOIDCTenantSwitchApplyResultWire{
		Applied: tenantSwitchBoolPointer(true), Decision: "rotated",
		SourceSessionID: fixture.request.SourceSessionID.String(), SessionID: fixture.request.NewSessionID.String(),
		TargetTenantID: fixture.request.TargetTenantID.String(), SessionVersion: 2,
	}
	var replayPayload []byte
	tx := &platformOIDCTenantSwitchTransaction{}
	tx.steps = []platformOIDCTenantSwitchScriptStep{
		{queryContains: "app.admit_auth_attempts", row: platformOIDCTenantSwitchRateRow(true, time.Time{})},
		{queryContains: "app.get_auth_session_v3", row: platformOIDCTenantSwitchRow(func(...any) error { return pgx.ErrNoRows })},
		{queryContains: "app.lookup_platform_oidc_tenant_switch_replay_v1", row: platformOIDCTenantSwitchRow(func(destinations ...any) error {
			payload, ok := txJSONArgument(tx, 2)
			if !ok {
				return errors.New("missing replay proof payload")
			}
			replayPayload = payload
			var lookup platformOIDCTenantSwitchReplayLookupWire
			if err := unmarshalMFAWire(payload, &lookup); err != nil {
				return err
			}
			wantAuditID, err := platformOIDCDirectStableAuditEventID(
				platformOIDCTenantSwitchAuditContext(fixture.request.Event), platformOIDCTenantSwitchAuditAction,
				fixture.request.SourceSessionID[:], fixture.request.TargetTenantID[:], fixture.request.NewSessionID[:],
			)
			if err != nil || lookup.SourceSessionID != fixture.request.SourceSessionID.String() ||
				lookup.TargetTenantID != fixture.request.TargetTenantID.String() ||
				lookup.NewSessionID != fixture.request.NewSessionID.String() ||
				lookup.RotationFamilyID != fixture.request.RotationFamilyID.String() ||
				!bytes.Equal(lookup.SourceTokenDigest, fixture.request.SourceTokenDigest[:]) ||
				!bytes.Equal(lookup.NewTokenDigest, fixture.request.NewTokenDigest[:]) ||
				!bytes.Equal(lookup.CSRFSecretDigest, fixture.request.NewCSRFDigest[:]) ||
				lookup.Audit.EventID != wantAuditID.String() {
				return errors.New("replay lookup did not carry the exact proof")
			}
			return scanPlatformOIDCTenantSwitchJSON(destinations, marshalPlatformOIDCTenantSwitchTestWire(t,
				platformOIDCTenantSwitchReplayResultWire{
					Matched: tenantSwitchBoolPointer(true), Result: &rotated,
				},
			))
		})},
		{queryContains: "app.get_auth_session_v3", row: platformOIDCTenantSwitchSessionRow(fixture.result)},
	}
	repository := &FederatedAuthRepository{begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
		return tx, nil
	}}

	got, err := repository.SwitchDirectPlatformTenant(context.Background(), fixture.request)
	if err != nil {
		t.Fatalf("SwitchDirectPlatformTenant() replay error = %v", err)
	}
	if got.ID != fixture.request.NewSessionID || !tx.committed || len(tx.calls) != 4 {
		t.Fatalf("replay session/commit/calls = %s/%t/%d, want %s/true/4", got.ID, tx.committed, len(tx.calls), fixture.request.NewSessionID)
	}
	if len(replayPayload) == 0 || !allZeroFederatedBytes(replayPayload) {
		t.Fatal("tenant switch replay proof payload was not cleared")
	}
	for _, index := range []int{1, 3} {
		for _, argument := range tx.arguments[index] {
			if raw, ok := argument.([]byte); ok && len(raw) == sha256.Size && !allZeroFederatedBytes(raw) {
				t.Fatalf("replay secret digest argument for query %d was not cleared", index)
			}
		}
	}
}

func TestFederatedAuthRepositorySwitchDirectPlatformTenantRecoversAmbiguousCommit(t *testing.T) {
	fixture := newPlatformOIDCTenantSwitchFixture(t)
	ambiguousCommit := errors.New("ambiguous tenant switch commit")
	original := &platformOIDCTenantSwitchTransaction{
		steps:     platformOIDCTenantSwitchSuccessfulSteps(t, fixture),
		commitErr: ambiguousCommit,
	}
	recovery := &platformOIDCTenantSwitchTransaction{steps: []platformOIDCTenantSwitchScriptStep{
		{queryContains: "app.lookup_platform_oidc_tenant_switch_replay_v1", row: platformOIDCTenantSwitchJSONRow(
			marshalPlatformOIDCTenantSwitchTestWire(t, platformOIDCTenantSwitchReplayResultWire{
				Matched: tenantSwitchBoolPointer(true), Result: platformOIDCTenantSwitchRotatedResult(fixture),
			}),
		)},
		{queryContains: "app.get_auth_session_v3", row: platformOIDCTenantSwitchSessionRow(fixture.result)},
	}}
	transactions := []*platformOIDCTenantSwitchTransaction{original, recovery}
	options := make([]pgx.TxOptions, 0, len(transactions))
	repository := &FederatedAuthRepository{begin: func(_ context.Context, transactionOptions pgx.TxOptions) (databaseTransaction, error) {
		options = append(options, transactionOptions)
		index := len(options) - 1
		if index >= len(transactions) {
			return nil, errors.New("unexpected third transaction")
		}
		return transactions[index], nil
	}}

	got, err := repository.SwitchDirectPlatformTenant(context.Background(), fixture.request)
	if err != nil {
		t.Fatalf("SwitchDirectPlatformTenant() ambiguous commit recovery error = %v", err)
	}
	if got.ID != fixture.result.ID || got.ActiveTenantID == nil || *got.ActiveTenantID != fixture.request.TargetTenantID {
		t.Fatalf("SwitchDirectPlatformTenant() recovered session = %+v, want exact rotated session", got)
	}
	if len(options) != 2 || options[1].AccessMode != pgx.ReadOnly || options[1].IsoLevel != pgx.ReadCommitted {
		t.Fatalf("transaction options = %#v, want second transaction read-only/read-committed", options)
	}
	if !original.committed || !recovery.committed || len(original.calls) != 5 || len(recovery.calls) != 2 {
		t.Fatalf(
			"original/recovery committed and calls = %t/%d %t/%d, want true/5 true/2",
			original.committed, len(original.calls), recovery.committed, len(recovery.calls),
		)
	}
	rateAdmissions := 0
	for _, tx := range transactions {
		for _, call := range tx.calls {
			if strings.Contains(call, "app.admit_auth_attempts") {
				rateAdmissions++
			}
		}
	}
	if rateAdmissions != 1 {
		t.Fatalf("rate admission count = %d, want one across original and recovery transactions", rateAdmissions)
	}
	for index, arguments := range recovery.arguments {
		for _, argument := range arguments {
			if raw, ok := argument.([]byte); ok && len(raw) > 0 && !allZeroFederatedBytes(raw) {
				t.Fatalf("recovery secret payload for query %d was not cleared", index)
			}
		}
	}
}

func TestFederatedAuthRepositorySwitchDirectPlatformTenantRecoveryPreservesOriginalWorkError(t *testing.T) {
	fixture := newPlatformOIDCTenantSwitchFixture(t)
	original := &platformOIDCTenantSwitchTransaction{steps: []platformOIDCTenantSwitchScriptStep{{
		queryContains: "app.admit_auth_attempts",
		row:           platformOIDCTenantSwitchRow(func(...any) error { return errors.New("database query failed") }),
	}}}
	recovery := &platformOIDCTenantSwitchTransaction{steps: []platformOIDCTenantSwitchScriptStep{{
		queryContains: "app.lookup_platform_oidc_tenant_switch_replay_v1",
		row: platformOIDCTenantSwitchJSONRow(marshalPlatformOIDCTenantSwitchTestWire(t,
			platformOIDCTenantSwitchReplayResultWire{Matched: tenantSwitchBoolPointer(false)},
		)),
	}}}
	transactions := []databaseTransaction{original, recovery}
	beginCount := 0
	repository := &FederatedAuthRepository{begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
		if beginCount >= len(transactions) {
			return nil, errors.New("unexpected third transaction")
		}
		tx := transactions[beginCount]
		beginCount++
		return tx, nil
	}}

	_, err := repository.SwitchDirectPlatformTenant(context.Background(), fixture.request)
	if err != errFederatedAuthPersistence {
		t.Fatalf("SwitchDirectPlatformTenant() error = %v, want original persistence error", err)
	}
	if beginCount != 2 || !original.rolledBack || original.committed || !recovery.committed {
		t.Fatalf(
			"begin/original rollback+commit/recovery commit = %d/%t+%t/%t, want 2/true+false/true",
			beginCount, original.rolledBack, original.committed, recovery.committed,
		)
	}
	if len(original.calls) != 1 || len(recovery.calls) != 1 {
		t.Fatalf("original/recovery calls = %d/%d, want 1/1", len(original.calls), len(recovery.calls))
	}
}

func TestFederatedAuthRepositorySwitchDirectPlatformTenantRecoveryIgnoresCancellationAndIsBounded(t *testing.T) {
	fixture := newPlatformOIDCTenantSwitchFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	original := &platformOIDCTenantSwitchTransaction{steps: []platformOIDCTenantSwitchScriptStep{
		{queryContains: "app.admit_auth_attempts", row: platformOIDCTenantSwitchRateRow(true, time.Time{})},
		{queryContains: "app.get_auth_session_v3", row: platformOIDCTenantSwitchRow(func(destinations ...any) error {
			err := scanPlatformOIDCTenantSwitchSession(destinations, fixture.source)
			cancel()
			return err
		})},
	}}
	recovery := &platformOIDCTenantSwitchTransaction{steps: []platformOIDCTenantSwitchScriptStep{{
		queryContains: "app.lookup_platform_oidc_tenant_switch_replay_v1",
		row: platformOIDCTenantSwitchJSONRow(marshalPlatformOIDCTenantSwitchTestWire(t,
			platformOIDCTenantSwitchReplayResultWire{Matched: tenantSwitchBoolPointer(false)},
		)),
	}}}
	beginCount := 0
	recoveryContextLive := false
	recoveryDeadlineBounded := false
	repository := &FederatedAuthRepository{begin: func(beginContext context.Context, _ pgx.TxOptions) (databaseTransaction, error) {
		beginCount++
		switch beginCount {
		case 1:
			return original, nil
		case 2:
			recoveryContextLive = beginContext.Err() == nil
			deadline, ok := beginContext.Deadline()
			remaining := time.Until(deadline)
			recoveryDeadlineBounded = ok && remaining > 0 && remaining <= platformOIDCTenantSwitchRecoveryTimeout
			return recovery, nil
		default:
			return nil, errors.New("unexpected third transaction")
		}
	}}

	_, err := repository.SwitchDirectPlatformTenant(ctx, fixture.request)
	if err != errFederatedAuthPersistence {
		t.Fatalf("SwitchDirectPlatformTenant() error = %v, want original persistence error", err)
	}
	if !recoveryContextLive || !recoveryDeadlineBounded {
		t.Fatalf(
			"recovery context live/bounded = %t/%t, want true/true",
			recoveryContextLive, recoveryDeadlineBounded,
		)
	}
	if beginCount != 2 || len(recovery.calls) != 1 || !recovery.committed {
		t.Fatalf("recovery begin/calls/commit = %d/%d/%t, want 2/1/true", beginCount, len(recovery.calls), recovery.committed)
	}
}

func TestFederatedAuthRepositorySwitchDirectPlatformTenantRecoveryNeverMasksMalformedOrMismatchedProof(t *testing.T) {
	tests := map[string]func(*testing.T, platformOIDCTenantSwitchFixture) []platformOIDCTenantSwitchScriptStep{
		"malformed": func(_ *testing.T, _ platformOIDCTenantSwitchFixture) []platformOIDCTenantSwitchScriptStep {
			return []platformOIDCTenantSwitchScriptStep{{
				queryContains: "app.lookup_platform_oidc_tenant_switch_replay_v1",
				row:           platformOIDCTenantSwitchJSONRow([]byte(`{"matched":true}`)),
			}}
		},
		"mismatched": func(t *testing.T, fixture platformOIDCTenantSwitchFixture) []platformOIDCTenantSwitchScriptStep {
			result := platformOIDCTenantSwitchRotatedResult(fixture)
			result.SessionID = platformOIDCTenantSwitchUUID(99).String()
			return []platformOIDCTenantSwitchScriptStep{{
				queryContains: "app.lookup_platform_oidc_tenant_switch_replay_v1",
				row: platformOIDCTenantSwitchJSONRow(marshalPlatformOIDCTenantSwitchTestWire(t,
					platformOIDCTenantSwitchReplayResultWire{
						Matched: tenantSwitchBoolPointer(true), Result: result,
					},
				)),
			}}
		},
	}
	for name, recoverySteps := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newPlatformOIDCTenantSwitchFixture(t)
			ambiguousCommit := errors.New("ambiguous " + name + " commit")
			original := &platformOIDCTenantSwitchTransaction{
				steps:     platformOIDCTenantSwitchSuccessfulSteps(t, fixture),
				commitErr: ambiguousCommit,
			}
			recovery := &platformOIDCTenantSwitchTransaction{steps: recoverySteps(t, fixture)}
			transactions := []databaseTransaction{original, recovery}
			beginCount := 0
			repository := &FederatedAuthRepository{begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
				if beginCount >= len(transactions) {
					return nil, errors.New("unexpected third transaction")
				}
				tx := transactions[beginCount]
				beginCount++
				return tx, nil
			}}

			got, err := repository.SwitchDirectPlatformTenant(context.Background(), fixture.request)
			if !errors.Is(err, ambiguousCommit) || err.Error() != "commit database transaction: "+ambiguousCommit.Error() {
				t.Fatalf("SwitchDirectPlatformTenant() error = %v, want exact original commit error", err)
			}
			if got.ID != uuid.Nil || got.RotationFamilyID != uuid.Nil || got.User.ID != uuid.Nil ||
				len(got.CSRFDigest) != 0 || len(got.Permissions) != 0 || got.ActiveTenantID != nil {
				t.Fatalf("SwitchDirectPlatformTenant() session = %+v, want zero session", got)
			}
			if beginCount != 2 || recovery.committed || !recovery.rolledBack {
				t.Fatalf(
					"recovery begin/commit/rollback = %d/%t/%t, want 2/false/true",
					beginCount, recovery.committed, recovery.rolledBack,
				)
			}
		})
	}
}

func TestFederatedAuthRepositorySwitchDirectPlatformTenantCommitsExpectedDenials(t *testing.T) {
	tests := map[string]struct {
		steps    func(*testing.T, platformOIDCTenantSwitchFixture, *platformOIDCTenantSwitchTransaction) []platformOIDCTenantSwitchScriptStep
		wantRate bool
	}{
		"rate limit": {
			steps: func(_ *testing.T, fixture platformOIDCTenantSwitchFixture, _ *platformOIDCTenantSwitchTransaction) []platformOIDCTenantSwitchScriptStep {
				return []platformOIDCTenantSwitchScriptStep{{
					queryContains: "app.admit_auth_attempts",
					row:           platformOIDCTenantSwitchRateRow(false, fixture.request.OccurredAt.Add(time.Minute)),
				}}
			},
			wantRate: true,
		},
		"unknown source": {
			steps: func(t *testing.T, _ platformOIDCTenantSwitchFixture, _ *platformOIDCTenantSwitchTransaction) []platformOIDCTenantSwitchScriptStep {
				return []platformOIDCTenantSwitchScriptStep{
					{queryContains: "app.admit_auth_attempts", row: platformOIDCTenantSwitchRateRow(true, time.Time{})},
					{queryContains: "app.get_auth_session_v3", row: platformOIDCTenantSwitchRow(func(...any) error { return pgx.ErrNoRows })},
					{queryContains: "app.lookup_platform_oidc_tenant_switch_replay_v1", row: platformOIDCTenantSwitchJSONRow(
						marshalPlatformOIDCTenantSwitchTestWire(t, platformOIDCTenantSwitchReplayResultWire{
							Matched: tenantSwitchBoolPointer(false),
						}),
					)},
				}
			},
		},
		"no command capability": {
			steps: func(t *testing.T, fixture platformOIDCTenantSwitchFixture, _ *platformOIDCTenantSwitchTransaction) []platformOIDCTenantSwitchScriptStep {
				fixture.load.CommandPins = json.RawMessage("null")
				return platformOIDCTenantSwitchPrefixSteps(fixture, marshalPlatformOIDCTenantSwitchTestWire(t, fixture.load))
			},
		},
		"local policy": {
			steps: func(t *testing.T, fixture platformOIDCTenantSwitchFixture, _ *platformOIDCTenantSwitchTransaction) []platformOIDCTenantSwitchScriptStep {
				pins := fixture.commandPins(t)
				var policy platformOIDCTenantSwitchPolicySnapshotWire
				if err := unmarshalMFAWire(pins.PolicySnapshot, &policy); err != nil {
					t.Fatal(err)
				}
				policy.Policies[0].Policy.LocalRequired = true
				policy.Requirement.LocalRequired = true
				pins.PolicySnapshot = marshalPlatformOIDCTenantSwitchTestWire(t, policy)
				fixture.load.CommandPins = marshalPlatformOIDCTenantSwitchTestWire(t, pins)
				return platformOIDCTenantSwitchPrefixSteps(fixture, marshalPlatformOIDCTenantSwitchTestWire(t, fixture.load))
			},
		},
		"target provenance drift": {
			steps: func(t *testing.T, fixture platformOIDCTenantSwitchFixture, _ *platformOIDCTenantSwitchTransaction) []platformOIDCTenantSwitchScriptStep {
				fixture.load.Target.AccessGrant.AccessSourceID = platformOIDCTenantSwitchUUID(90).String()
				return platformOIDCTenantSwitchPrefixSteps(fixture, marshalPlatformOIDCTenantSwitchTestWire(t, fixture.load))
			},
		},
		"command pin drift": {
			steps: func(t *testing.T, fixture platformOIDCTenantSwitchFixture, _ *platformOIDCTenantSwitchTransaction) []platformOIDCTenantSwitchScriptStep {
				pins := fixture.commandPins(t)
				pins.MFASubjectVersion++
				fixture.load.CommandPins = marshalPlatformOIDCTenantSwitchTestWire(t, pins)
				return platformOIDCTenantSwitchPrefixSteps(fixture, marshalPlatformOIDCTenantSwitchTestWire(t, fixture.load))
			},
		},
		"replayed session no longer usable": {
			steps: func(t *testing.T, fixture platformOIDCTenantSwitchFixture, _ *platformOIDCTenantSwitchTransaction) []platformOIDCTenantSwitchScriptStep {
				rotated := platformOIDCTenantSwitchApplyResultWire{
					Applied: tenantSwitchBoolPointer(true), Decision: "rotated",
					SourceSessionID: fixture.request.SourceSessionID.String(),
					SessionID:       fixture.request.NewSessionID.String(),
					TargetTenantID:  fixture.request.TargetTenantID.String(), SessionVersion: 2,
				}
				return []platformOIDCTenantSwitchScriptStep{
					{queryContains: "app.admit_auth_attempts", row: platformOIDCTenantSwitchRateRow(true, time.Time{})},
					{queryContains: "app.get_auth_session_v3", row: platformOIDCTenantSwitchRow(func(...any) error { return pgx.ErrNoRows })},
					{queryContains: "app.lookup_platform_oidc_tenant_switch_replay_v1", row: platformOIDCTenantSwitchJSONRow(
						marshalPlatformOIDCTenantSwitchTestWire(t, platformOIDCTenantSwitchReplayResultWire{
							Matched: tenantSwitchBoolPointer(true), Result: &rotated,
						}),
					)},
					{queryContains: "app.get_auth_session_v3", row: platformOIDCTenantSwitchRow(func(...any) error { return pgx.ErrNoRows })},
				}
			},
		},
		"stale apply": {
			steps: func(t *testing.T, fixture platformOIDCTenantSwitchFixture, _ *platformOIDCTenantSwitchTransaction) []platformOIDCTenantSwitchScriptStep {
				steps := platformOIDCTenantSwitchPrefixSteps(fixture, marshalPlatformOIDCTenantSwitchTestWire(t, fixture.load))
				steps = append(steps, platformOIDCTenantSwitchScriptStep{
					queryContains: "app.apply_platform_oidc_tenant_switch_v1",
					row: platformOIDCTenantSwitchJSONRow(marshalPlatformOIDCTenantSwitchTestWire(t,
						platformOIDCTenantSwitchApplyResultWire{Applied: tenantSwitchBoolPointer(false), Category: "stale"},
					)),
				})
				return steps
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newPlatformOIDCTenantSwitchFixture(t)
			tx := &platformOIDCTenantSwitchTransaction{}
			tx.steps = test.steps(t, fixture, tx)
			repository := &FederatedAuthRepository{begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
				return tx, nil
			}}
			_, err := repository.SwitchDirectPlatformTenant(context.Background(), fixture.request)
			if test.wantRate {
				var rate *authentication.RateLimitError
				if !errors.As(err, &rate) || rate.RetryAfter != time.Minute {
					t.Fatalf("SwitchDirectPlatformTenant() error = %v, want one-minute rate limit", err)
				}
			} else if !errors.Is(err, authentication.ErrForbidden) {
				t.Fatalf("SwitchDirectPlatformTenant() error = %v, want forbidden", err)
			}
			if !tx.committed {
				t.Fatal("ordinary tenant-switch denial did not commit rate admission")
			}
		})
	}
}

func TestFederatedAuthRepositorySwitchDirectPlatformTenantRollsBackMalformedAndCancelledWork(t *testing.T) {
	tests := map[string]func(*testing.T, platformOIDCTenantSwitchFixture, *platformOIDCTenantSwitchTransaction, context.CancelFunc) []platformOIDCTenantSwitchScriptStep{
		"database failure": func(_ *testing.T, _ platformOIDCTenantSwitchFixture, _ *platformOIDCTenantSwitchTransaction, _ context.CancelFunc) []platformOIDCTenantSwitchScriptStep {
			return []platformOIDCTenantSwitchScriptStep{{
				queryContains: "app.admit_auth_attempts",
				row:           platformOIDCTenantSwitchRow(func(...any) error { return errors.New("database unavailable") }),
			}}
		},
		"malformed replay": func(_ *testing.T, _ platformOIDCTenantSwitchFixture, _ *platformOIDCTenantSwitchTransaction, _ context.CancelFunc) []platformOIDCTenantSwitchScriptStep {
			return []platformOIDCTenantSwitchScriptStep{
				{queryContains: "app.admit_auth_attempts", row: platformOIDCTenantSwitchRateRow(true, time.Time{})},
				{queryContains: "app.get_auth_session_v3", row: platformOIDCTenantSwitchRow(func(...any) error { return pgx.ErrNoRows })},
				{queryContains: "app.lookup_platform_oidc_tenant_switch_replay_v1", row: platformOIDCTenantSwitchJSONRow(
					[]byte(`{"matched":true}`),
				)},
			}
		},
		"malformed apply": func(t *testing.T, fixture platformOIDCTenantSwitchFixture, _ *platformOIDCTenantSwitchTransaction, _ context.CancelFunc) []platformOIDCTenantSwitchScriptStep {
			steps := platformOIDCTenantSwitchPrefixSteps(fixture, marshalPlatformOIDCTenantSwitchTestWire(t, fixture.load))
			steps = append(steps, platformOIDCTenantSwitchScriptStep{
				queryContains: "app.apply_platform_oidc_tenant_switch_v1",
				row:           platformOIDCTenantSwitchJSONRow([]byte(`{"applied":true,"decision":"rotated"}`)),
			})
			return steps
		},
		"policy projection mismatch": func(t *testing.T, fixture platformOIDCTenantSwitchFixture, _ *platformOIDCTenantSwitchTransaction, _ context.CancelFunc) []platformOIDCTenantSwitchScriptStep {
			pins := fixture.commandPins(t)
			var policy platformOIDCTenantSwitchPolicySnapshotWire
			if err := unmarshalMFAWire(pins.PolicySnapshot, &policy); err != nil {
				t.Fatal(err)
			}
			policy.Requirement.Level = "mfa"
			pins.PolicySnapshot = marshalPlatformOIDCTenantSwitchTestWire(t, policy)
			fixture.load.CommandPins = marshalPlatformOIDCTenantSwitchTestWire(t, pins)
			return platformOIDCTenantSwitchPrefixSteps(fixture, marshalPlatformOIDCTenantSwitchTestWire(t, fixture.load))
		},
		"cancelled": func(_ *testing.T, fixture platformOIDCTenantSwitchFixture, _ *platformOIDCTenantSwitchTransaction, cancel context.CancelFunc) []platformOIDCTenantSwitchScriptStep {
			return []platformOIDCTenantSwitchScriptStep{
				{queryContains: "app.admit_auth_attempts", row: platformOIDCTenantSwitchRateRow(true, time.Time{})},
				{queryContains: "app.get_auth_session_v3", row: platformOIDCTenantSwitchRow(func(destinations ...any) error {
					err := scanPlatformOIDCTenantSwitchSession(destinations, fixture.source)
					cancel()
					return err
				})},
			}
		},
	}
	for name, steps := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newPlatformOIDCTenantSwitchFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tx := &platformOIDCTenantSwitchTransaction{}
			tx.steps = steps(t, fixture, tx, cancel)
			repository := &FederatedAuthRepository{begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
				return tx, nil
			}}
			if _, err := repository.SwitchDirectPlatformTenant(ctx, fixture.request); err == nil ||
				errors.Is(err, authentication.ErrForbidden) {
				t.Fatalf("SwitchDirectPlatformTenant() error = %v, want persistence failure", err)
			}
			if tx.committed || !tx.rolledBack {
				t.Fatalf("transaction committed = %t, rolled back = %t, want false/true", tx.committed, tx.rolledBack)
			}
		})
	}
}

func TestPlatformOIDCTenantSwitchRejectsTOTPProvenanceElevation(t *testing.T) {
	fixture := newPlatformOIDCTenantSwitchFixture(t)
	pins := fixture.commandPins(t)
	var policy platformOIDCTenantSwitchPolicySnapshotWire
	if err := unmarshalMFAWire(pins.PolicySnapshot, &policy); err != nil {
		t.Fatal(err)
	}
	policy.Policies[0].Policy.Level = "mfa"
	policy.Requirement.Level = "mfa"
	pins.PolicySnapshot = marshalPlatformOIDCTenantSwitchTestWire(t, policy)
	fixture.load.CommandPins = marshalPlatformOIDCTenantSwitchTestWire(t, pins)
	totpEvidenceID := platformOIDCTenantSwitchUUID(31)
	totpID := platformOIDCTenantSwitchUUID(32)
	factorRevision := int64(1)
	fixture.load.Assurance.Evidence = append(fixture.load.Assurance.Evidence, platformOIDCDirectSessionEvidenceWire{
		ID: totpEvidenceID.String(), UserID: fixture.request.UserID.String(), Kind: "totp", Level: "mfa",
		PlatformProviderID: json.RawMessage("null"), ExternalIdentityID: json.RawMessage("null"),
		AuthenticatedAt: fixture.request.OccurredAt.Add(-time.Minute), ExpiresAt: json.RawMessage("null"),
		TOTPCredentialID: mustRawJSONString(t, totpID.String()), FactorRevision: mustRawJSON(t, factorRevision),
		TrustRuleID: json.RawMessage("null"), TrustRuleRevision: json.RawMessage("null"),
	})
	fixture.load.Assurance.Level = "mfa"
	fixture.load.Assurance.LocalSatisfied = tenantSwitchBoolPointer(true)
	// The database orders provider evidence before TOTP evidence.
	tx := &platformOIDCTenantSwitchTransaction{steps: platformOIDCTenantSwitchPrefixSteps(
		fixture, marshalPlatformOIDCTenantSwitchTestWire(t, fixture.load),
	)}
	repository := &FederatedAuthRepository{begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
		return tx, nil
	}}
	if _, err := repository.SwitchDirectPlatformTenant(context.Background(), fixture.request); !errors.Is(err, authentication.ErrForbidden) {
		t.Fatalf("SwitchDirectPlatformTenant() error = %v, want forbidden", err)
	}
	if !tx.committed || len(tx.calls) != 3 {
		t.Fatalf("TOTP provenance denial committed/calls = %t/%d, want true/3", tx.committed, len(tx.calls))
	}
}

func TestPlatformOIDCTenantSwitchApplyCommandIsStableAndClearsSecrets(t *testing.T) {
	fixture := newPlatformOIDCTenantSwitchFixture(t)
	pins := fixture.commandPins(t)
	snapshot, err := platformOIDCTenantSwitchSnapshotFromWire(fixture.load.Source, fixture.load.Target)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := platformoidcAdmissionForTest(fixture.request.OccurredAt, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	audit := platformOIDCTenantSwitchAuditContext(fixture.request.Event)
	eventID, err := platformOIDCDirectStableAuditEventID(
		audit, platformOIDCTenantSwitchAuditAction,
		fixture.request.SourceSessionID[:], fixture.request.TargetTenantID[:], fixture.request.NewSessionID[:],
	)
	if err != nil {
		t.Fatal(err)
	}
	auditWire, err := platformOIDCDirectAuditToWire(audit, eventID)
	if err != nil {
		t.Fatal(err)
	}
	first, err := platformOIDCTenantSwitchApplyCommand(fixture.request, admission, pins, auditWire)
	if err != nil {
		t.Fatal(err)
	}
	second, err := platformOIDCTenantSwitchApplyCommand(fixture.request, admission, pins, auditWire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.RequestDigest, second.RequestDigest) || first.Audit.EventID != second.Audit.EventID {
		t.Fatal("exact retry did not preserve the request digest and audit identity")
	}
	requestDigest := first.RequestDigest
	tokenDigest := first.Session.TokenDigest
	csrfDigest := first.Session.CSRFSecretDigest
	clearPlatformOIDCTenantSwitchApplyWire(&first)
	if !allZeroFederatedBytes(requestDigest) || !allZeroFederatedBytes(tokenDigest) || !allZeroFederatedBytes(csrfDigest) {
		t.Fatal("tenant switch apply wire did not clear secret buffers")
	}
	clearPlatformOIDCTenantSwitchApplyWire(&second)
}

func TestFederatedAuthRepositorySwitchDirectPlatformTenantRejectsInvalidRequestBeforeBegin(t *testing.T) {
	base := newPlatformOIDCTenantSwitchFixture(t).request
	tests := map[string]func(*authentication.DirectPlatformTenantSwitchRequest){
		"non v7 source": func(value *authentication.DirectPlatformTenantSwitchRequest) {
			value.SourceSessionID = uuid.New()
		},
		"duplicate identifier": func(value *authentication.DirectPlatformTenantSwitchRequest) {
			value.NewSessionID = value.SourceSessionID
		},
		"zero digest": func(value *authentication.DirectPlatformTenantSwitchRequest) {
			value.NewTokenDigest = [sha256.Size]byte{}
		},
		"duplicate digest": func(value *authentication.DirectPlatformTenantSwitchRequest) {
			value.NewCSRFDigest = value.NewTokenDigest
		},
		"non canonical time": func(value *authentication.DirectPlatformTenantSwitchRequest) {
			value.OccurredAt = value.OccurredAt.Add(time.Nanosecond)
		},
		"wrong rate scope": func(value *authentication.DirectPlatformTenantSwitchRequest) {
			value.AdmissionRules[0].Key.Scope = "local_login"
		},
		"invalid audit": func(value *authentication.DirectPlatformTenantSwitchRequest) {
			value.Event.UserAgent = "forged\nagent"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := base
			request.AdmissionRules = []authentication.RateLimitRule{{
				Key: authentication.RateLimitKey{
					Scope:  request.AdmissionRules[0].Key.Scope,
					Digest: append([]byte(nil), request.AdmissionRules[0].Key.Digest...),
				},
				Policy: request.AdmissionRules[0].Policy,
			}}
			mutate(&request)
			began := false
			repository := &FederatedAuthRepository{begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
				began = true
				return nil, errors.New("unexpected begin")
			}}
			if _, err := repository.SwitchDirectPlatformTenant(context.Background(), request); err == nil {
				t.Fatal("SwitchDirectPlatformTenant() accepted an invalid request")
			}
			if began {
				t.Fatal("invalid tenant-switch request began a transaction")
			}
		})
	}
}

func newPlatformOIDCTenantSwitchFixture(t *testing.T) platformOIDCTenantSwitchFixture {
	t.Helper()
	now := time.Date(2026, 8, 30, 12, 0, 0, 123000000, time.UTC)
	sourceID := platformOIDCTenantSwitchUUID(1)
	familyID := platformOIDCTenantSwitchUUID(2)
	userID := platformOIDCTenantSwitchUUID(3)
	tenantID := platformOIDCTenantSwitchUUID(4)
	newID := platformOIDCTenantSwitchUUID(5)
	providerID := platformOIDCTenantSwitchUUID(6)
	externalID := platformOIDCTenantSwitchUUID(7)
	membershipID := platformOIDCTenantSwitchUUID(8)
	bindingID := platformOIDCTenantSwitchUUID(9)
	epochID := platformOIDCTenantSwitchUUID(10)
	sourceAuthorityID := platformOIDCTenantSwitchUUID(11)
	grantID := platformOIDCTenantSwitchUUID(12)
	policyID := platformOIDCTenantSwitchUUID(13)
	evidenceID := platformOIDCTenantSwitchUUID(14)
	requestID := platformOIDCTenantSwitchUUID(15)
	correlationID := platformOIDCTenantSwitchUUID(16)
	sourceToken := filledPlatformOIDCTenantSwitchDigest(0x11)
	newToken := filledPlatformOIDCTenantSwitchDigest(0x22)
	newCSRF := filledPlatformOIDCTenantSwitchDigest(0x33)
	sourceCSRF := filledPlatformOIDCTenantSwitchDigest(0x44)
	rateDigest := filledPlatformOIDCTenantSwitchDigest(0x55)
	absoluteExpiresAt := now.Add(time.Hour)
	request := authentication.DirectPlatformTenantSwitchRequest{
		SourceSessionID: sourceID, RotationFamilyID: familyID, AuthenticationMethod: "oidc",
		SourceTokenDigest: sourceToken,
		NewSessionID:      newID, NewTokenDigest: newToken, NewCSRFDigest: newCSRF,
		UserID: userID, TargetTenantID: tenantID, OccurredAt: now,
		IdleExpiresAt: now.Add(15 * time.Minute), AbsoluteExpiresAt: absoluteExpiresAt,
		Event: authentication.EventContext{
			RequestID: requestID, CorrelationID: correlationID,
			RemoteAddress: netip.MustParseAddr("192.0.2.10"), UserAgent: "periapsis-test-agent",
		},
		AdmissionRules: []authentication.RateLimitRule{{
			Key:    authentication.RateLimitKey{Scope: "tenant_switch", Digest: rateDigest[:]},
			Policy: authentication.RateLimitPolicy{Limit: 10, Window: time.Minute, BlockFor: 5 * time.Minute},
		}},
	}
	truth := tenantSwitchBoolPointer(true)
	revision := platformOIDCDirectExactRevisionWire{Pinned: 1, Current: 1}
	policy := platformOIDCTenantSwitchPolicySnapshotWire{
		PolicyContext: policyContextWire{
			TenantID: tenantID.String(), RoleIDs: []string{}, SecurityGroupIDs: []string{}, Action: "session.create",
		},
		Policies: []scopedPolicyWire{{
			Scope: "tenant_baseline", TenantID: tenantID.String(), Policy: assurancePolicyWire{
				ID: policyID.String(), Revision: 1, Level: "primary",
			},
		}},
		Requirement: assuranceRequirementWire{
			Level: "primary", PolicyRevisions: []policyRevisionWire{{PolicyID: policyID.String(), Revision: 1}},
		},
	}
	pins := platformOIDCTenantSwitchCommandPinsWire{
		TenantID: tenantID.String(), TenantVersion: 1, MembershipID: membershipID.String(),
		MFASubjectVersion: 1, IdentityEpoch: 1, SessionInvalidationEpoch: 1,
		BindingID: bindingID.String(), BindingVersion: 1, MappingRevision: 1, AuthorizationRevision: 1,
		AccessEpochID: epochID.String(), AccessEpochVersion: 1, AccessSourceID: sourceAuthorityID.String(),
		AccessGrantID: grantID.String(), AccessGrantVersion: 1, PlatformProviderID: providerID.String(),
		ProviderRevision: 1, SecurityRevision: 1, ExternalIdentityID: externalID.String(),
		IdentityVersion: 1, AliasKeyVersion: 1, PolicySnapshot: marshalPlatformOIDCTenantSwitchTestWire(t, policy),
	}
	load := platformOIDCTenantSwitchLoadWire{
		Source: platformOIDCTenantSwitchSourceWire{
			SessionID: sourceID.String(), RotationFamilyID: familyID.String(), UserID: userID.String(),
			ProviderID: providerID.String(), ExternalIdentityID: externalID.String(), ActiveTenantID: json.RawMessage("null"),
			AuthenticationMethod: "oidc", PrimaryKind: "platform_provider", DirectStateCount: 1,
			DirectProvenanceCount: 1, TenantProvenanceCount: 0, ExpectedVersion: 1, CurrentVersion: 1,
			IdleExpiresAt: now.Add(10 * time.Minute), AbsoluteExpiresAt: absoluteExpiresAt,
			SessionActive: truth, RotationFamilyLive: truth, UserActive: truth, ProviderEnabled: truth,
			PlatformLoginLive: truth, AccountMode: "existing_identity", IdentityLive: truth, SubjectAliasLive: truth,
			Revisions: platformOIDCTenantSwitchSourceRevisionsWire{
				Provider: revision, Security: revision, PlatformLogin: revision,
				ExternalIdentity: revision, SubjectAliasKey: revision,
			},
		},
		Assurance: &platformOIDCTenantSwitchAssuranceWire{
			Level: "primary", AuthenticatedAt: now.Add(-5 * time.Minute), ExpiresAt: json.RawMessage("null"),
			LocalSatisfied: tenantSwitchBoolPointer(false), Evidence: []platformOIDCDirectSessionEvidenceWire{{
				ID: evidenceID.String(), UserID: userID.String(), Kind: "platform_provider", Level: "primary",
				PlatformProviderID: mustRawJSONString(t, providerID.String()),
				ExternalIdentityID: mustRawJSONString(t, externalID.String()),
				AuthenticatedAt:    now.Add(-5 * time.Minute), ExpiresAt: json.RawMessage("null"),
				TOTPCredentialID: json.RawMessage("null"), FactorRevision: json.RawMessage("null"),
				TrustRuleID: json.RawMessage("null"), TrustRuleRevision: json.RawMessage("null"),
			}},
		},
		Target: platformOIDCTenantSwitchTargetWire{
			TenantExecutionLive: truth,
			Tenant:              platformOIDCTenantSwitchTenantWire{ID: tenantID.String(), Version: 1, Active: truth},
			Membership: platformOIDCTenantSwitchMembershipWire{
				ID: membershipID.String(), TenantID: tenantID.String(), UserID: userID.String(), Active: truth,
			},
			Binding: platformOIDCTenantSwitchBindingWire{
				ID: bindingID.String(), TenantID: tenantID.String(), ProviderID: providerID.String(), Version: 1,
				MappingRevision: 1, AuthorizationRevision: 1, CurrentAccessEpochID: epochID.String(), Enabled: truth,
			},
			AccessEpoch: platformOIDCTenantSwitchAccessEpochWire{
				ID: epochID.String(), TenantID: tenantID.String(), BindingID: bindingID.String(),
				ProviderID: providerID.String(), SourceID: sourceAuthorityID.String(), Version: 1, Live: truth,
			},
			AccessSource: platformOIDCTenantSwitchAccessSourceWire{
				ID: sourceAuthorityID.String(), TenantID: tenantID.String(), PlatformProvider: truth,
				Authoritative: truth, Live: truth,
			},
			ExternalIdentity: platformOIDCTenantSwitchExternalIdentityWire{
				ID: externalID.String(), ProviderID: providerID.String(), UserID: userID.String(), Version: 1, Live: truth,
			},
			SubjectAlias: platformOIDCTenantSwitchSubjectAliasWire{
				ExternalIdentityID: externalID.String(), KeyVersion: 1, Live: truth,
			},
			AccessGrant: platformOIDCTenantSwitchAccessGrantWire{
				ID: grantID.String(), TenantID: tenantID.String(), ProviderID: providerID.String(),
				BindingID: bindingID.String(), AccessEpochID: epochID.String(), AccessSourceID: sourceAuthorityID.String(),
				ExternalIdentityID: externalID.String(), MembershipID: membershipID.String(), UserID: userID.String(),
				Version: 1, Live: truth,
			},
			MFASubject: platformOIDCTenantSwitchMFASubjectWire{Version: 1, IdentityEpoch: 1, SessionInvalidationEpoch: 1},
		},
		CommandPins: marshalPlatformOIDCTenantSwitchTestWire(t, pins),
	}
	source := authentication.Session{
		ID: sourceID, RotationFamilyID: familyID, User: authentication.User{ID: userID, DisplayName: "Test User"},
		CSRFDigest: sourceCSRF[:], CreatedAt: now.Add(-time.Hour), LastSeenAt: now.Add(-time.Minute),
		IdleExpiresAt: now.Add(10 * time.Minute), AbsoluteExpiresAt: absoluteExpiresAt,
		AuthenticationMethod: "oidc",
	}
	resultTenant := tenantID
	result := authentication.Session{
		ID: newID, RotationFamilyID: familyID, User: authentication.User{ID: userID, DisplayName: "Test User"},
		CSRFDigest: newCSRF[:], ActiveTenantID: &resultTenant, CreatedAt: now, LastSeenAt: now,
		IdleExpiresAt: request.IdleExpiresAt, AbsoluteExpiresAt: absoluteExpiresAt,
		AuthenticationMethod: "oidc",
	}
	return platformOIDCTenantSwitchFixture{request: request, load: load, source: source, result: result}
}

func (fixture platformOIDCTenantSwitchFixture) commandPins(t *testing.T) platformOIDCTenantSwitchCommandPinsWire {
	t.Helper()
	var pins platformOIDCTenantSwitchCommandPinsWire
	if err := unmarshalMFAWire(fixture.load.CommandPins, &pins); err != nil {
		t.Fatal(err)
	}
	return pins
}

func (fixture platformOIDCTenantSwitchFixture) CommandPinsPolicy(t *testing.T) json.RawMessage {
	t.Helper()
	return fixture.commandPins(t).PolicySnapshot
}

func platformOIDCTenantSwitchPrefixSteps(
	fixture platformOIDCTenantSwitchFixture,
	load []byte,
) []platformOIDCTenantSwitchScriptStep {
	return []platformOIDCTenantSwitchScriptStep{
		{queryContains: "app.admit_auth_attempts", row: platformOIDCTenantSwitchRateRow(true, time.Time{})},
		{queryContains: "app.get_auth_session_v3", row: platformOIDCTenantSwitchSessionRow(fixture.source)},
		{queryContains: "app.load_platform_oidc_tenant_switch_v1", row: platformOIDCTenantSwitchJSONRow(load)},
	}
}

func platformOIDCTenantSwitchSuccessfulSteps(
	t *testing.T,
	fixture platformOIDCTenantSwitchFixture,
) []platformOIDCTenantSwitchScriptStep {
	t.Helper()
	steps := platformOIDCTenantSwitchPrefixSteps(
		fixture,
		marshalPlatformOIDCTenantSwitchTestWire(t, fixture.load),
	)
	return append(steps,
		platformOIDCTenantSwitchScriptStep{
			queryContains: "app.apply_platform_oidc_tenant_switch_v1",
			row: platformOIDCTenantSwitchJSONRow(marshalPlatformOIDCTenantSwitchTestWire(
				t,
				platformOIDCTenantSwitchRotatedResult(fixture),
			)),
		},
		platformOIDCTenantSwitchScriptStep{
			queryContains: "app.get_auth_session_v3",
			row:           platformOIDCTenantSwitchSessionRow(fixture.result),
		},
	)
}

func platformOIDCTenantSwitchRotatedResult(
	fixture platformOIDCTenantSwitchFixture,
) *platformOIDCTenantSwitchApplyResultWire {
	return &platformOIDCTenantSwitchApplyResultWire{
		Applied: tenantSwitchBoolPointer(true), Decision: "rotated",
		SourceSessionID: fixture.request.SourceSessionID.String(),
		SessionID:       fixture.request.NewSessionID.String(),
		TargetTenantID:  fixture.request.TargetTenantID.String(),
		SessionVersion:  2,
	}
}

func platformOIDCTenantSwitchRateRow(admitted bool, blockedUntil time.Time) pgx.Row {
	return platformOIDCTenantSwitchRow(func(destinations ...any) error {
		if len(destinations) != 3 {
			return errors.New("unexpected rate admission projection")
		}
		*destinations[0].(*bool) = admitted
		*destinations[1].(*int32) = 1
		if !blockedUntil.IsZero() {
			*destinations[2].(*pgtype.Timestamptz) = pgtype.Timestamptz{Time: blockedUntil, Valid: true}
		}
		return nil
	})
}

func platformOIDCTenantSwitchJSONRow(payload []byte) pgx.Row {
	return platformOIDCTenantSwitchRow(func(destinations ...any) error {
		return scanPlatformOIDCTenantSwitchJSON(destinations, payload)
	})
}

func scanPlatformOIDCTenantSwitchJSON(destinations []any, payload []byte) error {
	if len(destinations) != 1 {
		return errors.New("unexpected JSON projection")
	}
	*destinations[0].(*[]byte) = append([]byte(nil), payload...)
	return nil
}

func platformOIDCTenantSwitchSessionRow(value authentication.Session) pgx.Row {
	return platformOIDCTenantSwitchRow(func(destinations ...any) error {
		return scanPlatformOIDCTenantSwitchSession(destinations, value)
	})
}

func scanPlatformOIDCTenantSwitchSession(destinations []any, value authentication.Session) error {
	if len(destinations) != 13 {
		return errors.New("unexpected session projection")
	}
	*destinations[0].(*pgtype.UUID) = toDatabaseUUID(value.ID)
	*destinations[1].(*pgtype.UUID) = toDatabaseUUID(value.User.ID)
	*destinations[2].(*pgtype.UUID) = toDatabaseUUID(value.RotationFamilyID)
	if value.User.Email != nil {
		*destinations[3].(*string) = *value.User.Email
	}
	*destinations[4].(*string) = value.User.DisplayName
	if value.ActiveTenantID != nil {
		*destinations[5].(*pgtype.UUID) = toDatabaseUUID(*value.ActiveTenantID)
	}
	*destinations[6].(*[]byte) = append([]byte(nil), value.CSRFDigest...)
	*destinations[7].(*string) = value.AuthenticationMethod
	*destinations[8].(*pgtype.Timestamptz) = databaseTime(value.CreatedAt)
	*destinations[9].(*pgtype.Timestamptz) = databaseTime(value.LastSeenAt)
	*destinations[10].(*pgtype.Timestamptz) = databaseTime(value.IdleExpiresAt)
	*destinations[11].(*pgtype.Timestamptz) = databaseTime(value.AbsoluteExpiresAt)
	*destinations[12].(*[]string) = []string{}
	return nil
}

func txJSONArgument(tx *platformOIDCTenantSwitchTransaction, call int) ([]byte, bool) {
	if tx == nil || call < 0 || call >= len(tx.arguments) || len(tx.arguments[call]) != 1 {
		return nil, false
	}
	value, ok := tx.arguments[call][0].([]byte)
	return value, ok
}

func platformOIDCTenantSwitchAuditContext(event authentication.EventContext) platformoidcauth.DirectAuditContext {
	return platformoidcauth.DirectAuditContext{
		RequestID: identity.EntityID(event.RequestID), CorrelationID: identity.EntityID(event.CorrelationID),
		RemoteAddress: event.RemoteAddress, UserAgent: event.UserAgent,
	}
}

func platformoidcAdmissionForTest(
	now time.Time,
	snapshot platformoidcauth.TenantSwitchSnapshot,
) (platformoidcauth.TenantSwitchAdmission, error) {
	return platformoidcauth.PlanTenantSwitchAdmission(now, snapshot)
}

func platformOIDCTenantSwitchUUID(seed byte) uuid.UUID {
	return uuid.UUID(postgresFederatedID(seed))
}

func filledPlatformOIDCTenantSwitchDigest(value byte) [sha256.Size]byte {
	var result [sha256.Size]byte
	for index := range result {
		result[index] = value
	}
	return result
}

func marshalPlatformOIDCTenantSwitchTestWire(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustRawJSONString(t *testing.T, value string) json.RawMessage {
	t.Helper()
	return marshalPlatformOIDCTenantSwitchTestWire(t, value)
}

func mustRawJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	return marshalPlatformOIDCTenantSwitchTestWire(t, value)
}

func tenantSwitchBoolPointer(value bool) *bool { return &value }

func jsonSemanticallyEqual(left, right []byte) bool {
	var leftValue, rightValue any
	return json.Unmarshal(left, &leftValue) == nil && json.Unmarshal(right, &rightValue) == nil &&
		reflectDeepEqual(leftValue, rightValue)
}

func reflectDeepEqual(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}
