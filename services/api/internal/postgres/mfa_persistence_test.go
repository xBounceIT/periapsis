package postgres

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
	"github.com/periapsis-im/periapsis/services/api/internal/mfaauth"
)

var mfaPersistenceTestNow = time.Date(2026, 8, 26, 8, 30, 0, 0, time.UTC)

type mfaQueryerStub struct {
	query func(context.Context, string, ...any) pgx.Row
}

func (stub mfaQueryerStub) QueryRow(ctx context.Context, query string, arguments ...any) pgx.Row {
	return stub.query(ctx, query, arguments...)
}

type mfaRowFunc func(...any) error

func (scan mfaRowFunc) Scan(destinations ...any) error { return scan(destinations...) }

func TestMFAWireDecoderRejectsUnknownTrailingAndOversizedState(t *testing.T) {
	t.Parallel()

	for name, raw := range map[string][]byte{
		"unknown":  []byte(`{"level":"mfa","localRequired":true,"freshnessNanoseconds":0,"enrollmentDeadline":null,"policyRevisions":[],"secret":"canary"}`),
		"trailing": []byte(`{} {}`),
		"oversize": bytes.Repeat([]byte{'x'}, maximumMFAWireBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var target assuranceRequirementWire
			if err := unmarshalMFAWire(raw, &target); !errors.Is(err, errInvalidMFAWire) {
				t.Fatalf("unmarshalMFAWire() error = %v", err)
			}
		})
	}
}

func TestMFAStepUpCreateUsesProtectedFunctionAndDigestOnlyPayload(t *testing.T) {
	t.Parallel()

	pending := mfaPendingChallengeFixture()
	called := false
	var retainedPayload []byte
	repository := &MFAStepUpRepository{queryer: mfaQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		called = true
		if query != createMFAStepUpChallengeSQL || len(arguments) != 1 {
			t.Fatalf("query = %q, arguments = %d", query, len(arguments))
		}
		payload, ok := arguments[0].([]byte)
		if !ok {
			t.Fatalf("payload type = %T", arguments[0])
		}
		retainedPayload = payload
		if bytes.Contains(payload, []byte("654321")) || bytes.Contains(payload, []byte("raw-browser")) {
			t.Fatal("protected function payload contains a raw proof")
		}
		var wire stepUpChallengeWire
		if err := unmarshalMFAWire(payload, &wire); err != nil || !bytes.Equal(wire.ID, pending.ID[:]) ||
			!bytes.Equal(wire.BrowserDigest, pending.BrowserDigest[:]) || wire.Binding.Action != "case.export" {
			t.Fatalf("wire = %#v, error = %v", wire, err)
		}
		return mfaRowFunc(func(destinations ...any) error {
			*destinations[0].(*bool) = true
			return nil
		})
	}}}

	if err := repository.Create(context.Background(), pending); err != nil || !called {
		t.Fatalf("Create() error = %v, called = %t", err, called)
	}
	if len(retainedPayload) == 0 || !allMFABytesCleared(retainedPayload) {
		t.Fatal("Create() retained an uncleared protected-function payload")
	}
}

func TestMFAAdmissionDecisionIsClosedAndComplete(t *testing.T) {
	t.Parallel()

	retryAt := mfaPersistenceTestNow.Add(time.Minute)
	tests := []struct {
		name       string
		outcome    string
		retryAt    pgtype.Timestamptz
		want       mfaauth.AdmissionOutcome
		wantRetry  time.Time
		wantReject bool
	}{
		{name: "allowed", outcome: "allowed", want: mfaauth.AdmissionAllowed},
		{name: "rate limited", outcome: "rate_limited", retryAt: pgtype.Timestamptz{Time: retryAt, Valid: true}, want: mfaauth.AdmissionRateLimited, wantRetry: retryAt},
		{name: "locked", outcome: "locked", retryAt: pgtype.Timestamptz{Time: retryAt, Valid: true}, want: mfaauth.AdmissionLocked, wantRetry: retryAt},
		{name: "allowed with retry", outcome: "allowed", retryAt: pgtype.Timestamptz{Time: retryAt, Valid: true}, wantReject: true},
		{name: "limited without retry", outcome: "rate_limited", wantReject: true},
		{name: "unknown", outcome: "future", wantReject: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository := &MFAAdmissionRepository{queryer: mfaQueryerStub{query: func(
				_ context.Context,
				query string,
				arguments ...any,
			) pgx.Row {
				if query != admitMFAOperationSQL || len(arguments) != 5 {
					t.Fatalf("query = %q, arguments = %d", query, len(arguments))
				}
				return mfaRowFunc(func(destinations ...any) error {
					*destinations[0].(*string) = test.outcome
					*destinations[1].(*pgtype.Timestamptz) = test.retryAt
					return nil
				})
			}}}
			decision, err := repository.Admit(context.Background(), mfaauth.AdmissionContext{
				OperationID:     mfaPersistenceID(1),
				NetworkDigest:   mfaauth.AdmissionDigest(bytes.Repeat([]byte{0x11}, 32)),
				PrincipalDigest: mfaauth.AdmissionDigest(bytes.Repeat([]byte{0x22}, 32)),
				ResourceDigest:  mfaauth.AdmissionDigest(bytes.Repeat([]byte{0x33}, 32)),
			}, mfaPersistenceTestNow)
			if test.wantReject {
				if !errors.Is(err, errMFAPersistence) {
					t.Fatalf("Admit() error = %v", err)
				}
				return
			}
			if err != nil || decision.Outcome != test.want || !decision.RetryAt.Equal(test.wantRetry) {
				t.Fatalf("Admit() = %#v, %v", decision, err)
			}
		})
	}
}

func TestMFARecoveryReplacementPinsDigestVersionAndClearsPayload(t *testing.T) {
	t.Parallel()

	binding := mfaPendingChallengeFixture().Binding
	digests := make([]mfaauth.RecoveryCodeDigest, 8)
	for index := range digests {
		digests[index] = mfaauth.RecoveryCodeDigest(bytes.Repeat([]byte{byte(index + 1)}, 32))
	}
	var retainedPayload []byte
	repository := &MFAEnrollmentRepository{queryer: mfaQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if query != replaceRecoveryCodesSQL || len(arguments) != 1 {
			t.Fatalf("query = %q, arguments = %d", query, len(arguments))
		}
		retainedPayload = arguments[0].([]byte)
		var wire replaceRecoveryCodesWire
		if err := unmarshalMFAWire(retainedPayload, &wire); err != nil || wire.DigestKeyVersion != 7 ||
			len(wire.Digests) != 8 || len(wire.Digests[0]) != 32 {
			t.Fatalf("wire = %#v, error = %v", wire, err)
		}
		return mfaRowFunc(func(...any) error { return pgx.ErrNoRows })
	}}}

	_, err := repository.ReplaceRecoveryCodes(context.Background(), mfaauth.ReplaceRecoveryCodesWrite{
		NewSetID: mfaPersistenceID(20), DigestKeyVersion: 7,
		ExpectedSetID: mfaPersistenceID(19), ExpectedSetVersion: 4,
		Binding: binding, Digests: digests, GeneratedAt: mfaPersistenceTestNow,
		Audit: mfaauth.AuditIntent{
			Kind: mfaauth.AuditRecoveryRegenerated, TenantID: binding.TenantID, UserID: binding.UserID,
			Action: binding.Action, OccurredAt: mfaPersistenceTestNow,
			PolicyRevisions: append([]identity.AssurancePolicyRevision(nil), binding.Requirement.PolicyRevisions...),
		},
		Session: mfaauth.SessionIntent{
			Mutation: mfaauth.SessionRotate, ExpectedSessionID: binding.SessionID,
			ExpectedFamilyID: binding.SessionFamilyID, ExpectedAnchorVersion: binding.AnchorVersion,
			ExpectedIdentityEpoch: binding.IdentityEpoch, ExpectedAnchorExpiry: binding.AnchorExpiresAt,
			Audience: binding.Audience, Requirement: binding.Requirement,
		},
	})
	if !errors.Is(err, errMFAPersistence) {
		t.Fatalf("ReplaceRecoveryCodes() error = %v", err)
	}
	if len(retainedPayload) == 0 || !allMFABytesCleared(retainedPayload) {
		t.Fatal("ReplaceRecoveryCodes() retained an uncleared digest payload")
	}

	called := false
	repository.queryer = mfaQueryerStub{query: func(context.Context, string, ...any) pgx.Row {
		called = true
		return mfaRowFunc(func(...any) error { return nil })
	}}
	if _, err := repository.ReplaceRecoveryCodes(context.Background(), mfaauth.ReplaceRecoveryCodesWrite{}); !errors.Is(err, errMFAPersistence) || called {
		t.Fatalf("invalid digest version reached database = %t, error = %v", called, err)
	}
}

func TestMFAStepUpClaimRoundTripsExactPinnedAuthority(t *testing.T) {
	t.Parallel()

	pending := mfaPendingChallengeFixture()
	claimedAt := mfaPersistenceTestNow.Add(time.Minute)
	wire, err := stepUpChallengeToWire(pending)
	if err != nil {
		t.Fatal(err)
	}
	wire.State, wire.Version, wire.ClaimedAt, wire.ClaimedFactorKind = "claimed", 2, &claimedAt, "totp"
	raw, err := marshalMFAWire(wire)
	if err != nil {
		t.Fatal(err)
	}
	repository := &MFAStepUpRepository{queryer: mfaQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if len(arguments) != 5 {
			t.Fatalf("claim query = %q, arguments = %#v", query, arguments)
		}
		receipt, receiptOK := arguments[4].([]byte)
		if query != claimMFAStepUpChallengeSQL || arguments[2] != "totp" ||
			!receiptOK || len(receipt) != 0 {
			t.Fatalf("claim query = %q, arguments = %#v", query, arguments)
		}
		return jsonMFAResultRow(raw)
	}}}

	claimed, err := repository.Claim(context.Background(), mfa.ChallengeClaim{
		ID: pending.ID, BrowserDigest: pending.BrowserDigest, Factor: mfa.FactorTOTP, ClaimedAt: claimedAt,
	})
	if err != nil || claimed.ID != pending.ID || claimed.State != mfa.ChallengeClaimed || claimed.Version != 2 ||
		!claimed.ClaimedAt.Equal(claimedAt) || claimed.Binding.TenantID != pending.Binding.TenantID ||
		claimed.Binding.Action != pending.Binding.Action {
		t.Fatalf("Claim() = %#v, %v", claimed, err)
	}
}

func TestMFAStepUpClaimRejectsPersistedFactorSubstitution(t *testing.T) {
	t.Parallel()

	pending := mfaPendingChallengeFixture()
	pending.AllowedFactors = []mfa.FactorKind{mfa.FactorTOTP, mfa.FactorRecoveryCode}
	claimedAt := mfaPersistenceTestNow.Add(time.Minute)
	for _, test := range []struct {
		requested mfa.FactorKind
		persisted string
	}{
		{requested: mfa.FactorTOTP, persisted: "recovery_code"},
		{requested: mfa.FactorRecoveryCode, persisted: "totp"},
	} {
		wire, err := stepUpChallengeToWire(pending)
		if err != nil {
			t.Fatal(err)
		}
		wire.State, wire.Version, wire.ClaimedAt, wire.ClaimedFactorKind =
			"claimed", 2, &claimedAt, test.persisted
		raw, err := marshalMFAWire(wire)
		if err != nil {
			t.Fatal(err)
		}
		repository := &MFAStepUpRepository{queryer: staticMFAJSONQueryer(raw)}
		if _, err := repository.Claim(context.Background(), mfa.ChallengeClaim{
			ID: pending.ID, BrowserDigest: pending.BrowserDigest, Factor: test.requested, ClaimedAt: claimedAt,
		}); !errors.Is(err, errMFAPersistence) {
			t.Fatalf("Claim(%v) with persisted %q error = %v", test.requested, test.persisted, err)
		}
	}
}

func TestMFAFactorLookupRejectsCrossTenantAndCrossFactorProjection(t *testing.T) {
	t.Parallel()

	tenantID, userID, factorID := mfaPersistenceID(1), mfaPersistenceID(2), mfaPersistenceID(3)
	base := totpFactorWire{
		ID: entityIDWire(factorID), TenantID: entityIDWire(tenantID), UserID: entityIDWire(userID),
		RecordVersion: 1, SecurityRevision: 4, Status: "active", LastCounter: 9,
		KeyVersion: 1, SecretEnvelope: []byte("authenticated-envelope"),
	}
	for name, mutate := range map[string]func(*totpFactorWire){
		"cross tenant":  func(value *totpFactorWire) { value.TenantID = entityIDWire(mfaPersistenceID(9)) },
		"wrong user":    func(value *totpFactorWire) { value.UserID = entityIDWire(mfaPersistenceID(9)) },
		"wrong factor":  func(value *totpFactorWire) { value.ID = entityIDWire(mfaPersistenceID(9)) },
		"unknown state": func(value *totpFactorWire) { value.Status = "future" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wire := base
			wire.SecretEnvelope = append([]byte(nil), base.SecretEnvelope...)
			mutate(&wire)
			raw, err := marshalMFAWire(wire)
			if err != nil {
				t.Fatal(err)
			}
			repository := &MFAStepUpRepository{queryer: staticMFAJSONQueryer(raw)}
			if _, err := repository.LoadTOTP(context.Background(), tenantID, userID, factorID); !errors.Is(err, errMFAPersistence) {
				t.Fatalf("LoadTOTP() error = %v", err)
			}
		})
	}
}

func TestWebAuthnCredentialLookupRejectsTenantAndCredentialSubstitution(t *testing.T) {
	t.Parallel()

	tenantID, userID := mfaPersistenceID(1), mfaPersistenceID(2)
	credentialID := []byte("credential-id")
	base := webauthnCredentialWire{
		ID: credentialID, PublicKey: bytes.Repeat([]byte{0xA5}, 64), TenantID: entityIDWire(tenantID),
		UserID: entityIDWire(userID), IdentityEpoch: 3, UserHandleDigest: bytes.Repeat([]byte{0xB4}, 32),
		RPID: "app.example.test", RPRevision: 1, Version: 1, SecurityRevision: 1,
		Status: "active", SignCount: 4,
		Discoverable: true, UserVerification: true, Transports: []string{"internal"},
	}
	for name, mutate := range map[string]func(*webauthnCredentialWire){
		"cross tenant":            func(value *webauthnCredentialWire) { value.TenantID = entityIDWire(mfaPersistenceID(9)) },
		"credential substitution": func(value *webauthnCredentialWire) { value.ID = []byte("other") },
		"unknown transport":       func(value *webauthnCredentialWire) { value.Transports = []string{"future"} },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wire := base
			wire.ID = append([]byte(nil), base.ID...)
			wire.PublicKey = append([]byte(nil), base.PublicKey...)
			wire.UserHandleDigest = append([]byte(nil), base.UserHandleDigest...)
			wire.Transports = append([]string(nil), base.Transports...)
			mutate(&wire)
			raw, err := marshalMFAWire(wire)
			if err != nil {
				t.Fatal(err)
			}
			repository := &WebAuthnRepository{queryer: staticMFAJSONQueryer(raw)}
			if _, err := repository.LoadForAuthentication(context.Background(), webauthn.CredentialLookup{
				TenantID: tenantID, CredentialID: credentialID, UserHandle: []byte("opaque"), Discoverable: true,
			}); !errors.Is(err, errMFAPersistence) {
				t.Fatalf("LoadForAuthentication() error = %v", err)
			}
		})
	}
}

func TestWebAuthnCredentialLookupMapsClosedProjection(t *testing.T) {
	t.Parallel()

	tenantID, userID := mfaPersistenceID(1), mfaPersistenceID(2)
	credentialID := []byte("credential-id")
	wire := webauthnCredentialWire{
		ID: credentialID, PublicKey: bytes.Repeat([]byte{0xA5}, 64), TenantID: entityIDWire(tenantID),
		UserID: entityIDWire(userID), IdentityEpoch: 3, UserHandleDigest: bytes.Repeat([]byte{0xB4}, 32),
		RPID: "app.example.test", RPRevision: 7, Version: 5, SecurityRevision: 4,
		Status: "active", SignCount: 4,
		Discoverable: true, UserVerification: true, BackupEligible: true, BackedUp: true,
		Transports: []string{"hybrid", "internal"},
	}
	raw, err := marshalMFAWire(wire)
	if err != nil {
		t.Fatal(err)
	}
	repository := &WebAuthnRepository{queryer: staticMFAJSONQueryer(raw)}
	credential, err := repository.LoadForAuthentication(context.Background(), webauthn.CredentialLookup{
		TenantID: tenantID, CredentialID: credentialID, UserHandle: []byte("opaque"), Discoverable: true,
	})
	if err != nil || credential.TenantID != tenantID || credential.UserID != userID ||
		credential.IdentityEpoch != 3 || credential.RPRevision != 7 || credential.Version != 5 ||
		credential.SecurityRevision != 4 ||
		credential.Status != webauthn.CredentialActive || credential.SignCount != 4 ||
		!credential.Discoverable || !credential.UserVerification || !credential.BackupEligible || !credential.BackedUp ||
		len(credential.Transports) != 2 || credential.Transports[0] != webauthn.TransportHybrid ||
		credential.Transports[1] != webauthn.TransportInternal {
		t.Fatalf("LoadForAuthentication() = %#v, %v", credential, err)
	}
}

func TestTOTPEnrollmentResultDecoderAcceptsOnlyClosedMutationIdentifiers(t *testing.T) {
	t.Parallel()

	base := totpEnrollmentResultWire{
		TenantID: entityIDWire(mfaPersistenceID(1)), UserID: entityIDWire(mfaPersistenceID(2)),
		IdentityEpoch: 3, FactorID: entityIDWire(mfaPersistenceID(3)), FactorSecurityRevision: 1,
		AuditID: entityIDWire(mfaPersistenceID(4)), SessionVersion: 2,
	}
	rotation := base
	rotation.Mutation = "rotate"
	rotation.NewSessionID = entityIDWire(mfaPersistenceID(5))
	rotation.NewSessionFamilyID = entityIDWire(mfaPersistenceID(6))
	if result, err := totpEnrollmentResultFromWire(rotation); err != nil ||
		result.NewSessionID != mfaPersistenceID(5) || result.NewSessionFamilyID != mfaPersistenceID(6) ||
		result.RetainedContinuationID != (identity.EntityID{}) {
		t.Fatalf("rotation result = %#v, %v", result, err)
	}

	retention := base
	retention.Mutation = "retain_continuation"
	retention.RetainedContinuationID = entityIDWire(mfaPersistenceID(7))
	if result, err := totpEnrollmentResultFromWire(retention); err != nil ||
		result.NewSessionID != (identity.EntityID{}) || result.NewSessionFamilyID != (identity.EntityID{}) ||
		result.RetainedContinuationID != mfaPersistenceID(7) {
		t.Fatalf("retention result = %#v, %v", result, err)
	}

	malformed := retention
	malformed.AuditID = ""
	if _, err := totpEnrollmentResultFromWire(malformed); !errors.Is(err, errMFAPersistence) {
		t.Fatalf("malformed result error = %v", err)
	}
}

func TestRecoveryCompletionWireKeepsTypedSetSeparateFromEmptyFactor(t *testing.T) {
	t.Parallel()

	binding := mfaPendingChallengeFixture().Binding
	setID := mfaPersistenceID(8)
	wire, err := completeFactorToWire(
		mfa.ChallengeID(bytes.Repeat([]byte{0x41}, 32)), 2, binding,
		identity.EntityID{}, 3, 4, nil, setID, bytes.Repeat([]byte{0x52}, 32),
		mfaPersistenceTestNow, mfa.CompletionIntent{
			Session: mfa.StepUpSessionRotate, Audit: mfa.AuditRecoveryCodeUsed,
			RecoveryRestricted: true,
		},
	)
	if err != nil || wire.FactorID != "" || wire.SetID != entityIDWire(setID) ||
		len(wire.CodeDigest) != 32 || wire.Counter != nil {
		t.Fatalf("recovery wire = %#v, %v", wire, err)
	}
}

func TestMFAPersistenceSourceUsesProtectedFunctionsWithoutDirectDML(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		"mfa_admission_repository.go",
		"mfa_enrollment_repository.go",
		"mfa_plan_repository.go",
		"mfa_stepup_repository.go",
		"webauthn_repository.go",
	} {
		source, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(string(source))
		for _, forbidden := range []string{"insert into ", "update tenant_", "delete from ", "from tenant_mfa_", "from tenant_webauthn_"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("%s contains direct table DML %q", name, forbidden)
			}
		}
		if !strings.Contains(lower, "app.") {
			t.Fatalf("%s does not call a protected app function", name)
		}
	}
}

func TestWebAuthnRepositoryHasNoNonAtomicCompletionBoundary(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("webauthn_repository.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, forbidden := range []string{
		"completeWebAuthnRegistrationSQL",
		"completeWebAuthnAuthenticationSQL",
		"func (repository *WebAuthnRepository) CompleteRegistration(",
		"func (repository *WebAuthnRepository) CompleteAuthentication(",
		"webauthn.CredentialRepository",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("non-atomic WebAuthn completion boundary returned: %q", forbidden)
		}
	}
	for _, required := range []string{
		"webauthn.CredentialLookupRepository",
		"completeMFAPasskeyRegistrationSQL",
		"completeMFAPasskeyAuthenticationSQL",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("protected WebAuthn boundary missing: %q", required)
		}
	}
}

func jsonMFAResultRow(raw []byte) pgx.Row {
	return mfaRowFunc(func(destinations ...any) error {
		if len(destinations) != 1 {
			return errors.New("unexpected scan destination count")
		}
		*destinations[0].(*[]byte) = append([]byte(nil), raw...)
		return nil
	})
}

func staticMFAJSONQueryer(raw []byte) mfaQueryerStub {
	return mfaQueryerStub{query: func(context.Context, string, ...any) pgx.Row {
		return jsonMFAResultRow(raw)
	}}
}

func mfaPendingChallengeFixture() mfa.PendingChallenge {
	tenantID, userID := mfaPersistenceID(1), mfaPersistenceID(2)
	policyID := mfaPersistenceID(9)
	revision := int64(4)
	return mfa.PendingChallenge{
		ID:            mfa.ChallengeID(bytes.Repeat([]byte{0x91}, 32)),
		BrowserDigest: [32]byte(bytes.Repeat([]byte{0x82}, 32)),
		Binding: mfa.StepUpBinding{
			Flow: mfa.FlowExistingSession, TenantID: tenantID, UserID: userID, IdentityEpoch: 3,
			SessionID: mfaPersistenceID(3), SessionFamilyID: mfaPersistenceID(4), AnchorVersion: 5,
			AnchorExpiresAt: mfaPersistenceTestNow.Add(time.Hour), Action: "case.export", Audience: "tenant-console",
			Requirement: identity.EffectiveAssuranceRequirement{
				Level:           identity.AssuranceMFA,
				PolicyRevisions: []identity.AssurancePolicyRevision{{PolicyID: policyID, Revision: 4}},
			},
			BaselineEvidence: []identity.AssuranceEvidence{{
				Level: identity.AssurancePrimary, Kind: identity.AssuranceEvidenceFactor,
				Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: mfaPersistenceTestNow,
				FactorRevision: &revision,
			}},
		},
		AllowedFactors: []mfa.FactorKind{mfa.FactorTOTP, mfa.FactorRecoveryCode},
		CreatedAt:      mfaPersistenceTestNow, ExpiresAt: mfaPersistenceTestNow.Add(5 * time.Minute),
		State: mfa.ChallengePending, Version: 1,
	}
}

func mfaPersistenceID(seed byte) identity.EntityID {
	return identity.EntityID{
		0x01, 0x9d, 0x2f, 0x44, 0x80, seed,
		0x70, seed,
		0x80, seed,
		0x11, 0x22, 0x33, 0x44, 0x55, seed,
	}
}

func allMFABytesCleared(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
