package mfaauth

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

var testNow = time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)

func TestAuthorityPreservesIdPProvenanceAndLocalRequiredWins(t *testing.T) {
	providerRevision := int64(4)
	evidence := []identity.AssuranceEvidence{{
		Level: identity.AssuranceMFA, Kind: identity.AssuranceEvidenceFactor,
		Source:          identity.AssuranceSource{ProviderID: testID(80), BindingID: testID(81)},
		AuthenticatedAt: testNow, TrustRuleRevision: &providerRevision,
	}}
	trusted := authorityInput(evidence, false, mfa.FlowExistingSession)
	snapshot, err := NewAuthoritySnapshot(trusted)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.decision() != identity.AssuranceSatisfied || !snapshot.enrollmentAllowed() || snapshot.freshLocalMFA() {
		t.Fatalf("trusted IdP projection = %#v", snapshot)
	}

	localRequired := trusted
	localRequired.Policies = cloneScopedPolicies(trusted.Policies)
	localRequired.Policies[0].Policy.LocalRequired = true
	snapshot, err = NewAuthoritySnapshot(localRequired)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.decision() != identity.AssuranceStepUpRequired || snapshot.enrollmentAllowed() {
		t.Fatalf("local-required projection = %#v", snapshot)
	}
}

func TestEnrollmentGraceIsContinuationOnlyAndRecoveryRegenerationNeedsLocalMFA(t *testing.T) {
	providerRevision := int64(4)
	evidence := []identity.AssuranceEvidence{{
		Level: identity.AssurancePrimary, Kind: identity.AssuranceEvidenceFactor,
		Source:          identity.AssuranceSource{ProviderID: testID(80), BindingID: testID(81)},
		AuthenticatedAt: testNow, TrustRuleRevision: &providerRevision,
	}}
	input := authorityInput(evidence, true, mfa.FlowPostPrimaryContinuation)
	deadline := testNow.Add(10 * time.Minute)
	input.Policies[0].Policy.EnrollmentDeadline = &deadline
	snapshot, err := NewAuthoritySnapshot(input)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.decision() != identity.AssuranceEnrollmentOnly || !snapshot.enrollmentAllowed() || snapshot.freshLocalMFA() {
		t.Fatalf("continuation = %#v", snapshot)
	}

	sessionInput := input
	sessionInput.Flow = mfa.FlowExistingSession
	sessionInput.SessionID = testID(3)
	sessionInput.SessionFamilyID = testID(4)
	sessionInput.ContinuationID = identity.EntityID{}
	sessionInput.ContinuationReceiptDigest = [32]byte{}
	session, err := NewAuthoritySnapshot(sessionInput)
	if err != nil {
		t.Fatal(err)
	}
	if session.enrollmentAllowed() || session.decision() != identity.AssuranceStepUpRequired {
		t.Fatalf("an existing session inherited continuation grace: %q", session.decision())
	}

	localRevision := int64(9)
	sessionInput.BaselineEvidence = append(sessionInput.BaselineEvidence, identity.AssuranceEvidence{
		Level: identity.AssuranceMFA, Kind: identity.AssuranceEvidenceFactor,
		Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: testNow, FactorRevision: &localRevision,
	})
	session, err = NewAuthoritySnapshot(sessionInput)
	if err != nil || !session.freshLocalMFA() {
		t.Fatalf("local MFA = %#v, %v", session, err)
	}
}

func TestContinuationAuthorityRequiresExactNonzeroReceiptDigest(t *testing.T) {
	providerRevision := int64(4)
	input := authorityInput([]identity.AssuranceEvidence{{
		Level: identity.AssurancePrimary, Kind: identity.AssuranceEvidenceFactor,
		Source:          identity.AssuranceSource{ProviderID: testID(80), BindingID: testID(81)},
		AuthenticatedAt: testNow, TrustRuleRevision: &providerRevision,
	}}, true, mfa.FlowPostPrimaryContinuation)
	snapshot, err := NewAuthoritySnapshot(input)
	if err != nil {
		t.Fatal(err)
	}
	lookup := AuthorityLookup{
		Flow: mfa.FlowPostPrimaryContinuation, AnchorID: input.ContinuationID,
		Action: input.Action, Audience: input.Audience,
		ContinuationReceiptDigest: input.ContinuationReceiptDigest,
	}
	if !validAuthorityLookup(lookup) || !snapshot.matches(lookup) {
		t.Fatal("exact continuation receipt digest was rejected")
	}
	missing := lookup
	missing.ContinuationReceiptDigest = [32]byte{}
	if validAuthorityLookup(missing) || snapshot.matches(missing) {
		t.Fatal("a continuation UUID without its receipt digest was accepted")
	}
	wrong := lookup
	wrong.ContinuationReceiptDigest[31] ^= 0xff
	if !validAuthorityLookup(wrong) || snapshot.matches(wrong) {
		t.Fatal("a different continuation receipt digest matched live authority")
	}
}

func TestRecoveryRestrictedAuthorityAdmitsOnlyFactorRepair(t *testing.T) {
	revision := int64(7)
	input := authorityInput([]identity.AssuranceEvidence{{
		Level: identity.AssuranceMFA, Kind: identity.AssuranceEvidenceRecovery,
		Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: testNow, FactorRevision: &revision,
	}}, false, mfa.FlowExistingSession)
	input.AnchorRecoveryRestricted = true
	snapshot, err := NewAuthoritySnapshot(input)
	if err != nil || !snapshot.enrollmentAllowed() || snapshot.freshLocalMFA() ||
		!snapshot.binding().AnchorRecoveryRestricted {
		t.Fatalf("recovery repair snapshot = %#v, err = %v", snapshot, err)
	}

	input.BaselineEvidence[0].Kind = identity.AssuranceEvidenceFactor
	if _, err = NewAuthoritySnapshot(input); !errors.Is(err, ErrDenied) {
		t.Fatalf("restricted anchor without recovery evidence = %v", err)
	}
	input = authorityInput([]identity.AssuranceEvidence{{
		Level: identity.AssuranceMFA, Kind: identity.AssuranceEvidenceRecovery,
		Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: testNow, FactorRevision: &revision,
	}}, false, mfa.FlowPostPrimaryContinuation)
	input.AnchorRecoveryRestricted = true
	if _, err = NewAuthoritySnapshot(input); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("restricted continuation = %v", err)
	}
}

func TestAuthorityRejectsMixedAnchorsDuplicateFactorsAndMalformedEvidence(t *testing.T) {
	localRevision := int64(2)
	base := authorityInput([]identity.AssuranceEvidence{{
		Level: identity.AssuranceMFA, Kind: identity.AssuranceEvidenceFactor,
		Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: testNow, FactorRevision: &localRevision,
	}}, false, mfa.FlowExistingSession)
	tests := map[string]func(*AuthoritySnapshotInput){
		"mixed anchors":           func(input *AuthoritySnapshotInput) { input.ContinuationID = testID(9) },
		"missing identity epoch":  func(input *AuthoritySnapshotInput) { input.IdentityEpoch = 0 },
		"overflow identity epoch": func(input *AuthoritySnapshotInput) { input.IdentityEpoch = ^uint64(0) },
		"expired anchor":          func(input *AuthoritySnapshotInput) { input.AnchorExpiresAt = testNow },
		"duplicate TOTP":          func(input *AuthoritySnapshotInput) { input.TOTPFactorIDs = []identity.EntityID{testID(7), testID(7)} },
		"duplicate passkey":       func(input *AuthoritySnapshotInput) { input.PasskeyCredentialIDs = [][]byte{{1}, {1}} },
		"zero passkey handle":     func(input *AuthoritySnapshotInput) { input.PasskeyUserHandle = make([]byte, 32) },
		"missing recovery tuple":  func(input *AuthoritySnapshotInput) { input.RecoverySetVersion = 0 },
		"policy action mismatch":  func(input *AuthoritySnapshotInput) { input.PolicyContext.Action = "different" },
		"future evidence": func(input *AuthoritySnapshotInput) {
			input.BaselineEvidence[0].AuthenticatedAt = testNow.Add(time.Minute)
		},
		"duplicate evidence": func(input *AuthoritySnapshotInput) {
			input.BaselineEvidence = append(input.BaselineEvidence, cloneEvidence(input.BaselineEvidence)...)
		},
		"trimmed action":  func(input *AuthoritySnapshotInput) { input.Action = " case.export" },
		"unicode control": func(input *AuthoritySnapshotInput) { input.Audience = "tenant\u202econsole" },
		"invalid UTF-8":   func(input *AuthoritySnapshotInput) { input.Action = string([]byte{0xff}) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := base
			input.Policies = cloneScopedPolicies(base.Policies)
			input.BaselineEvidence = cloneEvidence(base.BaselineEvidence)
			input.TOTPFactorIDs = append([]identity.EntityID(nil), base.TOTPFactorIDs...)
			input.PasskeyCredentialIDs = cloneBytes2D(base.PasskeyCredentialIDs)
			mutate(&input)
			if _, err := NewAuthoritySnapshot(input); err == nil {
				t.Fatal("malformed source projection was accepted")
			}
		})
	}
}

func TestAuthorityAndAdmissionFormattingRedactsProvenance(t *testing.T) {
	canary := "sensitive-account-canary"
	values := []any{
		AuthorityLookup{Action: canary, Audience: canary},
		AuthoritySnapshotInput{Action: canary, Audience: canary, PasskeyUserHandle: []byte(canary)},
		AuthoritySnapshot{action: canary, audience: canary, passkeyUserHandle: []byte(canary)},
		AdmissionContext{}, &RateLimitError{retryAfter: time.Minute, locked: true},
	}
	for _, value := range values {
		if formatted := fmt.Sprintf("%#v", value); strings.Contains(formatted, canary) {
			t.Fatalf("unsafe format %T: %s", value, formatted)
		}
	}
}

func authorityInput(evidence []identity.AssuranceEvidence, localRequired bool, flow mfa.StepUpFlow) AuthoritySnapshotInput {
	policy := identity.AssurancePolicy{
		ID: testID(10), Revision: 3, Level: identity.AssuranceMFA, LocalRequired: localRequired,
		Freshness: time.Hour,
	}
	input := AuthoritySnapshotInput{
		LoadedAt: testNow, Flow: flow, TenantID: testID(1), UserID: testID(2), IdentityEpoch: 4,
		AnchorVersion: 5, AnchorExpiresAt: testNow.Add(30 * time.Minute),
		Action: "case.export", Audience: "tenant-console", PolicyContext: mfa.PolicyContext{
			TenantID: testID(1), Action: "case.export",
		},
		Policies:         []mfa.ScopedPolicy{{Scope: mfa.PolicyTenantBaseline, TenantID: testID(1), Policy: policy}},
		BaselineEvidence: evidence, TOTPFactorIDs: []identity.EntityID{testID(7)},
		RecoveryAvailable: true, RecoverySetID: testID(8), RecoverySetVersion: 2,
		PasskeyUserHandle: make([]byte, 32), PasskeyCredentialIDs: [][]byte{{0x11, 0x22}},
	}
	input.PasskeyUserHandle[0] = 1
	if flow == mfa.FlowExistingSession {
		input.SessionID, input.SessionFamilyID = testID(3), testID(4)
	} else {
		input.ContinuationID = testID(5)
		input.ContinuationReceiptDigest = [32]byte{1}
	}
	return input
}

func cloneScopedPolicies(values []mfa.ScopedPolicy) []mfa.ScopedPolicy {
	result := append([]mfa.ScopedPolicy(nil), values...)
	for index := range result {
		if result[index].Policy.EnrollmentDeadline != nil {
			copyValue := *result[index].Policy.EnrollmentDeadline
			result[index].Policy.EnrollmentDeadline = &copyValue
		}
	}
	return result
}

func testID(value byte) identity.EntityID {
	var id identity.EntityID
	id[6] = 0x70
	id[8] = 0x80
	id[15] = value
	return id
}
