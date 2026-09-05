package postgres

import (
	"bytes"
	"testing"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
	"github.com/periapsis-im/periapsis/services/api/internal/mfaauth"
)

func TestWebAuthnCredentialWireKeepsRecordAndSecurityRevisionsDistinct(t *testing.T) {
	t.Parallel()

	base := webauthnCredentialWire{
		ID: []byte("credential-id"), PublicKey: bytes.Repeat([]byte{0xa5}, 64),
		TenantID: entityIDWire(mfaPersistenceID(1)), UserID: entityIDWire(mfaPersistenceID(2)),
		IdentityEpoch: 3, UserHandleDigest: bytes.Repeat([]byte{0xb4}, 32),
		RPID: "app.example.test", RPRevision: 7, Version: 5, SecurityRevision: 3,
		Status: "active", SignCount: 4, Discoverable: true, UserVerification: true,
		BackupEligible: true, BackedUp: true, Transports: []string{"internal"},
	}
	credential, err := webauthnCredentialFromWire(base)
	if err != nil || credential.Version != 5 || credential.SecurityRevision != 3 {
		t.Fatalf("credential = %#v, %v", credential, err)
	}

	for name, mutate := range map[string]func(*webauthnCredentialWire){
		"missing security revision": func(value *webauthnCredentialWire) { value.SecurityRevision = 0 },
		"security beyond record": func(value *webauthnCredentialWire) {
			value.SecurityRevision = value.Version + 1
		},
		"record beyond JSON safe": func(value *webauthnCredentialWire) {
			value.Version = maximumMFAJSONSafeInteger + 1
		},
		"security beyond JSON safe": func(value *webauthnCredentialWire) {
			value.Version = maximumMFAJSONSafeInteger + 1
			value.SecurityRevision = maximumMFAJSONSafeInteger + 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			if _, err := webauthnCredentialFromWire(value); err == nil {
				t.Fatal("invalid credential revision projection was accepted")
			}
		})
	}
}

func TestWebAuthnAuthenticationResultRequiresExactSecurityEpochShape(t *testing.T) {
	t.Parallel()

	base := webauthnAuthenticationResultWire{
		CredentialVersion: 6, SecurityRevision: 3, Status: "active", SignCount: 5,
	}
	result, err := webauthnAuthenticationResultFromWire(base)
	if err != nil || result.CredentialVersion != 6 || result.SecurityRevision != 3 {
		t.Fatalf("result = %#v, %v", result, err)
	}
	for name, mutate := range map[string]func(*webauthnAuthenticationResultWire){
		"missing": func(value *webauthnAuthenticationResultWire) { value.SecurityRevision = 0 },
		"beyond record": func(value *webauthnAuthenticationResultWire) {
			value.SecurityRevision = value.CredentialVersion + 1
		},
		"record beyond JSON safe": func(value *webauthnAuthenticationResultWire) {
			value.CredentialVersion = maximumMFAJSONSafeInteger + 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			if _, err := webauthnAuthenticationResultFromWire(value); err == nil {
				t.Fatal("invalid authentication security revision was accepted")
			}
		})
	}
}

func TestPasskeyAuthenticationResultAllowsOnlyExactAnchorlessCloneVersion(t *testing.T) {
	t.Parallel()

	base := passkeyAuthenticationResultWire{
		Outcome: "committed",
		Credential: webauthnAuthenticationResultWire{
			CredentialVersion: 6, SecurityRevision: 4, Status: "clone_suspected", SignCount: 5,
		},
		TenantID: entityIDWire(mfaPersistenceID(1)), UserID: entityIDWire(mfaPersistenceID(2)),
		IdentityEpoch: 3, AuditID: entityIDWire(mfaPersistenceID(3)), Mutation: "revoke",
		SessionVersion: 0,
	}
	result, err := passkeyAuthenticationResultFromWire(base)
	if err != nil || result.Mutation != mfaauth.SessionRevoke || result.SessionVersion != 0 ||
		result.RevokedAnchorID != (identity.EntityID{}) {
		t.Fatalf("primary clone result = %#v, %v", result, err)
	}
	for name, mutate := range map[string]func(*passkeyAuthenticationResultWire){
		"create": func(value *passkeyAuthenticationResultWire) {
			value.Mutation = "create"
		},
		"rotate": func(value *passkeyAuthenticationResultWire) {
			value.Mutation = "rotate"
		},
		"consume continuation": func(value *passkeyAuthenticationResultWire) {
			value.Mutation = "consume_continuation"
			value.ConsumedContinuationID = entityIDWire(mfaPersistenceID(7))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			value := base
			value.Credential.Status = "active"
			value.NewSessionID = entityIDWire(mfaPersistenceID(5))
			value.NewSessionFamilyID = entityIDWire(mfaPersistenceID(6))
			value.SessionVersion = 1
			mutate(&value)
			parsed, parseErr := passkeyAuthenticationResultFromWire(value)
			if parseErr != nil || parsed.NewSessionID != mfaPersistenceID(5) ||
				parsed.NewSessionFamilyID != mfaPersistenceID(6) || parsed.SessionVersion != 1 {
				t.Fatalf("session result = %#v, %v", parsed, parseErr)
			}
		})
	}

	for name, mutate := range map[string]func(*passkeyAuthenticationResultWire){
		"non-committed outcome": func(value *passkeyAuthenticationResultWire) {
			value.Outcome = "stale"
		},
		"recovery-restricted result": func(value *passkeyAuthenticationResultWire) {
			value.RecoveryRestricted = true
		},
		"anchorless clone has positive version": func(value *passkeyAuthenticationResultWire) {
			value.SessionVersion = 1
		},
		"anchorless zero is not a clone": func(value *passkeyAuthenticationResultWire) {
			value.Credential.Status = "active"
		},
		"anchored clone has zero version": func(value *passkeyAuthenticationResultWire) {
			value.RevokedAnchorID = entityIDWire(mfaPersistenceID(4))
		},
		"revoke creates replacement session": func(value *passkeyAuthenticationResultWire) {
			value.NewSessionID = entityIDWire(mfaPersistenceID(5))
			value.SessionVersion = 2
		},
		"non-revoke has zero version": func(value *passkeyAuthenticationResultWire) {
			value.Mutation = "create"
		},
		"create omits successor identifiers": func(value *passkeyAuthenticationResultWire) {
			value.Credential.Status = "active"
			value.Mutation = "create"
			value.SessionVersion = 1
		},
		"authentication retains continuation": func(value *passkeyAuthenticationResultWire) {
			value.Credential.Status = "active"
			value.Mutation = "retain_continuation"
			value.ConsumedContinuationID = entityIDWire(mfaPersistenceID(7))
			value.SessionVersion = 1
		},
		"non-revoke exposes revoked anchor": func(value *passkeyAuthenticationResultWire) {
			value.Mutation = "create"
			value.RevokedAnchorID = entityIDWire(mfaPersistenceID(4))
			value.SessionVersion = 1
		},
		"clone status cannot create a session": func(value *passkeyAuthenticationResultWire) {
			value.Mutation = "create"
			value.NewSessionID = entityIDWire(mfaPersistenceID(5))
			value.NewSessionFamilyID = entityIDWire(mfaPersistenceID(6))
			value.SessionVersion = 1
		},
		"identity epoch exceeds JSON safe integer": func(value *passkeyAuthenticationResultWire) {
			value.IdentityEpoch = maximumMFAJSONSafeInteger + 1
		},
		"session version exceeds JSON safe integer": func(value *passkeyAuthenticationResultWire) {
			value.Mutation = "create"
			value.SessionVersion = maximumMFAJSONSafeInteger + 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			value := base
			mutate(&value)
			if _, err := passkeyAuthenticationResultFromWire(value); err == nil {
				t.Fatal("invalid passkey session result was accepted")
			}
		})
	}

	anchored := base
	anchored.RevokedAnchorID = entityIDWire(mfaPersistenceID(4))
	anchored.SessionVersion = maximumMFAJSONSafeInteger
	result, err = passkeyAuthenticationResultFromWire(anchored)
	if err != nil || result.RevokedAnchorID != mfaPersistenceID(4) ||
		result.SessionVersion != uint64(maximumMFAJSONSafeInteger) {
		t.Fatalf("anchored clone result = %#v, %v", result, err)
	}
}

func TestPasskeyRegistrationResultRequiresExactSessionShape(t *testing.T) {
	t.Parallel()

	base := passkeyRegistrationResultWire{
		Outcome: "committed",
		Credential: webauthnCredentialWire{
			ID: []byte("credential-id"), PublicKey: bytes.Repeat([]byte{0xa5}, 64),
			TenantID: entityIDWire(mfaPersistenceID(1)), UserID: entityIDWire(mfaPersistenceID(2)),
			IdentityEpoch: 3, UserHandleDigest: bytes.Repeat([]byte{0xb4}, 32),
			RPID: "app.example.test", RPRevision: 7, Version: 1, SecurityRevision: 1,
			Status: "active", Transports: []string{"internal"},
		},
		AuditID: entityIDWire(mfaPersistenceID(3)), Mutation: "rotate",
		NewSessionID:       entityIDWire(mfaPersistenceID(4)),
		NewSessionFamilyID: entityIDWire(mfaPersistenceID(5)), SessionVersion: 6,
	}
	result, err := passkeyRegistrationResultFromWire(base)
	if err != nil || result.Mutation != mfaauth.SessionRotate ||
		result.NewSessionID != mfaPersistenceID(4) || result.NewSessionFamilyID != mfaPersistenceID(5) ||
		result.SessionVersion != 6 {
		t.Fatalf("rotated registration result = %#v, %v", result, err)
	}

	retained := base
	retained.Mutation = "retain_continuation"
	retained.NewSessionID = ""
	retained.NewSessionFamilyID = ""
	retained.RetainedContinuationID = entityIDWire(mfaPersistenceID(6))
	retained.SessionVersion = maximumMFAJSONSafeInteger
	result, err = passkeyRegistrationResultFromWire(retained)
	if err != nil || result.Mutation != mfaauth.SessionRetainContinuation ||
		result.RetainedContinuationID != mfaPersistenceID(6) ||
		result.SessionVersion != uint64(maximumMFAJSONSafeInteger) {
		t.Fatalf("retained registration result = %#v, %v", result, err)
	}

	for name, mutate := range map[string]func(*passkeyRegistrationResultWire){
		"non-committed outcome": func(value *passkeyRegistrationResultWire) { value.Outcome = "denied" },
		"recovery-restricted result": func(value *passkeyRegistrationResultWire) {
			value.RecoveryRestricted = true
		},
		"non-active credential": func(value *passkeyRegistrationResultWire) {
			value.Credential.Status = "revoked"
		},
		"unsupported mutation": func(value *passkeyRegistrationResultWire) { value.Mutation = "create" },
		"rotate omits session": func(value *passkeyRegistrationResultWire) { value.NewSessionID = "" },
		"rotate exposes continuation": func(value *passkeyRegistrationResultWire) {
			value.RetainedContinuationID = entityIDWire(mfaPersistenceID(6))
		},
		"retention exposes session": func(value *passkeyRegistrationResultWire) {
			value.Mutation = "retain_continuation"
			value.RetainedContinuationID = entityIDWire(mfaPersistenceID(6))
		},
		"retention omits continuation": func(value *passkeyRegistrationResultWire) {
			value.Mutation = "retain_continuation"
			value.NewSessionID = ""
			value.NewSessionFamilyID = ""
		},
		"session version exceeds JSON safe integer": func(value *passkeyRegistrationResultWire) {
			value.SessionVersion = maximumMFAJSONSafeInteger + 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			value := base
			mutate(&value)
			if _, err := passkeyRegistrationResultFromWire(value); err == nil {
				t.Fatal("invalid registration session result was accepted")
			}
		})
	}
}

func TestWebAuthnExpectedSecurityRevisionStaysInternal(t *testing.T) {
	t.Parallel()

	policyID := mfaPersistenceID(9)
	completion := webauthn.AuthenticationCompletion{
		CeremonyID:              webauthn.CeremonyID{1},
		ExpectedCeremonyVersion: 2,
		Binding: webauthn.CeremonyBinding{
			Purpose: webauthn.PurposePrimaryAuthentication, TenantID: mfaPersistenceID(1),
			Action: "tenant.authentication.login", Audience: "tenant-console",
			Requirement: identity.EffectiveAssuranceRequirement{
				Level: identity.AssurancePrimary,
				PolicyRevisions: []identity.AssurancePolicyRevision{{
					PolicyID: policyID, Revision: 1,
				}},
			},
		},
		ResolvedUserID: mfaPersistenceID(2), ExpectedIdentityEpoch: 3,
		CredentialID: []byte("credential-id"), ExpectedCredentialVersion: 5,
		ExpectedSecurityRevision: 3, ExpectedSignCount: 4, ObservedSignCount: 5,
		CounterDisposition: webauthn.CounterAdvance,
	}
	wire, err := authenticationCompletionToWire(completion)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := marshalMFAWire(wire)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("expectedSecurityRevision")) ||
		bytes.Contains(raw, []byte("expectedBackupEligible")) {
		t.Fatalf("internal credential prestate leaked into strict request: %s", raw)
	}

	completion.ExpectedSecurityRevision = 0
	if _, err := authenticationCompletionToWire(completion); err == nil {
		t.Fatal("missing internal security revision was accepted")
	}
	completion.ExpectedSecurityRevision = 3
	completion.ExpectedCredentialVersion = uint64(maximumMFAJSONSafeInteger)
	if _, err := authenticationCompletionToWire(completion); err == nil {
		t.Fatal("record revision without completion headroom was accepted")
	}
}

func TestWebAuthnSharedIntentWireUsesJSONSafeRevisionBounds(t *testing.T) {
	t.Parallel()

	audit := mfaauth.AuditIntent{PolicyRevisions: []identity.AssurancePolicyRevision{{
		PolicyID: mfaPersistenceID(9), Revision: maximumMFAJSONSafeInteger,
	}}}
	if _, err := auditIntentToWire(audit); err != nil {
		t.Fatalf("last JSON-safe audit revision was rejected: %v", err)
	}
	audit.PolicyRevisions[0].Revision++
	if _, err := auditIntentToWire(audit); err == nil {
		t.Fatal("audit revision beyond the JSON-safe ceiling was accepted")
	}

	for name, intent := range map[string]mfaauth.SessionIntent{
		"primary create": {
			Mutation: mfaauth.SessionCreate, ExpectedIdentityEpoch: uint64(maximumMFAJSONSafeInteger),
		},
		"last mutable anchor": {
			Mutation: mfaauth.SessionRotate, ExpectedIdentityEpoch: 1,
			ExpectedAnchorVersion: uint64(maximumMFAJSONSafeInteger - 1),
		},
	} {
		if !validSessionIntentAnchorRevision(intent) || intent.ExpectedIdentityEpoch > uint64(maximumMFAJSONSafeInteger) {
			t.Fatalf("%s intent was rejected", name)
		}
	}
	for name, intent := range map[string]mfaauth.SessionIntent{
		"create with anchor": {
			Mutation: mfaauth.SessionCreate, ExpectedIdentityEpoch: 1, ExpectedAnchorVersion: 1,
		},
		"rotate without anchor": {
			Mutation: mfaauth.SessionRotate, ExpectedIdentityEpoch: 1,
		},
		"rotate without headroom": {
			Mutation: mfaauth.SessionRotate, ExpectedIdentityEpoch: 1,
			ExpectedAnchorVersion: uint64(maximumMFAJSONSafeInteger),
		},
	} {
		if validSessionIntentAnchorRevision(intent) {
			t.Fatalf("%s intent was accepted", name)
		}
	}
}
