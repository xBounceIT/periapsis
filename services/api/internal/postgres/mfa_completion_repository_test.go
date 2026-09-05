package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/mfaauth"
)

func TestMFACompletionWireAcceptsLDAPOnlyAsResultAuthenticationMethod(t *testing.T) {
	t.Parallel()

	ldap := string(mfa.SessionAuthenticationLDAP)
	result, err := completionResultMethodFromWire(&ldap)
	if err != nil || result != ldap {
		t.Fatalf("completionResultMethodFromWire(ldap) = %q, %v", result, err)
	}
	if _, err := completionReservationMethodFromWire(&ldap); !errors.Is(err, errInvalidMFAWire) {
		t.Fatalf("completionReservationMethodFromWire(ldap) error = %v, want %v", err, errInvalidMFAWire)
	}
}

func TestMFACompletionResolverUsesStrictProtectedWireAndPreservesSourceTuple(t *testing.T) {
	t.Parallel()

	lookup, response := mfaCompletionRepositoryFixture()
	var retainedPayload []byte
	repository := &MFAPlanRepository{queryer: mfaQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if query != resolveMFACompletionArtifactSQL || len(arguments) != 1 {
			t.Fatalf("query = %q, arguments = %d", query, len(arguments))
		}
		payload, ok := arguments[0].([]byte)
		if !ok {
			t.Fatalf("payload type = %T", arguments[0])
		}
		retainedPayload = payload
		var request mfaCompletionLookupWire
		if err := unmarshalMFAWire(payload, &request); err != nil {
			t.Fatal(err)
		}
		factorID := mfaPersistenceID(11)
		if request.ArtifactKind != "step_up_challenge" || request.SelectedFactorKind != "totp" ||
			request.SelectedFactorID != entityIDWire(factorID) || request.ContinuationReceiptDigest != "" ||
			request.ArtifactID != base64.StdEncoding.EncodeToString(lookup.ArtifactID) ||
			request.BrowserDigest != base64.StdEncoding.EncodeToString(lookup.BrowserDigest[:]) ||
			!request.RequestedAt.Equal(lookup.RequestedAt) {
			t.Fatalf("request = %#v", request)
		}
		raw, err := marshalMFAWire(response)
		if err != nil {
			t.Fatal(err)
		}
		return mfaRowFunc(func(destinations ...any) error {
			*destinations[0].(*[]byte) = raw
			return nil
		})
	}}}

	result, err := repository.ResolveMFACompletion(context.Background(), lookup)
	if err != nil {
		t.Fatal(err)
	}
	if result.ArtifactKind != lookup.ArtifactKind || !bytes.Equal(result.ArtifactID, lookup.ArtifactID) ||
		result.BrowserDigest != lookup.BrowserDigest || result.FactorKind != lookup.FactorKind ||
		!bytes.Equal(result.FactorID, lookup.FactorID) || result.Flow != mfaauth.CompletionFlowSession ||
		result.ResultAuthenticationMethod != string(mfa.SessionAuthenticationOIDC) ||
		result.ReservationAuthenticationMethod != mfa.SessionAuthenticationTOTP ||
		result.SourceSessionID != mfaPersistenceID(12) || result.SourceSessionFamilyID != mfaPersistenceID(13) ||
		result.SourceSessionVersion != 4 || !result.SourceAbsoluteExpiresAt.Equal(*response.SourceAbsoluteExpiresAt) ||
		result.LoadedAt.Location() != time.UTC || result.LoadedAt.Nanosecond()%int(time.Millisecond) == 0 ||
		result.AnchorExpiresAt.Location() != time.UTC || result.AnchorExpiresAt.Nanosecond()%int(time.Millisecond) != 0 {
		t.Fatalf("result = %#v", result)
	}
	if len(retainedPayload) == 0 || !allMFABytesCleared(retainedPayload) {
		t.Fatal("completion resolver retained an uncleared lookup payload")
	}
}

func TestMFACompletionLookupFactorIDBranchMatrix(t *testing.T) {
	t.Parallel()

	uuidFactor := mfaPersistenceID(21)
	credential := []byte("credential-id")
	tests := []struct {
		name       string
		artifact   mfaauth.CompletionArtifactKind
		artifactID []byte
		factor     mfaauth.CompletionFactorKind
		factorID   []byte
		wantID     string
	}{
		{
			name: "TOTP enrollment DB resolved", artifact: mfaauth.CompletionArtifactTOTPEnrollment,
			artifactID: mfaCompletionEntityBytes(mfaPersistenceID(20)), factor: mfaauth.CompletionFactorTOTP,
		},
		{
			name: "recovery set DB resolved", artifact: mfaauth.CompletionArtifactStepUp,
			artifactID: bytes.Repeat([]byte{0x22}, sha256.Size), factor: mfaauth.CompletionFactorRecovery,
		},
		{
			name: "TOTP selector exact", artifact: mfaauth.CompletionArtifactStepUp,
			artifactID: bytes.Repeat([]byte{0x23}, sha256.Size), factor: mfaauth.CompletionFactorTOTP,
			factorID: uuidFactor[:], wantID: entityIDWire(uuidFactor),
		},
		{
			name: "WebAuthn registration credential exact", artifact: mfaauth.CompletionArtifactWebAuthnRegistration,
			artifactID: bytes.Repeat([]byte{0x24}, sha256.Size), factor: mfaauth.CompletionFactorPasskey,
			factorID: credential, wantID: base64.StdEncoding.EncodeToString(credential),
		},
		{
			name: "WebAuthn authentication credential exact", artifact: mfaauth.CompletionArtifactWebAuthnAuthentication,
			artifactID: bytes.Repeat([]byte{0x25}, sha256.Size), factor: mfaauth.CompletionFactorPasskey,
			factorID: credential, wantID: base64.StdEncoding.EncodeToString(credential),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lookup := mfaauth.CompletionTicketLookup{
				ArtifactKind: test.artifact, ArtifactID: append([]byte(nil), test.artifactID...),
				BrowserDigest: sha256.Sum256([]byte(test.name)), FactorKind: test.factor,
				FactorID: append([]byte(nil), test.factorID...), RequestedAt: mfaPersistenceTestNow,
			}
			wire, err := mfaCompletionLookupToWire(lookup)
			if err != nil {
				t.Fatal(err)
			}
			if wire.SelectedFactorID != test.wantID {
				t.Fatalf("selectedFactorId = %q", wire.SelectedFactorID)
			}
			payload, err := marshalMFAWire(wire)
			if err != nil {
				t.Fatal(err)
			}
			if test.wantID == "" && bytes.Contains(payload, []byte(`"selectedFactorId"`)) {
				t.Fatalf("DB-resolved factor ID was sent by browser: %s", payload)
			}
		})
	}
}

func TestMFACompletionResolutionSupportsDiscoverablePrimaryAndAllArtifactIDs(t *testing.T) {
	t.Parallel()

	_, base := mfaCompletionRepositoryFixture()
	credential := []byte("credential-id")
	tests := []struct {
		name       string
		artifact   mfaauth.CompletionArtifactKind
		artifactID string
		factor     mfaauth.CompletionFactorKind
		factorID   string
	}{
		{
			name: "TOTP enrollment", artifact: mfaauth.CompletionArtifactTOTPEnrollment,
			artifactID: entityIDWire(mfaPersistenceID(31)), factor: mfaauth.CompletionFactorTOTP,
			factorID: entityIDWire(mfaPersistenceID(32)),
		},
		{
			name: "TOTP step-up", artifact: mfaauth.CompletionArtifactStepUp,
			artifactID: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, sha256.Size)),
			factor:     mfaauth.CompletionFactorTOTP, factorID: entityIDWire(mfaPersistenceID(33)),
		},
		{
			name: "recovery step-up", artifact: mfaauth.CompletionArtifactStepUp,
			artifactID: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x32}, sha256.Size)),
			factor:     mfaauth.CompletionFactorRecovery, factorID: entityIDWire(mfaPersistenceID(34)),
		},
		{
			name: "WebAuthn registration", artifact: mfaauth.CompletionArtifactWebAuthnRegistration,
			artifactID: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, sha256.Size)),
			factor:     mfaauth.CompletionFactorPasskey, factorID: base64.StdEncoding.EncodeToString(credential),
		},
		{
			name: "WebAuthn authentication", artifact: mfaauth.CompletionArtifactWebAuthnAuthentication,
			artifactID: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x34}, sha256.Size)),
			factor:     mfaauth.CompletionFactorPasskey, factorID: base64.StdEncoding.EncodeToString(credential),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := base
			wire.ArtifactKind, wire.ArtifactID = string(test.artifact), test.artifactID
			wire.FactorKind, wire.FactorID = string(test.factor), test.factorID
			result, err := mfaCompletionResolutionFromWire(wire)
			if err != nil || result.ArtifactKind != test.artifact || result.FactorKind != test.factor ||
				len(result.ArtifactID) == 0 || len(result.FactorID) == 0 {
				t.Fatalf("result = %#v, error = %v", result, err)
			}
		})
	}

	primary := base
	primary.ArtifactKind = string(mfaauth.CompletionArtifactWebAuthnAuthentication)
	primary.ArtifactID = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, sha256.Size))
	primary.FactorKind = string(mfaauth.CompletionFactorPasskey)
	primary.FactorID = base64.StdEncoding.EncodeToString(credential)
	primary.Flow = string(mfaauth.CompletionFlowPrimary)
	primary.UserID, primary.IdentityEpoch = nil, 0
	primary.SessionID, primary.SessionFamilyID, primary.ContinuationID = nil, nil, nil
	primary.AnchorVersion, primary.AnchorExpiresAt = 0, nil
	primary.ReservationDisposition = string(mfaauth.CompletionReservationCreate)
	primary.ReservationAuthenticationMethod = testStringPointer(string(mfa.SessionAuthenticationPasskey))
	primary.ResultAuthenticationMethod = testStringPointer(string(mfa.SessionAuthenticationPasskey))
	primary.SourceSessionID, primary.SourceSessionFamilyID, primary.SourceSessionVersion = nil, nil, nil
	primary.SourceAbsoluteExpiresAt = nil
	raw, err := marshalMFAWire(primary)
	if err != nil {
		t.Fatal(err)
	}
	var decodedPrimary mfaCompletionResolutionWire
	if err := unmarshalMFACompletionResolution(raw, &decodedPrimary); err != nil {
		t.Fatalf("present nullable primary keys were rejected: %v", err)
	}
	result, err := mfaCompletionResolutionFromWire(decodedPrimary)
	if err != nil || result.UserID != (identity.EntityID{}) || result.IdentityEpoch != 0 ||
		result.ResolvedUserID == (identity.EntityID{}) || result.ResolvedIdentityEpoch == 0 {
		t.Fatalf("discoverable result = %#v, error = %v", result, err)
	}
}

func TestMFACompletionResolutionRejectsUnknownMissingNullAndNonCanonicalWire(t *testing.T) {
	t.Parallel()

	lookup, base := mfaCompletionRepositoryFixture()
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "unknown key", mutate: func(value map[string]any) { value["secret"] = "canary" }},
		{name: "missing factor", mutate: func(value map[string]any) { delete(value, "factorId") }},
		{name: "null required", mutate: func(value map[string]any) { value["tenantId"] = nil }},
		{name: "unpadded Base64", mutate: func(value map[string]any) {
			value["browserDigest"] = strings.TrimRight(value["browserDigest"].(string), "=")
		}},
		{name: "noncanonical UUID", mutate: func(value map[string]any) {
			value["factorId"] = strings.ToUpper(value["factorId"].(string))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := mfaCompletionResolutionJSON(t, base, test.mutate)
			repository := &MFAPlanRepository{queryer: staticMFAJSONQueryer(raw)}
			if _, err := repository.ResolveMFACompletion(context.Background(), lookup); !errors.Is(err, errMFAPersistence) {
				t.Fatalf("ResolveMFACompletion() error = %v", err)
			}
		})
	}
}

func TestMFACompletionResolutionRequiresEveryNullableKeyAndRejectsDuplicates(t *testing.T) {
	t.Parallel()

	lookup, base := mfaCompletionRepositoryFixture()
	nullableKeys := []string{
		"userId", "sessionId", "sessionFamilyId", "continuationId", "anchorExpiresAt",
		"reservationAuthenticationMethod", "resultAuthenticationMethod", "sourceSessionId",
		"sourceSessionFamilyId", "sourceSessionVersion", "sourceAbsoluteExpiresAt",
		"continuationReceiptDigest",
	}
	for _, key := range nullableKeys {
		t.Run("missing "+key, func(t *testing.T) {
			raw := mfaCompletionResolutionJSON(t, base, func(value map[string]any) { delete(value, key) })
			repository := &MFAPlanRepository{queryer: staticMFAJSONQueryer(raw)}
			if _, err := repository.ResolveMFACompletion(context.Background(), lookup); !errors.Is(err, errMFAPersistence) {
				t.Fatalf("ResolveMFACompletion() error = %v", err)
			}
		})
	}

	raw := mfaCompletionResolutionJSON(t, base, func(map[string]any) {})
	duplicate := append([]byte(nil), raw[:len(raw)-1]...)
	duplicate = append(duplicate, []byte(`,"userId":null}`)...)
	repository := &MFAPlanRepository{queryer: staticMFAJSONQueryer(duplicate)}
	if _, err := repository.ResolveMFACompletion(context.Background(), lookup); !errors.Is(err, errMFAPersistence) {
		t.Fatalf("duplicate-key ResolveMFACompletion() error = %v", err)
	}
}

func TestMFACompletionResolutionEnforcesJSONHeadroomAndNormalizesUTCPrecision(t *testing.T) {
	t.Parallel()

	_, base := mfaCompletionRepositoryFixture()
	base.IdentityEpoch = maximumMFAJSONSafeInteger
	base.ResolvedIdentityEpoch = maximumMFAJSONSafeInteger
	base.AnchorVersion = maximumMFAJSONSafeInteger - 1
	sourceVersion := maximumMFAJSONSafeInteger - 1
	base.SourceSessionVersion = &sourceVersion
	result, err := mfaCompletionResolutionFromWire(base)
	if err != nil || result.IdentityEpoch != uint64(maximumMFAJSONSafeInteger) ||
		result.AnchorVersion != uint64(maximumMFAJSONSafeInteger-1) ||
		result.SourceSessionVersion != uint64(maximumMFAJSONSafeInteger-1) ||
		result.LoadedAt.Location() != time.UTC || result.LoadedAt.Nanosecond()%int(time.Microsecond) != 0 ||
		result.AnchorExpiresAt.Nanosecond()%int(time.Millisecond) != 0 ||
		result.SourceAbsoluteExpiresAt.Nanosecond()%int(time.Millisecond) != 0 {
		t.Fatalf("maximum result = %#v, error = %v", result, err)
	}

	for name, mutate := range map[string]func(*mfaCompletionResolutionWire){
		"anchor without successor headroom": func(value *mfaCompletionResolutionWire) {
			value.AnchorVersion = maximumMFAJSONSafeInteger
		},
		"source without successor headroom": func(value *mfaCompletionResolutionWire) {
			version := maximumMFAJSONSafeInteger
			value.SourceSessionVersion = &version
		},
		"identity above JSON safe": func(value *mfaCompletionResolutionWire) {
			value.IdentityEpoch = maximumMFAJSONSafeInteger + 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if _, err := mfaCompletionResolutionFromWire(candidate); !errors.Is(err, errInvalidMFAWire) {
				t.Fatalf("conversion error = %v", err)
			}
		})
	}
}

func mfaCompletionRepositoryFixture() (mfaauth.CompletionTicketLookup, mfaCompletionResolutionWire) {
	artifactID := bytes.Repeat([]byte{0x51}, sha256.Size)
	browserDigest := sha256.Sum256([]byte("browser"))
	factorID := mfaPersistenceID(11)
	loadedAt := mfaPersistenceTestNow.Add(123 * time.Microsecond)
	anchorExpiresAt := loadedAt.Add(time.Hour).Truncate(time.Millisecond)
	sourceAbsoluteExpiresAt := loadedAt.Add(24 * time.Hour).Truncate(time.Millisecond)
	sourceVersion := int64(4)
	return mfaauth.CompletionTicketLookup{
			ArtifactKind: mfaauth.CompletionArtifactStepUp, ArtifactID: artifactID,
			BrowserDigest: browserDigest, FactorKind: mfaauth.CompletionFactorTOTP,
			FactorID: factorID[:], RequestedAt: mfaPersistenceTestNow,
		}, mfaCompletionResolutionWire{
			LoadedAt: loadedAt, ArtifactKind: string(mfaauth.CompletionArtifactStepUp),
			ArtifactID:    base64.StdEncoding.EncodeToString(artifactID),
			BrowserDigest: base64.StdEncoding.EncodeToString(browserDigest[:]),
			FactorKind:    string(mfaauth.CompletionFactorTOTP), FactorID: entityIDWire(factorID),
			Flow: string(mfaauth.CompletionFlowSession), TenantID: entityIDWire(mfaPersistenceID(1)),
			UserID: testStringPointer(entityIDWire(mfaPersistenceID(2))), IdentityEpoch: 7,
			ResolvedUserID: entityIDWire(mfaPersistenceID(2)), ResolvedIdentityEpoch: 7,
			SessionID:       testStringPointer(entityIDWire(mfaPersistenceID(12))),
			SessionFamilyID: testStringPointer(entityIDWire(mfaPersistenceID(13))),
			AnchorVersion:   4, AnchorExpiresAt: &anchorExpiresAt, Action: "case.export", Audience: "tenant-console",
			ReservationDisposition:          string(mfaauth.CompletionReservationRotate),
			ReservationAuthenticationMethod: testStringPointer(string(mfa.SessionAuthenticationTOTP)),
			ResultAuthenticationMethod:      testStringPointer(string(mfa.SessionAuthenticationOIDC)),
			SourceSessionID:                 testStringPointer(entityIDWire(mfaPersistenceID(12))),
			SourceSessionFamilyID:           testStringPointer(entityIDWire(mfaPersistenceID(13))),
			SourceSessionVersion:            &sourceVersion, SourceAbsoluteExpiresAt: &sourceAbsoluteExpiresAt,
		}
}

func mfaCompletionResolutionJSON(
	t *testing.T,
	value mfaCompletionResolutionWire,
	mutate func(map[string]any),
) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	mutate(object)
	raw, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testStringPointer(value string) *string { return &value }

func mfaCompletionEntityBytes(value identity.EntityID) []byte {
	return append([]byte(nil), value[:]...)
}
