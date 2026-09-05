package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

var oidcMaintenanceRepositoryNow = time.Date(2026, time.September, 4, 13, 0, 0, 0, time.UTC)

func TestOIDCMaintenanceRepositoryUsesExactRefreshAndRetryABIs(t *testing.T) {
	tenantID := sessionLogoutRepositoryID(t)
	providerID := sessionLogoutRepositoryID(t)
	bindingID := sessionLogoutRepositoryID(t)
	materialID := sessionLogoutRepositoryID(t)
	familyID := sessionLogoutRepositoryID(t)
	jobID := sessionLogoutRepositoryID(t)
	digest := sha256.Sum256([]byte("refresh-token"))
	successorDigest := sha256.Sum256([]byte("rotated-refresh-token"))
	leaseExpiresAt := oidcMaintenanceRepositoryNow.Add(time.Minute)
	materialExpiresAt := oidcMaintenanceRepositoryNow.Add(time.Hour)
	absoluteExpiresAt := oidcMaintenanceRepositoryNow.Add(2 * time.Hour)
	tokenCiphertext := bytes.Repeat([]byte{0x41}, minimumOIDCProtectedTokenBytes)
	successorCiphertext := bytes.Repeat([]byte{0x42}, maximumOIDCProtectedTokenBytes)
	tenantIDWire := entityIDWire(tenantID)
	bindingIDWire := entityIDWire(bindingID)

	queries := make([]string, 0, 5)
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		queries = append(queries, query)
		payload := oidcMaintenanceRepositoryPayload(t, arguments)
		switch query {
		case claimOIDCRefreshRotationSQL:
			assertSessionLogoutJSONKeys(t, payload,
				"sessionFamilyId", "expectedGeneration", "expectedDigest", "claimedAt",
			)
			var request oidcRefreshClaimRequestWire
			if err := json.Unmarshal(payload, &request); err != nil || request.SessionFamilyID != entityIDWire(familyID) ||
				request.ExpectedGeneration != 7 || !bytes.Equal(request.ExpectedDigest, digest[:]) ||
				!request.ClaimedAt.Equal(oidcMaintenanceRepositoryNow) {
				t.Fatalf("refresh claim request = %s, %v", payload, err)
			}
			return federatedAuthJSONRow(mustFederatedJSON(t, oidcRefreshClaimSnapshotWire{
				Category: federatedRefreshClaimedWire(), TenantID: &tenantIDWire,
				EffectiveTenantID: &tenantIDWire, ObservedAt: &oidcMaintenanceRepositoryNow,
				MaterialID: entityIDWire(materialID), SessionFamilyID: entityIDWire(familyID),
				Generation: 7, Version: 9, LeaseExpiresAt: &leaseExpiresAt,
				Provider: &federatedProviderBindingWire{
					Scope: federatedTenantProviderScopeWire, TenantID: tenantIDWire,
					ProviderID: entityIDWire(providerID), BindingID: bindingIDWire,
				},
				BindingID: &bindingIDWire, ClientSecretRevision: 3,
				Endpoint: "https://idp.example/token", ClientAuthentication: federatedoidc.ClientSecretPost,
				ClientID: "客户端", Token: &oidcMaintenanceProtectedTokenWire{KeyVersion: 2, Ciphertext: tokenCiphertext},
				TokenDigest: digest[:], MaterialExpiresAt: &materialExpiresAt,
				AbsoluteSessionExpiry: &absoluteExpiresAt,
			}))
		case completeOIDCRefreshRotationSQL:
			assertSessionLogoutJSONKeys(t, payload,
				"tenantId", "effectiveTenantId", "materialId", "sessionFamilyId", "expectedVersion", "expectedGeneration",
				"outcome", "successorGeneration", "successorDigest", "successorToken", "accessExpiresAt", "completedAt",
			)
			var request oidcRefreshCompletionWire
			if err := json.Unmarshal(payload, &request); err != nil || request.Outcome != federatedauth.RefreshRotated ||
				request.SuccessorGeneration == nil || *request.SuccessorGeneration != 8 ||
				request.SuccessorToken == nil || len(request.SuccessorToken.Ciphertext) != maximumOIDCProtectedTokenBytes ||
				!bytes.Equal(request.SuccessorDigest, successorDigest[:]) {
				t.Fatalf("refresh completion request = %s, %v", payload, err)
			}
			return oidcMaintenanceBooleanRow(true)
		case revokeOIDCSessionFamilySQL:
			assertSessionLogoutJSONKeys(t, payload, "sessionFamilyId", "reason", "revokedAt")
			return oidcMaintenanceBooleanRow(true)
		case claimOIDCLogoutRetrySQL:
			assertSessionLogoutJSONKeys(t, payload, "jobId", "observedAt")
			return federatedAuthJSONRow(mustFederatedJSON(t, oidcLogoutRetrySnapshotWire{
				JobID: entityIDWire(jobID), TenantID: &tenantIDWire, MaterialID: entityIDWire(materialID),
				SessionFamilyID: entityIDWire(familyID), Attempt: 2, MaximumAttempts: 5,
				ClaimVersion: 4, LeaseExpiresAt: leaseExpiresAt, NotBefore: oidcMaintenanceRepositoryNow,
				Provider: federatedProviderBindingWire{
					Scope: federatedPlatformProviderScopeWire, ProviderID: entityIDWire(providerID),
				},
				Admission:            &federatedTenantAdmissionWire{TenantID: tenantIDWire, BindingID: bindingIDWire},
				ClientSecretRevision: 3, ClientAuthentication: federatedoidc.ClientSecretBasic,
				ClientID: "客户端", Endpoint: "https://idp.example/revoke", RefreshGeneration: 7,
				TokenDigest: digest[:], MaterialExpiresAt: materialExpiresAt,
				OpaqueReference: oidcMaintenanceProtectedTokenWire{KeyVersion: 2, Ciphertext: tokenCiphertext},
			}))
		case completeOIDCLogoutRetrySQL:
			assertSessionLogoutJSONKeys(t, payload,
				"jobId", "attempt", "expectedVersion", "outcome", "completedAt", "nextTryAt",
			)
			return oidcMaintenanceBooleanRow(true)
		default:
			t.Fatalf("unexpected query %q", query)
			return federatedAuthJSONRow(nil)
		}
	}}}

	command := federatedauth.RefreshCommand{
		SessionFamilyID: familyID, ExpectedGeneration: 7, ExpectedDigest: digest,
	}
	snapshot, err := repository.ClaimRefreshRotation(context.Background(), command, oidcMaintenanceRepositoryNow)
	if err != nil || snapshot.Category != federatedauth.RefreshClaimed || snapshot.TenantID != tenantID ||
		snapshot.MaterialID != materialID || snapshot.Provider.Scope != identity.TenantProviderScope ||
		snapshot.BindingID != bindingID || snapshot.Admission.BindingID != bindingID || snapshot.ClientID != "客户端" ||
		!bytes.Equal(snapshot.Token.Ciphertext, tokenCiphertext) || snapshot.TokenDigest != digest {
		t.Fatalf("ClaimRefreshRotation() = %s, %v", snapshot, err)
	}
	completion := federatedauth.RefreshCompletion{
		TenantID: tenantID, EffectiveTenantID: tenantID,
		MaterialID: materialID, SessionFamilyID: familyID,
		ExpectedVersion: 9, ExpectedGeneration: 7, Outcome: federatedauth.RefreshRotated,
		SuccessorGeneration: 8, SuccessorDigest: successorDigest,
		SuccessorToken:  federatedauth.ProtectedToken{KeyVersion: 2, Ciphertext: successorCiphertext},
		AccessExpiresAt: oidcMaintenanceRepositoryNow.Add(30 * time.Minute), CompletedAt: oidcMaintenanceRepositoryNow,
	}
	if err := repository.CompleteRefreshRotation(context.Background(), completion); err != nil {
		t.Fatalf("CompleteRefreshRotation() error = %v", err)
	}
	if err := repository.RevokeSessionFamily(
		context.Background(), familyID, federatedauth.RevokeRefreshFailure, oidcMaintenanceRepositoryNow,
	); err != nil {
		t.Fatalf("RevokeSessionFamily() error = %v", err)
	}
	job, err := repository.ClaimLogoutRetry(context.Background(), jobID, oidcMaintenanceRepositoryNow)
	if err != nil || job.JobID != jobID || job.TenantID != tenantID || job.Provider.Scope != identity.PlatformProviderScope ||
		job.Admission.BindingID != bindingID || job.BindingID != bindingID || job.TokenDigest != digest ||
		!bytes.Equal(job.OpaqueReference.Ciphertext, tokenCiphertext) {
		t.Fatalf("ClaimLogoutRetry() = %s, %v", job, err)
	}
	if err := repository.CompleteLogoutRetry(context.Background(), federatedauth.LogoutRetryUpdate{
		JobID: jobID, Attempt: 2, ExpectedVersion: 4, ObservedAt: oidcMaintenanceRepositoryNow,
		NextTryAt: oidcMaintenanceRepositoryNow.Add(time.Minute), Disposition: federatedauth.LogoutRetryReschedule,
	}); err != nil {
		t.Fatalf("CompleteLogoutRetry() error = %v", err)
	}
	if want := []string{
		claimOIDCRefreshRotationSQL, completeOIDCRefreshRotationSQL, revokeOIDCSessionFamilySQL,
		claimOIDCLogoutRetrySQL, completeOIDCLogoutRetrySQL,
	}; !reflect.DeepEqual(queries, want) {
		t.Fatalf("queries = %#v, want %#v", queries, want)
	}
}

func TestOIDCRefreshRepositoryAcceptsExactPlatformShapesAndRejectsDrift(t *testing.T) {
	providerID := sessionLogoutRepositoryID(t)
	tenantID := sessionLogoutRepositoryID(t)
	bindingID := sessionLogoutRepositoryID(t)
	materialID := sessionLogoutRepositoryID(t)
	familyID := sessionLogoutRepositoryID(t)
	digest := sha256.Sum256([]byte("refresh-token"))
	lease := oidcMaintenanceRepositoryNow.Add(time.Minute)
	materialExpiry := oidcMaintenanceRepositoryNow.Add(time.Hour)
	absoluteExpiry := oidcMaintenanceRepositoryNow.Add(2 * time.Hour)

	base := oidcRefreshClaimSnapshotWire{
		Category: federatedRefreshClaimedWire(), ObservedAt: &oidcMaintenanceRepositoryNow,
		MaterialID:      entityIDWire(materialID),
		SessionFamilyID: entityIDWire(familyID), Generation: 1, Version: 2, LeaseExpiresAt: &lease,
		Provider: &federatedProviderBindingWire{
			Scope: federatedPlatformProviderScopeWire, ProviderID: entityIDWire(providerID),
		},
		ClientSecretRevision: 1, Endpoint: "https://idp.example/token",
		ClientAuthentication: federatedoidc.ClientSecretBasic, ClientID: "客户端",
		Token: &oidcMaintenanceProtectedTokenWire{
			KeyVersion: 1, Ciphertext: bytes.Repeat([]byte{1}, minimumOIDCProtectedTokenBytes),
		},
		TokenDigest: digest[:], MaterialExpiresAt: &materialExpiry, AbsoluteSessionExpiry: &absoluteExpiry,
	}
	command := federatedauth.RefreshCommand{SessionFamilyID: familyID, ExpectedGeneration: 1, ExpectedDigest: digest}

	t.Run("direct platform", func(t *testing.T) {
		got, err := oidcRefreshSnapshotFromWire(base, command, oidcMaintenanceRepositoryNow)
		if err != nil || got.TenantID != (identity.EntityID{}) || got.BindingID != (identity.EntityID{}) ||
			got.Admission != (identity.TenantAdmissionContext{}) {
			t.Fatalf("snapshot = %s, %v", got, err)
		}
	})

	t.Run("tenant admitted platform", func(t *testing.T) {
		candidate := base
		tenantWire, bindingWire := entityIDWire(tenantID), entityIDWire(bindingID)
		candidate.TenantID = &tenantWire
		candidate.EffectiveTenantID = &tenantWire
		candidate.BindingID = &bindingWire
		candidate.Admission = &federatedTenantAdmissionWire{TenantID: tenantWire, BindingID: bindingWire}
		got, err := oidcRefreshSnapshotFromWire(candidate, command, oidcMaintenanceRepositoryNow)
		if err != nil || got.TenantID != tenantID || got.BindingID != bindingID || got.Admission.BindingID != bindingID {
			t.Fatalf("snapshot = %s, %v", got, err)
		}
	})

	t.Run("switched direct platform keeps origin separate", func(t *testing.T) {
		candidate := base
		effectiveWire := entityIDWire(tenantID)
		candidate.EffectiveTenantID = &effectiveWire
		got, err := oidcRefreshSnapshotFromWire(candidate, command, oidcMaintenanceRepositoryNow)
		if err != nil || got.TenantID != (identity.EntityID{}) || got.EffectiveTenantID != tenantID ||
			got.BindingID != (identity.EntityID{}) || got.Admission != (identity.TenantAdmissionContext{}) {
			t.Fatalf("switched direct snapshot = %s, %v", got, err)
		}
	})

	t.Run("direct platform rejects binding", func(t *testing.T) {
		candidate := base
		bindingWire := entityIDWire(bindingID)
		candidate.BindingID = &bindingWire
		if _, err := oidcRefreshSnapshotFromWire(candidate, command, oidcMaintenanceRepositoryNow); err == nil {
			t.Fatal("platform binding drift accepted")
		}
	})

	t.Run("utf8 client id byte bound", func(t *testing.T) {
		candidate := base
		candidate.ClientID = strings.Repeat("界", 171) // 513 UTF-8 bytes.
		if _, err := oidcRefreshSnapshotFromWire(candidate, command, oidcMaintenanceRepositoryNow); err == nil {
			t.Fatal("513-byte client id accepted")
		}
		candidate.ClientID = strings.Repeat("界", 170)
		if _, err := oidcRefreshSnapshotFromWire(candidate, command, oidcMaintenanceRepositoryNow); err != nil {
			t.Fatalf("510-byte multibyte client id rejected: %v", err)
		}
	})

	t.Run("ciphertext exact upper bound", func(t *testing.T) {
		candidate := base
		candidate.Token = &oidcMaintenanceProtectedTokenWire{
			KeyVersion: 1, Ciphertext: make([]byte, maximumOIDCProtectedTokenBytes+1),
		}
		if _, err := oidcRefreshSnapshotFromWire(candidate, command, oidcMaintenanceRepositoryNow); err == nil {
			t.Fatal("oversized protected token accepted")
		}
		candidate.Token.Ciphertext = make([]byte, maximumOIDCProtectedTokenBytes)
		if _, err := oidcRefreshSnapshotFromWire(candidate, command, oidcMaintenanceRepositoryNow); err != nil {
			t.Fatalf("exact protected token maximum rejected: %v", err)
		}
	})

	t.Run("lease boundary", func(t *testing.T) {
		candidate := base
		exactNow := oidcMaintenanceRepositoryNow
		candidate.LeaseExpiresAt = &exactNow
		if _, err := oidcRefreshSnapshotFromWire(candidate, command, oidcMaintenanceRepositoryNow); err == nil {
			t.Fatal("expired lease accepted")
		}
	})

	t.Run("semantic categories reject smuggled material", func(t *testing.T) {
		stale := oidcRefreshClaimSnapshotWire{Category: string(federatedauth.RefreshStale), SessionFamilyID: entityIDWire(familyID)}
		if got, err := oidcRefreshSnapshotFromWire(stale, command, oidcMaintenanceRepositoryNow); err != nil ||
			got.Category != federatedauth.RefreshStale {
			t.Fatalf("stale = %s, %v", got, err)
		}
		stale.TokenDigest = digest[:]
		if _, err := oidcRefreshSnapshotFromWire(stale, command, oidcMaintenanceRepositoryNow); err == nil {
			t.Fatal("stale snapshot with material accepted")
		}
		busy := oidcRefreshClaimSnapshotWire{Category: string(federatedauth.RefreshBusy), SessionFamilyID: entityIDWire(familyID)}
		if got, err := oidcRefreshSnapshotFromWire(busy, command, oidcMaintenanceRepositoryNow); err != nil ||
			got.Category != federatedauth.RefreshBusy {
			t.Fatalf("busy = %s, %v", got, err)
		}
		busy.TokenDigest = digest[:]
		if _, err := oidcRefreshSnapshotFromWire(busy, command, oidcMaintenanceRepositoryNow); err == nil {
			t.Fatal("busy snapshot with material accepted")
		}
	})
}

func TestOIDCMaintenanceRepositoryFailsClosedOnUnknownFieldsAndConflicts(t *testing.T) {
	familyID := sessionLogoutRepositoryID(t)
	digest := sha256.Sum256([]byte("refresh-token"))
	t.Run("unknown claim field", func(t *testing.T) {
		repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
			context.Context, string, ...any,
		) pgx.Row {
			return federatedAuthJSONRow([]byte(fmt.Sprintf(
				`{"category":"stale","sessionFamilyId":%q,"unexpected":true}`,
				entityIDWire(familyID),
			)))
		}}}
		if _, err := repository.ClaimRefreshRotation(context.Background(), federatedauth.RefreshCommand{
			SessionFamilyID: familyID, ExpectedGeneration: 1, ExpectedDigest: digest,
		}, oidcMaintenanceRepositoryNow); err == nil {
			t.Fatal("unknown claim field accepted")
		}
	})

	t.Run("completion conflict", func(t *testing.T) {
		repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
			context.Context, string, ...any,
		) pgx.Row {
			return oidcMaintenanceBooleanRow(false)
		}}}
		if err := repository.RevokeSessionFamily(
			context.Background(), familyID, federatedauth.RevokeSessionDrift, oidcMaintenanceRepositoryNow,
		); err == nil {
			t.Fatal("false compare-and-set accepted")
		}
	})
}

func TestOIDCMaintenanceSensitiveFormatsAreAlwaysRedacted(t *testing.T) {
	canaries := []string{"refresh-token-canary", "https://idp.example/revoke?token=canary"}
	values := []any{
		oidcMaintenanceProtectedTokenWire{KeyVersion: 1, Ciphertext: []byte(canaries[0])},
		oidcRefreshClaimSnapshotWire{
			Category: "claimed", Endpoint: canaries[1],
			Token: &oidcMaintenanceProtectedTokenWire{KeyVersion: 1, Ciphertext: []byte(canaries[0])},
		},
		oidcLogoutRetrySnapshotWire{
			Endpoint: canaries[1], OpaqueReference: oidcMaintenanceProtectedTokenWire{Ciphertext: []byte(canaries[0])},
		},
	}
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			formatted := fmt.Sprintf(format, value)
			for _, canary := range canaries {
				if strings.Contains(formatted, canary) {
					t.Fatalf("format %q of %T leaked %q: %s", format, value, canary, formatted)
				}
			}
		}
	}
}

func federatedRefreshClaimedWire() string { return string(federatedauth.RefreshClaimed) }

func oidcMaintenanceRepositoryPayload(t *testing.T, arguments []any) []byte {
	t.Helper()
	if len(arguments) != 1 {
		t.Fatalf("argument count = %d", len(arguments))
	}
	payload, ok := arguments[0].([]byte)
	if !ok || len(payload) == 0 || len(payload) > maximumOIDCMaintenanceWireBytes {
		t.Fatalf("payload = %T/%d", arguments[0], len(payload))
	}
	return append([]byte(nil), payload...)
}

func oidcMaintenanceBooleanRow(value bool) pgx.Row {
	return federatedAuthRowFunc(func(destinations ...any) error {
		if len(destinations) != 1 {
			return fmt.Errorf("destination count = %d", len(destinations))
		}
		destination, ok := destinations[0].(*bool)
		if !ok {
			return fmt.Errorf("destination = %T", destinations[0])
		}
		*destination = value
		return nil
	})
}
