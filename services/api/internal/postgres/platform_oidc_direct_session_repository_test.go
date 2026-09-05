package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

func TestDirectPlatformSessionAuthorityUsesExactRawPostgresSnapshotAndCAS(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 15, 0, 0, 0, time.UTC)
	fixture := platformOIDCDirectSessionRevalidationFixture(t, now)
	queries := make([]string, 0, 2)
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		queries = append(queries, query)
		if len(arguments) != 1 {
			t.Fatalf("arguments = %d", len(arguments))
		}
		payload, ok := arguments[0].([]byte)
		if !ok {
			t.Fatalf("payload = %T", arguments[0])
		}
		switch query {
		case loadPlatformOIDCDirectSessionRevalidationSQL:
			var lookup platformOIDCDirectSessionLookupWire
			if err := json.Unmarshal(payload, &lookup); err != nil || lookup.SessionID != fixture.Session.ID ||
				!lookup.ObservedAt.Equal(now) {
				t.Fatalf("load payload = %s, %v", payload, err)
			}
			return platformOIDCDirectJSONRow(t, fixture)
		case applyPlatformOIDCDirectSessionRevalidationSQL:
			var command platformOIDCDirectSessionMutationWire
			if err := json.Unmarshal(payload, &command); err != nil || command.SessionID != fixture.Session.ID ||
				command.ExpectedVersion != fixture.Session.CurrentVersion || command.Decision != "usable" ||
				command.Reason != "current" || len(command.RequestDigest) != 32 || !command.ObservedAt.Equal(now) {
				t.Fatalf("apply payload = %s, %v", payload, err)
			}
			return platformOIDCDirectJSONRow(t, platformOIDCDirectSessionMutationResultWire{
				Applied: platformOIDCDirectBool(true), SessionID: fixture.Session.ID,
				UserID: fixture.Session.UserID, ExpectedVersion: command.ExpectedVersion,
				NewVersion: command.ExpectedVersion + 1, Decision: command.Decision,
			})
		default:
			t.Fatalf("query = %q", query)
			return nil
		}
	}}}
	service, err := platformoidcauth.NewDirectPlatformSessionAuthority(
		platformoidcauth.DirectPlatformSessionAuthorityOptions{
			Store: repository, OperationTimeout: time.Second, Now: func() time.Time { return now },
		},
	)
	if err != nil {
		t.Fatalf("NewDirectPlatformSessionAuthority() error = %v", err)
	}
	result, err := service.RevalidateDirectPlatformSession(context.Background(), platformoidcauth.DirectSessionAuthorityLookup{
		SessionID: uuid.MustParse(fixture.Session.ID), UserID: uuid.MustParse(fixture.Session.UserID),
		AuthenticationMethod: "oidc", Audience: "api",
	})
	if err != nil || !result.AllowAuthority || !result.AllowIdleTouch ||
		result.SessionID != uuid.MustParse(fixture.Session.ID) || result.UserID != uuid.MustParse(fixture.Session.UserID) {
		t.Fatalf("RevalidateDirectPlatformSession() = %s, %v", result, err)
	}
	if len(queries) != 2 || queries[0] != loadPlatformOIDCDirectSessionRevalidationSQL ||
		queries[1] != applyPlatformOIDCDirectSessionRevalidationSQL {
		t.Fatalf("queries = %#v", queries)
	}
}

func TestDirectPlatformSessionSnapshotRejectsMissingRequiredRawFacts(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 15, 0, 0, 0, time.UTC)
	base := platformOIDCDirectSessionRevalidationFixture(t, now)
	tests := map[string]func(*platformOIDCDirectSessionSnapshotWire){
		"active tenant presence": func(value *platformOIDCDirectSessionSnapshotWire) {
			value.Session.ActiveTenantID = nil
		},
		"recovery restriction presence": func(value *platformOIDCDirectSessionSnapshotWire) {
			value.Session.RecoveryRestricted = nil
		},
		"runtime policy presence": func(value *platformOIDCDirectSessionSnapshotWire) {
			value.Authority.RuntimePolicyEnabled = nil
		},
		"floor local requirement presence": func(value *platformOIDCDirectSessionSnapshotWire) {
			value.Authority.PlatformFloor.LocalRequired = nil
		},
		"nullable trust presence": func(value *platformOIDCDirectSessionSnapshotWire) {
			value.Evidence[0].TrustRuleID = nil
		},
		"all policy pins": func(value *platformOIDCDirectSessionSnapshotWire) {
			value.PolicyPins = value.PolicyPins[:2]
		},
		"exact session echo": func(value *platformOIDCDirectSessionSnapshotWire) {
			value.Session.ID = uuid.Must(uuid.NewV7()).String()
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := clonePlatformOIDCDirectSessionRevalidationFixture(base)
			mutate(&candidate)
			lookup := platformoidcauth.DirectSessionRevalidationLookup{
				SessionID: uuid.MustParse(base.Session.ID), ObservedAt: now,
			}
			if snapshot, err := platformOIDCDirectSessionSnapshotFromWire(candidate, lookup); err == nil ||
				snapshot.Session.SessionID != uuid.Nil {
				t.Fatalf("platformOIDCDirectSessionSnapshotFromWire() = %s, %v", snapshot, err)
			}
		})
	}
}

func TestDirectPlatformSessionRepositoryRejectsInvalidCommandsBeforeQuery(t *testing.T) {
	t.Parallel()
	called := false
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		context.Context,
		string,
		...any,
	) pgx.Row {
		called = true
		return nil
	}}}
	now := time.Date(2026, 8, 30, 15, 0, 0, 0, time.UTC)
	if snapshot, err := repository.LoadDirectPlatformSessionForRevalidation(
		context.Background(),
		platformoidcauth.DirectSessionRevalidationLookup{SessionID: uuid.Nil, ObservedAt: now},
	); err == nil || snapshot.Session.SessionID != uuid.Nil || called {
		t.Fatalf("invalid LoadDirectPlatformSessionForRevalidation() = %s, %v, called=%t", snapshot, err, called)
	}
	mutation := platformoidcauth.DirectSessionRevalidationMutation{
		SessionID: uuid.Must(uuid.NewV7()), ExpectedVersion: 1,
		Decision: platformoidcauth.DirectSessionRevalidationUsable,
		Reason:   platformoidcauth.DirectSessionReasonCurrent, ObservedAt: now,
	}
	mutation.RequestDigest = platformOIDCDirectSessionMutationDigest(mutation)
	mutation.RequestDigest[0] ^= 0xff
	if result, err := repository.ApplyDirectPlatformSessionRevalidation(
		context.Background(), mutation,
	); err == nil || result.Applied || called {
		t.Fatalf("invalid ApplyDirectPlatformSessionRevalidation() = %#v, %v, called=%t", result, err, called)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if snapshot, err := repository.LoadDirectPlatformSessionForRevalidation(
		cancelled,
		platformoidcauth.DirectSessionRevalidationLookup{SessionID: uuid.Must(uuid.NewV7()), ObservedAt: now},
	); err == nil || snapshot.Session.SessionID != uuid.Nil || called {
		t.Fatalf("cancelled LoadDirectPlatformSessionForRevalidation() = %s, %v, called=%t", snapshot, err, called)
	}
}

func TestDirectPlatformSessionMutationRejectsStaleOrDriftedEcho(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 15, 0, 0, 0, time.UTC)
	mutation := platformoidcauth.DirectSessionRevalidationMutation{
		SessionID: uuid.Must(uuid.NewV7()), ExpectedVersion: 4,
		Decision: platformoidcauth.DirectSessionRevalidationUsable,
		Reason:   platformoidcauth.DirectSessionReasonCurrent, ObservedAt: now,
	}
	mutation.RequestDigest = platformOIDCDirectSessionMutationDigest(mutation)
	wanted, err := platformOIDCDirectSessionMutationToWire(mutation)
	if err != nil {
		t.Fatalf("platformOIDCDirectSessionMutationToWire() error = %v", err)
	}
	if result, err := platformOIDCDirectSessionMutationResultFromWire(
		platformOIDCDirectSessionMutationResultWire{
			Applied: platformOIDCDirectBool(false), Category: "stale", SessionID: wanted.SessionID,
			ExpectedVersion: wanted.ExpectedVersion, Decision: wanted.Decision,
		}, wanted,
	); err != nil || result.Applied {
		t.Fatalf("stale result = %#v, %v", result, err)
	}
	for name, mutate := range map[string]func(*platformOIDCDirectSessionMutationResultWire){
		"missing applied": func(value *platformOIDCDirectSessionMutationResultWire) { value.Applied = nil },
		"wrong decision":  func(value *platformOIDCDirectSessionMutationResultWire) { value.Decision = "revoke" },
		"wrong version":   func(value *platformOIDCDirectSessionMutationResultWire) { value.NewVersion++ },
		"malformed user":  func(value *platformOIDCDirectSessionMutationResultWire) { value.UserID = "not-a-uuid" },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			response := platformOIDCDirectSessionMutationResultWire{
				Applied: platformOIDCDirectBool(true), SessionID: wanted.SessionID,
				UserID: uuid.Must(uuid.NewV7()).String(), ExpectedVersion: wanted.ExpectedVersion,
				NewVersion: wanted.ExpectedVersion + 1, Decision: wanted.Decision,
			}
			mutate(&response)
			if result, err := platformOIDCDirectSessionMutationResultFromWire(response, wanted); err == nil || result.Applied {
				t.Fatalf("platformOIDCDirectSessionMutationResultFromWire() = %#v, %v", result, err)
			}
		})
	}
}

func platformOIDCDirectSessionRevalidationFixture(
	t *testing.T,
	now time.Time,
) platformOIDCDirectSessionSnapshotWire {
	t.Helper()
	sessionID := uuid.Must(uuid.NewV7())
	familyID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	providerID := uuid.Must(uuid.NewV7())
	identityID := uuid.Must(uuid.NewV7())
	floorID := uuid.Must(uuid.NewV7())
	evidenceID := uuid.Must(uuid.NewV7())
	issuedAt := now.Add(-10 * time.Minute)
	return platformOIDCDirectSessionSnapshotWire{
		Session: platformOIDCDirectSessionRevalidationStateWire{
			ID: sessionID.String(), RotationFamilyID: familyID.String(), UserID: userID.String(),
			ActiveTenantID: platformOIDCDirectRaw(nil), AuthenticationMethod: "oidc", Audience: "api",
			PrimaryKind: "platform_provider", IssuedAt: issuedAt,
			RecoveryRestricted: platformOIDCDirectBool(false), UserAuthenticationRevision: 5,
			DirectStateCount: platformOIDCDirectInt(1), DirectProvenanceCount: platformOIDCDirectInt(1),
			TenantProvenanceCount: platformOIDCDirectInt(0), ProviderEvidenceCount: platformOIDCDirectInt(1),
			TOTPEvidenceCount: platformOIDCDirectInt(0), CurrentVersion: 1,
			IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
			Active: platformOIDCDirectBool(true), RotationFamilyLive: platformOIDCDirectBool(true),
		},
		Authority: platformOIDCDirectSessionAuthorityWire{
			ProviderID: providerID.String(), ExternalIdentityID: identityID.String(), ProviderKind: "oidc",
			RuntimePolicyEnabled:       platformOIDCDirectBool(true),
			LegacyPlatformLoginEnabled: platformOIDCDirectBool(false), LoginPolicyEnabled: platformOIDCDirectBool(true),
			AccountMode: "existing_identity", IdentityCurrentProviderID: providerID.String(),
			IdentityCurrentUserID: userID.String(), IdentityProviderKind: "oidc",
			IdentityRetiredAt: platformOIDCDirectRaw(nil), AliasCurrentProviderID: providerID.String(),
			AliasCurrentIdentityID: identityID.String(), AliasRetiredAt: platformOIDCDirectRaw(nil),
			ProviderRevision:           platformOIDCDirectExactRevisionWire{Pinned: 2, Current: 2},
			SecurityRevision:           platformOIDCDirectExactRevisionWire{Pinned: 3, Current: 3},
			LoginPolicyRevision:        platformOIDCDirectExactRevisionWire{Pinned: 4, Current: 4},
			UserAuthenticationRevision: platformOIDCDirectExactRevisionWire{Pinned: 5, Current: 5},
			IdentityVersion:            platformOIDCDirectExactRevisionWire{Pinned: 6, Current: 6},
			AliasKeyVersion:            platformOIDCDirectExactRevisionWire{Pinned: 7, Current: 7},
			AssurancePolicyRevision:    platformOIDCDirectExactRevisionWire{Pinned: 8, Current: 8},
			PlatformFloor: platformOIDCDirectFloorWire{
				PinnedID: floorID.String(), PinnedRevision: 9, CurrentID: floorID.String(), CurrentRevision: 9,
				Level: "primary", LocalRequired: platformOIDCDirectBool(false), Freshness: platformOIDCDirectInt64(0),
				EnrollmentDeadline: platformOIDCDirectRaw(nil), CurrentScope: "platform_floor",
				CurrentTenantID: platformOIDCDirectRaw(nil), CurrentRetiredAt: platformOIDCDirectRaw(nil),
				CurrentCount: platformOIDCDirectInt(1),
			},
			TrustRuleID: platformOIDCDirectRaw(nil), TrustRuleRevision: platformOIDCDirectRaw(nil),
			ProviderEnabled: platformOIDCDirectBool(true), PlatformLoginLive: platformOIDCDirectBool(true),
			UserActive: platformOIDCDirectBool(true), IdentityLive: platformOIDCDirectBool(true),
			SubjectAliasLive: platformOIDCDirectBool(true), FactorEvidenceLive: platformOIDCDirectBool(true),
			EvidenceFresh: platformOIDCDirectBool(true), PolicyPinsExact: platformOIDCDirectBool(true),
			TrustEvidenceLive: platformOIDCDirectBool(true),
		},
		Evidence: []platformOIDCDirectSessionEvidenceWire{{
			ID: evidenceID.String(), UserID: userID.String(), Kind: "platform_provider", Level: "primary",
			PlatformProviderID: platformOIDCDirectRaw(providerID.String()),
			ExternalIdentityID: platformOIDCDirectRaw(identityID.String()), AuthenticatedAt: issuedAt,
			ExpiresAt:        platformOIDCDirectRaw(now.Add(30 * time.Minute)),
			TOTPCredentialID: platformOIDCDirectRaw(nil), FactorRevision: platformOIDCDirectRaw(nil),
			TrustRuleID: platformOIDCDirectRaw(nil), TrustRuleRevision: platformOIDCDirectRaw(nil),
		}},
		FactorAuthorities: []platformOIDCDirectFactorAuthorityWire{},
		TrustAuthorities:  []platformOIDCDirectTrustAuthorityWire{},
		PolicyPins: []platformOIDCDirectPolicyPinWire{
			{Kind: "assurance", ID: providerID.String(), Revision: 8},
			{Kind: "login", ID: providerID.String(), Revision: 4},
			{Kind: "platform_floor", ID: floorID.String(), Revision: 9},
		},
	}
}

func clonePlatformOIDCDirectSessionRevalidationFixture(
	value platformOIDCDirectSessionSnapshotWire,
) platformOIDCDirectSessionSnapshotWire {
	value.Session.ActiveTenantID = append(json.RawMessage(nil), value.Session.ActiveTenantID...)
	value.Authority.IdentityRetiredAt = append(json.RawMessage(nil), value.Authority.IdentityRetiredAt...)
	value.Authority.AliasRetiredAt = append(json.RawMessage(nil), value.Authority.AliasRetiredAt...)
	value.Authority.TrustRuleID = append(json.RawMessage(nil), value.Authority.TrustRuleID...)
	value.Authority.TrustRuleRevision = append(json.RawMessage(nil), value.Authority.TrustRuleRevision...)
	value.Evidence = append([]platformOIDCDirectSessionEvidenceWire(nil), value.Evidence...)
	for index := range value.Evidence {
		item := &value.Evidence[index]
		item.PlatformProviderID = append(json.RawMessage(nil), item.PlatformProviderID...)
		item.ExternalIdentityID = append(json.RawMessage(nil), item.ExternalIdentityID...)
		item.ExpiresAt = append(json.RawMessage(nil), item.ExpiresAt...)
		item.TOTPCredentialID = append(json.RawMessage(nil), item.TOTPCredentialID...)
		item.FactorRevision = append(json.RawMessage(nil), item.FactorRevision...)
		item.TrustRuleID = append(json.RawMessage(nil), item.TrustRuleID...)
		item.TrustRuleRevision = append(json.RawMessage(nil), item.TrustRuleRevision...)
	}
	value.PolicyPins = append([]platformOIDCDirectPolicyPinWire(nil), value.PolicyPins...)
	return value
}

func platformOIDCDirectRaw(value any) json.RawMessage {
	payload, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return payload
}

func platformOIDCDirectBool(value bool) *bool { return &value }

func platformOIDCDirectInt(value int) *int { return &value }

func platformOIDCDirectInt64(value int64) *int64 { return &value }
