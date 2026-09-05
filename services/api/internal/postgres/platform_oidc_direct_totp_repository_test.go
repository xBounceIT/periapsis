package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

func TestFederatedAuthRepositoryPersistsExactDirectPlatformTOTPFlow(t *testing.T) {
	fixture := newPlatformOIDCDirectTOTPRepositoryFixture(t)
	postgresJSONZone := time.FixedZone("postgres-json", 2*60*60)
	auditIDs := []uuid.UUID{
		uuid.MustParse("00000000-0000-7000-8000-000000000901"),
		uuid.MustParse("00000000-0000-7000-8000-000000000902"),
		uuid.MustParse("00000000-0000-7000-8000-000000000903"),
		uuid.MustParse("00000000-0000-7000-8000-000000000904"),
	}
	auditIndex := 0
	var retainedPayloads [][]byte
	var queries []string
	repository := &FederatedAuthRepository{
		newDirectAuditID: func() (uuid.UUID, error) {
			if auditIndex >= len(auditIDs) {
				t.Fatal("generated too many direct audit identifiers")
			}
			identifier := auditIDs[auditIndex]
			auditIndex++
			return identifier, nil
		},
		queryer: federatedAuthQueryerStub{query: func(
			_ context.Context,
			query string,
			arguments ...any,
		) pgx.Row {
			if len(arguments) != 1 {
				t.Fatalf("%s argument count = %d", query, len(arguments))
			}
			payload, ok := arguments[0].([]byte)
			if !ok || len(payload) == 0 || len(payload) > maximumFederatedAuthenticationWireBytes {
				t.Fatalf("%s payload type/size = %T/%d", query, arguments[0], len(payload))
			}
			retainedPayloads = append(retainedPayloads, payload)
			queries = append(queries, query)

			var response any
			switch query {
			case beginPlatformOIDCDirectTOTPSQL:
				var request platformOIDCDirectTOTPBeginWire
				if err := json.Unmarshal(payload, &request); err != nil ||
					request.ContinuationID != entityIDWire(fixture.continuationID) ||
					!bytes.Equal(request.ReceiptDigest, fixture.receiptDigest[:]) ||
					!bytes.Equal(request.Challenge.ID, fixture.challengeID[:]) ||
					!bytes.Equal(request.Challenge.BrowserDigest, fixture.browserDigest[:]) ||
					!request.ObservedAt.Equal(fixture.now) || !request.Challenge.CreatedAt.Equal(fixture.now) ||
					request.Audit.EventID != auditIDs[0].String() ||
					!validPlatformOIDCDirectAuditFixture(request.Audit, fixture.audit) {
					t.Fatalf("direct TOTP begin wire malformed: %#v, %v", request, err)
				}
				response = fixture.challengeWire(platformoidcauth.DirectTOTPChallengePending, 0, 1, postgresJSONZone)
			case loadPlatformOIDCDirectTOTPSQL:
				var request platformOIDCDirectTOTPLookupWire
				if err := json.Unmarshal(payload, &request); err != nil ||
					request.ContinuationID != entityIDWire(fixture.continuationID) ||
					!bytes.Equal(request.ReceiptDigest, fixture.receiptDigest[:]) ||
					!bytes.Equal(request.ChallengeID, fixture.challengeID[:]) ||
					!bytes.Equal(request.BrowserDigest, fixture.browserDigest[:]) ||
					!request.ObservedAt.Equal(fixture.now) {
					t.Fatalf("direct TOTP lookup wire malformed: %#v, %v", request, err)
				}
				response = fixture.verificationWire(postgresJSONZone)
			case recordPlatformOIDCDirectTOTPFailureSQL:
				var request platformOIDCDirectTOTPFailureWire
				if err := json.Unmarshal(payload, &request); err != nil || request.ExpectedVersion != 1 ||
					request.Audit.EventID != auditIDs[1].String() ||
					!validPlatformOIDCDirectAuditFixture(request.Audit, fixture.audit) {
					t.Fatalf("direct TOTP failure wire malformed: %#v, %v", request, err)
				}
				response = fixture.challengeWire(platformoidcauth.DirectTOTPChallengePending, 1, 2, postgresJSONZone)
			case applyPlatformOIDCDirectTOTPSQL:
				var request platformOIDCDirectTOTPApplyWire
				if err := json.Unmarshal(payload, &request); err != nil || request.ExpectedVersion != 1 ||
					request.AcceptedCounter != fixture.acceptedCounter ||
					!bytes.Equal(request.CompletionRequestDigest, fixture.completionDigest[:]) ||
					request.Session.ID != entityIDWire(fixture.session.SessionID()) ||
					request.Session.RotationFamilyID != entityIDWire(fixture.session.FamilyID()) ||
					request.Session.Audience != "api" || request.Session.SessionVersion != 1 ||
					request.Audit.EventID != auditIDs[2].String() ||
					!validPlatformOIDCDirectAuditFixture(request.Audit, fixture.audit) {
					t.Fatalf("direct TOTP apply wire malformed: %#v, %v", request, err)
				}
				var raw map[string]json.RawMessage
				var session map[string]json.RawMessage
				if err := json.Unmarshal(payload, &raw); err != nil || len(raw) != 10 {
					t.Fatalf("direct TOTP apply field set = %v, %v", raw, err)
				}
				if err := json.Unmarshal(raw["session"], &session); err != nil || len(session) != 8 ||
					session["authenticationMethod"] != nil || session["recoveryRestricted"] != nil {
					t.Fatalf("direct TOTP session field set = %v, %v", session, err)
				}
				response = fixture.applyResultWire()
			case abandonPlatformOIDCDirectTOTPSQL:
				var request platformOIDCDirectTOTPAbandonWire
				if err := json.Unmarshal(payload, &request); err != nil || request.ExpectedVersion != 1 ||
					request.Reason != string(platformoidcauth.DirectTOTPAbandonCancelled) ||
					request.Audit.EventID != auditIDs[3].String() ||
					!validPlatformOIDCDirectAuditFixture(request.Audit, fixture.audit) {
					t.Fatalf("direct TOTP abandon wire malformed: %#v, %v", request, err)
				}
				response = fixture.challengeWire(platformoidcauth.DirectTOTPChallengeAbandoned, 0, 2, postgresJSONZone)
			default:
				t.Fatalf("unexpected query: %s", query)
			}
			return federatedAuthJSONRow(mustFederatedJSON(t, response))
		}},
	}

	challenge, err := repository.BeginDirectTOTP(context.Background(), fixture.beginRequest())
	if err != nil || challenge.ChallengeID != fixture.challengeID || challenge.FactorID != fixture.factorID ||
		challenge.State != platformoidcauth.DirectTOTPChallengePending || challenge.ExpiresAt.Location() != time.UTC {
		t.Fatalf("BeginDirectTOTP() = %s, %v", challenge, err)
	}
	snapshot, err := repository.LoadDirectTOTP(context.Background(), fixture.lookup())
	if err != nil || snapshot.ChallengeID != fixture.challengeID || snapshot.UserID != fixture.userID ||
		snapshot.FactorID != fixture.factorID || snapshot.Authority != federatedauth.ContinuationAuthorityDirectPlatformOIDC ||
		snapshot.LastAcceptedCounter == nil || *snapshot.LastAcceptedCounter != fixture.lastAcceptedCounter ||
		!bytes.Equal(snapshot.Secret.Ciphertext, fixture.secretCiphertext) || snapshot.ExpiresAt.Location() != time.UTC {
		t.Fatalf("LoadDirectTOTP() = %s, %v", snapshot, err)
	}
	snapshot.Destroy()
	failure, err := repository.RecordDirectTOTPFailure(context.Background(), fixture.failureRequest())
	if err != nil || failure.FailureCount != 1 || failure.Version != 2 ||
		failure.State != platformoidcauth.DirectTOTPChallengePending {
		t.Fatalf("RecordDirectTOTPFailure() = %s, %v", failure, err)
	}
	result, err := repository.ApplyDirectTOTP(context.Background(), fixture.applyRequest())
	if err != nil || result.Category != platformoidcauth.DirectTOTPApplySuccess ||
		result.SessionID != fixture.session.SessionID() || result.UserID != fixture.userID ||
		result.FactorID != fixture.factorID || result.AcceptedCounter != fixture.acceptedCounter {
		t.Fatalf("ApplyDirectTOTP() = %s, %v", result, err)
	}
	abandoned, err := repository.AbandonDirectTOTP(context.Background(), fixture.abandonRequest())
	if err != nil || abandoned.State != platformoidcauth.DirectTOTPChallengeAbandoned || abandoned.Version != 2 {
		t.Fatalf("AbandonDirectTOTP() = %s, %v", abandoned, err)
	}

	wantQueries := []string{
		beginPlatformOIDCDirectTOTPSQL, loadPlatformOIDCDirectTOTPSQL,
		recordPlatformOIDCDirectTOTPFailureSQL, applyPlatformOIDCDirectTOTPSQL,
		abandonPlatformOIDCDirectTOTPSQL,
	}
	if fmt.Sprint(queries) != fmt.Sprint(wantQueries) || auditIndex != len(auditIDs) {
		t.Fatalf("queries/audits = %v/%d, want %v/%d", queries, auditIndex, wantQueries, len(auditIDs))
	}
	for index, payload := range retainedPayloads {
		if !allZeroFederatedBytes(payload) {
			t.Fatalf("payload %d retained direct TOTP material", index)
		}
	}
}

func TestFederatedAuthRepositoryRejectsMalformedDirectPlatformTOTPInputsAndResponses(t *testing.T) {
	fixture := newPlatformOIDCDirectTOTPRepositoryFixture(t)
	validAuditID := uuid.MustParse("00000000-0000-7000-8000-000000000911")
	queryCount := 0
	repository := &FederatedAuthRepository{
		newDirectAuditID: func() (uuid.UUID, error) { return validAuditID, nil },
		queryer: federatedAuthQueryerStub{query: func(
			_ context.Context,
			query string,
			_ ...any,
		) pgx.Row {
			queryCount++
			if query != beginPlatformOIDCDirectTOTPSQL {
				t.Fatalf("unexpected malformed-response query: %s", query)
			}
			response := fixture.challengeWire(platformoidcauth.DirectTOTPChallengePending, 0, 1, time.UTC)
			encoded := mustFederatedJSON(t, response)
			encoded[len(encoded)-1] = ','
			encoded = append(encoded, []byte(`"unexpected":true}`)...)
			return federatedAuthJSONRow(encoded)
		}},
	}
	if _, err := repository.BeginDirectTOTP(context.Background(), fixture.beginRequest()); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("unknown response field error = %v", err)
	}
	if queryCount != 1 {
		t.Fatalf("malformed response query count = %d", queryCount)
	}

	noQuery := &FederatedAuthRepository{
		newDirectAuditID: func() (uuid.UUID, error) { return validAuditID, nil },
		queryer: federatedAuthQueryerStub{query: func(context.Context, string, ...any) pgx.Row {
			t.Fatal("invalid request reached PostgreSQL")
			return nil
		}},
	}
	invalidBegin := fixture.beginRequest()
	invalidBegin.ReceiptDigest = [32]byte{}
	if _, err := noQuery.BeginDirectTOTP(context.Background(), invalidBegin); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("zero receipt digest error = %v", err)
	}
	invalidLookup := fixture.lookup()
	invalidLookup.Authority = federatedauth.ContinuationAuthorityTenant
	if snapshot, err := noQuery.LoadDirectTOTP(context.Background(), invalidLookup); !errors.Is(err, errFederatedAuthPersistence) ||
		snapshot.ChallengeID != (platformoidcauth.DirectTOTPChallengeID{}) || len(snapshot.Secret.Ciphertext) != 0 {
		t.Fatalf("tenant authority lookup = %s, %v", snapshot, err)
	}
	invalidApply := fixture.applyRequest()
	invalidApply.CompletionRequestDigest = platformoidcauth.DirectTOTPCompletionDigest{}
	if _, err := noQuery.ApplyDirectTOTP(context.Background(), invalidApply); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("zero completion digest error = %v", err)
	}
	invalidAbandon := fixture.abandonRequest()
	invalidAbandon.Reason = "future_reason"
	if _, err := noQuery.AbandonDirectTOTP(context.Background(), invalidAbandon); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("unknown abandon reason error = %v", err)
	}

	equalDeadlineSession, err := mfa.NewSessionReservation(mfa.SessionMaterial{
		SessionID: fixture.session.SessionID(), FamilyID: fixture.session.FamilyID(),
		TokenDigest: fixture.session.TokenDigest(), CSRFDigest: fixture.session.CSRFDigest(),
		AuthenticationMethod: mfa.SessionAuthenticationOIDC,
		IdleExpiresAt:        fixture.now.Add(time.Hour), AbsoluteExpiresAt: fixture.now.Add(time.Hour),
	}, fixture.now)
	if err != nil {
		t.Fatalf("construct equal-deadline session: %v", err)
	}
	invalidApply = fixture.applyRequest()
	invalidApply.Session = equalDeadlineSession
	if _, err := noQuery.ApplyDirectTOTP(context.Background(), invalidApply); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("equal session deadlines error = %v", err)
	}
}

func TestPlatformOIDCDirectTOTPWireRejectsNonCanonicalOrAmbiguousProjections(t *testing.T) {
	fixture := newPlatformOIDCDirectTOTPRepositoryFixture(t)
	challenge := fixture.challengeWire(platformoidcauth.DirectTOTPChallengePending, 0, 1, time.UTC)
	challenge.State = string(platformoidcauth.DirectTOTPChallengeCompleted)
	if _, err := platformOIDCDirectTOTPChallengeFromWire(challenge); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("completed challenge projection error = %v", err)
	}
	challenge = fixture.challengeWire(platformoidcauth.DirectTOTPChallengePending, 1, 1, time.UTC)
	if _, err := platformOIDCDirectTOTPChallengeFromWire(challenge); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("inconsistent failure/version projection error = %v", err)
	}

	verification := fixture.verificationWire(time.UTC)
	verification.SecretNonce = verification.SecretNonce[:11]
	if snapshot, err := platformOIDCDirectTOTPVerificationFromWire(verification); !errors.Is(err, errFederatedAuthPersistence) ||
		snapshot.ChallengeID != (platformoidcauth.DirectTOTPChallengeID{}) || len(snapshot.Secret.Ciphertext) != 0 {
		t.Fatalf("short secret nonce projection = %s, %v", snapshot, err)
	}
	verification = fixture.verificationWire(time.UTC)
	verification.Authority = string(federatedauth.ContinuationAuthorityTenant)
	if _, err := platformOIDCDirectTOTPVerificationFromWire(verification); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("tenant verification authority error = %v", err)
	}

	sessionID := entityIDWire(fixture.session.SessionID())
	result := platformOIDCDirectTOTPApplyResultWire{
		Applied: false, Category: string(platformoidcauth.DirectTOTPApplyStale), SessionID: &sessionID,
	}
	if _, err := platformOIDCDirectTOTPApplyResultFromWire(result); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("stale result carrying session error = %v", err)
	}
	result = fixture.applyResultWire()
	result.ExternalIdentityID = result.UserID
	if _, err := platformOIDCDirectTOTPApplyResultFromWire(result); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("aliased authority identifiers error = %v", err)
	}

	badAudit := fixture.audit
	badAudit.RemoteAddress = netip.MustParseAddr("::ffff:192.0.2.90")
	if _, err := platformOIDCDirectAuditToWire(badAudit,
		uuid.MustParse("00000000-0000-7000-8000-000000000912")); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("mapped audit address error = %v", err)
	}
	badAudit = fixture.audit
	badAudit.UserAgent = "unsafe\u202eagent"
	if _, err := platformOIDCDirectAuditToWire(badAudit,
		uuid.MustParse("00000000-0000-7000-8000-000000000913")); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("directional audit control error = %v", err)
	}
}

type platformOIDCDirectTOTPRepositoryFixture struct {
	now                 time.Time
	continuationID      identity.EntityID
	userID              identity.EntityID
	factorID            identity.EntityID
	externalIdentityID  identity.EntityID
	challengeID         platformoidcauth.DirectTOTPChallengeID
	browserDigest       platformoidcauth.DirectTOTPBrowserDigest
	receiptDigest       [32]byte
	completionDigest    platformoidcauth.DirectTOTPCompletionDigest
	secretCiphertext    []byte
	secretNonce         []byte
	secretAAD           []byte
	lastAcceptedCounter int64
	acceptedCounter     int64
	session             mfa.SessionReservation
	audit               platformoidcauth.DirectAuditContext
}

func newPlatformOIDCDirectTOTPRepositoryFixture(t *testing.T) platformOIDCDirectTOTPRepositoryFixture {
	t.Helper()
	now := time.Date(2026, time.August, 30, 12, 0, 0, 123_000_000, time.UTC)
	secretCiphertext := platformOIDCDirectBytes(161)
	secretNonce := platformOIDCDirectBytes(201)
	fixture := platformOIDCDirectTOTPRepositoryFixture{
		now:                now,
		continuationID:     identity.EntityID(uuid.MustParse("00000000-0000-7000-8000-000000000921")),
		userID:             identity.EntityID(uuid.MustParse("00000000-0000-7000-8000-000000000922")),
		factorID:           identity.EntityID(uuid.MustParse("00000000-0000-7000-8000-000000000923")),
		externalIdentityID: identity.EntityID(uuid.MustParse("00000000-0000-7000-8000-000000000924")),
		challengeID:        platformoidcauth.DirectTOTPChallengeID(platformOIDCDirectBytes(1)),
		browserDigest:      platformoidcauth.DirectTOTPBrowserDigest(platformOIDCDirectBytes(41)),
		receiptDigest:      platformOIDCDirectBytes(81),
		completionDigest:   platformoidcauth.DirectTOTPCompletionDigest(platformOIDCDirectBytes(121)),
		secretCiphertext:   append([]byte(nil), secretCiphertext[:]...),
		secretNonce:        append([]byte(nil), secretNonce[:12]...),
		secretAAD:          []byte("periapsis/totp/aad/v1"), lastAcceptedCounter: 40, acceptedCounter: 41,
		audit: platformoidcauth.DirectAuditContext{
			RequestID:     identity.EntityID(uuid.MustParse("00000000-0000-7000-8000-000000000925")),
			CorrelationID: identity.EntityID(uuid.MustParse("00000000-0000-7000-8000-000000000926")),
			RemoteAddress: netip.MustParseAddr("192.0.2.90"), UserAgent: "direct-oidc-totp-repository-test/1",
		},
	}
	tokenDigest := platformOIDCDirectBytes(11)
	csrfDigest := platformOIDCDirectBytes(51)
	session, err := mfa.NewSessionReservation(mfa.SessionMaterial{
		SessionID:   identity.EntityID(uuid.MustParse("00000000-0000-7000-8000-000000000927")),
		FamilyID:    identity.EntityID(uuid.MustParse("00000000-0000-7000-8000-000000000928")),
		TokenDigest: tokenDigest, CSRFDigest: csrfDigest,
		AuthenticationMethod: mfa.SessionAuthenticationOIDC,
		IdleExpiresAt:        now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("construct direct TOTP session: %v", err)
	}
	fixture.session = session
	return fixture
}

func (fixture platformOIDCDirectTOTPRepositoryFixture) beginRequest() platformoidcauth.DirectTOTPBeginRequest {
	return platformoidcauth.DirectTOTPBeginRequest{
		ContinuationID: fixture.continuationID, ReceiptDigest: fixture.receiptDigest,
		ExpectedContinuationVersion: 1, ChallengeID: fixture.challengeID,
		BrowserDigest: fixture.browserDigest, CreatedAt: fixture.now,
		ExpiresAt: fixture.now.Add(5 * time.Minute), Audit: fixture.audit,
	}
}

func (fixture platformOIDCDirectTOTPRepositoryFixture) lookup() platformoidcauth.DirectTOTPLookup {
	return platformoidcauth.DirectTOTPLookup{
		ChallengeID: fixture.challengeID, ContinuationID: fixture.continuationID,
		Authority:     federatedauth.ContinuationAuthorityDirectPlatformOIDC,
		ReceiptDigest: fixture.receiptDigest, BrowserDigest: fixture.browserDigest,
		ObservedAt: fixture.now,
	}
}

func (fixture platformOIDCDirectTOTPRepositoryFixture) failureRequest() platformoidcauth.DirectTOTPFailureRequest {
	return platformoidcauth.DirectTOTPFailureRequest{
		ChallengeID: fixture.challengeID, ContinuationID: fixture.continuationID,
		Authority:     federatedauth.ContinuationAuthorityDirectPlatformOIDC,
		ReceiptDigest: fixture.receiptDigest, BrowserDigest: fixture.browserDigest,
		ExpectedVersion: 1, ObservedAt: fixture.now, Audit: fixture.audit,
	}
}

func (fixture platformOIDCDirectTOTPRepositoryFixture) applyRequest() platformoidcauth.DirectTOTPApplyRequest {
	return platformoidcauth.DirectTOTPApplyRequest{
		ChallengeID: fixture.challengeID, ContinuationID: fixture.continuationID,
		Authority:     federatedauth.ContinuationAuthorityDirectPlatformOIDC,
		ReceiptDigest: fixture.receiptDigest, BrowserDigest: fixture.browserDigest,
		ExpectedVersion: 1, AcceptedCounter: fixture.acceptedCounter,
		CompletionRequestDigest: fixture.completionDigest, Session: fixture.session,
		ObservedAt: fixture.now, Audit: fixture.audit,
	}
}

func (fixture platformOIDCDirectTOTPRepositoryFixture) abandonRequest() platformoidcauth.DirectTOTPAbandonRequest {
	return platformoidcauth.DirectTOTPAbandonRequest{
		ChallengeID: fixture.challengeID, ContinuationID: fixture.continuationID,
		Authority:     federatedauth.ContinuationAuthorityDirectPlatformOIDC,
		ReceiptDigest: fixture.receiptDigest, BrowserDigest: fixture.browserDigest,
		ExpectedVersion: 1, ObservedAt: fixture.now,
		Reason: platformoidcauth.DirectTOTPAbandonCancelled, Audit: fixture.audit,
	}
}

func (fixture platformOIDCDirectTOTPRepositoryFixture) challengeWire(
	state platformoidcauth.DirectTOTPChallengeState,
	failureCount uint32,
	version uint64,
	zone *time.Location,
) platformOIDCDirectTOTPChallengeWire {
	return platformOIDCDirectTOTPChallengeWire{
		ChallengeID:    append([]byte(nil), fixture.challengeID[:]...),
		ContinuationID: entityIDWire(fixture.continuationID), UserID: entityIDWire(fixture.userID),
		TOTPCredentialID: entityIDWire(fixture.factorID), UserAuthenticationRevision: 3,
		TOTPSecurityRevision: 4, FailureCount: failureCount, State: string(state), Version: version,
		ExpiresAt: fixture.now.Add(5 * time.Minute).In(zone),
	}
}

func (fixture platformOIDCDirectTOTPRepositoryFixture) verificationWire(
	zone *time.Location,
) platformOIDCDirectTOTPVerificationWire {
	counter := fixture.lastAcceptedCounter
	return platformOIDCDirectTOTPVerificationWire{
		Authority:      string(federatedauth.ContinuationAuthorityDirectPlatformOIDC),
		ChallengeID:    append([]byte(nil), fixture.challengeID[:]...),
		ContinuationID: entityIDWire(fixture.continuationID), UserID: entityIDWire(fixture.userID),
		ReceiptDigest:    append([]byte(nil), fixture.receiptDigest[:]...),
		TOTPCredentialID: entityIDWire(fixture.factorID),
		SecretCiphertext: append([]byte(nil), fixture.secretCiphertext...),
		SecretNonce:      append([]byte(nil), fixture.secretNonce...), SecretAAD: append([]byte(nil), fixture.secretAAD...),
		KeyVersion: 1, EncryptionAlgorithm: "aes-256-gcm", OTPAlgorithm: "SHA1",
		Digits: 6, PeriodSeconds: 30, LastAcceptedCounter: &counter,
		UserAuthenticationRevision: 3, TOTPSecurityRevision: 4,
		ExpiresAt: fixture.now.Add(5 * time.Minute).In(zone), Version: 1,
	}
}

func (fixture platformOIDCDirectTOTPRepositoryFixture) applyResultWire() platformOIDCDirectTOTPApplyResultWire {
	sessionID := entityIDWire(fixture.session.SessionID())
	userID := entityIDWire(fixture.userID)
	externalIdentityID := entityIDWire(fixture.externalIdentityID)
	factorID := entityIDWire(fixture.factorID)
	counter := fixture.acceptedCounter
	revision := uint64(4)
	return platformOIDCDirectTOTPApplyResultWire{
		Applied: true, Category: string(platformoidcauth.DirectTOTPApplySuccess),
		SessionID: &sessionID, UserID: &userID, ExternalIdentityID: &externalIdentityID,
		AcceptedCounter: &counter, TOTPCredentialID: &factorID, TOTPSecurityRevision: &revision,
	}
}

func validPlatformOIDCDirectAuditFixture(
	wire platformOIDCDirectAuditWire,
	want platformoidcauth.DirectAuditContext,
) bool {
	return wire.RequestID == entityIDWire(want.RequestID) &&
		wire.CorrelationID == entityIDWire(want.CorrelationID) &&
		wire.IPAddress == want.RemoteAddress.String() && wire.UserAgent == want.UserAgent &&
		wire.AuthenticationMethod == "oidc"
}

func platformOIDCDirectBytes(seed byte) [32]byte {
	var value [32]byte
	for index := range value {
		value[index] = seed + byte(index)
	}
	return value
}
