package postgres

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentityprovider"
)

func TestPlatformLDAPDiagnosticBeginUsesOneProtectedTransactionAndRestoresSecret(t *testing.T) {
	t.Parallel()
	session, event := platformIdentityProviderRepositoryAuthority(t)
	providerID, testID, secretID := mustPostgresUUIDv7(t), mustPostgresUUIDv7(t), mustPostgresUUIDv7(t)
	nonce := bytes.Repeat([]byte{0x11}, 12)
	ciphertext := bytes.Repeat([]byte{0x22}, 17)
	document := platformLDAPDiagnosticSnapshotDocument(
		t, providerID, testID, secretID, hex.EncodeToString(nonce), hex.EncodeToString(ciphertext),
	)
	var observedRequest []byte
	tx := &platformIdentityProviderTransaction{actorID: session.ActorID}
	tx.row = func(query string, arguments []any, destinations []any) error {
		if !strings.Contains(query, "app.begin_platform_ldap_test_v1") || len(destinations) != 1 {
			return errors.New("unexpected platform LDAP diagnostic begin query")
		}
		observedRequest = append([]byte(nil), arguments[0].([]byte)...)
		*destinations[0].(*[]byte) = append([]byte(nil), document...)
		return nil
	}
	repository, beginCalls := platformIdentityProviderRepositoryHarness(t, tx, uuid.Nil)

	snapshot, err := repository.BeginLDAPTest(context.Background(), platformidentityprovider.BeginLDAPTestParams{
		SessionParams: session, ProviderID: providerID, TestID: testID,
		Kind: platformidentityprovider.LDAPTestBind, Event: event,
	})
	if err != nil {
		t.Fatalf("BeginLDAPTest() error = %v", err)
	}
	if snapshot.TestID != testID || snapshot.ProviderID != providerID ||
		snapshot.ProviderVersion != 5 || snapshot.ConfigurationRevision != 4 || snapshot.MappingRevision != 3 ||
		snapshot.BindSecret == nil || snapshot.BindSecret.SecretID != secretID ||
		snapshot.SecretRevision == nil || *snapshot.SecretRevision != 2 ||
		snapshot.BindSecret.Envelope.KeyVersion != 1 ||
		!bytes.Equal(snapshot.BindSecret.Envelope.Nonce[:], nonce) ||
		!bytes.Equal(snapshot.BindSecret.Envelope.Ciphertext, ciphertext) {
		t.Fatalf("BeginLDAPTest() snapshot = %#v", snapshot)
	}
	assertPlatformIdentityProviderTransaction(t, tx, beginCalls, "app.begin_platform_ldap_test_v1")
	var request struct {
		SessionID            uuid.UUID                             `json:"sessionId"`
		AuthenticationMethod string                                `json:"authenticationMethod"`
		ProviderID           uuid.UUID                             `json:"providerId"`
		TestID               uuid.UUID                             `json:"testId"`
		Kind                 platformidentityprovider.LDAPTestKind `json:"kind"`
		RequestID            uuid.UUID                             `json:"requestId"`
		CorrelationID        uuid.UUID                             `json:"correlationId"`
	}
	if err := json.Unmarshal(observedRequest, &request); err != nil ||
		request.SessionID != session.SessionID || request.AuthenticationMethod != session.AuthenticationMethod ||
		request.ProviderID != providerID || request.TestID != testID ||
		request.Kind != platformidentityprovider.LDAPTestBind || request.RequestID != event.RequestID ||
		request.CorrelationID != event.CorrelationID {
		t.Fatalf("BeginLDAPTest() request = %#v, %v", request, err)
	}

	snapshot.Destroy()
	if snapshot.BindSecret != nil || snapshot.Endpoints != nil || snapshot.Mappings != nil {
		t.Fatalf("Destroy() retained secret-bearing snapshot = %#v", snapshot)
	}
}

func TestPlatformLDAPDiagnosticCompleteCouplesAuditAndReturnsClosedProjection(t *testing.T) {
	t.Parallel()
	session, event := platformIdentityProviderRepositoryAuthority(t)
	testID, auditID := mustPostgresUUIDv7(t), mustPostgresUUIDv7(t)
	completedAt := time.Date(2026, 9, 2, 8, 30, 0, 123_000_000, time.UTC)
	document, err := json.Marshal(map[string]any{
		"testId": testID, "kind": "mapping_dry_run", "outcome": "success", "category": "success",
		"endpointPriority": 1, "durationMs": 42, "matchedEntryCount": 2,
		"attributes": []string{"cn", "entryuuid", "uid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var observedRequest []byte
	tx := &platformIdentityProviderTransaction{actorID: session.ActorID}
	tx.row = func(query string, arguments []any, destinations []any) error {
		if !strings.Contains(query, "app.complete_platform_ldap_test_v1") || len(destinations) != 1 {
			return errors.New("unexpected platform LDAP diagnostic completion query")
		}
		observedRequest = append([]byte(nil), arguments[0].([]byte)...)
		*destinations[0].(*[]byte) = append([]byte(nil), document...)
		return nil
	}
	repository, beginCalls := platformIdentityProviderRepositoryHarness(t, tx, auditID)
	priority, matched := 1, 2
	result, err := repository.CompleteLDAPTest(context.Background(), platformidentityprovider.CompleteLDAPTestParams{
		SessionParams: session, TestID: testID, Outcome: "success", Category: "success",
		EndpointPriority: &priority, Duration: 42 * time.Millisecond, MatchedEntryCount: &matched,
		Attributes: []string{"cn", "entryuuid", "uid"}, CompletedAt: completedAt,
		Reason: "Validate platform role mapping", Event: event,
	})
	if err != nil || result.TestID != testID || result.Kind != platformidentityprovider.LDAPTestMappingDryRun ||
		result.Outcome != "success" || result.Category != "success" || result.Duration != 42*time.Millisecond ||
		result.MatchedEntryCount == nil || *result.MatchedEntryCount != 2 ||
		!slices.Equal(result.Attributes, []string{"cn", "entryuuid", "uid"}) {
		t.Fatalf("CompleteLDAPTest() result=%#v error=%v", result, err)
	}
	assertPlatformIdentityProviderTransaction(t, tx, beginCalls, "app.complete_platform_ldap_test_v1")
	var request struct {
		SessionID            uuid.UUID       `json:"sessionId"`
		AuthenticationMethod string          `json:"authenticationMethod"`
		TestID               uuid.UUID       `json:"testId"`
		Outcome              string          `json:"outcome"`
		Category             string          `json:"category"`
		DurationMS           int64           `json:"durationMs"`
		CompletedAt          time.Time       `json:"completedAt"`
		Audit                json.RawMessage `json:"audit"`
	}
	if err := json.Unmarshal(observedRequest, &request); err != nil ||
		request.SessionID != session.SessionID || request.AuthenticationMethod != session.AuthenticationMethod ||
		request.TestID != testID || request.Outcome != "success" || request.Category != "success" ||
		request.DurationMS != 42 || !request.CompletedAt.Equal(completedAt) {
		t.Fatalf("CompleteLDAPTest() request = %#v, %v", request, err)
	}
	var audit struct {
		EventID              uuid.UUID `json:"eventId"`
		RequestID            uuid.UUID `json:"requestId"`
		CorrelationID        uuid.UUID `json:"correlationId"`
		IPAddress            string    `json:"ipAddress"`
		UserAgent            string    `json:"userAgent"`
		AuthenticationMethod string    `json:"authenticationMethod"`
		Reason               string    `json:"reason"`
	}
	if err := json.Unmarshal(request.Audit, &audit); err != nil || audit.EventID != auditID ||
		audit.RequestID != event.RequestID || audit.CorrelationID != event.CorrelationID ||
		audit.IPAddress != event.RemoteAddress.String() || audit.UserAgent != event.UserAgent ||
		audit.AuthenticationMethod != session.AuthenticationMethod || audit.Reason != "Validate platform role mapping" {
		t.Fatalf("CompleteLDAPTest() audit = %#v, %v", audit, err)
	}
	if bytes.Contains(observedRequest, []byte("bindSecret")) ||
		bytes.Contains(observedRequest, []byte("password")) {
		t.Fatal("CompleteLDAPTest() request contains secret-shaped fields")
	}
}

func TestPlatformLDAPDiagnosticBeginRejectsMalformedEncryptedSnapshot(t *testing.T) {
	t.Parallel()
	session, event := platformIdentityProviderRepositoryAuthority(t)
	providerID, testID, secretID := mustPostgresUUIDv7(t), mustPostgresUUIDv7(t), mustPostgresUUIDv7(t)
	document := platformLDAPDiagnosticSnapshotDocument(t, providerID, testID, secretID, "00", strings.Repeat("22", 17))
	tx := &platformIdentityProviderTransaction{actorID: session.ActorID}
	tx.row = func(_ string, _ []any, destinations []any) error {
		*destinations[0].(*[]byte) = append([]byte(nil), document...)
		return nil
	}
	repository, _ := platformIdentityProviderRepositoryHarness(t, tx, uuid.Nil)
	_, err := repository.BeginLDAPTest(context.Background(), platformidentityprovider.BeginLDAPTestParams{
		SessionParams: session, ProviderID: providerID, TestID: testID,
		Kind: platformidentityprovider.LDAPTestBind, Event: event,
	})
	if !errors.Is(err, authentication.ErrUnavailable) || tx.committed || !tx.rolledBack {
		t.Fatalf("BeginLDAPTest() error=%v commit=%t rollback=%t", err, tx.committed, tx.rolledBack)
	}
}

func platformLDAPDiagnosticSnapshotDocument(
	t testing.TB,
	providerID, testID, secretID uuid.UUID,
	nonce, ciphertext string,
) []byte {
	t.Helper()
	document, err := json.Marshal(map[string]any{
		"testId": testID, "providerId": providerID, "kind": "bind",
		"providerVersion": 5, "configurationRevision": 4, "mappingRevision": 3,
		"configuration": map[string]any{
			"template": "openldap", "verifyCertificate": true, "customCaPem": nil,
			"connectTimeoutMs": 1000, "operationTimeoutMs": 5000,
			"bindDn": "cn=service,dc=example,dc=test", "userBaseDn": "ou=users,dc=example,dc=test",
			"groupBaseDn": nil, "userSearchFilter": "(uid={username})", "groupSearchFilter": nil,
			"userDnTemplate": nil, "pageSize": 100, "maxPages": 10, "maxEntries": 1000,
			"maxResponseBytes": 1048576, "referralMode": "disabled", "maxReferralHops": 0,
			"nestedGroupMode": "disabled", "maxNestedGroupDepth": 0, "maxGroups": 100,
			"firstNameAttribute": "givenName", "lastNameAttribute": "sn", "displayNameAttribute": "cn",
			"usernameAttribute": "uid", "alternateUsernameAttribute": nil, "emailAttribute": "mail",
			"immutableSubjectAttribute": "entryUUID", "immutableSubjectFormat": "entry_uuid",
			"groupMembershipAttribute": nil, "posixMemberUidAttribute": nil, "posixGidNumberAttribute": nil,
			"accountStatusMode": "none", "accountStatusAttribute": nil, "accountDisabledValue": nil,
			"jitMode": "existing_identity", "noMatchPolicy": "deny", "deprovisionMode": "retain",
			"deprovisionGraceSeconds": 0, "syncIntervalSeconds": nil,
		},
		"endpoints": []map[string]any{{
			"id": mustPostgresUUIDv7(t), "priority": 1, "host": "ldap.example.test", "port": 636,
			"transport": "ldaps", "tlsServerName": "ldap.example.test", "referralAllowed": false,
			"enabled": true,
		}},
		"mappings": []map[string]any{},
		"bindSecret": map[string]any{
			"secretId": secretID, "revision": 2, "keyVersion": 1,
			"nonce": nonce, "ciphertext": ciphertext,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return document
}
