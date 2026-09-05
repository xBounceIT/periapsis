package postgres

import (
	"encoding/json"
	"testing"
)

func TestTenantNotificationDatabasePayloadKeepsLocalExemptionOutOfPublicDocument(t *testing.T) {
	payload := map[string]any{
		"name":                     "Development sink",
		"endpointUrl":              "http://127.0.0.1:9080/",
		"allowPlainLocalExemption": true,
		"eventTypes":               []string{"alert.created"},
		"audience":                 "operator",
		"retainSigningKey":         true,
		"timeoutMs":                5_000,
		"enabled":                  true,
	}

	databasePayload, allowed, err := tenantNotificationDatabasePayload("webhook.version", payload)
	if err != nil {
		t.Fatalf("prepare webhook payload: %v", err)
	}
	if !allowed {
		t.Fatal("expected the process-authorized local exemption")
	}
	encoded, err := json.Marshal(databasePayload)
	if err != nil {
		t.Fatalf("encode database payload: %v", err)
	}
	const legacyDocument = `{"audience":"operator","enabled":true,"endpointUrl":"http://127.0.0.1:9080/","eventTypes":["alert.created"],"name":"Development sink","retainSigningKey":true,"timeoutMs":5000}`
	if string(encoded) != legacyDocument {
		t.Fatalf("database payload changed the public idempotency document: %s", encoded)
	}
	if _, present := databasePayload.(map[string]any)["allowPlainLocalExemption"]; present {
		t.Fatal("server-side exemption leaked into the public database payload")
	}
	if _, present := payload["allowPlainLocalExemption"]; !present {
		t.Fatal("payload extraction mutated its caller")
	}
}

func TestTenantNotificationDatabasePayloadRejectsForgedLocalExemption(t *testing.T) {
	for _, payload := range []any{
		map[string]any{"endpointUrl": "http://127.0.0.1/"},
		map[string]any{"allowPlainLocalExemption": "true"},
		struct{ Allow bool }{Allow: true},
	} {
		if _, _, err := tenantNotificationDatabasePayload("webhook.create", payload); err == nil {
			t.Fatalf("accepted invalid local-exemption payload %#v", payload)
		}
	}
}
