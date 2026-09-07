package httpserver

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSLABodyPreservesRawRuleWarningAndActionObjects(t *testing.T) {
	const input = `{
		"matchRule":{"kind":"all","children":[]},
		"warning":{"kind":"remaining_duration","remainingMicros":900000000},
		"action":{"kind":"create_system_alert","value":"sla_warning","allowRecursiveSla":false}
	}`
	var body struct {
		MatchRule slaRawJSON `json:"matchRule"`
		Warning   slaRawJSON `json:"warning"`
		Action    slaRawJSON `json:"action"`
	}
	request := httptest.NewRequest("POST", "/", strings.NewReader(input))
	request.Header.Set("Content-Type", "application/json")
	if err := decodeSLABody(request, &body); err != nil {
		t.Fatal(err)
	}
	if _, err := parseSLARule(body.MatchRule); err != nil {
		t.Fatal(err)
	}
	if _, err := parseSLAWarning(body.Warning); err != nil {
		t.Fatal(err)
	}
	if _, err := parseSLATriggerAction(body.Action); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(input)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, compact.Bytes()) {
		t.Fatalf("raw subtrees changed: %s", encoded)
	}
	if _, err := parseSLARule(slaRawJSON(`{"kind":"all","children":[],"unknown":true}`)); err == nil {
		t.Fatal("raw decoding bypassed the rule's exact shape validation")
	}
}
