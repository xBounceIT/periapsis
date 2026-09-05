package dfir

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestIndicatorNormalizesKnownTypesWithoutChangingOriginal(t *testing.T) {
	tests := []struct {
		kind       IndicatorType
		value      string
		normalized string
	}{
		{IndicatorIPv4, "192.0.2.10", "192.0.2.10"},
		{IndicatorIPv6, "2001:0DB8:0:0::1", "2001:db8::1"},
		{IndicatorDomain, "BÜCHER.Example.", "xn--bcher-kva.example"},
		{IndicatorHostname, "WORKSTATION-01", "workstation-01"},
		{IndicatorURL, "https://BÜCHER.Example:443/path?q=One", "https://xn--bcher-kva.example/path?q=One"},
		{IndicatorURL, "HTTPS://Example.TEST", "https://example.test/"},
		{IndicatorURL, "http://[2001:0DB8::1]:80/path", "http://[2001:db8::1]/path"},
		{IndicatorEmail, "Analyst@BÜCHER.Example", "Analyst@xn--bcher-kva.example"},
		{IndicatorMD5, strings.Repeat("A1", 16), strings.Repeat("a1", 16)},
		{IndicatorSHA1, strings.Repeat("B2", 20), strings.Repeat("b2", 20)},
		{IndicatorSHA256, strings.Repeat("C3", 32), strings.Repeat("c3", 32)},
		{IndicatorSHA512, strings.Repeat("D4", 64), strings.Repeat("d4", 64)},
		{IndicatorCVE, "cve-2026-12345", "CVE-2026-12345"},
		{IndicatorRegistry, `HKLM\\Software\\Vendor`, `HKLM\\Software\\Vendor`},
	}
	for _, test := range tests {
		t.Run(string(test.kind), func(t *testing.T) {
			input := validIndicatorInput(test.kind, test.value)
			indicator, err := NewIndicator(input)
			if err != nil {
				t.Fatalf("NewIndicator() error = %v", err)
			}
			if indicator.Value() != test.value || indicator.NormalizedValue() != test.normalized {
				t.Fatalf("value/normalized = %q/%q", indicator.Value(), indicator.NormalizedValue())
			}
		})
	}
}

func TestIndicatorRejectsAmbiguousOrMalformedKnownValues(t *testing.T) {
	tests := []struct {
		kind  IndicatorType
		value string
	}{
		{IndicatorIPv4, "::ffff:192.0.2.1"},
		{IndicatorIPv6, "fe80::1%eth0"},
		{IndicatorDomain, "127.0.0.1"},
		{IndicatorDomain, "single-label"},
		{IndicatorHostname, "bad_label.example"},
		{IndicatorURL, "https://user:secret@example.com/path"},
		{IndicatorURL, "file:///etc/passwd"},
		{IndicatorURL, "//example.com/path"},
		{IndicatorURL, "0"},
		{IndicatorURL, "https://[::ffff:192.0.2.1]/"},
		{IndicatorURL, "https://example.test:0/"},
		{IndicatorEmail, "Display Name <user@example.com>"},
		{IndicatorEmail, "missing-at.example"},
		{IndicatorSHA256, strings.Repeat("a", 63)},
		{IndicatorSHA256, strings.Repeat("z", 64)},
		{IndicatorCVE, "CVE-98-1"},
	}
	for _, test := range tests {
		t.Run(string(test.kind)+"_"+test.value, func(t *testing.T) {
			if _, err := NewIndicator(validIndicatorInput(test.kind, test.value)); err == nil {
				t.Fatal("malformed indicator was accepted")
			}
		})
	}
}

func TestEntityIDHasStableCanonicalText(t *testing.T) {
	id := fixtureID(10)
	if got, want := id.String(), "019d0000-0000-700a-8000-000000000000"; got != want {
		t.Fatalf("EntityID.String() = %q, want %q", got, want)
	}
	if _, err := NewEntityID([16]byte{}); err == nil {
		t.Fatal("zero/non-v7 entity id was accepted")
	}
}

func TestIndicatorEnrichmentIsBoundedObjectAndRejectsDuplicateKeys(t *testing.T) {
	valid := validIndicatorInput(IndicatorDomain, "example.test")
	valid.Enrichment = json.RawMessage(`{"provider":{"score":91,"labels":["known","active"]}}`)
	indicator, err := NewIndicator(valid)
	if err != nil {
		t.Fatal(err)
	}
	valid.Enrichment[2] = 'X'
	if string(indicator.Enrichment()) != `{"provider":{"score":91,"labels":["known","active"]}}` {
		t.Fatal("indicator retained caller-owned enrichment bytes")
	}
	copyOfEnrichment := indicator.Enrichment()
	copyOfEnrichment[2] = 'Y'
	if string(indicator.Enrichment()) == string(copyOfEnrichment) {
		t.Fatal("Enrichment exposed mutable internal bytes")
	}

	invalidDocuments := []string{
		`[]`,
		`{"score":1,"score":2}`,
		`{"nested":{"duplicate":1,"duplicate":2}}`,
		`{"control":"\u0000"}`,
		`{"unterminated":`,
	}
	for _, document := range invalidDocuments {
		input := validIndicatorInput(IndicatorDomain, "example.test")
		input.Enrichment = json.RawMessage(document)
		if _, err := NewIndicator(input); err == nil {
			t.Fatalf("invalid enrichment accepted: %s", document)
		}
	}

	deep := strings.Repeat(`{"x":`, maximumEnrichmentDepth+1) + `true` +
		strings.Repeat(`}`, maximumEnrichmentDepth+1)
	deepInput := validIndicatorInput(IndicatorDomain, "example.test")
	deepInput.Enrichment = json.RawMessage(deep)
	if _, err := NewIndicator(deepInput); err == nil {
		t.Fatal("over-depth enrichment accepted")
	}
}

func TestIndicatorOwnsTagsAndRedactsSensitiveFields(t *testing.T) {
	input := validIndicatorInput(IndicatorURL, "https://secret.example/private?token=abc")
	input.Tags = []string{"malware", "phishing"}
	input.Description = "customer confidential context"
	input.Source = "sensor-private-01"
	input.Enrichment = json.RawMessage(`{"token":"classified"}`)
	indicator, err := NewIndicator(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Tags[0] = "changed"
	if got := indicator.Tags(); !reflect.DeepEqual(got, []string{"malware", "phishing"}) {
		t.Fatalf("tags = %v", got)
	}
	for _, rendered := range []string{fmt.Sprint(indicator), fmt.Sprintf("%#v", indicator)} {
		for _, secret := range []string{
			indicator.Value(), indicator.NormalizedValue(), indicator.Description(),
			indicator.Source(), "classified",
		} {
			if strings.Contains(rendered, secret) {
				t.Fatalf("formatting leaked %q: %q", secret, rendered)
			}
		}
		if !strings.Contains(rendered, "REDACTED") {
			t.Fatalf("formatting is not visibly redacted: %q", rendered)
		}
	}
}

func TestIndicatorRejectsCrossFieldAndTextBoundaryViolations(t *testing.T) {
	tests := []func(*IndicatorInput){
		func(input *IndicatorInput) { input.Confidence = 101 },
		func(input *IndicatorInput) { input.TLP = "future" },
		func(input *IndicatorInput) { input.Malicious = "maybe" },
		func(input *IndicatorInput) { input.LastSeen = input.FirstSeen.Add(-time.Millisecond) },
		func(input *IndicatorInput) { input.Value = " example.test" },
		func(input *IndicatorInput) { input.Value = "example\u202etest" },
		func(input *IndicatorInput) { input.Source = "sensor\x00name" },
		func(input *IndicatorInput) { input.Tags = []string{"Duplicate", "duplicate"} },
		func(input *IndicatorInput) { input.Tags = []string{"duplicate", "duplicate"} },
	}
	for index, mutate := range tests {
		input := validIndicatorInput(IndicatorDomain, "example.test")
		mutate(&input)
		if _, err := NewIndicator(input); err == nil {
			t.Fatalf("invalid case %d accepted", index)
		}
	}
}

func validIndicatorInput(kind IndicatorType, value string) IndicatorInput {
	return IndicatorInput{
		ID:          fixtureID(10),
		TenantID:    fixtureID(1),
		Type:        kind,
		Value:       value,
		Description: "Observed during triage",
		Source:      "endpoint_sensor",
		Confidence:  80,
		TLP:         TLPAmber,
		FirstSeen:   time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC),
		LastSeen:    time.Date(2026, 8, 25, 10, 5, 0, 0, time.UTC),
		Malicious:   MaliciousSuspicious,
		Tags:        []string{"triage"},
	}
}

func fixtureID(sequence uint16) EntityID {
	value := [16]byte{0x01, 0x9d, 0x00, 0x00, 0x00, byte(sequence >> 8), 0x70, byte(sequence)}
	value[8] = 0x80
	id, err := NewEntityID(value)
	if err != nil {
		panic(err)
	}
	return id
}
