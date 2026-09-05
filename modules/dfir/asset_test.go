package dfir

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAssetPreservesReportedIdentifiersAndCanonicalizesLookupValues(t *testing.T) {
	input := validAssetInput()
	asset, err := NewAsset(input)
	if err != nil {
		t.Fatalf("NewAsset() error = %v", err)
	}
	if got, want := asset.Hostname(), "WORKSTATION-01"; got != want {
		t.Fatalf("Hostname() = %q, want %q", got, want)
	}
	if got, want := asset.NormalizedHostname(), "workstation-01"; got != want {
		t.Fatalf("NormalizedHostname() = %q, want %q", got, want)
	}
	if got, want := asset.FQDN(), "BÜCHER.Example."; got != want {
		t.Fatalf("FQDN() = %q, want %q", got, want)
	}
	if got, want := asset.NormalizedFQDN(), "xn--bcher-kva.example"; got != want {
		t.Fatalf("NormalizedFQDN() = %q, want %q", got, want)
	}
	wantIPs := []NetworkAddress{
		{original: "192.0.2.10", normalized: "192.0.2.10", family: 4},
		{original: "2001:0DB8::10", normalized: "2001:db8::10", family: 6},
	}
	if got := asset.IPAddresses(); !reflect.DeepEqual(got, wantIPs) {
		t.Fatalf("IPAddresses() = %#v, want %#v", got, wantIPs)
	}
	wantMACs := []HardwareAddress{{original: "02-00-5E-10-00-00", normalized: "02:00:5e:10:00:00"}}
	if got := asset.MACAddresses(); !reflect.DeepEqual(got, wantMACs) {
		t.Fatalf("MACAddresses() = %#v, want %#v", got, wantMACs)
	}
}

func TestAssetRejectsMissingOrAmbiguousIdentifiers(t *testing.T) {
	tests := []func(*AssetInput){
		func(input *AssetInput) {
			input.Hostname, input.FQDN, input.IPAddresses, input.MACAddresses, input.ExternalID = "", "", nil, nil, ""
		},
		func(input *AssetInput) { input.IPAddresses = []string{"::ffff:192.0.2.1"} },
		func(input *AssetInput) { input.IPAddresses = []string{"2001:db8::1", "2001:0db8:0:0::1"} },
		func(input *AssetInput) { input.MACAddresses = []string{"not-a-mac"} },
		func(input *AssetInput) { input.MACAddresses = []string{"02:00:5e:10:00:00", "02-00-5E-10-00-00"} },
		func(input *AssetInput) { input.FQDN = "single-label" },
		func(input *AssetInput) { input.AssetType = "Endpoint" },
		func(input *AssetInput) { input.Environment = "prod/primary" },
		func(input *AssetInput) { input.Criticality = "severe" },
		func(input *AssetInput) { input.LastSeen = input.FirstSeen.Add(-time.Microsecond) },
		func(input *AssetInput) { input.CustomAttributes = json.RawMessage(`[]`) },
	}
	for index, mutate := range tests {
		input := validAssetInput()
		mutate(&input)
		if _, err := NewAsset(input); err == nil {
			t.Fatalf("invalid asset case %d accepted", index)
		}
	}
}

func TestAssetOwnsCollectionsAndRedactsOperationalMetadata(t *testing.T) {
	input := validAssetInput()
	asset, err := NewAsset(input)
	if err != nil {
		t.Fatal(err)
	}
	input.IPAddresses[0] = "198.51.100.3"
	input.MACAddresses[0] = "00:00:00:00:00:00"
	input.Tags[0] = "changed"
	input.CustomAttributes[2] = 'X'

	if got := asset.IPAddresses()[0].Original(); got != "192.0.2.10" {
		t.Fatalf("caller mutated IP address: %q", got)
	}
	if got := asset.MACAddresses()[0].Original(); got != "02-00-5E-10-00-00" {
		t.Fatalf("caller mutated MAC address: %q", got)
	}
	if got := asset.Tags(); !reflect.DeepEqual(got, []string{"critical_system", "triage"}) {
		t.Fatalf("Tags() = %v", got)
	}
	if got := string(asset.CustomAttributes()); got != `{"serial":"private-serial"}` {
		t.Fatalf("CustomAttributes() = %s", got)
	}

	for _, rendered := range []string{fmt.Sprint(asset), fmt.Sprintf("%#v", asset)} {
		for _, secret := range []string{
			asset.Hostname(), asset.FQDN(), asset.OperatingSystem(), asset.Owner(),
			asset.BusinessUnit(), asset.ExternalID(), "private-serial",
		} {
			if strings.Contains(rendered, secret) {
				t.Fatalf("asset formatting leaked %q: %q", secret, rendered)
			}
		}
	}
	if got := fmt.Sprint(asset.IPAddresses()[0]); strings.Contains(got, "192.0.2.10") {
		t.Fatalf("network identifier formatting leaked value: %q", got)
	}
}

func validAssetInput() AssetInput {
	return AssetInput{
		ID:               fixtureID(30),
		TenantID:         fixtureID(1),
		Hostname:         "WORKSTATION-01",
		FQDN:             "BÜCHER.Example.",
		IPAddresses:      []string{"2001:0DB8::10", "192.0.2.10"},
		MACAddresses:     []string{"02-00-5E-10-00-00"},
		AssetType:        "endpoint",
		OperatingSystem:  "Private OS 1",
		Owner:            "Private Owner",
		BusinessUnit:     "Private Unit",
		Criticality:      AssetCriticalityCritical,
		Environment:      "production",
		ExternalID:       "private-external-id",
		Tags:             []string{"triage", "critical_system"},
		FirstSeen:        time.Date(2026, 8, 25, 11, 0, 0, 0, time.UTC),
		LastSeen:         time.Date(2026, 8, 25, 11, 5, 0, 0, time.UTC),
		CustomAttributes: json.RawMessage(`{"serial":"private-serial"}`),
	}
}
