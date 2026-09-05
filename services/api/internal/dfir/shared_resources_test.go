package dfir

import (
	"testing"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

func TestSharedResourceProjectionMatchesInventoryAndContainsCurrentRoot(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(160)
	ioc, err := kernel.NewIndicator(indicatorInput(t, tenantID, 161))
	if err != nil {
		t.Fatal(err)
	}
	indicators := []Versioned[kernel.Indicator]{{Resource: ioc, Version: 1}}
	current := RelatedRoot{Kind: kernel.EntityCase, ID: testEntityID(t, 162)}
	other := RelatedRoot{Kind: kernel.EntityAlert, ID: testEntityID(t, 163)}
	valid := SharedResource{ResourceKind: kernel.EntityIOC, ResourceID: ioc.ID(), Roots: []RelatedRoot{current, other}}
	if !validSharedResources([]SharedResource{valid}, indicators, nil, current) {
		t.Fatal("valid cross-root projection was rejected")
	}
	if validSharedResources(nil, indicators, nil, current) {
		t.Fatal("inventory without a link projection was accepted")
	}
	for _, roots := range [][]RelatedRoot{
		nil, {other}, {current, current}, {current, {Kind: kernel.EntityExternal, ID: other.ID}}, {current, {Kind: kernel.EntityAlert}},
	} {
		bad := valid
		bad.Roots = roots
		if validSharedResources([]SharedResource{bad}, indicators, nil, current) {
			t.Fatalf("invalid roots accepted: %#v", roots)
		}
	}
	wrongKind := valid
	wrongKind.ResourceKind = kernel.EntityAsset
	if validSharedResources([]SharedResource{wrongKind}, indicators, nil, current) {
		t.Fatal("an asset projection was used for an IOC")
	}
	wrongID := valid
	wrongID.ResourceID = testEntityID(t, 164)
	if validSharedResources([]SharedResource{wrongID}, indicators, nil, current) {
		t.Fatal("an unlisted resource was projected")
	}
	if validSharedResources([]SharedResource{valid, valid}, indicators, nil, current) {
		t.Fatal("duplicate resource projection accepted")
	}
}
