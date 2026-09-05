package dfir

import (
	"testing"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

func TestCaseWorkspaceAcceptsCanonicalChildRelationship(t *testing.T) {
	t.Parallel()
	tenantID, caseID := testUUID(160), testEntityID(t, 161)
	tenant := testEntityIDFromUUID(t, tenantID)
	ioc, err := kernel.NewIndicator(indicatorInput(t, tenantID, 162))
	if err != nil {
		t.Fatal(err)
	}
	asset, err := kernel.NewAsset(alertAssetInput(t, tenantID, 163))
	if err != nil {
		t.Fatal(err)
	}
	source, _ := kernel.NewEntityReference(tenant, kernel.EntityIOC, ioc.ID())
	target, _ := kernel.NewEntityReference(tenant, kernel.EntityAsset, asset.ID())
	relationship, err := kernel.NewRelationship(kernel.RelationshipInput{
		ID: testEntityID(t, 164), TenantID: tenant, Source: source, Target: target,
		RelationshipType: "observed_on", CreatedBy: testEntityID(t, 165), CreatedAt: testTime(0),
	})
	if err != nil {
		t.Fatal(err)
	}
	roots := []RelatedRoot{{Kind: kernel.EntityCase, ID: caseID}}
	workspace := Workspace{
		Indicators: []Versioned[kernel.Indicator]{{Resource: ioc, Version: 1}},
		Assets:     []Versioned[kernel.Asset]{{Resource: asset, Version: 1}},
		SharedResources: []SharedResource{
			{ResourceKind: kernel.EntityIOC, ResourceID: ioc.ID(), Roots: roots},
			{ResourceKind: kernel.EntityAsset, ResourceID: asset.ID(), Roots: roots},
		},
		Relationships: []kernel.Relationship{relationship},
	}
	if !validWorkspace(workspace, tenantID, caseID) {
		t.Fatal("canonical relationship between Case-owned resources was rejected")
	}
	if validWorkspace(workspace, testUUID(166), caseID) {
		t.Fatal("cross-tenant workspace was accepted")
	}
	workspace.Relationships = append(workspace.Relationships, relationship)
	if validWorkspace(workspace, tenantID, caseID) {
		t.Fatal("duplicate relationship was accepted")
	}
}
