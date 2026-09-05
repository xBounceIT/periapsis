package dfir

import (
	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

const (
	maximumWorkspaceResources     = 500
	maximumWorkspaceTimeline      = 1000
	maximumWorkspaceRelationships = 1000
)

func validWorkspace(workspace Workspace, tenantID uuid.UUID, caseID kernel.EntityID) bool {
	if len(workspace.Indicators) > maximumWorkspaceResources ||
		len(workspace.Assets) > maximumWorkspaceResources ||
		len(workspace.Evidence) > maximumWorkspaceResources ||
		len(workspace.Timeline) > maximumWorkspaceTimeline ||
		len(workspace.Tasks) > maximumWorkspaceResources ||
		len(workspace.Attachments) > maximumWorkspaceResources ||
		len(workspace.Relationships) > maximumWorkspaceRelationships ||
		!validSharedResources(workspace.SharedResources, workspace.Indicators, workspace.Assets, RelatedRoot{Kind: kernel.EntityCase, ID: caseID}) {
		return false
	}
	tenant, err := kernel.NewEntityID([16]byte(tenantID))
	if err != nil {
		return false
	}
	seen := make(map[kernel.EntityID]struct{}, maximumWorkspaceResources)
	for _, item := range workspace.Indicators {
		if item.Version == 0 || item.Resource.TenantID() != tenant || !uniqueWorkspaceID(seen, item.Resource.ID()) {
			return false
		}
	}
	clear(seen)
	for _, item := range workspace.Assets {
		if item.Version == 0 || item.Resource.TenantID() != tenant || !uniqueWorkspaceID(seen, item.Resource.ID()) {
			return false
		}
	}
	clear(seen)
	for _, evidence := range workspace.Evidence {
		if evidence.TenantID() != tenant || evidence.CaseID() != caseID || evidence.Version() == 0 ||
			!evidence.VerifyCustodyChain() || !uniqueWorkspaceID(seen, evidence.ID()) {
			return false
		}
	}
	clear(seen)
	for _, item := range workspace.Timeline {
		if item.Version == 0 || item.Resource.TenantID() != tenant || item.Resource.CaseID() != caseID ||
			!uniqueWorkspaceID(seen, item.Resource.ID()) {
			return false
		}
	}
	clear(seen)
	for _, task := range workspace.Tasks {
		if task.TenantID() != tenant || task.CaseID() != caseID || task.Version() == 0 || !uniqueWorkspaceID(seen, task.ID()) {
			return false
		}
	}
	clear(seen)
	for _, attachment := range workspace.Attachments {
		subject := attachment.Subject()
		if attachment.TenantID() != tenant || subject.TenantID() != tenant || subject.Kind() == kernel.EntityExternal ||
			!uniqueWorkspaceID(seen, attachment.ID()) {
			return false
		}
	}
	clear(seen)
	for _, relationship := range workspace.Relationships {
		if relationship.TenantID() != tenant || !validCaseRelationshipProjection(relationship) ||
			!uniqueWorkspaceID(seen, relationship.ID()) {
			return false
		}
	}
	return true
}

func validAlertWorkspace(workspace AlertWorkspace, tenantID uuid.UUID, alertID kernel.EntityID) bool {
	if len(workspace.Indicators) > maximumWorkspaceResources ||
		len(workspace.Assets) > maximumWorkspaceResources ||
		len(workspace.Timeline) > maximumWorkspaceTimeline ||
		len(workspace.Attachments) > maximumWorkspaceResources ||
		!validSharedResources(workspace.SharedResources, workspace.Indicators, workspace.Assets, RelatedRoot{Kind: kernel.EntityAlert, ID: alertID}) {
		return false
	}
	tenant, err := kernel.NewEntityID([16]byte(tenantID))
	if err != nil {
		return false
	}
	seen := make(map[kernel.EntityID]struct{}, maximumWorkspaceResources)
	indicatorIDs := make(map[kernel.EntityID]struct{}, len(workspace.Indicators))
	for _, item := range workspace.Indicators {
		if item.Version == 0 || item.Resource.TenantID() != tenant || !uniqueWorkspaceID(seen, item.Resource.ID()) {
			return false
		}
		indicatorIDs[item.Resource.ID()] = struct{}{}
	}
	clear(seen)
	assetIDs := make(map[kernel.EntityID]struct{}, len(workspace.Assets))
	for _, item := range workspace.Assets {
		if item.Version == 0 || item.Resource.TenantID() != tenant || !uniqueWorkspaceID(seen, item.Resource.ID()) {
			return false
		}
		assetIDs[item.Resource.ID()] = struct{}{}
	}
	clear(seen)
	for _, item := range workspace.Timeline {
		if item.Version == 0 || item.Resource.TenantID() != tenant || item.Resource.AlertID() != alertID ||
			item.Resource.CaseID() != (kernel.EntityID{}) ||
			!alertTimelineReferences(item.Resource, indicatorIDs, assetIDs) ||
			!uniqueWorkspaceID(seen, item.Resource.ID()) {
			return false
		}
	}
	clear(seen)
	for _, attachment := range workspace.Attachments {
		subject := attachment.Subject()
		if attachment.TenantID() != tenant || subject.TenantID() != tenant ||
			!alertWorkspaceSubject(subject, alertID, indicatorIDs, assetIDs) ||
			!uniqueWorkspaceID(seen, attachment.ID()) {
			return false
		}
	}
	return true
}

func alertTimelineReferences(
	event kernel.TimelineEvent,
	indicatorIDs map[kernel.EntityID]struct{},
	assetIDs map[kernel.EntityID]struct{},
) bool {
	for _, id := range event.IOCIDs() {
		if _, exists := indicatorIDs[id]; !exists {
			return false
		}
	}
	for _, id := range event.AssetIDs() {
		if _, exists := assetIDs[id]; !exists {
			return false
		}
	}
	return true
}

func alertWorkspaceSubject(
	subject kernel.EntityReference,
	alertID kernel.EntityID,
	indicatorIDs map[kernel.EntityID]struct{},
	assetIDs map[kernel.EntityID]struct{},
) bool {
	switch subject.Kind() {
	case kernel.EntityAlert:
		return subject.ID() == alertID
	case kernel.EntityIOC:
		_, ok := indicatorIDs[subject.ID()]
		return ok
	case kernel.EntityAsset:
		_, ok := assetIDs[subject.ID()]
		return ok
	default:
		return false
	}
}

func uniqueWorkspaceID(seen map[kernel.EntityID]struct{}, id kernel.EntityID) bool {
	if id == (kernel.EntityID{}) {
		return false
	}
	if _, duplicate := seen[id]; duplicate {
		return false
	}
	seen[id] = struct{}{}
	return true
}

func validSharedResources(
	resources []SharedResource,
	indicators []Versioned[kernel.Indicator],
	assets []Versioned[kernel.Asset],
	requiredRoot RelatedRoot,
) bool {
	if len(resources) != len(indicators)+len(assets) {
		return false
	}
	expected := make(map[RelatedRoot]struct{}, len(resources))
	for _, item := range indicators {
		expected[RelatedRoot{Kind: kernel.EntityIOC, ID: item.Resource.ID()}] = struct{}{}
	}
	for _, item := range assets {
		expected[RelatedRoot{Kind: kernel.EntityAsset, ID: item.Resource.ID()}] = struct{}{}
	}
	for _, resource := range resources {
		key := RelatedRoot{Kind: resource.ResourceKind, ID: resource.ResourceID}
		if _, exists := expected[key]; !exists || len(resource.Roots) == 0 || len(resource.Roots) > 64 {
			return false
		}
		delete(expected, key)
		seen := make(map[RelatedRoot]struct{}, len(resource.Roots))
		for _, root := range resource.Roots {
			if (root.Kind != kernel.EntityCase && root.Kind != kernel.EntityAlert) || root.ID == (kernel.EntityID{}) {
				return false
			}
			if _, duplicate := seen[root]; duplicate {
				return false
			}
			seen[root] = struct{}{}
		}
		if _, exists := seen[requiredRoot]; !exists {
			return false
		}
	}
	return len(expected) == 0
}
