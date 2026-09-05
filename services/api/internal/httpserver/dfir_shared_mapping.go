package httpserver

import (
	"github.com/google/uuid"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func mapDfirSharedResources(values []application.SharedResource) ([]contract.DfirSharedResource, error) {
	result := make([]contract.DfirSharedResource, len(values))
	for index, item := range values {
		if item.ResourceID == (kernel.EntityID{}) ||
			(item.ResourceKind != kernel.EntityIOC && item.ResourceKind != kernel.EntityAsset) ||
			len(item.Roots) == 0 || len(item.Roots) > 64 {
			return nil, application.ErrUnavailable
		}
		result[index] = contract.DfirSharedResource{
			ResourceId: uuid.UUID(item.ResourceID.Bytes()), ResourceKind: contract.DfirSharedResourceResourceKind(item.ResourceKind),
			Roots: make([]contract.DfirRelatedRoot, len(item.Roots)),
		}
		for rootIndex, root := range item.Roots {
			if root.ID == (kernel.EntityID{}) || (root.Kind != kernel.EntityCase && root.Kind != kernel.EntityAlert) {
				return nil, application.ErrUnavailable
			}
			result[index].Roots[rootIndex] = contract.DfirRelatedRoot{Kind: contract.DfirRelatedRootKind(root.Kind), Id: uuid.UUID(root.ID.Bytes())}
		}
	}
	return result, nil
}
